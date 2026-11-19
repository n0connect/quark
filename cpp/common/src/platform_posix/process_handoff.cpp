#include "quark/platform/posix/process_handoff.hpp"

#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <thread>

#include "quark/error.hpp"
#include "quark/handoff.hpp"
#include "quark/token.hpp"

namespace quark::platform::posix {

namespace {

[[noreturn]] void FailDeadly(const std::string& component, error::Code code) {
    error::Report(code, component.c_str());
    std::exit(1);
}

uint64_t NowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

// Reads exactly 32 bytes from `fd` within `timeout_ms` using poll(2) --
// mirrors Windows' ReadResponseWithTimeout (PeekNamedPipe + polling), except
// POSIX pipes support poll() directly so no busy-wait peek loop is needed.
bool ReadResponseWithTimeout(int fd, uint8_t* buf32, int timeout_ms) {
    const uint64_t deadline = NowMs() + static_cast<uint64_t>(timeout_ms);
    int total = 0;
    while (total < 32) {
        const uint64_t now = NowMs();
        if (now >= deadline) return false;
        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int remaining = static_cast<int>(deadline - now);
        int pr = poll(&pfd, 1, remaining);
        if (pr <= 0) return false;  // timeout or poll() error
        if (pfd.revents & (POLLERR | POLLNVAL)) return false;
        ssize_t n = read(fd, buf32 + total, static_cast<size_t>(32 - total));
        if (n <= 0) return false;  // EOF or error -- child gone
        total += static_cast<int>(n);
    }
    return true;
}

// Polls waitpid(WNOHANG) every 50ms up to `timeout_ms`. There is no portable
// "wait on a pid with a timeout" POSIX primitive short of a SIGCHLD
// self-pipe; a short poll loop is the simple, correct choice here (CLAUDE.md
// rule 3) over that added complexity for a 30s interval.
bool WaitChildWithTimeout(pid_t pid, int timeout_ms, int& status_out) {
    constexpr int kPollIntervalMs = 50;
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += kPollIntervalMs) {
        pid_t r = waitpid(pid, &status_out, WNOHANG);
        if (r == pid) return true;
        if (r < 0) return true;  // ECHILD or similar -- treat as gone
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollIntervalMs));
    }
    return false;
}

}  // namespace

JvmSession LaunchWithInitialHandoff(const std::string& component,
                                     const std::string& path,
                                     const std::vector<std::string>& argv,
                                     const std::vector<uint8_t>& initial_frame) {
    // A dead child's stdin makes the next challenge write raise SIGPIPE,
    // which defaults to killing this process -- ignore it so write(2)
    // instead returns -1/EPIPE, which RunChallengeLoop already treats as a
    // failed challenge.
    signal(SIGPIPE, SIG_IGN);

    int stdin_pipe[2];   // [0] read (child), [1] write (parent keeps)
    int stdout_pipe[2];  // [0] read (parent keeps), [1] write (child)
    if (pipe(stdin_pipe) != 0 || pipe(stdout_pipe) != 0) {
        FailDeadly(component, error::Code::kWrapperPipeSetupFailed);
    }

    pid_t pid = fork();
    if (pid < 0) {
        FailDeadly(component, error::Code::kWrapperProcessLaunchFailed);
    }

    if (pid == 0) {
        // Child: wire pipes to stdin/stdout, then exec. Any failure here
        // exits the child with a distinct status; the parent's first pipe
        // write will fail and it will fail-deadly on that instead (the
        // child cannot safely call quark::error::Report/exit(1) machinery
        // post-fork/pre-exec beyond _exit).
        dup2(stdin_pipe[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);

        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);

        execv(path.c_str(), cargv.data());
        _exit(127);  // exec failed
    }

    // Parent: close the child-facing ends, keep the rest.
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);

    JvmSession session;
    session.pid = pid;
    session.stdin_write_fd = stdin_pipe[1];
    session.stdout_read_fd = stdout_pipe[0];

    ssize_t written = write(session.stdin_write_fd, initial_frame.data(), initial_frame.size());
    if (written < 0 || static_cast<size_t>(written) != initial_frame.size()) {
        FailDeadly(component, error::Code::kWrapperHandoffWriteFailed);
    }

    return session;
}

void RunChallengeLoop(JvmSession& session,
                       const crypto::AesKey& content_key,
                       const std::array<uint8_t, 32>& session_id,
                       int challenge_interval_ms,
                       int response_timeout_ms) {
    uint32_t counter = 0;

    while (true) {
        int status = 0;
        if (WaitChildWithTimeout(session.pid, challenge_interval_ms, status)) {
            session.reaped = true;
            session.wait_status = status;
            return;  // Java exited on its own -- clean exit path
        }

        auto rand_bytes = crypto::RandomBytes(32);
        std::array<uint8_t, 32> nonce{};
        for (size_t i = 0; i < 32; ++i) nonce[i] = rand_bytes[i];

        auto challenge = handoff::EncodeChallengeFrame(counter, nonce);
        ssize_t wr = write(session.stdin_write_fd, challenge.data(), challenge.size());
        if (wr < 0 || static_cast<size_t>(wr) != challenge.size()) {
            kill(session.pid, SIGKILL);
            waitpid(session.pid, &session.wait_status, 0);
            session.reaped = true;
            crypto::SecureZero(nonce.data(), nonce.size());
            return;
        }

        std::array<uint8_t, 32> response{};
        if (!ReadResponseWithTimeout(session.stdout_read_fd, response.data(), response_timeout_ms)) {
            kill(session.pid, SIGKILL);
            waitpid(session.pid, &session.wait_status, 0);
            session.reaped = true;
            crypto::SecureZero(nonce.data(), nonce.size());
            crypto::SecureZero(response.data(), response.size());
            return;
        }

        auto expected = token::DeriveChallengeMac(content_key, session_id, counter, nonce);
        uint8_t diff = 0;
        for (size_t i = 0; i < 32; ++i) diff |= response[i] ^ expected[i];

        crypto::SecureZero(nonce.data(), nonce.size());
        crypto::SecureZero(response.data(), response.size());
        crypto::SecureZero(expected.data(), expected.size());

        if (diff != 0) {
            kill(session.pid, SIGKILL);
            waitpid(session.pid, &session.wait_status, 0);
            session.reaped = true;
            return;
        }

        ++counter;
    }
}

int WaitAndGetExitCode(JvmSession& session) {
    if (!session.reaped) {
        waitpid(session.pid, &session.wait_status, 0);
        session.reaped = true;
    }
    if (WIFEXITED(session.wait_status)) {
        return WEXITSTATUS(session.wait_status);
    }
    return 1;
}

}  // namespace quark::platform::posix
