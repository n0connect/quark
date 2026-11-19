// Real, non-mocked end-to-end test for handoff_spy: forks the actual built
// binary, drives it over real POSIX pipes with a real QKH2 frame + a real
// challenge frame, and checks its response against quark_core's own
// (independently implemented and already-tested) HMAC derivation --
// verifying interoperability between handoff_spy's hand-rolled crypto and
// quark_core's, which is the entire point of this tool's existence.
//
// POSIX-only (fork/pipe/execv) -- Windows re-verification of handoff_spy is
// tracked separately; see docs/superpowers/specs/2026-07-05-cross-platform-
// porting-roadmap.md's non-goals.

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/token.hpp"

namespace {

int g_failures = 0;

void Check(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_failures;
    } else {
        std::printf("ok: %s\n", what);
    }
}

void WriteAll(int fd, const std::vector<uint8_t>& data) {
    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = write(fd, data.data() + total, data.size() - total);
        if (n <= 0) return;
        total += static_cast<size_t>(n);
    }
}

bool ReadAll(int fd, uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        ssize_t n = read(fd, buf + total, want - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

void AppendU32LE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <path-to-handoff_spy-binary>\n", argv[0]);
        return 2;
    }
    const char* spy_path = argv[1];

    int to_child[2];   // parent writes[1] -> child's stdin (read end [0])
    int from_child[2]; // child's stdout (write end [1]) -> parent reads[0]
    if (pipe(to_child) != 0 || pipe(from_child) != 0) {
        std::fprintf(stderr, "pipe() failed\n");
        return 1;
    }

    pid_t pid = fork();
    Check(pid >= 0, "fork() succeeds");
    if (pid < 0) return 1;

    if (pid == 0) {
        // Child: wire pipes to stdin/stdout, exec handoff_spy.
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        setenv("QUARK_SPY_CHALLENGES", "1", 1);
        execl(spy_path, spy_path, static_cast<char*>(nullptr));
        _exit(127);  // execl only returns on failure
    }

    // Parent: close the ends it doesn't use.
    close(to_child[0]);
    close(from_child[1]);

    // Build a real 136-byte QKH2 initial frame: magic + version + handoff_secret
    // + session_id + initial_seal + core_enc_key (initial_seal/core_enc_key are
    // not checked by handoff_spy, zero is fine here).
    quark::crypto::AesKey handoff_secret{};
    auto random_secret = quark::crypto::RandomBytes(32);
    std::copy(random_secret.begin(), random_secret.end(), handoff_secret.begin());

    std::array<uint8_t, 32> session_id{};
    auto random_session = quark::crypto::RandomBytes(32);
    std::copy(random_session.begin(), random_session.end(), session_id.begin());

    std::vector<uint8_t> frame;
    frame.insert(frame.end(), {'Q', 'K', 'H', '2'});
    AppendU32LE(frame, 2);
    frame.insert(frame.end(), handoff_secret.begin(), handoff_secret.end());
    frame.insert(frame.end(), session_id.begin(), session_id.end());
    frame.insert(frame.end(), 32, 0);  // initial_seal (unused by handoff_spy)
    frame.insert(frame.end(), 32, 0);  // core_enc_key (unused by handoff_spy)
    Check(frame.size() == 136, "constructed frame is exactly 136 bytes");

    WriteAll(to_child[1], frame);

    // content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret) --
    // quark_core's own, independently-implemented derivation.
    quark::crypto::AesKey content_key = quark::token::DeriveContentKey(handoff_secret);

    // Send one CHAL frame: magic + counter(u32-LE) + nonce(32).
    uint32_t counter = 42;
    std::array<uint8_t, 32> nonce{};
    auto random_nonce = quark::crypto::RandomBytes(32);
    std::copy(random_nonce.begin(), random_nonce.end(), nonce.begin());

    std::vector<uint8_t> chal;
    chal.insert(chal.end(), {'C', 'H', 'A', 'L'});
    AppendU32LE(chal, counter);
    chal.insert(chal.end(), nonce.begin(), nonce.end());
    Check(chal.size() == 40, "constructed challenge frame is exactly 40 bytes");

    WriteAll(to_child[1], chal);

    uint8_t response[32] = {0};
    bool got_response = ReadAll(from_child[0], response, 32);
    Check(got_response, "handoff_spy sends a 32-byte challenge response");

    if (got_response) {
        quark::crypto::Sha256Digest expected =
            quark::token::DeriveChallengeMac(content_key, session_id, counter, nonce);
        Check(std::memcmp(response, expected.data(), 32) == 0,
              "handoff_spy's hand-rolled HMAC matches quark_core's independent derivation");
    }

    close(to_child[1]);
    close(from_child[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    Check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "handoff_spy exits 0 after completing its one configured challenge cycle");

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
