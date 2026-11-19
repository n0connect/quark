// Real, non-mocked end-to-end test for quark-runtime-c: forks the real
// test_protected_app binary (which links quark_runtime, exactly like a real
// protected application would), drives it over real POSIX pipes with a real
// QKH2 frame, reads test_protected_app's own quark_checkpoint() result off
// its stderr, sends it a real challenge frame, and verifies both the
// checkpoint value and the heartbeat's HMAC response against quark_core's
// own independent derivation.
//
// POSIX-only; see docs/superpowers/specs/2026-07-05-cross-platform-porting-
// roadmap.md's non-goals for Windows re-verification.

#include <signal.h>
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
        std::fprintf(stderr, "usage: %s <path-to-test_protected_app-binary>\n", argv[0]);
        return 2;
    }
    const char* app_path = argv[1];

    int to_child[2];
    int from_child_stdout[2];
    int from_child_stderr[2];
    if (pipe(to_child) != 0 || pipe(from_child_stdout) != 0 || pipe(from_child_stderr) != 0) {
        std::fprintf(stderr, "pipe() failed\n");
        return 1;
    }

    pid_t pid = fork();
    Check(pid >= 0, "fork() succeeds");
    if (pid < 0) return 1;

    if (pid == 0) {
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child_stdout[1], STDOUT_FILENO);
        dup2(from_child_stderr[1], STDERR_FILENO);
        close(to_child[0]); close(to_child[1]);
        close(from_child_stdout[0]); close(from_child_stdout[1]);
        close(from_child_stderr[0]); close(from_child_stderr[1]);
        execl(app_path, app_path, static_cast<char*>(nullptr));
        _exit(127);
    }

    close(to_child[0]);
    close(from_child_stdout[1]);
    close(from_child_stderr[1]);

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
    frame.insert(frame.end(), 32, 0);  // initial_seal
    frame.insert(frame.end(), 32, 0);  // core_enc_key
    Check(frame.size() == 136, "constructed frame is exactly 136 bytes");

    WriteAll(to_child[1], frame);

    // Read test_protected_app's checkpoint result off its stderr.
    char stderr_buf[256] = {0};
    ssize_t n = read(from_child_stderr[0], stderr_buf, sizeof(stderr_buf) - 1);
    Check(n > 0, "test_protected_app writes a CHECKPOINT_RESULT line to stderr");

    long long checkpoint_result = 0;
    bool parsed = (n > 0) && (std::sscanf(stderr_buf, "CHECKPOINT_RESULT=%lld", &checkpoint_result) == 1);
    Check(parsed, "CHECKPOINT_RESULT line parses as an integer");

    if (parsed) {
        quark::crypto::AesKey content_key = quark::token::DeriveContentKey(handoff_secret);
        uint8_t msg[10];
        std::memcpy(msg, "CP", 2);
        msg[2] = 0x01; msg[3] = 0x10; msg[4] = 0x00; msg[5] = 0x00;  // id = 0x1001, LE
        msg[6] = 0x00; msg[7] = 0x00; msg[8] = 0x00; msg[9] = 0x00; // counter = 0 (first checkpoint call)
        quark::crypto::Sha256Digest mac = quark::crypto::HmacSha256(
            content_key.data(), content_key.size(), msg, sizeof(msg));
        int64_t expected = 0;
        for (int i = 0; i < 8; i++) expected |= static_cast<int64_t>(mac[i] & 0xFF) << (i * 8);
        Check(checkpoint_result == expected,
              "quark_checkpoint(0x1001)'s first-call value matches an independently computed HMAC");
    }

    // Now exercise the heartbeat thread with a real challenge frame.
    uint32_t counter = 7;
    std::array<uint8_t, 32> nonce{};
    auto random_nonce = quark::crypto::RandomBytes(32);
    std::copy(random_nonce.begin(), random_nonce.end(), nonce.begin());

    std::vector<uint8_t> chal;
    chal.insert(chal.end(), {'C', 'H', 'A', 'L'});
    AppendU32LE(chal, counter);
    chal.insert(chal.end(), nonce.begin(), nonce.end());
    WriteAll(to_child[1], chal);

    uint8_t response[32] = {0};
    bool got_response = ReadAll(from_child_stdout[0], response, 32);
    Check(got_response, "heartbeat thread sends a 32-byte challenge response");

    if (got_response) {
        quark::crypto::AesKey content_key = quark::token::DeriveContentKey(handoff_secret);
        quark::crypto::Sha256Digest expected =
            quark::token::DeriveChallengeMac(content_key, session_id, counter, nonce);
        Check(std::memcmp(response, expected.data(), 32) == 0,
              "heartbeat's HMAC response matches quark_core's independent derivation");
    }

    close(to_child[1]);
    close(from_child_stdout[0]);
    close(from_child_stderr[0]);
    kill(pid, SIGKILL);  // test_protected_app loops forever by design; stop it now
    int status = 0;
    waitpid(pid, &status, 0);

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
