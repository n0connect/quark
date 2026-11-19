// quark_runtime.cpp -- QKH2 heartbeat + checkpoint for native C/C++ applications.
// Mirrors QuarkHeartbeat.java and QuarkRuntime.java byte-for-byte in the wire protocol.
//
// Cross-platform: uses quark_core's crypto (quark::crypto::HmacSha256,
// quark::token::DeriveContentKey/DeriveChallengeMac) rather than Windows CNG
// -- this library is meant to be linked into a real protected application, so
// (unlike cpp/handoff_spy, a deliberately-independent test double) there is
// no reason to hand-roll its own crypto.

#include "quark_runtime.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "quark/crypto.hpp"
#include "quark/token.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

quark::crypto::AesKey g_content_key{};
uint8_t g_core_enc_key[32] = {0};
std::array<uint8_t, 32> g_session_id{};
std::atomic<uint32_t> g_cp_counter{0};
bool g_initialized = false;

uint32_t ReadU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

void WriteU32LE(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

#if defined(_WIN32)
bool ReadExact(uint8_t* buf, size_t want) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    size_t total = 0;
    while (total < want) {
        DWORD n = 0;
        if (!ReadFile(h, buf + total, static_cast<DWORD>(want - total), &n, NULL) || n == 0) return false;
        total += n;
    }
    return true;
}

bool WriteExact(const uint8_t* buf, size_t len) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    return WriteFile(h, buf, static_cast<DWORD>(len), &written, NULL) && written == len;
}

[[noreturn]] void FailDeadlyExit() { ExitProcess(static_cast<UINT>(-1)); }
#else
bool ReadExact(uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        ssize_t n = read(STDIN_FILENO, buf + total, want - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

bool WriteExact(const uint8_t* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(STDOUT_FILENO, buf + total, len - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

[[noreturn]] void FailDeadlyExit() { _exit(-1); }
#endif

void HeartbeatThread() {
    static const uint8_t kChalMagic[4] = {'C', 'H', 'A', 'L'};

    for (;;) {
        uint8_t chal[40] = {0};
        if (!ReadExact(chal, 40)) FailDeadlyExit();
        if (std::memcmp(chal, kChalMagic, 4) != 0) FailDeadlyExit();

        uint32_t counter = ReadU32LE(chal + 4);
        std::array<uint8_t, 32> nonce{};
        std::memcpy(nonce.data(), chal + 8, 32);

        quark::crypto::Sha256Digest mac =
            quark::token::DeriveChallengeMac(g_content_key, g_session_id, counter, nonce);

        if (!WriteExact(mac.data(), 32)) FailDeadlyExit();
    }
}

}  // namespace

extern "C" {

int quark_init(void) {
    static const uint8_t kInitMagic[4] = {'Q', 'K', 'H', '2'};

    uint8_t frame[136] = {0};
    if (!ReadExact(frame, 136)) return 0;

    if (std::memcmp(frame, kInitMagic, 4) != 0) return 0;
    uint32_t ver = ReadU32LE(frame + 4);
    if (ver != 2) return 0;

    quark::crypto::AesKey handoff_secret{};
    std::memcpy(handoff_secret.data(), frame + 8, 32);
    std::memcpy(g_session_id.data(), frame + 40, 32);
    // frame+72 = initial_seal (not verified here -- see HANDOFF_PROTOCOL.md)
    std::memcpy(g_core_enc_key, frame + 104, 32);

    g_content_key = quark::token::DeriveContentKey(handoff_secret);

    quark::crypto::SecureZero(frame, 136);
    g_initialized = true;
    return 1;
}

void quark_heartbeat_start(void) {
    if (!g_initialized) return;
    std::thread(HeartbeatThread).detach();
}

int64_t quark_checkpoint(int32_t id) {
    if (!g_initialized) return 0;

    uint32_t cnt = g_cp_counter.fetch_add(1);

    uint8_t msg[10];
    std::memcpy(msg, "CP", 2);
    WriteU32LE(msg + 2, static_cast<uint32_t>(id));
    WriteU32LE(msg + 6, cnt);

    quark::crypto::Sha256Digest mac = quark::crypto::HmacSha256(
        g_content_key.data(), g_content_key.size(), msg, sizeof(msg));

    int64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= static_cast<int64_t>(mac[i] & 0xFF) << (i * 8);
    }
    return v;
}

const uint8_t* quark_core_enc_key(void) {
    return g_initialized ? g_core_enc_key : NULL;
}

}  // extern "C"
