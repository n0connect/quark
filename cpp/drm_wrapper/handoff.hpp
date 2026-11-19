#pragma once
// QKH2 launch and challenge-response loop.
//
// Architecture change from v1: DRM_Wrapper.exe stays alive for the entire Java
// session. Two anonymous pipes are created:
//
//   stdin_write  (parent write end, kept OPEN) → Java's stdin
//   stdout_read  (parent read end)             ← Java's stdout
//
// After the QKH2 initial frame is written, DRM_Wrapper enters RunChallengeLoop:
// every ~30 s it sends a "CHAL" frame, then reads and verifies a 32-byte HMAC
// response from Java's stdout. Failure to respond within 10 s, or a wrong HMAC,
// causes TerminateProcess on the child.
//
// Java's QuarkHeartbeat thread detects a broken stdin pipe (parent death via
// ReadFile failure) and calls Runtime.getRuntime().halt(-1). Neither process can
// outlive the other -- mutual assured destruction by pipe coupling.
//
// Anonymous pipes are used (not named) for the same reason as v1: no name to
// enumerate, no ACL to misconfigure, handles are only ever visible to the two
// processes created in this one CreateProcess call.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/error.hpp"
#include "quark/handoff.hpp"
#include "quark/token.hpp"
#include "fail_deadly.hpp"

namespace quark::drm_wrapper {

// RAII for a Windows HANDLE -- closes on scope exit, never double-closes.
class ScopedHandle {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) : handle_(h) {}
    ~ScopedHandle() { Reset(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : handle_(other.Release()) {}
    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            handle_ = other.Release();
        }
        return *this;
    }

    HANDLE Get() const { return handle_; }
    bool Valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    HANDLE Release() {
        HANDLE h = handle_;
        handle_ = nullptr;
        return h;
    }

    void Reset(HANDLE h = nullptr) {
        if (Valid()) CloseHandle(handle_);
        handle_ = h;
    }

private:
    HANDLE handle_ = nullptr;
};

// Holds the live handles for an ongoing JVM session.
struct JvmSession {
    ScopedHandle process;
    ScopedHandle stdin_write;   // kept open; challenge frames are written here
    ScopedHandle stdout_read;   // HMAC responses are read from here
};

// ─── helpers ─────────────────────────────────────────────────────────────────

// Reads exactly 32 bytes from `pipe` within `timeout_ms`.  Uses PeekNamedPipe
// + polling; anonymous pipes do not support overlapped I/O.  Returns false on
// timeout or any pipe error.
inline bool ReadResponseWithTimeout(HANDLE pipe, uint8_t* buf32, DWORD timeout_ms) {
    const DWORD deadline = GetTickCount() + timeout_ms;
    DWORD total = 0;
    while (total < 32) {
        DWORD avail = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr)) return false;
        if (avail > 0) {
            DWORD want = (avail > 32 - total) ? (32 - total) : avail;
            DWORD n = 0;
            if (!ReadFile(pipe, buf32 + total, want, &n, nullptr) || n == 0) return false;
            total += n;
        } else {
            if (GetTickCount() >= deadline) return false;
            Sleep(20);
        }
    }
    return true;
}

// ─── launch ──────────────────────────────────────────────────────────────────

// Launches `jvm_path` / `command_line` with two pipes:
//   • stdin_pipe  read-end  → child stdin  (parent holds write-end open for challenges)
//   • stdout_pipe write-end → child stdout (parent holds read-end for responses)
// Writes `initial_frame` (QKH2, 104 bytes) into stdin WITHOUT closing the
// write end -- the pipe stays live for subsequent challenge frames.
// Returns a JvmSession holding the process handle and both parent pipe ends.
// Any WinAPI failure -> FailDeadly(kWrapperPipeSetupFailed / kWrapperProcessLaunchFailed).
inline JvmSession LaunchJvmWithInitialHandoff(const std::wstring& jvm_path,
                                               const std::wstring& command_line,
                                               const std::vector<uint8_t>& initial_frame) {
    SECURITY_ATTRIBUTES inheritable{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};

    // stdin pipe: read-end inheritable (child stdin), write-end NOT (parent keeps)
    HANDLE stdin_read_raw = nullptr, stdin_write_raw = nullptr;
    if (!CreatePipe(&stdin_read_raw, &stdin_write_raw, &inheritable, 0))
        FailDeadly(quark::error::Code::kWrapperPipeSetupFailed);
    ScopedHandle stdin_read(stdin_read_raw);
    ScopedHandle stdin_write(stdin_write_raw);
    if (!SetHandleInformation(stdin_write.Get(), HANDLE_FLAG_INHERIT, 0))
        FailDeadly(quark::error::Code::kWrapperPipeSetupFailed);

    // stdout pipe: write-end inheritable (child stdout), read-end NOT (parent keeps)
    HANDLE stdout_read_raw = nullptr, stdout_write_raw = nullptr;
    if (!CreatePipe(&stdout_read_raw, &stdout_write_raw, &inheritable, 0))
        FailDeadly(quark::error::Code::kWrapperPipeSetupFailed);
    ScopedHandle stdout_read(stdout_read_raw);
    ScopedHandle stdout_write(stdout_write_raw);
    if (!SetHandleInformation(stdout_read.Get(), HANDLE_FLAG_INHERIT, 0))
        FailDeadly(quark::error::Code::kWrapperPipeSetupFailed);

    STARTUPINFOW startup{};
    startup.cb          = sizeof(startup);
    startup.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput   = stdin_read.Get();
    startup.hStdOutput  = stdout_write.Get();
    startup.hStdError   = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION proc_info{};
    std::vector<wchar_t> cmd(command_line.begin(), command_line.end());
    cmd.push_back(L'\0');

    BOOL ok = CreateProcessW(
        jvm_path.empty() ? nullptr : jvm_path.c_str(),
        cmd.data(),
        nullptr, nullptr,
        /*bInheritHandles=*/TRUE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &startup, &proc_info);

    if (!ok) FailDeadly(quark::error::Code::kWrapperProcessLaunchFailed);

    ScopedHandle thread_handle(proc_info.hThread);
    ScopedHandle process_handle(proc_info.hProcess);

    // Parent doesn't need the child-facing ends after CreateProcess.
    stdin_read.Reset();
    stdout_write.Reset();

    // Write QKH2 initial frame -- leave stdin_write OPEN for challenge frames.
    DWORD written = 0;
    BOOL wrote_ok = WriteFile(stdin_write.Get(), initial_frame.data(),
                              static_cast<DWORD>(initial_frame.size()), &written, nullptr);
    if (!wrote_ok || written != static_cast<DWORD>(initial_frame.size()))
        FailDeadly(quark::error::Code::kWrapperHandoffWriteFailed);

    return JvmSession{
        std::move(process_handle),
        std::move(stdin_write),
        std::move(stdout_read),
    };
}

// ─── challenge loop ───────────────────────────────────────────────────────────

// Blocks until the Java process exits (normally or via TerminateProcess).
// Every `challenge_interval_ms`: sends a "CHAL" frame, waits
// `response_timeout_ms` for Java's HMAC response, verifies it. Any failure
// -> TerminateProcess + return. content_key and session_id are the values
// from the QKH2 initial frame.
//
// Defaults (30s/10s) match the original hardcoded values; CLAUDE.md rule 2
// -- main.cpp sources both from config instead of leaving them fixed.
inline void RunChallengeLoop(JvmSession& session,
                              const crypto::AesKey& content_key,
                              const std::array<uint8_t, 32>& session_id,
                              DWORD challenge_interval_ms = 30'000,
                              DWORD response_timeout_ms = 10'000) {
    uint32_t counter = 0;

    while (true) {
        // Wait for the challenge interval, or until Java exits.
        DWORD wait = WaitForSingleObject(session.process.Get(), challenge_interval_ms);
        if (wait == WAIT_OBJECT_0) return;  // Java exited normally -- clean exit path

        // Generate a fresh nonce.
        auto rand_bytes = crypto::RandomBytes(32);
        std::array<uint8_t, 32> nonce{};
        for (size_t i = 0; i < 32; ++i) nonce[i] = rand_bytes[i];

        // Send challenge.
        auto challenge = quark::handoff::EncodeChallengeFrame(counter, nonce);
        DWORD wr = 0;
        BOOL wrote = WriteFile(session.stdin_write.Get(), challenge.data(),
                               static_cast<DWORD>(challenge.size()), &wr, nullptr);
        if (!wrote || wr != static_cast<DWORD>(challenge.size())) {
            TerminateProcess(session.process.Get(), 1);
            WaitForSingleObject(session.process.Get(), INFINITE);
            crypto::SecureZero(nonce.data(), nonce.size());
            return;
        }

        // Read response with timeout.
        std::array<uint8_t, 32> response{};
        if (!ReadResponseWithTimeout(session.stdout_read.Get(), response.data(),
                                     response_timeout_ms)) {
            TerminateProcess(session.process.Get(), 1);
            WaitForSingleObject(session.process.Get(), INFINITE);
            crypto::SecureZero(nonce.data(), nonce.size());
            crypto::SecureZero(response.data(), response.size());
            return;
        }

        // Constant-time verification.
        auto expected = quark::token::DeriveChallengeMac(content_key, session_id, counter, nonce);
        uint8_t diff = 0;
        for (size_t i = 0; i < 32; ++i) diff |= response[i] ^ expected[i];

        crypto::SecureZero(nonce.data(), nonce.size());
        crypto::SecureZero(response.data(), response.size());
        crypto::SecureZero(expected.data(), expected.size());

        if (diff != 0) {
            TerminateProcess(session.process.Get(), 1);
            WaitForSingleObject(session.process.Get(), INFINITE);
            return;
        }

        ++counter;
    }
}

}  // namespace quark::drm_wrapper
