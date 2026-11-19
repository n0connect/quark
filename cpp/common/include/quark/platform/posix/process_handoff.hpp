#pragma once
// POSIX process/pipe handoff -- the fork+exec+pipe(2) equivalent of
// cpp/drm_wrapper/handoff.hpp's Win32 CreateProcess + anonymous-pipe design.
// Shared between the macOS and Linux orchestrators (quark_platform_posix,
// linked by both quark_platform_macos and quark_platform_linux) since fork,
// pipe, and exec are identical POSIX calls on both -- CLAUDE.md's
// cross-platform strategy calls this the case worth sharing rather than
// duplicating twice: it is genuinely OS-specific code (quark_core cannot
// touch it), but not genuinely *per-OS-different* the way HWID collection is.
//
// Same wire protocol as Windows (QKH2, quark/handoff.hpp): two pipes,
//   parent write-end (kept OPEN) -> child stdin
//   child stdout -> parent read-end
// The initial frame is written once; a "CHAL" frame is sent every ~30s and a
// 32-byte HMAC response is read back with a 10s timeout. Neither process can
// outlive the other: a dead child makes the next challenge write fail
// (SIGPIPE is ignored so this surfaces as EPIPE, not process death), and the
// Java side's QuarkHeartbeat thread detects EOF on its stdin exactly like the
// Windows build's broken-pipe check.

#include <sys/types.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::platform::posix {

struct JvmSession {
    pid_t pid = -1;
    int stdin_write_fd = -1;   // kept open; challenge frames are written here
    int stdout_read_fd = -1;   // HMAC responses are read from here
    bool reaped = false;       // true once RunChallengeLoop has waitpid()'d the child
    int wait_status = 0;       // raw waitpid() status, valid iff `reaped`
};

// Forks and execs `path` with `argv` (argv[0] conventionally repeats `path`,
// matching C convention). Wires the child's stdin/stdout to the two pipes
// described above, writes `initial_frame` into the child's stdin without
// closing the write end, and returns the live session.
//
// Any failure here (pipe(2), fork(2), or the initial write) reports through
// quark::error::Report(code, component) and terminates via std::exit(1) --
// the same fail-deadly funnel every other Quark failure path uses; this is
// not a function callers are expected to recover from.
JvmSession LaunchWithInitialHandoff(const std::string& component,
                                     const std::string& path,
                                     const std::vector<std::string>& argv,
                                     const std::vector<uint8_t>& initial_frame);

// Blocks until the child exits (normally, or is killed after a failed
// challenge). Mirrors Windows' RunChallengeLoop exactly: every
// `challenge_interval_ms` sends a CHAL frame, waits up to
// `response_timeout_ms` for a 32-byte HMAC response, verifies it
// constant-time. Any failure -> SIGKILL the child, reap it, return. Sets
// `session.reaped`/`session.wait_status` so WaitAndGetExitCode below never
// double-waits a child this function already reaped.
//
// Defaults (30s/10s) match the original hardcoded values; CLAUDE.md rule 2
// -- the real caller (DRM_Wrapper's main.cpp) sources both from config
// instead of leaving them fixed. The defaults exist for callers that don't
// care (e.g. quick manual invocations), not to encourage skipping config.
void RunChallengeLoop(JvmSession& session,
                       const crypto::AesKey& content_key,
                       const std::array<uint8_t, 32>& session_id,
                       int challenge_interval_ms = 30'000,
                       int response_timeout_ms = 10'000);

// Returns the child's exit code (WEXITSTATUS), or 1 if it died from a signal
// or was never cleanly reaped. Safe to call whether or not RunChallengeLoop
// already reaped the child.
int WaitAndGetExitCode(JvmSession& session);

}  // namespace quark::platform::posix
