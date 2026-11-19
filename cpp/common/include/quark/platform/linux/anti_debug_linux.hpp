#pragma once
// Linux debugger-presence speed bump -- the /proc/self/status equivalent of
// cpp/drm_wrapper/anti_debug.hpp's PEB reads. Same posture as the Windows and
// macOS checks: gates the casual "attach gdb/strace and step through the key
// check" path, not a defense against a determined kernel-level attacker.
// Detection feeds straight into fail-deadly (CLAUDE.md rule 5).

namespace quark::platform::linux_ {

// True if this process currently has a tracer attached (gdb/strace, or
// ptrace(PTRACE_ATTACH) from any process) -- reads the kernel-reported
// TracerPid field from /proc/self/status, which the kernel sets to the
// tracer's PID (0 if untraced) regardless of which tool attached.
bool DebuggerDetected();

}  // namespace quark::platform::linux_
