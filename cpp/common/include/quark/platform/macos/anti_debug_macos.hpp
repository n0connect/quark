#pragma once
// macOS debugger-presence speed bump -- the sysctl(KERN_PROC) equivalent of
// cpp/drm_wrapper/anti_debug.hpp's PEB reads. Same posture as the Windows
// check: a determined attacker with a kernel extension defeats this, the
// point is gating the casual "attach lldb and step through the key check"
// path so it hits FailDeadly() instead of a conveniently observable branch.
// Detection feeds straight into fail-deadly, never into a message or a
// distinguishable code path (CLAUDE.md rule 5).

namespace quark::platform::macos {

// True if this process is currently being traced (lldb/gdb attached, or
// ptrace(PT_TRACE_ME) already claimed by another tracer) -- reads the P_TRACED
// flag out of this process's own kinfo_proc via sysctl(CTL_KERN, KERN_PROC,
// KERN_PROC_PID, getpid()), the same real kernel-reported state `ps -O flags`
// and Activity Monitor ultimately read.
bool DebuggerDetected();

}  // namespace quark::platform::macos
