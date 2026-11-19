#pragma once
// Lightweight, dependency-free debugger checks. These are speed bumps, not a
// silver bullet (a determined attacker with a kernel driver defeats all of
// them) -- the point is to gate the *unlock* path specifically, so casual
// "attach WinDbg and step through the key check" attempts hit FailDeadly()
// instead of a conveniently observable branch.
//
// Per CLAUDE.md: detection feeds straight into FailDeadly(), never into a
// message or a distinguishable code path.

#include <cstddef>

#include <windows.h>
#include <intrin.h>

namespace quark::drm_wrapper {

namespace detail {

// Raw byte offsets into the PEB. Deliberately NOT reading these two fields
// through <winternl.h>'s `_PEB` struct -- its public definition is
// partial/version-dependent across SDKs (NtGlobalFlag in particular isn't
// even named in it, only reachable as reserved padding), and a field that
// resolves to the wrong offset would silently read garbage rather than fail
// to compile. These offsets (BeingDebugged @ 0x02, NtGlobalFlag @ 0xBC) are
// part of the PEB's stable, documented layout. If a future SDK ever changes
// them, we'd rather a reviewer re-derive and update these two constants
// deliberately than trust a struct neither side fully controls.
constexpr size_t kPebBeingDebuggedOffset = 0x02;
constexpr size_t kPebNtGlobalFlagOffset = 0xBC;

inline BYTE* CurrentPeb() {
    // gs:[0x30] is TEB->Self on x64; TEB->ProcessEnvironmentBlock sits at
    // offset 0x60 within it. This is the canonical, fast, no-syscall way to
    // reach the PEB from user mode on the Windows/x64 target this project
    // builds for (CLAUDE.md: MSVC /MT, x64 only).
    return reinterpret_cast<BYTE*>(__readgsqword(0x60));
}

}  // namespace detail

inline bool DebuggerDetected() {
    if (IsDebuggerPresent()) return true;

    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) return true;

    BYTE* peb = detail::CurrentPeb();
    if (peb == nullptr) return false;  // could not locate PEB -- not itself suspicious enough to fail-deadly on

    // PEB.BeingDebugged -- catches some IsDebuggerPresent hooks that patch the
    // exported function but leave the underlying PEB flag alone.
    if (*(peb + detail::kPebBeingDebuggedOffset) != 0) return true;

    // NtGlobalFlag heap flags (FLG_HEAP_ENABLE_TAIL_CHECK |
    // FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS == 0x70) are
    // set by the loader when a process is started under a debugger.
    constexpr DWORD kDebugHeapFlags = 0x70;
    DWORD nt_global_flag = *reinterpret_cast<DWORD*>(peb + detail::kPebNtGlobalFlagOffset);
    if ((nt_global_flag & kDebugHeapFlags) == kDebugHeapFlags) return true;

    return false;
}

}  // namespace quark::drm_wrapper
