#pragma once
// Cross-process mutual exclusion around a single license's unlock+roll
// sequence.
//
// Found via real concurrent-launch testing (see docs/PLAN.md's robustness-
// testing phase): quark::state::Load/Save and IWitnessStore::Load/Save have
// no locking of their own, so two DRM_Wrapper launches racing on the same
// state.bin can both Load() the same pre-roll anchor, both independently
// verify the SAME single-use key against it, and both roll+persist -- a
// real license clone under concurrent execution, not merely a theoretical
// TOCTOU. quark::orchestrator::RunUnlockFlow now acquires an IProcessLock
// (if the caller supplies one) before touching state.bin at all, and
// releases it on every return path, so only one caller at a time can ever
// be inside the read-verify-roll sequence for a given license.
//
// Advisory file locking is inherently OS-specific (flock/fcntl vs
// LockFileEx) -- like IHwidBackend/IWitnessStore, this lives behind a
// portable interface quark_core can depend on without itself calling an OS
// API (CLAUDE.md: quark_core has zero Win32/POSIX-specific calls).

#include <string>

namespace quark::platform {

class IProcessLock {
public:
    virtual ~IProcessLock() = default;

    // Blocks until this process holds an exclusive lock associated with
    // `path` (conventionally the license's state.bin path -- the actual
    // lock is taken on a sibling file, e.g. "state.bin.lock", never on the
    // license file itself). Returns false only on a genuine OS-level
    // failure (e.g. the lock file cannot be created/opened) -- never as a
    // "someone else holds it" signal, since a concurrent holder is expected
    // to be waited out, not treated as an error.
    virtual bool Acquire(const std::string& path) = 0;

    // Releases a lock previously acquired by Acquire(). Safe to call even
    // if Acquire() was never called or already failed (a no-op in that
    // case) -- callers use this unconditionally in a scope-exit guard.
    virtual void Release() = 0;
};

}  // namespace quark::platform
