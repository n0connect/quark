#pragma once
// POSIX flock(2)-based IProcessLock -- identical code on macOS and Linux
// (both are genuine POSIX flock implementations, not an emulation), so this
// is shared between quark_platform_macos and quark_platform_linux exactly
// like process_handoff.cpp already is. See quark/platform/process_lock.hpp
// for why this exists and why it lives behind an interface rather than in
// quark_core directly.

#include "quark/platform/process_lock.hpp"

namespace quark::platform::posix {

class FlockProcessLock final : public IProcessLock {
public:
    ~FlockProcessLock() override;

    // Opens (creating if needed) `path + ".lock"` and blocks on flock(LOCK_EX)
    // -- a *cooperative* lock: another process racing on the same license
    // must also go through IProcessLock to be excluded, exactly what
    // RunUnlockFlow does. Returns false only if the lock file itself cannot
    // be opened (e.g. read-only directory), never because another holder
    // has it (that case blocks instead, by design -- see the header comment
    // on IProcessLock::Acquire).
    bool Acquire(const std::string& path) override;

    // Unlocks and closes the fd. Safe to call unconditionally (e.g. from a
    // scope-exit guard) even if Acquire() was never called or failed.
    void Release() override;

private:
    int fd_ = -1;
};

}  // namespace quark::platform::posix
