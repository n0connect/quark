#pragma once
// Windows LockFileEx-based IProcessLock. See quark/platform/process_lock.hpp
// for why this exists (a real, demonstrated license-clone race found via
// concurrent-launch testing on macOS) and quark/platform/posix/
// process_lock_posix.hpp for the POSIX sibling this mirrors.
//
// NOT YET VERIFIED ON REAL WINDOWS -- written against the same
// already-documented LockFileEx contract every other Windows-specific file
// in this codebase uses, but per CLAUDE.md rule 1 "should compile" is not
// "verified"; no Windows machine was available when this was written.

#include "quark/platform/process_lock.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace quark::platform::win {

class LockFileProcessLock final : public IProcessLock {
public:
    ~LockFileProcessLock() override;

    // Opens (creating if needed) `path + ".lock"` and blocks on
    // LockFileEx(LOCKFILE_EXCLUSIVE_LOCK) over the whole file -- the
    // Windows equivalent of flock(LOCK_EX), with the same "wait it out,
    // don't treat a concurrent holder as an error" semantics documented on
    // IProcessLock::Acquire.
    bool Acquire(const std::string& path) override;

    // Unlocks and closes the handle. Safe to call unconditionally even if
    // Acquire() was never called or failed.
    void Release() override;

private:
#if defined(_WIN32)
    HANDLE handle_ = nullptr;
#endif
};

}  // namespace quark::platform::win
