#include "quark/platform/windows/process_lock_win.hpp"

namespace quark::platform::win {

LockFileProcessLock::~LockFileProcessLock() { Release(); }

bool LockFileProcessLock::Acquire(const std::string& path) {
    const std::string lock_path = path + ".lock";
    handle_ = CreateFileA(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
        handle_ = nullptr;
        return false;
    }

    // Lock the whole file, blocking (no LOCKFILE_FAIL_IMMEDIATELY) until any
    // other holder releases it -- the same "wait it out" semantics
    // IProcessLock::Acquire documents. OVERLAPPED is required by the API
    // even for a synchronous, whole-file lock; zero-initialized means "no
    // offset, no event" (LockFileEx ignores hEvent for a synchronous call).
    OVERLAPPED overlapped{};
    if (!LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped)) {
        CloseHandle(handle_);
        handle_ = nullptr;
        return false;
    }
    return true;
}

void LockFileProcessLock::Release() {
    if (handle_ != nullptr) {
        OVERLAPPED overlapped{};
        UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &overlapped);
        CloseHandle(handle_);
        handle_ = nullptr;
    }
}

}  // namespace quark::platform::win
