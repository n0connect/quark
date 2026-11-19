#include "quark/platform/posix/process_lock_posix.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace quark::platform::posix {

FlockProcessLock::~FlockProcessLock() { Release(); }

bool FlockProcessLock::Acquire(const std::string& path) {
    const std::string lock_path = path + ".lock";
    fd_ = open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd_ < 0) return false;

    // Blocks until any other holder (in this or another process) releases
    // it -- exactly the "wait it out" semantics IProcessLock::Acquire
    // documents. flock is per-open-file-description, so this genuinely
    // excludes a concurrent process, not just a concurrent thread.
    if (flock(fd_, LOCK_EX) != 0) {
        close(fd_);
        fd_ = -1;
        return false;
    }
    return true;
}

void FlockProcessLock::Release() {
    if (fd_ >= 0) {
        flock(fd_, LOCK_UN);
        close(fd_);
        fd_ = -1;
    }
}

}  // namespace quark::platform::posix
