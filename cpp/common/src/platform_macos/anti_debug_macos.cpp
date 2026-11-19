#include "quark/platform/macos/anti_debug_macos.hpp"

#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

namespace quark::platform::macos {

bool DebuggerDetected() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info {};
    size_t size = sizeof(info);

    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) {
        return false;  // couldn't read our own process info -- not itself suspicious enough to fail-deadly on
    }

    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

}  // namespace quark::platform::macos
