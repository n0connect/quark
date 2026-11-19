#include "quark/platform/linux/anti_debug_linux.hpp"

#include <fstream>
#include <string>
#include <string_view>

namespace quark::platform::linux_ {

bool DebuggerDetected() {
    std::ifstream status("/proc/self/status");
    if (!status) {
        return false;  // couldn't read our own status -- not itself suspicious enough to fail-deadly on
    }

    std::string line;
    constexpr std::string_view kPrefix = "TracerPid:";
    while (std::getline(status, line)) {
        if (line.rfind(kPrefix, 0) != 0) continue;
        std::string value = line.substr(kPrefix.size());
        try {
            return std::stoi(value) != 0;
        } catch (...) {
            return false;  // malformed field -- not itself a signal
        }
    }
    return false;
}

}  // namespace quark::platform::linux_
