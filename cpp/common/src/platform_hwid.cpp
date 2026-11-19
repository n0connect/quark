#include "quark/platform/hwid_backend.hpp"

namespace quark::platform {

std::vector<uint8_t> CanonicalBytes(const Fingerprint& fp) {
    std::string joined;
    for (const auto& field : fp.fields) {
        if (!joined.empty()) joined.push_back('\x1F');
        joined += field.value;
    }
    return std::vector<uint8_t>(joined.begin(), joined.end());
}

}  // namespace quark::platform
