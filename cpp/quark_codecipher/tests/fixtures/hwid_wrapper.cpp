// Forces the linker to pull MacHwidBackend::Collect() into this dylib, and
// gives us a real, simple-signature entry point (CollectHwidCanonical) that
// internally does a real virtual dispatch into real, unmodified HWID
// collection code (sysctlbyname, IOKit, DiskArbitration, CoreFoundation).
#include <cstring>

#include "quark/platform/macos/hwid_backend_macos.hpp"

extern "C" int CollectHwidCanonical(unsigned char* out_buf, int out_buf_cap) {
    quark::platform::macos::MacHwidBackend backend;
    auto fp = backend.Collect();
    if (!fp) return -1;
    auto bytes = quark::platform::CanonicalBytes(*fp);
    int n = static_cast<int>(bytes.size());
    if (n > out_buf_cap) return -2;
    std::memcpy(out_buf, bytes.data(), static_cast<size_t>(n));
    return n;
}
