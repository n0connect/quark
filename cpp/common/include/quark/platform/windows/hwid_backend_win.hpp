#pragma once
// Windows implementation of quark::platform::IHwidBackend. A thin adapter --
// all the actual collection logic stays in quark::hwid (SMBIOS/CPUID/
// registry/iphlpapi reads, see quark/hwid.hpp); this class only reshapes
// quark::hwid::Components into the OS-agnostic quark::platform::Fingerprint
// shape, in the same kFieldOrder, so DRM_Wrapper's orchestration logic can be
// written against IHwidBackend without knowing Windows-specific field names.

#include "quark/platform/hwid_backend.hpp"

namespace quark::platform::win {

class WindowsHwidBackend final : public IHwidBackend {
public:
    std::optional<Fingerprint> Collect() const override;
    std::string_view PlatformName() const override { return "windows"; }
};

}  // namespace quark::platform::win
