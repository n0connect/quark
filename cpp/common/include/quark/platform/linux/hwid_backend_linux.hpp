#pragma once
// Linux implementation of quark::platform::IHwidBackend.
//
// Field selection, same philosophy as Windows (quark/hwid.hpp) and macOS
// (quark/platform/macos/hwid_backend_macos.hpp) -- independent, low-level,
// hard-to-spoof sources -- but adapted to what an *unprivileged* process can
// actually read on Linux, which is a real constraint the other two platforms
// don't have in the same way:
//
//   - /sys/class/dmi/id/product_uuid and board_serial/product_serial are
//     kernel-enforced root-only (mode 0400) on stock distributions -- unlike
//     Windows' SMBIOS reads (unprivileged via GetSystemFirmwareTable) or
//     macOS's IOPlatformUUID (unprivileged via IOKit). Requiring root would
//     mean either running DRM_Wrapper elevated (a strictly worse security
//     posture than Windows' deliberately-unprivileged design, CLAUDE.md's
//     registry witness rationale) or a setuid helper (a meaningfully larger
//     attack surface addition). Given that trade-off, this backend
//     deliberately uses only the *world-readable* DMI fields
//     (board_vendor/name/version, product_name/version, bios_vendor/version/
//     date, chassis_vendor/type) and does not attempt product_uuid.
//   - DMI/SMBIOS itself is an x86-firmware convention; bare-metal ARM Linux
//     without UEFI (e.g. Raspberry Pi) has no /sys/class/dmi/id at all. This
//     backend requires it to be present (fail-deadly if absent, per
//     Collect()'s "partial fingerprint rejected outright" rule) -- it is
//     scoped to x86_64 (and UEFI-booted ARM) Linux, matching where Linux
//     desktop/gaming software actually runs today. A bare-metal-ARM backend
//     would need a different field set and is out of scope here.
//   - /etc/machine-id (falling back to /var/lib/dbus/machine-id) is the
//     closest Linux analogue of Windows' registry MachineGuid: systemd
//     creates it once at first boot, and -- like MachineGuid -- a from-
//     scratch OS reinstall regenerates it, which this project treats as
//     "different machine" for licensing purposes (same policy as Windows).
//
// Hardened beyond the initial cut with: every non-virtual NIC's MAC (not
// just the first), chassis_vendor/chassis_type (a fourth world-readable DMI
// field), total physical memory from /proc/meminfo (a coarse analogue of
// Windows' per-DIMM ram_fingerprint -- real per-slot SPD data needs
// `dmidecode --type 17`, root-only for the same reason product_uuid is
// skipped), and a storage-topology fingerprint from /sys/block (model+size
// per attached, non-virtual block device -- not a real serial, which also
// needs elevated privileges via SG_IO, but still a real fact that changes if
// a drive is added, removed, or swapped for a different model).

#include "quark/platform/hwid_backend.hpp"

namespace quark::platform::linux_ {

// Trailing underscore: `linux` is a predefined macro on Linux toolchains
// (historically for `#if defined(linux)` portability checks) and can't be
// used as a namespace name without `-std=c++2a`-style pitfalls on some
// compilers; `linux_` sidesteps it entirely rather than fighting the macro.
class LinuxHwidBackend final : public IHwidBackend {
public:
    std::optional<Fingerprint> Collect() const override;
    std::string_view PlatformName() const override { return "linux"; }
};

}  // namespace quark::platform::linux_
