#pragma once
// macOS implementation of quark::platform::IHwidBackend.
//
// Field selection follows the same philosophy as the Windows backend
// (quark/hwid.hpp) -- independent, low-level, hard-to-spoof sources, raw
// APIs over shell-outs wherever one exists -- but the *fields themselves*
// differ because Mac hardware doesn't expose the same concepts:
//
//   - No SMBIOS. IOKit's IOPlatformExpertDevice node carries the closest
//     equivalents: IOPlatformUUID (~ Windows board_uuid) and
//     IOPlatformSerialNumber (~ board_manufacturer+serial; this is the
//     machine's actual printed serial number).
//   - No user-upgradable, per-slot RAM on current Apple Silicon Macs
//     (unified memory is soldered) -- hw.memsize (total physical memory) is
//     used as a coarse analogue of ram_fingerprint. This is honestly a
//     weaker signal than Windows' per-DIMM serial list; it is what the
//     hardware actually exposes, and low-level RAM identity simply isn't a
//     thing on this platform the way it is on a PC.
//   - No registry MachineGuid, and -- unlike Windows, where MachineGuid
//     regenerates on a clean reinstall and a reinstall is deliberately
//     treated as "different machine" -- macOS's Hardware UUID is bound to
//     the logic board and survives an OS reinstall. This is a genuine,
//     intentional behavioral difference between the two platforms' licensing
//     semantics, not a gap to paper over: on macOS, "reinstall the OS" does
//     NOT invalidate a license the way it does on Windows.
//   - The boot volume's UUID and the physical media's UUID (via
//     DiskArbitration) play the same two-independent-storage-identifiers
//     role as Windows' system_disk_serial + system_volume_serial.
//
// Hardened beyond the initial cut with: every non-virtual NIC's MAC (not
// just the first), hw.cpufamily/cputype/cpusubtype (a numeric CPU-family
// fact independent of the free-text brand string), and a hardware model
// code from IOPlatformExpertDevice ("board-id" on Intel Macs; verified via
// real `ioreg` inspection that Apple Silicon Macs expose no such key and
// instead carry the equivalent fact as OSData under "target-sub-type" on
// the same node -- this backend tries both). Eleven independent fields total.

#include <optional>
#include <string>
#include <string_view>

#include "quark/platform/hwid_backend.hpp"

namespace quark::platform::macos {

class MacHwidBackend final : public IHwidBackend {
public:
    std::optional<Fingerprint> Collect() const override;
    std::string_view PlatformName() const override { return "macos"; }
};

}  // namespace quark::platform::macos
