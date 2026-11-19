#pragma once
// Hardware fingerprint collection -- the single source of truth for "what
// machine is this". Both HWID_Extractor (exports it for the dev to bind a
// license to) and DRM_Wrapper (re-derives it locally and feeds it straight
// into AES-GCM as AAD / KDF input, see quark::token) MUST produce
// byte-identical output for identical hardware, and MUST change if *any*
// listed component changes. Keep CanonicalBytes() deterministic: fixed field
// order, fixed casing/encoding, no locale-dependent formatting, no
// allocation-order-dependent enumeration (e.g. RAM slots are sorted by
// physical handle before serialization).
//
// Components are deliberately drawn from low-level, hard-to-spoof sources
// (raw CPUID, raw SMBIOS tables, raw storage/volume queries, raw DXGI
// adapter enumeration, the registry) -- never WMI, which normalizes/caches/
// virtualizes values far more readily. Sixteen independent sources means an
// attacker has to simultaneously fake CPU topology, five separate SMBIOS
// table types, every attached disk (not just the boot one), the GPU, two
// independent storage identifiers, the network stack, and two separate
// registry-held identifiers to reproduce one fingerprint -- each
// individually spoofable, all sixteen in lockstep is a much taller order,
// and any single slip changes CanonicalBytes() completely (SHA-256
// avalanche), which is exactly what the AEAD layer needs.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace quark::hwid {

struct Components {
    // --- Processor -----------------------------------------------------
    std::string cpu_vendor_signature;  // CPUID leaf 0 vendor string + leaf 1 family/model/stepping (hex)
    std::string cpu_brand;             // CPUID leaves 0x80000002-4: full marketing brand string
    uint32_t cpu_logical_cores = 0;    // CPUID leaf 1 EBX[23:16]: logical processor count

    // --- Motherboard / firmware (SMBIOS) --------------------------------
    std::string board_uuid;            // Type 1 (System Information): UUID
    std::string board_manufacturer;    // Type 2 (Base Board): manufacturer + product + version + serial
    std::string bios_identity;         // Type 0 (BIOS Information): vendor + version + release date
    std::string chassis_identity;      // Type 3 (Chassis Information): manufacturer + type + serial + asset tag
    std::string processor_identity;    // Type 4 (Processor Information): socket designation + mfr + version + serial + asset tag -- firmware-reported strings, independent of the CPUID leaves above

    // --- Memory (SMBIOS Type 17, one entry per populated slot) ----------
    std::string ram_fingerprint;       // sorted, per-slot: locator|manufacturer|part_number|serial|size|speed

    // --- Storage ---------------------------------------------------------
    std::string system_disk_serial;    // IOCTL_STORAGE_QUERY_PROPERTY serial of the boot physical drive
    std::string system_volume_serial;  // GetVolumeInformation serial of the system volume (hex)
    std::string all_disk_serials;      // sorted, every \\.\PhysicalDriveN's serial -- not just the boot disk; swapping/adding/removing ANY attached drive changes this

    // --- Graphics ----------------------------------------------------------
    std::string gpu_fingerprint;       // sorted, every DXGI adapter: vendor_id|device_id|subsys_id|revision (raw PCI IDs via DXGI, not WMI's Win32_VideoController)

    // --- Network ----------------------------------------------------------
    std::string mac_address;           // first non-virtual NIC's permanent MAC, colon-free hex, uppercase

    // --- OS install identity ----------------------------------------------
    std::string machine_guid;          // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    std::string windows_product_id;    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId -- a second, independently-generated OS-install identifier alongside MachineGuid
};

// Field order used by both CanonicalBytes and ToJson/FromJson -- defined once
// so the two can never silently diverge.
inline constexpr const char* kFieldOrder[] = {
    "cpu_vendor_signature", "cpu_brand", "cpu_logical_cores",
    "board_uuid", "board_manufacturer", "bios_identity", "chassis_identity", "processor_identity",
    "ram_fingerprint",
    "system_disk_serial", "system_volume_serial", "all_disk_serials",
    "gpu_fingerprint",
    "mac_address",
    "machine_guid", "windows_product_id",
};

// Collects every component from the live machine. Returns nullopt if ANY
// component cannot be read -- a partial fingerprint is worse than none (it
// would let an attacker stabilize the parts they can spoof while the rest
// silently reads as empty). Callers must treat nullopt as fail-deadly.
std::optional<Components> Collect();

// Deterministic, order-fixed byte serialization of `Components`, suitable for
// (a) hashing into a stable identifier and (b) feeding directly as AES-GCM AAD
// / KDF input. Format: UTF-8 fields joined with '\x1F' (ASCII Unit Separator)
// in `kFieldOrder`. Changing a single character of any field -- a RAM stick
// swapped for a same-capacity one with a different serial, a re-imaged disk
// with a new volume serial, a NIC replaced -- produces a completely different
// digest (SHA-256 avalanche), which is what makes the AAD check a hard wall
// rather than a fuzzy "close enough" comparison.
std::vector<uint8_t> CanonicalBytes(const Components& c);

// Human-readable JSON rendering -- what HWID_Extractor.exe writes to disk for
// the developer to inspect / paste into Dev_Keygen. Field order matches
// kFieldOrder for auditability, but JSON itself is NOT used as AAD
// (CanonicalBytes is -- JSON whitespace/escaping would make the AAD fragile
// to formatting rather than to hardware identity).
std::string ToJson(const Components& c);

// Inverse of ToJson -- Dev_Keygen reads the extractor's output back in.
std::optional<Components> FromJson(const std::string& json);

}  // namespace quark::hwid
