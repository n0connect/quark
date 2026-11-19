# Quark Hardware Fingerprint Extractor (`HWID_Extractor`)

`HWID_Extractor` is a lightweight, customer-facing console utility. Customers run it on their target deployment machine to generate a JSON snapshot of their hardware configuration. This JSON output is subsequently sent to the developer, who uses `Dev_Keygen` to mint a hardware-locked license (`state.bin`).

To keep client delivery low-footprint and transparent, the extractor is designed with:
*   **No Cryptographic Keys or Operations**: It is purely an info gatherer.
*   **Plain-text Human-readable Outputs**: The JSON can be verified by the customer before delivery.
*   **Simple Diagnostic Errors**: Provides clear hints if execution fails (e.g. asking to be run as Administrator).

---

## JSON Output Schema

Cross-platform via `quark::platform::IHwidBackend` -- the extractor writes
whichever ordered field list the current OS's backend collects, tagged with
`platform` (`quark::platform::FingerprintToJson`, see
[cpp/common/include/quark/platform/hwid_json.hpp](../common/include/quark/platform/hwid_json.hpp))
so a license-issuing tool can reject a cross-platform mismatch outright
instead of producing a `state.bin` that can never authenticate:

```json
{
  "platform": "macos",
  "fields": [
    {"name": "cpu_brand", "value": "Apple M2"},
    {"name": "cpu_logical_cores", "value": "8"},
    {"name": "cpu_family_ids", "value": "1234567890|16777228|2"},
    {"name": "hw_model", "value": "Mac14,2"},
    {"name": "board_id", "value": "0000000000000000"},
    {"name": "platform_uuid", "value": "00000000-0000-4000-8000-000000000000"},
    {"name": "platform_serial", "value": "EXAMPLE0001"},
    {"name": "physical_memory_bytes", "value": "17179869184"},
    {"name": "boot_volume_uuid", "value": "11111111-2222-4333-8444-555555555555"},
    {"name": "boot_media_uuid", "value": "11111111-2222-4333-8444-555555555555"},
    {"name": "mac_addresses", "value": "001122334455;66778899AABB;..."}
  ]
}
```

The Windows backend produces the same shape with `"platform": "windows"` and
its own 16-field list (CPU/SMBIOS/disk/GPU/registry -- see
[quark/hwid.hpp](../common/include/quark/hwid.hpp)); the Linux backend
produces `"platform": "linux"` with its `/proc` + `/sys/class/dmi` field
list. Field *values* (in collection order) are exactly what
`CanonicalBytes()` hashes/binds as AES-GCM AAD and KDF input elsewhere in
Quark -- the field *names* are structural metadata only.

---

## Usage

### 1. Execute
Run from a command prompt:
```cmd
HWID_Extractor.exe [output_path.json]
```
If no parameter is specified, it defaults to creating `hwid.json` in the current directory.

### 2. Permissions & Failures (Windows)
*   **Run as Administrator**: Gathering low-level BIOS table mappings (SMBIOS) and disk hardware identifiers via `IOCTL_STORAGE_QUERY_PROPERTY` requires administrative privileges on Windows. If run from a standard user prompt, the utility exits with error code `kHwidFieldUnreadable` (see [error.hpp](../common/include/quark/error.hpp)).

On macOS and Linux, `IHwidBackend::Collect()` only reads world-readable
sources (see
[quark/platform/macos/hwid_backend_macos.hpp](../common/include/quark/platform/macos/hwid_backend_macos.hpp) /
[quark/platform/linux/hwid_backend_linux.hpp](../common/include/quark/platform/linux/hwid_backend_linux.hpp))
-- no elevated privileges needed.

---

## Compilation

Cross-platform -- builds with whichever `quark_platform_<os>` target the
current OS provides (Windows SMBIOS/CPUID, macOS sysctl/IOKit/
DiskArbitration, or Linux /proc + /sys/class/dmi):
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target HWID_Extractor
```
Outputs `sandbox/build-host/cpp/hwid_extractor/HWID_Extractor` (or
`HWID_Extractor.exe` on Windows).
