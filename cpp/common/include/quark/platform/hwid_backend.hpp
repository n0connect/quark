#pragma once
// Cross-platform hardware-fingerprint contract. quark_core and DRM_Wrapper's
// orchestration logic talk to IHwidBackend only, never to an OS-specific
// collector directly -- this is what lets a Linux or macOS backend be added
// later as a pure addition (one new adapter file + one line wiring it up),
// with zero changes to the unlock flow or to quark_core.
//
// The existing 11-field Windows fingerprint (quark::hwid::Components, see
// quark/hwid.hpp) is ONE implementation of this contract, not the contract
// itself. Other platforms will not have the same 11 fields, because the same
// concepts don't all exist everywhere -- e.g. Windows' registry MachineGuid
// has no literal equivalent on Linux (closest analogue: /etc/machine-id) or
// macOS (closest analogue: IOPlatformUUID, which is arguably closer to
// board_uuid in spirit). Each backend defines whatever *independent,
// hard-to-spoof, low-level* sources its OS actually exposes; CanonicalBytes()
// below only needs a stable, ordered, complete field list to do its job.
//
// A fingerprint minted on one OS is never expected to validate against a
// different OS's backend -- PlatformName() is embedded in exported HWID JSON
// specifically so Dev_Keygen can reject a cross-platform mismatch outright
// instead of producing a state.bin that can never authenticate.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace quark::platform {

// One raw fingerprint component, e.g. {"cpu_vendor_signature", "GenuineIntel:000806EA"}.
struct FingerprintField {
    std::string name;
    std::string value;
};

// A complete, ordered fingerprint. Field order is fixed per backend and must
// never change between two calls to Collect() on the same machine and OS
// build -- CanonicalBytes() depends on that stability for a usable AAD/KDF
// input (CLAUDE.md rule 2).
struct Fingerprint {
    std::vector<FingerprintField> fields;
};

// Deterministic byte serialization: joins each field's *value* (not its
// name -- names are structural metadata, not part of the machine's identity)
// with 0x1F (ASCII Unit Separator), in the order Collect() returned them.
// Intentionally byte-identical to quark::hwid::CanonicalBytes(Components) for
// the same 11 values in the same order, so migrating the Windows backend onto
// this interface later is a representation change, not a cryptographic one --
// no existing state.bin/witness data is invalidated by the switch.
std::vector<uint8_t> CanonicalBytes(const Fingerprint& fp);

class IHwidBackend {
public:
    virtual ~IHwidBackend() = default;

    // Collects every field this backend defines. Returns nullopt if ANY
    // field fails to read -- a partial fingerprint is rejected outright, the
    // same fail-deadly posture as quark::hwid::Collect() (CLAUDE.md rule 2).
    virtual std::optional<Fingerprint> Collect() const = 0;

    // "windows", "linux", "macos", ... -- see file header for why this is
    // embedded rather than inferred.
    virtual std::string_view PlatformName() const = 0;
};

}  // namespace quark::platform
