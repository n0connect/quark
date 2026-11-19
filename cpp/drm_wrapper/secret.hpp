#pragma once
// Build-time constants for DRM_Wrapper. Both kBuildSecret and kEcPublicKey are
// generated once by `Dev_Keygen --setup` and pasted here before any real build.
//
// *** REPLACE ALL PLACEHOLDER VALUES BEFORE ANY REAL BUILD. ***
//
// kBuildSecret: generate with `openssl rand -hex 32` (one value per product
//   line -- customer binding comes from HWID; this binds the build).
//
// kEcPublicKey: uncompressed SEC1 P-256 point (0x04 || x[32] || y[32]).
//   Output by `Dev_Keygen --setup`, stored in kpriv.bin (developer side) and
//   embedded here (binary side). The matching private key signs every online-
//   witness paste at issuance time; DRM_Wrapper verifies here. Without K_priv
//   an attacker who extracts kBuildSecret still cannot forge a valid paste.

#include "quark/online.hpp"

namespace quark::drm_wrapper {

// TEST VALUE -- MUST be regenerated before any real/release build.
inline constexpr const char* kBuildSecret =
    "f31add891145c1e328d5ac0839610c47ee1de3f6ecb07a45cad5e40e654de9a5";

// TEST VALUE -- all-zeros placeholder. Run `Dev_Keygen --setup` to generate
// the real keypair, then paste the 65-byte public key here.
inline constexpr quark::online::EcPublicKey kEcPublicKey = {};

}  // namespace quark::drm_wrapper
