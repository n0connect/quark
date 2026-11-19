#pragma once
// Generic AES-256-GCM sealed-payload codec for arbitrary-length application
// data -- the actual protection primitive behind cpp/quark_c_api's
// quark_unlock_and_decrypt(). This generalizes the pattern
// java/drm-core/CoreDecryptor.java already uses for core.enc (decrypt the
// protected payload with a key that only exists if the full DRM flow
// succeeded; a wrong key produces wrong plaintext, not a skippable branch)
// so any language behind the C API gets the same non-negotiable property:
// there is no "quark_unlock_and_decrypt succeeded: true/false" boolean for
// an attacker to patch, because the function's entire output IS the
// decrypted payload -- wrong key material means wrong bytes come out, full
// stop (CLAUDE.md rule 3's "no boolean trap", generalized past the
// Java-specific case it was written for).
//
// No AAD here, unlike quark::witness's codec: the sealing key itself
// (core_enc_key, see quark::token::DeriveCoreEncKey) is already HWID-bound
// and SECRET-bound by construction, so binding the ciphertext to HWID a
// second time via AAD would be redundant complexity for no added guarantee
// (CLAUDE.md rule 3: simple over clever).

#include <cstdint>
#include <optional>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::payload {

// magic(4) + version(u32 LE) + iv(12) + tag(16) + ct_len(u32 LE) + ciphertext
std::vector<uint8_t> Seal(const crypto::AesKey& key, const std::vector<uint8_t>& plaintext);

// Returns nullopt on any structural or authentication failure -- wrong key,
// tampering, and truncation are all indistinguishable, same as everywhere
// else in Quark.
std::optional<std::vector<uint8_t>> Unseal(const crypto::AesKey& key,
                                            const std::vector<uint8_t>& sealed);

}  // namespace quark::payload
