#pragma once
// state.bin codec — the persisted, hardware-bound license state.
//
// On-disk layout (all little-endian):
//   magic        : 4 bytes  "QSTA"
//   version      : u32      format version (3)
//   iv           : 12 bytes AES-GCM nonce (crypto::kGcmIvSize)
//   tag          : 16 bytes AES-GCM authentication tag (crypto::kGcmTagSize)
//   ct_len       : u32      ciphertext length
//   ciphertext   : ct_len bytes  -- AES-256-GCM(plaintext) under the
//                                   per-install token-derivation key, with
//                                   AAD = quark::hwid::CanonicalBytes(local HWID)
//
// Plaintext (the part that's actually encrypted) layout:
//   anchor                : 32 bytes  current Lamport anchor H^k(seed)
//   remaining_links       : u32       k -- how many unlocks are left in the chain
//   hwid_digest           : 32 bytes  SHA-256(CanonicalBytes(hwid)) the state was
//                                      minted for (belt-and-suspenders alongside AAD)
//   original_chain_length : u32       n -- immutable chain length at mint time
//   paste_id_len          : u8        length of the paste.rs ID string (0-32)
//   paste_id              : paste_id_len bytes  ASCII paste.rs ID (e.g. "abc12")
//                                      Used by DRM_Wrapper to fetch the online-witness
//                                      blob. Stored here (encrypted + HWID-bound) so
//                                      neither Dev_Keygen nor DRM_Wrapper needs an
//                                      out-of-band channel to communicate the paste ID.
//
// Decoding requires BOTH a successful AES-GCM auth (which transitively proves
// the supplied HWID-as-AAD matches what the file was sealed with) AND a
// structurally sane plaintext. Any failure anywhere -> std::nullopt -> caller
// fail-deadlies. We never report *which* check failed.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::state {

constexpr uint32_t kFormatVersion = 3;

struct LicenseState {
    crypto::Sha256Digest anchor{};            // current Lamport anchor
    uint32_t remaining_links = 0;             // unlocks left before the chain is exhausted
    crypto::Sha256Digest hwid_digest{};       // SHA-256 of the HWID this state is bound to
    uint32_t original_chain_length = 0;       // immutable: the chain length this license was minted with
    std::string paste_id;                     // paste.rs ID for the online-witness blob (e.g. "abc12")
};

// Serializes + AES-256-GCM-encrypts `state` under `token_key`, using
// `hwid_aad` (== quark::hwid::CanonicalBytes(local hwid)) as Associated Data,
// and writes the framed result to `path`. Returns false on any I/O or crypto
// failure (caller fail-deadlies; no partial file is left behind — written via
// a temp file + atomic rename).
bool Save(const std::string& path, const crypto::AesKey& token_key,
          const std::vector<uint8_t>& hwid_aad, const LicenseState& state);

// Reads, authenticates (HWID-as-AAD) and decodes `path`. Returns nullopt on:
//   - file missing / unreadable / wrong size
//   - bad magic / unsupported version
//   - AES-GCM authentication failure (covers BOTH tampering and "wrong
//     machine" -- these must be indistinguishable to an attacker)
//   - structurally invalid plaintext (wrong length after decryption)
// Every one of these collapses to the same nullopt; do not add diagnostics
// that would let an attacker binary-search their way to "which check failed".
std::optional<LicenseState> Load(const std::string& path, const crypto::AesKey& token_key,
                                 const std::vector<uint8_t>& hwid_aad);

}  // namespace quark::state
