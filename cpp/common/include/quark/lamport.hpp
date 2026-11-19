#pragma once
// Lamport one-time-key hash chain. This is the entire "licensing clock" —
// Quark deliberately has no notion of wall-clock expiry (see CLAUDE.md §
// "No network, no system-clock trust"). A license is a chain of length n;
// each unlock consumes exactly one link, and the chain cannot run backwards.
//
//   seed = random 32 bytes            (kept secret by the developer)
//   H^0(seed) = SHA256(seed)          (never the raw seed -- raw randomness
//                                      never doubles as a usable key)
//   H^k(seed) = SHA256(H^{k-1}(seed))
//   anchor    = H^n(seed)             (what ships inside state.bin; n == the
//                                      number of unlocks the license grants)
//
// To unlock, the user supplies H^{n-1}(seed); the wrapper checks
// SHA256(supplied) == anchor, then the chain rolls forward:
// new anchor = supplied, remaining n -> n-1. One-way (can't derive H^{k-1}
// from H^k), so a leaked "current" key can't be used to mint earlier
// (already-spent) ones, and the chain physically runs out at H^0 -- no clock
// needed to enforce "expired". All of H^{n-1} .. H^0 (n keys total) are valid,
// one-time, sequentially-required unlock keys.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::lamport {

// Builds the full chain H^0(seed) .. H^n(seed), inclusive, length n+1.
// `seed` should be `quark::crypto::RandomBytes(32)` from the dev-side keygen.
// Index 0 is the seed itself; index n is the anchor shipped to the customer.
// Returns the chain so Dev_Keygen can hand out H^{n-1}, H^{n-2}, ... as the
// customer's one-time unlock keys (in *reverse* order of use).
std::vector<crypto::Sha256Digest> BuildChain(const std::vector<uint8_t>& seed, uint32_t n);

// One verification step: does SHA256(candidate_preimage) == current_anchor?
// This is the ONLY place a Lamport step is checked — keep it a pure function
// so both Dev_Keygen (self-test) and DRM_Wrapper (real unlock) share it,
// rather than risking two subtly-different implementations.
bool VerifyStep(const crypto::Sha256Digest& candidate_preimage,
                const crypto::Sha256Digest& current_anchor);

// Parses a user-supplied key string (hex-encoded SHA-256 digest, case
// insensitive, optional whitespace) into raw bytes. Returns nullopt on any
// malformed input — malformed input is treated identically to "wrong key"
// by the caller (no distinct error message; see fail-deadly principle).
std::optional<crypto::Sha256Digest> ParseKey(const std::string& text);

// Renders a digest as the lowercase hex string handed to end users as their
// one-time unlock key.
std::string FormatKey(const crypto::Sha256Digest& digest);

}  // namespace quark::lamport
