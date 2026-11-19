#pragma once
// Windows-Registry-backed cryptographic witness -- a second, independent copy
// of the Lamport chain position (plus a clock-rollback tripwire), stored
// under HKEY_CURRENT_USER and sealed exactly like state.bin: AES-256-GCM,
// HWID canonical bytes as Associated Data, framed binary blob.
//
// --- Why a second copy, when state.bin is already tamper-evident? ----------
// AES-GCM proves state.bin hasn't been *edited* -- it cannot prove state.bin
// hasn't been *replaced* with an earlier, validly-sealed copy of itself (e.g.
// restoring yesterday's backup to "rewind" remaining_links back to full). A
// witness sealed under a *different* derived key (quark::token::DeriveRegistryKey
// -- domain-separated from the state key) and stored in a *second* location
// that ordinary file-level backups don't capture closes that gap: on every
// launch the wrapper requires BOTH copies to authenticate AND agree byte-for-
// byte on the chain position. Restoring only one half now authenticates fine
// on its own but disagrees with its sibling -- which is exactly as detectable,
// and exactly as fatal, as a torn AES-GCM tag (see CLAUDE.md rule 2: a single
// numbered code, never a boolean an attacker could special-case around).
//
// --- The high-water-mark timestamp: NOT a clock-trust expiry mechanism -----
// CLAUDE.md rule 6 stands untouched: the Lamport chain remains the *only*
// authority on "how many uses are left", and nothing here ever reads
// GetSystemTime() to decide whether to grant, extend, or unlock anything.
// What IS stored is a one-way ratchet -- "the highest wall-clock time this
// machine has ever reported to us" -- purely as a forensic tripwire: if "now"
// is ever observed to be *earlier* than that high-water mark, the clock has
// moved backwards, which is itself strong evidence of manipulation (a known
// technique for attacking *other* software's expiry, so seeing it attempted
// against Quark -- which doesn't even have a clock-based expiry to attack --
// is pure anomaly). A forward-running or merely-normal-looking clock proves
// nothing and grants nothing; only a *backwards* jump is ever acted upon.
//
// --- Sealed format (mirrors quark::state -- see state.hpp for the rationale
// of every choice duplicated here) ------------------------------------------
//   magic "QREG" + version (u32 LE) + iv (12) + tag (16) + ct_len (u32 LE)
//   + ciphertext, where the plaintext is:
//     anchor                : 32 bytes  current Lamport anchor (mirrors state.bin)
//     remaining_links       : u32       mirrors state.bin's counter
//     hwid_digest           : 32 bytes  belt-and-suspenders, mirrors state.bin
//     high_water_unix_time  : u64       largest wall-clock time ever observed

#include <cstdint>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/witness.hpp"

namespace quark::registry {

constexpr uint32_t kFormatVersion = 1;

// Aliases, not new types: the record shape and load outcome are generic
// (quark::witness -- shared by every OS's witness channels), not specific to
// the Windows registry. Kept as aliases under this name purely so existing
// call sites (registry.cpp, ads.hpp/cpp, overlay.hpp/cpp, drm_wrapper/main.cpp)
// don't need to change; new code should prefer quark::witness::Record /
// quark::witness::LoadResult directly, or better yet, quark::platform::IWitnessStore.
using Witness = witness::Record;
using LoadResult = witness::LoadResult;

LoadResult Load(const crypto::AesKey& registry_key, const std::vector<uint8_t>& hwid_aad,
                Witness& out_witness);

// Seals `witness` under `registry_key` (HWID-as-AAD, fresh random IV) and
// writes it as a REG_BINARY value, creating the key if it doesn't exist yet.
// Returns false on any registry or crypto failure (caller fail-deadlies --
// an unwritable witness must never be silently skipped, or the "double" in
// double-check becomes optional, which is the same as not having it).
bool Save(const crypto::AesKey& registry_key, const std::vector<uint8_t>& hwid_aad,
          const Witness& witness);

}  // namespace quark::registry
