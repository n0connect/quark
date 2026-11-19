#pragma once
// Generic secondary-witness record and load outcome -- the data shape shared
// by every storage-backed witness channel on every OS (CLAUDE.md rule 6's
// four-channel system: state.bin is the primary; each platform supplies
// three independently-sealed secondary channels). Lives in quark_core, not
// under quark/registry.hpp, because a chain-position snapshot has nothing
// Windows-specific about its *meaning* -- only how a given channel stores and
// seals it does. quark::registry, quark::ads, and quark::overlay (Windows)
// all read/write this same shape today; a future Linux or macOS channel does
// too, through quark::platform::IWitnessStore (see platform/witness_store.hpp).

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::witness {

struct Record {
    crypto::Sha256Digest anchor{};
    uint32_t remaining_links = 0;
    crypto::Sha256Digest hwid_digest{};
    uint64_t high_water_unix_time = 0;
};

// Three-way (not two-way) outcome, because "no witness yet" and "a witness
// exists but is broken" call for genuinely different caller behavior -- the
// former means "first run, mint one"; the latter means "tampering, lock
// down" -- while the *reasons* a witness can be broken (auth failure, bad
// magic, wrong size, ...) collapse into a single kInvalid, exactly like
// quark::state::Load's nullopt (CLAUDE.md rule 2).
enum class LoadResult {
    kFound,    // value existed and authenticated correctly -- out_witness valid
    kAbsent,   // no value at this name -- legitimate first run
    kInvalid,  // value existed but failed to authenticate or decode -- tampering
};

// Shared, platform-agnostic wire codec for a sealed witness blob -- the exact
// framing quark::registry.cpp (Windows) hand-rolls today: magic(4) +
// format_version(u32 LE) + iv(12) + tag(16) + ct_len(u32 LE) + ciphertext,
// where the plaintext is anchor(32) + remaining_links(u32 LE) + hwid_digest(32)
// + high_water_unix_time(u64 LE) = 76 bytes fixed. Every new platform channel
// (macOS: config-dir file + two xattrs; Linux: dotfile + two xattrs) uses
// this instead of re-deriving the same AES-GCM framing a third and fourth
// time -- only "where do these bytes live" differs per channel, not "how are
// they sealed". The Windows channels (registry.cpp/ads.cpp/overlay.cpp)
// predate this extraction and are left as-is (already correct, already
// shipped, not worth the risk of touching code that can only be re-verified
// on a real Windows machine); new channels should prefer this over
// hand-rolling the framing again.
constexpr uint32_t kCodecFormatVersion = 1;

// `magic` distinguishes channels in a hex dump (does not affect security --
// the AES-GCM key is already domain-separated per channel via quark::token).
std::vector<uint8_t> Seal(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                          const Record& record, const std::array<char, 4>& magic);

// Returns nullopt on any structural or authentication failure (wrong magic,
// wrong version, truncated blob, or AES-GCM auth failure -- tampering and
// wrong-machine collapse into the same outcome, same as everywhere else in
// Quark). Caller maps nullopt to LoadResult::kInvalid.
std::optional<Record> Unseal(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              const std::vector<uint8_t>& sealed, const std::array<char, 4>& magic);

}  // namespace quark::witness
