#pragma once
// A CodeRegion is one captured, scrambled function's worth of real machine
// code plus the (small) list of PC-relative fixups it needs when placed at
// a new address. Its bytes are plain data -- quark_codecipher has no
// encryption of its own beyond the AES-256-CTR scramble already baked into
// `scrambled` (see capture.hpp); a CodeRegion's SERIALIZED bytes are what an
// outer AEAD layer (e.g. core.enc's single AES-256-GCM seal) protects as a
// whole, the same single-encryption-layer principle used everywhere else in
// this codebase.

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "quark/codecipher/relocation.hpp"

namespace quark::codecipher {

constexpr size_t kNonceSize = 16;

struct Relocation {
    uint32_t offset = 0;                    // byte offset within the region
    RelocKind kind = RelocKind::kAdrp;
    uint64_t original_absolute_target = 0;  // captured at Capture() time

    bool operator==(const Relocation& other) const {
        return offset == other.offset && kind == other.kind &&
               original_absolute_target == other.original_absolute_target;
    }
};

struct CodeRegion {
    std::array<uint8_t, kNonceSize> nonce{};
    std::vector<uint8_t> scrambled;           // AES-256-CTR'd real instruction bytes
    std::vector<Relocation> relocations;      // only EXTERNAL (out-of-region) PC-relative refs
};

// On-disk/in-core.enc-plaintext container format (all integers little-
// endian): magic(4)="QCC1" + version(u32) + nonce(16) + scrambled_len(u32) +
// scrambled_bytes + reloc_count(u32) + per-reloc{offset(u32) + kind(u8) +
// pad(3) + original_absolute_target(u64)}.
std::vector<uint8_t> SerializeCodeRegion(const CodeRegion& region);

// Returns nullopt on bad magic, unsupported version, or truncation.
std::optional<CodeRegion> DeserializeCodeRegion(const std::vector<uint8_t>& bytes);

}  // namespace quark::codecipher
