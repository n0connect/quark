#include "quark/codecipher/region.hpp"

#include <cstring>

namespace quark::codecipher {

namespace {

constexpr char kMagic[4] = {'Q', 'C', 'C', '1'};
constexpr uint32_t kFormatVersion = 1;

void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

void AppendU64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

}  // namespace

std::vector<uint8_t> SerializeCodeRegion(const CodeRegion& region) {
    std::vector<uint8_t> out;
    out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
    AppendU32(out, kFormatVersion);
    out.insert(out.end(), region.nonce.begin(), region.nonce.end());
    AppendU32(out, static_cast<uint32_t>(region.scrambled.size()));
    out.insert(out.end(), region.scrambled.begin(), region.scrambled.end());
    AppendU32(out, static_cast<uint32_t>(region.relocations.size()));
    for (const auto& reloc : region.relocations) {
        AppendU32(out, reloc.offset);
        out.push_back(static_cast<uint8_t>(reloc.kind));
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
        AppendU64(out, reloc.original_absolute_target);
    }
    return out;
}

std::optional<CodeRegion> DeserializeCodeRegion(const std::vector<uint8_t>& bytes) {
    constexpr size_t kHeaderSize = 4 + 4 + kNonceSize + 4;
    if (bytes.size() < kHeaderSize) return std::nullopt;
    if (std::memcmp(bytes.data(), kMagic, sizeof(kMagic)) != 0) return std::nullopt;

    size_t off = sizeof(kMagic);
    if (ReadU32(bytes.data() + off) != kFormatVersion) return std::nullopt;
    off += 4;

    CodeRegion region;
    std::memcpy(region.nonce.data(), bytes.data() + off, kNonceSize);
    off += kNonceSize;

    uint32_t scrambled_len = ReadU32(bytes.data() + off);
    off += 4;
    if (off + scrambled_len > bytes.size()) return std::nullopt;
    region.scrambled.assign(bytes.begin() + static_cast<ptrdiff_t>(off),
                            bytes.begin() + static_cast<ptrdiff_t>(off + scrambled_len));
    off += scrambled_len;

    if (off + 4 > bytes.size()) return std::nullopt;
    uint32_t reloc_count = ReadU32(bytes.data() + off);
    off += 4;

    constexpr size_t kRelocEncodedSize = 4 + 1 + 3 + 8;
    for (uint32_t i = 0; i < reloc_count; ++i) {
        if (off + kRelocEncodedSize > bytes.size()) return std::nullopt;
        Relocation reloc;
        reloc.offset = ReadU32(bytes.data() + off);
        off += 4;
        reloc.kind = static_cast<RelocKind>(bytes[off]);
        off += 4;  // kind byte + 3 padding bytes
        reloc.original_absolute_target = ReadU64(bytes.data() + off);
        off += 8;
        region.relocations.push_back(reloc);
    }
    if (off != bytes.size()) return std::nullopt;
    return region;
}

}  // namespace quark::codecipher
