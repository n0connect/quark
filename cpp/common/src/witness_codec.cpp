#include <cstring>

#include "quark/witness.hpp"

namespace quark::witness {

namespace {

constexpr size_t kPlaintextSize =
    crypto::kSha256Size       // anchor
    + sizeof(uint32_t)        // remaining_links
    + crypto::kSha256Size     // hwid_digest
    + sizeof(uint64_t);       // high_water_unix_time

constexpr size_t kHeaderSize =
    4 + sizeof(uint32_t) + crypto::kGcmIvSize + crypto::kGcmTagSize + sizeof(uint32_t);

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

std::vector<uint8_t> Serialize(const Record& r) {
    std::vector<uint8_t> out;
    out.reserve(kPlaintextSize);
    out.insert(out.end(), r.anchor.begin(), r.anchor.end());
    AppendU32(out, r.remaining_links);
    out.insert(out.end(), r.hwid_digest.begin(), r.hwid_digest.end());
    AppendU64(out, r.high_water_unix_time);
    return out;
}

bool Deserialize(const std::vector<uint8_t>& bytes, Record& out) {
    if (bytes.size() != kPlaintextSize) return false;
    size_t off = 0;
    std::memcpy(out.anchor.data(), bytes.data() + off, crypto::kSha256Size);
    off += crypto::kSha256Size;
    out.remaining_links = ReadU32(bytes.data() + off);
    off += sizeof(uint32_t);
    std::memcpy(out.hwid_digest.data(), bytes.data() + off, crypto::kSha256Size);
    off += crypto::kSha256Size;
    out.high_water_unix_time = ReadU64(bytes.data() + off);
    return true;
}

}  // namespace

std::vector<uint8_t> Seal(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                          const Record& record, const std::array<char, 4>& magic) {
    std::vector<uint8_t> plaintext = Serialize(record);
    crypto::ScopedZero<std::vector<uint8_t>> zero_plaintext(plaintext);

    crypto::GcmCiphertext sealed = crypto::Aes256GcmEncrypt(key, hwid_aad, plaintext);

    std::vector<uint8_t> blob;
    blob.reserve(kHeaderSize + sealed.ciphertext.size());
    blob.insert(blob.end(), magic.begin(), magic.end());
    AppendU32(blob, kCodecFormatVersion);
    blob.insert(blob.end(), sealed.iv.begin(), sealed.iv.end());
    blob.insert(blob.end(), sealed.tag.begin(), sealed.tag.end());
    AppendU32(blob, static_cast<uint32_t>(sealed.ciphertext.size()));
    blob.insert(blob.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
    return blob;
}

std::optional<Record> Unseal(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              const std::vector<uint8_t>& sealed, const std::array<char, 4>& magic) {
    if (sealed.size() < kHeaderSize) return std::nullopt;
    if (std::memcmp(sealed.data(), magic.data(), magic.size()) != 0) return std::nullopt;

    size_t off = magic.size();
    if (ReadU32(sealed.data() + off) != kCodecFormatVersion) return std::nullopt;
    off += sizeof(uint32_t);

    std::vector<uint8_t> iv(sealed.begin() + static_cast<ptrdiff_t>(off),
                            sealed.begin() + static_cast<ptrdiff_t>(off + crypto::kGcmIvSize));
    off += crypto::kGcmIvSize;
    std::vector<uint8_t> tag(sealed.begin() + static_cast<ptrdiff_t>(off),
                             sealed.begin() + static_cast<ptrdiff_t>(off + crypto::kGcmTagSize));
    off += crypto::kGcmTagSize;

    uint32_t ct_len = ReadU32(sealed.data() + off);
    off += sizeof(uint32_t);
    if (sealed.size() != off + ct_len) return std::nullopt;

    std::vector<uint8_t> ciphertext(sealed.begin() + static_cast<ptrdiff_t>(off), sealed.end());

    auto plaintext = crypto::Aes256GcmDecrypt(key, iv, hwid_aad, ciphertext, tag);
    if (!plaintext) return std::nullopt;
    crypto::ScopedZero<std::vector<uint8_t>> zero_plaintext(*plaintext);

    Record out;
    if (!Deserialize(*plaintext, out)) return std::nullopt;
    return out;
}

}  // namespace quark::witness
