#include "quark/payload.hpp"

#include <cstring>

namespace quark::payload {

namespace {

constexpr char kMagic[4] = {'Q', 'P', 'L', 'D'};
constexpr uint32_t kFormatVersion = 1;
constexpr size_t kHeaderSize =
    4 + sizeof(uint32_t) + crypto::kGcmIvSize + crypto::kGcmTagSize + sizeof(uint32_t);

void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

std::vector<uint8_t> Seal(const crypto::AesKey& key, const std::vector<uint8_t>& plaintext) {
    crypto::GcmCiphertext sealed = crypto::Aes256GcmEncrypt(key, /*aad=*/{}, plaintext);

    std::vector<uint8_t> blob;
    blob.reserve(kHeaderSize + sealed.ciphertext.size());
    blob.insert(blob.end(), std::begin(kMagic), std::end(kMagic));
    AppendU32(blob, kFormatVersion);
    blob.insert(blob.end(), sealed.iv.begin(), sealed.iv.end());
    blob.insert(blob.end(), sealed.tag.begin(), sealed.tag.end());
    AppendU32(blob, static_cast<uint32_t>(sealed.ciphertext.size()));
    blob.insert(blob.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
    return blob;
}

std::optional<std::vector<uint8_t>> Unseal(const crypto::AesKey& key,
                                            const std::vector<uint8_t>& sealed) {
    if (sealed.size() < kHeaderSize) return std::nullopt;
    if (std::memcmp(sealed.data(), kMagic, sizeof(kMagic)) != 0) return std::nullopt;

    size_t off = sizeof(kMagic);
    if (ReadU32(sealed.data() + off) != kFormatVersion) return std::nullopt;
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

    return crypto::Aes256GcmDecrypt(key, iv, /*aad=*/{}, ciphertext, tag);
}

}  // namespace quark::payload
