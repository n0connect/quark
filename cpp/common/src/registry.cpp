#include "quark/registry.hpp"

#include <windows.h>

#include <cstring>

namespace quark::registry {

namespace {

// HKCU is deliberately chosen over HKLM: it requires no elevation (the
// wrapper already runs as the interactive user), and -- just as importantly
// -- it is per-user, so cloning a machine image to another account on the
// same box doesn't silently inherit a "this license is fine here" witness.
constexpr wchar_t kKeyPath[] = L"Software\\Quark\\License";
constexpr wchar_t kValueName[] = L"Witness";

constexpr uint8_t kMagic[4] = {'Q', 'R', 'E', 'G'};

constexpr size_t kPlaintextSize =
    crypto::kSha256Size       // anchor
    + sizeof(uint32_t)        // remaining_links
    + crypto::kSha256Size     // hwid_digest
    + sizeof(uint64_t);       // high_water_unix_time

constexpr size_t kHeaderSize =
    sizeof(kMagic) + sizeof(uint32_t) + crypto::kGcmIvSize + crypto::kGcmTagSize + sizeof(uint32_t);

class ScopedHKey {
public:
    explicit ScopedHKey(HKEY key = nullptr) : key_(key) {}
    ~ScopedHKey() {
        if (key_) {
            RegCloseKey(key_);
        }
    }
    ScopedHKey(const ScopedHKey&) = delete;
    ScopedHKey& operator=(const ScopedHKey&) = delete;
    HKEY* AddressOf() { return &key_; }
    HKEY Get() const { return key_; }

private:
    HKEY key_;
};

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

std::vector<uint8_t> Serialize(const Witness& w) {
    std::vector<uint8_t> out;
    out.reserve(kPlaintextSize);
    out.insert(out.end(), w.anchor.begin(), w.anchor.end());
    AppendU32(out, w.remaining_links);
    out.insert(out.end(), w.hwid_digest.begin(), w.hwid_digest.end());
    AppendU64(out, w.high_water_unix_time);
    return out;
}

bool Deserialize(const std::vector<uint8_t>& bytes, Witness& out) {
    if (bytes.size() != kPlaintextSize) {
        return false;
    }
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

LoadResult Load(const crypto::AesKey& registry_key, const std::vector<uint8_t>& hwid_aad,
                Witness& out_witness) {
    ScopedHKey key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kKeyPath, 0, KEY_QUERY_VALUE, key.AddressOf()) != ERROR_SUCCESS) {
        return LoadResult::kAbsent;
    }

    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(key.Get(), kValueName, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        return LoadResult::kAbsent;
    }
    if (type != REG_BINARY || size < kHeaderSize) {
        // Present but structurally nonsensical -- not "absent", that would
        // let an attacker turn "delete the value" into a free first-run reset.
        return LoadResult::kInvalid;
    }

    std::vector<uint8_t> blob(size);
    if (RegQueryValueExW(key.Get(), kValueName, nullptr, &type, blob.data(), &size) != ERROR_SUCCESS) {
        return LoadResult::kInvalid;
    }
    blob.resize(size);

    if (std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) {
        return LoadResult::kInvalid;
    }
    size_t off = sizeof(kMagic);
    if (ReadU32(blob.data() + off) != kFormatVersion) {
        return LoadResult::kInvalid;
    }
    off += sizeof(uint32_t);

    std::vector<uint8_t> iv(blob.begin() + off, blob.begin() + off + crypto::kGcmIvSize);
    off += crypto::kGcmIvSize;
    std::vector<uint8_t> tag(blob.begin() + off, blob.begin() + off + crypto::kGcmTagSize);
    off += crypto::kGcmTagSize;
    uint32_t ct_len = ReadU32(blob.data() + off);
    off += sizeof(uint32_t);
    if (blob.size() != off + ct_len) {
        return LoadResult::kInvalid;
    }
    std::vector<uint8_t> ciphertext(blob.begin() + off, blob.end());

    auto plaintext = crypto::Aes256GcmDecrypt(registry_key, iv, hwid_aad, ciphertext, tag);
    if (!plaintext) {
        // Auth failure -- covers tampering, wrong machine, and wrong-key
        // alike, exactly like quark::state::Load. One signal, one code.
        return LoadResult::kInvalid;
    }
    crypto::ScopedZero<std::vector<uint8_t>> zero_plaintext(*plaintext);

    if (!Deserialize(*plaintext, out_witness)) {
        return LoadResult::kInvalid;
    }
    return LoadResult::kFound;
}

bool Save(const crypto::AesKey& registry_key, const std::vector<uint8_t>& hwid_aad,
          const Witness& witness) {
    std::vector<uint8_t> plaintext = Serialize(witness);
    crypto::ScopedZero<std::vector<uint8_t>> zero_plaintext(plaintext);

    crypto::GcmCiphertext sealed = crypto::Aes256GcmEncrypt(registry_key, hwid_aad, plaintext);

    std::vector<uint8_t> blob;
    blob.reserve(kHeaderSize + sealed.ciphertext.size());
    blob.insert(blob.end(), kMagic, kMagic + sizeof(kMagic));
    AppendU32(blob, kFormatVersion);
    blob.insert(blob.end(), sealed.iv.begin(), sealed.iv.end());
    blob.insert(blob.end(), sealed.tag.begin(), sealed.tag.end());
    AppendU32(blob, static_cast<uint32_t>(sealed.ciphertext.size()));
    blob.insert(blob.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());

    ScopedHKey key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kKeyPath, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, nullptr, key.AddressOf(), nullptr) != ERROR_SUCCESS) {
        return false;
    }

    return RegSetValueExW(key.Get(), kValueName, 0, REG_BINARY, blob.data(),
                          static_cast<DWORD>(blob.size())) == ERROR_SUCCESS;
}

}  // namespace quark::registry
