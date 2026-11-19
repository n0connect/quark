#include "quark/overlay.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>

namespace quark::overlay {

namespace {

// Distinct magic from ads.cpp ("QADS") so a blob written to one channel
// cannot be replayed verbatim into the other (the key is already domain-
// separated, but distinct magic is a cheap structural sanity check).
constexpr uint8_t kMagic[4] = {'Q', 'O', 'V', 'L'};
constexpr uint32_t kFormatVersion = 1;

// ADS name on the running exe.  A single common word keeps it innocuous if
// stumbled upon; post-obfuscation it is opaque in the binary.
constexpr char kStreamSuffix[] = ":quark";

constexpr size_t kPlaintextSize =
    crypto::kSha256Size   // anchor
    + sizeof(uint32_t)    // remaining_links
    + crypto::kSha256Size // hwid_digest
    + sizeof(uint64_t);   // high_water_unix_time

constexpr size_t kHeaderSize =
    sizeof(kMagic) + sizeof(uint32_t) + crypto::kGcmIvSize + crypto::kGcmTagSize + sizeof(uint32_t);

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

std::vector<uint8_t> Serialize(const quark::registry::Witness& w) {
    std::vector<uint8_t> out;
    out.reserve(kPlaintextSize);
    out.insert(out.end(), w.anchor.begin(), w.anchor.end());
    AppendU32(out, w.remaining_links);
    out.insert(out.end(), w.hwid_digest.begin(), w.hwid_digest.end());
    AppendU64(out, w.high_water_unix_time);
    return out;
}

bool Deserialize(const std::vector<uint8_t>& bytes, quark::registry::Witness& out) {
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

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
    ~ScopedHandle() { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    HANDLE Get() const { return h_; }
    bool Valid() const { return h_ != INVALID_HANDLE_VALUE; }
private:
    HANDLE h_;
};

std::vector<uint8_t> ReadAll(HANDLE h) {
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart == 0) return {};
    std::vector<uint8_t> buf(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    if (!ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr)) return {};
    buf.resize(read);
    return buf;
}

}  // namespace

std::string StreamPath() {
    char buf[MAX_PATH] = {0};
    if (GetModuleFileNameA(nullptr, buf, MAX_PATH) == 0) return "";
    return std::string(buf) + kStreamSuffix;
}

quark::registry::LoadResult Load(const quark::crypto::AesKey& overlay_key,
                                 const std::vector<uint8_t>& hwid_aad,
                                 quark::registry::Witness& out_witness) {
    std::string path = StreamPath();
    if (path.empty()) return quark::registry::LoadResult::kInvalid;

    ScopedHandle h(CreateFileA(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h.Valid()) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            return quark::registry::LoadResult::kAbsent;
        }
        return quark::registry::LoadResult::kInvalid;
    }

    std::vector<uint8_t> blob = ReadAll(h.Get());
    if (blob.size() < kHeaderSize) {
        return blob.empty() ? quark::registry::LoadResult::kAbsent
                            : quark::registry::LoadResult::kInvalid;
    }

    if (std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) {
        return quark::registry::LoadResult::kInvalid;
    }
    size_t off = sizeof(kMagic);
    if (ReadU32(blob.data() + off) != kFormatVersion) {
        return quark::registry::LoadResult::kInvalid;
    }
    off += sizeof(uint32_t);

    std::vector<uint8_t> iv(blob.begin() + off, blob.begin() + off + crypto::kGcmIvSize);
    off += crypto::kGcmIvSize;
    std::vector<uint8_t> tag(blob.begin() + off, blob.begin() + off + crypto::kGcmTagSize);
    off += crypto::kGcmTagSize;
    uint32_t ct_len = ReadU32(blob.data() + off);
    off += sizeof(uint32_t);
    if (blob.size() != off + ct_len) return quark::registry::LoadResult::kInvalid;

    std::vector<uint8_t> ciphertext(blob.begin() + off, blob.end());
    auto plaintext = crypto::Aes256GcmDecrypt(overlay_key, iv, hwid_aad, ciphertext, tag);
    if (!plaintext) return quark::registry::LoadResult::kInvalid;
    crypto::ScopedZero<std::vector<uint8_t>> zero(*plaintext);

    if (!Deserialize(*plaintext, out_witness)) return quark::registry::LoadResult::kInvalid;
    return quark::registry::LoadResult::kFound;
}

bool Save(const quark::crypto::AesKey& overlay_key,
          const std::vector<uint8_t>& hwid_aad,
          const quark::registry::Witness& witness) {
    std::string path = StreamPath();
    if (path.empty()) return false;

    std::vector<uint8_t> plaintext = Serialize(witness);
    crypto::ScopedZero<std::vector<uint8_t>> zero_pt(plaintext);

    crypto::GcmCiphertext sealed = crypto::Aes256GcmEncrypt(overlay_key, hwid_aad, plaintext);

    std::vector<uint8_t> blob;
    blob.reserve(kHeaderSize + sealed.ciphertext.size());
    blob.insert(blob.end(), kMagic, kMagic + sizeof(kMagic));
    AppendU32(blob, kFormatVersion);
    blob.insert(blob.end(), sealed.iv.begin(), sealed.iv.end());
    blob.insert(blob.end(), sealed.tag.begin(), sealed.tag.end());
    AppendU32(blob, static_cast<uint32_t>(sealed.ciphertext.size()));
    blob.insert(blob.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());

    ScopedHandle h(CreateFileA(path.c_str(), GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h.Valid()) return false;

    DWORD written = 0;
    return WriteFile(h.Get(), blob.data(), static_cast<DWORD>(blob.size()), &written, nullptr)
           && written == static_cast<DWORD>(blob.size());
}

}  // namespace quark::overlay
