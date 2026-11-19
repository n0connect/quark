#include "quark/state.hpp"

#include <cstdio>
#include <cstring>

namespace quark::state {

namespace {

constexpr char kMagic[4] = {'Q', 'S', 'T', 'A'};
// Fixed part: anchor(32) + remaining_links(4) + hwid_digest(32) + original_chain_length(4) + paste_id_len(1)
// Variable part: paste_id (0-32 bytes)
constexpr size_t kPlaintextFixedSize =
    crypto::kSha256Size + sizeof(uint32_t) + crypto::kSha256Size + sizeof(uint32_t) + 1;
constexpr size_t kMaxPasteIdLen = 32;

void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

bool ReadU32(const uint8_t* p, size_t remaining, uint32_t& out) {
    if (remaining < sizeof(uint32_t)) return false;
    out = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
          (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    return true;
}

std::vector<uint8_t> EncodePlaintext(const LicenseState& s) {
    const uint8_t pid_len = static_cast<uint8_t>(
        s.paste_id.size() < kMaxPasteIdLen ? s.paste_id.size() : kMaxPasteIdLen);
    std::vector<uint8_t> p;
    p.reserve(kPlaintextFixedSize + pid_len);
    p.insert(p.end(), s.anchor.begin(), s.anchor.end());
    AppendU32(p, s.remaining_links);
    p.insert(p.end(), s.hwid_digest.begin(), s.hwid_digest.end());
    AppendU32(p, s.original_chain_length);
    p.push_back(pid_len);
    p.insert(p.end(), s.paste_id.begin(), s.paste_id.begin() + pid_len);
    return p;
}

std::optional<LicenseState> DecodePlaintext(const std::vector<uint8_t>& p) {
    if (p.size() < kPlaintextFixedSize) return std::nullopt;

    LicenseState s;
    size_t off = 0;
    std::memcpy(s.anchor.data(), p.data() + off, s.anchor.size());
    off += s.anchor.size();

    if (!ReadU32(p.data() + off, p.size() - off, s.remaining_links)) return std::nullopt;
    off += sizeof(uint32_t);

    std::memcpy(s.hwid_digest.data(), p.data() + off, s.hwid_digest.size());
    off += s.hwid_digest.size();

    if (!ReadU32(p.data() + off, p.size() - off, s.original_chain_length)) return std::nullopt;
    off += sizeof(uint32_t);

    uint8_t pid_len = p[off++];
    if (pid_len > kMaxPasteIdLen) return std::nullopt;
    if (p.size() - off < pid_len) return std::nullopt;
    s.paste_id.assign(p.begin() + static_cast<ptrdiff_t>(off),
                      p.begin() + static_cast<ptrdiff_t>(off + pid_len));
    return s;
}

// A fixed ".tmp" suffix would let two processes writing the same `path`
// concurrently (e.g. two DRM_Wrapper launches racing on one license)
// clobber each other's in-flight temp file, turning a harmless race into a
// spurious write failure -- found via real concurrent-launch testing (see
// docs/PLAN.md's robustness-testing phase). A random suffix, not a PID,
// keeps this quark_core-portable: PIDs need an OS-specific call, but
// quark_core has zero Win32/POSIX API calls by design (CLAUDE.md).
std::string RandomTmpSuffix() {
    static const char* kHex = "0123456789abcdef";
    auto bytes = crypto::RandomBytes(8);
    std::string out;
    out.reserve(16);
    for (uint8_t b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

bool WriteFileAtomic(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::string tmp_path = path + "." + RandomTmpSuffix() + ".tmp";
    {
        // fopen (not fopen_s) is intentional: fopen_s is MSVC-only and this
        // file is shared with the rest of quark::common's portable C++ I/O
        // style (see ReadFileBytes below). C4996 is a style nudge, not a
        // real safety issue for a path we constructed ourselves. The pragma
        // is itself MSVC-only syntax -- #if-guarded so Clang/GCC (which
        // don't warn on fopen at all) don't hit -Wunknown-pragmas instead.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
        FILE* f = std::fopen(tmp_path.c_str(), "wb");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
        if (f == nullptr) return false;
        size_t written = std::fwrite(bytes.data(), 1, bytes.size(), f);
        bool ok = (written == bytes.size()) && (std::fflush(f) == 0);
        std::fclose(f);
        if (!ok) {
            std::remove(tmp_path.c_str());
            return false;
        }
    }
    // rename() on Windows fails if the destination exists; remove first. This
    // narrow window (remove succeeds, rename fails) is the same risk every
    // "replace a config file" routine accepts -- acceptable for a license
    // state file that's re-derivable by re-running Dev_Keygen if truly lost.
    std::remove(path.c_str());
    if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
        std::remove(tmp_path.c_str());
        return false;
    }
    return true;
}

std::optional<std::vector<uint8_t>> ReadFileBytes(const std::string& path) {
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    FILE* f = std::fopen(path.c_str(), "rb");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (f == nullptr) return std::nullopt;
    if (std::fseek(f, 0, SEEK_END) != 0) {
        std::fclose(f);
        return std::nullopt;
    }
    long size = std::ftell(f);
    if (size < 0) {
        std::fclose(f);
        return std::nullopt;
    }
    std::rewind(f);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    size_t read = buf.empty() ? 0 : std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    if (read != buf.size()) return std::nullopt;
    return buf;
}

}  // namespace

bool Save(const std::string& path, const crypto::AesKey& token_key,
          const std::vector<uint8_t>& hwid_aad, const LicenseState& s) {
    std::vector<uint8_t> plaintext = EncodePlaintext(s);
    crypto::ScopedZero<std::vector<uint8_t>> zero_plain(plaintext);

    crypto::GcmCiphertext sealed = crypto::Aes256GcmEncrypt(token_key, hwid_aad, plaintext);

    std::vector<uint8_t> framed;
    framed.reserve(4 + 4 + sealed.iv.size() + sealed.tag.size() + 4 + sealed.ciphertext.size());
    framed.insert(framed.end(), kMagic, kMagic + sizeof(kMagic));
    AppendU32(framed, kFormatVersion);
    framed.insert(framed.end(), sealed.iv.begin(), sealed.iv.end());
    framed.insert(framed.end(), sealed.tag.begin(), sealed.tag.end());
    AppendU32(framed, static_cast<uint32_t>(sealed.ciphertext.size()));
    framed.insert(framed.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());

    return WriteFileAtomic(path, framed);
}

std::optional<LicenseState> Load(const std::string& path, const crypto::AesKey& token_key,
                                 const std::vector<uint8_t>& hwid_aad) {
    auto bytes = ReadFileBytes(path);
    if (!bytes) return std::nullopt;

    constexpr size_t kHeaderSize = sizeof(kMagic) + sizeof(uint32_t) + crypto::kGcmIvSize +
                                   crypto::kGcmTagSize + sizeof(uint32_t);
    if (bytes->size() < kHeaderSize) return std::nullopt;

    const uint8_t* p = bytes->data();
    size_t off = 0;

    if (std::memcmp(p + off, kMagic, sizeof(kMagic)) != 0) return std::nullopt;
    off += sizeof(kMagic);

    uint32_t version = 0;
    ReadU32(p + off, bytes->size() - off, version);
    off += sizeof(uint32_t);
    if (version != kFormatVersion) return std::nullopt;

    std::vector<uint8_t> iv(p + off, p + off + crypto::kGcmIvSize);
    off += crypto::kGcmIvSize;

    std::vector<uint8_t> tag(p + off, p + off + crypto::kGcmTagSize);
    off += crypto::kGcmTagSize;

    uint32_t ct_len = 0;
    ReadU32(p + off, bytes->size() - off, ct_len);
    off += sizeof(uint32_t);

    if (bytes->size() - off != ct_len) return std::nullopt;  // size anomaly -> reject
    std::vector<uint8_t> ciphertext(p + off, p + off + ct_len);

    auto plaintext = crypto::Aes256GcmDecrypt(token_key, iv, hwid_aad, ciphertext, tag);
    if (!plaintext) return std::nullopt;  // auth failure: tampering OR wrong machine -- identical outcome

    crypto::ScopedZero<std::vector<uint8_t>> zero_plain(*plaintext);
    return DecodePlaintext(*plaintext);
}

}  // namespace quark::state
