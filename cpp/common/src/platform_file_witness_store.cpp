#include "quark/platform/file_witness_store.hpp"

#include <cstdio>

#include "quark/crypto.hpp"

namespace quark::platform {

namespace {

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

// Same "no partial write survives a crash" posture as quark::state::Save --
// write to a sibling temp file, then rename over the real path.
bool WriteFileAtomic(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::string tmp_path = path + "." + RandomTmpSuffix() + ".tmp";
    {
        FILE* f = std::fopen(tmp_path.c_str(), "wb");
        if (f == nullptr) return false;
        size_t written = std::fwrite(bytes.data(), 1, bytes.size(), f);
        bool ok = (written == bytes.size()) && (std::fflush(f) == 0);
        std::fclose(f);
        if (!ok) {
            std::remove(tmp_path.c_str());
            return false;
        }
    }
    std::remove(path.c_str());
    if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
        std::remove(tmp_path.c_str());
        return false;
    }
    return true;
}

std::optional<std::vector<uint8_t>> ReadFileBytes(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
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

witness::LoadResult FileWitnessStore::Load(const crypto::AesKey& key,
                                            const std::vector<uint8_t>& hwid_aad,
                                            witness::Record& out) const {
    auto bytes = ReadFileBytes(path_);
    if (!bytes) return witness::LoadResult::kAbsent;

    auto record = witness::Unseal(key, hwid_aad, *bytes, magic_);
    if (!record) return witness::LoadResult::kInvalid;

    out = *record;
    return witness::LoadResult::kFound;
}

bool FileWitnessStore::Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                             const witness::Record& record) {
    auto blob = witness::Seal(key, hwid_aad, record, magic_);
    return WriteFileAtomic(path_, blob);
}

}  // namespace quark::platform
