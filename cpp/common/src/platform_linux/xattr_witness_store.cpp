#include "quark/platform/linux/xattr_witness_store.hpp"

#include <sys/types.h>
#include <sys/xattr.h>

namespace quark::platform::linux_ {

namespace {

// Linux getxattr/setxattr (unlike macOS's) take no `position`/`options`
// arguments -- see xattr(7). Two-call size-then-fill pattern, same as the
// macOS and Windows-ADS channels.
std::optional<std::vector<uint8_t>> ReadXattr(const std::string& path, const std::string& name) {
    ssize_t size = getxattr(path.c_str(), name.c_str(), nullptr, 0);
    if (size < 0) return std::nullopt;  // attribute absent, or path unreadable
    if (size == 0) return std::vector<uint8_t>{};

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    ssize_t read = getxattr(path.c_str(), name.c_str(), buf.data(), buf.size());
    if (read < 0 || static_cast<size_t>(read) != buf.size()) return std::nullopt;
    return buf;
}

bool WriteXattr(const std::string& path, const std::string& name, const std::vector<uint8_t>& bytes) {
    return setxattr(path.c_str(), name.c_str(), bytes.data(), bytes.size(), 0) == 0;
}

}  // namespace

witness::LoadResult XattrWitnessStore::Load(const crypto::AesKey& key,
                                             const std::vector<uint8_t>& hwid_aad,
                                             witness::Record& out) const {
    auto bytes = ReadXattr(path_, attr_name_);
    if (!bytes) return witness::LoadResult::kAbsent;

    auto record = witness::Unseal(key, hwid_aad, *bytes, magic_);
    if (!record) return witness::LoadResult::kInvalid;

    out = *record;
    return witness::LoadResult::kFound;
}

bool XattrWitnessStore::Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              const witness::Record& record) {
    auto blob = witness::Seal(key, hwid_aad, record, magic_);
    return WriteXattr(path_, attr_name_, blob);
}

}  // namespace quark::platform::linux_
