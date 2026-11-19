#pragma once
// Linux extended-attribute witness channel -- the closest analogue to
// Windows' NTFS Alternate Data Streams: invisible to `ls`/most file
// managers, requires `getfattr -d` to see. ext4, btrfs, and xfs all support
// user xattrs out of the box.
//
// Unlike macOS (arbitrary attribute names), Linux kernel-enforces that an
// *unprivileged* process may only set/get attributes in the "user." xattr
// namespace on a regular file it owns (man 7 xattr) -- any other namespace
// either requires CAP_SYS_ADMIN or is reserved for the kernel/filesystem.
// This class prepends "user." automatically so callers never have to know
// or remember that constraint.

#include <string>
#include <string_view>

#include "quark/platform/witness_store.hpp"

namespace quark::platform::linux_ {

class XattrWitnessStore final : public IWitnessStore {
public:
    // `path` is the file the attribute is attached to (must already exist
    // and be owned by the running user); `attr_key` is the attribute name
    // *without* the "user." prefix (e.g. "quark.witness") -- this class adds
    // it. `channel_name` is what ChannelName() reports (error-registry
    // labeling only, CLAUDE.md rule 2).
    XattrWitnessStore(std::string path, std::string attr_key, std::array<char, 4> magic,
                       std::string channel_name)
        : path_(std::move(path)),
          attr_name_("user." + attr_key),
          magic_(magic),
          channel_name_(std::move(channel_name)) {}

    witness::LoadResult Load(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              witness::Record& out) const override;
    bool Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
              const witness::Record& record) override;
    std::string_view ChannelName() const override { return channel_name_; }

private:
    std::string path_;
    std::string attr_name_;
    std::array<char, 4> magic_;
    std::string channel_name_;
};

}  // namespace quark::platform::linux_
