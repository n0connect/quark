#pragma once
// macOS extended-attribute witness channel -- the closest analogue to
// Windows' NTFS Alternate Data Streams (quark/ads.hpp, quark/overlay.hpp):
// invisible to Finder, `ls`, and most backup tools unless they explicitly
// preserve xattrs (`xattr -l <path>` or `cp -p`/`ditto` show them; a plain
// `cp` or a naive re-download does not carry them over). APFS and HFS+ both
// support extended attributes natively.
//
// Two instances of this class play the same two roles the Windows backend's
// ADS channels play:
//   - one on an innocuous, pre-existing host file (~ ThemeCache ADS: attacker
//     has to know the exact path *and* attribute name to find it)
//   - one on DRM_Wrapper's own executable (~ exe ADS: travels with the
//     binary on the same volume, destroyed by a plain-overwrite replacement,
//     a meaningfully different forensic property than the host-file channel)

#include <string>
#include <string_view>

#include "quark/platform/witness_store.hpp"

namespace quark::platform::macos {

class XattrWitnessStore final : public IWitnessStore {
public:
    // `path` is the file the attribute is attached to (must already exist);
    // `attr_name` is the xattr key (by convention "user.<something>" is not
    // required on macOS the way it is on Linux, but namespacing it under a
    // vendor prefix like "com.quark.witness" avoids collisions regardless).
    XattrWitnessStore(std::string path, std::string attr_name, std::array<char, 4> magic,
                       std::string channel_name)
        : path_(std::move(path)),
          attr_name_(std::move(attr_name)),
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

}  // namespace quark::platform::macos
