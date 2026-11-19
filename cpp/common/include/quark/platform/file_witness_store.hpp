#pragma once
// Portable "plain file" witness channel -- reads/writes a sealed blob
// (quark::witness::Seal/Unseal) at a fixed path via ordinary <cstdio> I/O.
// No OS-specific API at all; used as one of the three witness channels on
// both the macOS and Linux platform layers (the "lives in a user config
// directory, survives the binary being replaced" channel -- the same
// forensic role as Windows' HKCU registry witness, just backed by a file
// since neither macOS nor Linux has a registry).

#include <array>
#include <string>
#include <string_view>

#include "quark/platform/witness_store.hpp"

namespace quark::platform {

class FileWitnessStore final : public IWitnessStore {
public:
    // `path` should already be an OS-appropriate path (e.g. ~/Library/
    // Application Support/Quark/witness.bin on macOS, $XDG_CONFIG_HOME/
    // quark/witness.bin on Linux) whose parent directory exists -- this
    // class does not create directories. `magic` distinguishes this
    // channel's blobs from sibling channels in a hex dump (four ASCII
    // bytes, e.g. {'Q','C','F','G'}); `name` is what ChannelName() reports.
    FileWitnessStore(std::string path, std::array<char, 4> magic, std::string name)
        : path_(std::move(path)), magic_(magic), name_(std::move(name)) {}

    witness::LoadResult Load(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              witness::Record& out) const override;
    bool Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
              const witness::Record& record) override;
    std::string_view ChannelName() const override { return name_; }

private:
    std::string path_;
    std::array<char, 4> magic_;
    std::string name_;
};

}  // namespace quark::platform
