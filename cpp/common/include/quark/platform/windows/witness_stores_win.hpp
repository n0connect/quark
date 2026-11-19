#pragma once
// Windows implementations of quark::platform::IWitnessStore. Pure, stateless
// adapters -- all the actual sealing/storage logic stays in quark::registry,
// quark::ads, and quark::overlay (see their headers for per-channel
// rationale); each class here only forwards to the matching free functions,
// so DRM_Wrapper's cross-check loop can hold three `IWitnessStore*` instead
// of three hand-written call sites. The AES key stays a call-time parameter
// (not a stored member) -- mirroring the free functions exactly, and keeping
// key material out of any object whose lifetime DRM_Wrapper doesn't tightly
// control (ScopedZero already governs the caller's key on the stack).

#include "quark/platform/witness_store.hpp"

namespace quark::platform::win {

class RegistryWitnessStore final : public IWitnessStore {
public:
    witness::LoadResult Load(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              witness::Record& out) const override;
    bool Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
              const witness::Record& record) override;
    std::string_view ChannelName() const override { return "registry"; }
};

class AdsWitnessStore final : public IWitnessStore {
public:
    witness::LoadResult Load(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              witness::Record& out) const override;
    bool Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
              const witness::Record& record) override;
    std::string_view ChannelName() const override { return "ads"; }
};

class OverlayWitnessStore final : public IWitnessStore {
public:
    witness::LoadResult Load(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                              witness::Record& out) const override;
    bool Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
              const witness::Record& record) override;
    std::string_view ChannelName() const override { return "overlay"; }
};

}  // namespace quark::platform::win
