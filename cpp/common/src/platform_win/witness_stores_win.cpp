#include "quark/platform/windows/witness_stores_win.hpp"

#include "quark/ads.hpp"
#include "quark/overlay.hpp"
#include "quark/registry.hpp"

namespace quark::platform::win {

witness::LoadResult RegistryWitnessStore::Load(const crypto::AesKey& key,
                                                const std::vector<uint8_t>& hwid_aad,
                                                witness::Record& out) const {
    return quark::registry::Load(key, hwid_aad, out);
}

bool RegistryWitnessStore::Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                                 const witness::Record& record) {
    return quark::registry::Save(key, hwid_aad, record);
}

witness::LoadResult AdsWitnessStore::Load(const crypto::AesKey& key,
                                           const std::vector<uint8_t>& hwid_aad,
                                           witness::Record& out) const {
    return quark::ads::Load(key, hwid_aad, out);
}

bool AdsWitnessStore::Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                            const witness::Record& record) {
    return quark::ads::Save(key, hwid_aad, record);
}

witness::LoadResult OverlayWitnessStore::Load(const crypto::AesKey& key,
                                               const std::vector<uint8_t>& hwid_aad,
                                               witness::Record& out) const {
    return quark::overlay::Load(key, hwid_aad, out);
}

bool OverlayWitnessStore::Save(const crypto::AesKey& key, const std::vector<uint8_t>& hwid_aad,
                                const witness::Record& record) {
    return quark::overlay::Save(key, hwid_aad, record);
}

}  // namespace quark::platform::win
