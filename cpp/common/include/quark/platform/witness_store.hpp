#pragma once
// Cross-platform secondary-witness storage contract (CLAUDE.md rule 6's
// four-channel witness system: state.bin is the primary; every platform
// supplies exactly three independently-sealed secondary channels behind this
// interface). DRM_Wrapper's cross-check loop is written against
// IWitnessStore only -- a Linux or macOS backend is an addition (three new
// IWitnessStore implementations), not a rewrite of the unlock flow, as long
// as each channel has comparable forensic properties to its Windows
// counterparts: survives a disk wipe, survives the binary being replaced,
// and is invisible to an attacker who treats the binary as a static file
// (see quark/registry.hpp, ads.hpp, overlay.hpp for the per-channel
// rationale this must be matched against, not copied literally -- NTFS ADS
// has no Linux/macOS equivalent, but xattrs and a dotfile under a
// user-config directory serve the same structural role).

#include <string_view>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/witness.hpp"

namespace quark::platform {

class IWitnessStore {
public:
    virtual ~IWitnessStore() = default;

    // Same three-way semantics as quark::registry::Load (see witness.hpp):
    // kFound (authenticated, out is valid), kAbsent (first run), kInvalid
    // (present but failed auth/decode -- a tamper signal, CLAUDE.md rule 2).
    virtual witness::LoadResult Load(const crypto::AesKey& key,
                                      const std::vector<uint8_t>& hwid_aad,
                                      witness::Record& out) const = 0;

    // Seals and commits `record` under `key` (HWID-as-AAD). Returns false on
    // any storage or crypto failure -- caller fail-deadlies; a witness that
    // silently failed to write is worse than no witness system at all.
    virtual bool Save(const crypto::AesKey& key,
                       const std::vector<uint8_t>& hwid_aad,
                       const witness::Record& record) = 0;

    // For error-registry labeling only ("registry", "ads", "overlay", ...) --
    // never used to change behavior, only to say which numbered code fired
    // (CLAUDE.md rule 2: the *outward* consequence of every channel failing
    // is identical; this exists purely for the debug-crash.txt line).
    virtual std::string_view ChannelName() const = 0;
};

}  // namespace quark::platform
