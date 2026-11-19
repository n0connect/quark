#pragma once
// NTFS Alternate Data Stream witness -- a third, independent copy of the
// Lamport chain position, stored as an ADS attached to an innocuous-looking
// file under %APPDATA%\Microsoft\Windows\. Semantics mirror quark::registry
// exactly (same Witness struct, same LoadResult enum, same sealed format,
// same HWID-as-AAD; only the storage backend and AES key differ).
//
// --- Why ADS specifically? --------------------------------------------------
// An attacker who knows about state.bin and the registry entry can back up
// and restore both. ADS are invisible to `dir`, most backup tools, and
// standard file managers; they are not listed in registry exports; and the
// host path is unremarkable enough that an attacker who hasn't reverse-
// engineered this specific binary won't know to look for it.  Crucially, the
// *host file* can exist for entirely ordinary reasons -- it is never the
// content of the host that betrays anything, only the presence of the ADS
// stream, which requires knowing the exact path:stream name.
// Post-obfuscation that path is opaque in the binary; pre-obfuscation it is
// at least out of the obvious "Quark" namespace that a manual cleanup would
// target first.
//
// --- Sealed format ----------------------------------------------------------
// Magic "QADS" + version (u32 LE) + iv (12) + tag (16) + ct_len (u32 LE)
// + ciphertext -- identical structure to registry.cpp, different magic byte.
// The AES key comes from quark::token::DeriveAdsKey (domain-separated from
// both the state key and the registry key).

#include <string>
#include <vector>

#include "quark/registry.hpp"  // reuse Witness, LoadResult -- identical data

namespace quark::ads {

// Builds the ADS target path (host_file:stream) from %APPDATA%.
// Returns empty string if APPDATA is unset; caller fail-deadlies.
std::string WitnessPath();

// Same three-way semantics as quark::registry::Load; see registry.hpp.
quark::registry::LoadResult Load(const quark::crypto::AesKey& ads_key,
                                 const std::vector<uint8_t>& hwid_aad,
                                 quark::registry::Witness& out_witness);

bool Save(const quark::crypto::AesKey& ads_key,
          const std::vector<uint8_t>& hwid_aad,
          const quark::registry::Witness& witness);

}  // namespace quark::ads
