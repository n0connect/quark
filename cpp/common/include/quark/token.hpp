#pragma once
// Key-derivation glue that ties together SECRET (embedded in DRM_Wrapper at
// build time), HWID (this machine), Lamport chain state (this unlock), and the
// online_secret fetched from paste.rs -- the "cryptographic interlocking" the
// architecture spec calls for. Centralized here so Dev_Keygen and DRM_Wrapper
// derive byte-identical keys from the same inputs without duplicating logic.
//
// State/witness/online/overlay keys use plain SHA-256 over a fixed-order,
// length-prefixed concatenation -- intentionally not HKDF/PBKDF2 (no low-entropy
// human password here). The session-seal and challenge-response functions use
// HMAC-SHA256, which is strictly more correct when the key and message are
// distinct objects at the call site (vs. SHA-256 with a domain prefix, which is
// also fine but conflates key and data in one buffer).

#include <cstdint>
#include <string>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::token {

// token_key = SHA256("QUARK-STATE-KEY" || len(SECRET) || SECRET || hwid_canonical_bytes)
//
// This is the AES-256 key that seals/opens state.bin. Both Dev_Keygen (when
// minting the initial file for a customer) and DRM_Wrapper (every time it
// re-derives locally) compute it the same way -- neither ever transmits it.
crypto::AesKey DeriveStateKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical);

// registry_key = SHA256("QUARK-REGISTRY-KEY" || len(SECRET) || SECRET || hwid_canonical_bytes)
//
// The AES-256 key that seals/opens the Windows-Registry witness (see
// quark/registry.hpp) -- a second, independently-stored copy of the Lamport
// chain position used to detect "restore an old state.bin to rewind the
// chain" attacks. Deliberately a *separate* derivation from `state_key`
// (different domain string, otherwise identical inputs): domain separation
// means the two sealed stores can be reasoned about independently even
// though both ultimately answer to the same SECRET+HWID root -- a leak of
// one derived key says nothing about the other.
crypto::AesKey DeriveRegistryKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical);

// ads_key = SHA256("QUARK-ADS-KEY" || len(SECRET) || SECRET || hwid_canonical_bytes)
//
// Seals the NTFS Alternate Data Stream witness (quark::ads). Domain-separated
// from both the state key and the registry key so that compromising any one
// sealed store reveals nothing about how to forge another.
crypto::AesKey DeriveAdsKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical);

// overlay_key = SHA256("QUARK-OVERLAY-KEY" || len(SECRET) || SECRET || hwid_canonical_bytes)
//
// Seals the PE-overlay witness appended to DRM_Wrapper.exe itself
// (quark::overlay). Same domain-separation rationale as DeriveAdsKey.
crypto::AesKey DeriveOverlayKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical);

// online_key = SHA256("QUARK-ONLINE-KEY" || len(SECRET) || SECRET || hwid_canonical_bytes)
//
// The AES-256 key that seals/opens the online-witness paste blob on rentry.co.
// Domain-separated from every local-storage key so that learning this key
// tells an attacker nothing about state_key, registry_key, or any witness key.
crypto::AesKey DeriveOnlineKey(const std::string& secret,
                               const std::vector<uint8_t>& hwid_canonical);

// handoff_secret = SHA256("QUARK-HANDOFF" || state_key || new_anchor || hwid_canonical_bytes || online_secret)
//
// The one-time AES-256 key piped to drm-core's stdin and used to decrypt
// core.enc in memory. It changes every successful unlock (new_anchor rolls
// forward), is bound to this machine (hwid_canonical), and is unreproducible
// without SECRET (via state_key) AND the online_secret fetched from the
// rentry.co paste. The online_secret is NOT stored anywhere locally -- it
// exists only inside the AES-256-GCM-sealed paste blob, which requires
// SECRET+HWID to decrypt. This makes the paste a mandatory KDF input:
// patching out the "check the paste" branch is insufficient because
// online_secret is not known until the paste is actually decrypted.
crypto::AesKey DeriveHandoffSecret(const crypto::AesKey& state_key,
                                   const crypto::Sha256Digest& new_anchor,
                                   const std::vector<uint8_t>& hwid_canonical,
                                   const crypto::OnlineSecret& online_secret);

// content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret)
//
// The HMAC key for the QKH2 challenge-response loop. Deliberately NOT the same
// bytes as `handoff_secret` (key separation -- wire bytes cannot be used
// directly). Changes every Lamport step (new_anchor changes handoff_secret),
// preventing challenge-response replay across sessions.
// quark.jar's HandoffFrame mirrors this derivation byte-for-byte.
crypto::AesKey DeriveContentKey(const crypto::AesKey& handoff_secret);

// core_enc_key = SHA256("QUARK-CORE-ENC-KEY" || state_key || online_secret_hash || hwid_canonical)
//
// The AES-256 key that decrypts core.enc in memory. Stable for the lifetime of
// the license (same machine, same paste, same SECRET) -- unlike content_key,
// it deliberately excludes new_anchor so that core.enc can be pre-encrypted
// once at license issuance and reused across all subsequent sessions.
//
// Still HWID-bound (via state_key and explicit hwid_canonical) and
// online-secret-bound (via online_secret_hash), so a wrong machine or a
// replaced paste cannot derive it. `online_secret_hash` = SHA256(online_secret)
// so this can be called after online_secret has been zeroed.
crypto::AesKey DeriveCoreEncKey(const crypto::AesKey& state_key,
                                const crypto::Sha256Digest& online_secret_hash,
                                const std::vector<uint8_t>& hwid_canonical);

// initial_seal = HMAC-SHA256(key=content_key,
//     msg = "SEAL" || anchor_before || anchor_after || online_secret_hash || hwid_canonical)
//
// Written into the QKH2 initial frame; Java verifies it on receipt. This proves
// to Java that the full DRM flow ran -- anchor_before (current Lamport position),
// anchor_after (the user's spent key), online_secret_hash (paste.rs was live),
// and hwid_canonical (this machine) are all baked in. A fake DRM_Wrapper that
// didn't run the full flow cannot produce a valid seal because content_key itself
// requires SECRET + HWID + online_secret + anchor_after (via DeriveHandoffSecret).
//
// `online_secret_hash` = SHA256(online_secret); the hash (not the raw secret) is
// passed here so this function can be called after online_secret has been zeroed.
crypto::Sha256Digest DeriveInitialSeal(
    const crypto::AesKey& content_key,
    const crypto::Sha256Digest& anchor_before,
    const crypto::Sha256Digest& anchor_after,
    const crypto::Sha256Digest& online_secret_hash,
    const std::vector<uint8_t>& hwid_canonical);

// challenge_mac = HMAC-SHA256(key=content_key,
//     msg = "RESP" || session_id || counter (u32-LE) || nonce)
//
// Java's QuarkHeartbeat thread computes this in response to each challenge frame
// sent by DRM_Wrapper over the open stdin pipe. DRM_Wrapper verifies it against
// the same computation. Correct response proves Java still holds the right
// content_key (i.e. is still running legitimately on this machine with this
// session). counter + nonce guarantee each challenge is unique and unreplayable.
crypto::Sha256Digest DeriveChallengeMac(
    const crypto::AesKey& content_key,
    const std::array<uint8_t, 32>& session_id,
    uint32_t counter,
    const std::array<uint8_t, 32>& nonce);

// code_key = HMAC-SHA256(content_key, "QUARK-CODE-STREAM-KEY")
//
// Domain-separated key for quark::codecipher's AES-256-CTR instruction-level
// scramble/reconstruct transform (see cpp/quark_codecipher). Deterministic in
// content_key, following the same convention as every other Derive* function
// here -- but unlike DeriveStateKey/DeriveRegistryKey/etc., the ciphertext
// this key protects is never independently authenticated: quark::codecipher
// scrambles bytes that already live inside an outer AES-256-GCM seal (e.g.
// core.enc, keyed by content_key itself), so a second, independent auth tag
// here would be redundant -- see cpp/quark_codecipher/README.md.
crypto::AesKey DeriveCodeStreamKey(const crypto::AesKey& content_key);

}  // namespace quark::token
