#pragma once
// Online-witness channel (paste.rs backend).
//
// A paste.rs paste carries an AES-256-GCM-sealed blob that contains:
//   - online_secret : 32 random bytes generated at license mint time
//   - P-256 ECDSA signature over (HWID + chain_length + online_secret)
//
// Security model (three independently-required layers):
//   1. AES-256-GCM seal: derive_online_key(SECRET, HWID) -- only the machine
//      this license was issued for can decrypt it (HWID is AAD).
//   2. P-256 ECDSA signature: only the holder of K_priv (developer) can
//      produce a blob that verifies against K_pub (embedded in the binary).
//   3. online_secret as mandatory KDF input to DeriveHandoffSecret -- the
//      paste is a cryptographic hard dependency, not a patchable if-check.
//
// Paste ID storage: paste.rs assigns the ID on creation. Dev_Keygen stores it
// in state.bin (encrypted, HWID-bound) and in licenses.txt. DRM_Wrapper reads
// it from state.bin and fetches the paste.
//
// Revocation: DELETE https://paste.rs/{id} → next launch: kWrapperOnlineFetchFailed.

#include <array>
#include <optional>
#include <string>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::online {

// Fixed-size P-256 ECDSA key and signature types.
using EcPublicKey  = std::array<uint8_t, 65>;  // uncompressed SEC1: 0x04 || x(32) || y(32)
using EcPrivateKey = std::array<uint8_t, 32>;  // raw big-endian scalar
using EcSignature  = std::array<uint8_t, 64>;  // raw r(32) || s(32)

// Plaintext payload inside the sealed paste blob: online_secret(32) + sig(64)
struct PastePayload {
    crypto::OnlineSecret online_secret{};
    EcSignature          ec_signature{};
};

// --- Crypto -----------------------------------------------------------------

// Build the P-256 signing message:
//   "QUARK-ONLINE-V1" || hwid_canonical || original_chain_length[u32-LE] || online_secret[32]
std::vector<uint8_t> BuildSignMessage(const std::vector<uint8_t>& hwid_canonical,
                                       uint32_t original_chain_length,
                                       const crypto::OnlineSecret& online_secret);

// AES-256-GCM seal the payload. AAD = hwid_canonical.
// Returns the framed blob: magic(4) + version(4) + iv(12) + tag(16) + ct_len(4) + ct(96).
std::vector<uint8_t> SealPayload(const crypto::AesKey& online_key,
                                  const std::vector<uint8_t>& hwid_canonical,
                                  const PastePayload& payload);

// Unseal the blob. Returns nullopt on any auth/format failure.
std::optional<PastePayload> UnsealPayload(const crypto::AesKey& online_key,
                                           const std::vector<uint8_t>& hwid_canonical,
                                           const std::vector<uint8_t>& blob);

// Sign with a P-256 private key (PSA ECDSA + SHA-256). Returns nullopt on failure.
std::optional<EcSignature> SignPayload(const EcPrivateKey& kpriv,
                                        const std::vector<uint8_t>& message);

// Verify a P-256 ECDSA signature. Returns false if invalid or on PSA error.
bool VerifySignature(const EcPublicKey& kpub,
                     const std::vector<uint8_t>& message,
                     const EcSignature& sig);

// --- HTTP (WinHTTP, HTTPS, paste.rs) ----------------------------------------

// POST the sealed blob (hex-encoded) to paste.rs.
// Returns the paste ID (e.g. "abc12") on success, nullopt on failure.
std::optional<std::string> PostPaste(const std::vector<uint8_t>& sealed_blob);

// GET the raw paste content from paste.rs/{paste_id}.
// Returns the raw response body, or nullopt on any network/HTTP error.
std::optional<std::string> FetchPaste(const std::string& paste_id);

// DELETE the paste from paste.rs. Returns true if acknowledged (HTTP 200).
// After this, the next DRM_Wrapper launch will hit kWrapperOnlineFetchFailed.
bool DeletePaste(const std::string& paste_id);

// --- Keypair generation ----------------------------------------------------

struct Keypair {
    EcPrivateKey priv{};  // SENSITIVE -- zero on scope exit
    EcPublicKey  pub{};
};

// Generate a fresh P-256 keypair via the process-wide CTR-DRBG.
std::optional<Keypair> GenerateKeypair();

}  // namespace quark::online
