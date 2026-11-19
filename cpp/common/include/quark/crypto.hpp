#pragma once
// Thin RAII wrappers around mbedTLS primitives. Quark links mbedTLS statically
// (see /third_party/mbedtls + top-level CMakeLists) — this header is the only
// place the rest of the codebase is allowed to touch crypto internals.

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace quark::crypto {

constexpr size_t kSha256Size = 32;
constexpr size_t kAes256KeySize = 32;
constexpr size_t kGcmIvSize = 12;   // 96-bit nonce, the GCM-recommended size
constexpr size_t kGcmTagSize = 16;  // 128-bit authentication tag
constexpr size_t kCtrNonceSize = 16;  // full 128-bit CTR nonce+counter block

using Sha256Digest  = std::array<uint8_t, kSha256Size>;
using AesKey        = std::array<uint8_t, kAes256KeySize>;
// 32-byte random value generated at license mint time and mixed into the
// handoff_secret KDF (see quark::token::DeriveHandoffSecret). It lives inside
// the AES-256-GCM-sealed online-witness paste on rentry.co; without fetching
// and decrypting that paste, DRM_Wrapper cannot derive the correct
// handoff_secret -- making the online channel a mandatory KDF input, not just
// a patchable if-check.
using OnlineSecret  = std::array<uint8_t, 32>;

// SHA-256 over an arbitrary byte buffer. Used both for Lamport chain steps
// (H(x)) and for deriving the canonical HWID digest used as AAD.
Sha256Digest Sha256(const uint8_t* data, size_t len);
Sha256Digest Sha256(const std::vector<uint8_t>& data);

// Cryptographically-secure random bytes via mbedTLS CTR-DRBG seeded from the
// platform entropy source (Windows: BCrypt). Used for Lamport seeds, IVs, etc.
std::vector<uint8_t> RandomBytes(size_t count);

struct GcmCiphertext {
    std::vector<uint8_t> iv;          // kGcmIvSize bytes, freshly random per encryption
    std::vector<uint8_t> ciphertext;  // same length as plaintext
    std::vector<uint8_t> tag;         // kGcmTagSize bytes
};

// AES-256-GCM encrypt. `aad` (Associated Authenticated Data) is NOT encrypted
// but IS bound into the authentication tag — Quark uses the freshly-collected
// HWID blob as `aad` so that decrypting on different hardware fails at the
// authentication-tag stage, not via an `if` comparison that could be patched out.
GcmCiphertext Aes256GcmEncrypt(const AesKey& key,
                               const std::vector<uint8_t>& aad,
                               const std::vector<uint8_t>& plaintext);

// AES-256-GCM decrypt + verify. Returns std::nullopt on ANY failure
// (bad key, bad IV, tampered ciphertext, or — critically — AAD mismatch i.e.
// wrong machine). Callers must treat nullopt as fail-deadly: no diagnostic
// detail about *why* it failed should ever reach the user.
std::optional<std::vector<uint8_t>> Aes256GcmDecrypt(const AesKey& key,
                                                      const std::vector<uint8_t>& iv,
                                                      const std::vector<uint8_t>& aad,
                                                      const std::vector<uint8_t>& ciphertext,
                                                      const std::vector<uint8_t>& tag);

// AES-256 in CTR mode, used as a keyed keystream XOR: output = input XOR
// AES_encrypt(key, counter||counter+1||...). Unlike Aes256GcmEncrypt/Decrypt,
// this is NOT authenticated (no tag) and is its own inverse -- calling it
// twice with the same key and the same starting `nonce` (16 bytes, caller-
// supplied, must never repeat under the same key for different plaintexts)
// recovers the original input exactly, since XOR is self-inverting. Used to
// reversibly scramble real machine-code bytes (quark::codecipher) where the
// content is already covered by an outer AES-256-GCM seal (e.g. core.enc)
// and this layer's only job is "unrecognizable at rest, exact byte-for-byte
// reconstruction at runtime" -- not independent authentication.
std::vector<uint8_t> Aes256CtrXor(const AesKey& key,
                                  const std::array<uint8_t, kCtrNonceSize>& nonce,
                                  const std::vector<uint8_t>& input);

// HMAC-SHA256: RFC 2104 keyed MAC. Used for challenge-response derivations where
// the key and message are distinct inputs -- HMAC makes that separation explicit
// in the API (vs. SHA256("domain" || key || msg) which works but conflates them).
// Returns the 32-byte HMAC digest; the key is never mixed into a hash input buffer
// that could accidentally be swapped with plaintext data.
Sha256Digest HmacSha256(const uint8_t* key, size_t key_len,
                        const uint8_t* msg, size_t msg_len);

// Convenience overload for the most common call sites in token.cpp.
inline Sha256Digest HmacSha256(const AesKey& key, const std::vector<uint8_t>& msg) {
    return HmacSha256(key.data(), key.size(), msg.data(), msg.size());
}

// Zeroes a buffer in a way the optimizer cannot eliminate (wraps
// mbedtls_platform_zeroize / SecureZeroMemory). Call on every buffer that ever
// held key material, a token, or a Lamport preimage before it goes out of scope.
void SecureZero(void* data, size_t len);

// RAII guard: SecureZero(buf.data(), buf.size()) on destruction. Use this
// instead of remembering to call SecureZero by hand at every return path.
template <typename Container>
class ScopedZero {
public:
    explicit ScopedZero(Container& c) : container_(c) {}
    ~ScopedZero() {
        if (!container_.empty()) {
            SecureZero(container_.data(), container_.size() * sizeof(typename Container::value_type));
        }
    }
    ScopedZero(const ScopedZero&) = delete;
    ScopedZero& operator=(const ScopedZero&) = delete;

private:
    Container& container_;
};

}  // namespace quark::crypto
