#include "quark/crypto.hpp"

#include <stdexcept>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/platform_util.h>

namespace quark::crypto {

namespace {

// One process-wide DRBG, lazily seeded. mbedTLS's entropy module pulls from
// the platform CSPRNG (BCryptGenRandom on Windows) — Quark never rolls its own
// randomness.
class Drbg {
public:
    static Drbg& Instance() {
        static Drbg instance;
        return instance;
    }

    void Fill(uint8_t* out, size_t len) {
        if (mbedtls_ctr_drbg_random(&ctr_drbg_, out, len) != 0) {
            // Entropy failure is exactly the kind of anomaly that should be
            // fail-deadly: we cannot safely produce key material or nonces.
            std::abort();
        }
    }

private:
    Drbg() {
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&ctr_drbg_);
        const char* pers = "quark-drm";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                                  reinterpret_cast<const unsigned char*>(pers),
                                  std::char_traits<char>::length(pers)) != 0) {
            std::abort();
        }
    }
    ~Drbg() {
        mbedtls_ctr_drbg_free(&ctr_drbg_);
        mbedtls_entropy_free(&entropy_);
    }

    mbedtls_entropy_context entropy_{};
    mbedtls_ctr_drbg_context ctr_drbg_{};
};

}  // namespace

Sha256Digest Sha256(const uint8_t* data, size_t len) {
    Sha256Digest digest{};
    // `0` selects SHA-256 (vs. SHA-224) in mbedTLS's combined sha256 API.
    mbedtls_sha256(data, len, digest.data(), 0);
    return digest;
}

Sha256Digest Sha256(const std::vector<uint8_t>& data) {
    return Sha256(data.data(), data.size());
}

std::vector<uint8_t> RandomBytes(size_t count) {
    std::vector<uint8_t> out(count);
    if (count > 0) {
        Drbg::Instance().Fill(out.data(), count);
    }
    return out;
}

GcmCiphertext Aes256GcmEncrypt(const AesKey& key,
                               const std::vector<uint8_t>& aad,
                               const std::vector<uint8_t>& plaintext) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // NB: we do not zero `key` here -- it is owned and lifetime-managed by the
    // caller (via ScopedZero or otherwise). Zeroing someone else's const
    // reference as a side effect of encrypting would be a correctness bug
    // (their next use of the key would silently operate on zeros).
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(),
                           static_cast<unsigned int>(key.size() * 8)) != 0) {
        mbedtls_gcm_free(&ctx);
        std::abort();
    }

    GcmCiphertext out;
    out.iv = RandomBytes(kGcmIvSize);
    out.ciphertext.resize(plaintext.size());
    out.tag.resize(kGcmTagSize);

    int rc = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(), out.iv.data(), out.iv.size(),
        aad.data(), aad.size(), plaintext.empty() ? nullptr : plaintext.data(),
        out.ciphertext.empty() ? nullptr : out.ciphertext.data(), out.tag.size(), out.tag.data());

    mbedtls_gcm_free(&ctx);
    if (rc != 0) {
        std::abort();
    }
    return out;
}

std::optional<std::vector<uint8_t>> Aes256GcmDecrypt(const AesKey& key,
                                                      const std::vector<uint8_t>& iv,
                                                      const std::vector<uint8_t>& aad,
                                                      const std::vector<uint8_t>& ciphertext,
                                                      const std::vector<uint8_t>& tag) {
    if (iv.size() != kGcmIvSize || tag.size() != kGcmTagSize) {
        return std::nullopt;
    }

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(),
                           static_cast<unsigned int>(key.size() * 8)) != 0) {
        mbedtls_gcm_free(&ctx);
        return std::nullopt;
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    int rc = mbedtls_gcm_auth_decrypt(
        &ctx, ciphertext.size(), iv.data(), iv.size(), aad.data(), aad.size(), tag.data(),
        tag.size(), ciphertext.empty() ? nullptr : ciphertext.data(),
        plaintext.empty() ? nullptr : plaintext.data());

    mbedtls_gcm_free(&ctx);

    if (rc != 0) {
        // MBEDTLS_ERR_GCM_AUTH_FAILED covers both tampering AND AAD mismatch
        // (i.e. "this state.bin belongs to different hardware"). We deliberately
        // do not distinguish — both must look identical to an attacker.
        SecureZero(plaintext.data(), plaintext.size());
        return std::nullopt;
    }
    return plaintext;
}

std::vector<uint8_t> Aes256CtrXor(const AesKey& key,
                                  const std::array<uint8_t, kCtrNonceSize>& nonce,
                                  const std::vector<uint8_t>& input) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    // CTR mode always uses the block cipher's ENCRYPT direction to build the
    // keystream, for both scrambling and reconstructing -- there is no
    // "decrypt" key schedule involved.
    if (mbedtls_aes_setkey_enc(&ctx, key.data(), static_cast<unsigned int>(key.size() * 8)) != 0) {
        mbedtls_aes_free(&ctx);
        std::abort();
    }

    std::array<uint8_t, kCtrNonceSize> nonce_counter = nonce;  // mutated in place by mbedTLS
    std::array<uint8_t, 16> stream_block{};
    size_t nc_off = 0;

    std::vector<uint8_t> output(input.size());
    int rc = mbedtls_aes_crypt_ctr(&ctx, input.size(), &nc_off, nonce_counter.data(),
                                   stream_block.data(), input.empty() ? nullptr : input.data(),
                                   output.empty() ? nullptr : output.data());
    mbedtls_aes_free(&ctx);
    SecureZero(stream_block.data(), stream_block.size());
    if (rc != 0) {
        std::abort();
    }
    return output;
}

Sha256Digest HmacSha256(const uint8_t* key, size_t key_len,
                        const uint8_t* msg, size_t msg_len) {
    Sha256Digest out{};
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(info, key, key_len, msg, msg_len, out.data());
    return out;
}

void SecureZero(void* data, size_t len) {
    if (data != nullptr && len > 0) {
        mbedtls_platform_zeroize(data, len);
    }
}

}  // namespace quark::crypto
