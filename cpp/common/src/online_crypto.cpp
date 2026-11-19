#include "quark/online.hpp"

#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <cstring>
#include <string>

#include "quark/crypto.hpp"
#include "quark/token.hpp"

namespace quark::online {

namespace {

// --- PSA lazy init ----------------------------------------------------------
bool EnsurePsa() {
    static const bool kOk = (psa_crypto_init() == PSA_SUCCESS);
    return kOk;
}

// --- Blob serialization helpers ---------------------------------------------
void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

uint32_t ReadU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

// --- Blob format ------------------------------------------------------------
constexpr uint8_t kMagic[4]       = {'Q', 'O', 'N', 'L'};
constexpr uint32_t kBlobVersion   = 1;
constexpr size_t kPlaintextSize   = 32 + 64;  // online_secret + ec_signature

constexpr size_t kHeaderSize =
    sizeof(kMagic) + sizeof(uint32_t) + crypto::kGcmIvSize
    + crypto::kGcmTagSize + sizeof(uint32_t);

static std::vector<uint8_t> SerializePayload(const PastePayload& p) {
    std::vector<uint8_t> out;
    out.reserve(kPlaintextSize);
    out.insert(out.end(), p.online_secret.begin(), p.online_secret.end());
    out.insert(out.end(), p.ec_signature.begin(), p.ec_signature.end());
    return out;
}

static bool DeserializePayload(const std::vector<uint8_t>& bytes, PastePayload& out) {
    if (bytes.size() != kPlaintextSize) return false;
    std::memcpy(out.online_secret.data(), bytes.data(), 32);
    std::memcpy(out.ec_signature.data(), bytes.data() + 32, 64);
    return true;
}

}  // namespace

std::vector<uint8_t> BuildSignMessage(const std::vector<uint8_t>& hwid_canonical,
                                       uint32_t original_chain_length,
                                       const crypto::OnlineSecret& online_secret) {
    const char* prefix = "QUARK-ONLINE-V1";
    std::vector<uint8_t> msg;
    msg.reserve(std::strlen(prefix) + hwid_canonical.size() + 4 + 32);
    msg.insert(msg.end(), prefix, prefix + std::strlen(prefix));
    msg.insert(msg.end(), hwid_canonical.begin(), hwid_canonical.end());
    AppendU32(msg, original_chain_length);
    msg.insert(msg.end(), online_secret.begin(), online_secret.end());
    return msg;
}

std::vector<uint8_t> SealPayload(const crypto::AesKey& online_key,
                                  const std::vector<uint8_t>& hwid_canonical,
                                  const PastePayload& payload) {
    std::vector<uint8_t> pt = SerializePayload(payload);
    crypto::ScopedZero<std::vector<uint8_t>> zero_pt(pt);

    auto sealed = crypto::Aes256GcmEncrypt(online_key, hwid_canonical, pt);

    std::vector<uint8_t> blob;
    blob.reserve(kHeaderSize + sealed.ciphertext.size());
    blob.insert(blob.end(), kMagic, kMagic + sizeof(kMagic));
    AppendU32(blob, kBlobVersion);
    blob.insert(blob.end(), sealed.iv.begin(), sealed.iv.end());
    blob.insert(blob.end(), sealed.tag.begin(), sealed.tag.end());
    AppendU32(blob, static_cast<uint32_t>(sealed.ciphertext.size()));
    blob.insert(blob.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
    return blob;
}

std::optional<PastePayload> UnsealPayload(const crypto::AesKey& online_key,
                                           const std::vector<uint8_t>& hwid_canonical,
                                           const std::vector<uint8_t>& blob) {
    if (blob.size() < kHeaderSize) return std::nullopt;
    if (std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) return std::nullopt;

    size_t off = sizeof(kMagic);
    if (ReadU32LE(blob.data() + off) != kBlobVersion) return std::nullopt;
    off += 4;

    std::vector<uint8_t> iv(blob.begin() + off, blob.begin() + off + crypto::kGcmIvSize);
    off += crypto::kGcmIvSize;
    std::vector<uint8_t> tag(blob.begin() + off, blob.begin() + off + crypto::kGcmTagSize);
    off += crypto::kGcmTagSize;
    uint32_t ct_len = ReadU32LE(blob.data() + off);
    off += 4;
    if (blob.size() != off + ct_len) return std::nullopt;

    std::vector<uint8_t> ct(blob.begin() + off, blob.end());
    auto pt = crypto::Aes256GcmDecrypt(online_key, iv, hwid_canonical, ct, tag);
    if (!pt) return std::nullopt;
    crypto::ScopedZero<std::vector<uint8_t>> zero_pt(*pt);

    PastePayload out{};
    if (!DeserializePayload(*pt, out)) return std::nullopt;
    return out;
}

std::optional<EcSignature> SignPayload(const EcPrivateKey& kpriv,
                                        const std::vector<uint8_t>& message) {
    if (!EnsurePsa()) return std::nullopt;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (psa_import_key(&attr, kpriv.data(), kpriv.size(), &key_id) != PSA_SUCCESS)
        return std::nullopt;

    EcSignature sig{};
    size_t sig_len = 0;
    psa_status_t st = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                        message.data(), message.size(),
                                        sig.data(), sig.size(), &sig_len);
    psa_destroy_key(key_id);
    if (st != PSA_SUCCESS || sig_len != 64) return std::nullopt;
    return sig;
}

bool VerifySignature(const EcPublicKey& kpub,
                     const std::vector<uint8_t>& message,
                     const EcSignature& sig) {
    if (!EnsurePsa()) return false;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (psa_import_key(&attr, kpub.data(), kpub.size(), &key_id) != PSA_SUCCESS)
        return false;

    psa_status_t st = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                          message.data(), message.size(),
                                          sig.data(), sig.size());
    psa_destroy_key(key_id);
    return (st == PSA_SUCCESS);
}

std::optional<Keypair> GenerateKeypair() {
    if (!EnsurePsa()) return std::nullopt;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (psa_generate_key(&attr, &key_id) != PSA_SUCCESS) return std::nullopt;

    Keypair kp{};
    size_t len = 0;
    if (psa_export_key(key_id, kp.priv.data(), kp.priv.size(), &len) != PSA_SUCCESS
        || len != 32) {
        psa_destroy_key(key_id);
        return std::nullopt;
    }
    if (psa_export_public_key(key_id, kp.pub.data(), kp.pub.size(), &len) != PSA_SUCCESS
        || len != 65) {
        mbedtls_platform_zeroize(kp.priv.data(), kp.priv.size());
        psa_destroy_key(key_id);
        return std::nullopt;
    }
    psa_destroy_key(key_id);
    return kp;
}

}  // namespace quark::online
