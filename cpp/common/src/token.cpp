#include "quark/token.hpp"

#include <cstring>

namespace quark::token {

namespace {

void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

void AppendBytes(std::vector<uint8_t>& buf, const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    buf.insert(buf.end(), p, p + len);
}

void AppendDomain(std::vector<uint8_t>& buf, const char* domain) {
    AppendBytes(buf, domain, std::strlen(domain));
}

}  // namespace

crypto::AesKey DeriveStateKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical) {
    std::vector<uint8_t> material;
    material.reserve(32 + secret.size() + hwid_canonical.size() + 8);
    AppendDomain(material, "QUARK-STATE-KEY");
    AppendU32(material, static_cast<uint32_t>(secret.size()));
    AppendBytes(material, secret.data(), secret.size());
    AppendBytes(material, hwid_canonical.data(), hwid_canonical.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey key{};
    static_assert(sizeof(key) == sizeof(digest), "AES-256 key and SHA-256 digest are both 32 bytes");
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

crypto::AesKey DeriveRegistryKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical) {
    std::vector<uint8_t> material;
    material.reserve(32 + secret.size() + hwid_canonical.size() + 8);
    AppendDomain(material, "QUARK-REGISTRY-KEY");
    AppendU32(material, static_cast<uint32_t>(secret.size()));
    AppendBytes(material, secret.data(), secret.size());
    AppendBytes(material, hwid_canonical.data(), hwid_canonical.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

crypto::AesKey DeriveOnlineKey(const std::string& secret,
                               const std::vector<uint8_t>& hwid_canonical) {
    std::vector<uint8_t> material;
    material.reserve(32 + secret.size() + hwid_canonical.size() + 8);
    AppendDomain(material, "QUARK-ONLINE-KEY");
    AppendU32(material, static_cast<uint32_t>(secret.size()));
    AppendBytes(material, secret.data(), secret.size());
    AppendBytes(material, hwid_canonical.data(), hwid_canonical.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

crypto::AesKey DeriveHandoffSecret(const crypto::AesKey& state_key,
                                   const crypto::Sha256Digest& new_anchor,
                                   const std::vector<uint8_t>& hwid_canonical,
                                   const crypto::OnlineSecret& online_secret) {
    std::vector<uint8_t> material;
    material.reserve(16 + state_key.size() + new_anchor.size() + hwid_canonical.size() + online_secret.size());
    AppendDomain(material, "QUARK-HANDOFF");
    AppendBytes(material, state_key.data(), state_key.size());
    AppendBytes(material, new_anchor.data(), new_anchor.size());
    AppendBytes(material, hwid_canonical.data(), hwid_canonical.size());
    AppendBytes(material, online_secret.data(), online_secret.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey token{};
    std::memcpy(token.data(), digest.data(), token.size());
    return token;
}

crypto::AesKey DeriveAdsKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical) {
    std::vector<uint8_t> material;
    material.reserve(32 + secret.size() + hwid_canonical.size() + 8);
    AppendDomain(material, "QUARK-ADS-KEY");
    AppendU32(material, static_cast<uint32_t>(secret.size()));
    AppendBytes(material, secret.data(), secret.size());
    AppendBytes(material, hwid_canonical.data(), hwid_canonical.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

crypto::AesKey DeriveOverlayKey(const std::string& secret, const std::vector<uint8_t>& hwid_canonical) {
    std::vector<uint8_t> material;
    material.reserve(32 + secret.size() + hwid_canonical.size() + 8);
    AppendDomain(material, "QUARK-OVERLAY-KEY");
    AppendU32(material, static_cast<uint32_t>(secret.size()));
    AppendBytes(material, secret.data(), secret.size());
    AppendBytes(material, hwid_canonical.data(), hwid_canonical.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

crypto::AesKey DeriveContentKey(const crypto::AesKey& handoff_secret) {
    std::vector<uint8_t> material;
    material.reserve(24 + handoff_secret.size());
    AppendDomain(material, "QUARK-CORE-CONTENT-KEY");
    AppendBytes(material, handoff_secret.data(), handoff_secret.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey content_key{};
    std::memcpy(content_key.data(), digest.data(), content_key.size());
    return content_key;
}

crypto::AesKey DeriveCoreEncKey(const crypto::AesKey& state_key,
                                const crypto::Sha256Digest& online_secret_hash,
                                const std::vector<uint8_t>& hwid_canonical) {
    std::vector<uint8_t> material;
    material.reserve(18 + state_key.size() + online_secret_hash.size() + hwid_canonical.size());
    AppendDomain(material, "QUARK-CORE-ENC-KEY");
    AppendBytes(material, state_key.data(), state_key.size());
    AppendBytes(material, online_secret_hash.data(), online_secret_hash.size());
    AppendBytes(material, hwid_canonical.data(), hwid_canonical.size());

    crypto::ScopedZero<std::vector<uint8_t>> zero(material);
    crypto::Sha256Digest digest = crypto::Sha256(material);

    crypto::AesKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

crypto::Sha256Digest DeriveInitialSeal(
    const crypto::AesKey& content_key,
    const crypto::Sha256Digest& anchor_before,
    const crypto::Sha256Digest& anchor_after,
    const crypto::Sha256Digest& online_secret_hash,
    const std::vector<uint8_t>& hwid_canonical) {

    std::vector<uint8_t> msg;
    msg.reserve(4 + 32 + 32 + 32 + hwid_canonical.size());
    AppendDomain(msg, "SEAL");
    AppendBytes(msg, anchor_before.data(), anchor_before.size());
    AppendBytes(msg, anchor_after.data(), anchor_after.size());
    AppendBytes(msg, online_secret_hash.data(), online_secret_hash.size());
    AppendBytes(msg, hwid_canonical.data(), hwid_canonical.size());

    return crypto::HmacSha256(content_key.data(), content_key.size(),
                              msg.data(), msg.size());
}

crypto::Sha256Digest DeriveChallengeMac(
    const crypto::AesKey& content_key,
    const std::array<uint8_t, 32>& session_id,
    uint32_t counter,
    const std::array<uint8_t, 32>& nonce) {

    std::vector<uint8_t> msg;
    msg.reserve(4 + 32 + 4 + 32);
    AppendDomain(msg, "RESP");
    AppendBytes(msg, session_id.data(), session_id.size());
    AppendU32(msg, counter);
    AppendBytes(msg, nonce.data(), nonce.size());

    return crypto::HmacSha256(content_key.data(), content_key.size(),
                              msg.data(), msg.size());
}

crypto::AesKey DeriveCodeStreamKey(const crypto::AesKey& content_key) {
    std::vector<uint8_t> msg;
    AppendDomain(msg, "QUARK-CODE-STREAM-KEY");

    crypto::Sha256Digest digest = crypto::HmacSha256(content_key.data(), content_key.size(),
                                                      msg.data(), msg.size());
    crypto::AesKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

}  // namespace quark::token
