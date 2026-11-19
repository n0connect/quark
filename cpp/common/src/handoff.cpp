#include "quark/handoff.hpp"

namespace quark::handoff {

namespace {

void AppendU32LE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

}  // namespace

std::vector<uint8_t> EncodeInitialFrame(
    const crypto::AesKey& handoff_secret,
    const std::array<uint8_t, 32>& session_id,
    const crypto::Sha256Digest& initial_seal,
    const crypto::AesKey& core_enc_key) {

    std::vector<uint8_t> frame;
    frame.reserve(kInitialFrameSize);

    frame.insert(frame.end(), kInitialMagic, kInitialMagic + 4);
    AppendU32LE(frame, kInitialVersion);
    frame.insert(frame.end(), handoff_secret.begin(), handoff_secret.end());
    frame.insert(frame.end(), session_id.begin(), session_id.end());
    frame.insert(frame.end(), initial_seal.begin(), initial_seal.end());
    frame.insert(frame.end(), core_enc_key.begin(), core_enc_key.end());

    return frame;
}

std::vector<uint8_t> EncodeChallengeFrame(
    uint32_t counter, const std::array<uint8_t, 32>& nonce) {

    std::vector<uint8_t> frame;
    frame.reserve(kChallengeFrameSize);

    frame.insert(frame.end(), kChallengeMagic, kChallengeMagic + 4);
    AppendU32LE(frame, counter);
    frame.insert(frame.end(), nonce.begin(), nonce.end());

    return frame;
}

}  // namespace quark::handoff
