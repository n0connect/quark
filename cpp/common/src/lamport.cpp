#include "quark/lamport.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace quark::lamport {

std::vector<crypto::Sha256Digest> BuildChain(const std::vector<uint8_t>& seed, uint32_t n) {
    std::vector<crypto::Sha256Digest> chain;
    chain.reserve(static_cast<size_t>(n) + 1);

    // chain[0] = H^0(seed) = SHA256(seed) -- the raw seed itself never doubles
    // as a key (see header comment); everything from here on is plain
    // iterated hashing. chain[n] ends up as the anchor; chain[0..n-1] are the
    // n one-time keys handed out, in descending order, by Dev_Keygen.
    crypto::Sha256Digest current = crypto::Sha256(seed);
    chain.push_back(current);

    for (uint32_t i = 1; i <= n; ++i) {
        current = crypto::Sha256(current.data(), current.size());
        chain.push_back(current);
    }
    return chain;
}

bool VerifyStep(const crypto::Sha256Digest& candidate_preimage,
                const crypto::Sha256Digest& current_anchor) {
    crypto::Sha256Digest hashed = crypto::Sha256(candidate_preimage.data(), candidate_preimage.size());
    // Constant-time compare: chain links are not secret-dependent in a way
    // that timing leaks would matter cryptographically, but it costs nothing
    // and removes one more thing for a reviewer to question.
    uint8_t diff = 0;
    for (size_t i = 0; i < hashed.size(); ++i) {
        diff |= static_cast<uint8_t>(hashed[i] ^ current_anchor[i]);
    }
    return diff == 0;
}

std::optional<crypto::Sha256Digest> ParseKey(const std::string& text) {
    std::string hex;
    hex.reserve(text.size());
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        hex.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (hex.size() != crypto::kSha256Size * 2) return std::nullopt;

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };

    crypto::Sha256Digest out{};
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string FormatKey(const crypto::Sha256Digest& digest) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (uint8_t b : digest) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

}  // namespace quark::lamport
