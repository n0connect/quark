#include "quark/codecipher/capture.hpp"

#include <cstring>

namespace quark::codecipher {

CodeRegion Capture(const uint8_t* code, size_t length, const crypto::AesKey& code_key) {
    CodeRegion region;
    auto nonce_bytes = crypto::RandomBytes(kNonceSize);
    std::copy(nonce_bytes.begin(), nonce_bytes.end(), region.nonce.begin());

    auto base = reinterpret_cast<uint64_t>(code);

    // Scan the REAL bytes (before scrambling) for PC-relative instructions.
    // A target inside [base, base+length) is an INTERNAL reference: when
    // the whole region is later copied as one contiguous block to a new
    // address, its relative encoding stays correct automatically (the
    // instruction and its target move by the exact same offset) -- no
    // relocation entry needed. Only EXTERNAL targets (globals, string
    // literals, other functions) need one, because they do NOT move.
    for (size_t off = 0; off + 4 <= length; off += 4) {
        uint32_t instr = 0;
        std::memcpy(&instr, code + off, 4);
        auto kind = ClassifyInstruction(instr);
        if (!kind) continue;

        uint64_t pc = base + off;
        uint64_t target = DecodeTarget(pc, instr, *kind);
        bool internal = (target >= base) && (target < base + length);
        if (internal) continue;

        Relocation reloc;
        reloc.offset = static_cast<uint32_t>(off);
        reloc.kind = *kind;
        reloc.original_absolute_target = target;
        region.relocations.push_back(reloc);
    }

    std::vector<uint8_t> plaintext(code, code + length);
    region.scrambled = crypto::Aes256CtrXor(code_key, region.nonce, plaintext);
    return region;
}

}  // namespace quark::codecipher
