#include "quark/codecipher/relocation.hpp"

namespace quark::codecipher {

namespace {

bool IsAdrp(uint32_t instr) { return (instr & 0x9F000000u) == 0x90000000u; }
bool IsB(uint32_t instr) { return (instr & 0xFC000000u) == 0x14000000u; }
bool IsBl(uint32_t instr) { return (instr & 0xFC000000u) == 0x94000000u; }
// B.cond: bits[31:24] = 0101_0100, bit4 = 0 (distinguishes it from other
// 0x54-prefixed encodings), cond = bits[3:0].
bool IsBCond(uint32_t instr) { return (instr & 0xFF000010u) == 0x54000000u; }

int64_t SignExtend(uint32_t value, int bits) {
    // (value ^ sign_bit) - sign_bit is computed in uint32_t, so the result's
    // BIT PATTERN is the correct negative two's-complement value, but
    // widening a uint32_t straight to int64_t zero-extends (it's an
    // unsigned->signed WIDENING conversion, not a reinterpretation) --
    // producing a huge positive number instead of a small negative one for
    // any negative offset. Reinterpreting as int32_t first forces a signed
    // widening (sign-extension) on the next conversion. Real, confirmed bug:
    // every negative-offset B/BL/B.cond/ADRP in a captured function decoded
    // to `correct_target + 2^34`, silently masked in all prior tests because
    // none of them exercised a backward branch/call large enough to matter
    // -- found via a real 710-instruction capture of
    // quark::platform::macos::MacHwidBackend::Collect() (see
    // cpp/quark_codecipher/tests/quark_codecipher_hwid_test.cpp).
    uint32_t sign_bit = 1u << (bits - 1);
    return static_cast<int64_t>(static_cast<int32_t>((value ^ sign_bit) - sign_bit));
}

uint64_t DecodeAdrpTarget(uint64_t pc, uint32_t instr) {
    uint32_t immlo = (instr >> 29) & 0x3u;
    uint32_t immhi = (instr >> 5) & 0x7FFFFu;
    int64_t imm21 = SignExtend((immhi << 2) | immlo, 21);
    return (pc & ~static_cast<uint64_t>(0xFFF)) + static_cast<uint64_t>(imm21 << 12);
}

uint32_t EncodeAdrp(uint64_t new_pc, uint64_t target_page, uint32_t original_instr) {
    uint32_t rd_bits = original_instr & 0x1Fu;
    int64_t imm21 = static_cast<int64_t>((target_page & ~static_cast<uint64_t>(0xFFF)) -
                                         (new_pc & ~static_cast<uint64_t>(0xFFF))) >> 12;
    uint32_t immlo = static_cast<uint32_t>(imm21) & 0x3u;
    uint32_t immhi = (static_cast<uint32_t>(imm21) >> 2) & 0x7FFFFu;
    return 0x90000000u | (immlo << 29) | (immhi << 5) | rd_bits;
}

uint64_t DecodeBranch26Target(uint64_t pc, uint32_t instr) {
    int64_t imm26 = SignExtend(instr & 0x03FFFFFFu, 26);
    return pc + static_cast<uint64_t>(imm26 * 4);
}

uint32_t EncodeBranch26(uint64_t new_pc, uint64_t target, uint32_t opcode_bits) {
    int64_t imm26 = (static_cast<int64_t>(target) - static_cast<int64_t>(new_pc)) / 4;
    return opcode_bits | (static_cast<uint32_t>(imm26) & 0x03FFFFFFu);
}

uint64_t DecodeBCondTarget(uint64_t pc, uint32_t instr) {
    int64_t imm19 = SignExtend((instr >> 5) & 0x7FFFFu, 19);
    return pc + static_cast<uint64_t>(imm19 * 4);
}

uint32_t EncodeBCond(uint64_t new_pc, uint64_t target, uint32_t original_instr) {
    uint32_t cond_bits = original_instr & 0xFu;
    int64_t imm19 = (static_cast<int64_t>(target) - static_cast<int64_t>(new_pc)) / 4;
    return 0x54000000u | ((static_cast<uint32_t>(imm19) & 0x7FFFFu) << 5) | cond_bits;
}

}  // namespace

std::optional<RelocKind> ClassifyInstruction(uint32_t instr) {
    // Order matters: IsAdrp/IsB/IsBl are mutually exclusive by construction
    // (top-bit patterns don't overlap), but check the narrower B.cond mask
    // (which also constrains bit 4) after the wider ones for clarity.
    if (IsAdrp(instr)) return RelocKind::kAdrp;
    if (IsBl(instr)) return RelocKind::kBl;
    if (IsB(instr)) return RelocKind::kB;
    if (IsBCond(instr)) return RelocKind::kBCond;
    return std::nullopt;
}

uint64_t DecodeTarget(uint64_t pc, uint32_t instr, RelocKind kind) {
    switch (kind) {
        case RelocKind::kAdrp: return DecodeAdrpTarget(pc, instr);
        case RelocKind::kB:
        case RelocKind::kBl: return DecodeBranch26Target(pc, instr);
        case RelocKind::kBCond: return DecodeBCondTarget(pc, instr);
    }
    return 0;
}

uint32_t EncodeForTarget(uint64_t new_pc, uint32_t instr, RelocKind kind, uint64_t target) {
    switch (kind) {
        case RelocKind::kAdrp: return EncodeAdrp(new_pc, target, instr);
        case RelocKind::kB: return EncodeBranch26(new_pc, target, 0x14000000u);
        case RelocKind::kBl: return EncodeBranch26(new_pc, target, 0x94000000u);
        case RelocKind::kBCond: return EncodeBCond(new_pc, target, instr);
    }
    return instr;
}

}  // namespace quark::codecipher
