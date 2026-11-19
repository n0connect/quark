#pragma once
// ARM64 PC-relative instruction detection and re-encoding. When a captured
// function's bytes are placed at a NEW address (Materialize), any
// instruction whose behavior depends on ITS OWN address needs its encoding
// updated so it still reaches the same real target -- exactly what a
// dynamic linker does when loading a position-independent shared library at
// a different base address.
//
// Scope (honest limits, not exhaustive ARM64 coverage): ADRP, B, BL, and
// B.cond -- the four PC-relative forms clang actually emits for the
// simple, dependency-bearing functions this module targets (global/string
// access via ADRP, unconditional jumps, calls, conditional branches).
// CBZ/CBNZ/TBZ/TBNZ and PC-relative literal loads (LDR literal) are NOT
// handled -- code using them will be mis-relocated if it has external
// (out-of-region) targets. See cpp/quark_codecipher/README.md.
//
// Detection is a bit-pattern scan over raw bytes, not a real disassembler
// and not linker relocation records -- a plausible false positive (a 4-byte
// word that happens to match one of these patterns but is actually literal
// data embedded in the function, e.g. a jump table or constant pool entry)
// is a real, open risk for code more complex than what this module has
// been tested against. See README.md.

#include <cstdint>
#include <optional>

namespace quark::codecipher {

enum class RelocKind : uint8_t {
    kAdrp = 1,
    kB = 2,
    kBl = 3,
    kBCond = 4,
};

// Returns the instruction's PC-relative kind if `instr`'s bits match one of
// ADRP/B/BL/B.cond's fixed encoding, or nullopt otherwise (an ordinary,
// non-PC-relative instruction as far as this module is concerned).
std::optional<RelocKind> ClassifyInstruction(uint32_t instr);

// Decodes the absolute address `instr` (of the given `kind`, located at
// real address `pc`) computes. For ADRP this is the 4KB PAGE address (ADRP
// is always paired with a same-page-relative ADD/LDR for the low 12 bits,
// which needs no relocation since it's a constant offset, not PC-relative).
uint64_t DecodeTarget(uint64_t pc, uint32_t instr, RelocKind kind);

// Re-encodes `instr` so that, placed at `new_pc`, it computes exactly
// `target` -- preserving every bit that isn't part of the PC-relative
// immediate (ADRP's destination register, B.cond's condition code, etc.).
uint32_t EncodeForTarget(uint64_t new_pc, uint32_t instr, RelocKind kind, uint64_t target);

}  // namespace quark::codecipher
