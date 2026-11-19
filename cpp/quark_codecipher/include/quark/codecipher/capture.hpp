#pragma once
// Module 1 ("scramble"): turns `length` bytes of real, live machine code
// into a CodeRegion whose `scrambled` bytes don't resemble the original
// instructions, plus the small list of external PC-relative fixups needed
// to run correctly once relocated (see materialize.hpp).
//
// Honest scope: `code` must already be loaded and resolved (e.g. via
// dlopen, exactly like every capture in this module's tests) -- this proves
// the RUNTIME mechanism (scramble/reconstruct/relocate/execute) for real.
// A real dev-time toolchain step that captures straight from a linker's
// relocation records (rather than a live, same-process function pointer)
// does not exist yet -- the same class of gap as quark_vm's retired
// qvm_aktif. See README.md.

#include <cstddef>
#include <cstdint>

#include "quark/codecipher/region.hpp"
#include "quark/crypto.hpp"

namespace quark::codecipher {

CodeRegion Capture(const uint8_t* code, size_t length, const crypto::AesKey& code_key);

}  // namespace quark::codecipher
