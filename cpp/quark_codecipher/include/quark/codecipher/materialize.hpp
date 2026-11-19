#pragma once
// Module 2 ("reconstruct + run"): turns a CodeRegion back into real,
// directly executable machine code -- byte-for-byte identical to what
// Capture() originally read, with every external PC-relative reference
// re-encoded for the new address. No interpreter loop, no new instruction
// set: the returned pointer is real code the CPU executes natively.
//
// macOS-only (Apple Silicon W^X via MAP_JIT + pthread_jit_write_protect_np)
// -- see README.md for the Linux/Windows equivalents this has NOT been
// built or verified against yet.

#include <cstddef>
#include <cstdint>

#include "quark/codecipher/region.hpp"
#include "quark/crypto.hpp"

namespace quark::codecipher {

// Returns nullptr if the JIT-capable memory mapping fails. On success, the
// returned pointer is real, executable memory holding the reconstructed
// function -- caller casts it to the appropriate function-pointer type.
// The mapping is deliberately leaked for the process's lifetime (matching
// this module's test scope); a real embedder would track and eventually
// wipe/unmap it, exactly as quark_vm's now-retired BlockCache once did for
// its decrypted blocks.
void* Materialize(const CodeRegion& region, const crypto::AesKey& code_key);

}  // namespace quark::codecipher
