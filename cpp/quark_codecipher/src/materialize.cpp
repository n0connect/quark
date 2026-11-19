#include "quark/codecipher/materialize.hpp"

#include <cstring>

#if defined(__APPLE__)
#include <pthread.h>
#include <sys/mman.h>
#endif

namespace quark::codecipher {

#if defined(__APPLE__)

void* Materialize(const CodeRegion& region, const crypto::AesKey& code_key) {
    size_t region_size = region.scrambled.size();
    if (region_size == 0) return nullptr;

    void* mapped = mmap(nullptr, region_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (mapped == MAP_FAILED) return nullptr;
    auto* bytes = static_cast<uint8_t*>(mapped);
    auto new_base = reinterpret_cast<uint64_t>(bytes);

    // Module 2, step 1: reconstruct the real instruction bytes exactly
    // (same AES-256-CTR transform, same key+nonce as Capture used -- CTR's
    // self-inverting property does the rest).
    auto reconstructed = crypto::Aes256CtrXor(code_key, region.nonce, region.scrambled);

    pthread_jit_write_protect_np(0);  // writable phase (never simultaneously executable)
    std::memcpy(bytes, reconstructed.data(), reconstructed.size());

    // Module 2, step 2: patch every external PC-relative reference so it
    // reaches the SAME absolute target from the region's new address.
    // Internal references need no patching -- proven safe in capture.cpp's
    // comment: the whole block moved together, relative offsets held.
    for (const auto& reloc : region.relocations) {
        if (reloc.offset + 4 > reconstructed.size()) continue;  // defensive: malformed region
        uint32_t instr = 0;
        std::memcpy(&instr, bytes + reloc.offset, 4);
        uint64_t new_pc = new_base + reloc.offset;
        uint32_t patched = EncodeForTarget(new_pc, instr, reloc.kind, reloc.original_absolute_target);
        std::memcpy(bytes + reloc.offset, &patched, 4);
    }

    pthread_jit_write_protect_np(1);  // executable phase
    __builtin___clear_cache(reinterpret_cast<char*>(bytes),
                            reinterpret_cast<char*>(bytes) + region_size);
    return mapped;
}

#else

void* Materialize(const CodeRegion&, const crypto::AesKey&) {
    // Not yet built or verified on this OS -- see README.md. Returning
    // nullptr rather than a half-working implementation: a caller checking
    // the return value fails safely instead of executing garbage.
    return nullptr;
}

#endif

}  // namespace quark::codecipher
