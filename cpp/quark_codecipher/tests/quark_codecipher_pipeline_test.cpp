// Proves the real, single-encryption-layer pipeline end to end, the same
// discipline already proven for quark_vm's (now-retired) bytecode approach
// -- but here the "bytecode" IS the real, unmodified ARM64 machine code:
//
//   (issuance)  real dep_func -> Capture(code_key) -> SerializeCodeRegion
//               -> quark::payload::Seal(content_key)   [this IS core.enc]
//
//   (runtime)   core.enc bytes -> quark::payload::Unseal(content_key)
//               -> DeserializeCodeRegion
//               -> Materialize(DeriveCodeStreamKey(content_key)) -> call it
//
// A wrong content_key must fail at Unseal -- structurally, via the AES-GCM
// auth tag -- before quark_codecipher ever sees a byte, exactly mirroring
// quark_vm_pipeline_test.cpp's proof for the bytecode approach.
#include <dlfcn.h>
#include <cstdio>

#include "quark/codecipher/capture.hpp"
#include "quark/codecipher/materialize.hpp"
#include "quark/payload.hpp"
#include "quark/token.hpp"

namespace {

int g_failures = 0;

void Check(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_failures;
    } else {
        std::printf("ok: %s\n", what);
    }
}

quark::crypto::AesKey RandomKey() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(key.size());
    std::copy(random.begin(), random.end(), key.begin());
    return key;
}

using LongFn2 = long (*)(long, long);

void TestSingleEncryptionRoundTrip(void* handle, void* dep_func_addr, size_t dep_func_len) {
    auto content_key = RandomKey();
    auto code_key = quark::token::DeriveCodeStreamKey(content_key);

    // --- issuance side ---
    auto region = quark::codecipher::Capture(reinterpret_cast<const uint8_t*>(dep_func_addr),
                                             dep_func_len, code_key);
    auto plaintext = quark::codecipher::SerializeCodeRegion(region);
    auto core_enc_bytes = quark::payload::Seal(content_key, plaintext);  // the ONLY encryption step

    // --- runtime side ---
    auto unsealed = quark::payload::Unseal(content_key, core_enc_bytes);
    Check(unsealed.has_value(), "core.enc-equivalent decrypts with the right content_key");

    auto restored = quark::codecipher::DeserializeCodeRegion(*unsealed);
    Check(restored.has_value(), "the single-decrypt plaintext is a valid CodeRegion container");
    Check(restored->relocations.size() == 3, "dep_func's 3 relocations survive the serialize round-trip");

    auto code_key_at_runtime = quark::token::DeriveCodeStreamKey(content_key);
    void* materialized = quark::codecipher::Materialize(*restored, code_key_at_runtime);
    Check(materialized != nullptr, "Materialize succeeds from the deserialized region");

    auto reconstructed_fn = reinterpret_cast<LongFn2>(materialized);
    auto* g_counter = reinterpret_cast<int*>(dlsym(handle, "g_counter"));
    int before = *g_counter;
    long result = reconstructed_fn(7, 8);
    Check(result == before + 15,
          "real dep_func, captured/sealed/unsealed/materialized through the FULL pipeline, still "
          "correctly mutates the real global and returns the right value -- through exactly ONE "
          "AES-GCM decrypt");
}

void TestWrongContentKeyFailsBeforeCodecipherEverRuns(void* dep_func_addr, size_t dep_func_len) {
    auto right_key = RandomKey();
    auto wrong_key = RandomKey();
    auto code_key = quark::token::DeriveCodeStreamKey(right_key);

    auto region = quark::codecipher::Capture(reinterpret_cast<const uint8_t*>(dep_func_addr),
                                             dep_func_len, code_key);
    auto plaintext = quark::codecipher::SerializeCodeRegion(region);
    auto core_enc_bytes = quark::payload::Seal(right_key, plaintext);

    auto unsealed = quark::payload::Unseal(wrong_key, core_enc_bytes);
    Check(!unsealed.has_value(),
          "wrong content_key fails the OUTER AES-GCM auth tag -- quark_codecipher never receives a "
          "byte, never needs its own wrong-key handling (same discipline as quark_vm's retired "
          "BlockCache proof, now at the real-machine-code layer)");
}

}  // namespace

int main() {
    void* handle = dlopen(FIXTURES_DYLIB_PATH, RTLD_NOW);
    if (!handle) {
        std::fprintf(stderr, "dlopen(%s) failed: %s\n", FIXTURES_DYLIB_PATH, dlerror());
        return 1;
    }
    void* dep_func_addr = dlsym(handle, "dep_func");
    if (!dep_func_addr) {
        std::fprintf(stderr, "dlsym(dep_func) failed: %s\n", dlerror());
        return 1;
    }
    constexpr size_t kDepFuncLen = 0x6c;  // 27 instructions, from otool -tv

    TestSingleEncryptionRoundTrip(handle, dep_func_addr, kDepFuncLen);
    TestWrongContentKeyFailsBeforeCodecipherEverRuns(dep_func_addr, kDepFuncLen);

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
