// Regression test for a real, confirmed bug: relocation.cpp's SignExtend
// widened an already-correct negative two's-complement bit pattern from
// uint32_t to int64_t via zero-extension instead of sign-extension,
// corrupting every NEGATIVE-offset B/BL/B.cond/ADRP target by +2^34. Every
// other fixture (tiny_func, branchy_func, dep_func) only exercises forward
// (positive-offset) branches/calls, so this went undetected until a real,
// 710-instruction capture of MacHwidBackend::Collect() surfaced it (see
// quark_codecipher_hwid_test.cpp) -- 20 of its 172 relocations were silently
// wrong, masked only because the corrupted call targets happened to be on
// code paths this repo's earlier tests never exercised.
//
// caller_after calls helper_before, which is compiled EARLIER in the same
// file -- a real, compiler-generated BACKWARD (negative-offset) BL.
#include <dlfcn.h>
#include <cstdio>

#include "quark/codecipher/capture.hpp"
#include "quark/codecipher/materialize.hpp"

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

quark::crypto::AesKey TestCodeKey() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(key.size());
    std::copy(random.begin(), random.end(), key.begin());
    return key;
}

using LongFn1 = long (*)(long);

void TestBackwardCallRelocatesCorrectly(void* handle) {
    auto real_fn = reinterpret_cast<LongFn1>(dlsym(handle, "caller_after"));
    Check(real_fn != nullptr, "dlsym(caller_after) succeeds");

    constexpr size_t kCallerAfterLen = 0x28;  // 10 instructions, from otool -tv
    auto code_key = TestCodeKey();
    auto region = quark::codecipher::Capture(reinterpret_cast<const uint8_t*>(real_fn),
                                             kCallerAfterLen, code_key);
    Check(region.relocations.size() == 1,
          "caller_after's single BL to helper_before is found as one external relocation");

    if (!region.relocations.empty()) {
        auto real_base = reinterpret_cast<uint64_t>(real_fn);
        Check(region.relocations[0].original_absolute_target < real_base,
              "the decoded target is a real BACKWARD address (before caller_after itself) -- "
              "the exact case the SignExtend bug corrupted");
    }

    void* materialized = quark::codecipher::Materialize(region, code_key);
    Check(materialized != nullptr, "Materialize succeeds for caller_after");
    auto reconstructed_fn = reinterpret_cast<LongFn1>(materialized);

    long expected = real_fn(41);
    long actual = reconstructed_fn(41);
    Check(expected == actual,
          "reconstructed caller_after, with its backward-BL relocation patched, computes "
          "(41+1)*2 == 84 correctly -- would have jumped to a wild address (target+2^34) "
          "and crashed under the original buggy SignExtend");
}

}  // namespace

int main() {
    void* handle = dlopen(FIXTURES_DYLIB_PATH, RTLD_NOW);
    if (!handle) {
        std::fprintf(stderr, "dlopen(%s) failed: %s\n", FIXTURES_DYLIB_PATH, dlerror());
        return 1;
    }

    TestBackwardCallRelocatesCorrectly(handle);

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
