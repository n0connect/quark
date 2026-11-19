// Real, non-mocked tests: dlopen a real dylib built from real C source
// (fixtures/*.c, compiled by the C compiler at build time -- see
// CMakeLists.txt), Capture() its real machine code, Materialize() it at a
// brand-new address, and call the reconstructed function -- comparing
// against either the real function's own output or, where the real
// function has a side effect (dep_func mutates a global), an analytically
// known expected value (calling both would double the side effect).
//
// Byte lengths below (kTinyFuncLen etc.) come from a real `otool -tv
// -arch arm64` inspection of this exact fixture dylib, not a guess -- see
// README.md's "How the fixture lengths were determined".
#include <dlfcn.h>
#include <cstdio>
#include <cstring>

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

using LongFn2 = long (*)(long, long);

void TestTinyFuncNoRelocationsNeeded(void* handle) {
    auto real_fn = reinterpret_cast<LongFn2>(dlsym(handle, "tiny_func"));
    Check(real_fn != nullptr, "dlsym(tiny_func) succeeds");

    constexpr size_t kTinyFuncLen = 0x40;  // 16 instructions, from otool -tv
    auto code_key = TestCodeKey();
    auto region = quark::codecipher::Capture(reinterpret_cast<const uint8_t*>(real_fn),
                                             kTinyFuncLen, code_key);
    Check(region.relocations.empty(), "tiny_func (no branches, no deps) needs zero relocations");

    void* materialized = quark::codecipher::Materialize(region, code_key);
    Check(materialized != nullptr, "Materialize succeeds for tiny_func");
    auto reconstructed_fn = reinterpret_cast<LongFn2>(materialized);

    long expected = real_fn(3, 4);
    long actual = reconstructed_fn(3, 4);
    Check(expected == actual, "reconstructed tiny_func produces the same result as the real function");
}

void TestBranchyFuncInternalBranchesNeedNoRelocation(void* handle) {
    auto real_fn = reinterpret_cast<LongFn2>(dlsym(handle, "branchy_func"));
    Check(real_fn != nullptr, "dlsym(branchy_func) succeeds");

    constexpr size_t kBranchyFuncLen = 0x58;  // 22 instructions, from otool -tv
    auto code_key = TestCodeKey();
    auto region = quark::codecipher::Capture(reinterpret_cast<const uint8_t*>(real_fn),
                                             kBranchyFuncLen, code_key);
    Check(region.relocations.empty(),
          "branchy_func's internal B/B.cond targets are correctly classified as needing no relocation");

    void* materialized = quark::codecipher::Materialize(region, code_key);
    Check(materialized != nullptr, "Materialize succeeds for branchy_func");
    auto reconstructed_fn = reinterpret_cast<LongFn2>(materialized);

    struct Case { long a, b; };
    Case cases[] = {{10, 3}, {3, 10}, {5, 5}};
    bool all_ok = true;
    for (auto& c : cases) {
        long expected = real_fn(c.a, c.b);
        long actual = reconstructed_fn(c.a, c.b);
        if (expected != actual) all_ok = false;
    }
    Check(all_ok, "reconstructed branchy_func's real internal branches (both directions) compute correctly");
}

void TestDepFuncExternalRelocationsPatchedCorrectly(void* handle) {
    auto real_fn = reinterpret_cast<LongFn2>(dlsym(handle, "dep_func"));
    Check(real_fn != nullptr, "dlsym(dep_func) succeeds");
    auto* g_counter = reinterpret_cast<int*>(dlsym(handle, "g_counter"));
    Check(g_counter != nullptr, "dlsym(g_counter) succeeds");
    Check(*g_counter == 100, "g_counter starts at its real initial value (100)");

    constexpr size_t kDepFuncLen = 0x6c;  // 27 instructions, from otool -tv
    auto code_key = TestCodeKey();
    auto region = quark::codecipher::Capture(reinterpret_cast<const uint8_t*>(real_fn),
                                             kDepFuncLen, code_key);
    Check(region.relocations.size() == 3,
          "dep_func's 2 ADRP (global + string literal) + 1 BL (printf) are all found as external relocations");

    void* materialized = quark::codecipher::Materialize(region, code_key);
    Check(materialized != nullptr, "Materialize succeeds for dep_func");
    auto reconstructed_fn = reinterpret_cast<LongFn2>(materialized);

    // Do NOT also call real_fn here -- it shares the same mutable global as
    // the reconstructed function, and calling both would double-count.
    // Expected value is analytically known instead.
    long expected = 100 + (5 + 6);
    long actual = reconstructed_fn(5, 6);
    Check(actual == expected,
          "reconstructed dep_func, placed at a brand-new address, correctly mutates the REAL global "
          "and calls the REAL printf via its patched ADRP/BL relocations");
    Check(*g_counter == expected, "the real global g_counter was genuinely mutated through the patched ADRP");
}

}  // namespace

int main() {
    void* handle = dlopen(FIXTURES_DYLIB_PATH, RTLD_NOW);
    if (!handle) {
        std::fprintf(stderr, "dlopen(%s) failed: %s\n", FIXTURES_DYLIB_PATH, dlerror());
        return 1;
    }

    TestTinyFuncNoRelocationsNeeded(handle);
    TestBranchyFuncInternalBranchesNeedNoRelocation(handle);
    TestDepFuncExternalRelocationsPatchedCorrectly(handle);

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
