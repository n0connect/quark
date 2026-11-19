// The real, complex-program stress test: captures
// quark::platform::macos::MacHwidBackend::Collect()'s OWN compiled body --
// not a toy fixture -- directly. 710 real ARM64 instructions: real
// sysctlbyname calls, real IOKit/DiskArbitration/CoreFoundation calls, real
// std::optional<Fingerprint>/std::vector<FingerprintField>/std::string
// handling, 172 external ADRP/BL relocations, and TBZ/TBNZ branches
// relocation.cpp does not classify (all confirmed internal-only for this
// function -- see README.md's "Honest scope limits"). This is what found
// the real SignExtend bug fixed alongside this test (see
// quark_codecipher_relocation_test.cpp) -- kept here permanently because a
// toy fixture would never have surfaced it.
//
// Correctness check: the reconstructed, relocated Collect() must produce
// hardware fingerprint data BYTE-IDENTICAL to a real, un-relocated call --
// proving quark_codecipher's mechanism preserves full functionality on a
// genuinely complex real program, not just small synthetic examples.
#include <dlfcn.h>
#include <cstdio>

#include "quark/codecipher/capture.hpp"
#include "quark/codecipher/materialize.hpp"
#include "quark/platform/macos/hwid_backend_macos.hpp"

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

// Raw ABI shape for `std::optional<Fingerprint> Collect() const`: the
// Itanium/AAPCS64 indirect-return-slot + `this` convention, expressed
// directly so the compiler generates a matching call.
using RawCollectFn = std::optional<quark::platform::Fingerprint> (*)(
    const quark::platform::macos::MacHwidBackend*);

}  // namespace

int main() {
    void* handle = dlopen(HWID_FIXTURE_DYLIB_PATH, RTLD_NOW);
    if (!handle) {
        std::fprintf(stderr, "dlopen(%s) failed: %s\n", HWID_FIXTURE_DYLIB_PATH, dlerror());
        return 1;
    }
    // Real mangled symbol, found via `nm` on this exact fixture dylib --
    // see README.md for the command to re-derive it after a compiler change.
    void* collect_addr = dlsym(handle, "_ZNK5quark8platform5macos14MacHwidBackend7CollectEv");
    Check(collect_addr != nullptr, "dlsym finds MacHwidBackend::Collect()'s real mangled symbol");
    if (!collect_addr) return 1;

    constexpr size_t kCollectLen = 0x2268 - 0x1750;  // 710 instructions, from otool -tv
    auto code_key = []() {
        quark::crypto::AesKey key{};
        auto random = quark::crypto::RandomBytes(key.size());
        std::copy(random.begin(), random.end(), key.begin());
        return key;
    }();

    auto region = quark::codecipher::Capture(reinterpret_cast<const uint8_t*>(collect_addr),
                                             kCollectLen, code_key);
    Check(region.relocations.size() > 100,
          "a real, complex function yields a large, real relocation set (not zero, not a handful)");

    void* materialized = quark::codecipher::Materialize(region, code_key);
    Check(materialized != nullptr, "Materialize succeeds for a real 710-instruction function");
    if (!materialized) return 1;
    auto reconstructed_fn = reinterpret_cast<RawCollectFn>(materialized);

    quark::platform::macos::MacHwidBackend backend;
    auto expected = backend.Collect();
    Check(expected.has_value(), "reference (real, un-relocated) Collect() call succeeds");
    if (!expected) return 1;
    auto expected_bytes = quark::platform::CanonicalBytes(*expected);

    auto actual = reconstructed_fn(&backend);
    Check(actual.has_value(), "the reconstructed, relocated Collect() call succeeds (doesn't crash)");
    if (!actual) return 1;
    auto actual_bytes = quark::platform::CanonicalBytes(*actual);

    Check(expected->fields.size() == actual->fields.size(),
          "reconstructed Collect() reports the same field count as the real function");
    Check(expected_bytes == actual_bytes,
          "reconstructed Collect(), captured/scrambled/reconstructed/relocated by quark_codecipher, "
          "produces BYTE-IDENTICAL real hardware fingerprint data to the unmodified function -- "
          "full functional correctness preserved on a genuinely complex real program");

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
