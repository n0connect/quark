// Isolated mechanism proof, whole-binary model: seals a tiny, normally
// compiled, zero-Quark-awareness EXECUTABLE in its entirety (no symbol
// search, no linker re-invocation -- just read the file and
// quark::payload::Seal it), then Unseal/dlopen/dlsym("main")/call proves
// the fully protected copy runs correctly. Real HWID_Extractor-scale proof
// lives in quark_linkload_hwid_test.cpp; this one isolates the mechanism
// from that program's complexity.
#include <cstdio>
#include <fstream>

#include "quark/linkload/loader.hpp"
#include "quark/payload.hpp"

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

std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

quark::crypto::AesKey RandomKey() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(key.size());
    std::copy(random.begin(), random.end(), key.begin());
    return key;
}

using MainFn = int (*)(int, char**);

}  // namespace

int main() {
    // Packaging time: read the WHOLE compiled binary, seal it whole. No
    // symbol name, no .o search, no linker invocation -- this is the
    // entire packaging step.
    auto binary_bytes = ReadFile(SIMPLE_FIXTURE_EXE_PATH);
    Check(!binary_bytes.empty(), "read the whole compiled fixture executable");

    auto content_key = RandomKey();
    auto sealed = quark::payload::Seal(content_key, binary_bytes);

    // Wrong-key path: must fail closed, no partial state.
    auto wrong_load = quark::linkload::ProtectedModule::Load(sealed, RandomKey(), ".");
    Check(!wrong_load.has_value(), "ProtectedModule::Load fails closed with the wrong content_key");

    auto loaded = quark::linkload::ProtectedModule::Load(sealed, content_key, ".");
    Check(loaded.has_value(), "ProtectedModule::Load succeeds with the correct content_key");
    if (!loaded) return 1;

    auto real_main = reinterpret_cast<MainFn>(loaded->Symbol("main"));
    Check(real_main != nullptr, "dlsym(\"main\") finds the sealed executable's own real entry point");
    if (!real_main) return 1;

    const std::string out_path = "./quark_linkload_simple_test_output.txt";
    char arg0[] = "simple_fixture";
    char arg1[] = "./quark_linkload_simple_test_output.txt";
    char* argv[] = {arg0, arg1, nullptr};
    int rc = real_main(2, argv);
    Check(rc == 0, "the fully protected, dlopen'd copy's main() runs to completion");

    auto output = ReadFile(out_path);
    std::string output_str(output.begin(), output.end());
    Check(output_str == "quark_linkload_simple_fixture_output",
          "the protected copy's main() produced the correct, real output -- proving the whole "
          "program (not a curated symbol) runs correctly end to end");

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
