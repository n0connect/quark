// The real, complex-program proof, whole-binary model: seals HWID_Extractor
// -- the entire compiled binary (main(), argument handling, JSON writing,
// real IOKit/DiskArbitration/CoreFoundation/sysctlbyname calls through
// quark_platform_macos, real C++ std library) -- in its entirety. No
// symbol name, no .o search, no linker re-invocation at packaging time;
// just read the file and quark::payload::Seal it.
//
// This replaces an earlier version of this test that extracted only
// MacHwidBackend::Collect() into a separate dylib -- that approach left
// the ORIGINAL HWID_Extractor binary still shipping that same code in
// plaintext, so it never actually protected anything a real attacker
// couldn't just read out of the unmodified original. Sealing the whole
// binary means the shipped artifact IS core.enc; there is no unprotected
// original sitting alongside it.
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <vector>

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

using MainFn = int (*)(int, char**);

}  // namespace

int main() {
    // Baseline: run the real, unmodified HWID_Extractor binary normally
    // (real fork+exec, exactly how a customer would run it).
    pid_t pid = fork();
    if (pid == 0) {
        execl(HWID_EXTRACTOR_PATH, HWID_EXTRACTOR_PATH, "hwid_linkload_baseline.json", (char*)nullptr);
        perror("execl");
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    Check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "baseline (real fork+exec) run succeeds");

    // Packaging time: read the WHOLE compiled HWID_Extractor binary, seal
    // it whole. This is the entire packaging step -- no symbol, no .o
    // search, no linker invocation.
    auto binary_bytes = ReadFile(HWID_EXTRACTOR_PATH);
    Check(!binary_bytes.empty(), "read the whole compiled HWID_Extractor binary");
    std::printf("HWID_Extractor is %zu bytes, sealed whole\n", binary_bytes.size());

    quark::crypto::AesKey content_key{};
    auto random = quark::crypto::RandomBytes(content_key.size());
    std::copy(random.begin(), random.end(), content_key.begin());
    auto sealed = quark::payload::Seal(content_key, binary_bytes);

    // Runtime: Unseal, dlopen, dlsym("main"), call -- with a constructed
    // argv, exactly as a real native Quark launcher would.
    auto loaded = quark::linkload::ProtectedModule::Load(sealed, content_key, ".");
    Check(loaded.has_value(), "ProtectedModule::Load succeeds on the whole, real, complex binary");
    if (!loaded) return 1;

    auto real_main = reinterpret_cast<MainFn>(loaded->Symbol("main"));
    Check(real_main != nullptr, "dlsym(\"main\") finds HWID_Extractor's own real entry point");
    if (!real_main) return 1;

    char arg0[] = "HWID_Extractor";
    char arg1[] = "hwid_linkload_protected.json";
    char* argv[] = {arg0, arg1, nullptr};
    int rc = real_main(2, argv);
    Check(rc == 0, "the fully protected, dlopen'd copy's main() runs to completion "
                   "(real IOKit/DiskArbitration/CoreFoundation calls, real file write)");

    auto baseline_json = ReadFile("hwid_linkload_baseline.json");
    auto protected_json = ReadFile("hwid_linkload_protected.json");
    Check(!baseline_json.empty() && !protected_json.empty(), "both JSON outputs are non-empty");
    Check(baseline_json == protected_json,
          "the WHOLE-BINARY pipeline (Seal entire exe -> Unseal -> dlopen -> call its own "
          "main()) produces BYTE-IDENTICAL real hardware fingerprint output to the untouched "
          "original -- on a genuinely complex real program, with zero symbol specification "
          "anywhere in the chain");

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
