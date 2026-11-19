// HWID_Extractor.exe
//
// Run on the customer's machine (or by the customer, before purchase) to
// produce a JSON snapshot of their hardware fingerprint. The developer feeds
// this file into Dev_Keygen to mint a machine-bound license.
//
// Deliberately the simplest tool in the repo: collect, render, write. No
// crypto, no secrets -- this output is meant to be emailed/uploaded.
//
// Cross-platform via quark::platform::IHwidBackend: the concrete backend
// (Windows SMBIOS/CPUID, macOS sysctl/IOKit/DiskArbitration, Linux /proc +
// /sys/class/dmi) is selected at compile time by whichever quark_platform_<os>
// target this OS built -- this file has zero OS-specific code itself.

#include <cstdio>
#include <fstream>
#include <memory>
#include <string>

#include "quark/error.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/hwid_json.hpp"

#if defined(__APPLE__)
#include "quark/platform/macos/hwid_backend_macos.hpp"
#elif defined(__linux__)
#include "quark/platform/linux/hwid_backend_linux.hpp"
#elif defined(_WIN32)
#include "quark/platform/windows/hwid_backend_win.hpp"
#endif

namespace {

constexpr const char* kComponent = "HWID_Extractor";

void PrintUsage(const char* argv0) {
    std::fprintf(stderr, "Usage: %s [output.json]\n", argv0);
    std::fprintf(stderr, "  Collects this machine's hardware fingerprint and writes it as JSON.\n");
    std::fprintf(stderr, "  Defaults to hwid.json in the current directory.\n");
}

std::unique_ptr<quark::platform::IHwidBackend> MakeBackend() {
#if defined(__APPLE__)
    return std::make_unique<quark::platform::macos::MacHwidBackend>();
#elif defined(__linux__)
    return std::make_unique<quark::platform::linux_::LinuxHwidBackend>();
#elif defined(_WIN32)
    return std::make_unique<quark::platform::win::WindowsHwidBackend>();
#else
    return nullptr;
#endif
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 2) {
        PrintUsage(argv[0]);
        return 2;
    }

    std::string out_path = (argc == 2) ? argv[1] : "hwid.json";

    auto backend = MakeBackend();
    if (!backend) {
        quark::error::Report(quark::error::Code::kHwidFieldUnreadable, kComponent,
                             "no HWID backend built for this platform");
        return 1;
    }

    auto fingerprint = backend->Collect();
    if (!fingerprint) {
        // Not a fail-deadly context (this tool isn't part of the protected
        // runtime) -- a clear diagnostic here genuinely helps the customer,
        // and is also recorded with a stable code for support purposes.
        quark::error::Report(quark::error::Code::kHwidFieldUnreadable, kComponent,
                             "one or more fingerprint fields could not be read -- "
                             "on Windows, try running elevated (Administrator)");
        return 1;
    }

    std::string json = quark::platform::FingerprintToJson(
        std::string(backend->PlatformName()), *fingerprint);

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        quark::error::Report(quark::error::Code::kExtractorOutputOpenFailed, kComponent, out_path.c_str());
        return 1;
    }
    out << json;
    out.close();
    if (!out) {
        quark::error::Report(quark::error::Code::kExtractorJsonWriteFailed, kComponent, out_path.c_str());
        return 1;
    }

    std::printf("Hardware fingerprint written to '%s'.\n", out_path.c_str());
    std::printf("Send this file to your software provider to receive your license.\n");
    return 0;
}
