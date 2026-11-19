// Real, non-mocked tests for quark_platform_macos. This actually calls
// sysctlbyname, IOKit, DiskArbitration, and getifaddrs on whatever Mac this
// runs on, and actually reads/writes an xattr on a real file -- see
// CLAUDE.md engineering rule 1 (no mocks, anywhere). There is no fake IOKit
// service and no stubbed sysctl table here.

#include <cstdio>
#include <filesystem>
#include <fstream>

#include "quark/crypto.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/macos/hwid_backend_macos.hpp"
#include "quark/platform/macos/xattr_witness_store.hpp"

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

void TestMacHwidBackendOnThisRealMachine() {
    quark::platform::macos::MacHwidBackend backend;
    Check(backend.PlatformName() == "macos", "MacHwidBackend::PlatformName() reports \"macos\"");

    auto fp1 = backend.Collect();
    Check(fp1.has_value(), "MacHwidBackend::Collect() succeeds on this real machine");
    if (!fp1) return;

    Check(!fp1->fields.empty(), "the collected Fingerprint is non-empty");
    for (const auto& field : fp1->fields) {
        Check(!field.value.empty(), (std::string("field '") + field.name + "' is non-empty").c_str());
    }

    auto fp2 = backend.Collect();
    Check(fp2.has_value(), "a second Collect() call also succeeds");
    if (fp2) {
        bool identical = fp1->fields.size() == fp2->fields.size();
        for (size_t i = 0; identical && i < fp1->fields.size(); ++i) {
            identical = fp1->fields[i].name == fp2->fields[i].name &&
                        fp1->fields[i].value == fp2->fields[i].value;
        }
        Check(identical, "two Collect() calls on the same machine return identical fields (real determinism, not luck)");
    }

    auto bytes1 = quark::platform::CanonicalBytes(*fp1);
    auto bytes2 = quark::platform::CanonicalBytes(*fp1);
    Check(bytes1 == bytes2, "CanonicalBytes is deterministic for the real collected Fingerprint");
}

void TestXattrWitnessStoreOnRealFile() {
    // A real file on the real filesystem (relative path -- stays under
    // sandbox/, same convention as the quark_core tests).
    const std::string host_path = "quark_macos_test_xattr_host.txt";
    {
        std::ofstream f(host_path);
        f << "quark witness host file\n";
    }

    quark::platform::macos::XattrWitnessStore store(host_path, "com.quark.test.witness",
                                                     {'Q', 'M', 'X', 'T'}, "test-xattr");

    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), key.begin());
    std::vector<uint8_t> hwid_aad = {'m', 'a', 'c', '-', 't', 'e', 's', 't'};

    quark::witness::Record missing;
    Check(store.Load(key, hwid_aad, missing) == quark::witness::LoadResult::kAbsent,
          "XattrWitnessStore reports kAbsent before any Save() (real xattr, real ENOATTR)");

    quark::witness::Record record;
    record.anchor = quark::crypto::Sha256(std::vector<uint8_t>{7, 7, 7});
    record.remaining_links = 4;
    record.hwid_digest = quark::crypto::Sha256(hwid_aad);
    record.high_water_unix_time = 99;

    Check(store.Save(key, hwid_aad, record), "XattrWitnessStore::Save writes a real xattr");

    quark::witness::Record loaded;
    Check(store.Load(key, hwid_aad, loaded) == quark::witness::LoadResult::kFound,
          "XattrWitnessStore::Load finds what Save() wrote");
    Check(loaded.anchor == record.anchor && loaded.remaining_links == record.remaining_links,
          "XattrWitnessStore round-trip preserves the record");

    quark::crypto::AesKey wrong_key{};
    quark::witness::Record wrong_out;
    Check(store.Load(wrong_key, hwid_aad, wrong_out) == quark::witness::LoadResult::kInvalid,
          "XattrWitnessStore::Load reports kInvalid for a present-but-wrong-key attribute");

    // The host file's ordinary content is untouched by the xattr -- proves
    // the witness really is a side-channel, not a visible content edit.
    std::ifstream check(host_path);
    std::string first_line;
    std::getline(check, first_line);
    Check(first_line == "quark witness host file", "the xattr does not disturb the host file's visible content");

    std::filesystem::remove(host_path);
}

}  // namespace

int main() {
    TestMacHwidBackendOnThisRealMachine();
    TestXattrWitnessStoreOnRealFile();

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
