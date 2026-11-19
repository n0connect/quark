// Paste_Test.exe
//
// Standalone integration test for the quark::online HTTP layer (paste.rs backend).
// Tests the full paste.rs lifecycle without any DRM crypto involved:
//
//   1. POST a test blob to paste.rs, get back a paste ID
//   2. GET the paste and verify content matches what was POSTed
//   3. DELETE the paste
//   4. Verify a fresh FetchPaste on the deleted ID returns nullopt (404)
//
// Exit code 0 = all tests passed.
// Exit code 1 = one or more tests failed (details printed to stderr).
//
// Dev-only tool; must NOT be shipped to customers.
// Makes live HTTPS requests to paste.rs and creates/deletes real pastes.

#include <cstdio>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/online.hpp"

namespace {

bool Check(bool cond, const char* label) {
    if (cond) {
        std::printf("  [PASS] %s\n", label);
    } else {
        std::fprintf(stderr, "  [FAIL] %s\n", label);
    }
    return cond;
}

std::string ToHex(const std::vector<uint8_t>& v) {
    static const char kH[] = "0123456789abcdef";
    std::string out(v.size() * 2, '\0');
    for (size_t i = 0; i < v.size(); ++i) {
        out[i * 2]     = kH[v[i] >> 4];
        out[i * 2 + 1] = kH[v[i] & 0x0F];
    }
    return out;
}

}  // namespace

int main(int /*argc*/, char** /*argv*/) {
    std::printf("Paste_Test: live integration test against paste.rs\n");
    std::printf("====================================================\n\n");

    // Use 32 random bytes as test payload (same size as a real online_secret,
    // so the test exercises the same wire format as production usage).
    const auto test_blob = quark::crypto::RandomBytes(32);
    const std::string expected_hex = ToHex(test_blob);

    std::printf("Test payload (hex): %s\n\n", expected_hex.c_str());

    bool all_ok = true;
    std::string paste_id;

    // ------------------------------------------------------------------
    // Test 1: POST paste
    // ------------------------------------------------------------------
    std::printf("[1] POST paste to paste.rs\n");
    {
        auto id = quark::online::PostPaste(test_blob);
        bool got = id.has_value() && !id->empty();
        all_ok &= Check(got, "PostPaste returned a non-empty paste ID");
        if (got) {
            paste_id = *id;
            std::printf("      paste_id: %s\n", paste_id.c_str());
            std::printf("      URL     : https://paste.rs/%s\n", paste_id.c_str());
        }
    }

    if (paste_id.empty()) {
        std::fprintf(stderr, "\nCannot continue: POST failed.\n");
        return 1;
    }

    // ------------------------------------------------------------------
    // Test 2: GET and verify content
    // ------------------------------------------------------------------
    std::printf("\n[2] GET paste content (FetchPaste)\n");
    {
        auto fetched = quark::online::FetchPaste(paste_id);
        bool got = fetched.has_value();
        all_ok &= Check(got, "FetchPaste returned a value");

        if (got) {
            bool match = (*fetched == expected_hex);
            all_ok &= Check(match, "Fetched hex matches posted content");
            if (!match) {
                std::fprintf(stderr, "    Expected: %s\n", expected_hex.c_str());
                std::fprintf(stderr, "    Got     : %s\n", fetched->c_str());
            }
        }
    }

    // ------------------------------------------------------------------
    // Test 3: DELETE paste
    // ------------------------------------------------------------------
    std::printf("\n[3] DELETE paste (DeletePaste)\n");
    {
        bool ok = quark::online::DeletePaste(paste_id);
        all_ok &= Check(ok, "DeletePaste returned true");
    }

    // ------------------------------------------------------------------
    // Test 4: Verify paste is gone (404 -> nullopt)
    // ------------------------------------------------------------------
    std::printf("\n[4] Verify paste is gone after DELETE (FetchPaste should return nullopt)\n");
    {
        auto fetched = quark::online::FetchPaste(paste_id);
        bool gone = !fetched.has_value();
        all_ok &= Check(gone, "FetchPaste after DELETE returns nullopt (kWrapperOnlineFetchFailed would fire)");
        if (!gone) {
            std::fprintf(stderr, "    Paste still returned content: %s\n", fetched->c_str());
        }
    }

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    std::printf("\n====================================================\n");
    if (all_ok) {
        std::printf("Result: ALL TESTS PASSED\n");
        return 0;
    } else {
        std::fprintf(stderr, "Result: ONE OR MORE TESTS FAILED\n");
        return 1;
    }
}
