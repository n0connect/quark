# Phase A: Cross-Platform Porting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `HWID_Extractor`, `handoff_spy`, and `quark-runtime-c` -- the three Windows-only programs identified as needing no new shared infrastructure -- to build and run for real on macOS and Linux, removing their Win32-only code paths.

**Architecture:** `HWID_Extractor` switches from the legacy Windows-only `quark::hwid::Collect()`/`ToJson()` to the already-portable `quark::platform::IHwidBackend` contract, plus a new portable JSON codec for the generic `Fingerprint` type (this codec doesn't exist yet -- it's new, small, quark_core-resident work). `handoff_spy` keeps its Windows CNG HMAC path unchanged but adds a genuinely independent, hand-rolled, dependency-free SHA-256/HMAC-SHA256 for non-Windows builds (it must NOT depend on `quark_core`, by design -- see Task 3). `quark-runtime-c` switches its CNG calls to `quark_core`'s already-audited `quark::crypto`/`quark::token` functions (no independence constraint here -- it's a real runtime library, not a test double), replaces Win32 threading/pipe I/O with `std::thread`/POSIX file descriptors, and gets wired into the top-level build for the first time.

**Tech Stack:** C++17, CMake, the project's existing hand-rolled `Check()`-style test harness. Task 3 and Task 4 also use raw POSIX `fork`/`pipe`/`exec` for real (non-mocked) end-to-end pipe tests -- this plan only covers macOS/Linux; Windows re-verification is explicitly out of scope (see the roadmap spec's non-goals).

Reference: [docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md](../specs/2026-07-05-cross-platform-porting-roadmap.md)

---

## File structure

```
cpp/common/include/quark/platform/hwid_json.hpp   new: Fingerprint <-> JSON codec
cpp/common/src/platform_hwid_json.cpp             new
cpp/common/tests/core_smoke_test.cpp              modify: add hwid_json round-trip test
cpp/common/CMakeLists.txt                         modify: add platform_hwid_json.cpp to quark_core; define quark_common for APPLE/UNIX too

cpp/hwid_extractor/main.cpp                       modify: IHwidBackend + hwid_json instead of quark::hwid
cpp/hwid_extractor/README.md                      modify: drop Windows-only build note

cpp/handoff_spy/main.cpp                          modify: add portable SHA-256/HMAC-SHA256, POSIX I/O branch
cpp/handoff_spy/tests/CMakeLists.txt              new
cpp/handoff_spy/tests/handoff_spy_e2e_test.cpp    new: real fork/pipe end-to-end test
cpp/handoff_spy/README.md                         modify

cpp/quark-runtime-c/quark_runtime.cpp             modify: quark_core crypto, POSIX I/O, std::thread
cpp/quark-runtime-c/CMakeLists.txt                modify: cross-platform, link quark_core, drop MSVC-only flags
cpp/quark-runtime-c/tests/CMakeLists.txt          new
cpp/quark-runtime-c/tests/test_protected_app.cpp  new: tiny app linking quark_runtime
cpp/quark-runtime-c/tests/quark_runtime_e2e_test.cpp  new: real fork/pipe end-to-end test
cpp/quark-runtime-c/README.md                     modify

CMakeLists.txt                                    modify: un-gate hwid_extractor/handoff_spy/quark-runtime-c from WIN32
docs/PLAN.md                                      modify: record Phase X
```

---

### Task 1: Portable `Fingerprint` <-> JSON codec in `quark_core`

**Files:**
- Create: `cpp/common/include/quark/platform/hwid_json.hpp`
- Create: `cpp/common/src/platform_hwid_json.cpp`
- Modify: `cpp/common/CMakeLists.txt`
- Modify: `cpp/common/tests/core_smoke_test.cpp`

`quark::platform::Fingerprint` (an ordered list of `{name, value}` fields, see
`quark/platform/hwid_backend.hpp`) has no JSON serialization today -- only the
legacy, Windows-only `quark::hwid::Components` does (`ToJson`/`FromJson` in
`hwid.cpp`, which only compiles into `quark_platform_win`). `HWID_Extractor`
needs a portable equivalent so its output JSON works the same shape on every
OS, tagged with which OS produced it (`IHwidBackend::PlatformName()`) so a
license-issuing tool can reject a cross-platform mismatch outright.

- [ ] **Step 1: Write the failing test**

Add to `cpp/common/tests/core_smoke_test.cpp`, right after
`TestPlatformCanonicalBytes()`'s definition (insert immediately after its
closing `}`):

```cpp
void TestFingerprintJsonRoundTrip() {
    quark::platform::Fingerprint fp;
    fp.fields.push_back({"cpu_vendor_signature", "GenuineIntel:AAA"});
    fp.fields.push_back({"machine_guid", "1234-5678"});
    fp.fields.push_back({"quote_and_backslash", "a\"b\\c"});

    std::string json = quark::platform::FingerprintToJson("macos", fp);
    Check(json.find("\"platform\"") != std::string::npos,
          "FingerprintToJson includes a platform field");
    Check(json.find("macos") != std::string::npos,
          "FingerprintToJson includes the given platform name");

    auto parsed = quark::platform::FingerprintFromJson(json);
    Check(parsed.has_value(), "FingerprintFromJson parses FingerprintToJson's own output");
    if (parsed) {
        Check(parsed->platform_name == "macos", "platform_name round-trips");
        Check(parsed->fingerprint.fields.size() == 3, "field count round-trips");
        Check(parsed->fingerprint.fields[0].name == "cpu_vendor_signature" &&
                  parsed->fingerprint.fields[0].value == "GenuineIntel:AAA",
              "field 0 round-trips exactly");
        Check(parsed->fingerprint.fields[2].value == "a\"b\\c",
              "escaped quote/backslash round-trips exactly");
        Check(quark::platform::CanonicalBytes(parsed->fingerprint) ==
                  quark::platform::CanonicalBytes(fp),
              "CanonicalBytes is identical before and after the JSON round-trip");
    }

    Check(!quark::platform::FingerprintFromJson("not json at all").has_value(),
          "FingerprintFromJson rejects malformed input");
}
```

Add `TestFingerprintJsonRoundTrip();` to `main()`, right after
`TestPlatformCanonicalBytes();`.

- [ ] **Step 2: Run test to verify it fails (does not compile)**

Run: `cmake --build sandbox/build-macos --target quark_core_tests`
Expected: FAIL -- `error: no member named 'FingerprintToJson' in namespace 'quark::platform'` (the header doesn't exist yet, so also add `#include "quark/platform/hwid_json.hpp"` to the test file's includes now, right after the existing `#include "quark/platform/hwid_backend.hpp"` line -- this makes the failure be "file not found" instead, which is fine, same intent).

- [ ] **Step 3: Write the header**

Create `cpp/common/include/quark/platform/hwid_json.hpp`:

```cpp
#pragma once
// JSON transport for quark::platform::Fingerprint -- the cross-platform
// successor to quark::hwid::ToJson/FromJson (Windows-only, cpp/quark_hwid.hpp),
// used by HWID_Extractor to hand a fingerprint from the licensed machine to
// whatever machine mints its license. Tags the JSON with which platform
// backend produced it (IHwidBackend::PlatformName()) so a mismatch (e.g. a
// macOS-collected fingerprint fed into a Windows-built keygen) is rejected
// outright instead of producing a state.bin that can never authenticate.

#include <optional>
#include <string>

#include "quark/platform/hwid_backend.hpp"

namespace quark::platform {

// {"platform": "<platform_name>", "fields": [{"name": "...", "value": "..."}, ...]}
std::string FingerprintToJson(const std::string& platform_name, const Fingerprint& fp);

struct ParsedFingerprint {
    std::string platform_name;
    Fingerprint fingerprint;
};

// Returns nullopt on malformed JSON. Not a general JSON parser -- Quark only
// ever reads files this codebase itself wrote (same posture as
// quark::hwid::FromJson).
std::optional<ParsedFingerprint> FingerprintFromJson(const std::string& json);

}  // namespace quark::platform
```

- [ ] **Step 4: Write the implementation**

Create `cpp/common/src/platform_hwid_json.cpp`:

```cpp
#include "quark/platform/hwid_json.hpp"

#include <sstream>

namespace quark::platform {

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

// Finds the next `"key": "value"` pair at or after `pos`, honoring the same
// escaping FieldToJson produces (\" and \\ only -- no unicode escapes, this
// is not a general JSON parser). Returns the byte offset just past the
// closing quote of the value, or std::string::npos on failure.
std::optional<std::pair<std::string, std::string>> ParseNextStringField(
    const std::string& json, size_t start, size_t* end_out) {
    size_t key_start = json.find('"', start);
    if (key_start == std::string::npos) return std::nullopt;
    size_t key_end = json.find('"', key_start + 1);
    if (key_end == std::string::npos) return std::nullopt;
    std::string key = json.substr(key_start + 1, key_end - key_start - 1);

    size_t colon = json.find(':', key_end);
    if (colon == std::string::npos) return std::nullopt;
    size_t val_start = json.find('"', colon);
    if (val_start == std::string::npos) return std::nullopt;

    std::string value;
    size_t i = val_start + 1;
    while (i < json.size() && json[i] != '"') {
        if (json[i] == '\\' && i + 1 < json.size()) ++i;
        value.push_back(json[i]);
        ++i;
    }
    if (i >= json.size()) return std::nullopt;
    *end_out = i + 1;
    return std::make_pair(key, value);
}

}  // namespace

std::string FingerprintToJson(const std::string& platform_name, const Fingerprint& fp) {
    std::ostringstream oss;
    oss << "{\n  \"platform\": \"" << JsonEscape(platform_name) << "\",\n  \"fields\": [\n";
    for (size_t i = 0; i < fp.fields.size(); ++i) {
        oss << "    {\"name\": \"" << JsonEscape(fp.fields[i].name)
            << "\", \"value\": \"" << JsonEscape(fp.fields[i].value) << "\"}";
        if (i + 1 != fp.fields.size()) oss << ',';
        oss << '\n';
    }
    oss << "  ]\n}\n";
    return oss.str();
}

std::optional<ParsedFingerprint> FingerprintFromJson(const std::string& json) {
    size_t platform_pos = json.find("\"platform\"");
    if (platform_pos == std::string::npos) return std::nullopt;
    size_t end = 0;
    auto platform_field = ParseNextStringField(json, platform_pos, &end);
    if (!platform_field) return std::nullopt;

    size_t fields_pos = json.find("\"fields\"", end);
    if (fields_pos == std::string::npos) return std::nullopt;
    size_t array_start = json.find('[', fields_pos);
    if (array_start == std::string::npos) return std::nullopt;
    size_t array_end = json.find(']', array_start);
    if (array_end == std::string::npos) return std::nullopt;

    ParsedFingerprint result;
    result.platform_name = platform_field->second;

    size_t pos = array_start + 1;
    while (pos < array_end) {
        size_t name_search_end = 0;
        size_t brace = json.find('{', pos);
        if (brace == std::string::npos || brace >= array_end) break;

        auto name_field = ParseNextStringField(json, brace, &name_search_end);
        if (!name_field || name_field->first != "name") return std::nullopt;

        size_t value_search_end = 0;
        auto value_field = ParseNextStringField(json, name_search_end, &value_search_end);
        if (!value_field || value_field->first != "value") return std::nullopt;

        result.fingerprint.fields.push_back({name_field->second, value_field->second});
        pos = value_search_end;
    }

    if (result.fingerprint.fields.empty()) return std::nullopt;
    return result;
}

}  // namespace quark::platform
```

- [ ] **Step 5: Wire the new file into the build**

In `cpp/common/CMakeLists.txt`, add `src/platform_hwid_json.cpp` to
`quark_core`'s source list (alongside the existing `src/platform_hwid.cpp`
line):

```cmake
add_library(quark_core STATIC
    src/crypto.cpp
    src/error.cpp
    src/handoff.cpp
    src/lamport.cpp
    src/orchestrator.cpp
    src/payload_codec.cpp
    src/platform_file_witness_store.cpp
    src/platform_hwid.cpp
    src/platform_hwid_json.cpp
    src/state.cpp
    src/token.cpp
    src/witness_codec.cpp
)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target quark_core_tests && ./sandbox/build-macos/cpp/common/tests/quark_core_tests`
Expected: all `TestFingerprintJsonRoundTrip` checks print `ok:`, `all checks passed.`, exit code 0.

- [ ] **Step 7: Commit**

```bash
git add cpp/common/include/quark/platform/hwid_json.hpp cpp/common/src/platform_hwid_json.cpp cpp/common/CMakeLists.txt cpp/common/tests/core_smoke_test.cpp
git commit -m "Add portable Fingerprint<->JSON codec to quark_core"
```

---

### Task 2: `quark_common` INTERFACE target for macOS/Linux + port `HWID_Extractor`

**Files:**
- Modify: `cpp/common/CMakeLists.txt`
- Modify: `cpp/hwid_extractor/main.cpp`
- Modify: `cpp/hwid_extractor/README.md`
- Modify: `CMakeLists.txt` (top-level)

- [ ] **Step 1: Add `quark_common` for macOS and Linux**

In `cpp/common/CMakeLists.txt`, at the end of the `if(APPLE)` block (right
before its closing `endif()`), add:

```cmake
    # quark_common: kept as the combined name every executable already links
    # against, same convention as the Windows quark_common INTERFACE target
    # above -- lets HWID_Extractor/handoff_spy/quark-runtime-c and (later)
    # Dev_Keygen/DRM_Wrapper/paste_test link one name regardless of OS.
    add_library(quark_common INTERFACE)
    target_link_libraries(quark_common INTERFACE quark_core quark_platform_macos)
```

At the end of the `if(UNIX AND NOT APPLE)` block (right before its closing
`endif()`), add the equivalent:

```cmake
    add_library(quark_common INTERFACE)
    target_link_libraries(quark_common INTERFACE quark_core quark_platform_linux)
```

- [ ] **Step 2: Run configure to verify it doesn't break anything**

Run: `cmake -S . -B sandbox/build-macos`
Expected: configures cleanly (no "target already defined" error -- `quark_common` is now defined exactly once, inside whichever OS branch actually runs).

- [ ] **Step 3: Rewrite `HWID_Extractor` to use `IHwidBackend`**

Replace the contents of `cpp/hwid_extractor/main.cpp`:

```cpp
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
```

- [ ] **Step 4: Un-gate `hwid_extractor` from `WIN32` in the top-level build**

In the top-level `CMakeLists.txt`, move `add_subdirectory(cpp/hwid_extractor)`
out of the `if(WIN32)` block entirely. Replace:

```cmake
if(WIN32)
    add_subdirectory(cpp/hwid_extractor)
    add_subdirectory(cpp/dev_keygen)
    add_subdirectory(cpp/drm_wrapper)
    add_subdirectory(cpp/paste_test)
    add_subdirectory(cpp/handoff_spy)
else()
    message(STATUS
        "Not configuring on Windows -- only quark_core (the platform-agnostic "
        "crypto/licensing logic) and its tests will be built. HWID_Extractor, "
        "Dev_Keygen, DRM_Wrapper, paste_test, and handoff_spy all require the "
        "Windows platform layer; see CLAUDE.md 'Cross-platform build & test "
        "strategy'.")
endif()
```

with:

```cmake
# HWID_Extractor, handoff_spy, and quark-runtime-c are cross-platform (see
# docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md Phase A)
# -- never gated behind WIN32.
add_subdirectory(cpp/hwid_extractor)
add_subdirectory(cpp/handoff_spy)
add_subdirectory(cpp/quark-runtime-c)

if(WIN32)
    add_subdirectory(cpp/dev_keygen)
    add_subdirectory(cpp/drm_wrapper)
    add_subdirectory(cpp/paste_test)
else()
    message(STATUS
        "Not configuring on Windows -- Dev_Keygen, DRM_Wrapper, and paste_test "
        "still require the Windows platform layer (see docs/superpowers/specs/"
        "2026-07-05-cross-platform-porting-roadmap.md Phases B/C for the "
        "in-progress cross-platform port).")
endif()
```

- [ ] **Step 5: Build and run for real**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target HWID_Extractor`
Expected: builds successfully.

Run (from the build directory, so the output file stays under `sandbox/`,
per CLAUDE.md's sandbox-only rule):
```bash
cd sandbox/build-macos && ./cpp/hwid_extractor/HWID_Extractor test_hwid.json && cat test_hwid.json && cd ../..
```
Expected: prints "Hardware fingerprint written to 'test_hwid.json'.", and
`test_hwid.json` contains real JSON with `"platform": "macos"` and a non-empty
`"fields"` array containing this real machine's actual fingerprint values
(cpu_vendor_signature, board identifiers, etc. -- whatever
`MacHwidBackend::Collect()` genuinely reads from this machine).

- [ ] **Step 6: Update the README**

In `cpp/hwid_extractor/README.md`, replace the "Compilation" section's
content (currently MSVC-only) with:

```markdown
## Compilation

Cross-platform -- builds with whichever `quark_platform_<os>` target the
current OS provides (Windows SMBIOS/CPUID, macOS sysctl/IOKit/
DiskArbitration, or Linux /proc + /sys/class/dmi):
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target HWID_Extractor
```
Outputs `sandbox/build-host/cpp/hwid_extractor/HWID_Extractor` (or
`HWID_Extractor.exe` on Windows).
```

Also update the "Permissions & Failures" section to note this is
Windows-specific (SMBIOS/disk queries needing Administrator) -- change its
heading to "Permissions & Failures (Windows)" and add a one-line note above
it: "On macOS and Linux, `IHwidBackend::Collect()` only reads
world-readable sources (see `quark/platform/macos/hwid_backend_macos.hpp` /
`quark/platform/linux/hwid_backend_linux.hpp`) -- no elevated privileges
needed."

- [ ] **Step 7: Commit**

```bash
git add cpp/common/CMakeLists.txt cpp/hwid_extractor/main.cpp cpp/hwid_extractor/README.md CMakeLists.txt
git commit -m "Port HWID_Extractor to IHwidBackend; un-gate it and handoff_spy/quark-runtime-c from WIN32"
```

---

### Task 3: Port `handoff_spy` -- portable independent HMAC + real pipe test

**Files:**
- Modify: `cpp/handoff_spy/main.cpp`
- Create: `cpp/handoff_spy/tests/CMakeLists.txt`
- Create: `cpp/handoff_spy/tests/handoff_spy_e2e_test.cpp`
- Modify: `cpp/handoff_spy/CMakeLists.txt`
- Modify: `cpp/handoff_spy/README.md`

`handoff_spy` exists to prove `DRM_Wrapper`'s QKH2 implementation
interoperates with an INDEPENDENT implementation of the same protocol (the
existing file comment: "keep this stub dependency-free of quark headers to
simulate a clean Java process"). Porting it must preserve that property --
the non-Windows HMAC-SHA256 must NOT call into `quark_core`/mbedTLS. This is
the one place in this plan where writing a second, hand-rolled crypto
primitive is correct, not duplication -- the whole point is that it doesn't
share code with the thing it's testing.

- [ ] **Step 1: Replace the Windows-only includes and I/O helpers with cross-platform branches**

Replace the top of `cpp/handoff_spy/main.cpp` (from the top through the
`HmacSha256`/`DeriveContentKey` functions) with:

```cpp
// handoff_spy.exe
//
// End-to-end test stub that impersonates "javaw.exe" during testing.
// Placed at jre\bin\javaw.exe so DRM_Wrapper launches it without any code changes.
//
// Protocol: QKH2 (v2 bi-directional challenge-response)
//
//   1. Read 136-byte QKH2 initial frame from stdin.
//      Validate magic "QKH2" and version 2.
//      Print handoff_secret (32 B), session_id (32 B), initial_seal (32 B) as hex.
//
//   2. Enter challenge loop (mirrors QuarkHeartbeat):
//      Read 40-byte CHAL frame.
//      Derive HMAC response = HMAC-SHA256(content_key, "RESP"||session_id||counter||nonce).
//      Write 32-byte response to stdout.
//      Repeat up to kMaxChallenges times, then exit 0.
//
// This validates that:
//   - DRM_Wrapper wrote the correct QKH2 initial frame
//   - The challenge pipe is functional and frames arrive on schedule
//   - DRM_Wrapper correctly verifies responses (spy derives them the same way)
//
// Exit 0 = all checks passed.  Exit 1 = bad frame (test failure).
//
// Deliberately dependency-free of quark_core on every platform: this stub
// exists to prove interoperability with an INDEPENDENT implementation of the
// QKH2 protocol, not to reuse DRM_Wrapper's own crypto code (which would let
// a shared bug in that code hide from this test). The SHA-256/HMAC-SHA256
// below (non-Windows path) is therefore hand-rolled in this file, not linked
// from quark_core -- see Sha256Transform/HmacSha256Portable.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <unistd.h>
#endif

// ─── constants ───────────────────────────────────────────────────────────────
static const char kInitialMagic[4]  = {'Q', 'K', 'H', '2'};
static const uint32_t kInitialVersion = 2;
static const size_t kInitialFrameSize = 136;  // 4+4+32+32+32+32

static const char kChallengeMagic[4] = {'C', 'H', 'A', 'L'};
static const size_t kChallengeFrameSize = 40;
static const size_t kResponseSize = 32;

// Default: 1 challenge cycle (30 s).  Override via QUARK_SPY_CHALLENGES env var.
static const int kDefaultChallenges = 1;

// ─── helpers ─────────────────────────────────────────────────────────────────
static void PrintHex(const char* label, const uint8_t* data, size_t len) {
    fprintf(stderr, "[handoff_spy] %s: ", label);
    for (size_t i = 0; i < len; i++) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
}

static uint32_t ReadU32LE(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void SecureZeroLocal(void* buf, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
}

#if defined(_WIN32)

static int ReadExact(HANDLE h, uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        DWORD n = 0;
        BOOL ok = ReadFile(h, buf + total, (DWORD)(want - total), &n, NULL);
        if (!ok || n == 0) return 0;
        total += n;
    }
    return 1;
}

static int WriteExact(HANDLE h, const uint8_t* buf, size_t len) {
    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, (DWORD)len, &written, NULL);
    return ok && written == len;
}

// ─── CNG HMAC-SHA256 (avoids a dependency on mbedTLS from the spy) ───────────
static int HmacSha256(const uint8_t* key, size_t key_len,
                      const uint8_t* msg, size_t msg_len,
                      uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    ULONG hmac_obj_len = 0, out_len = 0;
    ULONG cb = 0;
    int rc = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) goto done;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hmac_obj_len,
                          sizeof(hmac_obj_len), &cb, 0) != 0) goto done;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&out_len,
                          sizeof(out_len), &cb, 0) != 0) goto done;
    if (out_len != 32) goto done;

    {
        PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, hmac_obj_len);
        if (!obj) goto done;
        if (BCryptCreateHash(alg, &hash, obj, hmac_obj_len,
                             (PUCHAR)key, (ULONG)key_len, 0) == 0
            && BCryptHashData(hash, (PUCHAR)msg, (ULONG)msg_len, 0) == 0
            && BCryptFinishHash(hash, out, 32, 0) == 0) {
            rc = 1;
        }
        if (hash) BCryptDestroyHash(hash);
        HeapFree(GetProcessHeap(), 0, obj);
    }
done:
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

static void DeriveContentKey(const uint8_t* handoff_secret, uint8_t out_key[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    ULONG obj_len = 0, cb = 0;

    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0);
    PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, obj_len);
    BCryptCreateHash(alg, &hash, obj, obj_len, NULL, 0, 0);
    BCryptHashData(hash, (PUCHAR)"QUARK-CORE-CONTENT-KEY", 22, 0);
    BCryptHashData(hash, (PUCHAR)handoff_secret, 32, 0);
    BCryptFinishHash(hash, out_key, 32, 0);
    BCryptDestroyHash(hash);
    HeapFree(GetProcessHeap(), 0, obj);
    BCryptCloseAlgorithmProvider(alg, 0);
}

#else  // !_WIN32

static int ReadExact(int fd, uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        ssize_t n = read(fd, buf + total, want - total);
        if (n <= 0) return 0;
        total += (size_t)n;
    }
    return 1;
}

static int WriteExact(int fd, const uint8_t* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) return 0;
        total += (size_t)n;
    }
    return 1;
}

// ─── Hand-rolled, dependency-free SHA-256 (FIPS 180-4) ───────────────────────
// Deliberately NOT quark::crypto::Sha256 -- see the file header. This is a
// standard, from-scratch SHA-256 implementation: 64-round compression
// function, standard round constants and initial hash values.
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} Sha256Ctx;

static const uint32_t kSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA256_ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

static void Sha256Transform(Sha256Ctx* ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SHA256_SIG1(m[i-2]) + m[i-7] + SHA256_SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + kSha256K[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void Sha256Init(Sha256Ctx* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void Sha256Update(Sha256Ctx* ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            Sha256Transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void Sha256Final(Sha256Ctx* ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        Sha256Transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    Sha256Transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i*8)) & 0xff);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i*8)) & 0xff);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i*8)) & 0xff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i*8)) & 0xff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i*8)) & 0xff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i*8)) & 0xff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i*8)) & 0xff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i*8)) & 0xff);
    }
}

// RFC 2104 HMAC, built on the SHA-256 above. `key_len` is always 32 in this
// file's actual usage (content_key), but this is written as the fully
// general construction (the > 64 branch) rather than a shortcut specific to
// that one call site -- a primitive should be correct on its own terms.
static int HmacSha256(const uint8_t* key, size_t key_len,
                      const uint8_t* msg, size_t msg_len,
                      uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    Sha256Ctx ctx;

    if (key_len > 64) {
        Sha256Init(&ctx);
        Sha256Update(&ctx, key, key_len);
        Sha256Final(&ctx, tk);
        key = tk;
        key_len = 32;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; ++i) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    uint8_t inner[32];
    Sha256Init(&ctx);
    Sha256Update(&ctx, k_ipad, 64);
    Sha256Update(&ctx, msg, msg_len);
    Sha256Final(&ctx, inner);

    Sha256Init(&ctx);
    Sha256Update(&ctx, k_opad, 64);
    Sha256Update(&ctx, inner, 32);
    Sha256Final(&ctx, out);

    SecureZeroLocal(k_ipad, 64);
    SecureZeroLocal(k_opad, 64);
    SecureZeroLocal(inner, 32);
    return 1;
}

static void DeriveContentKey(const uint8_t* handoff_secret, uint8_t out_key[32]) {
    Sha256Ctx ctx;
    Sha256Init(&ctx);
    Sha256Update(&ctx, (const uint8_t*)"QUARK-CORE-CONTENT-KEY", 22);
    Sha256Update(&ctx, handoff_secret, 32);
    Sha256Final(&ctx, out_key);
}

#endif  // !_WIN32
```

- [ ] **Step 2: Update `main()` to use the cross-platform I/O helpers**

Replace the `main()` function (everything from `int main(void) {` to the end
of the file) with:

```cpp
// ─── main ────────────────────────────────────────────────────────────────────
int main(void) {
#if defined(_WIN32)
    HANDLE stdin_h  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);
#else
    int stdin_h = STDIN_FILENO;
    int stdout_h = STDOUT_FILENO;
#endif

    // Read challenge count from env var (for test speed control).
    int kMaxChallenges = kDefaultChallenges;
    {
#if defined(_WIN32)
        char buf[16] = {0};
        if (GetEnvironmentVariableA("QUARK_SPY_CHALLENGES", buf, sizeof(buf)) > 0) {
            int n = atoi(buf);
            if (n > 0 && n <= 100) kMaxChallenges = n;
        }
#else
        const char* env = getenv("QUARK_SPY_CHALLENGES");
        if (env) {
            int n = atoi(env);
            if (n > 0 && n <= 100) kMaxChallenges = n;
        }
#endif
    }

    // ── Step 1: Read and validate QKH2 initial frame ─────────────────────
    uint8_t frame[136] = {0};
    if (!ReadExact(stdin_h, frame, kInitialFrameSize)) {
        fprintf(stderr, "[handoff_spy] FAIL: could not read %zu bytes\n", kInitialFrameSize);
        return 1;
    }

    if (memcmp(frame, kInitialMagic, 4) != 0) {
        fprintf(stderr, "[handoff_spy] FAIL: bad magic %02x%02x%02x%02x\n",
                frame[0], frame[1], frame[2], frame[3]);
        return 1;
    }
    uint32_t ver = ReadU32LE(frame + 4);
    if (ver != kInitialVersion) {
        fprintf(stderr, "[handoff_spy] FAIL: bad version %u\n", ver);
        return 1;
    }

    const uint8_t* handoff_secret = frame + 8;
    const uint8_t* session_id     = frame + 40;
    const uint8_t* initial_seal   = frame + 72;
    const uint8_t* core_enc_key   = frame + 104;

    fprintf(stderr, "[handoff_spy] PASS: QKH2 initial frame valid (magic=QKH2, version=2, 136 bytes)\n");
    PrintHex("handoff_secret", handoff_secret, 32);
    PrintHex("session_id    ", session_id,     32);
    PrintHex("initial_seal  ", initial_seal,   32);
    PrintHex("core_enc_key  ", core_enc_key,   32);
    fflush(stderr);

    // Derive content_key (same derivation as Java's HandoffFrame.deriveContentKey)
    uint8_t content_key[32] = {0};
    DeriveContentKey(handoff_secret, content_key);
    PrintHex("content_key   ", content_key, 32);
    fflush(stderr);

    // ── Step 2: Challenge-response loop (mirrors QuarkHeartbeat) ─────────
    fprintf(stderr, "[handoff_spy] entering challenge-response loop (max %d cycles)\n", kMaxChallenges);
    fflush(stderr);

    for (int cycle = 0; cycle < kMaxChallenges; ++cycle) {
        uint8_t chal[40] = {0};
        if (!ReadExact(stdin_h, chal, kChallengeFrameSize)) {
            fprintf(stderr, "[handoff_spy] FAIL: could not read challenge frame (cycle %d)\n", cycle);
            SecureZeroLocal(content_key, 32);
            return 1;
        }

        if (memcmp(chal, kChallengeMagic, 4) != 0) {
            fprintf(stderr, "[handoff_spy] FAIL: bad challenge magic cycle %d\n", cycle);
            SecureZeroLocal(content_key, 32);
            return 1;
        }

        uint32_t counter = ReadU32LE(chal + 4);
        const uint8_t* nonce = chal + 8;

        fprintf(stderr, "[handoff_spy] challenge %u received (counter=%u)\n", cycle, counter);
        fflush(stderr);

        // Build HMAC message: "RESP" || session_id || counter (LE u32) || nonce
        uint8_t hmac_msg[4 + 32 + 4 + 32] = {0};
        memcpy(hmac_msg,      "RESP",     4);
        memcpy(hmac_msg + 4,  session_id, 32);
        hmac_msg[36] = (uint8_t)(counter & 0xFF);
        hmac_msg[37] = (uint8_t)((counter >> 8) & 0xFF);
        hmac_msg[38] = (uint8_t)((counter >> 16) & 0xFF);
        hmac_msg[39] = (uint8_t)((counter >> 24) & 0xFF);
        memcpy(hmac_msg + 40, nonce, 32);

        uint8_t response[32] = {0};
        if (!HmacSha256(content_key, 32, hmac_msg, sizeof(hmac_msg), response)) {
            fprintf(stderr, "[handoff_spy] FAIL: HMAC computation failed\n");
            SecureZeroLocal(content_key, 32);
            return 1;
        }

        if (!WriteExact(stdout_h, response, kResponseSize)) {
            fprintf(stderr, "[handoff_spy] FAIL: could not write response\n");
            SecureZeroLocal(content_key, 32);
            SecureZeroLocal(response, 32);
            return 1;
        }
        SecureZeroLocal(response, 32);

        fprintf(stderr, "[handoff_spy] challenge %u response sent\n", cycle);
        fflush(stderr);
    }

    fprintf(stderr, "[handoff_spy] PASS: %d challenge cycles completed\n", kMaxChallenges);
    fflush(stderr);

    SecureZeroLocal(content_key, 32);
    SecureZeroLocal(frame, 136);
    return 0;
}
```

- [ ] **Step 3: Build it**

Run: `cmake --build sandbox/build-macos --target handoff_spy`
Expected: builds successfully (this target already exists in
`cpp/handoff_spy/CMakeLists.txt`, and Task 2's Step 4 already un-gated it
from `WIN32`).

- [ ] **Step 4: Write the failing end-to-end test**

Create `cpp/handoff_spy/tests/handoff_spy_e2e_test.cpp` -- a real (non-mocked)
test that forks the actual built `handoff_spy` binary, feeds it a real QKH2
frame and a real challenge frame over real pipes, and independently verifies
its response using `quark_core`'s own (separately-implemented, already-tested)
`quark::token::DeriveContentKey`/`DeriveChallengeMac` as the oracle:

```cpp
// Real, non-mocked end-to-end test for handoff_spy: forks the actual built
// binary, drives it over real POSIX pipes with a real QKH2 frame + a real
// challenge frame, and checks its response against quark_core's own
// (independently implemented and already-tested) HMAC derivation --
// verifying interoperability between handoff_spy's hand-rolled crypto and
// quark_core's, which is the entire point of this tool's existence.
//
// POSIX-only (fork/pipe/execv) -- Windows re-verification of handoff_spy is
// tracked separately; see docs/superpowers/specs/2026-07-05-cross-platform-
// porting-roadmap.md's non-goals.

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "quark/crypto.hpp"
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

void WriteAll(int fd, const std::vector<uint8_t>& data) {
    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = write(fd, data.data() + total, data.size() - total);
        if (n <= 0) return;
        total += static_cast<size_t>(n);
    }
}

bool ReadAll(int fd, uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        ssize_t n = read(fd, buf + total, want - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

void AppendU32LE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <path-to-handoff_spy-binary>\n", argv[0]);
        return 2;
    }
    const char* spy_path = argv[1];

    int to_child[2];   // parent writes[1] -> child's stdin (read end [0])
    int from_child[2]; // child's stdout (write end [1]) -> parent reads[0]
    if (pipe(to_child) != 0 || pipe(from_child) != 0) {
        std::fprintf(stderr, "pipe() failed\n");
        return 1;
    }

    pid_t pid = fork();
    Check(pid >= 0, "fork() succeeds");
    if (pid < 0) return 1;

    if (pid == 0) {
        // Child: wire pipes to stdin/stdout, exec handoff_spy.
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        setenv("QUARK_SPY_CHALLENGES", "1", 1);
        execl(spy_path, spy_path, static_cast<char*>(nullptr));
        _exit(127);  // execl only returns on failure
    }

    // Parent: close the ends it doesn't use.
    close(to_child[0]);
    close(from_child[1]);

    // Build a real 136-byte QKH2 initial frame: magic + version + handoff_secret
    // + session_id + initial_seal + core_enc_key (initial_seal/core_enc_key are
    // not checked by handoff_spy, zero is fine here).
    quark::crypto::AesKey handoff_secret{};
    auto random_secret = quark::crypto::RandomBytes(32);
    std::copy(random_secret.begin(), random_secret.end(), handoff_secret.begin());

    std::array<uint8_t, 32> session_id{};
    auto random_session = quark::crypto::RandomBytes(32);
    std::copy(random_session.begin(), random_session.end(), session_id.begin());

    std::vector<uint8_t> frame;
    frame.insert(frame.end(), {'Q', 'K', 'H', '2'});
    AppendU32LE(frame, 2);
    frame.insert(frame.end(), handoff_secret.begin(), handoff_secret.end());
    frame.insert(frame.end(), session_id.begin(), session_id.end());
    frame.insert(frame.end(), 32, 0);  // initial_seal (unused by handoff_spy)
    frame.insert(frame.end(), 32, 0);  // core_enc_key (unused by handoff_spy)
    Check(frame.size() == 136, "constructed frame is exactly 136 bytes");

    WriteAll(to_child[1], frame);

    // content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret) --
    // quark_core's own, independently-implemented derivation.
    quark::crypto::AesKey content_key = quark::token::DeriveContentKey(handoff_secret);

    // Send one CHAL frame: magic + counter(u32-LE) + nonce(32).
    uint32_t counter = 42;
    std::array<uint8_t, 32> nonce{};
    auto random_nonce = quark::crypto::RandomBytes(32);
    std::copy(random_nonce.begin(), random_nonce.end(), nonce.begin());

    std::vector<uint8_t> chal;
    chal.insert(chal.end(), {'C', 'H', 'A', 'L'});
    AppendU32LE(chal, counter);
    chal.insert(chal.end(), nonce.begin(), nonce.end());
    Check(chal.size() == 40, "constructed challenge frame is exactly 40 bytes");

    WriteAll(to_child[1], chal);

    uint8_t response[32] = {0};
    bool got_response = ReadAll(from_child[0], response, 32);
    Check(got_response, "handoff_spy sends a 32-byte challenge response");

    if (got_response) {
        quark::crypto::Sha256Digest expected =
            quark::token::DeriveChallengeMac(content_key, session_id, counter, nonce);
        Check(std::memcmp(response, expected.data(), 32) == 0,
              "handoff_spy's hand-rolled HMAC matches quark_core's independent derivation");
    }

    close(to_child[1]);
    close(from_child[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    Check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "handoff_spy exits 0 after completing its one configured challenge cycle");

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
```

- [ ] **Step 5: Register the test**

Create `cpp/handoff_spy/tests/CMakeLists.txt`:

```cmake
# POSIX-only real end-to-end test (fork/pipe/exec) -- see the test file's
# header comment. Not built on Windows; that side is re-verified separately
# per docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md.
if(NOT WIN32)
    add_executable(handoff_spy_e2e_test handoff_spy_e2e_test.cpp)
    target_link_libraries(handoff_spy_e2e_test PRIVATE quark_common)

    add_test(
        NAME handoff_spy_e2e_test
        COMMAND handoff_spy_e2e_test $<TARGET_FILE:handoff_spy>
    )
endif()
```

Add `add_subdirectory(tests)` to the end of `cpp/handoff_spy/CMakeLists.txt`.

- [ ] **Step 6: Run test to verify it fails first (sanity: prove the oracle actually checks something)**

Temporarily change `counter = 42` to `counter = 43` in the test's HMAC
verification line only (i.e. compute `expected` with a mismatched counter) to
confirm the check can fail:
```cpp
quark::crypto::Sha256Digest expected =
    quark::token::DeriveChallengeMac(content_key, session_id, counter + 1, nonce);
```
Run: `cmake --build sandbox/build-macos --target handoff_spy_e2e_test && ./sandbox/build-macos/cpp/handoff_spy/tests/handoff_spy_e2e_test ./sandbox/build-macos/cpp/handoff_spy/handoff_spy`
Expected: `FAIL: handoff_spy's hand-rolled HMAC matches quark_core's independent derivation`.
Revert the `+ 1` change back to plain `counter`.

- [ ] **Step 7: Run test to verify it passes for real**

Run: `cmake --build sandbox/build-macos --target handoff_spy_e2e_test && ./sandbox/build-macos/cpp/handoff_spy/tests/handoff_spy_e2e_test ./sandbox/build-macos/cpp/handoff_spy/handoff_spy`
Expected:
```
ok: fork() succeeds
ok: constructed frame is exactly 136 bytes
ok: constructed challenge frame is exactly 40 bytes
ok: handoff_spy sends a 32-byte challenge response
ok: handoff_spy's hand-rolled HMAC matches quark_core's independent derivation
ok: handoff_spy exits 0 after completing its one configured challenge cycle

all checks passed.
```
This proves handoff_spy's from-scratch, non-Windows SHA-256/HMAC
implementation is byte-correct against real, independently-derived output --
not merely "compiles."

- [ ] **Step 8: Update the README**

In `cpp/handoff_spy/README.md`, replace the "Compilation" section with:

```markdown
## Compilation

Cross-platform -- POSIX builds (macOS/Linux) use a from-scratch,
dependency-free SHA-256/HMAC-SHA256 implementation local to this program
(deliberately not linked from quark_core -- see the source file's header
comment on why sharing crypto code with the thing being tested would defeat
the point). Windows keeps its existing CNG (`bcrypt.dll`) implementation.

```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target handoff_spy
ctest --test-dir sandbox/build-host -R handoff_spy_e2e_test --output-on-failure
```

For manual DRM_Wrapper integration testing, copy the output binary to
`jre\bin\javaw.exe` (Windows) or the equivalent path your build expects on
macOS/Linux.
```

- [ ] **Step 9: Commit**

```bash
git add cpp/handoff_spy/main.cpp cpp/handoff_spy/tests cpp/handoff_spy/CMakeLists.txt cpp/handoff_spy/README.md
git commit -m "Port handoff_spy to POSIX with an independent, hand-rolled HMAC; add real pipe e2e test"
```

---

### Task 4: Port `quark-runtime-c` -- quark_core crypto, POSIX I/O, wire into the build

**Files:**
- Modify: `cpp/quark-runtime-c/quark_runtime.cpp`
- Modify: `cpp/quark-runtime-c/CMakeLists.txt`
- Create: `cpp/quark-runtime-c/tests/CMakeLists.txt`
- Create: `cpp/quark-runtime-c/tests/test_protected_app.cpp`
- Create: `cpp/quark-runtime-c/tests/quark_runtime_e2e_test.cpp`
- Modify: `cpp/quark-runtime-c/README.md`

Unlike `handoff_spy`, `quark-runtime-c` IS meant to be linked into a real
protected application -- there is no "must stay independent" constraint here,
so it should use `quark_core`'s already-audited, already-tested
`quark::crypto`/`quark::token` functions directly, exactly like every other
Quark component.

- [ ] **Step 1: Replace the CNG crypto and Win32 I/O/threading with portable equivalents**

Replace the entire contents of `cpp/quark-runtime-c/quark_runtime.cpp`:

```cpp
// quark_runtime.cpp -- QKH2 heartbeat + checkpoint for native C/C++ applications.
// Mirrors QuarkHeartbeat.java and QuarkRuntime.java byte-for-byte in the wire protocol.
//
// Cross-platform: uses quark_core's crypto (quark::crypto::HmacSha256,
// quark::token::DeriveContentKey/DeriveChallengeMac) rather than Windows CNG
// -- this library is meant to be linked into a real protected application, so
// (unlike cpp/handoff_spy, a deliberately-independent test double) there is
// no reason to hand-roll its own crypto.

#include "quark_runtime.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "quark/crypto.hpp"
#include "quark/token.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

quark::crypto::AesKey g_content_key{};
uint8_t g_core_enc_key[32] = {0};
std::array<uint8_t, 32> g_session_id{};
std::atomic<uint32_t> g_cp_counter{0};
bool g_initialized = false;

uint32_t ReadU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

void WriteU32LE(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

#if defined(_WIN32)
bool ReadExact(uint8_t* buf, size_t want) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    size_t total = 0;
    while (total < want) {
        DWORD n = 0;
        if (!ReadFile(h, buf + total, static_cast<DWORD>(want - total), &n, NULL) || n == 0) return false;
        total += n;
    }
    return true;
}

bool WriteExact(const uint8_t* buf, size_t len) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    return WriteFile(h, buf, static_cast<DWORD>(len), &written, NULL) && written == len;
}

[[noreturn]] void FailDeadlyExit() { ExitProcess(static_cast<UINT>(-1)); }
#else
bool ReadExact(uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        ssize_t n = read(STDIN_FILENO, buf + total, want - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

bool WriteExact(const uint8_t* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(STDOUT_FILENO, buf + total, len - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

[[noreturn]] void FailDeadlyExit() { _exit(-1); }
#endif

void HeartbeatThread() {
    static const uint8_t kChalMagic[4] = {'C', 'H', 'A', 'L'};

    for (;;) {
        uint8_t chal[40] = {0};
        if (!ReadExact(chal, 40)) FailDeadlyExit();
        if (std::memcmp(chal, kChalMagic, 4) != 0) FailDeadlyExit();

        uint32_t counter = ReadU32LE(chal + 4);
        std::array<uint8_t, 32> nonce{};
        std::memcpy(nonce.data(), chal + 8, 32);

        quark::crypto::Sha256Digest mac =
            quark::token::DeriveChallengeMac(g_content_key, g_session_id, counter, nonce);

        if (!WriteExact(mac.data(), 32)) FailDeadlyExit();
    }
}

}  // namespace

extern "C" {

int quark_init(void) {
    static const uint8_t kInitMagic[4] = {'Q', 'K', 'H', '2'};

    uint8_t frame[136] = {0};
    if (!ReadExact(frame, 136)) return 0;

    if (std::memcmp(frame, kInitMagic, 4) != 0) return 0;
    uint32_t ver = ReadU32LE(frame + 4);
    if (ver != 2) return 0;

    quark::crypto::AesKey handoff_secret{};
    std::memcpy(handoff_secret.data(), frame + 8, 32);
    std::memcpy(g_session_id.data(), frame + 40, 32);
    // frame+72 = initial_seal (not verified here -- see HANDOFF_PROTOCOL.md)
    std::memcpy(g_core_enc_key, frame + 104, 32);

    g_content_key = quark::token::DeriveContentKey(handoff_secret);

    quark::crypto::SecureZero(frame, 136);
    g_initialized = true;
    return 1;
}

void quark_heartbeat_start(void) {
    if (!g_initialized) return;
    std::thread(HeartbeatThread).detach();
}

int64_t quark_checkpoint(int32_t id) {
    if (!g_initialized) return 0;

    uint32_t cnt = g_cp_counter.fetch_add(1);

    uint8_t msg[10];
    std::memcpy(msg, "CP", 2);
    WriteU32LE(msg + 2, static_cast<uint32_t>(id));
    WriteU32LE(msg + 6, cnt);

    quark::crypto::Sha256Digest mac = quark::crypto::HmacSha256(
        g_content_key.data(), g_content_key.size(), msg, sizeof(msg));

    int64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= static_cast<int64_t>(mac[i] & 0xFF) << (i * 8);
    }
    return v;
}

const uint8_t* quark_core_enc_key(void) {
    return g_initialized ? g_core_enc_key : NULL;
}

}  // extern "C"
```

- [ ] **Step 2: Fix the CMakeLists.txt to be cross-platform**

Replace the contents of `cpp/quark-runtime-c/CMakeLists.txt`:

```cmake
# quark-runtime-c: native C/C++ runtime for protected applications (QKH2
# pipe protocol). Cross-platform -- links quark_core for crypto instead of
# CNG/bcrypt, so it builds and runs identically on Windows/macOS/Linux.
add_library(quark_runtime STATIC quark_runtime.cpp)

target_include_directories(quark_runtime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(quark_runtime PUBLIC quark_core)

add_subdirectory(tests)

install(TARGETS quark_runtime ARCHIVE DESTINATION lib)
install(FILES quark_runtime.h DESTINATION include)
```

(This drops the standalone `cmake_minimum_required`/`project()` calls -- this
directory is now always brought in via the top-level project's
`add_subdirectory`, per Task 2's Step 4 -- and drops the hardcoded MSVC-only
`/MT /W4 /WX` flags and the `bcrypt` link, both no longer applicable.)

- [ ] **Step 3: Write the failing end-to-end test's helper app**

Create `cpp/quark-runtime-c/tests/test_protected_app.cpp` -- a minimal stand-in
for a real protected native application, linking `quark_runtime` the same way
a real one would:

```cpp
// A minimal stand-in for a real protected native application, linking
// quark_runtime exactly like a real one would. Driven by
// quark_runtime_e2e_test.cpp over real pipes. Prints the quark_checkpoint()
// result to STDERR (not stdout) so it doesn't corrupt the heartbeat
// thread's stdout protocol, which the parent test reads separately.

#include <cstdio>

#include "quark_runtime.h"

int main() {
    if (!quark_init()) {
        std::fprintf(stderr, "quark_init failed\n");
        return 1;
    }
    quark_heartbeat_start();

    int64_t token = quark_checkpoint(0x1001);
    std::fprintf(stderr, "CHECKPOINT_RESULT=%lld\n", static_cast<long long>(token));
    std::fflush(stderr);

    // Keep the process alive so the heartbeat thread can answer a challenge
    // sent by the parent test after this point.
    for (;;) {
#if defined(_WIN32)
        Sleep(60000);
#else
        pause();
#endif
    }
}
```

- [ ] **Step 4: Write the failing end-to-end test**

Create `cpp/quark-runtime-c/tests/quark_runtime_e2e_test.cpp`:

```cpp
// Real, non-mocked end-to-end test for quark-runtime-c: forks the real
// test_protected_app binary (which links quark_runtime, exactly like a real
// protected application would), drives it over real POSIX pipes with a real
// QKH2 frame, reads test_protected_app's own quark_checkpoint() result off
// its stderr, sends it a real challenge frame, and verifies both the
// checkpoint value and the heartbeat's HMAC response against quark_core's
// own independent derivation.
//
// POSIX-only; see docs/superpowers/specs/2026-07-05-cross-platform-porting-
// roadmap.md's non-goals for Windows re-verification.

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "quark/crypto.hpp"
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

void WriteAll(int fd, const std::vector<uint8_t>& data) {
    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = write(fd, data.data() + total, data.size() - total);
        if (n <= 0) return;
        total += static_cast<size_t>(n);
    }
}

bool ReadAll(int fd, uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        ssize_t n = read(fd, buf + total, want - total);
        if (n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

void AppendU32LE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <path-to-test_protected_app-binary>\n", argv[0]);
        return 2;
    }
    const char* app_path = argv[1];

    int to_child[2];
    int from_child_stdout[2];
    int from_child_stderr[2];
    if (pipe(to_child) != 0 || pipe(from_child_stdout) != 0 || pipe(from_child_stderr) != 0) {
        std::fprintf(stderr, "pipe() failed\n");
        return 1;
    }

    pid_t pid = fork();
    Check(pid >= 0, "fork() succeeds");
    if (pid < 0) return 1;

    if (pid == 0) {
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child_stdout[1], STDOUT_FILENO);
        dup2(from_child_stderr[1], STDERR_FILENO);
        close(to_child[0]); close(to_child[1]);
        close(from_child_stdout[0]); close(from_child_stdout[1]);
        close(from_child_stderr[0]); close(from_child_stderr[1]);
        execl(app_path, app_path, static_cast<char*>(nullptr));
        _exit(127);
    }

    close(to_child[0]);
    close(from_child_stdout[1]);
    close(from_child_stderr[1]);

    quark::crypto::AesKey handoff_secret{};
    auto random_secret = quark::crypto::RandomBytes(32);
    std::copy(random_secret.begin(), random_secret.end(), handoff_secret.begin());

    std::array<uint8_t, 32> session_id{};
    auto random_session = quark::crypto::RandomBytes(32);
    std::copy(random_session.begin(), random_session.end(), session_id.begin());

    std::vector<uint8_t> frame;
    frame.insert(frame.end(), {'Q', 'K', 'H', '2'});
    AppendU32LE(frame, 2);
    frame.insert(frame.end(), handoff_secret.begin(), handoff_secret.end());
    frame.insert(frame.end(), session_id.begin(), session_id.end());
    frame.insert(frame.end(), 32, 0);  // initial_seal
    frame.insert(frame.end(), 32, 0);  // core_enc_key
    Check(frame.size() == 136, "constructed frame is exactly 136 bytes");

    WriteAll(to_child[1], frame);

    // Read test_protected_app's checkpoint result off its stderr.
    char stderr_buf[256] = {0};
    ssize_t n = read(from_child_stderr[0], stderr_buf, sizeof(stderr_buf) - 1);
    Check(n > 0, "test_protected_app writes a CHECKPOINT_RESULT line to stderr");

    long long checkpoint_result = 0;
    bool parsed = (n > 0) && (std::sscanf(stderr_buf, "CHECKPOINT_RESULT=%lld", &checkpoint_result) == 1);
    Check(parsed, "CHECKPOINT_RESULT line parses as an integer");

    if (parsed) {
        quark::crypto::AesKey content_key = quark::token::DeriveContentKey(handoff_secret);
        uint8_t msg[10];
        std::memcpy(msg, "CP", 2);
        msg[2] = 0x01; msg[3] = 0x10; msg[4] = 0x00; msg[5] = 0x00;  // id = 0x1001, LE
        msg[6] = 0x00; msg[7] = 0x00; msg[8] = 0x00; msg[9] = 0x00; // counter = 0 (first checkpoint call)
        quark::crypto::Sha256Digest mac = quark::crypto::HmacSha256(
            content_key.data(), content_key.size(), msg, sizeof(msg));
        int64_t expected = 0;
        for (int i = 0; i < 8; i++) expected |= static_cast<int64_t>(mac[i] & 0xFF) << (i * 8);
        Check(checkpoint_result == expected,
              "quark_checkpoint(0x1001)'s first-call value matches an independently computed HMAC");
    }

    // Now exercise the heartbeat thread with a real challenge frame.
    uint32_t counter = 7;
    std::array<uint8_t, 32> nonce{};
    auto random_nonce = quark::crypto::RandomBytes(32);
    std::copy(random_nonce.begin(), random_nonce.end(), nonce.begin());

    std::vector<uint8_t> chal;
    chal.insert(chal.end(), {'C', 'H', 'A', 'L'});
    AppendU32LE(chal, counter);
    chal.insert(chal.end(), nonce.begin(), nonce.end());
    WriteAll(to_child[1], chal);

    uint8_t response[32] = {0};
    bool got_response = ReadAll(from_child_stdout[0], response, 32);
    Check(got_response, "heartbeat thread sends a 32-byte challenge response");

    if (got_response) {
        quark::crypto::AesKey content_key = quark::token::DeriveContentKey(handoff_secret);
        quark::crypto::Sha256Digest expected =
            quark::token::DeriveChallengeMac(content_key, session_id, counter, nonce);
        Check(std::memcmp(response, expected.data(), 32) == 0,
              "heartbeat's HMAC response matches quark_core's independent derivation");
    }

    close(to_child[1]);
    close(from_child_stdout[0]);
    close(from_child_stderr[0]);
    kill(pid, SIGKILL);  // test_protected_app loops forever by design; stop it now
    int status = 0;
    waitpid(pid, &status, 0);

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
```

- [ ] **Step 5: Register both test binaries**

Create `cpp/quark-runtime-c/tests/CMakeLists.txt`:

```cmake
add_executable(test_protected_app test_protected_app.cpp)
target_link_libraries(test_protected_app PRIVATE quark_runtime)

if(NOT WIN32)
    add_executable(quark_runtime_e2e_test quark_runtime_e2e_test.cpp)
    target_link_libraries(quark_runtime_e2e_test PRIVATE quark_core)

    add_test(
        NAME quark_runtime_e2e_test
        COMMAND quark_runtime_e2e_test $<TARGET_FILE:test_protected_app>
    )
endif()
```

- [ ] **Step 6: Build and run for real**

Run:
```bash
cmake -S . -B sandbox/build-macos
cmake --build sandbox/build-macos --target quark_runtime_e2e_test
./sandbox/build-macos/cpp/quark-runtime-c/tests/quark_runtime_e2e_test ./sandbox/build-macos/cpp/quark-runtime-c/tests/test_protected_app
```
Expected:
```
ok: fork() succeeds
ok: constructed frame is exactly 136 bytes
ok: test_protected_app writes a CHECKPOINT_RESULT line to stderr
ok: CHECKPOINT_RESULT line parses as an integer
ok: quark_checkpoint(0x1001)'s first-call value matches an independently computed HMAC
ok: heartbeat thread sends a 32-byte challenge response
ok: heartbeat's HMAC response matches quark_core's independent derivation

all checks passed.
```

- [ ] **Step 7: Run the full suite via ctest**

Run: `ctest --test-dir sandbox/build-macos --output-on-failure`
Expected: every pre-existing test plus `handoff_spy_e2e_test` and
`quark_runtime_e2e_test` report `Passed`.

- [ ] **Step 8: Update the README**

In `cpp/quark-runtime-c/README.md`, replace the "Compilation & Linking"
section with:

```markdown
## Compilation & Linking

Cross-platform -- links `quark_core` for crypto (HMAC-SHA256, SHA-256)
instead of Windows CNG:
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target quark_runtime
ctest --test-dir sandbox/build-host -R quark_runtime_e2e_test --output-on-failure
```
Produces `sandbox/build-host/cpp/quark-runtime-c/libquark_runtime.a` (or
`quark_runtime.lib` on Windows).

### Link Instructions
When compiling your protected C++ application:
1.  Include [quark_runtime.h](quark_runtime.h) in your sources.
2.  Link with `quark_runtime` (which pulls in `quark_core` transitively).
```

- [ ] **Step 9: Commit**

```bash
git add cpp/quark-runtime-c
git commit -m "Port quark-runtime-c to quark_core crypto + POSIX/std::thread; wire into the build"
```

---

### Task 5: Documentation

**Files:**
- Modify: `docs/PLAN.md`

- [ ] **Step 1: Record Phase A in the plan**

Append to `docs/PLAN.md` (after the current last section):

```markdown
## Phase X — Cross-platform port, Phase A: the zero-new-infrastructure programs
Implements Phase A of docs/superpowers/specs/2026-07-05-cross-platform-
porting-roadmap.md.

- [x] `quark::platform::FingerprintToJson`/`FingerprintFromJson` -- portable
      JSON transport for `Fingerprint` (quark_core), the cross-platform
      successor to the Windows-only `quark::hwid::ToJson`/`FromJson`.
- [x] `quark_common` INTERFACE target now also defined for `APPLE` and
      `UNIX AND NOT APPLE`, matching the existing Windows one -- every
      consumer keeps linking one name regardless of OS.
- [x] `HWID_Extractor` ported to `quark::platform::IHwidBackend` --
      builds and runs for real on macOS (Linux untested this pass, but
      uses the same portable code path as macOS).
- [x] `handoff_spy` ported to POSIX: kept its "must not share code with the
      thing it tests" property by hand-rolling a from-scratch, dependency-free
      SHA-256/HMAC-SHA256 for non-Windows builds (Windows keeps its existing
      CNG implementation). Verified via a real fork/pipe end-to-end test that
      cross-checks handoff_spy's response against `quark::token`'s
      independently-implemented derivation.
- [x] `quark-runtime-c` ported to `quark_core` crypto (no independence
      constraint here -- unlike `handoff_spy`, this is a real runtime library),
      POSIX I/O, and `std::thread`; wired into the top-level build for the
      first time (previously a fully standalone, un-built CMake project).
      Verified via a real fork/pipe end-to-end test against an actual
      `quark_runtime`-linked stand-in application.
- [x] `HWID_Extractor`, `handoff_spy`, and `quark-runtime-c` all un-gated
      from `if(WIN32)` in the top-level `CMakeLists.txt`.

### Not done yet (Phases B and C, tracked separately)
- `Dev_Keygen`, `Paste_Test`, and `DRM_Wrapper` remain Windows-only --
  they need the portable mbedTLS-based HTTPS client (Phase B) before they
  can be ported; `DRM_Wrapper` additionally needs Phase C's integration
  work (wiring the already-written-but-unused `process_handoff`/
  `DebuggerDetected` code, and replacing its hand-rolled duplicate of
  `RunUnlockFlow`'s logic with a real call to it).
- Linux was not available to test against in this session; Phase A's
  Linux-specific code paths (`LinuxHwidBackend`, the POSIX branches in
  `handoff_spy`/`quark-runtime-c`) compile against the same interfaces
  already verified on Linux elsewhere in this repo, but were not
  independently re-run on a Linux machine in this pass.
```

- [ ] **Step 2: Commit**

```bash
git add docs/PLAN.md
git commit -m "Document Phase A of the cross-platform porting roadmap"
```

---

## Self-review notes (from writing this plan)

- **Spec coverage:** The roadmap spec's Phase A scope (HWID_Extractor,
  handoff_spy, quark-runtime-c; zero new shared infrastructure beyond what
  each program needs on its own) is fully covered by Tasks 1-4. Task 1's new
  JSON codec was flagged by the roadmap's audit as *not* pre-existing (the
  original agent audit incorrectly called HWID_Extractor's port "trivial,
  needs no new work" -- verified against the actual source that this was
  wrong: `quark::hwid::ToJson`/`Collect` are Windows-only, so a portable
  codec genuinely had to be designed here) -- caught and corrected before
  writing this plan, not left as a gap.
- **Placeholder scan:** no TBD/TODO; every step has complete, runnable code,
  including the from-scratch SHA-256 (FIPS 180-4 constants/algorithm spelled
  out in full, not "implement SHA-256 here").
- **Type consistency:** `quark::platform::Fingerprint`/`ParsedFingerprint`,
  `quark::crypto::AesKey`/`Sha256Digest`, and the QKH2 frame field offsets
  (8/40/72/104, matching `quark/handoff.hpp`'s existing layout) are used
  identically across Tasks 1-4.
- **Independence property preserved:** Task 3 explicitly does NOT link
  `quark_core` into `handoff_spy` itself (only its *test* does) -- verified
  this constraint is stated in both the roadmap spec and this plan's Task 3
  intro, and enforced by the actual CMakeLists.txt structure (the
  `handoff_spy` target's own `target_link_libraries` is unchanged from
  before; only the new `tests/` subdirectory links `quark_common`).
- **Testing rigor:** every task ends with a real build+run on this machine,
  not just a compile check, per CLAUDE.md rule 1 and the roadmap's own
  "Testing strategy" section. Tasks 3 and 4's tests both cross-check against
  an independently-computed value (`quark::token::DeriveChallengeMac`/
  `DeriveContentKey`), not merely "the program exited 0."
