# Phase C: Cross-Platform DRM_Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `DRM_Wrapper.exe` -- the last remaining Windows-only program -- to build and run for real on macOS/Linux, replacing its ~250-line hand-rolled duplicate of `quark::orchestrator::RunUnlockFlow`'s logic with a real call to it, and wiring the already-written-but-unused POSIX process-handoff and anti-debug code.

**Architecture:** Three genuine gaps block this, found by reading the actual current source (not assumed): (1) `quark::orchestrator::RunUnlockFlow` doesn't yet fetch the online witness for real (it predates Phase B's portable HTTP client) and doesn't expose `handoff_secret`/`initial_seal`, so nothing can actually build a QKH2 frame from its output -- both fixed here. (2) `quark::config::Config` is declared in a header with zero implementation anywhere in the repo -- implemented here for real, since `DRM_Wrapper`'s jar path/hash and witness file locations need to be config-driven (CLAUDE.md rule 2) rather than hardcoded, and because config-driven values are what make a real macOS end-to-end test possible without a production `quark.jar`. (3) `quark::platform::posix::process_handoff` and the macOS/Linux `DebuggerDetected()` implementations exist and are complete but were never added to `quark_platform_macos`/`quark_platform_linux`'s CMake source lists -- wired in here. With all three gaps closed, `main.cpp` becomes a single portable flow with four small `#ifdef`-selected pieces (anti-debug function, HWID backend, witness stores, process launch/challenge-loop) instead of an entirely separate Windows-only program.

**Tech Stack:** C++17, CMake, POSIX `fork`/`pipe`/`exec` (already implemented), real end-to-end testing using `cpp/handoff_spy` (ported in Phase A) as the "JVM" stand-in -- this is exactly what that tool exists for.

Reference: [docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md](../specs/2026-07-05-cross-platform-porting-roadmap.md)

---

## File structure

```
cpp/common/src/config.cpp                         new: quark::config::Config implementation
cpp/common/CMakeLists.txt                         modify: add config.cpp to quark_core;
                                                   add process_handoff.cpp/anti_debug_*.cpp to
                                                   quark_platform_macos/quark_platform_linux
cpp/common/tests/core_smoke_test.cpp              modify: add real Config file round-trip test

cpp/common/include/quark/orchestrator.hpp         modify: Config.ec_public_key,
                                                   UnlockResult.handoff_secret/initial_seal
cpp/common/src/orchestrator.cpp                   modify: real online-witness fetch/verify,
                                                   expose handoff_secret/initial_seal
cpp/common/tests/orchestrator_online_test.cpp     new: real live-network end-to-end test
                                                   (separate binary, not in default ctest)
cpp/common/tests/CMakeLists.txt                   modify: register the new test binary (build only)

cpp/drm_wrapper/main.cpp                          rewrite: cross-platform, config-driven,
                                                   calls RunUnlockFlow
cpp/drm_wrapper/CMakeLists.txt                    modify: cross-platform build
cpp/drm_wrapper/drm_wrapper.conf.example           new: documents every config key + default
cpp/drm_wrapper/README.md                         modify

CMakeLists.txt                                    modify: un-gate cpp/drm_wrapper from WIN32
docs/PLAN.md                                      modify: record Phase C
```

---

### Task 1: Implement `quark::config::Config` for real

**Files:**
- Create: `cpp/common/src/config.cpp`
- Modify: `cpp/common/CMakeLists.txt`
- Modify: `cpp/common/tests/core_smoke_test.cpp`

`quark::config::Config` (`cpp/common/include/quark/config.hpp`) is declared
with a full docstring but has **no implementation anywhere in the repo** and
is not in any CMake source list -- confirmed via `grep -rn "Config::Load"
cpp/common/src/` returning nothing. This has to exist for real before
`DRM_Wrapper` can use it.

- [ ] **Step 1: Write the failing test**

Add to `cpp/common/tests/core_smoke_test.cpp`, right after
`TestOnlinePayloadCrypto()`'s definition (insert immediately after its
closing `}`):

```cpp
void TestConfigFileRoundTrip() {
    // Relative path -- stays under sandbox/, same convention as every other
    // real-filesystem test in this file.
    const std::string path = "quark_core_test_config.conf";
    {
        std::ofstream out(path);
        out << "# a comment\n"
            << "\n"
            << "jvm_path = jre/bin/java\n"
            << "  witness_xattr1_attr =com.quark.witness1  \n"
            << "challenge_interval_ms=30000\n"
            << "malformed line with no equals sign\n";
    }

    auto cfg = quark::config::Config::Load(path);
    Check(cfg.has_value(), "Config::Load succeeds against a real file");
    if (cfg) {
        Check(cfg->GetOr("jvm_path", "fallback") == "jre/bin/java",
              "Config::GetOr returns the file's value when the key is present");
        Check(cfg->GetOr("witness_xattr1_attr", "fallback") == "com.quark.witness1",
              "Config::GetOr trims surrounding whitespace from key and value");
        Check(cfg->GetOr("missing_key", "the-fallback") == "the-fallback",
              "Config::GetOr returns the fallback for an absent key");
        Check(cfg->GetIntOr("challenge_interval_ms", -1) == 30000,
              "Config::GetIntOr parses a real integer value");
        Check(cfg->GetIntOr("jvm_path", -1) == -1,
              "Config::GetIntOr returns the fallback for a non-integer value");
        Check(cfg->GetIntOr("missing_key", 42) == 42,
              "Config::GetIntOr returns the fallback for an absent key");
    }

    Check(!quark::config::Config::Load("quark_core_test_config_does_not_exist.conf").has_value(),
          "Config::Load returns nullopt for a nonexistent file");

    std::filesystem::remove(path);
}
```

Add `#include "quark/config.hpp"` to the test file's includes (alphabetically,
right before `#include "quark/crypto.hpp"`). Add `TestConfigFileRoundTrip();`
to `main()`, right after `TestOnlinePayloadCrypto();`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build sandbox/build-macos --target quark_core_tests`
Expected: FAIL -- linker error, `Config::Load`/`GetOr`/`GetIntOr` undefined
(the header exists, the implementation doesn't).

- [ ] **Step 3: Write the implementation**

Create `cpp/common/src/config.cpp`:

```cpp
#include "quark/config.hpp"

#include <fstream>

namespace quark::config {

namespace {

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

}  // namespace

std::optional<Config> Config::Load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::nullopt;

    Config cfg;
    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) continue;  // malformed line -- skip, don't fail the whole file

        std::string key = Trim(trimmed.substr(0, eq));
        std::string value = Trim(trimmed.substr(eq + 1));
        if (key.empty()) continue;
        cfg.values_[key] = value;
    }
    return cfg;
}

std::string Config::GetOr(const std::string& key, const std::string& fallback) const {
    auto it = values_.find(key);
    return it != values_.end() ? it->second : fallback;
}

int Config::GetIntOr(const std::string& key, int fallback) const {
    auto it = values_.find(key);
    if (it == values_.end()) return fallback;
    try {
        size_t consumed = 0;
        int value = std::stoi(it->second, &consumed);
        if (consumed != it->second.size()) return fallback;  // trailing garbage, e.g. "30000ms"
        return value;
    } catch (...) {
        return fallback;
    }
}

}  // namespace quark::config
```

- [ ] **Step 4: Wire it into `quark_core`**

In `cpp/common/CMakeLists.txt`, add `src/config.cpp` to `quark_core`'s source
list (alongside the other `src/*.cpp` entries, alphabetically after
`crypto.cpp`):

```cmake
add_library(quark_core STATIC
    src/config.cpp
    src/crypto.cpp
    src/error.cpp
    src/handoff.cpp
    src/lamport.cpp
    src/online_crypto.cpp
    src/online_http.cpp
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

- [ ] **Step 5: Run test to verify it passes**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target quark_core_tests && ./sandbox/build-macos/cpp/common/tests/quark_core_tests`
Expected: all `TestConfigFileRoundTrip` checks print `ok:`, `all checks
passed.`, exit code 0. This is a real filesystem test -- it writes and reads
an actual file under the test binary's working directory (`sandbox/`), not a
mock.

- [ ] **Step 6: Commit**

```bash
git add cpp/common/src/config.cpp cpp/common/CMakeLists.txt cpp/common/tests/core_smoke_test.cpp
git commit -m "Implement quark::config::Config for real (previously declared, never implemented)"
```

---

### Task 2: Extend `quark::orchestrator` -- real online witness, expose handoff_secret/initial_seal

**Files:**
- Modify: `cpp/common/include/quark/orchestrator.hpp`
- Modify: `cpp/common/src/orchestrator.cpp`
- Create: `cpp/common/tests/orchestrator_online_test.cpp`
- Modify: `cpp/common/tests/CMakeLists.txt`

`RunUnlockFlow`'s online-witness section currently returns
`kWrapperOnlineFetchFailed` unconditionally for any non-empty `paste_id`
(dating from before Phase B's portable HTTP client existed). Its
`UnlockResult` also has no `handoff_secret` or `initial_seal` field, so no
caller can actually build a QKH2 frame (`quark::handoff::EncodeInitialFrame`
needs `handoff_secret` and `initial_seal` directly, not `content_key`) --
`DRM_Wrapper` needs both fixed to be usable at all.

- [ ] **Step 1: Update the header**

Replace the contents of `cpp/common/include/quark/orchestrator.hpp`:

```cpp
#pragma once
// The platform-agnostic half of the DRM unlock flow -- HWID collection,
// state.bin open, three-witness cross-check, online-witness fetch/verify,
// chain-exhaustion check, one-time key verification, chain roll-forward +
// persistence, and session key derivation. Extracted so any consumer (the C
// ABI in cpp/quark_c_api, DRM_Wrapper, or a future standalone executable)
// gets this for free instead of re-implementing the same crypto/licensing
// logic.
//
// This function is a pure engine, not a fail-deadly funnel: it returns
// quark::error::Code (kOk on success) rather than reporting through
// quark::error::Report() or calling std::exit() itself. A shared library has
// no business terminating its host process or writing files the host didn't
// ask for -- CLAUDE.md rule 5's "no recovery, immediate exit" discipline is a
// policy for whoever is building a *standalone executable* on top of this
// engine to apply at their own call site, not something quark_core can
// impose on an arbitrary caller (a Python/Go host embedding this via the C
// API would have its interpreter/runtime killed outright, which is not
// something a library is allowed to do to its host).
//
// What deliberately stays OUT of this function:
//   - anti-debug detection (a caller's concern, if it wants one at all)
//   - process/pipe launch and any challenge-response loop -- those are one
//     specific *consumer's* choice of how to use the returned key material
//     (e.g. a JVM-launching wrapper), not something every consumer of this
//     engine needs forced on it.
//   - prompting for the key (the caller already has it by the time it calls
//     this function)
//
// A caller that wants QKH2 framing (quark::handoff::EncodeInitialFrame) has
// everything it needs in UnlockResult: handoff_secret, session_id,
// initial_seal, and core_enc_key.

#include <array>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/error.hpp"
#include "quark/online.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/witness_store.hpp"

namespace quark::orchestrator {

struct Config {
    std::string build_secret;   // kBuildSecret equivalent -- see quark/token.hpp
    std::string state_path;     // path to state.bin

    // P-256 public key verifying the online-witness paste's signature (see
    // quark::online). Only consulted when the license has a non-empty
    // paste_id; dev-mode licenses (empty paste_id) never touch this field.
    online::EcPublicKey ec_public_key{};
};

struct UnlockResult {
    crypto::AesKey content_key{};              // HMAC key for a challenge-response loop, if the caller wants one
    crypto::AesKey core_enc_key{};              // decrypts core.enc / the caller's equivalent protected payload
    crypto::AesKey handoff_secret{};            // needed verbatim to build a QKH2 initial frame
    crypto::Sha256Digest initial_seal{};        // ditto -- proves to the far end that the full flow ran
    std::array<uint8_t, 32> session_id{};      // fresh per-session context, e.g. for challenge MACs
};

// Runs the full pre-launch DRM flow against `hwid_backend` and exactly three
// `witnesses` (secondary witness channels -- see CLAUDE.md rule 6's
// four-channel design; state.bin is the primary, these three are the
// independently-sealed secondaries). `candidate_key` is the user's one-time
// unlock key (hex-encoded, as accepted by quark::lamport::ParseKey).
//
// Returns quark::error::Code::kOk and populates `out` on success. Any other
// return value means `out` was not populated and the caller must treat the
// license as unusable -- CLAUDE.md rule 2's "tampering and wrong-machine
// must be indistinguishable" still holds; the *code* only exists for
// diagnostics, callers must not branch on which one came back to decide
// whether to retry or partially trust the result.
error::Code RunUnlockFlow(const Config& config,
                           platform::IHwidBackend& hwid_backend,
                           std::array<platform::IWitnessStore*, 3> witnesses,
                           const std::string& candidate_key,
                           UnlockResult& out);

}  // namespace quark::orchestrator
```

- [ ] **Step 2: Update the implementation**

In `cpp/common/src/orchestrator.cpp`, add `#include "quark/online.hpp"` to
the includes (alongside the existing `quark/handoff.hpp`/`quark/lamport.hpp`/
`quark/state.hpp`/`quark/token.hpp` includes).

Add this helper to the anonymous namespace (right after the existing
`CurrentUnixTime()` function):

```cpp
// Minimal hex decoder -- FetchPaste returns the sealed blob hex-encoded
// (see quark::online::PostPaste's own hex encoding). Not a general parser;
// returns nullopt on any malformed input, same posture as every other
// "this codebase only reads what it itself wrote" decoder in Quark.
std::optional<std::vector<uint8_t>> HexDecode(const std::string& hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}
```

Replace the entire `// --- online witness --------` section (currently just
the unconditional-failure stub) with:

```cpp
    // --- online witness ----------------------------------------------------
    // The paste carries an AES-256-GCM-sealed blob containing online_secret
    // (32 B) and a P-256 ECDSA signature. online_secret is a mandatory KDF
    // input to DeriveHandoffSecret -- without it the wrong handoff_secret is
    // derived and the far end's content_key is wrong, so this is a
    // cryptographic hard dependency, not a patchable if-check.
    crypto::AesKey online_key = token::DeriveOnlineKey(config.build_secret, hwid_canonical);
    crypto::ScopedZero<crypto::AesKey> zero_online_key(online_key);

    crypto::OnlineSecret online_secret{};
    if (license.paste_id.empty()) {
        // Dev-mode license (Dev_Keygen --dev): online_secret is fixed to
        // all-zero bytes, matching how it was minted.
        std::memset(online_secret.data(), 0, online_secret.size());
    } else {
        auto paste_raw = online::FetchPaste(license.paste_id);
        if (!paste_raw) {
            return error::Code::kWrapperOnlineFetchFailed;
        }
        auto blob_bytes = HexDecode(*paste_raw);
        if (!blob_bytes) {
            return error::Code::kWrapperOnlineDecryptFailed;
        }
        auto unsealed = online::UnsealPayload(online_key, hwid_canonical, *blob_bytes);
        if (!unsealed) {
            return error::Code::kWrapperOnlineDecryptFailed;
        }
        auto sign_msg = online::BuildSignMessage(
            hwid_canonical, license.original_chain_length, unsealed->online_secret);
        if (!online::VerifySignature(config.ec_public_key, sign_msg, unsealed->ec_signature)) {
            return error::Code::kWrapperOnlineSigInvalid;
        }
        online_secret = unsealed->online_secret;
        crypto::SecureZero(unsealed->online_secret.data(), unsealed->online_secret.size());
    }
```

Right before `state::LicenseState rolled = license;`, add the missing
`anchor_before` capture (needed for `DeriveInitialSeal` below):

```cpp
    // Capture BEFORE rolling -- DeriveInitialSeal needs both the pre- and
    // post-roll anchor to prove to the far end that a real roll happened.
    const crypto::Sha256Digest anchor_before = license.anchor;

    state::LicenseState rolled = license;
```

Replace the final block (from `const crypto::Sha256Digest online_secret_hash`
through the `return error::Code::kOk;`) with:

```cpp
    // --- derive session key material for the caller ------------------------------
    const crypto::Sha256Digest online_secret_hash =
        crypto::Sha256(online_secret.data(), online_secret.size());

    crypto::AesKey handoff_secret =
        token::DeriveHandoffSecret(state_key, rolled.anchor, hwid_canonical, online_secret);
    crypto::SecureZero(online_secret.data(), online_secret.size());
    crypto::SecureZero(candidate->data(), candidate->size());

    out.content_key = token::DeriveContentKey(handoff_secret);
    out.core_enc_key = token::DeriveCoreEncKey(state_key, online_secret_hash, hwid_canonical);
    out.initial_seal = token::DeriveInitialSeal(
        out.content_key, anchor_before, rolled.anchor, online_secret_hash, hwid_canonical);
    out.handoff_secret = handoff_secret;

    auto random_session_id = crypto::RandomBytes(32);
    for (size_t i = 0; i < 32; ++i) out.session_id[i] = random_session_id[i];

    crypto::SecureZero(handoff_secret.data(), handoff_secret.size());

    return error::Code::kOk;
}

}  // namespace quark::orchestrator
```

- [ ] **Step 3: Build it**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target quark_core`
Expected: builds successfully.

- [ ] **Step 4: Verify existing consumers (`quark_c_api`) still build**

Run: `cmake --build sandbox/build-macos --target quark_c && cmake --build sandbox/build-macos --target quark_c_api_test && ctest --test-dir sandbox/build-macos -R quark_c_api_test --output-on-failure`
Expected: builds and all 17 checks still pass -- `quark_c_api.cpp`'s existing
`Config` construction (`config.build_secret = ...; config.state_path = ...;`)
is field-by-field assignment, so the new `ec_public_key` field (default
all-zero) doesn't break it, and `quark_state_mint` only ever mints dev-mode
(empty `paste_id`) licenses today, so the new online-witness branch is never
reached by its existing tests -- this step proves that claim for real rather
than assuming it.

- [ ] **Step 5: Write a real, live-network end-to-end test**

This exercises the ENTIRE flow this task changed -- online witness fetch,
signature verification, and the new `handoff_secret`/`initial_seal` fields --
against a real, freshly-minted license and a real live paste.rs paste.
Deliberately built as its **own executable, not registered via `add_test`**
(so it never runs automatically under `ctest`), mirroring `Paste_Test`'s
existing precedent of keeping live-network checks out of the default,
always-green suite.

Create `cpp/common/tests/orchestrator_online_test.cpp`:

```cpp
// Real, live-network end-to-end test for quark::orchestrator::RunUnlockFlow's
// online-witness path -- mints a real license (state.bin + a Lamport chain),
// posts a real signed+sealed online-witness paste to the live paste.rs
// service, then calls RunUnlockFlow against both for real, verifying it
// fetches, decrypts, and signature-checks the paste, and that the resulting
// handoff_secret/initial_seal are internally consistent with independently
// re-derived values.
//
// NOT registered with ctest (see CMakeLists.txt) -- run manually:
//   ./orchestrator_online_test

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>

#include "quark/crypto.hpp"
#include "quark/lamport.hpp"
#include "quark/online.hpp"
#include "quark/orchestrator.hpp"
#include "quark/platform/file_witness_store.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/state.hpp"
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

// A trivial IHwidBackend for this test -- a real fingerprint's exact content
// doesn't matter here (RunUnlockFlow just needs it to be reproducible
// between mint-time and unlock-time within THIS process), only that it's
// genuinely collected via the interface RunUnlockFlow actually depends on.
class FixedFingerprintBackend : public quark::platform::IHwidBackend {
public:
    std::optional<quark::platform::Fingerprint> Collect() const override {
        quark::platform::Fingerprint fp;
        fp.fields.push_back({"test_field", "orchestrator-online-test-machine"});
        return fp;
    }
    std::string_view PlatformName() const override { return "test"; }
};

}  // namespace

int main() {
    const std::string kBuildSecret = "orchestrator-online-test-secret";
    const std::string kStatePath = "orchestrator_online_test_state.bin";
    std::filesystem::remove(kStatePath);

    FixedFingerprintBackend backend;
    auto fp = backend.Collect();
    std::vector<uint8_t> hwid_canonical = quark::platform::CanonicalBytes(*fp);

    // --- mint a real 2-link license ------------------------------------------
    auto seed = quark::crypto::RandomBytes(32);
    constexpr uint32_t kChainLength = 2;
    auto chain = quark::lamport::BuildChain(seed, kChainLength);

    quark::crypto::AesKey state_key = quark::token::DeriveStateKey(kBuildSecret, hwid_canonical);

    quark::state::LicenseState license;
    license.anchor = chain[kChainLength];
    license.remaining_links = kChainLength;
    license.hwid_digest = quark::crypto::Sha256(hwid_canonical);
    license.original_chain_length = kChainLength;

    // --- mint + POST a real online-witness paste -----------------------------
    auto kp = quark::online::GenerateKeypair();
    Check(kp.has_value(), "online::GenerateKeypair succeeds");

    quark::crypto::OnlineSecret online_secret{};
    auto random_secret = quark::crypto::RandomBytes(32);
    std::copy(random_secret.begin(), random_secret.end(), online_secret.begin());

    auto sign_msg = quark::online::BuildSignMessage(hwid_canonical, kChainLength, online_secret);
    auto sig = quark::online::SignPayload(kp->priv, sign_msg);
    Check(sig.has_value(), "online::SignPayload succeeds");

    quark::online::PastePayload payload{};
    payload.online_secret = online_secret;
    payload.ec_signature = *sig;

    quark::crypto::AesKey online_key = quark::token::DeriveOnlineKey(kBuildSecret, hwid_canonical);
    auto sealed = quark::online::SealPayload(online_key, hwid_canonical, payload);

    auto paste_id = quark::online::PostPaste(sealed);
    Check(paste_id.has_value(), "online::PostPaste succeeds against live paste.rs");
    if (!paste_id) {
        std::fprintf(stderr, "\ncannot continue without a real paste -- network issue?\n");
        return 1;
    }
    license.paste_id = *paste_id;

    Check(quark::state::Save(kStatePath, state_key, hwid_canonical, license),
          "state.bin Save() succeeds for the freshly minted license");

    // --- run the real unlock flow --------------------------------------------
    quark::orchestrator::Config config;
    config.build_secret = kBuildSecret;
    config.state_path = kStatePath;
    config.ec_public_key = kp->pub;

    quark::platform::FileWitnessStore w0("orchestrator_online_test_w0.bin", {'Q', 'W', '0', '0'}, "w0");
    quark::platform::FileWitnessStore w1("orchestrator_online_test_w1.bin", {'Q', 'W', '0', '1'}, "w1");
    quark::platform::FileWitnessStore w2("orchestrator_online_test_w2.bin", {'Q', 'W', '0', '2'}, "w2");

    std::string candidate_key = quark::lamport::FormatKey(chain[kChainLength - 1]);

    quark::orchestrator::UnlockResult result;
    quark::error::Code code = quark::orchestrator::RunUnlockFlow(
        config, backend, {&w0, &w1, &w2}, candidate_key, result);

    Check(code == quark::error::Code::kOk,
          "RunUnlockFlow succeeds end to end, including the real online-witness fetch");

    if (code == quark::error::Code::kOk) {
        bool any_zero = std::all_of(result.handoff_secret.begin(), result.handoff_secret.end(),
                                    [](uint8_t b) { return b == 0; });
        Check(!any_zero, "handoff_secret is populated (non-zero)");

        Check(result.content_key == quark::token::DeriveContentKey(result.handoff_secret),
              "content_key is independently re-derivable from handoff_secret");

        auto expected_seal = quark::token::DeriveInitialSeal(
            result.content_key, license.anchor, chain[kChainLength - 1],
            quark::crypto::Sha256(online_secret.data(), online_secret.size()), hwid_canonical);
        Check(result.initial_seal == expected_seal,
              "initial_seal matches an independently re-derived value");
    }

    // --- cleanup: revoke the real paste, remove local test files -------------
    quark::online::DeletePaste(*paste_id);
    std::filesystem::remove(kStatePath);
    std::filesystem::remove("orchestrator_online_test_w0.bin");
    std::filesystem::remove("orchestrator_online_test_w1.bin");
    std::filesystem::remove("orchestrator_online_test_w2.bin");

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
```

- [ ] **Step 6: Register the binary WITHOUT `add_test`**

In `cpp/common/tests/CMakeLists.txt`, add (near the other `add_executable`
calls, but with no accompanying `add_test`):

```cmake
# Real, live-network test -- deliberately NOT registered with add_test() so
# ctest's default run never depends on network access. Run manually:
#   ./sandbox/build-host/cpp/common/tests/orchestrator_online_test
add_executable(orchestrator_online_test orchestrator_online_test.cpp)
target_link_libraries(orchestrator_online_test PRIVATE quark_core)
```

- [ ] **Step 7: Build and run it for real**

Run:
```bash
cmake -S . -B sandbox/build-macos
cmake --build sandbox/build-macos --target orchestrator_online_test
cd sandbox/build-macos/cpp/common/tests && ./orchestrator_online_test && cd -
```
Expected:
```
ok: online::GenerateKeypair succeeds
ok: online::SignPayload succeeds
ok: online::PostPaste succeeds against live paste.rs
ok: state.bin Save() succeeds for the freshly minted license
ok: RunUnlockFlow succeeds end to end, including the real online-witness fetch
ok: handoff_secret is populated (non-zero)
ok: content_key is independently re-derivable from handoff_secret
ok: initial_seal matches an independently re-derived value

all checks passed.
```

- [ ] **Step 8: Run the full default suite to confirm no regression**

Run: `ctest --test-dir sandbox/build-macos --output-on-failure`
Expected: the same 7 tests from Phase A/B still pass;
`orchestrator_online_test` does NOT appear in this list (by design).

- [ ] **Step 9: Commit**

```bash
git add cpp/common/include/quark/orchestrator.hpp cpp/common/src/orchestrator.cpp cpp/common/tests/orchestrator_online_test.cpp cpp/common/tests/CMakeLists.txt
git commit -m "Extend RunUnlockFlow: real online-witness fetch, expose handoff_secret/initial_seal"
```

---

### Task 3: Wire the dormant POSIX process-handoff and anti-debug code into the build

**Files:**
- Modify: `cpp/common/CMakeLists.txt`

`quark::platform::posix::process_handoff` (`src/platform_posix/process_handoff.cpp`)
and the macOS/Linux `DebuggerDetected()` implementations
(`src/platform_macos/anti_debug_macos.cpp`, `src/platform_linux/anti_debug_linux.cpp`)
are complete, correct implementations from an earlier design pass -- but none
of them are in any CMake target's source list yet (confirmed: neither
`quark_platform_macos` nor `quark_platform_linux` currently lists them).

- [ ] **Step 1: Add them to the macOS target**

In `cpp/common/CMakeLists.txt`, inside the `if(APPLE)` block, change:

```cmake
    add_library(quark_platform_macos STATIC
        src/platform_macos/hwid_backend_macos.cpp
        src/platform_macos/xattr_witness_store.cpp
    )
```

to:

```cmake
    add_library(quark_platform_macos STATIC
        src/platform_macos/anti_debug_macos.cpp
        src/platform_macos/hwid_backend_macos.cpp
        src/platform_macos/xattr_witness_store.cpp
        src/platform_posix/process_handoff.cpp
    )
```

- [ ] **Step 2: Add them to the Linux target**

In the same file, inside the `if(UNIX AND NOT APPLE)` block, change:

```cmake
    add_library(quark_platform_linux STATIC
        src/platform_linux/hwid_backend_linux.cpp
        src/platform_linux/xattr_witness_store.cpp
    )
```

to:

```cmake
    add_library(quark_platform_linux STATIC
        src/platform_linux/anti_debug_linux.cpp
        src/platform_linux/hwid_backend_linux.cpp
        src/platform_linux/xattr_witness_store.cpp
        src/platform_posix/process_handoff.cpp
    )
```

(`process_handoff.cpp` compiles into both targets independently -- it's
identical POSIX code shared by both OSes, not logic that differs per OS; see
its own header comment for why this is the one case worth sharing rather
than duplicating.)

- [ ] **Step 3: Build both to verify**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target quark_platform_macos`
Expected: builds successfully -- this is the first time
`anti_debug_macos.cpp`/`process_handoff.cpp` have ever been compiled in this
repo, so this step is a real, meaningful verification, not a formality.

- [ ] **Step 4: Commit**

```bash
git add cpp/common/CMakeLists.txt
git commit -m "Wire the dormant POSIX process-handoff and anti-debug code into the build"
```

---

### Task 4: Rewrite `DRM_Wrapper`'s `main.cpp` to be cross-platform

**Files:**
- Rewrite: `cpp/drm_wrapper/main.cpp`
- Modify: `cpp/drm_wrapper/CMakeLists.txt`
- Create: `cpp/drm_wrapper/drm_wrapper.conf.example`
- Modify: `CMakeLists.txt` (top-level)

The existing `main.cpp` hand-rolls the entire unlock flow using
Windows-specific `quark::registry`/`quark::ads`/`quark::overlay` types
directly (not the generic `IWitnessStore` interface `quark_platform_win`
already exposes via `RegistryWitnessStore`/`AdsWitnessStore`/
`OverlayWitnessStore`), duplicating exactly what Tasks 1-2 just made
`RunUnlockFlow` capable of doing portably. This task replaces that
duplication and adds the three platform-specific `#ifdef` seams (anti-debug,
HWID backend + witness stores, process launch) needed for macOS/Linux.

- [ ] **Step 1: Write the config file documentation**

Create `cpp/drm_wrapper/drm_wrapper.conf.example`:

```ini
# Copy to drm_wrapper.conf next to DRM_Wrapper (or wherever
# kConfigPath points) and adjust for your deployment. Every key has a
# built-in fallback (see main.cpp) -- this file only needs to list the keys
# you actually want to override.

# Path to state.bin, relative to DRM_Wrapper's working directory.
state_path = state.bin

# Path to the protected application's jar.
quark_jar_path = quark.jar

# Overrides the compiled-in jar_digest.hpp hash (hex-encoded SHA-256, 64 hex
# chars) if set. Leave unset in production -- this exists so a test build can
# point at a throwaway file with a hash that doesn't match any real quark.jar.
# quark_jar_sha256_hex = <64 hex chars>

# Path to the JVM (or JVM stand-in, e.g. handoff_spy for testing) to launch,
# and any arguments after it. Windows example: jre\bin\javaw.exe; POSIX
# example: jre/bin/java.
jvm_path = jre/bin/java
jvm_args = -cp quark.jar:main.jar quark.drmcore.Bootstrap

# macOS/Linux only -- the two xattr-backed witness channels both live on one
# host file (the ADS-equivalent design; see CLAUDE.md's witness-channel
# table), distinguished by attribute name. The third witness channel is
# always the portable FileWitnessStore below.
witness_xattr_host_path = quark_witness_host.bin
witness_xattr1_attr = com.quark.witness1
witness_xattr2_attr = com.quark.witness2
witness_file_path = quark_witness_file.bin
```

- [ ] **Step 2: Rewrite `main.cpp`**

Replace the entire contents of `cpp/drm_wrapper/main.cpp`:

```cpp
// DRM_Wrapper
//
// Customer-facing shield. Flow (every launch):
//   1.   Anti-debug speed bumps -- any hit -> FailDeadly() immediately.
//   1.5. Hash quark.jar and compare against the expected digest (config
//        override, or the compiled-in jar_digest.hpp default) -- closes the
//        "swap the jar" gap.
//   2-7. quark::orchestrator::RunUnlockFlow does the rest: HWID collection,
//        state.bin open, three-witness cross-check, online-witness
//        fetch/verify, chain-exhaustion check, one-time key verification,
//        chain roll-forward + persistence, and session key derivation.
//   8.   Launch the JVM with a QKH2 initial frame (136 B) on stdin; stdin
//        stays OPEN. A second pipe (child stdout -> parent) carries
//        challenge responses.
//   9.   Run the challenge loop until the child exits or fails a challenge.
//
// Every failure is the same outward event: exit(1), also funneled through
// the numbered registry (fail_deadly.hpp / CLAUDE.md rule 5).
//
// Cross-platform: the flow above is identical on every OS (it's all
// quark_core/quark::orchestrator now). Only four small, explicitly-marked
// seams differ per OS -- anti-debug, the HWID backend, the three witness
// stores, and the process-launch/challenge-loop pair.

#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/config.hpp"
#include "quark/error.hpp"
#include "quark/handoff.hpp"
#include "quark/orchestrator.hpp"
#include "quark/platform/file_witness_store.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/witness_store.hpp"

#include "fail_deadly.hpp"
#include "jar_digest.hpp"
#include "secret.hpp"

#if defined(_WIN32)
#include "anti_debug.hpp"
#include "handoff.hpp"
#include "quark/platform/windows/hwid_backend_win.hpp"
#include "quark/platform/windows/witness_stores_win.hpp"
#elif defined(__APPLE__)
#include "quark/platform/macos/anti_debug_macos.hpp"
#include "quark/platform/macos/hwid_backend_macos.hpp"
#include "quark/platform/macos/xattr_witness_store.hpp"
#include "quark/platform/posix/process_handoff.hpp"
#elif defined(__linux__)
#include "quark/platform/linux/anti_debug_linux.hpp"
#include "quark/platform/linux/hwid_backend_linux.hpp"
#include "quark/platform/linux/xattr_witness_store.hpp"
#include "quark/platform/posix/process_handoff.hpp"
#endif

namespace {

using namespace quark::drm_wrapper;

constexpr const char* kComponent = "DRM_Wrapper";
constexpr const char* kConfigPath = "drm_wrapper.conf";

std::optional<quark::crypto::Sha256Digest> HashFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::vector<uint8_t> contents((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
    if (in.bad()) return std::nullopt;
    return quark::crypto::Sha256(contents);
}

bool DigestsEqual(const quark::crypto::Sha256Digest& a, const quark::crypto::Sha256Digest& b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

std::optional<quark::crypto::Sha256Digest> HexDecodeDigest(const std::string& hex) {
    if (hex.size() != 64) return std::nullopt;
    quark::crypto::Sha256Digest out{};
    for (size_t i = 0; i < 32; ++i) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string PromptForKey() {
    std::cout << "Enter your one-time unlock key: ";
    std::string line;
    std::getline(std::cin, line);
    return line;
}

std::unique_ptr<quark::platform::IHwidBackend> MakeHwidBackend() {
#if defined(_WIN32)
    return std::make_unique<quark::platform::win::WindowsHwidBackend>();
#elif defined(__APPLE__)
    return std::make_unique<quark::platform::macos::MacHwidBackend>();
#elif defined(__linux__)
    return std::make_unique<quark::platform::linux_::LinuxHwidBackend>();
#else
    return nullptr;
#endif
}

bool DebuggerDetected() {
#if defined(_WIN32)
    return quark::drm_wrapper::DebuggerDetected();
#elif defined(__APPLE__)
    return quark::platform::macos::DebuggerDetected();
#elif defined(__linux__)
    return quark::platform::linux_::DebuggerDetected();
#else
    return false;
#endif
}

// Split "a b c" into {"a", "b", "c"} -- used to turn the config's jvm_args
// string into an argv vector on POSIX.
std::vector<std::string> SplitArgs(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ' ') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

}  // namespace

int main() {
    // --- Step 1: anti-debug speed bumps ------------------------------------
    if (DebuggerDetected()) {
        FailDeadly(quark::error::Code::kWrapperDebuggerDetected);
    }

    auto config = quark::config::Config::Load(kConfigPath);
    quark::config::Config cfg = config.value_or(quark::config::Config{});

    const std::string state_path = cfg.GetOr("state_path", "state.bin");
    const std::string quark_jar_path = cfg.GetOr("quark_jar_path", "quark.jar");
    const std::string jvm_path = cfg.GetOr(
        "jvm_path",
#if defined(_WIN32)
        "jre\\bin\\javaw.exe"
#else
        "jre/bin/java"
#endif
    );
    const std::string jvm_args = cfg.GetOr(
        "jvm_args", "-cp quark.jar main.jar quark.drmcore.Bootstrap");

    // --- Step 1.5: jar integrity --------------------------------------------
    quark::crypto::Sha256Digest expected_jar_hash = kQuarkJarSha256;
    if (auto override_hex = cfg.GetOr("quark_jar_sha256_hex", ""); !override_hex.empty()) {
        auto decoded = HexDecodeDigest(override_hex);
        if (!decoded) FailDeadly(quark::error::Code::kWrapperJarIntegrityFailed);
        expected_jar_hash = *decoded;
    }

    auto jar_digest = HashFile(quark_jar_path);
    if (!jar_digest || !DigestsEqual(*jar_digest, expected_jar_hash)) {
        FailDeadly(quark::error::Code::kWrapperJarIntegrityFailed);
    }

    // --- Steps 2-7: the entire unlock flow -----------------------------------
    auto hwid_backend = MakeHwidBackend();
    if (!hwid_backend) FailDeadly(quark::error::Code::kWrapperHwidCollectionFailed);

#if defined(_WIN32)
    quark::platform::win::RegistryWitnessStore w0;
    quark::platform::win::AdsWitnessStore w1;
    quark::platform::win::OverlayWitnessStore w2;
#else
    const std::string xattr_host = cfg.GetOr("witness_xattr_host_path", "quark_witness_host.bin");
    const std::string xattr1_attr = cfg.GetOr("witness_xattr1_attr", "com.quark.witness1");
    const std::string xattr2_attr = cfg.GetOr("witness_xattr2_attr", "com.quark.witness2");
    const std::string file_path = cfg.GetOr("witness_file_path", "quark_witness_file.bin");

#if defined(__APPLE__)
    quark::platform::macos::XattrWitnessStore w0(xattr_host, xattr1_attr, {'Q', 'W', 'X', '1'}, "xattr1");
    quark::platform::macos::XattrWitnessStore w1(xattr_host, xattr2_attr, {'Q', 'W', 'X', '2'}, "xattr2");
#elif defined(__linux__)
    quark::platform::linux_::XattrWitnessStore w0(xattr_host, xattr1_attr, {'Q', 'W', 'X', '1'}, "xattr1");
    quark::platform::linux_::XattrWitnessStore w1(xattr_host, xattr2_attr, {'Q', 'W', 'X', '2'}, "xattr2");
#endif
    quark::platform::FileWitnessStore w2(file_path, {'Q', 'W', 'F', '0'}, "file");
#endif

    quark::orchestrator::Config unlock_config;
    unlock_config.build_secret = quark::drm_wrapper::kBuildSecret;
    unlock_config.state_path = state_path;
    unlock_config.ec_public_key = quark::drm_wrapper::kEcPublicKey;

    std::string raw_key = PromptForKey();

    quark::orchestrator::UnlockResult result;
    quark::error::Code code = quark::orchestrator::RunUnlockFlow(
        unlock_config, *hwid_backend, {&w0, &w1, &w2}, raw_key, result);
    quark::crypto::SecureZero(raw_key.data(), raw_key.size());

    if (code != quark::error::Code::kOk) {
        FailDeadly(code);
    }

    // --- encode the QKH2 initial frame --------------------------------------
    std::vector<uint8_t> initial_frame = quark::handoff::EncodeInitialFrame(
        result.handoff_secret, result.session_id, result.initial_seal, result.core_enc_key);
    quark::crypto::SecureZero(result.handoff_secret.data(), result.handoff_secret.size());

    // --- Step 8/9: launch + challenge loop -----------------------------------
#if defined(_WIN32)
    std::wstring wjvm_path(jvm_path.begin(), jvm_path.end());
    std::string command_line_str = jvm_path + " " + jvm_args;
    std::wstring wcommand_line(command_line_str.begin(), command_line_str.end());

    JvmSession session = LaunchJvmWithInitialHandoff(wjvm_path, wcommand_line, initial_frame);
    RunChallengeLoop(session, result.content_key, result.session_id);

    DWORD exit_code = 1;
    GetExitCodeProcess(session.process.Get(), &exit_code);
    return static_cast<int>(exit_code);
#else
    std::vector<std::string> argv = {jvm_path};
    for (auto& arg : SplitArgs(jvm_args)) argv.push_back(arg);

    quark::platform::posix::JvmSession session =
        quark::platform::posix::LaunchWithInitialHandoff(kComponent, jvm_path, argv, initial_frame);
    quark::platform::posix::RunChallengeLoop(session, result.content_key, result.session_id);
    return quark::platform::posix::WaitAndGetExitCode(session);
#endif
}
```

- [ ] **Step 3: Update the CMakeLists.txt for cross-platform linking**

Replace the contents of `cpp/drm_wrapper/CMakeLists.txt`:

```cmake
# Console subsystem: the wrapper itself prompts the user for their one-time
# unlock key via stdin/stdout (see main.cpp's PromptForKey). The JVM it
# launches is a *separate* process. Cross-platform: quark_common already
# resolves to the right quark_core + quark_platform_<os> combination on
# every OS (see cpp/common/CMakeLists.txt).
add_executable(DRM_Wrapper main.cpp)
target_link_libraries(DRM_Wrapper PRIVATE quark_common)

if(WIN32)
    # /MT is enforced globally via CMAKE_MSVC_RUNTIME_LIBRARY in the top-level
    # CMakeLists -- no per-target override needed, which is itself a guard
    # against someone accidentally shipping a /MD build of just this binary.
endif()
```

- [ ] **Step 4: Un-gate `DRM_Wrapper` from `WIN32`**

In the top-level `CMakeLists.txt`, replace:

```cmake
if(WIN32)
    add_subdirectory(cpp/drm_wrapper)
else()
    message(STATUS
        "Not configuring on Windows -- DRM_Wrapper still requires the Windows "
        "platform layer (see docs/superpowers/specs/2026-07-05-cross-platform-"
        "porting-roadmap.md Phase C for the in-progress cross-platform port).")
endif()
```

with:

```cmake
# DRM_Wrapper is cross-platform as of Phase C of
# docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md.
add_subdirectory(cpp/drm_wrapper)
```

- [ ] **Step 5: Build it for real**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target DRM_Wrapper`
Expected: builds successfully. This is the first time `DRM_Wrapper` has ever
been compiled on a non-Windows machine.

- [ ] **Step 6: Commit**

```bash
git add cpp/drm_wrapper/main.cpp cpp/drm_wrapper/CMakeLists.txt cpp/drm_wrapper/drm_wrapper.conf.example CMakeLists.txt
git commit -m "Port DRM_Wrapper to be cross-platform: config-driven, calls RunUnlockFlow"
```

---

### Task 5: Real end-to-end test using `handoff_spy` as the JVM stand-in

**Files:** none created -- this is a manual, real-system verification using
binaries already built by earlier tasks/phases.

This is the payoff of everything above: a genuine, non-mocked, full
`DRM_Wrapper` launch cycle on macOS, using `handoff_spy` (ported in Phase A)
as the "JVM" -- exactly what that tool exists for.

- [ ] **Step 1: Set up a scratch directory under `sandbox/`**

```bash
cd sandbox/build-macos
mkdir -p phase_c_e2e && cd phase_c_e2e
```

- [ ] **Step 2: Mint a real dev-mode license**

```bash
../cpp/hwid_extractor/HWID_Extractor hwid.json
../cpp/dev_keygen/Dev_Keygen hwid.json 2 . --dev --label "phase-c-e2e"
ls state.bin unlock_keys.txt
```
Expected: both files exist. `--dev` mode mints with an empty `paste_id`, so
`RunUnlockFlow`'s online-witness branch takes the all-zero-secret path --
this test is about proving the process-launch/challenge-loop machinery, not
re-testing Task 2's online path (already covered by
`orchestrator_online_test`).

- [ ] **Step 3: Create a fake "quark.jar" and compute its real hash**

```bash
echo "not a real jar, just needs a stable hash for this test" > quark.jar
shasum -a 256 quark.jar
```
Note the printed hash (64 hex characters).

- [ ] **Step 4: Write `drm_wrapper.conf` pointing at `handoff_spy`**

```bash
cat > drm_wrapper.conf << EOF
state_path = state.bin
quark_jar_path = quark.jar
quark_jar_sha256_hex = $(shasum -a 256 quark.jar | awk '{print $1}')
jvm_path = ../cpp/handoff_spy/handoff_spy
jvm_args =
witness_xattr_host_path = quark_witness_host.bin
witness_xattr1_attr = com.quark.phase_c_test.witness1
witness_xattr2_attr = com.quark.phase_c_test.witness2
witness_file_path = quark_witness_file.bin
EOF
touch quark_witness_host.bin
```

- [ ] **Step 5: Run `DRM_Wrapper` for real, feeding it the real unlock key**

```bash
export QUARK_SPY_CHALLENGES=1
head -n 1 unlock_keys.txt | ../cpp/drm_wrapper/DRM_Wrapper
echo "exit code: $?"
```
Expected: `DRM_Wrapper` prints "Enter your one-time unlock key: ", consumes
the piped key, and (via stderr, since that's where `handoff_spy` logs)
prints lines like:
```
[handoff_spy] PASS: QKH2 initial frame valid (magic=QKH2, version=2, 136 bytes)
[handoff_spy] handoff_secret: ...
...
[handoff_spy] PASS: 1 challenge cycles completed
```
and finally `exit code: 0` -- `DRM_Wrapper` exits with `handoff_spy`'s own
exit code (0, since it completed its one configured challenge cycle cleanly).
This proves, for real: anti-debug check passed, jar integrity check passed
against the config-overridden hash, `RunUnlockFlow` completed (HWID collect,
`state.bin` open, all three witness channels minted fresh and cross-checked,
chain rolled forward), the QKH2 frame was correctly built and piped to a
real child process over real POSIX pipes, and a full challenge-response
cycle completed with a byte-correct HMAC in both directions.

- [ ] **Step 6: Verify the chain actually rolled forward**

```bash
head -n 1 unlock_keys.txt > /tmp/phase_c_first_key.txt
export QUARK_SPY_CHALLENGES=1
./../cpp/drm_wrapper/DRM_Wrapper < /tmp/phase_c_first_key.txt
echo "exit code (expect nonzero -- replayed key): $?"
```
Expected: nonzero exit -- the first key was already consumed in Step 5, so
`RunUnlockFlow` now returns `kWrapperUnlockKeyInvalid` and `DRM_Wrapper`
fail-deadlies before ever launching `handoff_spy` again. This proves the
Lamport chain genuinely persisted and rolled forward across the two
`DRM_Wrapper` invocations, not just within one process's memory.

- [ ] **Step 7: Verify the second (still-valid) key works**

```bash
sed -n '2p' unlock_keys.txt | ../cpp/drm_wrapper/DRM_Wrapper
echo "exit code: $?"
```
Expected: exit code 0, same success pattern as Step 5 -- the license had 2
links; the second key is still valid and this was its only use.

- [ ] **Step 8: Clean up**

```bash
cd sandbox/build-macos
rm -rf phase_c_e2e
rm -f /tmp/phase_c_first_key.txt
```

---

### Task 6: Documentation

**Files:**
- Modify: `cpp/drm_wrapper/README.md`
- Modify: `docs/PLAN.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `cpp/drm_wrapper/README.md`**

Replace the "Compilation" section:

```markdown
## Compilation

Cross-platform as of Phase C of docs/superpowers/specs/2026-07-05-cross-
platform-porting-roadmap.md -- config-driven (see
[drm_wrapper.conf.example](drm_wrapper.conf.example)) and built on
`quark::orchestrator::RunUnlockFlow` instead of a Windows-specific
hand-rolled copy of the same logic.

```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target DRM_Wrapper
```
Outputs `sandbox/build-host/cpp/drm_wrapper/DRM_Wrapper` (or
`DRM_Wrapper.exe` on Windows). Copy `drm_wrapper.conf.example` to
`drm_wrapper.conf` next to the binary and adjust for your deployment --
every key has a built-in fallback matching the original Windows defaults, so
an empty/missing config file preserves prior behavior.

On macOS/Linux, `handoff_spy` (see [cpp/handoff_spy](../handoff_spy/README.md))
can stand in for a real JVM during testing -- point `jvm_path` at it in
`drm_wrapper.conf`.
```

Also update the "Core Flow & Operations" section's step 4 (witness channels)
to add a note: "On macOS/Linux, the same logic runs against two
xattr-backed channels plus one portable file-backed channel instead of
registry/ADS/exe-overlay -- see CLAUDE.md's witness-channel table."

- [ ] **Step 2: Record Phase C in the plan**

Append to `docs/PLAN.md` (after Phase XI):

```markdown
## Phase XII — Cross-platform port, Phase C: DRM_Wrapper
Implements Phase C of docs/superpowers/specs/2026-07-05-cross-platform-
porting-roadmap.md -- the last of the six originally Windows-only programs.

- [x] `quark::config::Config` implemented for real (`config.cpp`) --
      previously declared in a header with zero implementation anywhere in
      the repo. Covered by a real filesystem round-trip test.
- [x] `quark::orchestrator::RunUnlockFlow` extended: real online-witness
      fetch/decrypt/signature-verify (using Phase B's portable HTTP client --
      previously this path unconditionally failed for any non-dev-mode
      license), plus `handoff_secret`/`initial_seal` added to `UnlockResult`
      (without these, no caller could actually build a QKH2 frame from this
      function's output at all). Covered by a real, live-network end-to-end
      test (`orchestrator_online_test`, deliberately not part of the default
      `ctest` run, matching `Paste_Test`'s precedent).
- [x] The dormant `quark::platform::posix::process_handoff` and macOS/Linux
      `DebuggerDetected()` implementations -- written in an earlier,
      since-abandoned design pass and never added to any CMake target --
      wired into `quark_platform_macos`/`quark_platform_linux` for real.
- [x] `DRM_Wrapper`'s `main.cpp` rewritten from a ~250-line Windows-specific
      hand-rolled duplicate of `RunUnlockFlow`'s logic into a single
      portable flow with four `#ifdef`-selected seams (anti-debug, HWID
      backend, witness stores, process launch/challenge-loop). Jar path/hash
      and JVM launch settings are now config-driven
      (`drm_wrapper.conf`/`quark::config`) instead of hardcoded, per
      CLAUDE.md rule 2.
- [x] Verified for real on macOS: a full `DRM_Wrapper` launch cycle against
      a real, freshly Dev_Keygen-minted `state.bin`, using `handoff_spy` as
      the JVM stand-in -- real anti-debug check, real jar-hash check against
      a config-overridden digest, real `RunUnlockFlow` execution (HWID
      collect, witness mint/cross-check, chain roll), a real QKH2 handoff
      over real POSIX pipes, and a real challenge-response cycle. Also
      verified the Lamport chain genuinely persists and rolls forward
      across separate process invocations (a replayed first key correctly
      fails on the second run; the still-valid second key succeeds).
- [x] All six originally Windows-only programs (`HWID_Extractor`,
      `handoff_spy`, `quark-runtime-c`, `Paste_Test`, `Dev_Keygen`,
      `DRM_Wrapper`) are now cross-platform. The
      docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md
      roadmap is complete.

### Not done yet
- Linux was not available to test against in this session. Every
  Linux-specific code path this phase touches (`LinuxHwidBackend`,
  `quark::platform::linux_::DebuggerDetected`, `process_handoff.cpp`
  compiled into `quark_platform_linux`, `XattrWitnessStore`) either already
  had independent Linux verification from earlier phases of this project, or
  (for `process_handoff.cpp`/anti-debug) is identical POSIX code already
  verified for real on macOS in this phase -- but the *whole, assembled*
  `DRM_Wrapper` binary itself has only been run end-to-end on macOS so far.
- Windows re-verification of the refactored `main.cpp` (same file, now built
  from shared logic instead of a hand-rolled copy) has not happened in this
  session -- no Windows machine was available. The Windows-specific code
  paths (`anti_debug.hpp`, `handoff.hpp`, `RegistryWitnessStore`/
  `AdsWitnessStore`/`OverlayWitnessStore`) are unchanged from before this
  phase; what changed is which function calls them.
- No anti-tamper/obfuscation hardening was added or changed -- out of scope,
  consistent with this project's standing sequencing (CLAUDE.md: that comes
  last, after the core is clean and correct).
```

- [ ] **Step 3: Update CLAUDE.md's "Target platform" section**

In `CLAUDE.md`, find the "Target platform" section's bullet describing what's
"still missing" for macOS/Linux (currently says "an actual
`DRM_Wrapper`-equivalent orchestrator binary... hasn't happened yet"), and
replace that entire bullet with:

```markdown
- **Cross-platform by design; all three platform layers now exist, and
  every module builds and runs on every OS.** `quark_core` builds anywhere
  (any C++17 compiler + mbedTLS). All three platform layers
  (`quark_platform_win`/`quark_platform_macos`/`quark_platform_linux`) are
  fully implemented. As of docs/superpowers/specs/2026-07-05-cross-platform-
  porting-roadmap.md, all six originally Windows-only executables
  (`HWID_Extractor`, `Dev_Keygen`, `DRM_Wrapper`, `Paste_Test`,
  `handoff_spy`, `quark-runtime-c`) are cross-platform and have been
  verified for real on macOS. Linux verification of the fully-assembled
  executables (as opposed to the underlying `quark_platform_linux` library,
  independently verified earlier) and a Windows re-verification of
  `DRM_Wrapper`'s refactored `main.cpp` are the two remaining gaps -- see
  `docs/PLAN.md`'s Phase XII for the exact scope of what's confirmed versus
  outstanding.
```

- [ ] **Step 4: Commit**

```bash
git add cpp/drm_wrapper/README.md docs/PLAN.md CLAUDE.md
git commit -m "Document Phase C of the cross-platform porting roadmap"
```

---

## Self-review notes (from writing this plan)

- **Spec coverage:** The roadmap spec's Phase C scope (wire the dormant
  `process_handoff`/`DebuggerDetected` code, refactor `main.cpp` to call
  `RunUnlockFlow`, use Phase B's HTTP client for the online-witness fetch) is
  covered by Tasks 3-5. Two gaps the roadmap spec did NOT anticipate --
  `RunUnlockFlow` couldn't actually support the online-witness path or
  expose `handoff_secret` at all, and `quark::config` had never been
  implemented -- were found by reading the actual current source (not
  assumed) and are fixed in Tasks 1-2 before Task 4 depends on them.
- **Placeholder scan:** no TBD/TODO; every step has complete, runnable code,
  including the full config-file format and every `#ifdef` branch's
  concrete implementation.
- **Type consistency:** `quark::orchestrator::Config`/`UnlockResult`,
  `quark::config::Config`, and the per-OS `IHwidBackend`/`IWitnessStore`
  concrete types (already established in Phase A/B and quark_c_api.cpp) are
  used identically across all six tasks.
- **Testing rigor:** Task 1's config test and Task 2's live-network
  orchestrator test are both real, non-mocked (a real file, a real paste.rs
  round trip). Task 5 is the capstone: a genuine, multi-invocation
  `DRM_Wrapper` run against a real Dev_Keygen-minted license, using
  `handoff_spy` (deliberately independent crypto, see Phase A) as the far
  end -- and explicitly verifies chain persistence *across process
  invocations*, not just within one run, which is the property that
  actually matters for a real license (a bug that only manifested on a
  second launch would be invisible to a single-shot test).
- **Scope boundary respected:** anti-tamper/obfuscation hardening and
  Windows re-verification are explicitly called out as out of scope for this
  phase (Task 6, Step 2's "Not done yet" section) rather than silently
  glossed over.
