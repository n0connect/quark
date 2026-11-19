# Phase B: Portable HTTPS Client + Paste_Test/Dev_Keygen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `quark::online`'s WinHTTP-only `PostPaste`/`FetchPaste`/`DeletePaste` with one portable, mbedTLS-based implementation used identically on every OS, then port `Paste_Test` and `Dev_Keygen` (both already 90% portable per Phase A's audit) to build and run for real on macOS/Linux.

**Architecture:** `cpp/common/src/online.cpp` currently mixes two orthogonal things in one Windows-only file: portable PSA/mbedTLS crypto (`SealPayload`/`UnsealPayload`/`SignPayload`/`VerifySignature`/`GenerateKeypair`/`BuildSignMessage`) and WinHTTP-specific network I/O (`PostPaste`/`FetchPaste`/`DeletePaste`). This plan splits it into `online_crypto.cpp` (moves to `quark_core` unmodified -- it never touched WinHTTP) and a brand-new `online_http.cpp` (also `quark_core`) that implements the same three network functions using mbedTLS's own `net`/`ssl`/`x509` modules (already statically linked into every build -- see the roadmap spec's "Decision" section for why mbedTLS over `curl` subprocess). The HTTP client pins paste.rs's issuing CA certificate as the sole trusted root (narrower and more secure than trusting an arbitrary CA bundle for a single fixed host). `Dev_Keygen` additionally needs one real fix: it still parses `hwid.json` via the legacy Windows-only `quark::hwid::FromJson`, which cannot read the new cross-platform format `HWID_Extractor` now produces (Phase A) -- this plan switches it to `quark::platform::FingerprintFromJson`.

**Tech Stack:** C++17, CMake, mbedTLS's `net_sockets`/`ssl`/`x509_crt`/`ctr_drbg`/`entropy` modules (already vendored and linked as the `mbedtls` CMake target). This plan makes real, live network calls to `https://paste.rs` as its acceptance test -- per CLAUDE.md rule 1, "compiles" is not the bar.

Reference: [docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md](../specs/2026-07-05-cross-platform-porting-roadmap.md)

---

## File structure

```
cpp/common/src/online_crypto.cpp          new: moved verbatim (portable) from online.cpp
cpp/common/src/online_http.cpp            new: mbedTLS-based PostPaste/FetchPaste/DeletePaste
cpp/common/src/online.cpp                 deleted (split into the two files above)
cpp/common/CMakeLists.txt                 modify: online_crypto.cpp + online_http.cpp -> quark_core;
                                           remove online.cpp + winhttp lib from quark_platform_win
cpp/common/tests/core_smoke_test.cpp      modify: add online_crypto round-trip tests

cpp/dev_keygen/main.cpp                   modify: quark::hwid::FromJson/CanonicalBytes ->
                                           quark::platform::FingerprintFromJson/CanonicalBytes

CMakeLists.txt                            modify: un-gate Dev_Keygen and paste_test from WIN32
docs/PLAN.md                              modify: record Phase B
```

---

### Task 1: Split `online.cpp` -- extract the already-portable crypto half

**Files:**
- Create: `cpp/common/src/online_crypto.cpp`
- Modify: `cpp/common/CMakeLists.txt`
- Modify: `cpp/common/tests/core_smoke_test.cpp`

`BuildSignMessage`/`SealPayload`/`UnsealPayload`/`SignPayload`/`VerifySignature`/`GenerateKeypair`
in the current `cpp/common/src/online.cpp` only use `quark::crypto`, `quark::token`,
and mbedTLS's PSA API (`psa_crypto_init`, `psa_sign_message`, etc.) -- nothing
WinHTTP-specific. They are being moved verbatim, not rewritten.

- [ ] **Step 1: Write the failing tests**

Add to `cpp/common/tests/core_smoke_test.cpp`, right after
`TestHandoffFrameEncoding()`'s definition (insert immediately after its
closing `}`):

```cpp
void TestOnlinePayloadCrypto() {
    quark::crypto::AesKey online_key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), online_key.begin());
    std::vector<uint8_t> hwid_aad = FakeHwidAad();

    quark::online::PastePayload payload{};
    auto secret = quark::crypto::RandomBytes(32);
    std::copy(secret.begin(), secret.end(), payload.online_secret.begin());
    auto sig_bytes = quark::crypto::RandomBytes(64);
    std::copy(sig_bytes.begin(), sig_bytes.end(), payload.ec_signature.begin());

    auto sealed = quark::online::SealPayload(online_key, hwid_aad, payload);
    auto opened = quark::online::UnsealPayload(online_key, hwid_aad, sealed);
    Check(opened.has_value(), "online::UnsealPayload succeeds on its own SealPayload output");
    if (opened) {
        Check(opened->online_secret == payload.online_secret &&
                  opened->ec_signature == payload.ec_signature,
              "online payload round-trip preserves both fields");
    }

    auto opened_wrong_aad = quark::online::UnsealPayload(
        online_key, std::vector<uint8_t>{'w', 'r', 'o', 'n', 'g'}, sealed);
    Check(!opened_wrong_aad.has_value(), "online::UnsealPayload fails on wrong HWID AAD");

    auto msg = quark::online::BuildSignMessage(hwid_aad, 10, payload.online_secret);
    auto msg2 = quark::online::BuildSignMessage(hwid_aad, 10, payload.online_secret);
    Check(msg == msg2, "online::BuildSignMessage is deterministic for identical inputs");

    auto kp = quark::online::GenerateKeypair();
    Check(kp.has_value(), "online::GenerateKeypair succeeds");
    if (kp) {
        auto sig = quark::online::SignPayload(kp->priv, msg);
        Check(sig.has_value(), "online::SignPayload succeeds with a freshly generated key");
        if (sig) {
            Check(quark::online::VerifySignature(kp->pub, msg, *sig),
                  "online::VerifySignature accepts a signature made with the matching private key");

            auto tampered_msg = msg;
            tampered_msg.push_back(0xFF);
            Check(!quark::online::VerifySignature(kp->pub, tampered_msg, *sig),
                  "online::VerifySignature rejects a signature over a different message");
        }
    }
}
```

Add `#include "quark/online.hpp"` to the test file's includes (alphabetically,
after `#include "quark/lamport.hpp"`). Add `TestOnlinePayloadCrypto();` to
`main()`, right after `TestHandoffFrameEncoding();`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build sandbox/build-macos --target quark_core_tests`
Expected: FAIL -- `error: no member named 'SealPayload' in namespace 'quark::online'`
(the crypto implementation is still only compiled into `quark_platform_win`,
which this test target doesn't link).

- [ ] **Step 3: Create the portable crypto file**

Create `cpp/common/src/online_crypto.cpp` with this exact content (moved
verbatim from the crypto half of the current `cpp/common/src/online.cpp` --
the serialization/PSA logic is unchanged, only the WinHTTP-specific parts are
left out):

```cpp
#include "quark/online.hpp"

#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <cstring>
#include <string>

#include "quark/crypto.hpp"
#include "quark/token.hpp"

namespace quark::online {

namespace {

// --- PSA lazy init ----------------------------------------------------------
bool EnsurePsa() {
    static const bool kOk = (psa_crypto_init() == PSA_SUCCESS);
    return kOk;
}

// --- Blob serialization helpers ---------------------------------------------
void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

uint32_t ReadU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

// --- Blob format ------------------------------------------------------------
constexpr uint8_t kMagic[4]       = {'Q', 'O', 'N', 'L'};
constexpr uint32_t kBlobVersion   = 1;
constexpr size_t kPlaintextSize   = 32 + 64;  // online_secret + ec_signature

constexpr size_t kHeaderSize =
    sizeof(kMagic) + sizeof(uint32_t) + crypto::kGcmIvSize
    + crypto::kGcmTagSize + sizeof(uint32_t);

static std::vector<uint8_t> SerializePayload(const PastePayload& p) {
    std::vector<uint8_t> out;
    out.reserve(kPlaintextSize);
    out.insert(out.end(), p.online_secret.begin(), p.online_secret.end());
    out.insert(out.end(), p.ec_signature.begin(), p.ec_signature.end());
    return out;
}

static bool DeserializePayload(const std::vector<uint8_t>& bytes, PastePayload& out) {
    if (bytes.size() != kPlaintextSize) return false;
    std::memcpy(out.online_secret.data(), bytes.data(), 32);
    std::memcpy(out.ec_signature.data(), bytes.data() + 32, 64);
    return true;
}

}  // namespace

std::vector<uint8_t> BuildSignMessage(const std::vector<uint8_t>& hwid_canonical,
                                       uint32_t original_chain_length,
                                       const crypto::OnlineSecret& online_secret) {
    const char* prefix = "QUARK-ONLINE-V1";
    std::vector<uint8_t> msg;
    msg.reserve(std::strlen(prefix) + hwid_canonical.size() + 4 + 32);
    msg.insert(msg.end(), prefix, prefix + std::strlen(prefix));
    msg.insert(msg.end(), hwid_canonical.begin(), hwid_canonical.end());
    AppendU32(msg, original_chain_length);
    msg.insert(msg.end(), online_secret.begin(), online_secret.end());
    return msg;
}

std::vector<uint8_t> SealPayload(const crypto::AesKey& online_key,
                                  const std::vector<uint8_t>& hwid_canonical,
                                  const PastePayload& payload) {
    std::vector<uint8_t> pt = SerializePayload(payload);
    crypto::ScopedZero<std::vector<uint8_t>> zero_pt(pt);

    auto sealed = crypto::Aes256GcmEncrypt(online_key, hwid_canonical, pt);

    std::vector<uint8_t> blob;
    blob.reserve(kHeaderSize + sealed.ciphertext.size());
    blob.insert(blob.end(), kMagic, kMagic + sizeof(kMagic));
    AppendU32(blob, kBlobVersion);
    blob.insert(blob.end(), sealed.iv.begin(), sealed.iv.end());
    blob.insert(blob.end(), sealed.tag.begin(), sealed.tag.end());
    AppendU32(blob, static_cast<uint32_t>(sealed.ciphertext.size()));
    blob.insert(blob.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
    return blob;
}

std::optional<PastePayload> UnsealPayload(const crypto::AesKey& online_key,
                                           const std::vector<uint8_t>& hwid_canonical,
                                           const std::vector<uint8_t>& blob) {
    if (blob.size() < kHeaderSize) return std::nullopt;
    if (std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) return std::nullopt;

    size_t off = sizeof(kMagic);
    if (ReadU32LE(blob.data() + off) != kBlobVersion) return std::nullopt;
    off += 4;

    std::vector<uint8_t> iv(blob.begin() + off, blob.begin() + off + crypto::kGcmIvSize);
    off += crypto::kGcmIvSize;
    std::vector<uint8_t> tag(blob.begin() + off, blob.begin() + off + crypto::kGcmTagSize);
    off += crypto::kGcmTagSize;
    uint32_t ct_len = ReadU32LE(blob.data() + off);
    off += 4;
    if (blob.size() != off + ct_len) return std::nullopt;

    std::vector<uint8_t> ct(blob.begin() + off, blob.end());
    auto pt = crypto::Aes256GcmDecrypt(online_key, iv, hwid_canonical, ct, tag);
    if (!pt) return std::nullopt;
    crypto::ScopedZero<std::vector<uint8_t>> zero_pt(*pt);

    PastePayload out{};
    if (!DeserializePayload(*pt, out)) return std::nullopt;
    return out;
}

std::optional<EcSignature> SignPayload(const EcPrivateKey& kpriv,
                                        const std::vector<uint8_t>& message) {
    if (!EnsurePsa()) return std::nullopt;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (psa_import_key(&attr, kpriv.data(), kpriv.size(), &key_id) != PSA_SUCCESS)
        return std::nullopt;

    EcSignature sig{};
    size_t sig_len = 0;
    psa_status_t st = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                        message.data(), message.size(),
                                        sig.data(), sig.size(), &sig_len);
    psa_destroy_key(key_id);
    if (st != PSA_SUCCESS || sig_len != 64) return std::nullopt;
    return sig;
}

bool VerifySignature(const EcPublicKey& kpub,
                     const std::vector<uint8_t>& message,
                     const EcSignature& sig) {
    if (!EnsurePsa()) return false;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (psa_import_key(&attr, kpub.data(), kpub.size(), &key_id) != PSA_SUCCESS)
        return false;

    psa_status_t st = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                          message.data(), message.size(),
                                          sig.data(), sig.size());
    psa_destroy_key(key_id);
    return (st == PSA_SUCCESS);
}

std::optional<Keypair> GenerateKeypair() {
    if (!EnsurePsa()) return std::nullopt;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);

    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (psa_generate_key(&attr, &key_id) != PSA_SUCCESS) return std::nullopt;

    Keypair kp{};
    size_t len = 0;
    if (psa_export_key(key_id, kp.priv.data(), kp.priv.size(), &len) != PSA_SUCCESS
        || len != 32) {
        psa_destroy_key(key_id);
        return std::nullopt;
    }
    if (psa_export_public_key(key_id, kp.pub.data(), kp.pub.size(), &len) != PSA_SUCCESS
        || len != 65) {
        mbedtls_platform_zeroize(kp.priv.data(), kp.priv.size());
        psa_destroy_key(key_id);
        return std::nullopt;
    }
    psa_destroy_key(key_id);
    return kp;
}

}  // namespace quark::online
```

- [ ] **Step 4: Wire it into `quark_core` (not `quark_platform_win`)**

In `cpp/common/CMakeLists.txt`, add `src/online_crypto.cpp` to `quark_core`'s
source list:

```cmake
add_library(quark_core STATIC
    src/crypto.cpp
    src/error.cpp
    src/handoff.cpp
    src/lamport.cpp
    src/online_crypto.cpp
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

`quark_core` links `mbedcrypto` already (for AES-GCM/SHA-256/HMAC); PSA's
crypto API (`psa_crypto_init`, `psa_sign_message`, etc.) is part of that same
`mbedcrypto` library, so no new link dependency is needed.

- [ ] **Step 5: Run test to verify it passes**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target quark_core_tests && ./sandbox/build-macos/cpp/common/tests/quark_core_tests`
Expected: all `TestOnlinePayloadCrypto` checks print `ok:`, `all checks passed.`,
exit code 0. This is a real, non-mocked test: `GenerateKeypair`/`SignPayload`/
`VerifySignature` run mbedTLS's actual PSA ECDSA implementation, not a stub.

- [ ] **Step 6: Commit**

```bash
git add cpp/common/src/online_crypto.cpp cpp/common/CMakeLists.txt cpp/common/tests/core_smoke_test.cpp
git commit -m "Extract quark::online's portable crypto into quark_core (online_crypto.cpp)"
```

---

### Task 2: Portable mbedTLS-based HTTPS client for paste.rs

**Files:**
- Create: `cpp/common/src/online_http.cpp`
- Modify: `cpp/common/CMakeLists.txt`
- Delete: `cpp/common/src/online.cpp`

This is genuinely new code (no prior implementation to move) -- the roadmap
spec's "Decision" section covers why mbedTLS's own `net`/`ssl` modules were
chosen over shelling out to `curl`, and why the client pins paste.rs's
issuing CA rather than trusting an arbitrary CA bundle.

- [ ] **Step 1: Create the portable HTTP client**

Create `cpp/common/src/online_http.cpp`:

```cpp
// Portable HTTPS client for paste.rs, built on mbedTLS's own net/ssl/x509
// modules (already statically linked into quark_core -- see
// cpp/common/CMakeLists.txt's `mbedtls` link) rather than a platform-specific
// HTTP stack (Windows' old implementation used WinHTTP) or a subprocess
// dependency on a system `curl` binary. One implementation, used identically
// by DRM_Wrapper (customer runtime), Dev_Keygen, and Paste_Test on every OS.
//
// Certificate pinning, not a CA bundle: Quark only ever talks to one fixed
// host (paste.rs), so bundling/maintaining a portable Mozilla root store is
// unnecessary complexity. Instead, this pins paste.rs's issuing CA
// certificate as the ONLY trusted root -- more restrictive (and therefore
// more secure for this one connection) than trusting arbitrary CAs, and it
// survives paste.rs's routine ~90-day LEAF certificate renewals because we
// pin the much-longer-lived issuing intermediate, not the leaf.
//
// This constant is crypto-load-bearing (CLAUDE.md rule 2's hardcoding
// exception): a config file would just move the attack surface (an attacker
// who can rewrite config can already MITM the connection) without adding
// real value. Captured via:
//   openssl s_client -connect paste.rs:443 -servername paste.rs -showcerts
// then taking the SECOND certificate in the chain (the issuing intermediate,
// not the leaf -- `subject=C=US, O=Let's Encrypt, CN=YR2` at capture time).
// Valid 2025-09-03 through 2028-09-02. If paste.rs's operator changes CA
// (or this expires), re-run the command above and replace the PEM below with
// whatever intermediate is now serving paste.rs's leaf certificate.

#include "quark/online.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <cstdlib>
#include <cstring>
#include <sstream>

namespace quark::online {

namespace {

constexpr const char* kHost = "paste.rs";
constexpr const char* kPort = "443";

constexpr char kPastersCaPem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIE2jCCAsKgAwIBAgIQTr0klH4k05SALYSlL9WzGTANBgkqhkiG9w0BAQsFADAu\n"
"MQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZUjAe\n"
"Fw0yNTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYw\n"
"FAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZUjIwggEiMA0GCSqGSIb3\n"
"DQEBAQUAA4IBDwAwggEKAoIBAQDZ0LxwBppqh84luqMerV/eeL/fXQ7mLQQv1Lnp\n"
"WKZbyvGpx6wh6AfnslAnF6ewTkcHA+gSOoBvm3Dfm06AuGiF+KRut4fAcowqnAQQ\n"
"CW98+QPP/eOv/wug7Iyk4NkOxf2I6g2f55T6nJoOTLFcukeRq80JGQEYan+dPFr9\n"
"OGUgQK2hGKgNkW87pappsOAuUJcroYhRt5uUis4qaZireiseu32gzDJNBAiKtsvd\n"
"6HX4v25bpkRNcS/B/Gtc9kVbUpD+2PLPxdei3Tim55k4tfAEXwD2qyiPTxrTNq6l\n"
"N+AMr5g2c1dNqkOTwjxeV6L5lpP1rGiYvLnRaPlOqyZRPW+5AgMBAAGjge4wgesw\n"
"DgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQI\n"
"MAYBAf8CAQAwHQYDVR0OBBYEFEAVLSZ57TIgnt+ach3WMh+BDIEMMB8GA1UdIwQY\n"
"MBaAFN7nW2DQIm1AKH0/DQH+pLVStFGUMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEF\n"
"BQcwAoYWaHR0cDovL3lyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAEC\n"
"ATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veXIuYy5sZW5jci5vcmcvMA0GCSqG\n"
"SIb3DQEBCwUAA4ICAQB0ZUQWZ9/Yn9COEpo+JfecMnB0h0vwDm/M66IqXqw3LoaL\n"
"mx9lZvRTeDIS67PUeI3yCA2W6PKRD0/FE/G57lOmS+Xy5AaaL00ICGOqjNcCaMWW\n"
"8o8nevHOd4i4lqgtznE/28QwlcdJyF8yBiWHpnyjhEpmNWJURgOCOg2xpwRMBCsj\n"
"MScqYPtOhBeuYQvSwAEeTML2Ukh6uGuX4E14q65Ja8cdjF5bAldnP1eE4FBaAwsZ\n"
"G2fOqqrKV03Y85Nw2btedP1AtliQuJZs/Jo/gXxXdc7LrH3McgnpnbTiAncX7yES\n"
"hP6kzQejllqMCIt52HOjxDGWafS7Xw+DKwqmH+Eqy8dcbOuag/1AYlQoKNVK3F5q\n"
"Hh6tEDiMqQcLIibGKteE6iHo4A/bIScbzrhXUYuism42ZYzmc48FMVIH3qy4L84E\n"
"TdAH2gtxw0PAhvRVXp8HP7wfngpzsN/8xOTpeRSbM4+Qbc56G6+Bifmv6sk1ieQb\n"
"NA3wJdl4DDUuQSV8hBgx6zoI1ZSGORprDFux7c6rhc77QZMSRrEgomBeklervEve\n"
"86ylWmZ3WWHV6RLMi8xNvjd71r4EPIGgY7BZU/VPBkq+uA7Gb6mbJnFgV43uh3xy\n"
"LRFgxIAphIukwTGSMZZR+AI+Qnp0BYTWovHXozOf3H8r6hozEoT02JHn0AeTfA==\n"
"-----END CERTIFICATE-----\n";

// RAII wrapper owning every mbedTLS context a single request needs. One
// connection per request (paste.rs's operations are infrequent -- license
// issuance/revocation, or a launch-time witness fetch -- so there is no
// value in connection pooling here, only complexity).
struct TlsConnection {
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    TlsConnection() {
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
    }
    ~TlsConnection() {
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_net_free(&server_fd);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
};

// Strip trailing whitespace/newlines -- same behavior as the old WinHTTP
// implementation's TrimRight, kept so Paste_Test's exact-match checks and
// Dev_Keygen's paste-ID extraction see byte-identical results.
void TrimRight(std::string& s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
}

bool Connect(TlsConnection& c) {
    if (mbedtls_ctr_drbg_seed(&c.ctr_drbg, mbedtls_entropy_func, &c.entropy, nullptr, 0) != 0) {
        return false;
    }
    if (mbedtls_x509_crt_parse(&c.cacert,
                               reinterpret_cast<const unsigned char*>(kPastersCaPem),
                               sizeof(kPastersCaPem)) != 0) {
        return false;
    }
    if (mbedtls_net_connect(&c.server_fd, kHost, kPort, MBEDTLS_NET_PROTO_TCP) != 0) {
        return false;
    }
    if (mbedtls_ssl_config_defaults(&c.conf, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return false;
    }
    // VERIFY_REQUIRED against ONLY our pinned CA -- mbedTLS's normal chain
    // validation (signature, validity window, hostname) still runs in full;
    // the only difference from a default setup is which single CA it's
    // allowed to trust.
    mbedtls_ssl_conf_authmode(&c.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&c.conf, &c.cacert, nullptr);
    mbedtls_ssl_conf_rng(&c.conf, mbedtls_ctr_drbg_random, &c.ctr_drbg);

    if (mbedtls_ssl_setup(&c.ssl, &c.conf) != 0) return false;
    if (mbedtls_ssl_set_hostname(&c.ssl, kHost) != 0) return false;
    mbedtls_ssl_set_bio(&c.ssl, &c.server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&c.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return false;
        }
    }
    // Belt-and-suspenders: VERIFY_REQUIRED already fails the handshake on a
    // bad chain, but checking the result explicitly documents the intent and
    // guards against a future config change silently downgrading authmode.
    return mbedtls_ssl_get_verify_result(&c.ssl) == 0;
}

bool WriteAll(TlsConnection& c, const std::string& data) {
    size_t written = 0;
    while (written < data.size()) {
        int ret = mbedtls_ssl_write(&c.ssl,
                                     reinterpret_cast<const unsigned char*>(data.data()) + written,
                                     data.size() - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret <= 0) return false;
        written += static_cast<size_t>(ret);
    }
    return true;
}

// Reads until the peer closes the connection (paste.rs's responses are small
// and the request always sends "Connection: close", so read-until-EOF is
// correct and simpler than parsing Content-Length/chunked framing).
std::optional<std::string> ReadUntilClose(TlsConnection& c) {
    std::string raw;
    unsigned char buf[4096];
    for (;;) {
        int ret = mbedtls_ssl_read(&c.ssl, buf, sizeof(buf));
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) break;
        if (ret < 0) break;  // peer closed the TCP connection without close_notify
        raw.append(reinterpret_cast<char*>(buf), static_cast<size_t>(ret));
    }
    if (raw.empty()) return std::nullopt;
    return raw;
}

struct HttpResponse {
    int status = 0;
    std::string body;
};

std::optional<HttpResponse> ParseHttpResponse(const std::string& raw) {
    size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) return std::nullopt;

    size_t status_line_end = raw.find("\r\n");
    if (status_line_end == std::string::npos) return std::nullopt;
    std::string status_line = raw.substr(0, status_line_end);

    size_t sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) return std::nullopt;

    HttpResponse resp;
    resp.status = std::atoi(status_line.c_str() + sp1 + 1);
    resp.body = raw.substr(header_end + 4);
    return resp;
}

std::optional<HttpResponse> DoRequest(const std::string& method, const std::string& path,
                                       const std::string& body) {
    TlsConnection c;
    if (!Connect(c)) return std::nullopt;

    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n"
        << "Host: " << kHost << "\r\n"
        << "User-Agent: quark-online/1.0\r\n"
        << "Connection: close\r\n";
    if (!body.empty()) {
        req << "Content-Type: text/plain; charset=utf-8\r\n"
            << "Content-Length: " << body.size() << "\r\n";
    }
    req << "\r\n" << body;

    if (!WriteAll(c, req.str())) return std::nullopt;

    auto raw = ReadUntilClose(c);
    if (!raw) return std::nullopt;
    return ParseHttpResponse(*raw);
}

}  // namespace

std::optional<std::string> PostPaste(const std::vector<uint8_t>& sealed_blob) {
    static const char kHexChars[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(sealed_blob.size() * 2);
    for (uint8_t b : sealed_blob) {
        hex.push_back(kHexChars[b >> 4]);
        hex.push_back(kHexChars[b & 0x0F]);
    }

    auto resp = DoRequest("POST", "/", hex);
    if (!resp || (resp->status != 201 && resp->status != 200)) return std::nullopt;

    std::string body = resp->body;
    TrimRight(body);
    if (body.empty()) return std::nullopt;

    // paste.rs responds with the full URL, e.g. "https://paste.rs/abc12".
    const std::string prefix = "https://paste.rs/";
    if (body.size() > prefix.size() && body.substr(0, prefix.size()) == prefix) {
        return body.substr(prefix.size());
    }
    // Fallback: treat the whole response as the ID if it looks short.
    if (body.size() <= 32) return body;
    return std::nullopt;
}

std::optional<std::string> FetchPaste(const std::string& paste_id) {
    auto resp = DoRequest("GET", "/" + paste_id, "");
    if (!resp || resp->status != 200) return std::nullopt;

    std::string body = resp->body;
    TrimRight(body);
    if (body.empty()) return std::nullopt;
    return body;
}

bool DeletePaste(const std::string& paste_id) {
    auto resp = DoRequest("DELETE", "/" + paste_id, "");
    return resp.has_value() && (resp->status == 200 || resp->status == 204);
}

}  // namespace quark::online
```

- [ ] **Step 2: Delete the old WinHTTP file and remove it from `quark_platform_win`**

Run:
```bash
git rm cpp/common/src/online.cpp
```

In `cpp/common/CMakeLists.txt`, remove `src/online.cpp` from
`quark_platform_win`'s source list and remove the now-unused `winhttp` link
(nothing else in that target ever needed it -- `hwid.cpp`/`registry.cpp`/
`ads.cpp`/`overlay.cpp` don't touch WinHTTP):

```cmake
    add_library(quark_platform_win STATIC
        src/ads.cpp
        src/hwid.cpp
        src/overlay.cpp
        src/registry.cpp
        src/platform_win/hwid_backend_win.cpp
        src/platform_win/witness_stores_win.cpp
    )

    target_include_directories(quark_platform_win PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_link_libraries(quark_platform_win PUBLIC
        quark_core
        iphlpapi
        advapi32
    )
```

Add `src/online_http.cpp` to `quark_core`'s source list (alongside
`src/online_crypto.cpp` from Task 1):

```cmake
add_library(quark_core STATIC
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

`quark_core` already links `mbedtls` (the actual TLS/SSL library target, not
just `mbedcrypto`) -- confirmed in the existing `target_link_libraries(quark_core
PUBLIC mbedtls mbedx509 mbedcrypto)` block -- so no new link dependency is
needed for `mbedtls_net_*`/`mbedtls_ssl_*`/`mbedtls_x509_crt_*`.

- [ ] **Step 3: Build it**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target quark_core`
Expected: builds successfully.

- [ ] **Step 4: Real, live-network verification**

This function set has no existing automated test binary of its own yet
(Task 3 wires up `Paste_Test`, the dedicated tool for exactly this) -- for
now, verify it manually against the real, live `paste.rs` service:

```bash
cat > /tmp/quark_online_http_manual_test.cpp << 'EOF'
#include <cstdio>
#include "quark/online.hpp"
int main() {
    std::vector<uint8_t> blob = {0xDE, 0xAD, 0xBE, 0xEF};
    auto id = quark::online::PostPaste(blob);
    if (!id) { std::fprintf(stderr, "PostPaste failed\n"); return 1; }
    std::printf("posted: %s\n", id->c_str());

    auto fetched = quark::online::FetchPaste(*id);
    if (!fetched) { std::fprintf(stderr, "FetchPaste failed\n"); return 1; }
    std::printf("fetched: %s (expect deadbeef)\n", fetched->c_str());

    bool deleted = quark::online::DeletePaste(*id);
    std::printf("deleted: %s\n", deleted ? "true" : "false");

    auto refetch = quark::online::FetchPaste(*id);
    std::printf("refetch after delete: %s\n", refetch ? "UNEXPECTED VALUE" : "nullopt (correct)");
    return 0;
}
EOF
clang++ -std=c++17 -I cpp/common/include \
  -I sandbox/build-macos/_deps/mbedtls-src/include \
  /tmp/quark_online_http_manual_test.cpp \
  sandbox/build-macos/cpp/common/libquark_core.a \
  sandbox/build-macos/_deps/mbedtls-build/library/libmbedtls.a \
  sandbox/build-macos/_deps/mbedtls-build/library/libmbedx509.a \
  sandbox/build-macos/_deps/mbedtls-build/library/libmbedcrypto.a \
  -o /tmp/quark_online_http_manual_test
/tmp/quark_online_http_manual_test
```
Expected:
```
posted: <some short id>
fetched: deadbeef (expect deadbeef)
deleted: true
refetch after delete: nullopt (correct)
```
This proves the mbedTLS-based client performs a real TLS handshake against
paste.rs (verified against the pinned CA), and a real POST/GET/DELETE cycle
-- not a mock. Task 3 wires the same functions into `Paste_Test` for a
permanent, repeatable version of this check.

- [ ] **Step 5: Commit**

```bash
git add cpp/common/src/online_http.cpp cpp/common/CMakeLists.txt
git rm cpp/common/src/online.cpp
git commit -m "Replace WinHTTP with a portable, CA-pinned mbedTLS HTTPS client for paste.rs"
```

---

### Task 3: Fix Dev_Keygen's HWID JSON parsing; un-gate Dev_Keygen and Paste_Test

**Files:**
- Modify: `cpp/dev_keygen/main.cpp`
- Modify: `CMakeLists.txt` (top-level)

Per Phase A, `HWID_Extractor` now writes the cross-platform
`{"platform": ..., "fields": [...]}` format (`quark::platform::
FingerprintToJson`) instead of the legacy flat Windows-only schema
(`quark::hwid::ToJson`). `Dev_Keygen` still reads the OLD format via
`quark::hwid::FromJson`/`CanonicalBytes` at its two HWID-consuming call
sites -- this is a real interoperability bug introduced by Phase A that this
task fixes as part of making `Dev_Keygen` itself cross-platform.

- [ ] **Step 1: Find both call sites**

Run: `grep -n "quark::hwid::" cpp/dev_keygen/main.cpp`
Expected output (line numbers may drift slightly from edits made in the same
file during this task, but both call sites look like this):
```
444:    auto hwid = quark::hwid::FromJson(*hwid_json);
450:    std::vector<uint8_t> hwid_canonical = quark::hwid::CanonicalBytes(*hwid);
554:    auto hwid = quark::hwid::FromJson(*hwid_json);
560:    std::vector<uint8_t> hwid_canonical = quark::hwid::CanonicalBytes(*hwid);
```

- [ ] **Step 2: Switch the include**

In `cpp/dev_keygen/main.cpp`, replace:
```cpp
#include "quark/hwid.hpp"
```
with:
```cpp
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/hwid_json.hpp"
```

- [ ] **Step 3: Switch both call sites**

At each of the two locations found in Step 1, replace the two-line pattern:
```cpp
    auto hwid = quark::hwid::FromJson(*hwid_json);
    if (!hwid) {
```
with:
```cpp
    auto parsed_fp = quark::platform::FingerprintFromJson(*hwid_json);
    if (!parsed_fp) {
```
(keep whatever the original `if (!hwid) { ... }` error-handling body already
was at each site -- only the condition and the variable being tested change,
the error-reporting/`return` statements inside stay exactly as they are today).

Then replace:
```cpp
    std::vector<uint8_t> hwid_canonical = quark::hwid::CanonicalBytes(*hwid);
```
with:
```cpp
    std::vector<uint8_t> hwid_canonical = quark::platform::CanonicalBytes(parsed_fp->fingerprint);
```

- [ ] **Step 4: Build it**

Run: `cmake --build sandbox/build-macos --target Dev_Keygen`
Expected: FAIL at this point with "target Dev_Keygen not found" -- it's still
inside the top-level `CMakeLists.txt`'s `if(WIN32)` block. Continue to Step 5
before re-running.

- [ ] **Step 5: Un-gate `Dev_Keygen` and `paste_test` from `WIN32`**

In the top-level `CMakeLists.txt`, replace:
```cmake
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
with:
```cmake
# Dev_Keygen and paste_test are cross-platform as of Phase B of
# docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md.
add_subdirectory(cpp/dev_keygen)
add_subdirectory(cpp/paste_test)

if(WIN32)
    add_subdirectory(cpp/drm_wrapper)
else()
    message(STATUS
        "Not configuring on Windows -- DRM_Wrapper still requires the Windows "
        "platform layer (see docs/superpowers/specs/2026-07-05-cross-platform-"
        "porting-roadmap.md Phase C for the in-progress cross-platform port).")
endif()
```

- [ ] **Step 6: Build both for real**

Run: `cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos --target Dev_Keygen Paste_Test`
Expected: both build successfully.

- [ ] **Step 7: Commit**

```bash
git add cpp/dev_keygen/main.cpp CMakeLists.txt
git commit -m "Fix Dev_Keygen's HWID JSON parsing for the Phase A format; un-gate Dev_Keygen/Paste_Test from WIN32"
```

---

### Task 4: Real end-to-end verification of both ported programs

**Files:** none (verification only)

- [ ] **Step 1: Run `Paste_Test` for real against live paste.rs**

Run (from the build directory, per the sandbox-only rule):
```bash
cd sandbox/build-macos && ./cpp/paste_test/Paste_Test && cd ../..
```
Expected: all four checks (`[1]` through `[4]`) print `[PASS]`, ending with
`Result: ALL TESTS PASSED`, exit code 0. This is the exact same real
POST/GET/DELETE cycle Task 2's manual check ran, now via the permanent,
purpose-built tool -- no changes were needed to `Paste_Test`'s own
`main.cpp` at all (confirmed during the Phase A/B audit that it was already
100% portable; only the `quark::online` implementation it calls needed to
change).

- [ ] **Step 2: Run `HWID_Extractor` and `Dev_Keygen` together for real, in dev mode**

This exercises Dev_Keygen's now-fixed HWID JSON parsing against a real,
Phase-A-produced fingerprint file, and mints a real `state.bin` -- dev mode
(`--dev`) skips the online-witness paste.rs round trip so this check doesn't
also depend on network access:

```bash
cd sandbox/build-macos
./cpp/hwid_extractor/HWID_Extractor test_hwid_for_devkeygen.json
mkdir -p test_license_output
./cpp/dev_keygen/Dev_Keygen test_hwid_for_devkeygen.json 5 test_license_output --dev --label "phase-b-smoke-test"
ls test_license_output
cd ../..
```
Expected: `Dev_Keygen` runs to completion (no `quark::hwid::FromJson` parse
failure), and `test_license_output/` contains at least `state.bin` and
`unlock_keys.txt`.

- [ ] **Step 3: Run `Dev_Keygen`'s real (non-dev) paste.rs path end to end**

This is the path that actually exercises Task 2's new HTTP client from
inside `Dev_Keygen` itself, including the `--setup` keypair-generation flow:

```bash
cd sandbox/build-macos
./cpp/dev_keygen/Dev_Keygen --setup --out /tmp/phase_b_secret.hpp --kpriv /tmp/phase_b_kpriv.bin
./cpp/dev_keygen/Dev_Keygen test_hwid_for_devkeygen.json 3 test_license_output_prod \
    --kpriv /tmp/phase_b_kpriv.bin --label "phase-b-online-smoke-test" \
    --registry /tmp/phase_b_licenses.txt
cat /tmp/phase_b_licenses.txt
./cpp/dev_keygen/Dev_Keygen --list --registry /tmp/phase_b_licenses.txt
cd ../..
```
Expected: the `--setup` step writes both output files; the license-issuance
step succeeds and prints a paste ID it actually posted to live paste.rs;
`/tmp/phase_b_licenses.txt` contains one `active` record with that paste ID;
`--list` prints it back correctly formatted.

- [ ] **Step 4: Revoke it and confirm the registry updates**

```bash
cd sandbox/build-macos
PASTE_ID=$(awk -F'|' 'NR==4{gsub(/ /,"",$1); print $1}' /tmp/phase_b_licenses.txt)
./cpp/dev_keygen/Dev_Keygen --revoke "$PASTE_ID" --registry /tmp/phase_b_licenses.txt
cat /tmp/phase_b_licenses.txt
cd ../..
```
Expected: `Dev_Keygen` prints "Revoked. Paste deleted..." and the registry
now shows that record's status as `revoked` -- this exercises `DeletePaste`
through the new HTTP client from `Dev_Keygen`'s actual `--revoke` code path
(not just Task 2's standalone manual test).

- [ ] **Step 5: Clean up the manual test artifacts**

```bash
rm -rf sandbox/build-macos/test_license_output sandbox/build-macos/test_license_output_prod
rm -f sandbox/build-macos/test_hwid_for_devkeygen.json
rm -f /tmp/phase_b_secret.hpp /tmp/phase_b_kpriv.bin /tmp/phase_b_licenses.txt
rm -f /tmp/quark_online_http_manual_test.cpp /tmp/quark_online_http_manual_test
```

- [ ] **Step 6: Run the full suite via ctest**

Run: `ctest --test-dir sandbox/build-macos --output-on-failure`
Expected: every test from Phase A plus the new `TestOnlinePayloadCrypto`
checks (inside `quark_core_tests`) report `Passed`.

---

### Task 5: Documentation

**Files:**
- Modify: `docs/PLAN.md`
- Modify: `cpp/paste_test/README.md`
- Modify: `cpp/dev_keygen/README.md`

- [ ] **Step 1: Update `cpp/paste_test/README.md`'s Compilation section**

Replace the "Compilation" section:

```markdown
## Compilation

Cross-platform -- uses `quark::online`'s portable, mbedTLS-based HTTPS
client (CA-pinned to paste.rs, see
[cpp/common/src/online_http.cpp](../common/src/online_http.cpp)) instead of
WinHTTP:
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target Paste_Test
./sandbox/build-host/cpp/paste_test/Paste_Test
```
Makes real, live HTTPS requests to `paste.rs` -- run manually, not part of
`ctest` (this repo doesn't make automated tests depend on live network
access; `Paste_Test` exists specifically to be the manually-run, real check).
```

- [ ] **Step 2: Update `cpp/dev_keygen/README.md`'s Compilation section**

Replace the "Compilation" section:

```markdown
## Compilation

Cross-platform:
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target Dev_Keygen
```
Outputs `sandbox/build-host/cpp/dev_keygen/Dev_Keygen` (or `Dev_Keygen.exe`
on Windows). Reads hardware fingerprints in the format
`HWID_Extractor` now produces on any OS (`quark::platform::
FingerprintFromJson`, tagged with the platform that collected it).
```

- [ ] **Step 3: Record Phase B in the plan**

Append to `docs/PLAN.md` (after Phase X):

```markdown
## Phase XI — Cross-platform port, Phase B: portable HTTPS client + Paste_Test/Dev_Keygen
Implements Phase B of docs/superpowers/specs/2026-07-05-cross-platform-
porting-roadmap.md.

- [x] `quark::online`'s crypto half (`BuildSignMessage`/`SealPayload`/
      `UnsealPayload`/`SignPayload`/`VerifySignature`/`GenerateKeypair`) moved
      verbatim into `quark_core` (`online_crypto.cpp`) -- it never touched
      WinHTTP, so this was a pure move, not a rewrite. Covered by new real
      (non-network) tests exercising actual PSA ECDSA sign/verify.
- [x] `quark::online`'s HTTP half (`PostPaste`/`FetchPaste`/`DeletePaste`)
      rewritten on mbedTLS's own `net`/`ssl`/`x509` modules (`online_http.cpp`,
      also `quark_core`) instead of WinHTTP -- one implementation for every
      OS and every consumer (Dev_Keygen, Paste_Test, and later DRM_Wrapper in
      Phase C). Pins paste.rs's issuing CA certificate (not a full CA bundle,
      not the leaf -- the leaf rotates every ~90 days, the issuing
      intermediate is valid through 2028-09-02).
- [x] Fixed a real interoperability bug Phase A introduced: `Dev_Keygen`
      still parsed `hwid.json` via the legacy, Windows-only
      `quark::hwid::FromJson`, which cannot read the new cross-platform
      `quark::platform::FingerprintToJson` format `HWID_Extractor` now
      writes. Both of `Dev_Keygen`'s HWID-consuming call sites switched to
      `quark::platform::FingerprintFromJson`/`CanonicalBytes`.
- [x] `Dev_Keygen` and `Paste_Test` un-gated from `if(WIN32)` -- both were
      already ~90% portable per the roadmap's audit; the HTTP client and the
      JSON-format fix were the only real blockers.
- [x] Verified for real end to end on this machine (macOS): a live
      POST/GET/DELETE cycle through `Paste_Test` against the real `paste.rs`
      service; `Dev_Keygen --dev` minting a real `state.bin` from a real
      Phase-A-produced `hwid.json`; `Dev_Keygen`'s real (non-dev) `--setup` +
      license-issuance + `--list` + `--revoke` flow, including a real
      `DeletePaste` call against live paste.rs from `Dev_Keygen`'s own
      `--revoke` code path.
- [x] Removed the now-dead `winhttp` library link from `quark_platform_win`
      (nothing else in that target used it).

### Not done yet (Phase C, tracked separately)
- `DRM_Wrapper` remains Windows-only -- it needs Phase C's integration work
  (wiring the already-written-but-unused `process_handoff`/
  `DebuggerDetected` code for macOS/Linux, and replacing its hand-rolled
  duplicate of `RunUnlockFlow`'s logic with a real call to it) on top of this
  phase's HTTP client for its online-witness fetch.
- The pinned CA certificate in `online_http.cpp` is a manually-captured,
  point-in-time value (valid through 2028-09-02) -- there is no automated
  monitoring for paste.rs rotating its issuing CA before then; the file's own
  comment documents the exact `openssl` command to re-derive it if the pin
  ever starts rejecting real connections.
- Linux was not available to test against in this session; Phase B's changes
  touch no Linux-specific code paths (the new HTTP client and the HWID JSON
  fix are both fully portable, OS-agnostic C++), but were not independently
  re-run on a Linux machine in this pass.
```

- [ ] **Step 4: Commit**

```bash
git add docs/PLAN.md cpp/paste_test/README.md cpp/dev_keygen/README.md
git commit -m "Document Phase B of the cross-platform porting roadmap"
```

---

## Self-review notes (from writing this plan)

- **Spec coverage:** The roadmap spec's Phase B scope (portable mbedTLS-based
  HTTP client, `Paste_Test`/`Dev_Keygen` ported) is fully covered by Tasks
  1-4. The spec's "Decision" section's certificate-pinning requirement is
  implemented exactly as specified (pin the issuing CA, not a bundle, with a
  documented rotation procedure in the source comment).
- **A gap the roadmap spec didn't anticipate, found and fixed during
  planning, not left as a surprise:** `Dev_Keygen` still reading `hwid.json`
  via the legacy `quark::hwid::FromJson` after Phase A changed
  `HWID_Extractor`'s output format. Verified via `grep` against the actual
  current source (not assumed) before writing Task 3.
- **Placeholder scan:** no TBD/TODO; every step has complete, runnable code,
  including the full PEM of the pinned CA certificate (captured for real via
  `openssl s_client` against the live service, not a placeholder value).
- **Type consistency:** `quark::online::PastePayload`/`EcSignature`/
  `EcPrivateKey`/`EcPublicKey`/`Keypair` (from the existing, unchanged
  `online.hpp`) and `quark::platform::Fingerprint`/`ParsedFingerprint` (from
  Phase A) are used identically across all four tasks.
- **Testing rigor:** Task 2's manual verification and Task 4's full
  `Paste_Test`/`Dev_Keygen` runs are real, live network calls against the
  actual `paste.rs` service -- not mocked, per CLAUDE.md rule 1 and the
  roadmap's testing strategy. `TestOnlinePayloadCrypto` (Task 1) is a real,
  non-network test that still exercises actual mbedTLS PSA cryptographic
  operations (key generation, ECDSA sign/verify), not stubs.
