/* Real, non-mocked end-to-end test of the Quark C ABI -- plain C, exactly
 * how a Go/Python/Java binding would call this library. Runs against THIS
 * machine's real, freshly-collected hardware fingerprint (no fake/mocked
 * HWID backend -- see CLAUDE.md rule 1) and real file/xattr witness storage.
 * All paths are relative to the test binary's working directory, which
 * CTest/CMake places under sandbox/ -- never a system temp directory (the
 * project's sandbox-only rule applies to this test the same as any other).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quark_c_api.h"

static int g_failures = 0;

static void check(int condition, const char* label) {
    if (condition) {
        printf("  [PASS] %s\n", label);
    } else {
        printf("  [FAIL] %s\n", label);
        g_failures++;
    }
}

static void hex_encode(const uint8_t* bytes, size_t len, char* out /* len*2+1 */) {
    static const char kHex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[bytes[i] >> 4];
        out[i * 2 + 1] = kHex[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int all_zero(const uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (bytes[i] != 0) return 0;
    }
    return 1;
}

int main(void) {
    const char* kStatePath = "quark_c_api_test_state.bin";
    const char* kHostPath = "quark_c_api_test_witness_host.bin";
    const char* kSecret = "quark-c-api-test-secret";

    remove(kStatePath);
    remove(kHostPath);
    FILE* host = fopen(kHostPath, "wb");
    check(host != NULL, "create witness host file");
    if (host) {
        fputs("witness host placeholder\n", host);
        fclose(host);
    }

    /* --- HWID: collect this real machine's fingerprint -------------------- */
    uint8_t hwid[4096];
    size_t hwid_len = 0;
    quark_error_t err = quark_hwid_collect(hwid, sizeof(hwid), &hwid_len);
    check(err == QUARK_OK, "quark_hwid_collect succeeds on this real machine");
    check(hwid_len > 0, "quark_hwid_collect returns non-empty canonical bytes");

    /* --- mint a 3-link chain + a state.bin bound to this machine ----------- */
    uint8_t anchor[32];
    uint8_t keys[3 * 32];
    err = quark_lamport_mint_chain(3, anchor, keys, sizeof(keys));
    check(err == QUARK_OK, "quark_lamport_mint_chain(3) succeeds");

    err = quark_state_mint(kStatePath, kSecret, hwid, hwid_len, anchor, 3);
    check(err == QUARK_OK, "quark_state_mint writes a fresh state.bin");

    /* --- three witness channels: one FILE, two XATTR on the host file ------ */
    quark_witness_channel_t witnesses[3];
    memset(witnesses, 0, sizeof(witnesses));

    witnesses[0].kind = QUARK_WITNESS_KIND_FILE;
    witnesses[0].path = "quark_c_api_test_witness_file.bin";
    memcpy(witnesses[0].magic, "QCF0", 4);
    witnesses[0].name = "file0";
    remove(witnesses[0].path);

#if defined(__APPLE__) || defined(__linux__)
    witnesses[1].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[1].path = kHostPath;
    witnesses[1].attr_name = "com.quark.test.witness1";
    memcpy(witnesses[1].magic, "QCX1", 4);
    witnesses[1].name = "xattr1";

    witnesses[2].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[2].path = kHostPath;
    witnesses[2].attr_name = "com.quark.test.witness2";
    memcpy(witnesses[2].magic, "QCX2", 4);
    witnesses[2].name = "xattr2";
#else
    witnesses[1].kind = QUARK_WITNESS_KIND_FILE;
    witnesses[1].path = "quark_c_api_test_witness_file1.bin";
    memcpy(witnesses[1].magic, "QCF1", 4);
    witnesses[1].name = "file1";
    remove(witnesses[1].path);

    witnesses[2].kind = QUARK_WITNESS_KIND_FILE;
    witnesses[2].path = "quark_c_api_test_witness_file2.bin";
    memcpy(witnesses[2].magic, "QCF2", 4);
    witnesses[2].name = "file2";
    remove(witnesses[2].path);
#endif

    /* --- dev-side: seal a protected payload for this machine ---------------- */
    const char kPayload[] = "quark-protected-payload";
    uint8_t sealed[256];
    size_t sealed_len = 0;
    err = quark_seal_payload(kSecret, hwid, hwid_len, (const uint8_t*)kPayload, sizeof(kPayload),
                              sealed, sizeof(sealed), &sealed_len);
    check(err == QUARK_OK, "quark_seal_payload succeeds");
    check(sealed_len > 0, "quark_seal_payload returns non-empty sealed bytes");

    /* --- unlock+decrypt #1: first key, first-run witness mint --------------- */
    char key_hex[65];
    hex_encode(keys + 0 * 32, 32, key_hex);

    uint8_t plaintext[256];
    size_t plaintext_len = 0;
    uint8_t content_key[32], session_id[32];
    err = quark_unlock_and_decrypt(kStatePath, kSecret, witnesses, key_hex, sealed, sealed_len,
                                    plaintext, sizeof(plaintext), &plaintext_len, content_key,
                                    session_id);
    check(err == QUARK_OK, "quark_unlock_and_decrypt #1 (first key, first run) succeeds");
    check(plaintext_len == sizeof(kPayload) && memcmp(plaintext, kPayload, sizeof(kPayload)) == 0,
          "quark_unlock_and_decrypt #1 recovers the exact sealed payload");
    check(!all_zero(content_key, 32), "quark_unlock_and_decrypt #1 content_key is non-zero");
    check(!all_zero(session_id, 32), "quark_unlock_and_decrypt #1 session_id is non-zero");

    /* --- unlock+decrypt #2: second key, all three witnesses must already agree */
    hex_encode(keys + 1 * 32, 32, key_hex);
    err = quark_unlock_and_decrypt(kStatePath, kSecret, witnesses, key_hex, sealed, sealed_len,
                                    plaintext, sizeof(plaintext), &plaintext_len, content_key,
                                    session_id);
    check(err == QUARK_OK, "quark_unlock_and_decrypt #2 (second key, witnesses agree) succeeds");
    check(plaintext_len == sizeof(kPayload) && memcmp(plaintext, kPayload, sizeof(kPayload)) == 0,
          "quark_unlock_and_decrypt #2 recovers the exact sealed payload again (core_enc_key is "
          "stable across unlocks on the same license -- see quark/token.hpp)");

    /* --- unlock+decrypt #3: replaying the already-spent first key must fail - */
    hex_encode(keys + 0 * 32, 32, key_hex);
    err = quark_unlock_and_decrypt(kStatePath, kSecret, witnesses, key_hex, sealed, sealed_len,
                                    plaintext, sizeof(plaintext), &plaintext_len, content_key,
                                    session_id);
    check(err == QUARK_ERR_UNLOCK_KEY_INVALID,
          "quark_unlock_and_decrypt #3 rejects a replayed, already-spent key");

    /* --- error describer never returns NULL --------------------------------- */
    check(quark_error_describe(QUARK_OK) != NULL, "quark_error_describe(QUARK_OK) is non-null");
    check(quark_error_describe(QUARK_ERR_UNLOCK_KEY_INVALID) != NULL,
          "quark_error_describe(QUARK_ERR_UNLOCK_KEY_INVALID) is non-null");
    check(quark_error_describe(999999) != NULL, "quark_error_describe(unrecognized) is non-null");

    remove(kStatePath);
    remove(kHostPath);
    remove(witnesses[0].path);
#if !(defined(__APPLE__) || defined(__linux__))
    remove(witnesses[1].path);
    remove(witnesses[2].path);
#endif

    printf("\n%d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
