/* Real, non-mocked concurrency test for the C ABI's IProcessLock protection.
 * Real concurrent-launch testing of DRM_Wrapper found that without locking,
 * multiple callers racing on the same license could all redeem the same
 * single-use key (see CLAUDE.md rule 6's IProcessLock paragraph and
 * docs/PLAN.md's Phase XIII). quark_unlock_and_decrypt() now acquires a real
 * OS file lock internally; this test proves it from the C ABI side by
 * calling it from several real POSIX threads at once against one license.
 *
 * POSIX-only (pthreads) -- Windows re-verification of LockFileProcessLock is
 * a separate, tracked gap (no Windows machine available in this pass).
 */
#include <pthread.h>
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

#define kRacers 8

struct RacerArgs {
    const char* state_path;
    const char* secret;
    const quark_witness_channel_t* witnesses;
    const char* key_hex;
    const uint8_t* sealed;
    size_t sealed_len;
    quark_error_t result;
};

static void* RacerThread(void* arg) {
    struct RacerArgs* a = (struct RacerArgs*)arg;
    uint8_t plaintext[256];
    size_t plaintext_len = 0;
    a->result = quark_unlock_and_decrypt(a->state_path, a->secret, a->witnesses, a->key_hex,
                                          a->sealed, a->sealed_len, plaintext, sizeof(plaintext),
                                          &plaintext_len, NULL, NULL);
    return NULL;
}

int main(void) {
    const char* kStatePath = "quark_c_api_lock_test_state.bin";
    const char* kHostPath = "quark_c_api_lock_test_witness_host.bin";
    const char* kSecret = "quark-c-api-lock-test-secret";

    remove(kStatePath);
    remove(kHostPath);
    FILE* host = fopen(kHostPath, "wb");
    check(host != NULL, "create witness host file");
    if (host) {
        fputs("witness host placeholder\n", host);
        fclose(host);
    }

    uint8_t hwid[4096];
    size_t hwid_len = 0;
    quark_error_t err = quark_hwid_collect(hwid, sizeof(hwid), &hwid_len);
    check(err == QUARK_OK, "quark_hwid_collect succeeds on this real machine");

    /* A 1-link chain: exactly one valid key exists, so "more than one
     * success" can only mean the lock failed to exclude a racer. */
    uint8_t anchor[32];
    uint8_t key[32];
    err = quark_lamport_mint_chain(1, anchor, key, sizeof(key));
    check(err == QUARK_OK, "quark_lamport_mint_chain(1) succeeds");

    err = quark_state_mint(kStatePath, kSecret, hwid, hwid_len, anchor, 1);
    check(err == QUARK_OK, "quark_state_mint writes a fresh single-use state.bin");

    quark_witness_channel_t witnesses[3];
    memset(witnesses, 0, sizeof(witnesses));

    witnesses[0].kind = QUARK_WITNESS_KIND_FILE;
    witnesses[0].path = "quark_c_api_lock_test_witness_file.bin";
    memcpy(witnesses[0].magic, "QLF0", 4);
    witnesses[0].name = "file0";
    remove(witnesses[0].path);

    witnesses[1].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[1].path = kHostPath;
    witnesses[1].attr_name = "com.quark.locktest.witness1";
    memcpy(witnesses[1].magic, "QLX1", 4);
    witnesses[1].name = "xattr1";

    witnesses[2].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[2].path = kHostPath;
    witnesses[2].attr_name = "com.quark.locktest.witness2";
    memcpy(witnesses[2].magic, "QLX2", 4);
    witnesses[2].name = "xattr2";

    const char kPayload[] = "quark-lock-test-payload";
    uint8_t sealed[256];
    size_t sealed_len = 0;
    err = quark_seal_payload(kSecret, hwid, hwid_len, (const uint8_t*)kPayload, sizeof(kPayload),
                              sealed, sizeof(sealed), &sealed_len);
    check(err == QUARK_OK, "quark_seal_payload succeeds");

    char key_hex[65];
    hex_encode(key, 32, key_hex);

    /* --- fire kRacers real threads at the SAME key, SAME license, at once - */
    pthread_t threads[kRacers];
    struct RacerArgs args[kRacers];
    for (int i = 0; i < kRacers; ++i) {
        args[i].state_path = kStatePath;
        args[i].secret = kSecret;
        args[i].witnesses = witnesses;
        args[i].key_hex = key_hex;
        args[i].sealed = sealed;
        args[i].sealed_len = sealed_len;
        args[i].result = QUARK_ERR_INVALID_ARGUMENT; /* sentinel, overwritten by the thread */
    }
    for (int i = 0; i < kRacers; ++i) {
        int rc = pthread_create(&threads[i], NULL, RacerThread, &args[i]);
        check(rc == 0, "pthread_create succeeds");
    }
    for (int i = 0; i < kRacers; ++i) {
        pthread_join(threads[i], NULL);
    }

    int success_count = 0;
    for (int i = 0; i < kRacers; ++i) {
        if (args[i].result == QUARK_OK) success_count++;
    }
    check(success_count == 1,
          "exactly one of 8 concurrent quark_unlock_and_decrypt calls redeems the single-use key");

    remove(kStatePath);
    remove("quark_c_api_lock_test_state.bin.lock"); /* FlockProcessLock's sibling lock file */
    remove(kHostPath);
    remove(witnesses[0].path);

    printf("\n%d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
