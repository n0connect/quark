/*
 * Method 2 ("protect a program at the source level"), C.
 *
 * Links libquark_c (cpp/quark_c_api) directly. This program's own source
 * calls quark_unlock_and_decrypt() itself -- no external wrapper process, no
 * pipe protocol. The protection is embedded in the program: it will only
 * ever see correct plaintext if HWID + state.bin + the three witnesses + the
 * supplied key all check out simultaneously.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quark_c_api.h"

static unsigned char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc((size_t)size);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *len_out = (size_t)size;
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 9) {
        fprintf(stderr,
                "usage: %s <state_path> <build_secret> <unlock_key_hex> <sealed_payload_path> "
                "<witness_host_path> <witness_file_path> <xattr1_attr> <xattr2_attr>\n",
                argv[0]);
        return 2;
    }
    const char *state_path   = argv[1];
    const char *build_secret = argv[2];
    const char *unlock_key   = argv[3];
    const char *sealed_path  = argv[4];
    const char *witness_host = argv[5];
    const char *witness_file = argv[6];
    const char *attr1        = argv[7];
    const char *attr2        = argv[8];

    size_t sealed_len = 0;
    unsigned char *sealed = read_file(sealed_path, &sealed_len);
    if (!sealed) {
        fprintf(stderr, "cannot read sealed payload: %s\n", sealed_path);
        return 1;
    }

    quark_witness_channel_t witnesses[3];
    memset(witnesses, 0, sizeof(witnesses));

    witnesses[0].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[0].path = witness_host;
    witnesses[0].attr_name = attr1;
    memcpy(witnesses[0].magic, "QWX1", 4);
    witnesses[0].name = "xattr1";

    witnesses[1].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[1].path = witness_host;
    witnesses[1].attr_name = attr2;
    memcpy(witnesses[1].magic, "QWX2", 4);
    witnesses[1].name = "xattr2";

    witnesses[2].kind = QUARK_WITNESS_KIND_FILE;
    witnesses[2].path = witness_file;
    memcpy(witnesses[2].magic, "QWF0", 4);
    witnesses[2].name = "file";

    unsigned char plaintext[4096];
    size_t plaintext_len = 0;

    quark_error_t rc = quark_unlock_and_decrypt(
        state_path, build_secret, witnesses, unlock_key,
        sealed, sealed_len,
        plaintext, sizeof(plaintext), &plaintext_len,
        NULL, NULL);

    free(sealed);

    if (rc != QUARK_OK) {
        fprintf(stderr, "quark_unlock_and_decrypt failed: %d (%s)\n", rc, quark_error_describe(rc));
        return 1;
    }

    fwrite(plaintext, 1, plaintext_len, stdout);
    return 0;
}
