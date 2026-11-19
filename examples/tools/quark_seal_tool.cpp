// Tiny dev-side helper for the method-2 (source-embedded) examples: seals a
// plaintext file into the exact wire format quark_unlock_and_decrypt()
// expects (quark::payload's "QPLD" framing), using THIS machine's own real,
// freshly-collected HWID -- consistent with every method-2 demo running its
// unlock against the same machine that issued the license, which is the
// realistic case for local testing.
//
// This is deliberately NOT the same as Dev_Keygen --input-bundle's core.enc:
// core.enc uses a different on-disk framing ("QENC", tag placed after the
// ciphertext) meant for java/drm-core's CoreDecryptor, even though both
// share the same core_enc_key derivation. quark_seal_payload/
// quark_unlock_and_decrypt use quark::payload's "QPLD" framing (tag placed
// right after the IV, explicit ciphertext-length prefix) -- the two are not
// interchangeable, only their key derivation is shared. This tool exists so
// the method-2 examples exercise the real, public quark_c_api surface
// (quark_hwid_collect + quark_seal_payload) exactly as any other FFI
// consumer would, rather than reusing Dev_Keygen's Java-pipeline-specific
// format by mistake.
//
// Links libquark_c only -- no quark_core internals touched directly, same
// boundary every example in examples/*/method2_embedded uses.
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "quark_c_api.h"

namespace {
std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}
}  // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: %s <build_secret> <plaintext_file> <sealed_out_file>\n", argv[0]);
        return 2;
    }
    const std::string build_secret = argv[1];
    const std::string plaintext_path = argv[2];
    const std::string sealed_out_path = argv[3];

    std::vector<uint8_t> plaintext = ReadFile(plaintext_path);
    if (plaintext.empty()) {
        std::fprintf(stderr, "cannot read plaintext file: %s\n", plaintext_path.c_str());
        return 1;
    }

    uint8_t hwid_canonical[4096];
    size_t hwid_len = 0;
    quark_error_t rc = quark_hwid_collect(hwid_canonical, sizeof(hwid_canonical), &hwid_len);
    if (rc != QUARK_OK) {
        std::fprintf(stderr, "quark_hwid_collect failed: %d (%s)\n", rc, quark_error_describe(rc));
        return 1;
    }

    uint8_t sealed[8192];
    size_t sealed_len = 0;
    rc = quark_seal_payload(build_secret.c_str(), hwid_canonical, hwid_len,
                             plaintext.data(), plaintext.size(),
                             sealed, sizeof(sealed), &sealed_len);
    if (rc != QUARK_OK) {
        std::fprintf(stderr, "quark_seal_payload failed: %d (%s)\n", rc, quark_error_describe(rc));
        return 1;
    }

    std::ofstream out(sealed_out_path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(sealed), static_cast<std::streamsize>(sealed_len));
    if (!out) {
        std::fprintf(stderr, "cannot write sealed output: %s\n", sealed_out_path.c_str());
        return 1;
    }

    return 0;
}
