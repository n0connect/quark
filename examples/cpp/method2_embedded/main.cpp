// Method 2 ("protect a program at the source level"), C++.
//
// Links libquark_c (cpp/quark_c_api) directly. This program's own source
// calls quark_unlock_and_decrypt() itself -- no external wrapper process, no
// pipe protocol. Protection lives in the program, not around it.
#include <cstdio>
#include <cstring>
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
    if (argc != 9) {
        std::fprintf(stderr,
                      "usage: %s <state_path> <build_secret> <unlock_key_hex> <sealed_payload_path> "
                      "<witness_host_path> <witness_file_path> <xattr1_attr> <xattr2_attr>\n",
                      argv[0]);
        return 2;
    }
    const std::string state_path   = argv[1];
    const std::string build_secret = argv[2];
    const std::string unlock_key   = argv[3];
    const std::string sealed_path  = argv[4];
    const std::string witness_host = argv[5];
    const std::string witness_file = argv[6];
    const std::string attr1        = argv[7];
    const std::string attr2        = argv[8];

    std::vector<uint8_t> sealed = ReadFile(sealed_path);
    if (sealed.empty()) {
        std::fprintf(stderr, "cannot read sealed payload: %s\n", sealed_path.c_str());
        return 1;
    }

    quark_witness_channel_t witnesses[3];
    std::memset(witnesses, 0, sizeof(witnesses));

    witnesses[0].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[0].path = witness_host.c_str();
    witnesses[0].attr_name = attr1.c_str();
    std::memcpy(witnesses[0].magic, "QWX1", 4);
    witnesses[0].name = "xattr1";

    witnesses[1].kind = QUARK_WITNESS_KIND_XATTR;
    witnesses[1].path = witness_host.c_str();
    witnesses[1].attr_name = attr2.c_str();
    std::memcpy(witnesses[1].magic, "QWX2", 4);
    witnesses[1].name = "xattr2";

    witnesses[2].kind = QUARK_WITNESS_KIND_FILE;
    witnesses[2].path = witness_file.c_str();
    std::memcpy(witnesses[2].magic, "QWF0", 4);
    witnesses[2].name = "file";

    uint8_t plaintext[4096];
    size_t plaintext_len = 0;

    quark_error_t rc = quark_unlock_and_decrypt(
        state_path.c_str(), build_secret.c_str(), witnesses, unlock_key.c_str(),
        sealed.data(), sealed.size(),
        plaintext, sizeof(plaintext), &plaintext_len,
        nullptr, nullptr);

    if (rc != QUARK_OK) {
        std::fprintf(stderr, "quark_unlock_and_decrypt failed: %d (%s)\n", rc, quark_error_describe(rc));
        return 1;
    }

    std::fwrite(plaintext, 1, plaintext_len, stdout);
    return 0;
}
