// Dev_Keygen.exe
//
// Developer-side tool. Subcommands:
//
//   --setup [--out secret.hpp] [--kpriv kpriv.bin]
//       One-time: generate BUILD SECRET + P-256 keypair. Writes kpriv.bin and
//       prints (optionally writes) the secret.hpp snippet for DRM_Wrapper.
//
//   <hwid.json> <chain_length> <out_dir> --kpriv <kpriv.bin>
//               [--label <name>] [--registry <licenses.txt>]
//               [--input-bundle <app.bundle>]
//       Issue a license: build Lamport chain, seal state.bin, write
//       unlock_keys.txt, generate+sign+seal the online-witness paste, POST
//       to paste.rs, store the paste ID in state.bin, and append one record
//       to licenses.txt.  If --input-bundle is given, also encrypts the bundle
//       as core.enc using the stable core_enc_key.
//
//   <hwid.json> <chain_length> <out_dir> --dev
//               [--label <name>] [--input-bundle <app.bundle>]
//       DEV/TEST mode: same as above but skips paste.rs entirely.
//       online_secret is fixed to 32 zero bytes.
//       Does NOT require --kpriv.  Output files work with DRM_Wrapper only
//       when DRM_Wrapper is also built in dev mode (no paste fetch step).
//       *** NEVER USE IN PRODUCTION -- core_enc_key is deterministic ***
//
//   --burn <hwid.json> <out_dir>
//       Create a revocation state.bin: remaining_links=0, original_chain_length=1.
//       Ship to the customer machine (replacing their existing state.bin) to
//       deny all further launches.  Triggers kWrapperWitnessMissingAfterUse
//       on a clean machine, kWrapperWitnessMismatch on one with existing witnesses.
//       Both outcomes deny launch -- that is the intent.
//
//   --list [--registry <licenses.txt>]
//       Print all records in licenses.txt.
//
//   --revoke <paste_id> [--registry <licenses.txt>]
//       Delete the paste.rs online-witness blob (HTTP DELETE) and mark the
//       record "revoked" in licenses.txt.  This invalidates the online-witness
//       check in DRM_Wrapper on next launch.
//
// licenses.txt format (pipe-separated, human-readable):
//   # comment lines start with #
//   paste_id | label | chain_length | issued_utc | status
//   (status: "active" or "revoked")

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/error.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/hwid_json.hpp"
#include "quark/lamport.hpp"
#include "quark/online.hpp"
#include "quark/state.hpp"
#include "quark/token.hpp"

#include "../drm_wrapper/secret.hpp"

namespace {

constexpr const char* kComponent        = "Dev_Keygen";
constexpr const char* kDefaultRegistry  = "licenses.txt";

// ---------------------------------------------------------------------------
// License registry record
// ---------------------------------------------------------------------------
struct LicenseRecord {
    std::string paste_id;   // paste.rs ID (e.g. "abc12") -- used for revocation
    std::string label;
    uint32_t    chain_length = 0;
    std::string issued_utc;
    std::string status;  // "active" | "revoked"
};

// Trim leading/trailing whitespace
static std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Split a string by delimiter (returns trimmed fields)
static std::vector<std::string> Split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim)) {
        parts.push_back(Trim(token));
    }
    return parts;
}

// Parse all records from licenses.txt (skips comment/blank lines)
static std::vector<LicenseRecord> LoadRegistry(const std::string& path) {
    std::vector<LicenseRecord> records;
    std::ifstream in(path);
    if (!in) return records;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto f = Split(line, '|');
        if (f.size() < 5) continue;
        LicenseRecord r;
        r.paste_id     = f[0];
        r.label        = f[1];
        r.chain_length = static_cast<uint32_t>(std::strtoul(f[2].c_str(), nullptr, 10));
        r.issued_utc   = f[3];
        r.status       = f[4];
        records.push_back(std::move(r));
    }
    return records;
}

// Write all records back to licenses.txt (preserves header comment)
static bool SaveRegistry(const std::string& path,
                          const std::vector<LicenseRecord>& records) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    out << "# Quark License Registry\n"
        << "# *** KEEP SECRET -- contains paste IDs; do not commit to source control ***\n"
        << "# paste_id         | label       | chain | issued_utc          | status\n";
    for (const auto& r : records) {
        out << r.paste_id << " | "
            << r.label << " | "
            << r.chain_length << " | "
            << r.issued_utc << " | "
            << r.status << "\n";
    }
    return static_cast<bool>(out);
}

// Append one record to licenses.txt (creates the file with header if absent)
static bool AppendRecord(const std::string& path, const LicenseRecord& rec) {
    // Load existing, append, save (keeps the file sorted by insertion order)
    auto records = LoadRegistry(path);
    records.push_back(rec);
    return SaveRegistry(path, records);
}

// Get current UTC time as ISO-8601 string
static std::string UtcNow() {
    std::time_t now = std::time(nullptr);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------
std::optional<std::string> ReadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool WriteFile(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << content;
    return static_cast<bool>(out);
}

bool WriteBinary(const std::string& path, const uint8_t* data, size_t len) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return static_cast<bool>(out);
}

std::optional<quark::online::EcPrivateKey> LoadKpriv(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    quark::online::EcPrivateKey key{};
    in.read(reinterpret_cast<char*>(key.data()), static_cast<std::streamsize>(key.size()));
    if (!in || in.gcount() != static_cast<std::streamsize>(key.size())) return std::nullopt;
    return key;
}

std::string ToCppInitializerList(const uint8_t* data, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        char buf[6];
        std::snprintf(buf, sizeof(buf), "0x%02X", data[i]);
        out += buf;
        if (i + 1 < len) out += ", ";
    }
    return out;
}

std::string ToHex(const uint8_t* data, size_t len) {
    static const char kH[] = "0123456789abcdef";
    std::string out(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = kH[data[i] >> 4];
        out[i * 2 + 1] = kH[data[i] & 0x0F];
    }
    return out;
}

// ---------------------------------------------------------------------------
// --setup
// ---------------------------------------------------------------------------
void PrintUsageSetup(const char* argv0) {
    std::fprintf(stderr,
                 "Usage: %s --setup [--out <secret.hpp>] [--kpriv <kpriv.bin>]\n",
                 argv0);
}

int RunSetup(int argc, char** argv) {
    std::string out_hpp;
    std::string kpriv_path = "kpriv.bin";

    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_hpp = argv[++i];
        } else if (std::strcmp(argv[i], "--kpriv") == 0 && i + 1 < argc) {
            kpriv_path = argv[++i];
        } else {
            PrintUsageSetup(argv[0]);
            return 2;
        }
    }

    auto secret_bytes = quark::crypto::RandomBytes(32);
    quark::crypto::ScopedZero<std::vector<uint8_t>> zero_secret(secret_bytes);
    const std::string build_secret = ToHex(secret_bytes.data(), secret_bytes.size());

    auto kp = quark::online::GenerateKeypair();
    if (!kp) {
        std::fprintf(stderr, "ERROR: P-256 key generation failed.\n");
        return 1;
    }

    if (!WriteBinary(kpriv_path, kp->priv.data(), kp->priv.size())) {
        std::fprintf(stderr, "ERROR: could not write %s\n", kpriv_path.c_str());
        quark::crypto::SecureZero(kp->priv.data(), kp->priv.size());
        return 1;
    }

    std::ostringstream snip;
    snip << "#pragma once\n"
         << "// Generated by Dev_Keygen --setup. DO NOT COMMIT.\n"
         << "#include \"quark/online.hpp\"\n\n"
         << "namespace quark::drm_wrapper {\n\n"
         << "inline constexpr const char* kBuildSecret =\n"
         << "    \"" << build_secret << "\";\n\n"
         << "inline constexpr quark::online::EcPublicKey kEcPublicKey = {{\n"
         << "    " << ToCppInitializerList(kp->pub.data(), kp->pub.size()) << "\n"
         << "}};\n\n"
         << "}  // namespace quark::drm_wrapper\n";

    const std::string snippet = snip.str();
    quark::crypto::SecureZero(kp->priv.data(), kp->priv.size());

    std::printf("%s", snippet.c_str());

    if (!out_hpp.empty()) {
        if (!WriteFile(out_hpp, snippet)) {
            std::fprintf(stderr, "ERROR: could not write %s\n", out_hpp.c_str());
            return 1;
        }
        std::fprintf(stderr, "Wrote %s and %s.\n", out_hpp.c_str(), kpriv_path.c_str());
    } else {
        std::fprintf(stderr, "Wrote %s. Paste the snippet above into cpp/drm_wrapper/secret.hpp.\n",
                     kpriv_path.c_str());
    }
    std::fprintf(stderr, "KEEP %s SECRET -- never leave the developer machine.\n",
                 kpriv_path.c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// --list
// ---------------------------------------------------------------------------
int RunList(int argc, char** argv) {
    std::string registry_path = kDefaultRegistry;
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--registry") == 0 && i + 1 < argc) {
            registry_path = argv[++i];
        }
    }

    auto records = LoadRegistry(registry_path);
    if (records.empty()) {
        std::printf("No license records in %s\n", registry_path.c_str());
        return 0;
    }

    std::printf("%-18s %-10s %-12s %-20s %s\n",
                "paste_id", "chain", "status", "issued", "label");
    std::printf("%-18s %-10s %-12s %-20s %s\n",
                "------------------", "----------", "------------",
                "--------------------", "-----");
    for (const auto& r : records) {
        std::printf("%-18s %-10u %-12s %-20s %s\n",
                    r.paste_id.c_str(), r.chain_length,
                    r.status.c_str(), r.issued_utc.c_str(),
                    r.label.c_str());
    }
    return 0;
}

// ---------------------------------------------------------------------------
// --revoke
// ---------------------------------------------------------------------------
void PrintUsageRevoke(const char* argv0) {
    std::fprintf(stderr,
                 "Usage: %s --revoke <paste_id> [--registry <licenses.txt>]\n",
                 argv0);
}

int RunRevoke(int argc, char** argv) {
    if (argc < 3) {
        PrintUsageRevoke(argv[0]);
        return 2;
    }
    const std::string id_to_revoke = argv[2];
    std::string registry_path = kDefaultRegistry;

    for (int i = 3; i < argc; ++i) {
        if (std::strcmp(argv[i], "--registry") == 0 && i + 1 < argc) {
            registry_path = argv[++i];
        } else {
            PrintUsageRevoke(argv[0]);
            return 2;
        }
    }

    auto records = LoadRegistry(registry_path);
    LicenseRecord* target = nullptr;
    for (auto& r : records) {
        if (r.paste_id == id_to_revoke) {
            target = &r;
            break;
        }
    }

    if (!target) {
        std::fprintf(stderr, "ERROR: paste_id '%s' not found in %s\n",
                     id_to_revoke.c_str(), registry_path.c_str());
        return 1;
    }

    if (target->status == "revoked") {
        std::printf("License %s is already revoked.\n", id_to_revoke.c_str());
        return 0;
    }

    std::printf("Revoking %s (label: %s) ...\n",
                id_to_revoke.c_str(), target->label.c_str());

    if (!quark::online::DeletePaste(target->paste_id)) {
        std::fprintf(stderr, "ERROR: DeletePaste failed -- network issue or paste already gone?\n");
        std::fprintf(stderr, "       Record NOT marked revoked in registry.\n");
        return 1;
    }

    target->status = "revoked";
    if (!SaveRegistry(registry_path, records)) {
        std::fprintf(stderr, "WARNING: paste deleted on paste.rs but could not update %s\n",
                     registry_path.c_str());
        return 1;
    }

    std::printf("Revoked. Paste deleted; next DRM_Wrapper launch will hit kWrapperOnlineFetchFailed.\n");
    return 0;
}

// ---------------------------------------------------------------------------
// QENC encryption helper (mirrors CoreDecryptor.java QENC format)
// ---------------------------------------------------------------------------
static bool WriteQenc(const std::string& out_path,
                      const quark::crypto::AesKey& key,
                      const std::vector<uint8_t>& plaintext) {
    // No AAD: core.enc is already HWID-bound via core_enc_key derivation.
    // NB: Aes256GcmEncrypt's signature is (key, aad, plaintext) -- aad comes
    // BEFORE plaintext. Passing them in the wrong order silently encrypts an
    // empty plaintext and binds the bundle as AAD (both args are
    // std::vector<uint8_t>, so the compiler cannot catch the swap).
    std::vector<uint8_t> aad;
    quark::crypto::GcmCiphertext ct = quark::crypto::Aes256GcmEncrypt(key, aad, plaintext);

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) return false;

    // magic "QENC" + version 1 LE u32
    out.write("QENC", 4);
    const uint8_t ver[4] = {1, 0, 0, 0};
    out.write(reinterpret_cast<const char*>(ver), 4);

    // IV (12 bytes)
    out.write(reinterpret_cast<const char*>(ct.iv.data()),
              static_cast<std::streamsize>(ct.iv.size()));

    // ciphertext then tag (CoreDecryptor expects them concatenated)
    out.write(reinterpret_cast<const char*>(ct.ciphertext.data()),
              static_cast<std::streamsize>(ct.ciphertext.size()));
    out.write(reinterpret_cast<const char*>(ct.tag.data()),
              static_cast<std::streamsize>(ct.tag.size()));

    return static_cast<bool>(out);
}

// ---------------------------------------------------------------------------
// --burn  (create revocation state.bin with remaining_links=0)
// ---------------------------------------------------------------------------
void PrintUsageBurn(const char* argv0) {
    std::fprintf(stderr,
                 "Usage: %s --burn <hwid.json> <out_dir>\n",
                 argv0);
}

int RunBurn(int argc, char** argv) {
    if (argc < 4) {
        PrintUsageBurn(argv[0]);
        return 2;
    }
    const std::string hwid_path = argv[2];
    const std::string out_dir   = argv[3];

    auto hwid_json = ReadFile(hwid_path);
    if (!hwid_json) {
        quark::error::Report(quark::error::Code::kKeygenInputReadFailed, kComponent, hwid_path.c_str());
        return 1;
    }
    auto parsed_fp = quark::platform::FingerprintFromJson(*hwid_json);
    if (!parsed_fp) {
        quark::error::Report(quark::error::Code::kKeygenInputInvalid, kComponent, hwid_path.c_str());
        return 1;
    }

    std::vector<uint8_t> hwid_canonical = quark::platform::CanonicalBytes(parsed_fp->fingerprint);
    quark::crypto::Sha256Digest hwid_digest = quark::crypto::Sha256(hwid_canonical);

    quark::crypto::AesKey state_key =
        quark::token::DeriveStateKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);
    quark::crypto::ScopedZero<quark::crypto::AesKey> zero_state_key(state_key);

    // Burned anchor: SHA256("QUARK-BURN-SENTINEL") -- distinguishable dummy.
    quark::state::LicenseState burned;
    burned.anchor = quark::crypto::Sha256(
        reinterpret_cast<const uint8_t*>("QUARK-BURN-SENTINEL"), 19);
    burned.remaining_links       = 0;
    burned.hwid_digest           = hwid_digest;
    burned.original_chain_length = 1;  // >0 so absent witnesses are not treated as first run
    burned.paste_id              = "";

    const std::string state_path = out_dir + "/state.bin";
    if (!quark::state::Save(state_path, state_key, hwid_canonical, burned)) {
        quark::error::Report(quark::error::Code::kKeygenStateWriteFailed, kComponent, state_path.c_str());
        return 1;
    }

    std::printf("[BURN] Revocation state.bin written to %s\n", state_path.c_str());
    std::printf("       remaining_links=0, original_chain_length=1\n");
    std::printf("       Replace the customer's state.bin with this file.\n");
    std::printf("       Effect: kWrapperWitnessMissingAfterUse (no witnesses)\n");
    std::printf("               or kWrapperWitnessMismatch (witnesses from prior session)\n");
    std::printf("       Both deny launch immediately.\n");
    return 0;
}

// ---------------------------------------------------------------------------
// Issue (positional: hwid.json chain_length out_dir [--dev | --kpriv kpriv.bin])
// ---------------------------------------------------------------------------
void PrintUsageIssue(const char* argv0) {
    std::fprintf(stderr,
                 "Usage: %s <hwid.json> <chain_length> <out_dir>\n"
                 "           --kpriv <kpriv.bin> [--label <name>]\n"
                 "           [--input-bundle <app.bundle>]\n"
                 "           [--registry <licenses.txt>]\n"
                 "   or: %s <hwid.json> <chain_length> <out_dir> --dev\n"
                 "           [--label <name>] [--input-bundle <app.bundle>]\n"
                 "           (DEV/TEST mode: no paste.rs, fixed online_secret)\n",
                 argv0, argv0);
}

int RunIssue(int argc, char** argv) {
    if (argc < 4) {
        PrintUsageIssue(argv[0]);
        return 2;
    }

    const std::string hwid_path = argv[1];
    const long chain_length     = std::strtol(argv[2], nullptr, 10);
    const std::string out_dir   = argv[3];

    std::string kpriv_path;
    std::string label          = "unlabeled";
    std::string registry_path  = kDefaultRegistry;
    std::string bundle_path;
    bool dev_mode              = false;

    for (int i = 4; i < argc; ++i) {
        if (std::strcmp(argv[i], "--kpriv") == 0 && i + 1 < argc) {
            kpriv_path = argv[++i];
        } else if (std::strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            label = argv[++i];
        } else if (std::strcmp(argv[i], "--input-bundle") == 0 && i + 1 < argc) {
            bundle_path = argv[++i];
        } else if (std::strcmp(argv[i], "--registry") == 0 && i + 1 < argc) {
            registry_path = argv[++i];
        } else if (std::strcmp(argv[i], "--dev") == 0) {
            dev_mode = true;
        } else {
            PrintUsageIssue(argv[0]);
            return 2;
        }
    }

    if (!dev_mode && kpriv_path.empty()) {
        std::fprintf(stderr, "ERROR: --kpriv <kpriv.bin> is required (or use --dev for testing).\n");
        PrintUsageIssue(argv[0]);
        return 2;
    }

    if (dev_mode) {
        std::fprintf(stderr,
            "************************************************************\n"
            "* DEV MODE: online witness DISABLED, online_secret = zeros *\n"
            "* core_enc_key is deterministic -- NOT FOR PRODUCTION USE  *\n"
            "************************************************************\n");
    }

    if (chain_length <= 0 || chain_length > 1'000'000) {
        quark::error::Report(quark::error::Code::kKeygenChainLengthInvalid, kComponent, argv[2]);
        return 2;
    }

    auto hwid_json = ReadFile(hwid_path);
    if (!hwid_json) {
        quark::error::Report(quark::error::Code::kKeygenInputReadFailed, kComponent, hwid_path.c_str());
        return 1;
    }

    auto parsed_fp = quark::platform::FingerprintFromJson(*hwid_json);
    if (!parsed_fp) {
        quark::error::Report(quark::error::Code::kKeygenInputInvalid, kComponent, hwid_path.c_str());
        return 1;
    }

    std::vector<uint8_t> hwid_canonical = quark::platform::CanonicalBytes(parsed_fp->fingerprint);
    quark::crypto::Sha256Digest hwid_digest = quark::crypto::Sha256(hwid_canonical);

    std::optional<quark::online::EcPrivateKey> kpriv;
    if (!dev_mode) {
        kpriv = LoadKpriv(kpriv_path);
        if (!kpriv) {
            std::fprintf(stderr, "ERROR: could not read private key from %s\n", kpriv_path.c_str());
            return 1;
        }
    }

    // --- Lamport chain -----------------------------------------------------
    std::vector<uint8_t> seed = quark::crypto::RandomBytes(32);
    quark::crypto::ScopedZero<std::vector<uint8_t>> zero_seed(seed);
    auto chain = quark::lamport::BuildChain(seed, static_cast<uint32_t>(chain_length));
    const auto& anchor = chain.back();

    // --- state.bin ---------------------------------------------------------
    quark::crypto::AesKey state_key =
        quark::token::DeriveStateKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);
    quark::crypto::ScopedZero<quark::crypto::AesKey> zero_state_key(state_key);

    quark::state::LicenseState initial_state;
    initial_state.anchor = anchor;
    initial_state.remaining_links = static_cast<uint32_t>(chain_length);
    initial_state.hwid_digest = hwid_digest;
    initial_state.original_chain_length = static_cast<uint32_t>(chain_length);

    const std::string state_path = out_dir + "/state.bin";
    if (!quark::state::Save(state_path, state_key, hwid_canonical, initial_state)) {
        quark::error::Report(quark::error::Code::kKeygenStateWriteFailed, kComponent, state_path.c_str());
        return 1;
    }

    // --- unlock_keys.txt ---------------------------------------------------
    std::ostringstream keys;
    keys << "Quark one-time unlock keys for " << hwid_path << "\n"
         << "Chain length: " << chain_length << "\n"
         << "Deliver/redeem in the order listed (top to bottom).\n"
         << "Each key may be used exactly once and then becomes invalid.\n\n";
    for (long i = static_cast<long>(chain.size()) - 2; i >= 0; --i) {
        keys << quark::lamport::FormatKey(chain[static_cast<size_t>(i)]) << "\n";
    }
    const std::string keys_path = out_dir + "/unlock_keys.txt";
    if (!WriteFile(keys_path, keys.str())) {
        quark::error::Report(quark::error::Code::kKeygenKeysWriteFailed, kComponent, keys_path.c_str());
        return 1;
    }

    // --- Self-test ---------------------------------------------------------
    {
        const auto& first_key = chain[chain.size() - 2];
        auto loaded = quark::state::Load(state_path, state_key, hwid_canonical);
        if (!loaded || !quark::lamport::VerifyStep(first_key, loaded->anchor)) {
            quark::error::Report(quark::error::Code::kKeygenSelfTestFailed, kComponent,
                                 "SECRET mismatch? check drm_wrapper/secret.hpp");
            return 1;
        }
    }

    // --- Online witness paste (skipped in --dev mode) ----------------------
    quark::crypto::OnlineSecret online_secret{};
    quark::crypto::Sha256Digest online_secret_hash{};
    std::string paste_id;

    if (dev_mode) {
        // Fixed zero online_secret -- deterministic, NOT safe for production.
        std::memset(online_secret.data(), 0, online_secret.size());
        online_secret_hash = quark::crypto::Sha256(online_secret.data(), online_secret.size());
        paste_id = "";
        std::fprintf(stderr, "[DEV] Skipping paste.rs -- online_secret=zeros\n");
    } else {
        {
            auto rnd = quark::crypto::RandomBytes(32);
            quark::crypto::ScopedZero<std::vector<uint8_t>> zero_rnd(rnd);
            std::memcpy(online_secret.data(), rnd.data(), 32);
        }

        auto sign_msg = quark::online::BuildSignMessage(
            hwid_canonical, initial_state.original_chain_length, online_secret);
        auto sig = quark::online::SignPayload(*kpriv, sign_msg);
        if (!sig) {
            quark::crypto::SecureZero(online_secret.data(), online_secret.size());
            std::fprintf(stderr, "ERROR: P-256 signing failed.\n");
            return 1;
        }

        quark::online::PastePayload payload{};
        payload.online_secret = online_secret;
        payload.ec_signature  = *sig;

        // Hash before zeroing -- needed for core_enc_key derivation.
        online_secret_hash =
            quark::crypto::Sha256(payload.online_secret.data(), payload.online_secret.size());

        quark::crypto::SecureZero(online_secret.data(), online_secret.size());

        quark::crypto::AesKey online_key =
            quark::token::DeriveOnlineKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);
        quark::crypto::ScopedZero<quark::crypto::AesKey> zero_online_key(online_key);

        auto sealed_blob = quark::online::SealPayload(online_key, hwid_canonical, payload);
        quark::crypto::SecureZero(payload.online_secret.data(), payload.online_secret.size());

        std::printf("Posting online-witness paste to paste.rs ...\n");
        auto paste_id_opt = quark::online::PostPaste(sealed_blob);
        if (!paste_id_opt || paste_id_opt->empty()) {
            quark::error::Report(quark::error::Code::kKeygenPastePostFailed, kComponent, "PostPaste");
            return 1;
        }
        paste_id = *paste_id_opt;

        // Store paste_id in state.bin so DRM_Wrapper can fetch the paste.
        initial_state.paste_id = paste_id;
        if (!quark::state::Save(state_path, state_key, hwid_canonical, initial_state)) {
            quark::error::Report(quark::error::Code::kKeygenStateWriteFailed, kComponent, state_path.c_str());
            quark::online::DeletePaste(paste_id);
            return 1;
        }
    }

    quark::crypto::SecureZero(online_secret.data(), online_secret.size());

    // --- core.enc: encrypt the app bundle if provided ----------------------
    std::string enc_path;
    if (!bundle_path.empty()) {
        auto bundle_bytes_opt = ReadFile(bundle_path);
        if (!bundle_bytes_opt) {
            quark::error::Report(quark::error::Code::kKeygenInputReadFailed, kComponent,
                                 bundle_path.c_str());
            quark::online::DeletePaste(paste_id);
            return 1;
        }
        std::vector<uint8_t> bundle_bytes(bundle_bytes_opt->begin(), bundle_bytes_opt->end());

        quark::crypto::AesKey core_enc_key =
            quark::token::DeriveCoreEncKey(state_key, online_secret_hash, hwid_canonical);
        quark::crypto::ScopedZero<quark::crypto::AesKey> zero_cek(core_enc_key);

        enc_path = out_dir + "/core.enc";
        if (!WriteQenc(enc_path, core_enc_key, bundle_bytes)) {
            quark::error::Report(quark::error::Code::kKeygenStateWriteFailed, kComponent,
                                 enc_path.c_str());
            quark::online::DeletePaste(paste_id);
            return 1;
        }
    }

    // --- Append to license registry (skipped in dev mode) ------------------
    if (!dev_mode) {
        LicenseRecord rec;
        rec.paste_id     = paste_id;
        rec.label        = label;
        rec.chain_length = static_cast<uint32_t>(chain_length);
        rec.issued_utc   = UtcNow();
        rec.status       = "active";

        if (!AppendRecord(registry_path, rec)) {
            std::fprintf(stderr, "WARNING: could not write to %s -- record NOT saved.\n"
                                 "         paste_id=%s\n"
                                 "         Save this manually if you need revocation later.\n",
                         registry_path.c_str(), paste_id.c_str());
        }
    }

    std::printf("%sIssued license:\n", dev_mode ? "[DEV] " : "");
    std::printf("  state.bin    : %s\n", state_path.c_str());
    std::printf("  unlock_keys  : %s\n", keys_path.c_str());
    if (!enc_path.empty()) {
        std::printf("  core.enc     : %s\n", enc_path.c_str());
    }
    if (!dev_mode) {
        std::printf("  paste_id     : %s  (https://paste.rs/%s)\n",
                    paste_id.c_str(), paste_id.c_str());
        std::printf("  registry     : %s\n", registry_path.c_str());
    } else {
        std::printf("  paste_id     : (none -- DEV mode)\n");
    }
    std::printf("Ship state.bin%s in the customer's DRM_Wrapper bundle.\n",
                enc_path.empty() ? "" : " + core.enc");
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 2) {
        if (std::strcmp(argv[1], "--setup") == 0)  return RunSetup(argc, argv);
        if (std::strcmp(argv[1], "--list") == 0)   return RunList(argc, argv);
        if (std::strcmp(argv[1], "--revoke") == 0) return RunRevoke(argc, argv);
        if (std::strcmp(argv[1], "--burn") == 0)   return RunBurn(argc, argv);
    }
    return RunIssue(argc, argv);
}
