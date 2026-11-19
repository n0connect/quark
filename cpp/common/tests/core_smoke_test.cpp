// Real, non-mocked smoke tests for quark_core. Every check here calls the
// actual mbedTLS-backed implementation and, where relevant, the real
// filesystem via a real temp file -- see CLAUDE.md engineering rule 1.
//
// Deliberately hand-rolled instead of pulling in a test framework: this repo
// has exactly one platform-agnostic library to test so far, and a framework
// dependency buys nothing yet that a couple dozen `Check()` calls don't
// already give -- CLAUDE.md engineering rule 3 (simple over clever).

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "quark/config.hpp"
#include "quark/crypto.hpp"
#include "quark/handoff.hpp"
#include "quark/lamport.hpp"
#include "quark/online.hpp"
#include "quark/platform/file_witness_store.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/hwid_json.hpp"
#include "quark/state.hpp"
#include "quark/token.hpp"
#include "quark/witness.hpp"

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

std::vector<uint8_t> FakeHwidAad() {
    // A stand-in HWID canonical byte string -- this is NOT mocking an OS
    // call (there is none here to mock: AES-GCM's AAD is just a byte
    // buffer as far as quark_core is concerned). Real HWID collection is
    // quark::hwid::Collect()'s job on the real OS, exercised separately by
    // HWID_Extractor.exe on real Windows hardware.
    std::string s = "test-machine-fingerprint";
    return std::vector<uint8_t>(s.begin(), s.end());
}

void TestCryptoRoundTrip() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), key.begin());

    std::vector<uint8_t> aad = FakeHwidAad();
    std::vector<uint8_t> plaintext = {'q', 'u', 'a', 'r', 'k'};

    auto sealed = quark::crypto::Aes256GcmEncrypt(key, aad, plaintext);
    auto opened = quark::crypto::Aes256GcmDecrypt(key, sealed.iv, aad, sealed.ciphertext, sealed.tag);
    Check(opened.has_value() && *opened == plaintext, "AES-256-GCM round-trip with matching AAD succeeds");

    std::vector<uint8_t> wrong_aad = {'w', 'r', 'o', 'n', 'g'};
    auto tampered_aad = quark::crypto::Aes256GcmDecrypt(key, sealed.iv, wrong_aad, sealed.ciphertext, sealed.tag);
    Check(!tampered_aad.has_value(), "AES-256-GCM decrypt fails on AAD mismatch (wrong-machine case)");

    std::vector<uint8_t> tampered_ct = sealed.ciphertext;
    if (!tampered_ct.empty()) tampered_ct[0] ^= 0xFF;
    auto tampered = quark::crypto::Aes256GcmDecrypt(key, sealed.iv, aad, tampered_ct, sealed.tag);
    Check(!tampered.has_value(), "AES-256-GCM decrypt fails on tampered ciphertext");

    auto mac1 = quark::crypto::HmacSha256(key.data(), key.size(), plaintext.data(), plaintext.size());
    auto mac2 = quark::crypto::HmacSha256(key.data(), key.size(), plaintext.data(), plaintext.size());
    Check(mac1 == mac2, "HMAC-SHA256 is deterministic for identical key+message");
}

void TestAesCtrXorRoundTrip() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), key.begin());

    std::array<uint8_t, quark::crypto::kCtrNonceSize> nonce{};
    std::vector<uint8_t> real_bytes = {0xff, 0xc3, 0x00, 0xd1, 0xe0, 0x17, 0x00, 0xf9};

    auto scrambled = quark::crypto::Aes256CtrXor(key, nonce, real_bytes);
    Check(scrambled != real_bytes, "Aes256CtrXor scrambling changes every input byte pattern");
    Check(scrambled.size() == real_bytes.size(), "Aes256CtrXor preserves length exactly");

    auto reconstructed = quark::crypto::Aes256CtrXor(key, nonce, scrambled);
    Check(reconstructed == real_bytes,
          "Aes256CtrXor applied twice with the same key+nonce reconstructs the original bytes exactly");

    quark::crypto::AesKey wrong_key{};
    auto random2 = quark::crypto::RandomBytes(32);
    std::copy(random2.begin(), random2.end(), wrong_key.begin());
    auto wrong_reconstruction = quark::crypto::Aes256CtrXor(wrong_key, nonce, scrambled);
    Check(wrong_reconstruction != real_bytes, "the wrong key does not reconstruct the original bytes");
}

void TestDeriveCodeStreamKey() {
    quark::crypto::AesKey content_key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), content_key.begin());

    auto code_key_a = quark::token::DeriveCodeStreamKey(content_key);
    auto code_key_b = quark::token::DeriveCodeStreamKey(content_key);
    Check(code_key_a == code_key_b, "DeriveCodeStreamKey is deterministic for the same content_key");

    quark::crypto::AesKey other_content_key{};
    auto random2 = quark::crypto::RandomBytes(32);
    std::copy(random2.begin(), random2.end(), other_content_key.begin());
    auto code_key_c = quark::token::DeriveCodeStreamKey(other_content_key);
    Check(code_key_a != code_key_c, "DeriveCodeStreamKey differs for a different content_key");
}

void TestLamportChain() {
    auto seed = quark::crypto::RandomBytes(32);
    constexpr uint32_t kChainLength = 5;
    auto chain = quark::lamport::BuildChain(seed, kChainLength);
    Check(chain.size() == kChainLength + 1, "Lamport chain has n+1 links (seed digest through anchor)");

    // chain[k] = H^k(seed); verifying chain[k-1] against chain[k] must succeed,
    // and verifying anything else against chain[k] must fail.
    bool all_steps_verify = true;
    for (uint32_t k = 1; k <= kChainLength; ++k) {
        if (!quark::lamport::VerifyStep(chain[k - 1], chain[k])) all_steps_verify = false;
    }
    Check(all_steps_verify, "every consecutive Lamport link verifies against its anchor");

    Check(!quark::lamport::VerifyStep(chain[0], chain[kChainLength]),
          "a non-consecutive preimage does not verify against a later anchor");

    std::string formatted = quark::lamport::FormatKey(chain[0]);
    auto parsed = quark::lamport::ParseKey(formatted);
    Check(parsed.has_value() && *parsed == chain[0], "FormatKey/ParseKey round-trip preserves the digest");

    Check(!quark::lamport::ParseKey("not-a-hex-digest").has_value(),
          "ParseKey rejects malformed input instead of guessing");
}

void TestTokenDerivationIsDeterministicAndDomainSeparated() {
    std::string secret = "test-secret";
    auto hwid_a = FakeHwidAad();
    std::vector<uint8_t> hwid_b = {'o', 't', 'h', 'e', 'r'};

    auto state_key_1 = quark::token::DeriveStateKey(secret, hwid_a);
    auto state_key_2 = quark::token::DeriveStateKey(secret, hwid_a);
    Check(state_key_1 == state_key_2, "DeriveStateKey is deterministic for identical inputs");

    auto state_key_other_hwid = quark::token::DeriveStateKey(secret, hwid_b);
    Check(state_key_1 != state_key_other_hwid, "DeriveStateKey changes when HWID changes");

    auto registry_key = quark::token::DeriveRegistryKey(secret, hwid_a);
    Check(state_key_1 != registry_key,
          "DeriveStateKey and DeriveRegistryKey are domain-separated (same inputs, different key)");
}

void TestStateBinRoundTripOnRealFilesystem() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), key.begin());
    std::vector<uint8_t> hwid_aad = FakeHwidAad();

    quark::state::LicenseState original;
    original.anchor = quark::crypto::Sha256(std::vector<uint8_t>{1, 2, 3});
    original.remaining_links = 7;
    original.hwid_digest = quark::crypto::Sha256(hwid_aad);
    original.original_chain_length = 10;
    original.paste_id = "abc12";

    // A relative path, not std::filesystem::temp_directory_path(): tests must
    // never write outside of wherever they were invoked from (this repo's
    // convention is to always run/build under sandbox/) -- a real OS temp
    // directory is still "leaving the sandbox" even though it's real, not
    // mocked. Relative to the test binary's current working directory.
    auto path = std::string("quark_core_test_state.bin");

    bool saved = quark::state::Save(path, key, hwid_aad, original);
    Check(saved, "state.bin Save() succeeds against a real temp file");

    auto loaded = quark::state::Load(path, key, hwid_aad);
    Check(loaded.has_value(), "state.bin Load() succeeds with the same key and AAD");
    if (loaded) {
        Check(loaded->anchor == original.anchor && loaded->remaining_links == original.remaining_links &&
                  loaded->hwid_digest == original.hwid_digest &&
                  loaded->original_chain_length == original.original_chain_length &&
                  loaded->paste_id == original.paste_id,
              "state.bin round-trip preserves every field");
    }

    auto loaded_wrong_aad = quark::state::Load(path, key, std::vector<uint8_t>{'w', 'r', 'o', 'n', 'g'});
    Check(!loaded_wrong_aad.has_value(), "state.bin Load() fails on wrong HWID AAD (simulated wrong machine)");

    std::filesystem::remove(path);
}

void TestPlatformCanonicalBytes() {
    quark::platform::Fingerprint fp;
    fp.fields.push_back({"cpu_vendor_signature", "GenuineIntel:AAA"});
    fp.fields.push_back({"machine_guid", "1234-5678"});

    auto bytes_a = quark::platform::CanonicalBytes(fp);
    auto bytes_b = quark::platform::CanonicalBytes(fp);
    Check(bytes_a == bytes_b, "platform::CanonicalBytes is deterministic for the same Fingerprint");

    std::string joined(bytes_a.begin(), bytes_a.end());
    Check(joined == std::string("GenuineIntel:AAA") + '\x1F' + "1234-5678",
          "platform::CanonicalBytes joins field values with 0x1F in field order");

    quark::platform::Fingerprint fp_changed = fp;
    fp_changed.fields[1].value = "1234-5679";  // one character different
    auto digest_a = quark::crypto::Sha256(quark::platform::CanonicalBytes(fp));
    auto digest_b = quark::crypto::Sha256(quark::platform::CanonicalBytes(fp_changed));
    Check(digest_a != digest_b, "a single changed field avalanches into a different SHA-256 digest");
}

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

void TestWitnessCodecRoundTrip() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), key.begin());
    std::vector<uint8_t> hwid_aad = FakeHwidAad();

    quark::witness::Record record;
    record.anchor = quark::crypto::Sha256(std::vector<uint8_t>{9, 9, 9});
    record.remaining_links = 3;
    record.hwid_digest = quark::crypto::Sha256(hwid_aad);
    record.high_water_unix_time = 1234567890ULL;

    std::array<char, 4> magic = {'Q', 'T', 'S', 'T'};
    auto sealed = quark::witness::Seal(key, hwid_aad, record, magic);
    auto opened = quark::witness::Unseal(key, hwid_aad, sealed, magic);
    Check(opened.has_value(), "witness::Unseal succeeds on its own Seal() output");
    if (opened) {
        Check(opened->anchor == record.anchor && opened->remaining_links == record.remaining_links &&
                  opened->hwid_digest == record.hwid_digest &&
                  opened->high_water_unix_time == record.high_water_unix_time,
              "witness::Seal/Unseal round-trip preserves every field");
    }

    std::array<char, 4> wrong_magic = {'X', 'X', 'X', 'X'};
    Check(!quark::witness::Unseal(key, hwid_aad, sealed, wrong_magic).has_value(),
          "witness::Unseal rejects a mismatched channel magic");
}

void TestFileWitnessStoreOnRealFilesystem() {
    quark::crypto::AesKey key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), key.begin());
    std::vector<uint8_t> hwid_aad = FakeHwidAad();

    // Relative path -- stays under wherever the test binary is invoked from
    // (this repo's convention: always sandbox/), same reasoning as the
    // state.bin test above.
    quark::platform::FileWitnessStore store("quark_core_test_witness.bin", {'Q', 'F', 'W', 'S'}, "test-file");

    quark::witness::Record missing;
    Check(store.Load(key, hwid_aad, missing) == quark::witness::LoadResult::kAbsent,
          "FileWitnessStore reports kAbsent before any Save()");

    quark::witness::Record record;
    record.anchor = quark::crypto::Sha256(std::vector<uint8_t>{4, 2});
    record.remaining_links = 9;
    record.hwid_digest = quark::crypto::Sha256(hwid_aad);
    record.high_water_unix_time = 42;

    Check(store.Save(key, hwid_aad, record), "FileWitnessStore::Save writes successfully to a real file");

    quark::witness::Record loaded;
    auto result = store.Load(key, hwid_aad, loaded);
    Check(result == quark::witness::LoadResult::kFound, "FileWitnessStore::Load finds what Save() wrote");
    Check(loaded.anchor == record.anchor && loaded.remaining_links == record.remaining_links,
          "FileWitnessStore round-trip preserves the record");

    quark::witness::Record wrong_key_out;
    quark::crypto::AesKey other_key{};
    auto other_random = quark::crypto::RandomBytes(32);
    std::copy(other_random.begin(), other_random.end(), other_key.begin());
    Check(store.Load(other_key, hwid_aad, wrong_key_out) == quark::witness::LoadResult::kInvalid,
          "FileWitnessStore::Load reports kInvalid (not kAbsent) for a present-but-wrong-key file");

    std::filesystem::remove("quark_core_test_witness.bin");
}

void TestHandoffFrameEncoding() {
    quark::crypto::AesKey handoff_secret{};
    quark::crypto::AesKey core_enc_key{};
    std::array<uint8_t, 32> session_id{};
    quark::crypto::Sha256Digest initial_seal{};

    auto frame = quark::handoff::EncodeInitialFrame(handoff_secret, session_id, initial_seal, core_enc_key);
    Check(frame.size() == quark::handoff::kInitialFrameSize, "QKH2 initial frame is exactly 136 bytes");
    Check(frame[0] == 'Q' && frame[1] == 'K' && frame[2] == 'H' && frame[3] == '2',
          "QKH2 initial frame starts with the correct magic");

    auto challenge = quark::handoff::EncodeChallengeFrame(42, session_id);
    Check(challenge.size() == quark::handoff::kChallengeFrameSize, "QKH2 challenge frame is exactly 40 bytes");
}

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

}  // namespace

int main() {
    TestCryptoRoundTrip();
    TestAesCtrXorRoundTrip();
    TestDeriveCodeStreamKey();
    TestLamportChain();
    TestTokenDerivationIsDeterministicAndDomainSeparated();
    TestStateBinRoundTripOnRealFilesystem();
    TestPlatformCanonicalBytes();
    TestFingerprintJsonRoundTrip();
    TestWitnessCodecRoundTrip();
    TestFileWitnessStoreOnRealFilesystem();
    TestHandoffFrameEncoding();
    TestOnlinePayloadCrypto();
    TestConfigFileRoundTrip();

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
