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
