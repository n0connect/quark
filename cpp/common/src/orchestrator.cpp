#include "quark/orchestrator.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#include "quark/handoff.hpp"
#include "quark/lamport.hpp"
#include "quark/online.hpp"
#include "quark/state.hpp"
#include "quark/token.hpp"

namespace quark::orchestrator {

namespace {

// Wall clock read as a hostile input, never an authority -- see
// cpp/drm_wrapper/main.cpp's CurrentUnixTime for the full rationale (CLAUDE.md
// rule 6: only ever compared against a high-water mark to detect a backwards
// jump; a forward or normal clock grants nothing). std::chrono::system_clock
// has no OS-specific call on any of Quark's target platforms, so this
// (unlike the HWID/witness-storage backends) belongs in quark_core rather
// than being re-implemented per OS.
uint64_t CurrentUnixTime() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

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

// Releases `lock` (if non-null) no matter which of RunUnlockFlow's many
// return statements fires -- manually calling Release() before every one of
// them would be exactly the kind of error-prone pattern RAII exists to
// prevent. Only constructed AFTER Acquire() has already succeeded, so
// there's no risk of releasing a lock that was never held.
class LockGuard {
public:
    explicit LockGuard(platform::IProcessLock* lock) : lock_(lock) {}
    ~LockGuard() {
        if (lock_) lock_->Release();
    }
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;

private:
    platform::IProcessLock* lock_;
};

}  // namespace

error::Code RunUnlockFlow(const Config& config,
                           platform::IHwidBackend& hwid_backend,
                           std::array<platform::IWitnessStore*, 3> witnesses,
                           const std::string& candidate_key,
                           UnlockResult& out,
                           platform::IProcessLock* lock) {
    // --- acquire the per-license lock (if supplied) BEFORE touching state.bin --
    // Real concurrent-launch testing showed the read-verify-roll sequence
    // below must be exclusive across processes, or a single-use key can be
    // redeemed more than once (see quark/platform/process_lock.hpp).
    if (lock && !lock->Acquire(config.state_path)) {
        return error::Code::kWrapperLockFailed;
    }
    LockGuard lock_guard(lock);

    // --- local HWID ----------------------------------------------------------
    auto fingerprint = hwid_backend.Collect();
    if (!fingerprint) {
        return error::Code::kWrapperHwidCollectionFailed;
    }
    std::vector<uint8_t> hwid_canonical = platform::CanonicalBytes(*fingerprint);

    // --- derive state_key and open state.bin (HWID as AAD) --------------------
    crypto::AesKey state_key = token::DeriveStateKey(config.build_secret, hwid_canonical);
    crypto::ScopedZero<crypto::AesKey> zero_state_key(state_key);

    auto loaded = state::Load(config.state_path, state_key, hwid_canonical);
    if (!loaded) {
        // Tampering, wrong machine, missing/corrupt file -- one code,
        // deliberately indistinguishable (CLAUDE.md rule 2).
        return error::Code::kWrapperStateOpenFailed;
    }
    state::LicenseState license = *loaded;

    if (license.hwid_digest != crypto::Sha256(hwid_canonical)) {
        return error::Code::kWrapperHwidDigestMismatch;
    }

    // --- cross-check against the three independent witnesses ------------------
    // Reuses the same three domain-separated derivations the Windows registry/
    // ADS/overlay channels use (quark::token::DeriveRegistryKey/DeriveAdsKey/
    // DeriveOverlayKey) positionally for witnesses[0]/[1]/[2] -- the label
    // inside each domain-separation string ("REGISTRY", "ADS", "OVERLAY") is
    // just a KDF salt, not a claim about what's storing the bytes on this OS.
    crypto::AesKey witness_keys[3] = {
        token::DeriveRegistryKey(config.build_secret, hwid_canonical),
        token::DeriveAdsKey(config.build_secret, hwid_canonical),
        token::DeriveOverlayKey(config.build_secret, hwid_canonical),
    };
    crypto::ScopedZero<crypto::AesKey> zero_witness_keys[3] = {
        crypto::ScopedZero<crypto::AesKey>(witness_keys[0]),
        crypto::ScopedZero<crypto::AesKey>(witness_keys[1]),
        crypto::ScopedZero<crypto::AesKey>(witness_keys[2]),
    };

    // Same numbered codes the Windows build reports for its registry/ADS/
    // overlay channels -- CLAUDE.md's error registry is deliberately shared
    // across every program and platform ("a code always means exactly one
    // thing"), so witness slot 0/1/2 reuses them rather than minting three
    // more near-duplicate codes for the same structural failure.
    constexpr error::Code kOpenFailedCodes[3] = {
        error::Code::kWrapperRegistryOpenFailed,
        error::Code::kWrapperAdsOpenFailed,
        error::Code::kWrapperOverlayOpenFailed,
    };
    constexpr error::Code kWriteFailedCodes[3] = {
        error::Code::kWrapperRegistryWriteFailed,
        error::Code::kWrapperAdsWriteFailed,
        error::Code::kWrapperOverlayWriteFailed,
    };

    const uint64_t now_unix = CurrentUnixTime();

    witness::Record records[3]{};
    witness::LoadResult results[3];
    for (int i = 0; i < 3; ++i) {
        results[i] = witnesses[i]->Load(witness_keys[i], hwid_canonical, records[i]);
        if (results[i] == witness::LoadResult::kInvalid) {
            return kOpenFailedCodes[i];
        }
    }

    const int absent_count = static_cast<int>(std::count(
        std::begin(results), std::end(results), witness::LoadResult::kAbsent));

    if (absent_count == 3) {
        // All witnesses absent. Legitimate only on a pristine chain;
        // otherwise "delete all witnesses, restore a used state.bin".
        if (license.remaining_links != license.original_chain_length) {
            return error::Code::kWrapperWitnessMissingAfterUse;
        }
        witness::Record fresh{};
        fresh.anchor = license.anchor;
        fresh.remaining_links = license.remaining_links;
        fresh.hwid_digest = license.hwid_digest;
        fresh.high_water_unix_time = now_unix;

        for (int i = 0; i < 3; ++i) {
            if (!witnesses[i]->Save(witness_keys[i], hwid_canonical, fresh)) {
                return kWriteFailedCodes[i];
            }
            records[i] = fresh;
        }
    } else if (absent_count > 0) {
        // Selective absence is a tamper signal -- witnesses are always
        // minted and rolled in lockstep on a legitimate run.
        return error::Code::kWrapperWitnessMismatch;
    } else {
        // All three present and authenticated -- they must all agree with
        // each other and with state.bin.
        for (int i = 0; i < 3; ++i) {
            if (records[i].anchor != license.anchor ||
                records[i].remaining_links != license.remaining_links ||
                records[i].hwid_digest != license.hwid_digest) {
                return error::Code::kWrapperWitnessMismatch;
            }
        }
        const uint64_t high_water = std::max(
            {records[0].high_water_unix_time, records[1].high_water_unix_time,
             records[2].high_water_unix_time});
        if (now_unix < high_water) {
            return error::Code::kWrapperClockRollbackDetected;
        }
    }

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

    // --- chain exhaustion is the entire expiry mechanism ------------------------
    if (license.remaining_links == 0) {
        return error::Code::kWrapperLicenseExhausted;
    }

    // --- verify the caller-supplied one-time key against the anchor -------------
    auto candidate = lamport::ParseKey(candidate_key);
    if (!candidate || !lamport::VerifyStep(*candidate, license.anchor)) {
        return error::Code::kWrapperUnlockKeyInvalid;
    }

    // --- roll the chain forward and persist BEFORE returning to the caller ------
    // Capture BEFORE rolling -- DeriveInitialSeal needs both the pre- and
    // post-roll anchor to prove to the far end that a real roll happened.
    const crypto::Sha256Digest anchor_before = license.anchor;

    state::LicenseState rolled = license;
    rolled.anchor = *candidate;
    rolled.remaining_links = license.remaining_links - 1;

    if (!state::Save(config.state_path, state_key, hwid_canonical, rolled)) {
        return error::Code::kWrapperStatePersistFailed;
    }

    const uint64_t prev_high_water = std::max(
        {records[0].high_water_unix_time, records[1].high_water_unix_time,
         records[2].high_water_unix_time});
    witness::Record rolled_witness{};
    rolled_witness.anchor = rolled.anchor;
    rolled_witness.remaining_links = rolled.remaining_links;
    rolled_witness.hwid_digest = rolled.hwid_digest;
    rolled_witness.high_water_unix_time = (now_unix > prev_high_water) ? now_unix : prev_high_water;

    for (int i = 0; i < 3; ++i) {
        if (!witnesses[i]->Save(witness_keys[i], hwid_canonical, rolled_witness)) {
            return kWriteFailedCodes[i];
        }
    }

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
