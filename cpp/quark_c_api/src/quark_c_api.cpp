#include "quark_c_api.h"

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/error.hpp"
#include "quark/lamport.hpp"
#include "quark/orchestrator.hpp"
#include "quark/payload.hpp"
#include "quark/platform/file_witness_store.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/process_lock.hpp"
#include "quark/platform/witness_store.hpp"
#include "quark/state.hpp"
#include "quark/token.hpp"

#if defined(__APPLE__)
#include "quark/platform/macos/hwid_backend_macos.hpp"
#include "quark/platform/macos/xattr_witness_store.hpp"
#include "quark/platform/posix/process_lock_posix.hpp"
#elif defined(__linux__)
#include "quark/platform/linux/hwid_backend_linux.hpp"
#include "quark/platform/linux/xattr_witness_store.hpp"
#include "quark/platform/posix/process_lock_posix.hpp"
#elif defined(_WIN32)
#include "quark/platform/windows/hwid_backend_win.hpp"
#include "quark/platform/windows/process_lock_win.hpp"
#include "quark/platform/windows/witness_stores_win.hpp"
#endif

// Every QUARK_ERR_* value in quark_c_api.h that overlaps quark::error::Code
// must be numerically identical to it -- this is what lets a code mean the
// same thing everywhere in Quark (see that header's file comment). These
// static_asserts turn any future drift between the two into a build failure
// instead of a silently wrong number crossing the C boundary.
static_assert(QUARK_ERR_HWID_FIELD_UNREADABLE == static_cast<int32_t>(quark::error::Code::kHwidFieldUnreadable), "");
static_assert(QUARK_ERR_CHAIN_LENGTH_INVALID == static_cast<int32_t>(quark::error::Code::kKeygenChainLengthInvalid), "");
static_assert(QUARK_ERR_STATE_WRITE_FAILED == static_cast<int32_t>(quark::error::Code::kKeygenStateWriteFailed), "");
static_assert(QUARK_ERR_HWID_COLLECTION_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperHwidCollectionFailed), "");
static_assert(QUARK_ERR_STATE_OPEN_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperStateOpenFailed), "");
static_assert(QUARK_ERR_HWID_DIGEST_MISMATCH == static_cast<int32_t>(quark::error::Code::kWrapperHwidDigestMismatch), "");
static_assert(QUARK_ERR_LICENSE_EXHAUSTED == static_cast<int32_t>(quark::error::Code::kWrapperLicenseExhausted), "");
static_assert(QUARK_ERR_UNLOCK_KEY_INVALID == static_cast<int32_t>(quark::error::Code::kWrapperUnlockKeyInvalid), "");
static_assert(QUARK_ERR_STATE_PERSIST_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperStatePersistFailed), "");
static_assert(QUARK_ERR_WITNESS0_OPEN_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperRegistryOpenFailed), "");
static_assert(QUARK_ERR_WITNESS0_WRITE_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperRegistryWriteFailed), "");
static_assert(QUARK_ERR_WITNESS_MISMATCH == static_cast<int32_t>(quark::error::Code::kWrapperWitnessMismatch), "");
static_assert(QUARK_ERR_CLOCK_ROLLBACK_DETECTED == static_cast<int32_t>(quark::error::Code::kWrapperClockRollbackDetected), "");
static_assert(QUARK_ERR_WITNESS_MISSING_AFTER_USE == static_cast<int32_t>(quark::error::Code::kWrapperWitnessMissingAfterUse), "");
static_assert(QUARK_ERR_WITNESS1_OPEN_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperAdsOpenFailed), "");
static_assert(QUARK_ERR_WITNESS1_WRITE_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperAdsWriteFailed), "");
static_assert(QUARK_ERR_WITNESS2_OPEN_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperOverlayOpenFailed), "");
static_assert(QUARK_ERR_WITNESS2_WRITE_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperOverlayWriteFailed), "");
static_assert(QUARK_ERR_ONLINE_WITNESS_UNSUPPORTED == static_cast<int32_t>(quark::error::Code::kWrapperOnlineFetchFailed), "");
static_assert(QUARK_ERR_LOCK_FAILED == static_cast<int32_t>(quark::error::Code::kWrapperLockFailed), "");
static_assert(QUARK_OK == static_cast<int32_t>(quark::error::Code::kOk), "");

namespace {

// Mirrors Dev_Keygen's existing sanity bound on chain length -- a request
// for zero or many-million links is almost certainly a caller bug, not a
// real license.
constexpr uint32_t kMaxChainLength = 1'000'000;

std::unique_ptr<quark::platform::IHwidBackend> MakeHwidBackend() {
#if defined(__APPLE__)
    return std::make_unique<quark::platform::macos::MacHwidBackend>();
#elif defined(__linux__)
    return std::make_unique<quark::platform::linux_::LinuxHwidBackend>();
#elif defined(_WIN32)
    return std::make_unique<quark::platform::win::WindowsHwidBackend>();
#else
    return nullptr;
#endif
}

// Excludes concurrent quark_unlock_and_decrypt calls (different threads
// within one host process, or different processes/hosts entirely) racing on
// the same state_path from both redeeming the same single-use key -- see
// CLAUDE.md rule 6's IProcessLock paragraph for the real concurrent-launch
// testing that found this was necessary.
std::unique_ptr<quark::platform::IProcessLock> MakeProcessLock() {
#if defined(__APPLE__) || defined(__linux__)
    return std::make_unique<quark::platform::posix::FlockProcessLock>();
#elif defined(_WIN32)
    return std::make_unique<quark::platform::win::LockFileProcessLock>();
#else
    return nullptr;
#endif
}

std::array<char, 4> ToMagic(const char magic[4]) {
    return {magic[0], magic[1], magic[2], magic[3]};
}

// Builds the concrete IWitnessStore for one channel descriptor. Returns
// nullptr (and sets *error) if `channel` requests a kind this build doesn't
// support (e.g. QUARK_WITNESS_KIND_REGISTRY on a non-Windows build) or is
// missing a required field.
std::unique_ptr<quark::platform::IWitnessStore> MakeWitnessStore(
    const quark_witness_channel_t& channel, quark_error_t* error) {
    *error = QUARK_OK;
    const std::string name = channel.name ? channel.name : "witness";

    switch (channel.kind) {
        case QUARK_WITNESS_KIND_FILE: {
            if (!channel.path) {
                *error = QUARK_ERR_INVALID_ARGUMENT;
                return nullptr;
            }
            return std::make_unique<quark::platform::FileWitnessStore>(
                channel.path, ToMagic(channel.magic), name);
        }
        case QUARK_WITNESS_KIND_XATTR: {
            if (!channel.path || !channel.attr_name) {
                *error = QUARK_ERR_INVALID_ARGUMENT;
                return nullptr;
            }
#if defined(__APPLE__)
            return std::make_unique<quark::platform::macos::XattrWitnessStore>(
                channel.path, channel.attr_name, ToMagic(channel.magic), name);
#elif defined(__linux__)
            return std::make_unique<quark::platform::linux_::XattrWitnessStore>(
                channel.path, channel.attr_name, ToMagic(channel.magic), name);
#else
            *error = QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM;
            return nullptr;
#endif
        }
        case QUARK_WITNESS_KIND_REGISTRY:
#if defined(_WIN32)
            return std::make_unique<quark::platform::win::RegistryWitnessStore>();
#else
            *error = QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM;
            return nullptr;
#endif
        case QUARK_WITNESS_KIND_ADS:
#if defined(_WIN32)
            return std::make_unique<quark::platform::win::AdsWitnessStore>();
#else
            *error = QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM;
            return nullptr;
#endif
        case QUARK_WITNESS_KIND_OVERLAY:
#if defined(_WIN32)
            return std::make_unique<quark::platform::win::OverlayWitnessStore>();
#else
            *error = QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM;
            return nullptr;
#endif
        default:
            *error = QUARK_ERR_INVALID_ARGUMENT;
            return nullptr;
    }
}

}  // namespace

extern "C" {

const char* quark_error_describe(quark_error_t code) {
    switch (code) {
        case QUARK_ERR_INVALID_ARGUMENT:
            return "invalid argument (null pointer or malformed input)";
        case QUARK_ERR_BUFFER_TOO_SMALL:
            return "caller-supplied buffer is too small for the output";
        case QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM:
            return "this operation is not supported by the platform backend this library was built with";
        default:
            if (code >= 0) {
                return quark::error::Describe(static_cast<quark::error::Code>(code));
            }
            return "unrecognized error code";
    }
}

quark_error_t quark_hwid_collect(uint8_t* canonical_out, size_t canonical_cap,
                                  size_t* canonical_len_out) {
    if (!canonical_len_out) return QUARK_ERR_INVALID_ARGUMENT;

    auto backend = MakeHwidBackend();
    if (!backend) return QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM;

    auto fingerprint = backend->Collect();
    if (!fingerprint) return QUARK_ERR_HWID_COLLECTION_FAILED;

    std::vector<uint8_t> canonical = quark::platform::CanonicalBytes(*fingerprint);
    *canonical_len_out = canonical.size();

    if (canonical_cap < canonical.size() || !canonical_out) {
        return QUARK_ERR_BUFFER_TOO_SMALL;
    }
    std::memcpy(canonical_out, canonical.data(), canonical.size());
    return QUARK_OK;
}

quark_error_t quark_lamport_mint_chain(uint32_t chain_length, uint8_t anchor_out[32],
                                        uint8_t* keys_out, size_t keys_cap) {
    if (!anchor_out) return QUARK_ERR_INVALID_ARGUMENT;
    if (chain_length == 0 || chain_length > kMaxChainLength) {
        return QUARK_ERR_CHAIN_LENGTH_INVALID;
    }
    const size_t required = static_cast<size_t>(chain_length) * 32;
    if (!keys_out || keys_cap < required) {
        return QUARK_ERR_BUFFER_TOO_SMALL;
    }

    std::vector<uint8_t> seed = quark::crypto::RandomBytes(32);
    std::vector<quark::crypto::Sha256Digest> chain = quark::lamport::BuildChain(seed, chain_length);
    quark::crypto::SecureZero(seed.data(), seed.size());

    // chain[chain_length] is the anchor H^n(seed); chain[chain_length-1] ..
    // chain[0] are handed out in that order (the order a customer consumes
    // them -- see quark/lamport.hpp).
    std::memcpy(anchor_out, chain[chain_length].data(), 32);
    for (uint32_t i = 0; i < chain_length; ++i) {
        std::memcpy(keys_out + static_cast<size_t>(i) * 32, chain[chain_length - 1 - i].data(), 32);
    }
    return QUARK_OK;
}

quark_error_t quark_state_mint(const char* state_path, const char* build_secret,
                                const uint8_t* hwid_canonical, size_t hwid_canonical_len,
                                const uint8_t anchor[32], uint32_t chain_length) {
    if (!state_path || !build_secret || !hwid_canonical || !anchor) {
        return QUARK_ERR_INVALID_ARGUMENT;
    }
    if (chain_length == 0 || chain_length > kMaxChainLength) {
        return QUARK_ERR_CHAIN_LENGTH_INVALID;
    }

    std::vector<uint8_t> hwid_bytes(hwid_canonical, hwid_canonical + hwid_canonical_len);

    quark::state::LicenseState license;
    std::memcpy(license.anchor.data(), anchor, 32);
    license.remaining_links = chain_length;
    license.hwid_digest = quark::crypto::Sha256(hwid_bytes);
    license.original_chain_length = chain_length;
    license.paste_id.clear();  // dev-mode: no online witness

    quark::crypto::AesKey state_key = quark::token::DeriveStateKey(build_secret, hwid_bytes);
    quark::crypto::ScopedZero<quark::crypto::AesKey> zero_key(state_key);

    if (!quark::state::Save(state_path, state_key, hwid_bytes, license)) {
        return QUARK_ERR_STATE_WRITE_FAILED;
    }
    return QUARK_OK;
}

quark_error_t quark_seal_payload(const char* build_secret,
                                  const uint8_t* hwid_canonical, size_t hwid_canonical_len,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  uint8_t* sealed_out, size_t sealed_cap,
                                  size_t* sealed_len_out) {
    if (!build_secret || !hwid_canonical || (!plaintext && plaintext_len > 0) || !sealed_len_out) {
        return QUARK_ERR_INVALID_ARGUMENT;
    }

    std::vector<uint8_t> hwid_bytes(hwid_canonical, hwid_canonical + hwid_canonical_len);
    std::vector<uint8_t> plaintext_bytes(plaintext, plaintext + plaintext_len);

    quark::crypto::AesKey state_key = quark::token::DeriveStateKey(build_secret, hwid_bytes);
    quark::crypto::ScopedZero<quark::crypto::AesKey> zero_state_key(state_key);

    // Dev-mode assumption, matching quark::orchestrator::RunUnlockFlow: no
    // portable HTTPS client exists yet, so only dev-mode licenses (empty
    // paste_id, online_secret == all zero) work through this engine today --
    // sealing here must derive core_enc_key exactly the way a real unlock
    // will, or a legitimately-issued license would never decrypt its own
    // payload.
    quark::crypto::OnlineSecret online_secret{};
    online_secret.fill(0);
    quark::crypto::Sha256Digest online_secret_hash =
        quark::crypto::Sha256(online_secret.data(), online_secret.size());

    quark::crypto::AesKey core_enc_key =
        quark::token::DeriveCoreEncKey(state_key, online_secret_hash, hwid_bytes);
    quark::crypto::ScopedZero<quark::crypto::AesKey> zero_core_enc_key(core_enc_key);

    std::vector<uint8_t> sealed = quark::payload::Seal(core_enc_key, plaintext_bytes);
    *sealed_len_out = sealed.size();
    if (!sealed_out || sealed_cap < sealed.size()) {
        return QUARK_ERR_BUFFER_TOO_SMALL;
    }
    std::memcpy(sealed_out, sealed.data(), sealed.size());
    return QUARK_OK;
}

quark_error_t quark_unlock_and_decrypt(const char* state_path, const char* build_secret,
                                        const quark_witness_channel_t witnesses[3],
                                        const char* candidate_key,
                                        const uint8_t* sealed_payload, size_t sealed_payload_len,
                                        uint8_t* plaintext_out, size_t plaintext_cap,
                                        size_t* plaintext_len_out,
                                        uint8_t content_key_out[32] /* nullable */,
                                        uint8_t session_id_out[32] /* nullable */) {
    if (!state_path || !build_secret || !witnesses || !candidate_key || !sealed_payload ||
        !plaintext_len_out) {
        return QUARK_ERR_INVALID_ARGUMENT;
    }

    auto backend = MakeHwidBackend();
    if (!backend) return QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM;

    std::unique_ptr<quark::platform::IWitnessStore> stores[3];
    for (int i = 0; i < 3; ++i) {
        quark_error_t err = QUARK_OK;
        stores[i] = MakeWitnessStore(witnesses[i], &err);
        if (!stores[i]) return err;
    }

    quark::orchestrator::Config config;
    config.build_secret = build_secret;
    config.state_path = state_path;

    auto lock = MakeProcessLock();

    quark::orchestrator::UnlockResult result;
    quark::error::Code code = quark::orchestrator::RunUnlockFlow(
        config, *backend, {stores[0].get(), stores[1].get(), stores[2].get()}, candidate_key,
        result, lock.get());

    if (code != quark::error::Code::kOk) {
        return static_cast<quark_error_t>(code);
    }

    // core_enc_key never crosses this boundary -- Unseal happens entirely
    // inside this function (see quark_c_api.h's file comment on why this is
    // the ONLY way to reach the payload's plaintext through this API).
    std::vector<uint8_t> sealed_vec(sealed_payload, sealed_payload + sealed_payload_len);
    auto plaintext = quark::payload::Unseal(result.core_enc_key, sealed_vec);
    quark::crypto::SecureZero(result.core_enc_key.data(), result.core_enc_key.size());

    if (!plaintext) {
        quark::crypto::SecureZero(result.content_key.data(), result.content_key.size());
        return QUARK_ERR_PAYLOAD_DECRYPT_FAILED;
    }

    *plaintext_len_out = plaintext->size();
    if (!plaintext_out || plaintext_cap < plaintext->size()) {
        quark::crypto::SecureZero(plaintext->data(), plaintext->size());
        quark::crypto::SecureZero(result.content_key.data(), result.content_key.size());
        return QUARK_ERR_BUFFER_TOO_SMALL;
    }
    std::memcpy(plaintext_out, plaintext->data(), plaintext->size());
    quark::crypto::SecureZero(plaintext->data(), plaintext->size());

    if (content_key_out) {
        std::memcpy(content_key_out, result.content_key.data(), 32);
    }
    quark::crypto::SecureZero(result.content_key.data(), result.content_key.size());

    if (session_id_out) {
        std::memcpy(session_id_out, result.session_id.data(), 32);
    }

    return QUARK_OK;
}

}  // extern "C"
