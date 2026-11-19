#pragma once
// The platform-agnostic half of the DRM unlock flow -- HWID collection,
// state.bin open, three-witness cross-check, online-witness fetch/verify,
// chain-exhaustion check, one-time key verification, chain roll-forward +
// persistence, and session key derivation. Extracted so any consumer (the C
// ABI in cpp/quark_c_api, DRM_Wrapper, or a future standalone executable)
// gets this for free instead of re-implementing the same crypto/licensing
// logic.
//
// This function is a pure engine, not a fail-deadly funnel: it returns
// quark::error::Code (kOk on success) rather than reporting through
// quark::error::Report() or calling std::exit() itself. A shared library has
// no business terminating its host process or writing files the host didn't
// ask for -- CLAUDE.md rule 5's "no recovery, immediate exit" discipline is a
// policy for whoever is building a *standalone executable* on top of this
// engine to apply at their own call site, not something quark_core can
// impose on an arbitrary caller (a Python/Go host embedding this via the C
// API would have its interpreter/runtime killed outright, which is not
// something a library is allowed to do to its host).
//
// What deliberately stays OUT of this function:
//   - anti-debug detection (a caller's concern, if it wants one at all)
//   - process/pipe launch and any challenge-response loop -- those are one
//     specific *consumer's* choice of how to use the returned key material
//     (e.g. a JVM-launching wrapper), not something every consumer of this
//     engine needs forced on it.
//   - prompting for the key (the caller already has it by the time it calls
//     this function)
//
// A caller that wants QKH2 framing (quark::handoff::EncodeInitialFrame) has
// everything it needs in UnlockResult: handoff_secret, session_id,
// initial_seal, and core_enc_key.

#include <array>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/error.hpp"
#include "quark/online.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/process_lock.hpp"
#include "quark/platform/witness_store.hpp"

namespace quark::orchestrator {

struct Config {
    std::string build_secret;   // kBuildSecret equivalent -- see quark/token.hpp
    std::string state_path;     // path to state.bin

    // P-256 public key verifying the online-witness paste's signature (see
    // quark::online). Only consulted when the license has a non-empty
    // paste_id; dev-mode licenses (empty paste_id) never touch this field.
    online::EcPublicKey ec_public_key{};
};

struct UnlockResult {
    crypto::AesKey content_key{};              // HMAC key for a challenge-response loop, if the caller wants one
    crypto::AesKey core_enc_key{};              // decrypts core.enc / the caller's equivalent protected payload
    crypto::AesKey handoff_secret{};            // needed verbatim to build a QKH2 initial frame
    crypto::Sha256Digest initial_seal{};        // ditto -- proves to the far end that the full flow ran
    std::array<uint8_t, 32> session_id{};      // fresh per-session context, e.g. for challenge MACs
};

// Runs the full pre-launch DRM flow against `hwid_backend` and exactly three
// `witnesses` (secondary witness channels -- see CLAUDE.md rule 6's
// four-channel design; state.bin is the primary, these three are the
// independently-sealed secondaries). `candidate_key` is the user's one-time
// unlock key (hex-encoded, as accepted by quark::lamport::ParseKey).
//
// `lock`, if non-null, is Acquire()'d (blocking) before state.bin is ever
// touched and Release()'d on every return path -- real concurrent-launch
// testing showed that without this, two processes racing on the same
// license can both Load() the same pre-roll anchor and both independently
// redeem the SAME single-use key (see quark/platform/process_lock.hpp). A
// null lock preserves the pre-existing, unlocked behavior for callers that
// cannot have two instances racing on one license by construction.
//
// Returns quark::error::Code::kOk and populates `out` on success. Any other
// return value means `out` was not populated and the caller must treat the
// license as unusable -- CLAUDE.md rule 2's "tampering and wrong-machine
// must be indistinguishable" still holds; the *code* only exists for
// diagnostics, callers must not branch on which one came back to decide
// whether to retry or partially trust the result.
error::Code RunUnlockFlow(const Config& config,
                           platform::IHwidBackend& hwid_backend,
                           std::array<platform::IWitnessStore*, 3> witnesses,
                           const std::string& candidate_key,
                           UnlockResult& out,
                           platform::IProcessLock* lock = nullptr);

}  // namespace quark::orchestrator
