#pragma once
// The Quark Handoff Protocol v2 (QKH2) -- the wire format between DRM_Wrapper.exe
// (C++) and quark.jar (Java). Three frame types, two anonymous pipes:
//
//   C++ stdin_write  →  Java stdin   : initial frame (once) + challenge frames (every 30s)
//   Java stdout      →  C++ stdout_read : response frames (one per challenge)
//
// See docs/HANDOFF_PROTOCOL.md for the full rationale. This header is the
// authoritative *encoding*; HandoffFrame.java (Java side) mirrors it byte-for-byte.
//
// ─────────────────────────────────────────────────────────────────────────────
// INITIAL FRAME  (136 bytes, written once at startup; pipe stays OPEN)
//
//   offset  size  field
//   ------  ----  -----------------------------------------------------------
//        0     4  magic          = {'Q','K','H','2'}
//        4     4  version        = 2, little-endian u32
//        8    32  handoff_secret  (Java derives content_key from this; challenges only)
//       40    32  session_id      (random; context for all challenge MACs)
//       72    32  initial_seal    (HMAC-SHA256 proof of full DRM flow; stored by Java)
//      104    32  core_enc_key    (stable per license; Java uses this to decrypt core.enc)
//   ------  ----
//      136        kInitialFrameSize
//
// initial_seal = HMAC-SHA256(key=content_key,
//     msg = "SEAL" || anchor_before || anchor_after || SHA256(online_secret) || hwid)
//
// Java cannot independently re-derive initial_seal (it lacks the anchor inputs),
// so it stores it for @QuarkCheckpoint context rather than verifying it.
// The real anti-tamper guarantee is that core.enc GCM auth passes iff core_enc_key
// is correct -- which requires SECRET + HWID + online_secret on this exact machine.
//
// core_enc_key = SHA256("QUARK-CORE-ENC-KEY" || state_key || SHA256(online_secret) || hwid)
// Stable across sessions (excludes rolling new_anchor) so core.enc is encrypted
// once at license issuance and reused every launch on the same machine.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHALLENGE FRAME  (40 bytes, sent by DRM_Wrapper every ~30 s)
//
//   offset  size  field
//   ------  ----  -----------------------------------------------------------
//        0     4  magic   = {'C','H','A','L'}
//        4     4  counter = monotonically increasing u32, little-endian
//        8    32  nonce   = 32 random bytes
//   ------  ----
//       40        kChallengeFrameSize
//
// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE  (32 bytes, Java QuarkHeartbeat → DRM_Wrapper)
//
//   offset  size  field
//   ------  ----  -----------------------------------------------------------
//        0    32  HMAC-SHA256(key=content_key, msg="RESP"||session_id||counter||nonce)
//   ------  ----
//       32        kResponseSize
//
// Verifying the response proves Java still holds content_key -- i.e. it is still
// the legitimate quark.jar running on this machine with this session. counter+nonce
// make each challenge unique; replaying an old response fails a freshly generated nonce.

#include <array>
#include <cstdint>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::handoff {

// Initial frame
inline constexpr char kInitialMagic[4]  = {'Q', 'K', 'H', '2'};
inline constexpr uint32_t kInitialVersion = 2;
inline constexpr size_t kInitialFrameSize = 4 + 4 + 32 + 32 + 32 + 32;  // 136

// Challenge frame
inline constexpr char kChallengeMagic[4] = {'C', 'H', 'A', 'L'};
inline constexpr size_t kChallengeFrameSize = 4 + 4 + 32;  // 40

// Response
inline constexpr size_t kResponseSize = 32;

// Encodes the 136-byte QKH2 initial frame.
// `handoff_secret` crosses the pipe; Java derives content_key (challenges) from it.
// `session_id` is a fresh random 32-byte context for all subsequent challenge MACs.
// `initial_seal` is DeriveInitialSeal(content_key, ...) -- Java stores for @QuarkCheckpoint.
// `core_enc_key` is DeriveCoreEncKey(...) -- Java uses this to decrypt core.enc.
std::vector<uint8_t> EncodeInitialFrame(
    const crypto::AesKey& handoff_secret,
    const std::array<uint8_t, 32>& session_id,
    const crypto::Sha256Digest& initial_seal,
    const crypto::AesKey& core_enc_key);

// Encodes the 40-byte challenge frame DRM_Wrapper sends every ~30 s.
// `counter` increments per challenge; `nonce` is freshly random each time.
std::vector<uint8_t> EncodeChallengeFrame(
    uint32_t counter, const std::array<uint8_t, 32>& nonce);

}  // namespace quark::handoff
