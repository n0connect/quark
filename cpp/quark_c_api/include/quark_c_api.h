#ifndef QUARK_C_API_H
#define QUARK_C_API_H
/*
 * Quark's C ABI -- the language-agnostic surface over quark_core's
 * cryptographic/licensing engine (Lamport chain, state.bin, the four-channel
 * witness system). This is a plain C header (no C++ types cross this
 * boundary) so it can be consumed from Go (cgo), Python (ctypes/cffi), Java
 * (JNI/Panama), Rust (bindgen), or C/C++ directly, in-process -- no pipes,
 * no child process, no JVM-specific assumptions anywhere in this file.
 *
 * What this library does NOT do, by design:
 *   - it never terminates your process. Every function returns a
 *     quark_error_t; QUARK_OK (0) means success, anything else means the
 *     operation did not complete and no output buffer was written. Quark's
 *     "fail-deadly, no recovery" philosophy (see CLAUDE.md rule 5) is still
 *     the *recommended* posture for a host built on this library, but a
 *     shared library has no right to kill its host process to enforce that
 *     -- that decision belongs to your code, at your call site.
 *   - it never prompts for input, launches a subprocess, or writes a log
 *     file. Every side effect is exactly what the function's own contract
 *     describes (e.g. quark_state_mint writes the file at `state_path`, and
 *     nothing else).
 *   - it never accepts a caller-supplied hardware fingerprint for the
 *     unlock path. quark_unlock() always collects HWID fresh, locally, from
 *     this exact machine -- accepting one as a parameter there would let a
 *     caller bypass hardware binding entirely, which defeats the point of
 *     the whole system. (quark_hwid_collect() exists separately for the
 *     legitimate case of shipping a fingerprint to a license-issuing
 *     machine that is NOT the one being unlocked.)
 *
 * Buffers: every fixed-size cryptographic output (keys, digests, session
 * IDs) is exactly 32 bytes and is always written into caller-owned memory --
 * this library never allocates memory it expects the caller to free, which
 * would require both sides to agree on an allocator across an FFI boundary.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Error codes.
 *
 * Non-negative values are shared 1:1 with quark::error::Code
 * (cpp/common/include/quark/error.hpp) -- a numbered code means the same
 * thing everywhere in Quark, across every language and every program that
 * can produce it. Negative values are specific to this C boundary itself
 * (a misuse of this API's own contract, e.g. a null pointer or an undersized
 * buffer) and can never collide with the shared registry.
 * ------------------------------------------------------------------------ */
typedef int32_t quark_error_t;

#define QUARK_OK 0

/* C-API-specific: argument/usage errors, not DRM-flow failures. */
#define QUARK_ERR_INVALID_ARGUMENT (-1)
#define QUARK_ERR_BUFFER_TOO_SMALL (-2)
#define QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM (-3)

/* Shared with quark::error::Code -- see quark/error.hpp for the full
 * rationale behind each one; the numeric values below must never be
 * renumbered without renumbering that enum identically (a static_assert in
 * quark_c_api.cpp enforces this at build time). */
#define QUARK_ERR_HWID_FIELD_UNREADABLE 1001
#define QUARK_ERR_CHAIN_LENGTH_INVALID 3003
#define QUARK_ERR_STATE_WRITE_FAILED 3004
#define QUARK_ERR_HWID_COLLECTION_FAILED 4002
#define QUARK_ERR_STATE_OPEN_FAILED 4003
#define QUARK_ERR_HWID_DIGEST_MISMATCH 4004
#define QUARK_ERR_LICENSE_EXHAUSTED 4005
#define QUARK_ERR_UNLOCK_KEY_INVALID 4006
#define QUARK_ERR_STATE_PERSIST_FAILED 4007
#define QUARK_ERR_WITNESS0_OPEN_FAILED 4011
#define QUARK_ERR_WITNESS0_WRITE_FAILED 4012
#define QUARK_ERR_WITNESS_MISMATCH 4013
#define QUARK_ERR_CLOCK_ROLLBACK_DETECTED 4014
#define QUARK_ERR_WITNESS_MISSING_AFTER_USE 4015
#define QUARK_ERR_WITNESS1_OPEN_FAILED 4017
#define QUARK_ERR_WITNESS1_WRITE_FAILED 4018
#define QUARK_ERR_WITNESS2_OPEN_FAILED 4019
#define QUARK_ERR_WITNESS2_WRITE_FAILED 4020
#define QUARK_ERR_ONLINE_WITNESS_UNSUPPORTED 4021
#define QUARK_ERR_LOCK_FAILED 4024
#define QUARK_ERR_PAYLOAD_DECRYPT_FAILED 5004 /* shares quark::error::Code's Java-side "core.enc failed to authenticate/decrypt" number -- same operation, generalized past the JVM-specific case it was written for */

/* Short, human-readable description of `code`. Never returns NULL -- an
 * unrecognized code returns a fixed "unrecognized error code" string, same
 * as quark::error::Describe. */
const char* quark_error_describe(quark_error_t code);

/* ---------------------------------------------------------------------------
 * HWID.
 * ------------------------------------------------------------------------ */

/* Collects this machine's hardware fingerprint via whichever platform
 * backend this library was built for (selected at compile time -- see
 * cpp/quark_c_api/CMakeLists.txt). Writes the canonical, deterministic byte
 * serialization to `canonical_out` (the exact bytes used as AAD/KDF input
 * everywhere else in this API) and the actual length to `*canonical_len_out`.
 *
 * Returns QUARK_ERR_BUFFER_TOO_SMALL (without touching `*canonical_len_out`)
 * if `canonical_cap` is insufficient -- call once with canonical_cap=0 and
 * canonical_out=NULL to discover the required size, matching the common C
 * "ask for the size first" convention. Returns
 * QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM if this library was not built with
 * a platform HWID backend at all.
 */
quark_error_t quark_hwid_collect(uint8_t* canonical_out, size_t canonical_cap,
                                  size_t* canonical_len_out);

/* ---------------------------------------------------------------------------
 * Dev-side license issuance.
 * ------------------------------------------------------------------------ */

/* Builds a fresh Lamport chain of `chain_length` one-time links from a
 * random seed. `anchor_out` receives H^n(seed) (32 bytes) -- the value
 * quark_state_mint seals into state.bin. `keys_out` receives all
 * `chain_length` intermediate preimages, 32 bytes each, in the order a
 * customer consumes them (H^{n-1}(seed) first ... H^0(seed) last); `keys_cap`
 * must be at least `chain_length * 32` bytes or this fails with
 * QUARK_ERR_BUFFER_TOO_SMALL without writing anything. `chain_length` must be
 * in [1, 1000000] (mirrors Dev_Keygen's existing sanity bound).
 */
quark_error_t quark_lamport_mint_chain(uint32_t chain_length, uint8_t anchor_out[32],
                                        uint8_t* keys_out, size_t keys_cap);

/* Seals a fresh state.bin at `state_path`, bound to
 * `hwid_canonical`/`hwid_canonical_len` (typically obtained by calling
 * quark_hwid_collect() on the machine the license is FOR, then transmitted
 * by whatever means the caller chooses to the machine minting the license).
 * `anchor`/`chain_length` should come from quark_lamport_mint_chain.
 *
 * Always mints a dev-mode license (no online witness / empty paste_id) --
 * this library has no portable HTTPS client yet, so online-witness support
 * is not exposed here. See docs/PLAN.md for the tracked follow-up.
 */
quark_error_t quark_state_mint(const char* state_path, const char* build_secret,
                                const uint8_t* hwid_canonical, size_t hwid_canonical_len,
                                const uint8_t anchor[32], uint32_t chain_length);

/* Seals `plaintext` -- your protected payload (bytecode, a script, a config
 * blob, whatever your protected application needs to function) -- so that
 * only quark_unlock_and_decrypt(), on the exact machine `hwid_canonical`
 * identifies, with a valid unlock key, can recover it. Uses the same
 * derivation quark_unlock_and_decrypt re-derives internally after a
 * successful unlock (see quark/token.hpp's DeriveCoreEncKey), so whatever
 * you seal here with the license-issuing machine's knowledge of
 * `hwid_canonical` is exactly what a real customer unlock produces.
 *
 * `sealed_out`/`sealed_cap`: pass sealed_out=NULL, sealed_cap=0 first to
 * learn the required size via `*sealed_len_out`, matching
 * quark_hwid_collect's convention.
 */
quark_error_t quark_seal_payload(const char* build_secret,
                                  const uint8_t* hwid_canonical, size_t hwid_canonical_len,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  uint8_t* sealed_out, size_t sealed_cap,
                                  size_t* sealed_len_out);

/* ---------------------------------------------------------------------------
 * Unlock flow.
 * ------------------------------------------------------------------------ */

typedef enum {
    QUARK_WITNESS_KIND_FILE = 0,     /* portable file-backed channel -- any OS */
    QUARK_WITNESS_KIND_XATTR = 1,    /* macOS/Linux extended-attribute channel */
    QUARK_WITNESS_KIND_REGISTRY = 2, /* Windows HKCU registry channel */
    QUARK_WITNESS_KIND_ADS = 3,      /* Windows NTFS alternate-data-stream channel */
    QUARK_WITNESS_KIND_OVERLAY = 4,  /* Windows PE-overlay-on-self channel */
} quark_witness_kind_t;

typedef struct {
    int32_t kind;          /* a quark_witness_kind_t value */
    const char* path;      /* FILE/XATTR: filesystem path (must already exist for XATTR). Ignored for REGISTRY/ADS/OVERLAY (fixed locations, see quark/registry.hpp etc). */
    const char* attr_name; /* XATTR only: attribute name (Linux: without the "user." prefix -- added automatically). Ignored otherwise. */
    char magic[4];         /* FILE/XATTR only: 4-byte channel tag inside the sealed blob, any 4 bytes you like. Ignored otherwise (fixed legacy on-disk format). */
    const char* name;      /* Human-readable channel label (diagnostics only, never affects behavior). */
} quark_witness_channel_t;

/* Runs the complete unlock flow AND decrypts your protected payload in the
 * same call -- this is the primary, recommended entry point, and
 * deliberately the ONLY way to reach the payload's plaintext through this
 * API. `core_enc_key` never crosses this boundary at all: this function
 * derives it internally, uses it to AES-256-GCM-decrypt `sealed_payload`
 * (as produced by quark_seal_payload), and hands back plaintext bytes if and
 * only if EVERY step succeeded -- HWID collection, state.bin
 * authentication, the three-witness cross-check, chain-exhaustion and
 * key-verification, AND the payload's own AEAD authentication.
 *
 * This closes a real gap a raw-key-returning API would leave open: if this
 * function instead handed you core_enc_key and trusted you to decrypt your
 * payload yourself, a host that only checked "did this return QUARK_OK?"
 * without actually using the key would have reintroduced exactly the
 * boolean-trap pattern CLAUDE.md rule 3 exists to prevent -- patch the
 * return value, skip the check, done. There is no such shortcut here: the
 * function's entire externally-visible output *is* the decrypted payload,
 * so a wrong key produces wrong bytes, not a patchable "yes/no".
 *
 * `plaintext_out`/`plaintext_cap`: pass plaintext_out=NULL, plaintext_cap=0
 * first to learn the required size via `*plaintext_len_out` (the decrypt
 * still has to succeed for this to return a size -- there is no way to
 * learn a payload's length without the correct key).
 *
 * `content_key_out`/`session_id_out` are optional (pass NULL for either you
 * don't need) -- they exist only for callers who additionally want to run
 * their own liveness/heartbeat scheme; unlike core_enc_key, holding
 * content_key alone does not grant access to the protected payload, so
 * exposing it does not reintroduce the boolean-trap concern above.
 *
 * Safe to call concurrently (multiple threads, or multiple processes) against
 * the SAME state_path with the SAME candidate_key: internally acquires a
 * real OS file lock (flock/LockFileEx) around the read-verify-roll sequence
 * before state.bin is ever touched, so at most one caller can ever redeem a
 * given single-use key -- found necessary via real concurrent-launch testing
 * (see CLAUDE.md rule 6's IProcessLock paragraph). A caller that races two
 * calls with the SAME key should expect exactly one QUARK_OK and the other
 * QUARK_ERR_UNLOCK_KEY_INVALID/QUARK_ERR_LICENSE_EXHAUSTED, not two QUARK_OKs.
 *
 * On any non-QUARK_OK return, no output parameter is written. Per CLAUDE.md
 * rule 2's spirit, do not build application logic that branches on *which*
 * non-OK code came back beyond logging it -- treat every failure as "this
 * license is not usable right now."
 */
quark_error_t quark_unlock_and_decrypt(const char* state_path, const char* build_secret,
                                        const quark_witness_channel_t witnesses[3],
                                        const char* candidate_key,
                                        const uint8_t* sealed_payload, size_t sealed_payload_len,
                                        uint8_t* plaintext_out, size_t plaintext_cap,
                                        size_t* plaintext_len_out,
                                        uint8_t content_key_out[32] /* nullable */,
                                        uint8_t session_id_out[32] /* nullable */);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // QUARK_C_API_H
