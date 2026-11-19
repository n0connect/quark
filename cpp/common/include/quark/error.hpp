#pragma once
// Quark's shared error-code registry and crash-reporting sink. Every Quark
// program -- HWID_Extractor, Dev_Keygen, DRM_Wrapper, and (mirrored, since
// C++ and Java can't share an enum) quark.jar -- reports failures through
// this single, numbered vocabulary instead of ad-hoc strings, so that:
//
//   - a code seen in a terminal or in debug-crash.txt always means exactly
//     one thing, regardless of which of the four programs produced it;
//   - the mapping from code -> meaning lives in exactly one place per
//     language (this file for C++, ErrorCodes.java for Java) -- there is no
//     separate "error code reference" document to fall out of sync, because
//     `Describe()` *is* the reference, runnable and greppable;
//   - every failure, expected or not, leaves the same two traces: one line
//     on the terminal (if attached) and one line appended to
//     `debug-crash.txt` next to the executable.
//
// Numbering convention (first digit = which program produced it):
//   1xxx  quark_common   -- shared HWID-collection failures (any tool)
//   2xxx  HWID_Extractor
//   3xxx  Dev_Keygen
//   4xxx  DRM_Wrapper
//   5xxx  quark.jar (Java side -- see ErrorCodes.java, numbers match exactly)
//
// NOTE on CLAUDE.md rule 5 ("fail-deadly... no diagnostic message to the
// user"): this registry is a deliberate, explicit broadening of that rule --
// requested so that crashes are debuggable in the field -- and every call
// site that reports a DRM_Wrapper/quark.jar code still terminates exactly the
// same way (`exit(1)` / `System.exit(1)`, no recovery, no behavioral branch
// an attacker could exploit). What changed is *visibility* of the failure,
// not its *consequence* -- the program still fails exactly as deadly as
// before, it just now says, in one numbered word, why.

#include <cstdint>

namespace quark::error {

enum class Code : uint32_t {
    // Sentinel for "no error" -- exists for return-value-style APIs (e.g.
    // quark::orchestrator, the C ABI in cpp/quark_c_api) that need a success
    // value to return; never passed to Report() (there is nothing to report).
    kOk = 0,

    // --- 1xxx: shared HWID collection (quark_common, used by all tools) ----
    kHwidFieldUnreadable     = 1001,  // one or more of the 11 fingerprint fields could not be read, or the result was incomplete

    // --- 2xxx: HWID_Extractor.exe -------------------------------------------
    kExtractorOutputOpenFailed = 2001,  // could not open the destination JSON file for writing
    kExtractorJsonWriteFailed  = 2002,  // write/flush to the destination JSON file failed mid-stream

    // --- 3xxx: Dev_Keygen.exe ------------------------------------------------
    kKeygenInputReadFailed    = 3001,  // could not read the customer's hwid.json from disk
    kKeygenInputInvalid       = 3002,  // hwid.json parsed but is not a well-formed HWID export
    kKeygenChainLengthInvalid = 3003,  // chain_length argument out of the sane [1, 1_000_000] range
    kKeygenStateWriteFailed   = 3004,  // could not seal/write the initial state.bin
    kKeygenKeysWriteFailed    = 3005,  // could not write unlock_keys.txt
    kKeygenSelfTestFailed     = 3006,  // freshly minted state.bin did not unlock with its own first key
    kKeygenPastePostFailed    = 3007,  // could not POST the online-witness blob to rentry.co (network, CSRF, or API error)

    // --- 4xxx: DRM_Wrapper.exe (every one of these -> FailDeadly) -----------
    kWrapperDebuggerDetected     = 4001,  // anti_debug speed bumps tripped
    kWrapperHwidCollectionFailed = 4002,  // local Collect() failed or returned a partial fingerprint
    kWrapperStateOpenFailed      = 4003,  // state.bin missing/corrupt/tampered/wrong-machine (one code, deliberately -- see CLAUDE.md rule 2)
    kWrapperHwidDigestMismatch   = 4004,  // decrypted state's internal hwid_digest disagreed with the AAD that just authenticated it (should be unreachable honestly)
    kWrapperLicenseExhausted     = 4005,  // remaining_links == 0 -- the entire expiry mechanism
    kWrapperUnlockKeyInvalid     = 4006,  // supplied key failed to parse, or SHA256(key) != anchor
    kWrapperStatePersistFailed   = 4007,  // could not commit the rolled chain to state.bin before launch
    kWrapperPipeSetupFailed      = 4008,  // CreatePipe / SetHandleInformation failed
    kWrapperProcessLaunchFailed  = 4009,  // CreateProcessW failed
    kWrapperHandoffWriteFailed   = 4010,  // WriteFile of the handoff frame was short or failed
    kWrapperRegistryOpenFailed   = 4011,  // registry witness exists but failed to authenticate (tampered/wrong machine)
    kWrapperRegistryWriteFailed  = 4012,  // could not seal/commit the registry witness (registry permissions, etc.)
    kWrapperWitnessMismatch      = 4013,  // state.bin and the registry witness disagree on the chain position -- a state.bin restore/rewind
    kWrapperClockRollbackDetected = 4014, // wall-clock time moved backwards relative to the high-water mark -- clock manipulation
    kWrapperWitnessMissingAfterUse = 4015, // registry witness absent, but state.bin shows uses already spent -- "delete witness, restore an old (used) state.bin" rewind attempt
    kWrapperJarIntegrityFailed   = 4016,  // quark.jar's SHA-256 doesn't match the digest embedded in this build -- the jar was swapped/modified
    kWrapperAdsOpenFailed        = 4017,  // NTFS-ADS witness exists but failed to authenticate (tampered, wrong machine, or corrupt)
    kWrapperAdsWriteFailed       = 4018,  // could not seal/write the NTFS-ADS witness
    kWrapperOverlayOpenFailed    = 4019,  // PE-overlay witness exists but failed to authenticate (tampered, wrong machine, or corrupt)
    kWrapperOverlayWriteFailed   = 4020,  // could not seal/write the PE-overlay witness into DRM_Wrapper.exe
    kWrapperOnlineFetchFailed    = 4021,  // could not fetch the online-witness paste from rentry.co (network failure or paste deleted -- revocation)
    kWrapperOnlineDecryptFailed  = 4022,  // paste blob failed AES-256-GCM authentication (wrong machine, tampered paste, or wrong SECRET)
    kWrapperOnlineSigInvalid     = 4023,  // P-256 ECDSA signature inside the paste did not verify against the embedded public key
    kWrapperLockFailed           = 4024,  // could not acquire the per-license process lock (see quark::platform::IProcessLock)

    // --- 5xxx: quark.jar (Java side -- ErrorCodes.java mirrors these) -------
    kJarFrameReadFailed     = 5001,  // stdin read timed out, hit EOF early, or had trailing bytes
    kJarFrameInvalid        = 5002,  // structurally wrong frame: bad magic and/or unsupported version
    kJarCoreEncReadFailed   = 5003,  // could not read core.enc from disk
    kJarCoreEncDecryptFailed = 5004, // AES-GCM auth/decrypt failed -- wrong key, tampering, or both
    kJarClassLoadFailed     = 5005,  // decrypted bundle did not yield a loadable CoreEntryPoint
    kJarEntryPointFailed    = 5006,  // CoreEntryPoint#start threw or could not be invoked
};

// Returns a short, fixed, human-readable description of `code` -- the single
// source of truth for "what does error N mean". Never allocates, never null.
const char* Describe(Code code);

// The one funnel every Quark program's failure paths go through:
//   1. Appends one line to debug-crash.txt next to the running executable
//      (created on first use): timestamp, component, numeric code, description,
//      and an optional free-form `detail` (kept short and non-sensitive --
//      e.g. "argc=2", never key material or HWID values).
//   2. If a console is attached, prints "[QUARK-ERR-NNNN] <component>: <description>"
//      (plus detail, if any) to stderr.
//
// `Report` does not terminate the process -- callers decide what happens
// next (HWID_Extractor/Dev_Keygen return a non-zero exit code and keep
// their own usage-message conventions; DRM_Wrapper's FailDeadly reports
// then immediately exits; quark.jar's analogous funnel does the same).
void Report(Code code, const char* component, const char* detail = nullptr);

}  // namespace quark::error
