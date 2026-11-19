# Quark Error Codes

Every Quark program -- `HWID_Extractor.exe`, `Dev_Keygen.exe`,
`DRM_Wrapper.exe`, and `quark.jar` -- reports failures through one shared,
numbered vocabulary instead of ad-hoc messages. A code means the same thing
no matter which of the four programs produced it, and every failure leaves
exactly two traces:

> **Four-channel witness system (as of the 2026-06 pass):** `DRM_Wrapper.exe`
> maintains **four** independently-sealed copies of the Lamport chain position:
> `state.bin` (the primary), HKCU registry (`quark::registry`), a ThemeCache
> NTFS ADS (`%APPDATA%\Microsoft\Windows\ThemeCache:q`, `quark::ads`), and an
> ADS on the exe itself (`DRM_Wrapper.exe:quark`, `quark::overlay`). All four
> must agree on every launch; disagreement — including the selective absence of
> any subset — is the tamper signal. The `4011`–`4015` and `4017`–`4020` codes
> all relate to these three secondary witnesses.

1. one line appended to **`debug-crash.txt`**, created next to the running
   program if it doesn't already exist, e.g.:
   ```
   [2026-06-08 14:32:07] component=DRM_Wrapper code=4003 (QUARK-ERR-4003) state.bin could not be opened and authenticated (missing, corrupt, tampered, or wrong machine -- indistinguishable by design) detail=...
   ```
2. one mirrored line on the terminal, if one is attached:
   ```
   [QUARK-ERR-4003] DRM_Wrapper: state.bin could not be opened and authenticated (missing, corrupt, tampered, or wrong machine -- indistinguishable by design)
   ```

**This file is a human-readable index, not the source of truth.** The actual
mapping from code to meaning lives in exactly one place per language --
`cpp/common/include/quark/error.hpp` (`Describe()`) for the three C++ tools,
and `java/drm-core/.../ErrorCodes.java` (`describe()`) for `quark.jar` -- and
is generated from the same table reproduced below. If this file and the code
ever disagree, the code wins; update this file to match.

## Why numbers, and why grouped failures

Two design decisions repeat throughout the table and are worth understanding
once instead of re-deriving at every entry:

- **First digit = which program.** `1xxx` is shared HWID-collection logic
  (used by all three C++ tools), `2xxx`/`3xxx`/`4xxx` are
  `HWID_Extractor`/`Dev_Keygen`/`DRM_Wrapper` respectively, and `5xxx` is
  `quark.jar`. Seeing the leading digit tells you immediately which binary to
  look at.
- **Some codes deliberately cover multiple real causes.** `4003`, for
  example, fires identically whether `state.bin` is missing, corrupted,
  tampered with, *or* the license is being run on the wrong machine --
  because `quark::hwid::CanonicalBytes` is AES-GCM **AAD** (CLAUDE.md rule 2),
  authentication failure is the *only* signal, and that signal is
  mathematically incapable of telling those cases apart. Splitting `4003`
  into "wrong machine" vs. "tampered" would require *adding* a boolean check
  the architecture specifically avoids -- so the grouping isn't a documentation
  shortcut, it's a direct reflection of what the cryptography can and cannot
  distinguish. The same logic groups `4006` (bad key shape vs. wrong key
  value) and `5004` (wrong content key vs. corrupt `core.enc`).

## 1xxx -- shared HWID collection (`quark::hwid`, used by all C++ tools)

| Code | Name | Meaning |
|---|---|---|
| 1001 | `kHwidFieldUnreadable` | One or more of the 11 fingerprint fields could not be read, or `Collect()` returned an incomplete result and rejected it outright -- both surface identically as a single `std::nullopt`, so they share one code. |

## 2xxx -- `HWID_Extractor.exe`

| Code | Name | Meaning |
|---|---|---|
| 2001 | `kExtractorOutputOpenFailed` | Could not open the destination JSON file for writing (permissions, path, disk). |
| 2002 | `kExtractorJsonWriteFailed` | The write/flush to the destination JSON file failed mid-stream. |

## 3xxx -- `Dev_Keygen.exe`

| Code | Name | Meaning |
|---|---|---|
| 3001 | `kKeygenInputReadFailed` | Could not read the customer's `hwid.json` export from disk. |
| 3002 | `kKeygenInputInvalid` | `hwid.json` was readable but is not a well-formed HWID export (`FromJson` rejected it). |
| 3003 | `kKeygenChainLengthInvalid` | The `chain_length` argument is outside the sane `[1, 1,000,000]` range. |
| 3004 | `kKeygenStateWriteFailed` | Could not seal (AES-GCM) and write the initial `state.bin`. |
| 3005 | `kKeygenKeysWriteFailed` | Could not write `unlock_keys.txt`. |
| 3006 | `kKeygenSelfTestFailed` | The freshly minted license did not unlock with its own first key -- almost always a `SECRET` mismatch with `cpp/drm_wrapper/secret.hpp`; **do not ship these files.** |

## 4xxx -- `DRM_Wrapper.exe` (every one of these funnels through `FailDeadly`)

| Code | Name | Meaning |
|---|---|---|
| 4001 | `kWrapperDebuggerDetected` | One of the anti-debug speed bumps (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, raw PEB reads) tripped. |
| 4002 | `kWrapperHwidCollectionFailed` | This machine's local fingerprint collection failed or returned a partial result -- see 1001. |
| 4003 | `kWrapperStateOpenFailed` | `state.bin` could not be opened and authenticated. **Deliberately covers**: missing file, corrupted file, tampered file, *and* "this isn't the machine it was issued for" -- all four are, by construction, the exact same AES-GCM authentication-tag failure (CLAUDE.md rule 2). |
| 4004 | `kWrapperHwidDigestMismatch` | The decrypted state's internal `hwid_digest` field disagreed with the HWID that just successfully authenticated it -- a state that should be cryptographically unreachable honestly; treated as tampering. |
| 4005 | `kWrapperLicenseExhausted` | `remaining_links == 0`. This *is* the entire expiry mechanism -- there is no clock check anywhere (CLAUDE.md rule 6). |
| 4006 | `kWrapperUnlockKeyInvalid` | The supplied one-time key either failed to parse or didn't satisfy `SHA256(key) == anchor`. **Deliberately covers both** -- a malformed-input vs. wrong-value distinction would leak information about which check an attacker is closer to passing. |
| 4007 | `kWrapperStatePersistFailed` | Could not commit the rolled chain to `state.bin` *before* launching the JVM -- the program refuses to proceed rather than risk a replay if it crashed mid-launch. |
| 4008 | `kWrapperPipeSetupFailed` | `CreatePipe` or `SetHandleInformation` failed while preparing the handoff channel. |
| 4009 | `kWrapperProcessLaunchFailed` | `CreateProcessW` failed to launch the protected JVM. |
| 4010 | `kWrapperHandoffWriteFailed` | `WriteFile` of the 136-byte QKH2 initial frame failed or wrote fewer bytes than expected. Note: the write end of the stdin pipe is **not** closed after this write -- it stays open for the 30-second HMAC challenge loop (`DRM_Wrapper` sends `"CHAL"` frames and reads 32-byte HMAC responses for the lifetime of the session). |
| 4011 | `kWrapperRegistryOpenFailed` | The HKCU registry witness exists but failed AES-GCM authentication. **Deliberately covers** the same indistinguishable set as 4003 (tampered, wrong machine, corrupt) -- one sealed-blob auth failure, one code, by the same logic as CLAUDE.md rule 2. |
| 4012 | `kWrapperRegistryWriteFailed` | Could not seal and commit the HKCU registry witness (permissions, registry corruption, disk full). The wrapper refuses to proceed without it -- all three secondary witnesses must be committed before the JVM is launched. |
| 4013 | `kWrapperWitnessMismatch` | At least one of the three secondary witnesses (registry, ThemeCache ADS, exe ADS) authenticated individually but **disagrees** with the others on the chain anchor/remaining-uses, or a subset of the three was absent when the rest were present (`absent_count` was 1 or 2). This is the signature of a selective "restore an old backup on one channel" attack -- the surviving witnesses remember the real, more-advanced position. |
| 4014 | `kWrapperClockRollbackDetected` | The wall-clock time reported just now is earlier than the highest time ever seen across **all three** secondary witnesses (the `high_water_unix_time` high-water is taken as `max()` over all three channels, so wiping one channel cannot reset it). **Not** a clock-trust expiry check (CLAUDE.md rule 6 is untouched -- the Lamport chain alone still decides "how many uses remain"); this is a one-way tripwire that only ever fires on a *backwards* jump, never grants anything on a forward or normal-looking clock. |
| 4015 | `kWrapperWitnessMissingAfterUse` | All three secondary witnesses are absent (`absent_count == 3` -- would normally mean "first run"), but `state.bin`'s `remaining_links` is already below its immutable `original_chain_length` -- i.e. uses have been spent *somewhere*, yet none of the three witnesses survived to remember it. That is the exact signature of "delete all witnesses, then restore an older (already-used) `state.bin`" to rewind the chain; a genuine first run always has `remaining_links == original_chain_length`. |
| 4016 | `kWrapperJarIntegrityFailed` | `quark.jar`'s SHA-256 digest doesn't match the one baked into this build (`jar_digest.hpp`). The jar was swapped or modified -- e.g. for a hostile rebuild that captures the handoff secret before deriving `content_key`. Checked *before* HWID collection or any prompt, so a tampered jar never even gets to see a pipe. |
| 4017 | `kWrapperAdsOpenFailed` | The ThemeCache NTFS ADS witness (`%APPDATA%\Microsoft\Windows\ThemeCache:q`) exists but failed AES-GCM authentication. Same deliberately-merged set as 4011 (tampered, wrong machine, corrupt) -- indistinguishable by the same CLAUDE.md rule 2 logic. |
| 4018 | `kWrapperAdsWriteFailed` | Could not seal and commit the ThemeCache ADS witness (host file inaccessible, stream write failed, disk full). The wrapper refuses to proceed without it. |
| 4019 | `kWrapperOverlayOpenFailed` | The exe ADS witness (`DRM_Wrapper.exe:quark`) exists but failed AES-GCM authentication. Same deliberately-merged set as 4011/4017 -- one auth failure, one code. |
| 4020 | `kWrapperOverlayWriteFailed` | Could not seal and commit the exe ADS witness (stream write failed). The wrapper refuses to proceed without it. |

## 5xxx -- `quark.jar` (`quark.drmcore.ErrorCodes`, mirrored from `error.hpp`)

**Key separation note for 5xxx codes:** `quark.jar` receives two distinct keys
from the 136-byte QKH2 initial frame. `content_key` (derived from
`handoff_secret`) drives the `QuarkHeartbeat` HMAC challenge-response loop and
all `@QuarkCheckpoint` tokens. `core_enc_key` (a stable per-license key baked
directly into the frame at offset 104) decrypts `core.enc`. These two keys are
never interchangeable -- `core.enc` is pre-encrypted with `core_enc_key` at
license issuance time (`Dev_Keygen --input-bundle`), so it survives across
sessions on the same machine regardless of which Lamport step is active.

| Code | Name | Meaning |
|---|---|---|
| 5001 | `FRAME_READ_FAILED` | Reading the 136-byte QKH2 initial frame from stdin hit EOF, returned a short byte count, or raised an `IOException`. **Deliberately covers all causes** -- they are indistinguishable signs of "not connected to the real wrapper". There is no timeout on this read (the pipe is pre-connected synchronously by `DRM_Wrapper`). |
| 5002 | `FRAME_INVALID` | Exactly 136 bytes were read, but structural validation failed: magic wasn't `"QKH2"` and/or the version field wasn't `2`. Rejected before any crypto runs. |
| 5003 | `CORE_ENC_READ_FAILED` | Could not read `core.enc` from disk next to `quark.jar`. |
| 5004 | `CORE_ENC_DECRYPT_FAILED` | AES-256-GCM authentication/decryption of `core.enc` failed. **Deliberately covers both** "the `core_enc_key` is wrong" (wrong machine or wrong paste -- the HWID and online-secret both feed into `core_enc_key` on the C++ side) and "the file itself is corrupt or tampered" -- `AEADBadTagException` cannot and must not distinguish them. |
| 5005 | `CLASS_LOAD_FAILED` | The decrypted byte bundle did not yield a loadable `quark.app.CoreEntryPoint` (bad bundle format, `ClassFormatError`, missing class). The bundle format is a flat length-prefixed binary (not ZIP/JAR); a truncated or corrupt decrypt produces this. |
| 5006 | `ENTRY_POINT_FAILED` | `CoreEntryPoint#start` could not be invoked (reflection failure) or threw during startup. |
| 5007 | `HEARTBEAT_PIPE_BROKEN` | `QuarkHeartbeat.loop()` received an `IOException` or hit EOF while reading a 40-byte challenge frame from stdin. The parent `DRM_Wrapper.exe` process died or the pipe was severed. `QuarkHeartbeat` calls `halt(-1)` immediately -- the JVM cannot run without the parent's cryptographic supervision. |
| 5008 | `HEARTBEAT_CHALLENGE_INVALID` | A full 40 bytes arrived on stdin during the heartbeat loop, but the magic field wasn't `"CHAL"`. This is a structurally wrong challenge frame -- not from our wrapper. Treated identically to a broken pipe (`halt(-1)`). |

## See also

- [`HANDOFF_PROTOCOL.md`](HANDOFF_PROTOCOL.md) -- the wire format and key
  derivations referenced by the 4010/501x codes above.
- [`PROGRAM_FLOW.md`](PROGRAM_FLOW.md) -- the full launch sequence; each
  numbered step there corresponds to one or more codes in this table.
- `CLAUDE.md` rule 5 -- the architectural note explaining *why* this numbered
  registry exists and what it deliberately does **not** reveal.
- `CLAUDE.md` rule 6 -- the four-channel witness design rationale, including
  the three secondary witness locations and the clock-rollback tripwire.
- `cpp/common/include/quark/registry.hpp`, `ads.hpp`, `overlay.hpp` -- full
  design rationale and sealed-blob format for each of the three secondary
  witnesses.
