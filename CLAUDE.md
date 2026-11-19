# Quark — Cross-Platform Native DRM & Licensing Architecture

## What this is
Quark is a **native C++ DRM/licensing engine** exposed as a language-agnostic
library: cryptographic interlocking, hardware-fingerprint binding, and a
Lamport one-time-key hash chain, callable **in-process** from any language
with an FFI (Go/cgo, Python/ctypes, Java/JNI, Rust/bindgen, C/C++ directly)
through the plain `extern "C"` surface in `cpp/quark_c_api`
(`quark_c_api.h`). There is no server component — everything is offline and
hardware-bound. The original Java/JVM pipeline (`DRM_Wrapper.exe` +
`quark.jar`, talking over the QKH2 pipe protocol) still exists and is fully
supported, but it is now **one consumer built on the engine**, not the
engine's only interface — see Phase VIII of `docs/PLAN.md` for the pivot
rationale and what changed.

Core principle: **Cryptographic Interlocking + Zero External Dependencies**.
A protected application cannot run without a decryption key that only this
engine can produce, and the engine cannot produce that key without a valid
hardware fingerprint + a valid Lamport chain step. What the caller *does*
with that key — decrypt an in-process payload, reconstruct and run real
machine code through `cpp/quark_codecipher`, hand it across a pipe to a JVM,
anything else — is the caller's choice, not something baked into the engine.

## Mission (do not forget this — re-read before any architectural decision)
Quark's end goal is a **Windows + Linux + macOS DRM system built on one shared,
modular cryptographic core**, with a thin, native, per-OS platform layer under
it. Both halves — the core and each OS's platform layer — must independently
be strong, modular, and easy to follow; neither side is allowed to become a
dumping ground. The eventual possibility of open-sourcing this repo is a
secondary motivation, not the reason for the quality bar — the real reason is
that a future hardening pass (obfuscation, anti-debugging, anti-tamper) is
only worth building on top of a codebase that is *already* clean, simple, and
correct. Sloppy code hidden behind obfuscation is still sloppy code.

## Engineering rules (non-negotiable — restated because they have been
## forgotten before; do not let that happen again)

1. **No mocks. Ever. Anywhere. Including tests.** Every test in this repo
   compiles and runs for real, directly against the real operating system it
   targets — real mbedTLS, real filesystem, real registry/ADS/SMBIOS/IOKit/
   sysfs calls, real pipes. A "unit test" that fakes out an OS call to avoid
   needing the real OS is not a Quark test; delete it and either (a) restrict
   what's under test to code that has no OS dependency (this is *why* the
   platform-agnostic core exists — it can be tested for real on any machine,
   because on any machine it really is running, not simulating), or (b) run
   the test on the real target OS (a real Linux kernel, a real Windows
   install — a VM or CI runner is fine, a mock/stub library is not).
   **All build and test activity happens under `sandbox/`** (e.g.
   `sandbox/build-macos`, `sandbox/build-linux`) — never in the repo root or
   anywhere else on disk. This is a hard boundary, not a preference: it keeps
   real-OS testing (rule 1) from ever touching state outside a directory the
   user has explicitly set aside for it. Tests that need a scratch file must
   use a path relative to the test binary's working directory, never
   `std::filesystem::temp_directory_path()` or any other system-wide temp
   location — a real OS temp dir is still "outside the sandbox" even though
   it's real, not mocked.
2. **Config over hardcoding.** No value or feature lives inline in source
   unless it is cryptographically load-bearing enough that hardcoding is the
   *safer* choice (e.g. domain-separation strings baked into a KDF, where a
   config file would just move the attack surface without adding value). If
   it's a path, a URL, a timeout, a retry count, a chain length default, a
   feature toggle — it belongs in config, not in a `constexpr` scattered
   through the source. Every executable reads its tunables from a config file
   at startup; only genuinely security-critical constants are the exception,
   and that exception must be justified in a comment at the point of use, not
   assumed.
3. **Simple and secure code, nothing else.** Small, direct, traceable
   implementations over clever ones. This applies equally to the
   platform-agnostic core and to every OS's platform layer — "it's just the
   Windows-specific part" is not an excuse for lower quality than the core.
4. **DevOps must stay low-effort.** The single biggest quality signal for
   this repo is how little manual ceremony it takes to prove the whole
   cross-platform tree still builds and passes. Prefer CI running on real
   OS-native runners (real Windows, real Linux, real macOS — not
   cross-compiled artifacts nobody actually executes) over local
   toolchain-juggling. See "Cross-platform build & test strategy" below for
   the concrete approach and why cross-compilation was deliberately rejected.

## Cross-platform build & test strategy
Quark is split into two kinds of code, and the split is architectural, not
cosmetic:

- **`quark_core`** (`cpp/common`: `crypto`, `token`, `lamport`, `state`,
  `handoff`, `error`) — zero Win32/POSIX/OS-specific API calls, only mbedTLS +
  the standard library. This is where nearly all of the actual cryptographic
  and licensing *logic* lives (KDF derivations, the Lamport chain, the
  state.bin codec, the QKH2 frame codec). It configures, builds, and — per
  rule 1 above — is genuinely, non-mocked *tested* on whatever machine you're
  sitting at, because it has no OS dependency to fake. This is expected to be
  where the large majority of day-to-day development happens.
- **`quark_platform_<os>`** — the genuinely OS-specific capability layer:
  hardware fingerprinting and tamper-evident local storage, each implementing
  the shared `quark::platform::IHwidBackend` / `IWitnessStore` contracts
  (`cpp/common/include/quark/platform/*.hpp`) so `quark_core` and
  `DRM_Wrapper`'s orchestration logic never need to know which OS they're
  running on. Status per OS:
  - **Windows** (`quark_platform_win`): fully implemented and shipped
    (`hwid.cpp`, `registry.cpp`, `ads.cpp`, `overlay.cpp`, `online.cpp` +
    thin `IHwidBackend`/`IWitnessStore` adapters in `platform_win/`).
  - **macOS** (`quark_platform_macos`): implemented and *verified for real*
    on real macOS hardware (`sysctlbyname`/IOKit/DiskArbitration for HWID,
    xattrs for two of the three witness channels — the third is the
    portable `FileWitnessStore` below). See `quark/platform/macos/*.hpp` for
    the field-by-field mapping from the Windows design and the honest
    deltas (no per-DIMM RAM identity; Hardware UUID survives an OS
    reinstall, unlike Windows' MachineGuid).
  - **Linux** (`quark_platform_linux`): implemented and verified for real
    inside a real Linux kernel (container or VM) — `/proc/cpuinfo`,
    `/etc/machine-id`, world-readable `/sys/class/dmi/id/*` fields, boot
    device UUID via `/proc/self/mountinfo` + `/dev/disk/by-uuid`, xattrs
    (`user.` namespace, kernel-enforced for unprivileged access) for the
    other two witness channels. Deliberately does **not** read
    `product_uuid`/`board_serial` (root-only, mode 0400 on stock kernels) —
    requiring root would be a worse posture than Windows' deliberately
    unprivileged design; see `quark/platform/linux/hwid_backend_linux.hpp`
    for the full trade-off. Scoped to x86_64 / UEFI-booted Linux (DMI is an
    x86-firmware convention; bare-metal ARM has no `/sys/class/dmi/id`).
- **`quark::platform::FileWitnessStore`** (portable, lives in `quark_core`) —
  a plain-file-backed `IWitnessStore` using `quark::witness::Seal`/`Unseal`
  (the shared AES-GCM witness codec, byte-identical to what `registry.cpp`
  hand-rolls). Used as the "config directory" channel on both macOS and
  Linux — no OS-specific code needed for that channel at all.

**Why cross-compilation is deliberately not the answer:** a Windows `.exe`
cross-compiled from macOS via `clang-cl`/`llvm-mingw` still cannot be
*executed or tested* on macOS — it can only be checked for "does it compile",
which is a weak guarantee and produces exactly the kind of untested artifact
rule 1 forbids trusting. The chosen alternative is a **CI matrix on real
OS-native runners** (genuine Windows, Linux, and macOS machines — GitHub
Actions' `windows-latest`/`ubuntu-latest`/`macos-latest` or equivalent):
`quark_core` builds and its real tests run on all three on every push; each
`quark_platform_<os>` target only builds and runs on its own runner. This is
what makes the "az efor, yüksek kalite" DevOps goal achievable — one push
proves the whole tree everywhere, without a developer manually round-tripping
through a Windows VM for every change that isn't actually Windows-specific.
The Windows ARM Parallels VM (or an eventual Linux VM/CI runner) is still the
right tool specifically for developing and testing that OS's platform layer —
it is not being eliminated, only scoped down to the code that actually needs
it.

## Target platform
- **Cross-platform by design; all three platform layers now exist, and
  every module builds and runs on every OS.** `quark_core` builds anywhere
  (any C++17 compiler + mbedTLS). All three platform layers
  (`quark_platform_win`/`quark_platform_macos`/`quark_platform_linux`) are
  fully implemented. As of docs/superpowers/specs/2026-07-05-cross-platform-
  porting-roadmap.md, all six originally Windows-only executables
  (`HWID_Extractor`, `Dev_Keygen`, `DRM_Wrapper`, `Paste_Test`,
  `handoff_spy`, `quark-runtime-c`) are cross-platform and have been
  verified for real on macOS. Linux verification of the fully-assembled
  executables (as opposed to the underlying `quark_platform_linux` library,
  independently verified earlier) and a Windows re-verification of
  `DRM_Wrapper`'s refactored `main.cpp` are the two remaining gaps -- see
  `docs/PLAN.md`'s Phase XII for the exact scope of what's confirmed versus
  outstanding.
- Build authority: this repo currently has **compile-only permission** — do not
  package/sign/ship installers or run end-to-end license issuance against real
  customer hardware without explicit approval.

## Module map

### Deployed (C++)
Platform scope is noted per row — `quark_core` and `quark_c_api` are
cross-platform; `quark_codecipher` and `quark_linkload` are macOS-only so
far; the rest are Windows-only today.

| Module | Role | Output |
|---|---|---|
| `cpp/hwid_extractor` | Collects an 11-field machine fingerprint (CPU identity+brand+cores, SMBIOS board/BIOS/per-slot RAM, system disk + volume serials, MAC, MachineGuid) → JSON | `HWID_Extractor.exe` |
| `cpp/dev_keygen` | Dev-side: builds Lamport `H^n(x)` chain, emits `state.bin` + posts online-witness paste; with `--input-bundle` also encrypts `app.bundle → core.enc` using `core_enc_key` (stable per license) | `Dev_Keygen.exe` |
| `cpp/drm_wrapper` | Customer-side shield: pins `quark.jar` SHA-256, verifies key, cross-checks state.bin against three secondary witnesses (registry + ThemeCache ADS + exe ADS), fetches + verifies paste.rs online witness, derives `content_key`, launches JVM via QKH2 two-pipe protocol, stays alive and sends 30-s HMAC challenges for session lifetime | `DRM_Wrapper.exe` |
| `cpp/common` (`quark_core`) | Platform-agnostic: AES-256-GCM/SHA-256/HMAC-SHA256 (mbedTLS static), KDF (`quark::token`), Lamport chain, state.bin codec, QKH2 handoff frame codec, numbered error registry, shared witness codec (`quark::witness::Seal`/`Unseal`), portable `FileWitnessStore`, the `quark::orchestrator::RunUnlockFlow` engine (pure, non-exiting, returns `quark::error::Code` — see Phase VIII of `docs/PLAN.md`), and a minimal `quark::config` key=value reader. Builds and tests on any OS — see "Cross-platform build & test strategy" | static lib |
| `cpp/common` (`quark_platform_win`, Windows only) | HWID collection (SMBIOS/CPUID/registry/iphlpapi), registry/ADS/overlay witness codecs, WinHTTP online paste codec, `IHwidBackend`/`IWitnessStore` adapters | static lib |
| `cpp/common` (`quark_platform_macos`, macOS only) | `IHwidBackend` via sysctlbyname/IOKit/DiskArbitration, `IWitnessStore` via xattrs — verified for real on macOS hardware | static lib |
| `cpp/common` (`quark_platform_linux`, Linux only) | `IHwidBackend` via `/proc`, `/etc/machine-id`, world-readable DMI, `IWitnessStore` via `user.`-namespaced xattrs — verified for real on a real Linux kernel | static lib |
| `cpp/quark_c_api` | **The language-agnostic entry point.** Plain `extern "C"` surface over quark_core: `quark_hwid_collect`, `quark_lamport_mint_chain`, `quark_state_mint`, `quark_seal_payload`, `quark_unlock_and_decrypt`, `quark_error_describe`. `core_enc_key` never crosses this boundary — `quark_unlock_and_decrypt` is the only way to reach a sealed payload's plaintext, closing the boolean-trap gap a raw-key-returning API would leave open. Never terminates its host process or prompts for input — every function returns a `quark_error_t` and the caller decides what happens next. Links whichever `quark_platform_<os>` target the current OS already builds; witness channels are OS-agnostic at the call site via `quark_witness_channel_t` | `libquark_c` (shared) |
| `cpp/quark_codecipher` (Phase XVI, macOS only) | Cryptographically interlocked protected logic for native/cross-language `quark_c_api` consumers, without a new instruction set — see "Quark Codecipher" below. `Capture` reversibly scrambles a real function's own machine code with `quark::crypto::Aes256CtrXor`; `Materialize` reconstructs it byte-for-byte, patches external PC-relative relocations, and runs it directly via `MAP_JIT`. Supersedes the removed `quark_vm`/`quark_vmasm` bytecode-VM approach | static lib |
| `cpp/quark_linkload` (Phase XVII, macOS only) | A second, structurally simpler answer to the same protected-native-code problem `quark_codecipher` solves — see "Quark Linkload" below. Seals a developer's own, completely normally compiled binary (a whole executable or dylib — no symbol/function to specify) with `quark::payload::Seal`; at runtime `ProtectedModule::Load` decrypts (`quark::payload::Unseal`), writes it to a fresh path, and `dlopen()`s it. Neither phase decodes an instruction or a relocation record itself — packaging is "read the file, seal it," and loading hands everything else to `dyld`, the real, already-trusted OS dynamic linker. Currently coexists with `quark_codecipher`; which becomes primary (if either) is still open | static lib |
| `cpp/paste_test` | Live integration test for paste.rs HTTP layer (POST/GET/DELETE lifecycle) | `Paste_Test.exe` |
| `cpp/handoff_spy` | Test stub: placed as `jre\bin\javaw.exe`, reads QKH2 initial frame, responds to challenge cycles, validates full pipe flow without a real JVM | `handoff_spy.exe` |

### Deployed (Java)
| Module | Role | Output |
|---|---|---|
| `java/drm-core` | Reads QKH2 initial frame (136 B) from stdin, starts `QuarkHeartbeat` non-daemon thread (challenge-response loop), initializes `QuarkRuntime` for checkpoint calls, decrypts `core.enc` in-memory with `core_enc_key`, loads via custom `ClassLoader` | `quark.jar` |
| `java/main-app` | Real application; core classes shipped pre-encrypted as `core.enc` | `main.jar` + `core.enc` |
| `java/quark-sdk` | Developer-facing library: `@QuarkProtected`, `@QuarkCheckpoint` annotations, compile-time stub `QuarkRuntime` (shadowed at runtime by real impl in `quark.jar`) | `quark-sdk.jar` |

### Deployed (SDK + tooling)
| Module | Role | Output |
|---|---|---|
| `tools/quark-protect` | Post-compile bytecode transformer: scans `@QuarkCheckpoint`-annotated methods, injects `QuarkRuntime.checkpoint(id)` at method entry; XORs return values with token at return sites — not NOP-patchable | `quark-protect.jar` |
| `tools/quark-build` | Bundle builder: packs class files from an input JAR into the `InMemoryClassLoader` wire format (`app.bundle`), ready for encryption by `Dev_Keygen.exe --input-bundle` | `quark-build.jar` |
| `cpp/quark-runtime-c` | C/C++ runtime for native protected apps: reads 136-byte QKH2 frame, starts heartbeat thread, exposes `quark_checkpoint(id)` — same pipe protocol as Java side | `quark_runtime.lib` |

## Hard architectural rules (do not weaken these)
1. **Static linking only.** MSVC `/MT`, mbedTLS vendored and statically compiled.
   Zero runtime DLL dependencies for `DRM_Wrapper.exe`.
2. **HWID is AAD (and KDF input), not just a check.** `quark::hwid::CanonicalBytes`
   -- the deterministic serialization of all 16 fingerprint fields (CPU
   identity/brand/cores, board UUID, baseboard, BIOS, chassis, processor
   (SMBIOS Type 4), per-slot RAM, boot disk + volume serials, every attached
   disk's serial, GPU (DXGI), MAC, MachineGuid, Windows Product ID; see
   `cpp/common/include/quark/hwid.hpp`) -- is passed as Associated Data into
   every AES-GCM operation on `state.bin`
   AND mixed into both KDF derivations in `quark::token` (`state_key` and the
   handoff secret). A mismatch on ANY single field changes the SHA-256 digest
   completely (avalanche effect) and surfaces purely as an authentication-tag
   failure or a wrong-key derivation -- never as an `if (hwid != stored_hwid)`
   boolean branch an attacker could patch out.
3. **No boolean trap on the Java side.** `drm-core` must not just check
   "is licensed: true/false". The derived `content_key` IS the AES key for
   `core.enc`. Without it, the JVM gets `ClassFormatError`/`ClassNotFoundException`
   — a real crash, not a graceful refusal. At deeper integration levels, injected
   `QuarkRuntime.checkpoint(id)` calls return HMAC-derived values that feed into
   business logic computations — wrong `content_key` corrupts outputs rather than
   triggering a patchable exception (see rule 7).
4. **The handoff secret and content_key never touch argv.** They cross inside
   a QKH2 frame (see `docs/HANDOFF_PROTOCOL.md` and `quark::handoff`) over an
   anonymous pipe → child process stdin. The pipe's **write end stays OPEN**
   after the initial 104-byte frame: `DRM_Wrapper.exe` sends a 40-byte `"CHAL"`
   frame every 30 s, and reads a 32-byte HMAC-SHA256 response from Java via a
   second anonymous pipe wired to the child's stdout. Neither secret ever appears
   in argv (visible in Task Manager / `wmic process list`).

   Consequence: **`DRM_Wrapper.exe` is the parent process and must stay alive
   for the entire Java session.** Java's `QuarkHeartbeat` thread detects a
   broken stdin pipe (parent death → `ReadFile` failure) and calls
   `Runtime.getRuntime().halt(-1)`. If Java fails to respond to a challenge
   within 10 s, `DRM_Wrapper.exe` calls `TerminateProcess` on the child.
   Neither process can outlive the other -- mutual assured destruction by pipe
   coupling, not by convention.
5. **Fail-deadly, not fail-safe.** Any anomaly (HWID read failure, debugger
   detected, file-size anomaly, AAD mismatch, Lamport chain exhausted) →
   immediate `exit(1)` / `System.exit(1)`, no recovery, no behavioral branch.
   By explicit decision, every one of those failures is now also reported
   through the shared numbered registry (`quark::error` / `ErrorCodes.java`,
   see `docs/ERROR_CODES.md`): one line to `debug-crash.txt`, one line to the
   terminal if attached -- e.g. `[QUARK-ERR-4003] DRM_Wrapper: state.bin could
   not be opened and authenticated...`. This is a deliberate broadening of
   "no diagnostic message" (chosen so field crashes are debuggable), made
   knowingly aware that it gives an attacker a coarse map of which numbered
   check fired -- but never *which specific value* mismatched, *why* in
   cryptographic terms, or *what to try next* (CLAUDE.md rules 2 and 3 still
   collapse "tampering" and "wrong machine" into one code; "wrong key" and
   "corrupt file" into one code; etc.). The outward *consequence* of every
   failure remains identical and absolute -- only its *visibility* changed.
6. **No network, no system-clock trust for *expiry*.** Offline-only.
   Expiry/usage limits are enforced **exclusively** by Lamport chain depth --
   `remaining_links == 0` is the entire mechanism, full stop, and nothing
   reads `GetSystemTime`/`GetSystemTimeAsFileTime` to decide whether to grant,
   extend, renew, or unlock anything. That guarantee is unchanged and
   non-negotiable. What *was* added, by explicit request, is a **four-channel
   witness system**: `state.bin` (primary) plus three independently-sealed
   secondary witnesses, each under a domain-separated AES-256 key derived from
   the same SECRET + HWID inputs:

   | Channel | Location | Key domain label |
   |---|---|---|
   | Primary | `state.bin` (disk) | `"QUARK-STATE-KEY"` |
   | Secondary 1 | `HKCU\Software\Quark\License` (registry) | `"QUARK-REGISTRY-KEY"` |
   | Secondary 2 | `%APPDATA%\Microsoft\Windows\ThemeCache:q` (NTFS ADS) | `"QUARK-ADS-KEY"` |
   | Secondary 3 | `DRM_Wrapper.exe:quark` (NTFS ADS on exe) | `"QUARK-OVERLAY-KEY"` |

   All four must agree on the chain position byte-for-byte on every launch.
   This closes a gap a *single* AEAD-sealed file cannot: AES-GCM proves a file
   wasn't *edited*, but not that it wasn't wholesale *replaced* with an
   earlier, validly-sealed copy of itself (a backup-restore "rewind" attack).
   The three independent storage locations have different forensic properties
   (registry survives disk wipes; ThemeCache ADS survives exe replacement; exe
   ADS is invisible to an attacker treating the binary as "static") so that
   backing up "the obvious files" unknowingly leaves surviving witnesses.

   "Witness absent" is itself checked rather than trusted as "must be a fresh
   install": `state.bin` (format v2) carries an immutable `original_chain_length`,
   set once at mint time and copied unchanged on every roll-forward. The number
   of absent secondary witnesses (`absent_count`, 0–3) drives a four-way
   branch:
   - `absent_count == 3` and `remaining_links == original_chain_length` →
     genuine first run; mint all three secondary witnesses.
   - `absent_count == 3` and `remaining_links < original_chain_length` →
     `kWrapperWitnessMissingAfterUse` ("delete all witnesses, restore an older
     used `state.bin`" -- no longer passes as day one).
   - `absent_count` 1 or 2 → `kWrapperWitnessMismatch` (selective
     absence = selective tamper).
   - `absent_count == 0` → verify all three agree with `state.bin`; any
     disagreement → `kWrapperWitnessMismatch`.

   The same sealed blobs carry a `high_water_unix_time` -- a one-way ratchet,
   **not** a clock-trust expiry check. The high-water mark is taken as
   `max()` across **all three** secondary witnesses on every launch, so wiping
   a single channel cannot reset it. It only ever fires
   `kWrapperClockRollbackDetected` when "now" is observed to be *earlier* than
   that maximum (strong evidence of manipulation); a forward-running or
   merely-normal clock grants, extends, or proves **nothing**. See
   `cpp/common/include/quark/registry.hpp`, `ads.hpp`, and `overlay.hpp`
   for the per-channel design rationale. In short: the *authority* on "how
   many uses remain" is still, and only ever will be, the Lamport chain depth;
   the three secondary witnesses and the rollback tripwire exist purely to make
   sure that authority's storage cannot be tampered with by someone who controls
   the filesystem, the registry, and the system clock.

   (Honestly: this narrows, but cannot fully close, "snapshot all four channels
   simultaneously and restore the entire snapshot" -- no purely offline design
   can, since at that point nothing anywhere disagrees with the restored copy;
   that is an inherent ceiling of "no server component", not an oversight.)

   **Concurrent-launch exclusion (`quark::platform::IProcessLock`):** the
   four-channel witness system above defends against a filesystem/registry-
   controlling attacker rewinding state *between* launches. Real concurrent-
   launch testing found a second, orthogonal gap: `state::Load`/`Save` and
   `IWitnessStore::Load`/`Save` have no locking of their own, so two
   `DRM_Wrapper` processes launched against the *same* license at the *same*
   time could both `Load()` the same pre-roll anchor and both independently
   redeem the same single-use key -- a real, reproducible license clone
   (demonstrated: 7 of 10 simultaneous launches with one key all succeeded
   before this fix). `RunUnlockFlow` now takes an optional `IProcessLock*`
   (`quark::platform::posix::FlockProcessLock` on macOS/Linux via `flock(2)`,
   `quark::platform::win::LockFileProcessLock` on Windows via `LockFileEx`,
   the Windows side not yet re-verified per this file's own rule 1) that it
   acquires before touching `state.bin` and releases on every return path;
   `DRM_Wrapper` always supplies one. Verified for real: with the lock, the
   same 10-way concurrent-launch test yields exactly one success and every
   other process cleanly reports whatever the now-current chain state
   actually is (`kWrapperLicenseExhausted` or `kWrapperUnlockKeyInvalid`),
   never a spurious I/O error and never a second redemption.
   `quark_c_api`'s `quark_unlock_and_decrypt` constructs and passes one too
   (`QUARK_ERR_LOCK_FAILED` = 4024 in `quark_c_api.h`) -- verified for real
   with 8 concurrent pthreads calling into the actual C ABI
   (`quark_c_api_lock_test.c`), so native/FFI hosts (Go/Python/Rust/Java) get
   the same guarantee whether they race across threads in one process or
   across separate processes.
7. **`@QuarkCheckpoint` — distributed cryptographic mesh (planned, not yet
   implemented).** A single `QuarkHeartbeat` thread responding to challenges is
   necessary but not sufficient: a determined attacker could locate and silence
   that one thread. The second defense layer is a build-time bytecode transformer
   (`tools/quark-protect`) that injects cryptographic derivations at developer-
   annotated hot spots throughout the protected application:

   ```java
   @QuarkCheckpoint(id = 0x1001)
   public Invoice generateInvoice(Order order) { ... }
   ```

   `quark-protect` rewrites each annotated method's entry to call:

   ```java
   long token = QuarkRuntime.checkpoint(0x1001);
   // token feeds into surrounding computation
   ```

   Where `checkpoint(id)` computes:
   ```
   HMAC-SHA256(key=content_key, msg="CP" || id (u32-LE) || session_counter (u32-LE))
   ```

   **Three properties make this non-patchable:**
   - The return value feeds into real business logic — patching to `return 0`
     corrupts outputs instead of merely unlocking access.
   - Each injection point uses a different `id` → different HMAC output.
   - The transformer can inject at arbitrary call sites unknown to the attacker
     (50+ checkpoints means 50+ locations to find and patch in reverse).

   **Integration cost for developers:** annotate hot spots with `@QuarkCheckpoint`,
   run `quark-build` — no other changes required. The SDK (`java/quark-sdk`)
   provides the annotations; `quark-protect` handles the bytecode work. See
   `docs/SDK_ARCHITECTURE.md` for the full developer integration guide.
8. **Quark Codecipher — the native/cross-language equivalent of `core.enc`
   (implemented, `cpp/quark_codecipher`, macOS-only so far).** Rule 3's "no
   boolean trap" is proven for the JVM target by `core.enc` +
   `InMemoryClassLoader` (a wrong `content_key` corrupts class bytes, not an
   `if` check), but Go/Python/native C/C++ consumers of `quark_c_api` have no
   equivalent. `quark_codecipher` fills that gap **without inventing a new
   instruction set**: it reversibly scrambles a program's OWN real machine
   code and reconstructs it byte-for-byte at runtime — no interpreter loop,
   no bytecode translation. (This module superseded an earlier bytecode-VM
   approach, `quark_vm`/`quark_vmasm`, removed — see docs/PLAN.md Phase XVI
   for why translating to a new instruction set was rejected: it required
   either hand-authored assembly or a compiler-IR translator that was never
   built, and even then could only represent a narrow, hand-picked opcode
   subset of a program's real operations, never the program's actual code.)

   Two modules, one AES-256-GCM encryption layer in the whole pipeline:

   ```
   (issuance) real function bytes -> Capture(code_key): scan for external
              PC-relative refs, scramble the whole buffer with
              quark::crypto::Aes256CtrXor -> SerializeCodeRegion
              -> quark::payload::Seal(content_key, ...)
              <-- the ONLY AES-256-GCM seal -> core.enc

   (runtime)  core.enc -> quark_unlock_and_decrypt/RunUnlockFlow (unchanged:
              real HWID + Lamport + witness verification produces
              content_key exactly as today) -> quark::payload::Unseal(content_key, ...)
              <-- the ONLY decrypt -> DeserializeCodeRegion
              -> Materialize(DeriveCodeStreamKey(content_key)): reconstruct
              the exact original bytes, patch relocations, mmap executable, run
   ```

   - **The scramble is AES-256 in CTR mode** (`quark::crypto::Aes256CtrXor`),
     not GCM: reduces to `output = input XOR AES_encrypt(key, counter)`,
     which is its own inverse (no separate encode/decode logic needed) and
     carries no per-chunk authentication overhead, so it can scramble at
     instruction granularity with no block/tag bloat. It deliberately does
     NOT re-authenticate — that would be the same redundant double
     encryption `quark_vm`'s original per-block `vm_key` sealing was removed
     for (Phase XV). A wrong `content_key` fails at `quark::payload::Unseal`
     — structurally, via the AES-GCM tag — **before `quark_codecipher` ever
     sees a byte**; see `cpp/quark_codecipher/tests/quark_codecipher_pipeline_test.cpp`
     for the real, non-mocked proof.
   - **`Capture` never leaves the real ISA.** What `Materialize` produces is
     the exact machine code the compiler originally emitted — not a
     translated, semantically-equivalent bytecode. A PC-relative instruction
     (ADRP/B/BL/B.cond) whose target lies OUTSIDE the captured byte range is
     recorded as a relocation and re-patched for the new address at
     `Materialize` time; a target INSIDE the range needs no fixup at all,
     because the whole block moves together and its relative encoding stays
     correct automatically — proven both algebraically and for real against
     compiler-generated branchy/dependency-bearing functions (see
     `cpp/quark_codecipher/README.md`).
   - **Real, directly executable memory is required** (unlike `quark_vm`'s
     interpreter, which never needed it): `Materialize` uses `MAP_JIT` +
     `pthread_jit_write_protect_np` on Apple Silicon, the same real W^X
     handling this repo's platform-agnostic exploration already validated.
   - **Honest scope limits, not yet closed:** macOS-only (Linux/Windows
     executable-memory equivalents unverified); relocation detection is a
     bit-pattern scan over raw bytes, not a real disassembler or linker
     relocation records (a false-positive misclassification is a real,
     open risk on code more complex than what's tested); CBZ/CBNZ/TBZ/TBNZ
     and PC-relative literal loads are not handled; and `Capture` reads
     already-loaded, same-process function bytes (via `dlopen`, exactly like
     its own tests) rather than a real dev-time toolchain step reading a
     linker's relocation records — see `cpp/quark_codecipher/README.md`'s
     "Honest scope limits" for the full list.
9. **Quark Linkload — a second, structurally simpler answer to the same
   problem Quark Codecipher solves (implemented, `cpp/quark_linkload`,
   macOS only so far).** Rule 8 above is real and works, but its relocation
   logic is hand-rolled: `relocation.cpp`'s ADRP/B/BL/B.cond bit-pattern
   classification is inherently open-ended (a real 710-instruction capture
   of `MacHwidBackend::Collect()` found a genuine, previously-invisible
   sign-extension bug in code that had already shipped with passing tests;
   CBZ/CBNZ/TBZ/TBNZ and PC-relative literal loads are still unhandled).
   `quark_linkload` closes that entire class of risk structurally, by never
   writing a relocation decoder at all — and, unlike an earlier version of
   this module that extracted a single symbol into its own dylib (removed;
   see `cpp/quark_linkload/README.md`'s "Why not seal just one function"),
   it seals the developer's **whole, unmodified, completely normally
   compiled binary** — no symbol name, no object-file search, no linker
   re-invocation at packaging time at all:

   ```
   (packaging, offline) developer's program compiles COMPLETELY NORMALLY —
              zero Quark awareness, zero source change, zero special build
              target — into one ordinary executable or dylib
              -> read the whole compiled binary's bytes
              -> quark::payload::Seal(content_key, binary_bytes)
              <-- the ONLY AES-256-GCM seal -> core.enc (the shipped
              artifact — there is no separate plaintext original)

   (runtime)  core.enc -> quark_unlock_and_decrypt/RunUnlockFlow (unchanged:
              real HWID + Lamport + witness verification produces
              content_key exactly as today) -> quark::payload::Unseal(content_key, ...)
              <-- the ONLY decrypt -> ProtectedModule::Load: write the
              plaintext binary to a fresh path, dlopen() it (the REAL dyld
              resolves every reference, internal or external, exactly as
              for any program), unlink() the path immediately
              -> ProtectedModule::Symbol("main") -> the program's own real
              entry point, called exactly as if the OS had exec'd it
   ```

   - **Neither phase decodes an instruction or a relocation record.**
     Packaging is a file read plus one `quark::payload::Seal` call — no
     subprocess, no symbol search. `ProtectedModule::Load` only ever calls
     `dlopen`/`dlsym`/`dlclose`. There is no ADRP/B/BL/B.cond classifier
     anywhere in this module — the bug class that hit `quark_codecipher`
     structurally cannot recur here.
   - **Why whole-binary, not one extracted symbol:** the earlier
     symbol-extraction design made a *copy* of the target function into a
     separate dylib but never removed it from the original binary — a real
     deployment would still ship the unmodified original containing the
     exact same code in plaintext, so it never actually protected anything.
     Fixing that would have required changing the protected program's
     source to call the extracted copy instead — the exact "packer-style,
     zero source change" violation this module exists to avoid. Sealing
     the whole binary removes the contradiction: the shipped artifact *is*
     `core.enc`.
   - **A wrong `content_key` fails at `quark::payload::Unseal`** — the same
     AES-GCM-tag failure, before `quark_linkload` ever writes a byte to
     disk; see `cpp/quark_linkload/tests/quark_linkload_simple_test.cpp`'s
     wrong-key check for the real, non-mocked proof.
   - **Verified on the same real, complex program that found the
     `quark_codecipher` bug:** `cpp/quark_linkload/tests/quark_linkload_hwid_test.cpp`
     seals the ENTIRE compiled `HWID_Extractor` binary and proves its
     `dlopen`'d `main()` produces byte-identical hardware-fingerprint JSON
     to a real, unprotected `fork`+`exec` of the untouched original.
   - **Real, on-disk exposure window, honestly not zero.** `dlopen()` on
     Darwin requires a real, filesystem-backed path — investigated for
     real (macOS has no `SHM_ANON`, and a named+immediately-unlinked
     `shm_open` object cannot be reopened via `/dev/fd` on this OS,
     confirmed by isolating the failure from `dlopen` itself). The
     decrypted bytes touch disk for the time between `write()` and the
     `unlink()` `ProtectedModule::Load` issues immediately after `dlopen()`
     returns — narrowed to microseconds, not eliminated. See
     `cpp/quark_linkload/README.md`'s "On-disk exposure window".
   - **Honest scope limits:** macOS only (Linux would need a different
     loading path and could plausibly use `memfd_create` to close the
     disk-exposure window entirely; Windows has no `dlopen`/Mach-O
     equivalent at all); only whole-binary granularity — a program that
     genuinely wants to protect just part of itself needs to be split into
     an unprotected launcher plus a separately protected binary, a
     build-organization decision outside this module's scope; a protected
     program's own additional dylibs (beyond OS frameworks) would each
     need their own `Seal`/`Load` round trip, untested against a real
     multi-dylib dependency chain. See `cpp/quark_linkload/README.md`'s
     "Honest scope limits" for the full list, including why
     `quark_codecipher` and `quark_linkload` currently coexist rather than
     one replacing the other.

## HWID fingerprint -- the 16 Windows fields (`quark::hwid::Components`)
Drawn from independent low-level sources so that no single spoofed value
reproduces a fingerprint, and so that swapping/re-imaging any one component
is enough to invalidate it. All raw-API, never WMI (WMI normalizes/caches/
virtualizes far more readily than the tables below):

| # | Field | Source | Changes when... |
|---|---|---|---|
| 1 | `cpu_vendor_signature` | `__cpuid` leaves 0/1 | CPU is replaced |
| 2 | `cpu_brand` | `__cpuid` leaves 0x80000002-4 | CPU is replaced |
| 3 | `cpu_logical_cores` | `__cpuid` leaf 1 (HTT-aware) | CPU/topology changes |
| 4 | `board_uuid` | SMBIOS Type 1 (System Information) | motherboard is replaced |
| 5 | `board_manufacturer` | SMBIOS Type 2 (Base Board): mfr+product+version+serial | motherboard is replaced |
| 6 | `bios_identity` | SMBIOS Type 0 (BIOS): vendor+version+release date | firmware is reflashed/updated |
| 7 | `chassis_identity` | SMBIOS Type 3 (Chassis): mfr+type+serial+asset tag | chassis is replaced |
| 8 | `processor_identity` | SMBIOS Type 4 (Processor): socket+mfr+version+serial+asset tag -- firmware-reported strings, independent of the CPUID leaves above | motherboard firmware's processor record changes |
| 9 | `ram_fingerprint` | SMBIOS Type 17, every populated slot, sorted by locator: locator+mfr+part+serial+size+speed | any DIMM is added/removed/swapped |
| 10 | `system_disk_serial` | `IOCTL_STORAGE_QUERY_PROPERTY` on the boot `PhysicalDriveN` | the boot drive is swapped |
| 11 | `system_volume_serial` | `GetVolumeInformation` on the system volume | the OS volume is reformatted/reimaged |
| 12 | `all_disk_serials` | `IOCTL_STORAGE_QUERY_PROPERTY` on every `\\.\PhysicalDriveN`, sorted | ANY attached drive is added/removed/swapped, not just the boot one |
| 13 | `gpu_fingerprint` | DXGI `IDXGIAdapter1::GetDesc1`, every non-software adapter, sorted: vendor+device+subsys+revision IDs | a GPU is added/removed/swapped |
| 14 | `mac_address` | `GetAdaptersAddresses`, first non-virtual NIC, virtual OUIs filtered | the network adapter is replaced |
| 15 | `machine_guid` | `HKLM\...\Cryptography\MachineGuid` | Windows is reinstalled |
| 16 | `windows_product_id` | `HKLM\...\Windows NT\CurrentVersion\ProductId` -- a second, independently-generated OS-install identifier | Windows is reinstalled |

`quark::hwid::CanonicalBytes` joins all 16 (in the fixed `kFieldOrder`) with
`\x1F` separators into one deterministic byte string -- this exact string is
what becomes AES-GCM AAD and KDF input. Because it's then SHA-256'd inside
`quark::token`, changing even one character anywhere avalanches into a
completely different key/tag: there is no "close enough" match, by
construction. `Collect()` requires *all sixteen* to read successfully -- a
partial fingerprint is rejected outright (see hwid.hpp for the rationale).
**Not yet re-verified by an actual MSVC build** -- written carefully against
the same, already-tested SMBIOS-walk/disk-enumeration infrastructure, but
per this repo's own rule 1, "should compile" isn't "verified".

### macOS and Linux: 11 fields each, same philosophy, different sources
Windows' 16-field design is the reference implementation, not the contract
-- `quark::platform::IHwidBackend` only requires "every field independently
verified real, all-or-nothing". See `quark/platform/macos/hwid_backend_macos.hpp`
and `quark/platform/linux/hwid_backend_linux.hpp` for the full per-field
rationale, including honest deltas from Windows (no per-DIMM RAM identity on
either OS; macOS's Hardware UUID survives an OS reinstall, Windows'
MachineGuid does not; Linux deliberately excludes root-only DMI fields like
`product_uuid` to stay unprivileged). **Both are verified for real** --
macOS on real hardware, Linux inside a real kernel (see "Cross-platform
build & test strategy").

## Lamport chain mechanics (the licensing heartbeat)
- Dev side picks a random seed `x` and a chain length `n` (= number of allowed
  uses/sessions). Computes `H^0(x), H^1(x), ..., H^n(x)` where `H = SHA-256`.
- Distributes `H^n(x)` (the "anchor") to the customer machine inside `state.bin`,
  bound to that machine's HWID via AAD.
- Each unlock, the user supplies the *previous* preimage `H^{n-1}(x)`; the
  wrapper checks `SHA256(supplied) == stored_anchor`, then rolls
  `stored_anchor = supplied` and decrements the counter — one-way, replay-proof,
  and self-exhausting (no clock needed for "this license is now spent").

## Build
- CMake + MSVC toolchain (`cl.exe`, `/MT`, x64).
- mbedTLS vendored under `third_party/mbedtls`, built as a static lib and linked
  into `cpp/common`.
- Current scope: **compile/build only** — no signing, packaging, or deployment.

## Conventions
- C++17, RAII wrappers around all WinAPI handles (`HANDLE`, `HCRYPTPROV`, etc.)
- Every crypto buffer that holds key material must be zeroed on scope exit
  (`SecureZeroMemory`).
- No exceptions crossing the `DRM_Wrapper` → JVM boundary; all failure paths
  collapse to `exit(1)`.
