# Quark Implementation Plan

Scope for this pass: **Windows-only C++ side, compile-only**. Java side
(`quark.jar` / `main.jar`) is reference/contract code -- it must exist for the
handoff protocol to be checkable end-to-end -- but build/signing/packaging
against real customer hardware is out of scope until explicitly authorized.

## Phase 0 — Scaffolding
- [x] CLAUDE.md describing architecture & hard rules
- [x] Directory layout: `cpp/{common,hwid_extractor,dev_keygen,drm_wrapper}`,
      `java/{drm-core,main-app}`, mbedTLS via `FetchContent`
- [x] Top-level CMakeLists wiring mbedTLS (static) + `/MT` + the three exes
- [x] `cpp/common`: HWID collection, SHA-256/AES-256-GCM wrappers, Lamport
      chain helpers, `state.bin` codec, registry-witness codec
      (`quark::registry`), KDF (`quark::token`) -- all via mbedTLS

## Phase I — C++ DRM Wrapper pieces
- [x] `HWID_Extractor.exe` / `quark::hwid`: an **11-field** fingerprint --
      CPU vendor+signature, CPU brand string, logical core count, SMBIOS board
      UUID, SMBIOS baseboard (mfr/product/version/serial), SMBIOS BIOS
      (vendor/version/release date), every populated RAM slot
      (locator/mfr/part/serial/size/speed, sorted for determinism), system
      disk serial (`IOCTL_STORAGE_QUERY_PROPERTY`), system volume serial
      (`GetVolumeInformation`), primary NIC MAC (virtual OUIs filtered),
      registry `MachineGuid` → canonical `\x1F`-joined byte blob + JSON. See
      CLAUDE.md "HWID fingerprint" table for the full source/invalidation map.
      `Collect()` requires all eleven to succeed -- partial reads are rejected.
- [x] `Dev_Keygen.exe`: takes `SECRET` + target HWID JSON, builds Lamport
      `H^0..H^n(x)` (n = chain length = number of unlocks), writes initial
      `state.bin` (AES-256-GCM, HWID canonical bytes as AAD), emits
      `unlock_keys.txt` in redemption order, self-tests the result
- [x] `DRM_Wrapper.exe`:
      1. Anti-debug speed bumps (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
         raw PEB `BeingDebugged`/`NtGlobalFlag` reads)
      1.5. **Jar integrity check** (`jar_digest.hpp`): hash `quark.jar` and
         compare against a build-time-embedded SHA-256. Closes the gap that
         nothing else covers -- the wrapper would otherwise pipe a freshly
         derived handoff secret to *whatever* sits at `kJvmPath`/`kJvmArgs`,
         including a hostile rebuild of `quark.jar` that captures the secret
         before deriving `content_key`. Same "authenticate, don't trust"
         posture as `state.bin`, aimed one hop further down the pipe
         (`kWrapperJarIntegrityFailed`).
      2. Re-collect HWID locally (never trust a stored copy)
      3. Derive `state_key = SHA256("QUARK-STATE-KEY" | SECRET | hwid_canonical)`,
         open + AES-GCM-decrypt `state.bin` using HWID canonical bytes as AAD
         (auth failure ⇒ `exit(1)`, no message — covers tampering & migration alike)
      3.5. **Four-channel witness cross-check** (`quark::registry`, `quark::ads`,
         `quark::overlay`; see CLAUDE.md rule 6 and [Phase IV](#phase-iv--fail-deadly-hardening-cross-cutting-applied-throughout)):
         derive three domain-separated keys and load three secondary
         AES-GCM-sealed witnesses -- HKCU registry, ThemeCache NTFS ADS
         (`%APPDATA%\Microsoft\Windows\ThemeCache:q`), and exe ADS
         (`DRM_Wrapper.exe:quark`) -- each mirroring state.bin's exact chain
         position. The `absent_count` (0–3 absent) drives a four-way branch:
         all-absent + pristine → mint all three; all-absent + used →
         `kWrapperWitnessMissingAfterUse`; partial → `kWrapperWitnessMismatch`;
         all present → verify all agree with state.bin, else
         `kWrapperWitnessMismatch`. Clock rollback tripwire: `high_water_unix_time`
         taken as `max()` across all three channels → `kWrapperClockRollbackDetected`
         on backwards jump only; forward clock grants nothing
      4. Reject if the Lamport chain is exhausted (`remaining_links == 0`)
      5. Prompt for the next key, verify `SHA256(key) == anchor`
      6. Roll the chain, persist updated `state.bin` **and all three secondary
         witnesses** in lockstep (all four before anything externally
         observable — so a crash mid-handoff can't be exploited as a replay
         or a drift between stores), derive
         `handoff_secret = SHA256("QUARK-HANDOFF" | state_key | new_anchor | hwid_canonical)`
      7. `CreateProcess` the JVM via `LaunchJvmWithHandoff` (anonymous pipe →
         child stdin, encode-frame+write+close+zero), wait, propagate exit code

## Phase II — Handoff protocol (documented, both sides honor it -- see [docs/HANDOFF_PROTOCOL.md](HANDOFF_PROTOCOL.md))
- [x] **Two anonymous pipes** (`CreatePipe` × 2): the stdin pipe carries the
      initial frame AND stays open for the challenge loop (write end never
      closed after the initial frame). The stdout pipe is the HMAC reply
      channel from Java back to `DRM_Wrapper`.
- [x] **Quark Handoff Protocol v2 / QKH2** (`quark::handoff` / `HandoffFrame.java`):
      a fixed **136-byte** initial frame -- magic `"QKH2"` + version `2`
      (LE u32) + 32-byte `handoff_secret` + 32-byte `session_id` + 32-byte
      `initial_seal` + 32-byte `core_enc_key`. Structural sanity gate (wrong
      build / truncated pipe / protocol drift all fail before any crypto).
      Followed by periodic 40-byte `"CHAL"` frames (counter + nonce) on the
      same pipe; child responds with 32-byte HMAC-SHA256 on its stdout.
- [x] **Two-key separation** -- both sides derive:
      - `content_key = SHA256("QUARK-CORE-CONTENT-KEY" | handoff_secret)` --
        per-session; drives HMAC challenge-response and `@QuarkCheckpoint` tokens
      - `core_enc_key` (sent verbatim in frame at offset 104) -- stable per
        license; derived C++ side as
        `SHA256("QUARK-CORE-ENC-KEY" | state_key | SHA256(online_secret) | hwid_canonical)`,
        excluding the rolling anchor so `core.enc` can be pre-encrypted once
        at issuance and reused every session on the same machine
- [x] **HMAC challenge-response loop** (QKH2 session lifetime): `DRM_Wrapper`
      sends `"CHAL" || counter(u32-LE) || nonce(32 B)` every 30 s; Java
      responds `HMAC-SHA256(content_key, "RESP" || session_id || counter || nonce)`.
      No response within 10 s → `TerminateProcess`. Broken stdin (parent died)
      → `QuarkHeartbeat` calls `halt(-1)`. Mutual assured destruction.
- [x] No secret material in argv/environment -- the launch command line
      (`kJvmArgs` in `drm_wrapper/main.cpp`) never references it; verified by
      inspecting the single `CreateProcessW` call site in `handoff.hpp`

## Phase III — Java side (`quark.jar` / `main.jar` / `quark-sdk`)
- [x] `quark.drmcore.Bootstrap`: reads exactly `HandoffFrame.FRAME_LENGTH`
      (136) bytes from stdin, structural frame validation (`HandoffFrame.parse`;
      magic `"QKH2"`, version `2`), two-key extraction (`handoff_secret` →
      `content_key`; `core_enc_key` verbatim from frame at offset 104),
      hands `contentKey` + `sessionId` to `QuarkHeartbeat.start()` and
      `QuarkRuntime.init()`, then uses `core_enc_key` with `CoreDecryptor` to
      AES-256-GCM-decrypt `core.enc` in-memory. `InMemoryClassLoader` defines
      classes from the decrypted flat bundle and reflectively invokes
      `quark.app.CoreEntryPoint#start`. Every failure path collapses to
      `ErrorCodes.report(code)` + `System.exit(1)` / `halt(-1)` -- no boolean trap.
- [x] `quark.drmcore.QuarkHeartbeat`: non-daemon thread; reads 40-byte
      `"CHAL"` frames from stdin, validates magic, computes and writes 32-byte
      HMAC responses. Companion watchdog daemon thread fires `halt(-1)` if no
      response has been sent in 60 s (belt-and-suspenders). Both `IOException`
      and structural failures call `halt(-1)` after `ErrorCodes.report(5007|5008)`.
- [x] `quark.sdk.QuarkRuntime` (real impl, inside `quark.jar`): same package
      as the compile-time stub in `quark-sdk.jar`; shadows it via classloader
      hierarchy at runtime. `checkpoint(id)` computes
      `HMAC-SHA256(content_key, "CP" || id(u32-LE) || counter(u32-LE))` →
      first 8 bytes as a `long`. `AtomicInteger` counter is thread-safe.
- [x] `java/quark-sdk`: compile-time-only annotations `@QuarkProtected`,
      `@QuarkCheckpoint(id)`, and a stub `QuarkRuntime` that returns `0L` from
      `checkpoint`. Developers compile against `quark-sdk.jar`; the real
      implementation takes over at runtime via the classloader hierarchy.
- [x] `quark.app.CoreEntryPoint`: reference shape of the class(es) whose
      `.class` bytes get pre-encrypted into `core.enc` at build time
- [x] Gradle build files for `quark.jar`, `main.jar`, and `quark-sdk`
      (`java/settings.gradle.kts` includes all three), dependency-free
      (uses only `javax.crypto` + ASM 9 for the tools)

## Phase V — SDK toolchain (`tools/` + `cpp/quark-runtime-c`)
- [x] **`tools/quark-protect`** (ASM 9 bytecode transformer): visits every
      class file in an input JAR; for each `@QuarkCheckpoint(id)` method,
      injects `long __q = QuarkRuntime.checkpoint(id)` at entry and XORs
      integer/long return values with a fold of `__q` at each return site.
      `ATHROW` and void returns pass through unmodified. Produces an output
      JAR with the same structure as the input.
- [x] **`tools/quark-build`** (bundle builder): reads a JAR (optionally
      post-`quark-protect`), packs class files into the flat
      length-prefixed binary format (`count(u32LE)` + repeated
      `name_len(u16LE) + name + class_len(u32LE) + class`) that
      `InMemoryClassLoader` expects. `--only-annotated` flag includes only
      `@QuarkProtected`-annotated classes. Produces `app.bundle`.
- [x] **`cpp/dev_keygen` `--input-bundle`**: new flag takes `app.bundle`,
      derives `core_enc_key` (from `state_key`, `SHA256(online_secret)`,
      `hwid_canonical`; excludes rolling anchor), AES-256-GCM-encrypts the
      bundle as a QENC blob, writes `core.enc` to the output directory.
      `online_secret_hash` is captured before `SecureZeroMemory` zeroes the
      online secret so the ordering is safe.
- [x] **`cpp/quark-runtime-c`** (C/C++ DRM runtime, static lib): mirrors
      `QuarkHeartbeat.java` wire-for-wire. `quark_init()` reads the 136-byte
      QKH2 frame, derives `content_key`, stores `core_enc_key` and
      `session_id`. `quark_heartbeat_start()` spawns a Windows thread
      (`CreateThread`) for the HMAC challenge loop (CNG HMAC-SHA256,
      `bcrypt.lib`). `quark_checkpoint(id)` uses `InterlockedIncrement` for
      a thread-safe counter. `quark_core_enc_key()` returns the 32-byte key.
      `ExitProcess(-1)` on any pipe failure -- same mutual-assured-destruction
      contract as the Java side. CMakeLists built as `/MT` static lib.

## Phase IV — Fail-deadly hardening (cross-cutting, applied throughout)
- [x] `SecureZero` / `ScopedZero<T>` RAII guard on every key-bearing buffer
- [x] Debugger checks gate the unlock path itself, not just logged
      (`anti_debug.hpp`, offset-based PEB reads -- not the partial SDK struct)
- [x] Structural sanity checks on `state.bin` (magic/version/size) and
      `core.enc` (magic/version) before crypto runs
- [x] Single funnel: every C++ failure path → `FailDeadly(code)` → `exit(1)`;
      every Java failure path → `ErrorCodes.report(code)` → `System.exit(1)`
- [x] **Numbered crash reporting** (`quark::error` / `ErrorCodes.java`, see
      [docs/ERROR_CODES.md](ERROR_CODES.md)): every failure across all four
      programs -- `HWID_Extractor`, `Dev_Keygen`, `DRM_Wrapper`, `quark.jar`
      -- now appends one structured line to `debug-crash.txt` and mirrors it
      to the terminal as `[QUARK-ERR-NNNN] <component>: <description>`. This
      is an explicit, conscious broadening of CLAUDE.md rule 5's original
      "no diagnostic message" wording (chosen so field crashes are
      debuggable) -- the *consequence* of every failure is unchanged
      (immediate, unconditional exit, no recovery), only its *visibility*
      changed, and codes that the cryptography genuinely cannot split apart
      (wrong-machine vs. tampered, wrong-key vs. corrupt-file, ...) are kept
      deliberately merged so the registry never reveals more than the math
      already does.
- [x] **Four-channel witness system + rollback tripwire** (`quark::registry`,
      `quark::ads`, `quark::overlay`; see CLAUDE.md rule 6): three secondary
      AES-256-GCM-sealed copies of the Lamport chain position, stored in
      independent locations -- `HKCU\Software\Quark\License` (registry),
      `%APPDATA%\Microsoft\Windows\ThemeCache:q` (NTFS ADS, hidden+system host
      file), and `DRM_Wrapper.exe:quark` (NTFS ADS on the exe itself) -- each
      under a domain-separated key, rolled forward in lockstep with `state.bin`
      on every unlock, all required to agree byte-for-byte on every launch.
      The `absent_count` (0–3 secondary witnesses absent) drives four outcomes:
      all-absent + pristine → first run (mint all three); all-absent + used →
      `kWrapperWitnessMissingAfterUse`; partial absence → `kWrapperWitnessMismatch`;
      all present + disagree → `kWrapperWitnessMismatch`. The `high_water_unix_time`
      ratchet is taken as `max()` across all three channels so wiping one
      channel cannot reset it; fires `kWrapperClockRollbackDetected` only on a
      backwards clock jump, never on a forward/normal clock, and
      `remaining_links == 0` remains the chain's sole authority on "how many
      uses are left" (CLAUDE.md rule 6). Error codes 4011-4015 and 4017-4020
      all relate to this system (see `docs/ERROR_CODES.md`).
- [x] **Jar integrity pinning** (`jar_digest.hpp`, `kWrapperJarIntegrityFailed`):
      a build-time-embedded SHA-256 of `quark.jar`, checked before anything
      else runs. Without it, the entire cryptographic interlock terminates at
      a process boundary the wrapper never actually inspects -- a rebuilt
      `quark.jar` that, say, dumps the handoff secret to disk before deriving
      `content_key` would be launched exactly like the real one. One digest
      compare closes that, at the cost of "regenerate it on every jar
      rebuild" (documented in the header; deliberately *not* extended to
      pinning the JRE too -- that constant would churn on every JDK update
      for comparatively little gain, exactly the kind of complexity
      "simple-solid" says to not chase).

## Phase VI — Cross-platform core split + macOS/Linux platform layers
- [x] **`quark_core` / `quark_platform_<os>` split**: `cpp/common`'s
      OS-independent files (`crypto`, `token`, `lamport`, `state`, `handoff`,
      `error`) build as `quark_core` on any OS with no `#ifdef` needed;
      Windows-only files (`hwid`, `registry`, `ads`, `overlay`, `online`)
      moved into `quark_platform_win`, gated by `if(WIN32)`. Verified: real
      compile + real test run (no mocks) on macOS via `sandbox/build-macos`.
- [x] **`quark::platform::IHwidBackend` / `IWitnessStore`** (`cpp/common/
      include/quark/platform/*.hpp`): the cross-platform contracts every OS's
      backend implements. `quark::platform::CanonicalBytes` is
      byte-identical to `quark::hwid::CanonicalBytes` for the same field
      values in the same order -- migrating Windows onto this interface
      later is a representation change, not a cryptographic one.
- [x] **`quark::witness::Seal`/`Unseal`** (`cpp/common/src/witness_codec.cpp`):
      the AES-GCM witness-blob framing extracted out of `registry.cpp` into a
      portable, shared codec (byte-identical wire format) so new channels
      don't re-derive it. `quark::platform::FileWitnessStore` (portable) uses
      it for the "config directory" channel on both macOS and Linux.
- [x] **Windows adapters** (`platform_win/hwid_backend_win.cpp`,
      `platform_win/witness_stores_win.cpp`): thin wrappers exposing the
      existing, already-shipped `quark::hwid`/`quark::registry`/`quark::ads`/
      `quark::overlay` free functions through `IHwidBackend`/`IWitnessStore` --
      zero behavior change to the underlying Windows code. **Not yet
      re-verified on a real Windows machine** (written and reasoned through
      carefully, but this repo's own rule 1 means "should compile" isn't
      "verified" until it's actually built with MSVC).
- [x] **macOS platform layer** (`quark_platform_macos`): `MacHwidBackend`
      (sysctlbyname for CPU/model/memory size, IOKit for
      IOPlatformUUID/IOPlatformSerialNumber, DiskArbitration for boot
      volume/media UUID, getifaddrs for MAC) + `XattrWitnessStore` (macOS
      xattr syscalls, 6-arg `getxattr`/`setxattr`). **Verified for real** on
      real macOS hardware: HWID collection succeeds, is deterministic across
      calls, and the xattr witness channel round-trips correctly including
      wrong-key rejection (`cpp/common/tests/platform_macos_test.cpp`).
      Documented deltas from Windows: no per-DIMM RAM identity (soldered
      unified memory), Hardware UUID survives an OS reinstall (Windows'
      MachineGuid does not -- a genuine, intentional platform difference).
- [x] **Linux platform layer** (`quark_platform_linux`): `LinuxHwidBackend`
      (`/proc/cpuinfo` with both x86 and ARM field families, `/etc/machine-id`
      with `/var/lib/dbus/machine-id` fallback, world-readable
      `/sys/class/dmi/id/*` fields only, boot device UUID via
      `/proc/self/mountinfo` + `/dev/disk/by-uuid`, getifaddrs for MAC) +
      `XattrWitnessStore` (Linux xattr syscalls, 4-arg, kernel-enforced
      `user.` namespace prefix for unprivileged access). **Verified for
      real** inside a real Linux kernel (Docker container, `sandbox/
      build-linux`): full `quark_core` suite passes, xattr witness channel
      round-trips correctly (against the container's native filesystem --
      a Docker bind-mount of a macOS host directory does **not** support
      Linux xattrs properly, a real finding worth remembering, not a code
      bug), and `Collect()` correctly fail-deadlies (returns `nullopt`,
      doesn't crash or return a partial fingerprint) in this specific
      container because it has no DMI table at all -- the exact fail-deadly
      guarantee CLAUDE.md rule 2 requires, verified rather than assumed.
      Deliberately excludes `product_uuid`/`board_serial` (root-only, mode
      0400 on stock kernels) and bare-metal ARM (no DMI without UEFI) -- see
      `quark/platform/linux/hwid_backend_linux.hpp` for the full rationale.

## Phase VII — HWID hardening (more independent sources per platform)
- [x] **Windows: 11 → 16 fields.** Added `chassis_identity` (SMBIOS Type 3),
      `processor_identity` (SMBIOS Type 4 -- firmware-reported, independent
      of the CPUID leaves), `all_disk_serials` (every `\\.\PhysicalDriveN`,
      not just the boot disk), `gpu_fingerprint` (DXGI adapter enumeration,
      raw PCI IDs, not WMI), and `windows_product_id` (a second, independent
      OS-install registry identifier alongside MachineGuid). **Not yet
      re-verified by MSVC** -- written against the same tested SMBIOS-walk
      infrastructure, but unverified per rule 1 until built on real Windows.
- [x] **macOS: 9 → 11 fields, verified for real.** Added every non-virtual
      NIC's MAC (not just the first), `hw.cpufamily`/`cputype`/`cpusubtype`
      (numeric CPU-family fact independent of the brand string), and a
      hardware model code from IOPlatformExpertDevice. Real finding during
      verification: `"board-id"` (the Intel-era key) does not exist on this
      Apple Silicon Mac at all -- confirmed via actual `ioreg -rd1 -c
      IOPlatformExpertDevice` inspection, not assumption -- Apple Silicon
      instead exposes the equivalent fact as **OSData** (not OSString) under
      `"target-sub-type"`. `ReadPlatformExpertProperty` was generalized to
      handle both CFString and CFData, and the backend now tries `board-id`
      then falls back to `target-sub-type`. All 20 checks (11 fields +
      determinism + xattr channel) pass on real hardware.
- [x] **Linux: 8 → 11 fields, verified for real.** Added every non-virtual
      NIC's MAC, `chassis_vendor`/`chassis_type` (fourth world-readable DMI
      field), `total_memory_kb` (`/proc/meminfo`, a coarse analogue of
      per-DIMM RAM identity -- real per-slot SPD data needs `dmidecode
      --type 17`, root-only for the same reason `product_uuid` is skipped),
      and a storage-topology fingerprint from `/sys/block` (model+size per
      attached non-virtual block device, sorted -- not a real serial, which
      also needs elevated privileges via SG_IO, but a real fact that changes
      if a drive is added/removed/swapped). Verified inside the real Docker
      Linux kernel: `/proc/meminfo` and `/sys/block` enumeration both
      confirmed against real (if virtualized) values; full `Collect()`
      still correctly fail-deadlies in this specific container (no DMI),
      exactly as before -- the new fields don't change that guarantee.

### Explicitly not done yet (do not claim otherwise)
- The Windows `quark_platform_win` adapters have not been re-verified by an
  actual MSVC build since this refactor.
- `config` system (CLAUDE.md rule 2) not started as a general mechanism;
  `quark::config::Config` (a minimal key=value reader) exists in quark_core
  but nothing consumes it yet.

## Phase VIII — Pivot: quark_core as a language-agnostic C ABI, not a
## Java-specific orchestrator
Direction change (explicit user decision): the DRM engine's value is the
core crypto/licensing logic, not the JVM-pipe handoff one specific consumer
(`DRM_Wrapper.exe` + `quark.jar`) built on top of it. Rather than writing a
macOS/Linux `DRM_Wrapper`-equivalent that re-embeds JVM-launching and
anti-debug concerns into quark_core's orbit, quark_core is now exposed
through a stable `extern "C"` surface any language with an FFI (Go/cgo,
Python/ctypes, Java/JNI, Rust/bindgen, C/C++ directly) can call **in-process**
-- no child process, no pipes, no QKH2 framing required. The existing
Java/JVM pipeline stays exactly as it is (a valid, still-supported way to use
Quark), but it is now one possible consumer of the engine, not the engine's
only interface.

- [x] **`quark::orchestrator::RunUnlockFlow`** (`cpp/common/include/quark/
      orchestrator.hpp` + `src/orchestrator.cpp`, quark_core): the
      OS-independent half of the unlock flow -- HWID collection via
      `IHwidBackend`, `state.bin` open, three-witness cross-check via
      `IWitnessStore`, chain-exhaustion check, key verification, roll-forward
      + persist, session-key derivation. Deliberately a **pure, non-exiting
      engine**: returns `quark::error::Code` (added `kOk = 0` as a new
      sentinel) instead of calling `quark::error::Report`/`std::exit(1)` --
      a library must never terminate its host process or write files the
      host didn't ask for, so CLAUDE.md rule 5's fail-deadly discipline is
      now explicitly a policy for whoever builds a *standalone executable*
      on top of this engine, applied at their own call site, not something
      quark_core can impose on an arbitrary embedder. No QKH2/JVM-specific
      framing happens inside it either -- it returns `content_key` /
      `core_enc_key` / `session_id` directly; a caller who wants QKH2 framing
      calls `quark::handoff::EncodeInitialFrame` itself with those values.
- [x] **`cpp/quark_c_api`** (new top-level module, `libquark_c` shared
      library): the actual `extern "C"` surface --
      `quark_hwid_collect`, `quark_lamport_mint_chain`, `quark_state_mint`,
      `quark_seal_payload`, `quark_unlock_and_decrypt`, `quark_error_describe`.
      (An earlier draft of this surface exposed a raw-key-returning
      `quark_unlock`; it was replaced by `quark_seal_payload` +
      `quark_unlock_and_decrypt` during this same phase specifically because
      returning `core_enc_key` to the caller reintroduces the boolean-trap
      pattern rule 3 exists to prevent -- see the Phase IX entry below for
      where the two replacement functions actually got implemented and
      tested.) Error codes are shared 1:1 with `quark::error::Code` wherever
      the underlying failure is the same (enforced by `static_assert` in
      `quark_c_api.cpp`, not just a comment); new negative codes
      (`QUARK_ERR_INVALID_ARGUMENT`, `QUARK_ERR_BUFFER_TOO_SMALL`,
      `QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM`) exist purely for this C
      boundary's own argument-contract failures. Witness channels are
      described by a plain `quark_witness_channel_t` struct (`kind` +
      path/attr_name/magic/name) so one `quark_unlock_and_decrypt` call shape
      covers FILE/XATTR (macOS, Linux) today and REGISTRY/ADS/OVERLAY
      (Windows -- wired up, **not yet verified by MSVC**) without the caller
      needing to know which concrete `IWitnessStore` backs which OS.
      HWID/witness backend selection is `#ifdef __APPLE__` /
      `#ifdef __linux__` / `#ifdef _WIN32` inside `quark_c_api.cpp`, scaling
      automatically with whichever `quark_platform_<os>` target that OS
      already builds.
- [x] **`cpp/quark_c_api/tests/quark_c_api_test.c`** -- a real, non-mocked,
      **plain C** (not C++) end-to-end test: collects this machine's actual
      HWID through the C ABI, mints a real 3-link chain + `state.bin`, seals a
      payload with `quark_seal_payload`, then unlocks and decrypts it twice
      through real FILE + XATTR witness channels via
      `quark_unlock_and_decrypt` (verifying the same plaintext comes back both
      times -- `core_enc_key` stays stable across unlocks on the same license
      per `quark/token.hpp`'s design, though the key itself never crosses the
      C boundary), and confirms a replayed already-spent key is rejected. All
      checks pass for real on macOS hardware; wired into `ctest` (see below).
- [x] **`ctest` now actually works from the top-level build directory.**
      Found and fixed in passing: `enable_testing()` was only ever called
      inside `cpp/common/tests/CMakeLists.txt` and
      `cpp/quark_c_api/tests/CMakeLists.txt`, which registers tests with
      CTest but never wires the *top-level* build directory to discover them
      -- running `ctest` from `sandbox/build-macos` silently reported "No
      tests were found" even though the test binaries themselves passed.
      Moved the one `enable_testing()` call to the top-level `CMakeLists.txt`
      (CLAUDE.md rule 4: low-effort DevOps -- one `ctest` invocation should
      prove the whole tree, not require knowing which subdirectory's binary
      to run by hand).

### Explicitly deferred (not abandoned -- deliberately out of scope for now)
Per explicit user direction: anti-debug and any further hardening/obfuscation
work is deliberately **not** the current priority -- it comes after the core
is solid, not before. Two small, self-contained, currently-unused files exist
from before this pivot and are intentionally left as dormant, uncommitted
building blocks for that later phase (not wired into any build target, not
deleted, per explicit instruction to leave them alone):
`quark/platform/macos/anti_debug_macos.hpp` (+`.cpp`, `sysctl(KERN_PROC)`
`P_TRACED` check), `quark/platform/linux/anti_debug_linux.hpp` (+`.cpp`,
`/proc/self/status` `TracerPid` check), and
`quark/platform/posix/process_handoff.hpp` (+`.cpp`, a `fork`/`pipe`/`execv`
JVM-launch-and-challenge-loop module mirroring `cpp/drm_wrapper/handoff.hpp`
for POSIX). None of these are referenced by any `CMakeLists.txt` and none of
this PLAN.md's other checklists depend on them.

## Remaining before a real build
- [ ] Replace the placeholder in `cpp/drm_wrapper/secret.hpp` with a freshly
      generated, high-entropy SECRET (`openssl rand -hex 32`). `Dev_Keygen`
      `#include`s the same header so the two tools physically cannot be built
      against different values.
- [ ] Replace the all-zero placeholder digest in `cpp/drm_wrapper/jar_digest.hpp`
      with the real `SHA-256(quark.jar)` once the jar is built (`certutil
      -hashfile quark.jar SHA256`). Regenerate on every subsequent jar rebuild
      or `DRM_Wrapper.exe` will refuse to launch its own companion
      (`kWrapperJarIntegrityFailed`).
- [ ] Produce the real `app.bundle` + `core.enc` for a customer:
      1. Compile `main-app` classes with `quark-sdk.jar` on classpath.
      2. Run `quark-protect.jar` to inject `@QuarkCheckpoint` tokens.
      3. Run `quark-build.jar [--only-annotated]` → `app.bundle`.
      4. Run `Dev_Keygen.exe hwid.json <n> out_dir --input-bundle app.bundle`
         → writes `state.bin`, `core.enc`, `unlock_keys.txt` in one step.
         The `core_enc_key` used to seal `core.enc` is derived inside
         `Dev_Keygen` and also baked into `state.bin`'s handoff path, so
         the files are paired to this machine and this paste automatically.
- [ ] Decide on / bundle a JRE layout to match `kJvmPath`/`kJvmArgs`

## Out of scope for now (needs explicit go-ahead)
- Code signing / packaging / installers
- Running real license issuance against a customer's actual hardware
- Anti-VM heuristics beyond what's listed (these can become an arms race;
  flag before investing more here)
- GPU fingerprinting: would require DXGI/D3D or WMI, both heavier
  dependencies than the rest of `quark::hwid` accepts; the existing 11
  independent fields already make spoofing all of them in lockstep
  impractical without it

## Phase IX — Quark VM: cryptographically interlocked protected logic
Implements docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-
interlocking-design.md and docs/superpowers/plans/2026-07-04-quark-vm-
implementation.md.

- [x] `cpp/quark_vm` -- new, OS-independent static library: fixed 24-byte
      instruction encoding, a `.qvm` program container, and a stack-machine
      `Interpreter`. **Superseded by Phase XV, then removed entirely by
      Phase XVI below**: this phase originally built a `DeriveVmKey`/
      `BlockCache` per-block decrypt-on-demand design (a second AES-GCM
      layer inside `quark_vm`, keyed off `content_key`); Phase XV removed it
      as redundant double encryption once the pipeline placement was
      corrected. Phase XVI then removed the whole bytecode-translation
      approach in favor of `cpp/quark_codecipher` (real machine code, no new
      instruction set) -- `cpp/quark_vm` no longer exists in the tree.
- [x] `cpp/quark_vmasm` -- dev/issuance-time text assembler. Originally
      produced sealed `.qvm` files; per Phase XV it now produces plain
      (unsealed) `.qvm` files and is scoped to internal test fixtures only,
      not the developer-facing path. Not linked into any shipped runtime.
- [x] Real, non-mocked, deterministic tests throughout (this module has zero
      OS dependency, so unlike most platform-layer work in this repo,
      nothing here needed a real-OS test environment to be genuinely
      tested) -- including an explicit "wrong key produces a wrong result,
      not a crash or a blocked branch" check, which is the property the
      whole design exists to prove.

### Explicitly not done yet (do not claim otherwise)
- `HostFunctionTable`'s C-ABI shape is defined and used internally, but it
  is not yet wired into `cpp/quark_c_api`'s public header -- a Go/Python
  host cannot yet actually supply one through `quark_c_api.h`. Tracked as
  the natural next step once this module is verified end to end.
- No dispatch-table permutation or other bytecode-obfuscation hardening
  (explicitly deferred in the design spec).
- No higher-level compiler targeting quark_vm -- `quark-vmasm`'s text format
  is hand-written only.
- Not yet built or tested on Linux/Windows in this session -- verify on
  those platforms the same way every other quark_core-adjacent module in
  this repo has been (see "Cross-platform build & test strategy" in
  CLAUDE.md) before relying on the cross-platform claim in practice.

## Phase X — Cross-platform port, Phase A: the zero-new-infrastructure programs
Implements Phase A of docs/superpowers/specs/2026-07-05-cross-platform-
porting-roadmap.md.

- [x] `quark::platform::FingerprintToJson`/`FingerprintFromJson` -- portable
      JSON transport for `Fingerprint` (quark_core), the cross-platform
      successor to the Windows-only `quark::hwid::ToJson`/`FromJson`.
- [x] `quark_common` INTERFACE target now also defined for `APPLE` and
      `UNIX AND NOT APPLE`, matching the existing Windows one -- every
      consumer keeps linking one name regardless of OS.
- [x] `HWID_Extractor` ported to `quark::platform::IHwidBackend` --
      builds and runs for real on macOS (Linux untested this pass, but
      uses the same portable code path as macOS).
- [x] `handoff_spy` ported to POSIX: kept its "must not share code with the
      thing it tests" property by hand-rolling a from-scratch, dependency-free
      SHA-256/HMAC-SHA256 for non-Windows builds (Windows keeps its existing
      CNG implementation). Verified via a real fork/pipe end-to-end test that
      cross-checks handoff_spy's response against `quark::token`'s
      independently-implemented derivation.
- [x] `quark-runtime-c` ported to `quark_core` crypto (no independence
      constraint here -- unlike `handoff_spy`, this is a real runtime library),
      POSIX I/O, and `std::thread`; wired into the top-level build for the
      first time (previously a fully standalone, un-built CMake project).
      Verified via a real fork/pipe end-to-end test against an actual
      `quark_runtime`-linked stand-in application.
- [x] `HWID_Extractor`, `handoff_spy`, and `quark-runtime-c` all un-gated
      from `if(WIN32)` in the top-level `CMakeLists.txt`.
- [x] Full "all" build (7 targets: quark_core_tests, quark_platform_macos_tests,
      quark_c_api_test, quark_vm_tests, quark_vmasm_e2e_test,
      handoff_spy_e2e_test, quark_runtime_e2e_test) compiles with zero errors
      and all 7 test binaries pass via `ctest` on this machine (macOS).

### Not done yet (Phases B and C, tracked separately)
- `Dev_Keygen`, `Paste_Test`, and `DRM_Wrapper` remain Windows-only --
  they need the portable mbedTLS-based HTTPS client (Phase B) before they
  can be ported; `DRM_Wrapper` additionally needs Phase C's integration
  work (wiring the already-written-but-unused `process_handoff`/
  `DebuggerDetected` code, and replacing its hand-rolled duplicate of
  `RunUnlockFlow`'s logic with a real call to it).
- Linux was not available to test against in this session; Phase A's
  Linux-specific code paths (`LinuxHwidBackend`, the POSIX branches in
  `handoff_spy`/`quark-runtime-c`) compile against the same interfaces
  already verified on Linux elsewhere in this repo, but were not
  independently re-run on a Linux machine in this pass.

## Phase XI — Cross-platform port, Phase B: portable HTTPS client + Paste_Test/Dev_Keygen
Implements Phase B of docs/superpowers/specs/2026-07-05-cross-platform-
porting-roadmap.md.

- [x] `quark::online`'s crypto half (`BuildSignMessage`/`SealPayload`/
      `UnsealPayload`/`SignPayload`/`VerifySignature`/`GenerateKeypair`) moved
      verbatim into `quark_core` (`online_crypto.cpp`) -- it never touched
      WinHTTP, so this was a pure move, not a rewrite. Covered by new real
      (non-network) tests exercising actual PSA ECDSA sign/verify.
- [x] `quark::online`'s HTTP half (`PostPaste`/`FetchPaste`/`DeletePaste`)
      rewritten on mbedTLS's own `net`/`ssl`/`x509` modules (`online_http.cpp`,
      also `quark_core`) instead of WinHTTP -- one implementation for every
      OS and every consumer (Dev_Keygen, Paste_Test, and later DRM_Wrapper in
      Phase C). Pins paste.rs's issuing CA certificate (not a full CA bundle,
      not the leaf -- the leaf rotates every ~90 days, the issuing
      intermediate is valid through 2028-09-02).
- [x] Fixed a real interoperability bug Phase A introduced: `Dev_Keygen`
      still parsed `hwid.json` via the legacy, Windows-only
      `quark::hwid::FromJson`, which cannot read the new cross-platform
      `quark::platform::FingerprintToJson` format `HWID_Extractor` now
      writes. Both of `Dev_Keygen`'s HWID-consuming call sites switched to
      `quark::platform::FingerprintFromJson`/`CanonicalBytes`.
- [x] `Dev_Keygen` and `Paste_Test` un-gated from `if(WIN32)` -- both were
      already ~90% portable per the roadmap's audit; the HTTP client and the
      JSON-format fix were the only real blockers.
- [x] Verified for real end to end on this machine (macOS): a live
      POST/GET/DELETE cycle through `Paste_Test` against the real `paste.rs`
      service; `Dev_Keygen --dev` minting a real `state.bin` from a real
      Phase-A-produced `hwid.json`; `Dev_Keygen`'s real (non-dev) `--setup` +
      license-issuance + `--list` + `--revoke` flow, including a real
      `DeletePaste` call against live paste.rs from `Dev_Keygen`'s own
      `--revoke` code path.
- [x] Removed the now-dead `winhttp` library link from `quark_platform_win`
      (nothing else in that target used it).
- [x] Full "all" build (11 targets, including `Dev_Keygen` and `Paste_Test`
      for the first time) compiles with zero errors; all 7 `ctest` binaries
      still pass.

### Not done yet (Phase C, tracked separately)
- `DRM_Wrapper` remains Windows-only -- it needs Phase C's integration work
  (wiring the already-written-but-unused `process_handoff`/
  `DebuggerDetected` code for macOS/Linux, and replacing its hand-rolled
  duplicate of `RunUnlockFlow`'s logic with a real call to it) on top of this
  phase's HTTP client for its online-witness fetch.
- The pinned CA certificate in `online_http.cpp` is a manually-captured,
  point-in-time value (valid through 2028-09-02) -- there is no automated
  monitoring for paste.rs rotating its issuing CA before then; the file's own
  comment documents the exact `openssl` command to re-derive it if the pin
  ever starts rejecting real connections.
- Linux was not available to test against in this session; Phase B's changes
  touch no Linux-specific code paths (the new HTTP client and the HWID JSON
  fix are both fully portable, OS-agnostic C++), but were not independently
  re-run on a Linux machine in this pass.

## Phase XII — Cross-platform port, Phase C: DRM_Wrapper
Implements Phase C of docs/superpowers/specs/2026-07-05-cross-platform-
porting-roadmap.md -- the last of the six originally Windows-only programs.

- [x] `quark::config::Config` implemented for real (`config.cpp`) --
      previously declared in a header with zero implementation anywhere in
      the repo. Covered by a real filesystem round-trip test.
- [x] `quark::orchestrator::RunUnlockFlow` extended: real online-witness
      fetch/decrypt/signature-verify (using Phase B's portable HTTP client --
      previously this path unconditionally failed for any non-dev-mode
      license), plus `handoff_secret`/`initial_seal` added to `UnlockResult`
      (without these, no caller could actually build a QKH2 frame from this
      function's output at all). Covered by a real, live-network end-to-end
      test (`orchestrator_online_test`, deliberately not part of the default
      `ctest` run, matching `Paste_Test`'s precedent).
- [x] The dormant `quark::platform::posix::process_handoff` and macOS/Linux
      `DebuggerDetected()` implementations -- written in an earlier,
      since-abandoned design pass and never added to any CMake target --
      wired into `quark_platform_macos`/`quark_platform_linux` for real.
- [x] `DRM_Wrapper`'s `main.cpp` rewritten from a ~250-line Windows-specific
      hand-rolled duplicate of `RunUnlockFlow`'s logic into a single
      portable flow with four `#ifdef`-selected seams (anti-debug, HWID
      backend, witness stores, process launch/challenge-loop). Jar path/hash
      and JVM launch settings are now config-driven
      (`drm_wrapper.conf`/`quark::config`) instead of hardcoded, per
      CLAUDE.md rule 2.
- [x] Verified for real on macOS: a full `DRM_Wrapper` launch cycle against
      a real, freshly Dev_Keygen-minted `state.bin`, using `handoff_spy` as
      the JVM stand-in -- real anti-debug check, real jar-hash check against
      a config-overridden digest, real `RunUnlockFlow` execution (HWID
      collect, witness mint/cross-check, chain roll), a real QKH2 handoff
      over real POSIX pipes, and a real challenge-response cycle. Also
      verified the Lamport chain genuinely persists and rolls forward
      across separate process invocations (a replayed first key correctly
      fails on the second run; the still-valid second key succeeds).
- [x] All six originally Windows-only programs (`HWID_Extractor`,
      `handoff_spy`, `quark-runtime-c`, `Paste_Test`, `Dev_Keygen`,
      `DRM_Wrapper`) are now cross-platform. The
      docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md
      roadmap is complete.

### Not done yet
- Linux was not available to test against in this session. Every
  Linux-specific code path this phase touches (`LinuxHwidBackend`,
  `quark::platform::linux_::DebuggerDetected`, `process_handoff.cpp`
  compiled into `quark_platform_linux`, `XattrWitnessStore`) either already
  had independent Linux verification from earlier phases of this project, or
  (for `process_handoff.cpp`/anti-debug) is identical POSIX code already
  verified for real on macOS in this phase -- but the *whole, assembled*
  `DRM_Wrapper` binary itself has only been run end-to-end on macOS so far.
- Windows re-verification of the refactored `main.cpp` (same file, now built
  from shared logic instead of a hand-rolled copy) has not happened in this
  session -- no Windows machine was available. The Windows-specific code
  paths (`anti_debug.hpp`, `handoff.hpp`, `RegistryWitnessStore`/
  `AdsWitnessStore`/`OverlayWitnessStore`) are unchanged from before this
  phase; what changed is which function calls them.
- No anti-tamper/obfuscation hardening was added or changed -- out of scope,
  consistent with this project's standing sequencing (CLAUDE.md: that comes
  last, after the core is clean and correct).

## Phase XIII — Adversarial robustness testing of the fully assembled DRM_Wrapper
With all six programs cross-platform (Phase X-XII), this phase asks a
different question: not "does it build and run everywhere" but "does it
actually resist real attacks against the real, assembled binary". Every
check here spawns the real compiled `DRM_Wrapper` via fork/exec and inspects
its real exit code and stderr -- no mocked filesystem, no stubbed crypto.

- [x] `cpp/drm_wrapper/tests/drm_wrapper_robustness_test.cpp` (macOS-only for
      now) added to the default `ctest` suite -- 13 real adversarial
      scenarios against a genuinely minted license and this machine's real
      HWID: tampered `state.bin`, a license minted for a different machine
      (proves CLAUDE.md rule 2's "tampering and wrong-machine are
      indistinguishable" for real), selective/total witness absence, a
      forged future high-water mark (clock-rollback detection), chain
      exhaustion, malformed/never-issued keys, a swapped/missing jar
      (including proving the jar check fires *before* the key is ever
      consumed), and a concurrent-launch race. Runs in ~2 seconds.
- [x] **Found and fixed: the challenge-response heartbeat interval/timeout
      were hardcoded constants** (`kChallengeIntervalMs = 30'000` /
      `kResponseTimeoutMs = 10'000` in both `process_handoff.cpp` and the
      Windows `handoff.hpp`) -- a direct CLAUDE.md rule 2 violation, and the
      reason a single successful launch scenario would otherwise cost 30
      real seconds. Both now take these as parameters (defaults unchanged);
      `DRM_Wrapper`'s `main.cpp` reads `challenge_interval_ms`/
      `challenge_timeout_ms` from config. The test suite overrides them to
      200 ms/2 s, which is why it runs in ~2 seconds instead of ~3 minutes.
- [x] **Found and fixed: a real, reproducible license-clone race.**
      `quark::state::Save`/`Load` and `IWitnessStore::Save`/`Load` had no
      locking. A first attempt at reproducing this showed only 1 of 5-10
      concurrent launches succeeding -- but investigation revealed that was
      an *accidental* side effect of `WriteFileAtomic` using a fixed
      `path + ".tmp"` intermediate filename, which made concurrent writers
      collide and fail loudly (`kWrapperOverlayWriteFailed` /
      `kWrapperStatePersistFailed`) rather than actually excluding each
      other. Fixing that collision (a random suffix instead of a fixed
      `.tmp` name, in both `state.cpp` and `platform_file_witness_store.cpp`)
      *removed* that accidental serialization and exposed the real
      race underneath: **7 of 10 concurrent launches with the same
      single-use key all succeeded**, each getting its own valid
      `handoff_secret`/session with the real `handoff_spy` -- a genuine
      license clone, not a theoretical TOCTOU. Fixed for real with a new
      `quark::platform::IProcessLock` abstraction (`FlockProcessLock` on
      POSIX via `flock(2)`, `LockFileProcessLock` on Windows via
      `LockFileEx`, not yet re-verified on real Windows) that
      `RunUnlockFlow` acquires before touching `state.bin` and releases on
      every return path; `DRM_Wrapper` always supplies one. Re-verified
      after the fix: exactly 1 of 10 concurrent launches succeeds, every
      other one cleanly reports the real current chain state
      (`kWrapperLicenseExhausted`/`kWrapperUnlockKeyInvalid`), and this is
      now scenario 13 of the permanent regression suite (8-way concurrent
      launch, asserts exactly one success).
- [x] Verified for real with an actual attached debugger (`lldb`): launching
      `DRM_Wrapper` under `lldb --batch -o "process launch -i /dev/stdin"`
      trips `kWrapperDebuggerDetected` and exits before the license flow
      (state.bin, witnesses, key prompt) ever runs -- a one-off manual
      verification, not part of the automated suite (running under a
      debugger changes process semantics in ways not worth automating).

### Not done yet
- The robustness test suite is macOS-only (mints licenses via the real
  `MacHwidBackend` and crafts witness artifacts via
  `quark::platform::macos::XattrWitnessStore` directly) -- a Linux
  equivalent using `LinuxHwidBackend`/`linux_::XattrWitnessStore` is a
  tracked follow-up; no Linux machine was available when this was written.
- `LockFileProcessLock` (Windows) is written but not run on real Windows.
- ~~`quark_c_api`'s `RunUnlockFlow` call site does not yet pass an
  `IProcessLock`~~ -- **closed in a follow-up pass**: `quark_unlock_and_decrypt`
  now constructs a real `IProcessLock` (via the same per-OS factory pattern as
  `MakeHwidBackend`) and passes it through, with `QUARK_ERR_LOCK_FAILED`
  (4024) added to `quark_c_api.h` for callers that want to name the failure.
  Verified for real with `quark_c_api_lock_test.c` (new, POSIX-only, plain C
  + pthreads): 8 real threads calling `quark_unlock_and_decrypt` concurrently
  against the same single-use key through the actual C ABI -- exactly one
  succeeds, same property already proven for `DRM_Wrapper` itself. Native/FFI
  consumers (Go/Python/Rust/Java via the C ABI) are now covered too, whether
  they race across threads in one host process or across separate processes.
- This pass tested `DRM_Wrapper` adversarially; it did not attempt a
  systematic audit of `Dev_Keygen`, `HWID_Extractor`, `Paste_Test`,
  `handoff_spy`, or `quark-runtime-c` for the same class of issues (they are
  lower-value targets: dev-side tools, or -- for `handoff_spy`/
  `quark-runtime-c` -- test/reference infrastructure rather than the
  customer-facing shield).

## Phase XIV — Cross-language protection matrix (`examples/`)

Every real test up to this point exercised the JVM pipeline (Java) or the
C++ engine's own test suite. This phase asks a different question: does
Quark actually protect a program written in a language other than Java, for
real, using each of the two protection methods this engine claims to
support -- not just "does the C ABI compile from other languages."

- [x] Eight small demo programs added under `examples/{go,c,cpp,java}/
      method{1_wrapper,2_embedded}/`: method 1 ("protect an already-written
      program" -- `DRM_Wrapper` launches the target as an external QKH2
      client) and method 2 ("protect a program at the source level" -- the
      program calls `quark_c_api` directly), each in Go, C, C++, and Java.
      Go's method-1 demo deliberately uses **no cgo** -- a from-scratch,
      pure-Go re-implementation of the QKH2 client wire format straight from
      `docs/HANDOFF_PROTOCOL.md` (stdlib `crypto/sha256`/`crypto/hmac`
      only), the strongest possible proof that the protocol is genuinely
      language-agnostic. Java's method-2 demo uses the FFM/Panama API
      (`java.lang.foreign`, stable since JDK 22) instead of hand-written JNI
      glue.
- [x] **Found and fixed a real bug while wiring this up**: `Dev_Keygen
      --input-bundle`'s `core.enc` (magic `"QENC"`, tag placed after the
      ciphertext -- the format `java/drm-core`'s `CoreDecryptor` expects) and
      `quark_seal_payload`'s sealed format (`quark::payload`'s `"QPLD"`
      framing, tag placed right after the IV, explicit ciphertext-length
      prefix) are **not interchangeable**, even though both derive
      `core_enc_key` identically. An initial attempt to reuse `core.enc` for
      the method-2 demos failed for real with
      `QUARK_ERR_PAYLOAD_DECRYPT_FAILED` (5004) -- the license/HWID/key flow
      had all genuinely succeeded, only the payload framing mismatched.
      Fixed by adding `examples/tools/quark_seal_tool.cpp`, a small dev-side
      helper that seals a payload through the real, public
      `quark_seal_payload` call instead of reusing `core.enc`.
- [x] `examples/build_all.sh` -- builds all 8 demos plus `quark_seal_tool`
      against an already-built `quark_core`/`quark_c_api`/`quark-runtime-c`
      tree, with per-OS branching in place (macOS/Linux share a toolchain
      shape) though only exercised on macOS so far; a Windows equivalent is
      a tracked gap, same caveat as every other cross-platform claim in this
      log.
- [x] `tools/e2e-test`'s `quark.test.CrossLangE2ETest` -- a new, independent
      runner (alongside the existing `QuarkE2ETest`) that mints a fresh
      `--dev`-mode license per scenario, drives all 8 demos for real, and
      deletes every scenario's license/witness artifacts whether it passes
      or fails. Verified for real: 8/8 passing across 3 consecutive runs, no
      flakiness, no leftover state, and -- deliberately, per this project's
      own "don't hammer paste.rs" guidance -- zero network calls anywhere in
      the matrix (every license is `--dev`-mode).

### Not done yet
- Linux/Windows execution of this matrix -- written with OS detection in
  place, not independently run on either platform yet (no machine available
  this pass).
- No negative-path assertions (wrong key, tampered state) were added to
  `CrossLangE2ETest` itself -- that class of adversarial testing already
  exists for `DRM_Wrapper` (`drm_wrapper_robustness_test`, Phase XIII); this
  phase's scope was specifically "does protection work at all, per language,
  per method," matching what was asked.

## Phase XV — Quark VM architecture correction: single encryption layer, not two
Phase IX shipped `quark_vm` with its own internal encryption: each block
sealed independently under `vm_key = HMAC-SHA256(content_key, "QUARK-VM-KEY")`
via a `BlockCache` that decrypted on demand. This put **two** AES-GCM layers
in series on the same content -- the outer `core.enc` seal (keyed by
`content_key`) and `quark_vm`'s own per-block seal (keyed by `vm_key`, itself
just a domain-separated derivation of the same `content_key`) -- which
protects nothing an attacker doesn't already have to break at the outer
layer, and is redundant complexity for zero added guarantee (CLAUDE.md rule
3: simple over clever).

Corrected architecture: `qvm_aktif`'s output (a `quark::vm::Program`, plain
blocks of instructions) is serialized and becomes the plaintext that
`core.enc`'s single `quark::payload::Seal(content_key, ...)` call seals --
exactly the same relationship Java's `core.enc` already has with
`InMemoryClassLoader`'s custom wire format. `quark_vm` now has **zero**
dependency on `quark_core` and no notion of a key at all.

- [x] `Program`/`Block`: `sealed_blocks` (sealed bytes) -> `blocks` (plain
      `Instruction`s). `SealBlock` removed entirely.
- [x] `BlockCache` (decrypt-on-demand, ref-counted residency, idle-timeout
      `Sweep()`) deleted -- `Interpreter` now holds `const Program&` directly
      and fetches blocks with no decrypt step; an unknown block id still
      resolves to a fixed poison instruction (defensive parsing of a
      corrupt/truncated container, not a wrong-key case -- there is no
      second key to get wrong).
- [x] `quark::token::DeriveVmKey` removed from `quark_core` (dead code per
      the corrected architecture) along with its test in
      `core_smoke_test.cpp`.
- [x] `quark_vmasm` updated: drops the `vm_key_hex` CLI argument, produces a
      plain (unsealed) `.qvm` file. Explicitly repositioned in its own
      README as an internal test-fixture tool, not the developer-facing
      path -- `qvm_aktif` (an automatic translator from compiler-emitted IR,
      not yet built) is.
- [x] `cpp/quark_vm/tests/quark_vm_test.cpp` and `quark_vmasm_e2e_test.cpp`
      rewritten against the new crypto-free API. New
      `quark_vm_pipeline_test.cpp` added: proves the real, corrected
      architecture end to end (`SerializeProgram` -> real
      `quark::payload::Seal`/`Unseal` -> `DeserializeProgram` ->
      `Interpreter::Run()`, including the wrong-`content_key` case failing
      structurally at `Unseal`, before `quark_vm` ever runs). All four
      `quark_vm`/`quark_core` test binaries rebuilt and run for real under
      `sandbox/build-macos` after the change: 100% pass, zero mocks.
- [x] `sandbox/vm_spike/spike4_ir_to_qvm.cpp` and `spike6_control_and_host.cpp`
      removed -- both referenced the deleted `SealBlock`/`BlockCache` API;
      their real findings (LLVM-IR-derived bytecode translation is
      tractable, control flow and host-function dependencies both work
      through the real interpreter) are now permanently encoded in the real
      test suite above instead of disposable spike files. The unrelated
      Path B (raw native-code fragmentation) spikes 1/2/3/5 are untouched --
      a different mechanism, not affected by this correction.
- [x] `CLAUDE.md` rule 8 and `cpp/quark_vm/README.md` rewritten to describe
      the corrected single-encryption-layer pipeline as current, authoritative
      fact; the original design spec
      (`docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-
      interlocking-design.md`) is left as historical record with a pointer to
      the correction rather than rewritten in place.

### Explicitly not done yet (do not claim otherwise)
- `qvm_aktif` (the automatic compiler-IR-to-`Program` translator) does not
  exist yet. Today, building a real `Program` means constructing
  `quark::vm::Block`/`Instruction` values directly or using `quark_vmasm`'s
  hand-authored text format -- both fine for internal tests, neither is the
  intended developer path for protecting a real program.
- `HostFunctionTable`'s C-ABI shape is still not wired into
  `cpp/quark_c_api`'s public header (carried over from Phase IX, unaffected
  by this correction).
- The single-encryption pipeline above is proven at the `quark_vm`/
  `quark::payload` level (`quark_vm_pipeline_test.cpp`), not yet wired into
  `Dev_Keygen`'s actual `core.enc` production or `quark_c_api`'s actual
  unlock path -- that integration is the natural next step once `qvm_aktif`
  exists.

**Superseded by Phase XVI below**: `quark_vm`/`quark_vmasm` were removed
entirely. The bytecode-translation approach this phase corrected the
encryption layering for turned out to have a deeper problem -- see Phase
XVI's rationale.

## Phase XVI — Quark VM replaced by Quark Codecipher: real machine code,
## not a new instruction set
Phase XV corrected quark_vm's encryption *layering* (one AES-GCM pass, not
two). It did not question the approach's core premise: translating a
protected program's logic into `quark_vm`'s own bytecode instruction set,
then interpreting it. Real user testing of that premise surfaced two
problems neither Phase IX nor Phase XV caught:

1. **Zero developer effort was never actually achieved.** Building a real
   `Program` still meant either hand-authoring `.qvmasm` text (explicitly,
   repeatedly rejected -- "elle .qvasm yazmaya tamamen karşıyım") or
   constructing `Block`/`Instruction` values directly in C++ (what every
   quark_vm test did). `qvm_aktif` -- the automatic compiler-IR-to-bytecode
   translator that would have closed this gap -- was flagged as missing in
   Phase XV and never built.
2. **The opcode set structurally cannot represent a real program's full
   operations**, even with `qvm_aktif` built: quark_vm's minimal integer
   stack-machine (23 opcodes, `int64_t`-only) has no floats, no direct
   memory/pointer access, no strings, no syscalls beyond a fixed
   `CALL_HOST` table. Unlike Java's `core.enc` (whose plaintext is real JVM
   bytecode -- a complete, compiler-native target), quark_vm invented its
   own reduced target. "Protect the whole program" was never actually
   achievable this way; only "protect the subset of logic expressible as
   integer arithmetic + control flow + host calls" was.

The corrected approach, `quark_codecipher`: never translate to a new
instruction set at all. Reversibly **scramble** a program's own real,
compiled machine code (AES-256 in CTR mode -- a keyed keystream XOR, its own
inverse, no per-chunk auth-tag overhead unlike GCM) and **reconstruct** it
byte-for-byte at runtime, then run it directly on the CPU. No interpreter
loop, no semantic translation, no opcode-coverage ceiling -- whatever the
compiler can emit, this mechanism can protect.

- [x] `quark::crypto::Aes256CtrXor` added to `quark_core` (real
      `mbedtls_aes_crypt_ctr`-backed keystream XOR, symmetric: the same call
      scrambles and reconstructs given the same key+nonce). Real tests in
      `core_smoke_test.cpp`: round-trip reconstructs exactly, wrong key does
      not.
- [x] `quark::token::DeriveCodeStreamKey(content_key)` added, following the
      established `Derive*`/domain-separation convention
      (`"QUARK-CODE-STREAM-KEY"`).
- [x] `cpp/quark_vm` and `cpp/quark_vmasm` deleted entirely (not deprecated
      in place -- removed, per the explicit "temiz bir implementasyon"
      request; git history preserves them if ever needed again).
- [x] New module `cpp/quark_codecipher` (macOS-only, gated behind
      `if(APPLE)` in the top-level `CMakeLists.txt`):
  - `relocation.{hpp,cpp}` -- real ARM64 ADRP/B/BL/B.cond bit-pattern
    classification, absolute-target decode, and re-encode-for-new-address,
    generalizing the exact mechanics validated by the (now-deleted)
    `sandbox/vm_spike` spikes 1/2/5 into permanent, reusable code.
  - `region.{hpp,cpp}` -- `CodeRegion` (scrambled bytes + nonce + a
    relocation list) and its plain-byte container format. Becomes
    `core.enc`'s plaintext payload, same single-outer-AES-GCM-layer
    principle as Phase XV established for `quark_vm::Program`.
  - `capture.{hpp,cpp}` (Module 1): scans real, live function bytes for
    PC-relative instructions, classifies each target as INTERNAL (inside
    the captured byte range -- needs no relocation, since the whole region
    moves together and relative offsets stay correct automatically, proven
    both algebraically and for real) or EXTERNAL (recorded as a
    relocation), then scrambles the whole buffer.
  - `materialize.{hpp,cpp}` (Module 2, macOS): `mmap(MAP_JIT)`,
    reconstructs the real bytes via the same `Aes256CtrXor` call,
    patches every external relocation for the new address, flips to
    executable via `pthread_jit_write_protect_np`, returns a real,
    callable function pointer.
- [x] Real, permanent fixture-based tests (not disposable spikes):
      `tests/fixtures/{tiny_func,branchy_func,dep_func}.c` compiled into a
      real dylib at build time via CMake, `dlopen`'d by
      `quark_codecipher_test.cpp` (no relocations / internal-only
      relocations / external relocations, each verified against the real
      function's own output or an analytically known expected value) and
      `quark_codecipher_pipeline_test.cpp` (the full single-encryption
      pipeline: `Capture` -> `Serialize` -> real `quark::payload::Seal` ->
      `Unseal` -> `Deserialize` -> `Materialize` -> execute, plus the
      wrong-`content_key` case failing structurally at `Unseal` before
      `quark_codecipher` ever runs). All verified for real on real ARM64
      machine code under `sandbox/build-macos`: 100% pass, including a real
      mutated global and a real `printf` call through patched relocations.
- [x] `sandbox/vm_spike/` deleted in full (gitignored, disposable; its
      findings now live permanently in `quark_codecipher`'s real test
      suite).
- [x] `CLAUDE.md` rule 8, the internal walkthrough document §7, and the module-map table
      rewritten to describe `quark_codecipher` as the current mechanism;
      `quark_vm`'s original design spec is left untouched as historical
      record (already carries Phase XV's amendment note).

### Explicitly not done yet (do not claim otherwise)
- **Linux and Windows equivalents of `Materialize`'s executable-memory
  handling do not exist.** `quark_codecipher` is gated behind `if(APPLE)`
  at the top level for exactly this reason.
- **Relocation detection is a heuristic bit-pattern scan, not a real
  disassembler or linker relocation records.** A 4-byte word that happens
  to match ADRP/B/BL/B.cond's bits but is actually embedded literal data
  (a jump table, a constant pool entry) would be misclassified. Verified
  only against straight-line, internally-branchy, and externally-dependent
  compiler output -- not against arbitrarily complex real programs.
- **CBZ/CBNZ/TBZ/TBNZ and PC-relative literal loads (`LDR` literal) are not
  handled.**
- **`Capture` reads already-loaded, same-process function bytes** (via
  `dlopen`, exactly like its own tests) rather than a real dev-time
  toolchain step reading a linker's relocation records for a function that
  hasn't been loaded into this process. The same class of gap as the
  never-built `qvm_aktif` -- the RUNTIME mechanism is proven for real; the
  dev-time capture-from-a-built-binary tool is not.
- Not yet wired into `Dev_Keygen`'s actual `core.enc` production or
  `quark_c_api`'s actual unlock path -- proven at the `quark_codecipher`/
  `quark::payload` level only, same as Phase XV left `quark_vm`.
