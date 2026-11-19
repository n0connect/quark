# Quark Native DRM Launcher (`DRM_Wrapper`)

`DRM_Wrapper` is the main parent process executable that serves as the customer-facing security shield. It implements anti-debugging, machine fingerprinting, license verification, witness verification, online witness signature validation, and manages the lifecycle of the protected Java virtual machine (JVM).

---

## File Registry & Components

*   [main.cpp](main.cpp): The central coordinator driving the sequence from startup checks to the final process handoff.
*   [anti_debug.hpp](anti_debug.hpp): Runs active anti-analysis checks including `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, and direct PEB (Process Environment Block) reads of `BeingDebugged` and `NtGlobalFlag`.
*   [fail_deadly.hpp](fail_deadly.hpp): Defines the `FailDeadly(Code)` mechanism. On anomaly detection, it prints a user-friendly code, writes the detailed error to a local log file, and immediately calls `ExitProcess(1)`.
*   [handoff.hpp](handoff.hpp): Controls child process spawning via Win32 `CreateProcessW`. Redirects the child's stdin/stdout to dedicated anonymous pipes.
*   [secret.hpp](secret.hpp): Contains the private static constants: the 32-byte compile-time build secret `kBuildSecret` and the Elliptic Curve signature verification key `kEcPublicKey`.
*   [jar_digest.hpp](jar_digest.hpp): Holds the expected SHA-256 hash of `quark.jar`.

---

## Core Flow & Operations

### 1. Verification Checklist
Before running the application, `DRM_Wrapper` performs the following steps:
1.  **Anti-Debugging**: Scans environment. Any hook results in an immediate crash.
2.  **JAR Integrity Verification**: Reads `quark.jar` and checks its SHA-256 against `kQuarkJarSha256` defined in [jar_digest.hpp](jar_digest.hpp).
3.  **Local HWID Extraction**: Collects the host machine signature canonical bytes.
4.  **Decrypt state.bin**: Uses the hardware signature as Associated Authenticated Data (AAD) for AES-256-GCM.
5.  **Multi-Channel Witness Check**: Loads and verifies state data against HKCU registry, NTFS Alternate Data Streams (ADS) in ThemeCache, and binary overlay storage. All witnesses must match exactly. On macOS/Linux, the same logic runs against two xattr-backed channels plus one portable file-backed channel instead of registry/ADS/exe-overlay -- see CLAUDE.md's witness-channel table.
6.  **Clock-ratchet Check**: Checks current unix time against the highest witness watermarks to block system clock resets.
7.  **Online Witness**: If a paste ID is registered, pulls from `paste.rs`, verifies the ECDSA signature, and incorporates the retrieved secret into key derivation.
8.  **Redeem Token**: Prompts the user for a redemption token. Verifies the input against the Lamport hash anchor.
9.  **Writeback State**: Rolls the Lamport anchor forward, decrements remaining links, and updates `state.bin` and all secondary witnesses simultaneously.

### 2. Bi-directional Process Handoff
Once the activation is approved, the wrapper handles execution:
1.  Derives the temporary `handoff_secret` and persistent `core_enc_key`.
2.  Builds the 136-byte QKH2 initialization packet and writes it to the JRE stdin pipe.
3.  The JVM reads the frame and boots `QuarkHeartbeat`.
4.  Every `challenge_interval_ms` (default 30000), `DRM_Wrapper` sends a `"CHAL"` frame containing a nonce and counter.
5.  `DRM_Wrapper` expects a 32-byte HMAC-SHA256 response from the JVM stdout within `challenge_timeout_ms` (default 10000). Failure to respond causes an immediate exit and terminates the child process.

### 3. Concurrent-launch exclusion
Before touching `state.bin` at all, `RunUnlockFlow` acquires a
`quark::platform::IProcessLock` (a real `flock(2)`-backed lock on
macOS/Linux, `LockFileEx` on Windows) tied to `state_path`, held until the
chain has rolled and every witness has been rewritten. Two `DRM_Wrapper`
launches racing on the same license can no longer both redeem the same
single-use key -- see [drm_wrapper_robustness_test.cpp](tests/drm_wrapper_robustness_test.cpp)'s
concurrent-race scenario and CLAUDE.md rule 6 for the real (not
theoretical) race this closes.

---

## Compilation

Cross-platform as of Phase C of docs/superpowers/specs/2026-07-05-cross-
platform-porting-roadmap.md -- config-driven (see
[drm_wrapper.conf.example](drm_wrapper.conf.example)) and built on
`quark::orchestrator::RunUnlockFlow` instead of a Windows-specific
hand-rolled copy of the same logic.

```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target DRM_Wrapper
```
Outputs `sandbox/build-host/cpp/drm_wrapper/DRM_Wrapper` (or
`DRM_Wrapper.exe` on Windows). Copy `drm_wrapper.conf.example` to
`drm_wrapper.conf` next to the binary and adjust for your deployment --
every key has a built-in fallback matching the original Windows defaults, so
an empty/missing config file preserves prior behavior.

On macOS/Linux, `handoff_spy` (see [cpp/handoff_spy](../handoff_spy/README.md))
can stand in for a real JVM during testing -- point `jvm_path` at it in
`drm_wrapper.conf`.

## Testing

[tests/drm_wrapper_robustness_test.cpp](tests/drm_wrapper_robustness_test.cpp)
(macOS-only for now, part of the default `ctest` suite) spawns the real
compiled `DRM_Wrapper` against a real, freshly minted license and checks its
real exit code/stderr across 13 adversarial scenarios: tampered `state.bin`,
a license minted for the wrong machine, selective/total witness absence, a
forged clock-rollback witness, chain exhaustion, malformed/never-issued
keys, a swapped/missing jar, and a concurrent-launch race. Runs in ~2
seconds; see docs/PLAN.md's Phase XIII for what it found.
