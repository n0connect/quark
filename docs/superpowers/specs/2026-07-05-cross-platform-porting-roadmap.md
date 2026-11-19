# Cross-platform porting roadmap: the six Windows-only programs

Status: design approved by user (delegated -- "ne yaparsan yap"), roadmap document,
not itself an implementation plan. Each phase below gets its own implementation
plan via `superpowers:writing-plans` before code is touched.
Date: 2026-07-05

## Motivation

Six executables in this repo are still 100% Windows-only, gated behind
`if(WIN32)` in the top-level `CMakeLists.txt` (`cpp/quark-runtime-c` isn't even
wired into the build at all): `DRM_Wrapper.exe`, `Dev_Keygen.exe`,
`HWID_Extractor.exe`, `Paste_Test.exe`, `handoff_spy.exe`, and the
`quark-runtime-c` static library. `quark_core`, `quark_c_api`, `quark_vm`, and
`quark_vmasm` are already genuinely cross-platform (built and tested for real
on this machine). This spec covers making the remaining six the same way --
**one implementation per concern, OS-specific code only where an OS API is
genuinely unavoidable** (HWID collection, witness storage) -- not six
parallel, Windows-flavored programs with no shared logic.

An audit (see the per-program breakdown below) found that most of the
Windows-specific surface in these six programs already has a portable
replacement sitting in the repo, sometimes literally unused:

- `quark::orchestrator::RunUnlockFlow` (built earlier this project, portable,
  pure) already does everything `DRM_Wrapper.exe`'s `main.cpp` hand-rolls a
  **second, Windows-specific copy of** -- HWID collection, `state.bin` open,
  three-witness cross-check, chain verification, key derivation. This
  duplication predates this spec and should be removed as part of the port,
  not preserved.
- `quark::platform::posix::process_handoff` (fork/exec/pipe QKH2 handoff,
  identical wire protocol to the Windows `CreateProcess`/pipe version) and
  `quark::platform::macos::DebuggerDetected()` /
  `quark::platform::linux::DebuggerDetected()` were written during an earlier,
  since-abandoned design pass and left deliberately unused ("Dursun, dokunma"
  -- see `docs/PLAN.md` Phase VIII's "Explicitly deferred" section). They are
  directly reusable here.
- `quark_platform_macos`/`quark_platform_linux` already implement
  `IHwidBackend` and `IWitnessStore` for real (verified this session via
  `quark_c_api_test`'s 1 FILE + 2 XATTR witness setup).
- The one genuinely missing piece, needed by four of the six programs, is a
  **portable HTTPS client for paste.rs** (`quark::online`'s `PostPaste`/
  `FetchPaste`/`DeletePaste` are WinHTTP-only today; the crypto half of that
  same file -- `SealPayload`/`UnsealPayload`/`SignPayload`/`VerifySignature`/
  `GenerateKeypair` -- is already portable mbedTLS/PSA code with no WinHTTP
  dependency, just physically sitting in the same Windows-gated file).

## Decision: the portable HTTP client is mbedTLS-based, not curl-subprocess

`quark_core` already links `mbedtls` (the actual TLS/SSL library target, not
just `mbedcrypto`) publicly -- confirmed via `cpp/common/CMakeLists.txt` and
the real build log (`ssl_tls13_client.c`/`ssl_tls13_server.c` etc. already
compile into every build on every OS). This means a portable HTTPS client can
be built with **zero new external dependencies** using `mbedtls_net_connect`
+ `mbedtls_ssl_*`, statically linked exactly like the rest of Quark.

This was chosen over shelling out to a system `curl` binary because:
- `DRM_Wrapper.exe` is customer-facing and runs on a machine Quark does not
  control. A `curl` subprocess dependency (must be installed, must be in
  `PATH`, must be the real curl and not a different tool of the same name)
  is a new, avoidable failure mode CLAUDE.md's "static linking only, zero
  runtime DLL dependencies" posture was written to prevent in spirit, even
  though that rule's literal text is about DLLs specifically.
- One mbedTLS-based implementation, in `quark_core`, is usable identically by
  `DRM_Wrapper` (customer runtime), `Dev_Keygen`/`Paste_Test` (developer
  tooling), and the license-management tool from the earlier conversation in
  this session -- exactly the "one shared implementation, not five" principle
  this whole roadmap exists to satisfy.

**Certificate handling: pinning, not a CA bundle.** Quark only ever talks to
one fixed host (`paste.rs`). Bundling/maintaining a Mozilla root CA store
portably (and keeping it updated) is unnecessary complexity for a single-host
client. Instead, `quark::online`'s new HTTP layer pins paste.rs's server
certificate's SPKI (Subject Public Key Info) hash, verified during the TLS
handshake via mbedTLS's certificate-verification callback. This is a
**hardcoded, crypto-load-bearing constant** in the CLAUDE.md rule 2 sense (the
justification lives in a comment at the point of use, per that rule) --
config would just move the attack surface (an attacker who can rewrite a
config file can already MITM the connection) without adding real value, and
pinning is *more* secure than trusting an arbitrary CA for a single known
host. The pin needs a documented rotation procedure (paste.rs could rotate
its cert) -- covered in the Phase B plan.

## Per-program audit summary

| Program | Windows-specific surface | Portable replacement | New work | Effort |
|---|---|---|---|---|
| `HWID_Extractor` | None at the app level -- already calls the portable `quark::hwid`/JSON path | `IHwidBackend` already implemented on macOS/Linux | Remove the `WIN32` build gate | Trivial |
| `handoff_spy` | CNG (`bcrypt.dll`) HMAC-SHA256, `HANDLE`-based stdin/stdout, `SecureZeroMemory` | `quark::crypto::HmacSha256`/`SecureZero` (mbedTLS, already linked); POSIX `read`/`write` on fd 0/1 | None -- direct swap | Trivial |
| `quark-runtime-c` | Same CNG/HANDLE pattern as `handoff_spy`, plus `CreateThread`/`ExitProcess` | Same crypto swap; `std::thread` for the heartbeat thread | None -- direct swap. Also needs wiring into the top-level build at all (currently absent) | Trivial |
| `Paste_Test` | WinHTTP calls in `quark::online` | Crypto half of `online.cpp` already portable | The new mbedTLS-based HTTP client (shared with Dev_Keygen) | Medium (shared cost with Dev_Keygen) |
| `Dev_Keygen` | Same WinHTTP dependency; one `#ifdef _WIN32`/`gmtime_s` branch (already has a POSIX branch written) | File I/O, JSON, crypto, token/lamport all already portable | Same shared HTTP client | Medium |
| `DRM_Wrapper` | WinHTTP (online witness), `CreateProcess`+pipes (`handoff.hpp`), PEB reads/`IsDebuggerPresent` (`anti_debug.hpp`), `GetSystemTimeAsFileTime`, registry/ADS/overlay witness stores, **and a hand-rolled duplicate of `RunUnlockFlow`'s entire logic** | `RunUnlockFlow` (removes the duplication entirely), `quark::platform::posix::process_handoff` (already written, unused), `quark::platform::macos/linux::DebuggerDetected()` (already written, unused), `IWitnessStore` macOS/Linux backends (already implemented), `std::chrono` for time | Same shared HTTP client; wiring the above four already-written pieces together; refactoring `main.cpp` to call `RunUnlockFlow` instead of reimplementing it | Medium-High (mostly integration, not new logic) |

## Phased plan

Each phase is independently shippable and gets its own `writing-plans` cycle.
Ordered so later phases build on earlier ones and nothing blocks on the
hardest piece first.

### Phase A -- the zero-new-infrastructure programs
`HWID_Extractor`, `handoff_spy`, `quark-runtime-c`. No new shared
infrastructure needed -- direct swaps (CNG -> mbedTLS, `HANDLE` I/O -> POSIX
fd I/O, `CreateThread` -> `std::thread`) plus removing/adding CMake gates.
Each gets real build+run verification on this machine (macOS) per CLAUDE.md
rule 1 -- `handoff_spy` and `quark-runtime-c` in particular need an actual
QKH2 frame round-tripped through real pipes, not just a clean compile.

### Phase B -- the portable HTTPS client + `Paste_Test`/`Dev_Keygen`
Build `quark::online`'s HTTP layer on mbedTLS (`mbedtls_net_connect` +
`mbedtls_ssl_*`, SPKI-pinned to paste.rs), replacing the WinHTTP
implementation. Split `online.cpp`'s already-portable crypto functions out so
they build on every OS regardless of the HTTP layer's state. Port
`Paste_Test` (a live network integration test -- the natural first real-world
exerciser of the new client) and `Dev_Keygen` (issuance/revocation) to use it.
Real test: an actual POST/GET/DELETE cycle against the live `paste.rs`
service from this machine.

### Phase C -- `DRM_Wrapper`
The integration phase: refactor `main.cpp` to call `RunUnlockFlow` instead of
its own duplicate logic, wire `process_handoff`/`DebuggerDetected` for
macOS/Linux (keeping the existing Windows code path for Windows builds,
selected the same way `quark_platform_<os>` already is), and use Phase B's
HTTP client for the online witness fetch. This is the module CLAUDE.md's
"Target platform" section already flags as the known gap ("what's still
missing... is an actual DRM_Wrapper-equivalent orchestrator binary") -- this
phase closes it for real, with real testing (a full unlock cycle against a
real `state.bin` + real witness files on this machine, and -- since
`handoff_spy` is ported in Phase A -- a real end-to-end pipe handoff test
without needing a JVM).

## Non-goals

- Re-verifying the *existing* Windows build on real Windows hardware is out
  of scope for this roadmap (no Windows machine available in this session);
  each phase's changes to Windows-specific code paths are limited to "select
  the right implementation per OS," not rewriting the Windows path itself.
- Anti-debug/anti-tamper *hardening* beyond what already exists
  (`DebuggerDetected()`'s current sysctl/PEB-read level) is explicitly out of
  scope, consistent with this project's standing "obfuscation/anti-tamper
  comes last" sequencing.
- The license/paste-management CLI discussed earlier in this session is a
  separate, later piece of work (it depends on Phase B's HTTP client existing
  first) and is not part of this roadmap's three phases.

## Testing strategy (applies to every phase)

CLAUDE.md rule 1, restated for this specific work: every ported program must
actually **run** on this machine after porting, not just compile. "Compiles
on macOS" is not the bar -- `handoff_spy` piping real bytes to a real child
process's stdin, `Dev_Keygen` actually POSTing to the live paste.rs and
getting a real paste ID back, `DRM_Wrapper` actually walking through a real
unlock against a real `state.bin` it minted -- these are the actual
acceptance criteria per phase.
