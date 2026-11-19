# Quark VM: cryptographically interlocked protected logic

Status: design approved by user, not yet implemented.
Date: 2026-07-04

> **Amendment (Phase XV, docs/PLAN.md):** this spec's per-block sealing
> design -- `vm_key = HMAC-SHA256(content_key, "QUARK-VM-KEY")` and a
> `BlockCache` that decrypts each block independently -- was implemented as
> written, then found to put two AES-GCM layers in series on the same
> content (the outer `core.enc` seal plus this module's own per-block seal)
> for no added guarantee, and was removed. The corrected architecture has
> `quark_vm` performing zero cryptography: a `Program`'s serialized bytes
> are the plaintext that `core.enc`'s single, pre-existing
> `quark::payload::Seal(content_key, ...)` call seals directly. Every
> section below describing `vm_key`/`BlockCache` reflects the original,
> superseded design.
>
> **Second amendment (Phase XVI, docs/PLAN.md):** `quark_vm` and
> `quark_vmasm` were subsequently removed from the tree entirely. Real user
> testing found the deeper problem Phase XV didn't catch: translating a
> protected program's logic into a bytecode instruction set -- even with
> the encryption layering fixed -- still required either hand-authored
> `.qvmasm` (rejected) or a never-built automatic translator, and even then
> could only represent a narrow, hand-picked opcode subset of a real
> program's operations (no floats, no memory/pointer access, no syscalls).
> `cpp/quark_codecipher` replaced it: it never translates to a new
> instruction set at all, instead reversibly scrambling (AES-256-CTR) and
> reconstructing a program's OWN real machine code byte-for-byte. This
> entire document -- including everything the first amendment marked as
> "current architecture" -- is now purely historical. Treat
> `cpp/quark_codecipher/README.md` and CLAUDE.md rule 8 as authoritative.
> The opcode set, W^X rationale for an interpreter, and non-goals below no
> longer describe any code in this repository.

## Motivation

Quark's core guarantee has always been that a protected application's *function*,
not just an access flag, depends on cryptographic material only a licensed machine
can produce (CLAUDE.md rule 3, "no boolean trap"). That guarantee is fully proven for
the JVM target (`core.enc` + `InMemoryClassLoader`), but the project now also exposes
a language-agnostic C ABI (`cpp/quark_c_api`) intended for Go/Python/native C/C++
consumers, and those targets have no equivalent of "decrypt bytecode, load classes."

This spec covers how a program protected via `quark_c_api` gets the same
non-negotiable property on any platform: **if the cryptographic flow was not
completed honestly, the protected logic does not merely refuse to run — it computes
the wrong thing, using the same code path a legitimate run would use.**

### Research summary (informs the design; see conversation for full detail and
sources)

- Real "on-demand code decryption" for raw native machine code exists (Windows
  PAGE_GUARD + VEH, Linux mprotect + SIGSEGV, macOS MAP_JIT under Hardened
  Runtime) but in practice decrypts-on-first-touch and *stays* decrypted — code
  has no reliable "definitely done, won't be re-entered" moment the way a
  function call does, because of loops, recursion, and indirect jumps.
- Commercial protectors with the strongest track record against reverse
  engineering (VMProtect, Themida) use **code virtualization** — translating
  protected logic into a custom bytecode + interpreter — as their primary
  defense; raw section encryption is a supplementary, weaker layer in those
  same products.
- macOS specifically has been tightening W^X enforcement (Hardened Runtime,
  MAP_JIT, Apple Silicon's hardware-enforced write-xor-execute via
  `pthread_jit_write_with_callback_np`), which is consistent with this
  project's own earlier finding that running a program purely from memory
  caused instability/failure on both JVM and native targets.
- Intel SGX and similar enclaves protect data confidentiality and execution
  integrity from the host OS, but do **not** hide the enclave's own code from
  disassembly of the on-disk image — it does not solve "hide the algorithm."

Conclusion: an embedded bytecode interpreter, not raw native-code
decrypt/execute, is the realistic and industry-precedented path to the stated
goal, and it sidesteps the entire class of OS-hardening fragility (W^X,
code-signing, MAP_JIT entitlements) because interpreted bytecode is never
marked executable memory — it is read as ordinary data by ordinary,
non-self-modifying interpreter code.

## Goals

- A protected application's real functionality (not a boolean check) is
  produced by executing encrypted bytecode that only decrypts correctly on a
  machine that completed a real `quark_unlock_and_decrypt` flow.
- Works identically on Windows, macOS, and Linux with zero OS-specific code in
  the interpreter itself.
- Protected bytecode is decrypted only block-by-block, on demand, and wiped
  from memory once idle — driven by a periodic sweep the embedding host
  invokes on its own timer (see "Data flow").
- Every failure mode (wrong key, tampered bytecode, expired license) produces
  *wrong output*, never a distinguishable "blocked" branch an attacker can
  patch around.

## Non-goals (v1)

- Raw native machine-code virtualization/protection (VMProtect-style). Ruled
  out per the research above; may be revisited later as an explicitly
  separate, much larger effort.
- A general-purpose high-level language or compiler targeting the VM. v1
  ships a minimal text assembler only.
- Dispatch-table permutation or other bytecode-obfuscation hardening beyond
  the core encryption. Tracked as a later hardening pass, consistent with the
  project's existing "anti-tamper/obfuscation comes last" sequencing.
- Multi-threaded interpreter execution. v1 is single-threaded; concurrent
  access to a shared `BlockCache` is out of scope.

## Architecture

New top-level module `cpp/quark_vm/` (its own CMake static library target,
not folded into `quark_core`, to keep `quark_core` from becoming a dumping
ground per CLAUDE.md's explicit warning). Zero OS-specific code — depends only
on `quark_core` (for `quark::crypto`, `quark::payload`, `quark::token`) and the
standard library, so it builds and is testable on any OS exactly like
`quark_core` itself.

| Component | Responsibility |
|---|---|
| `quark::vm::Interpreter` | Fetch-decode-execute loop. Holds `vm_key`. Decrypts a basic block from the `BlockCache` on entry, executes it, never branches on whether that decrypt authenticated. |
| `quark::vm::BlockCache` | Tracks, per basic block id: sealed bytes (always resident), decrypted plaintext (resident only while in use or recently used), last-used timestamp, ref-count. `Sweep()` wipes (`SecureZero`) any block with ref-count 0 whose idle time exceeds a configured threshold. |
| `quark::vm::HostFunctionTable` | Interface the embedding application implements to expose native capabilities (file I/O, network, etc.) to `CALL_HOST`. Same polymorphic pattern as `quark::platform::IHwidBackend`. |
| `tools/quark-vmasm` | Dev-side only. Text assembly format -> basic blocks -> `quark::payload::Seal`-ed `.qvm` file. Not linked into any shipped runtime. |

## Bytecode format

Stack machine, 64-bit words, a value stack, a call stack, and per-frame local
slots. Program counter always resets to the start of a basic block; a basic
block is the standard compiler-theory unit (a maximal straight-line run of
instructions ending in one control transfer) — chosen specifically because
**we control its boundaries**, unlike arbitrary native code, which is what
makes safe decrypt/wipe cycles tractable at all (see Research summary).

v1 opcode set: `PUSH_I64`, `LOAD_LOCAL`, `STORE_LOCAL`, `ADD`, `SUB`, `MUL`,
`DIV`, `MOD`, `AND`, `OR`, `XOR`, `NOT`, `SHL`, `SHR`, `CMP_EQ`, `CMP_LT`,
`CMP_GT`, `JMP <block_id>`, `JMP_IF_ZERO <block_id>`, `CALL <block_id> <argc>`,
`CALL_HOST <host_fn_id> <argc>`, `RET`, `HALT`. No floating point, no
composite types.

## Cryptographic interlocking mechanism

1. After a successful `quark_unlock_and_decrypt`, the embedding application
   derives `vm_key = HMAC-SHA256(content_key, "QUARK-VM-KEY")` — a new,
   domain-separated derivation following the exact convention already
   established in `quark/token.hpp`.
2. Every basic block is sealed independently with `quark::payload::Seal(vm_key,
   plaintext_block)` at build/issuance time (by `quark-vmasm`, using the same
   `vm_key` derivation the target machine will reproduce at runtime).
3. At runtime, `Interpreter` calls `quark::payload::Unseal(vm_key, sealed_block)`
   on first entry to a block. **There is no branch on the result.** On
   authentication failure, the interpreter substitutes a fixed, deterministic
   placeholder plaintext (e.g. all-zero bytes) and proceeds to decode/execute
   it exactly as it would real bytecode — the same code path runs whether the
   key was right or wrong; only the data differs. See "Anti-boolean-trap
   discipline" below for why this distinction is load-bearing.
4. A wrong `vm_key` therefore does not stop execution — it makes every block's
   decoded instructions wrong, so the interpreter computes a wrong result
   using the exact same control flow a legitimate run would use.

## Anti-boolean-trap discipline

This is the property the whole design exists to prove, restated precisely
because it is easy to violate accidentally:

**Bad pattern (rejected):**
```
bool licensed = quark_check_license();
if (licensed) { run_protected_feature(); }   // shell has its own copy of the logic
```
Patching the stored `licensed` value or the branch itself fully defeats this,
because the protected feature's real implementation lives in the shell,
independent of the check.

**Required pattern:**
```
vm_key = derive(content_key);                       // unconditional
result_bytes = interpreter.run(vm_key, program);     // unconditional
shell.use(result_bytes);                             // shell's function DEPENDS on this data
```
There is no conditional to patch. A wrong `content_key` (from a failed or
patched-around unlock) flows forward as wrong data, not as a skippable branch.
This only holds if the integrating developer follows one rule, which must be
stated explicitly and repeatedly in `quark_vm`'s documentation: **the VM must
produce data the shell's real functionality consumes (a decryption key, a
computed value, a decoded asset) — never a yes/no verdict the shell branches
on.** Quark's code cannot enforce this by itself; the documentation and any
example/reference integration must make violating it obviously wrong.

## Data flow

**Dev/issuance time:** protected logic is written in `quark-vmasm`'s text
format, assembled into basic blocks, each sealed under the `vm_key` that will
be reproducible on the licensed target machine (derived the same way from that
machine's `hwid_canonical` via the existing `state_key` / `content_key` chain).
Output is a single `.qvm` file shipped alongside the application binary.

**Runtime:** `quark_unlock_and_decrypt` succeeds -> `content_key` obtained ->
`vm_key` derived -> `Interpreter` constructed with `vm_key`, the `.qvm`
program, and the host's `HostFunctionTable` -> entry block runs -> blocks
decrypt/execute/idle-evict on demand.

Note: `quark_c_api` has no existing periodic-tick primitive today (the QKH2
challenge loop described elsewhere in this project is specific to the
JVM/pipe-based wrapper, not part of the C API). `BlockCache::Sweep()` is
therefore exposed as a plain, synchronous function the embedding host calls
on whatever timer/thread it already has -- Quark does not own or spawn a
background thread for this, consistent with `quark_c_api`'s existing "never
surprise the host with a side effect it didn't ask for" posture and with this
spec's single-threaded non-goal.

## Cross-platform story

The interpreter never marks a memory page executable and never generates or
modifies machine code — it only reads bytecode as data. This means zero
OS-specific code anywhere in `quark_vm`, and it structurally avoids every
problem identified in the research summary (W^X, MAP_JIT/entitlements,
code-signing, self-modifying-code fragility). The only OS-touching surface is
`HostFunctionTable`, implemented by the embedder per platform exactly like
`IHwidBackend`/`IWitnessStore` already are.

## Testing strategy

`quark_vm` has no OS dependency, so it gets fully real, non-mocked,
deterministic tests (CLAUDE.md rule 1 is trivially satisfiable here, not just
achievable):
- Known program + correct `vm_key` -> exact expected output.
- Known program + wrong `vm_key` -> output differs from the correct result
  and the interpreter does **not** crash or short-circuit (proves the
  no-branch property, not just "it fails").
- A block goes idle -> `Sweep()` -> assert the plaintext buffer is actually
  zeroed (a test-only accessor exposes residency) -> block is used again ->
  assert correct re-decryption.
- `quark-vmasm` round-trip: assemble -> seal -> unseal -> decode -> compare
  against the original instruction list.

## Open items for the implementation plan (not decided here)

- How `HostFunctionTable` crosses the C ABI. The architecture table above
  describes it as a C++ interface "same polymorphic pattern as
  `IHwidBackend`", but `IHwidBackend` is only ever used *inside*
  `quark_c_api.cpp` -- it never crosses the C boundary itself. A Go or Python
  host cannot implement a C++ virtual class. `HostFunctionTable` therefore
  needs a real C-ABI shape (most likely a plain struct of C function
  pointers, similar to how other C libraries expose callback tables) that the
  implementation plan must design explicitly -- this spec only establishes
  that the capability is needed, not its exact C signature.
- Exact on-disk `.qvm` container format (how basic blocks are indexed/located
  before their individual decryption -- this index itself is not sensitive,
  since it only reveals block *boundaries*, not content).
- Exact idle-timeout default and whether it's configurable via
  `quark::config`.
- Whether `HostFunctionTable` call arguments/return values need their own
  sealing, or are trusted as ordinary in-process data (current assumption:
  the latter, since they never touch disk).

## Honest limits (unchanged from the rest of Quark's design)

This defends against patch-level and hook-level bypass (flipping a stored
boolean, NOPing a check, hooking a function to fake success) by ensuring
those attacks flow forward as wrong *data* rather than a skippable branch. It
does not and cannot defend against an attacker who fully reverse-engineers the
protected logic's semantics and reimplements it from scratch without needing
Quark at all — no software-only scheme, including commercial ones with far
larger engineering budgets, achieves that. The goal is raising the cost from
"patch one comparison" to "independently rebuild the feature," not literal
invulnerability.
