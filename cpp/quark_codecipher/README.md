# quark_codecipher

Two small modules, not a virtual machine and not a new instruction set:

- **Capture** ("scramble"): takes real, live, already-compiled machine code
  and turns it into unrecognizable bytes.
- **Materialize** ("reconstruct + run"): takes those bytes back, reproduces
  the *exact original instructions* byte-for-byte, and runs them directly
  on the CPU -- no interpreter loop, no semantic translation.

This supersedes the earlier `quark_vm`/`quark_vmasm` bytecode-interpreter
approach (removed). That approach translated a program's logic into
`quark_vm`'s own instruction set -- which meant either hand-authoring
`.qvmasm` (rejected outright) or an automatic IR-to-bytecode translator that
was never built, and even then could only ever represent a narrow, hand-picked
opcode subset (integer arithmetic + control flow + host calls) of a real
program's actual operations. `quark_codecipher` never leaves the real ISA:
what comes out of `Materialize` is the same machine code the compiler
originally emitted, so it can do anything real code can do, with zero
translation step and zero developer effort beyond compiling normally.

## The mechanism: AES-256 in CTR mode as a keyed keystream

AES-256-GCM (used everywhere else in this codebase, e.g. `core.enc`) proves
*integrity* as well as confidentiality, via a 16-byte authentication tag --
which only makes sense per-message, not per-instruction. `quark_codecipher`
doesn't need a second integrity check (see "Where the encryption actually
happens" below), so it uses plain AES-256 in **CTR mode**
(`quark::crypto::Aes256CtrXor`), which reduces to `output = input XOR
AES_encrypt(key, counter)`. This is:

- **Reversible by construction**: XOR is its own inverse, so calling the
  same function twice with the same key and starting nonce recovers the
  original bytes exactly.
- **Free of block/tag overhead**: no 16-byte auth tag per chunk, so it can
  scramble at any granularity -- a whole function, without padding.

## Where the encryption actually happens

Exactly one AES-256-GCM layer in the whole pipeline, same principle as the
rest of this codebase:

```
(issuance)  real function bytes (Capture's input)
              -> Capture(code_key): scan for external PC-relative refs,
                 scramble the whole buffer with Aes256CtrXor
              -> SerializeCodeRegion               [plain bytes -- NOT authenticated]
              -> quark::payload::Seal(content_key, ...)  <-- the ONLY AES-256-GCM seal
              -> core.enc

(runtime)   core.enc
              -> quark_unlock_and_decrypt / RunUnlockFlow (unchanged: real
                 HWID + Lamport + witness verification produces content_key)
              -> quark::payload::Unseal(content_key, ...)  <-- the ONLY decrypt
              -> DeserializeCodeRegion
              -> Materialize(DeriveCodeStreamKey(content_key)): reconstruct
                 bytes, patch relocations, mmap executable, run
```

A wrong `content_key` fails at `Unseal` -- structurally, via the AES-GCM
auth tag -- **before `quark_codecipher` ever sees a byte**. `code_key`
(`quark::token::DeriveCodeStreamKey(content_key)`) is deterministic and
carries no independent authentication of its own; that would be redundant
double encryption on top of `core.enc`'s own seal, the exact mistake
`quark_vm`'s original per-block sealing made and was corrected for (see
`docs/PLAN.md` Phase XV). See
[quark_codecipher_pipeline_test.cpp](tests/quark_codecipher_pipeline_test.cpp)
for the real, non-mocked proof of this composition, including the
wrong-`content_key` negative case.

## Internal vs. external PC-relative references

`Capture` scans every 4-byte word in the function for ARM64's ADRP/B/BL/
B.cond bit patterns (`relocation.hpp`). For each match, it decodes the
absolute target the instruction computes and checks whether that target
falls **inside** or **outside** the function's own byte range:

- **Internal** (e.g. `branchy_func`'s conditional branches, jumping between
  its own basic blocks): needs **no relocation at all**. When the whole
  function is later copied as one contiguous block to a new address, an
  internal PC-relative instruction and its target move by the exact same
  offset, so the relative encoding stays correct automatically -- provable
  algebraically (`new_pc + delta == new_base + (original_target -
  original_base)`), and verified for real by
  `TestBranchyFuncInternalBranchesNeedNoRelocation`.
- **External** (e.g. `dep_func`'s `ADRP` to a global variable and string
  literal, and its `BL` to `printf`'s stub): recorded as a `Relocation`
  (offset + kind + the original absolute target). `Materialize` re-encodes
  each one for the function's new address, verified for real by
  `TestDepFuncExternalRelocationsPatchedCorrectly` -- the reconstructed
  `dep_func`, running from a brand-new `mmap`'d address, still mutates the
  real global and calls the real `printf`.

## W^X and execution

`Materialize`'s reconstructed bytes are real ARM64 machine code, so they
must actually be marked executable to run -- unlike `quark_vm`'s
interpreter, which never needed executable memory because it only ever
`switch`ed on bytes as data. On Apple Silicon, a page can never be
simultaneously writable and executable for the same thread: `Materialize`
allocates with `MAP_JIT`, writes the reconstructed bytes and patches
relocations during the writable phase, then calls
`pthread_jit_write_protect_np(1)` (executable phase) and
`__builtin___clear_cache` before returning a callable pointer.

## Honest scope limits

- **macOS only.** `Materialize`'s W^X handling is Apple-Silicon-specific
  (`MAP_JIT`/`pthread_jit_write_protect_np`). Linux (`mmap(PROT_EXEC)`,
  simpler but unverified here) and Windows (`VirtualAlloc`/`VirtualProtect`)
  equivalents do not exist yet -- the top-level `CMakeLists.txt` gates this
  module behind `if(APPLE)` rather than claiming cross-platform support it
  hasn't earned.
- **Relocation detection is a bit-pattern scan, not a real disassembler or
  linker relocation records.** A 4-byte word that happens to match ADRP/B/
  BL/B.cond's bits but is actually embedded literal data (a jump table, a
  constant pool entry) would be misclassified. This has been tested against
  real compiler output for straight-line, branchy, and externally-dependent
  functions -- not against arbitrary, arbitrarily complex real programs.
- **CBZ/CBNZ/TBZ/TBNZ and PC-relative literal loads (`LDR` literal) are not
  handled.** Code using them, with external targets, would be
  mis-relocated. See `relocation.hpp`.
- **Capture happens in the same process as the function it captures**
  (`dlopen` + read live, already-relocated bytes), exactly like this
  module's tests. A real dev-time toolchain step -- capturing straight from
  a linker's relocation records for a function that hasn't been loaded into
  this process -- does not exist yet. This is the same class of gap
  `quark_vm`'s retired `qvm_aktif` never closed.
- **How the fixture lengths were determined:** `tests/fixtures/*.c` are
  compiled into a real dylib at build time; the exact byte lengths used in
  the tests (`kTinyFuncLen` etc.) come from a real `otool -tv -arch arm64`
  inspection of that dylib, not a guess. Re-run it yourself after any
  compiler/fixture change:
  ```bash
  otool -tv -arch arm64 sandbox/build-macos/cpp/quark_codecipher/tests/libquark_codecipher_fixtures.dylib
  ```

## Layout

- `include/quark/codecipher/relocation.hpp`, `src/relocation.cpp` --
  ADRP/B/BL/B.cond classification, decode, and re-encode.
- `include/quark/codecipher/region.hpp`, `src/region.cpp` -- `CodeRegion`
  (scrambled bytes + nonce + relocation list) and its plain-byte container
  format (`SerializeCodeRegion`/`DeserializeCodeRegion`).
- `include/quark/codecipher/capture.hpp`, `src/capture.cpp` -- Module 1.
- `include/quark/codecipher/materialize.hpp`, `src/materialize.cpp` --
  Module 2 (macOS-only; other platforms return `nullptr`).
- `tests/fixtures/*.c` -- real, compiler-generated fixture functions.
- `tests/quark_codecipher_test.cpp` -- Capture/Materialize correctness
  against real dlopen'd functions (no relocations, internal-only
  relocations, external relocations).
- `tests/quark_codecipher_pipeline_test.cpp` -- the full single-encryption
  pipeline, including the wrong-key negative case.
