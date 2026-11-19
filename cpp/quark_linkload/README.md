# quark_linkload

Seals a developer's own, completely normally compiled binary -- a whole
executable or dylib, not a curated function -- and loads it back at
runtime through the real OS dynamic linker. One real API surface:
`ProtectedModule`.

```cpp
// packaging (offline, once):
auto binary_bytes = ReadFile(path_to_compiled_program);
auto sealed = quark::payload::Seal(content_key, binary_bytes);   // -> core.enc

// runtime (customer machine):
auto module = quark::linkload::ProtectedModule::Load(sealed, content_key, temp_dir);
auto real_main = reinterpret_cast<int(*)(int, char**)>(module->Symbol("main"));
real_main(argc, argv);
```

That's the whole mechanism. No symbol name to supply, no object file to
search for, no linker to re-invoke -- packaging is "read the file, seal
it," and loading is "unseal it, `dlopen()` it, `dlsym()` it." `dyld` (the
real, already-trusted OS dynamic linker) resolves every external reference
the binary makes -- other libraries, the C++ runtime, its own internal
calls -- exactly as it would for any other program on the system.
`quark_linkload` never decodes an instruction and never parses a
relocation record.

## Why not seal just one function (the design this replaced)

An earlier version of this module worked by finding the one `.o` file that
defined a given symbol (via a real `nm` subprocess call) and linking it
into its own small dylib with the real system linker, so only that one
function's bytes were sealed. It worked -- see the git history for
`ExtractSymbolToDylib` -- but it had a real structural flaw: extracting a
symbol makes a *copy*; it does not remove that symbol from the ORIGINAL
binary. A real deployment would still ship the original, unmodified
executable containing the exact same code in plaintext, sitting right next
to (or instead of) the "protected" copy nobody's build was actually wired
to call. Closing that gap would have required changing the protected
program's source to call the extracted, protected copy instead of the
function it already had -- which is precisely the "packer-style, zero
source change" requirement this whole module exists to satisfy. Sealing
the WHOLE binary sidesteps the contradiction entirely: the shipped artifact
*is* `core.enc`; there is no unprotected original sitting next to it, and
nothing to specify at packaging time beyond "here is the file."

This also made the module smaller, not just more correct: the symbol
search, the `nm` subprocess wrapper, and the linker re-invocation are gone
entirely. `ProtectedModule` (in `loader.hpp`/`loader.cpp`) was already the
right abstraction for "unseal, load, hand back a symbol" regardless of
whether the sealed content was a whole program or an extracted piece --
it needed no changes at all for this pivot.

## The pipeline

```
(packaging, offline)
  developer's program compiles COMPLETELY NORMALLY -- zero Quark
  awareness, zero source change, zero special build target -- into one
  ordinary executable or dylib, exactly as it always did.
        |
        v
  read the whole compiled binary's bytes
        |
        v
  quark::payload::Seal(content_key, binary_bytes)   <-- the ONLY AES-256-GCM
                                                          seal, same as core.enc
        |
        v
      core.enc  (the shipped artifact -- there is no separate plaintext original)

(runtime, customer machine)
  core.enc
        |
        v
  quark_unlock_and_decrypt / RunUnlockFlow (unchanged: real HWID +
  Lamport + witness verification produces content_key)
        |
        v
  quark::payload::Unseal(content_key, sealed)      <-- the ONLY decrypt
        |
        v
  ProtectedModule::Load: write the plaintext binary bytes to a fresh path,
  dlopen() it (the REAL dyld resolves every reference, internal or
  external, exactly as for any program), unlink() the path immediately
  (mapping stays valid -- see "On-disk exposure window" below)
        |
        v
  ProtectedModule::Symbol("main") -> the program's own real entry point,
  called exactly as if the OS had exec'd it directly
```

A wrong `content_key` fails at `Unseal` -- structurally, via the AES-GCM
tag -- before `quark_linkload` ever touches a byte of the binary. See
`tests/quark_linkload_simple_test.cpp`'s wrong-key check for the real,
non-mocked proof.

## On-disk exposure window

`dlopen()` on Darwin requires a real, filesystem-backed path -- there is no
fully in-memory alternative. This was investigated for real, not assumed:

- `shm_open(SHM_ANON, ...)` -- the FreeBSD anonymous-shared-memory
  extension -- does not exist on macOS at all (confirmed: absent from the
  entire macOS SDK header tree).
- A named `shm_open()` object, immediately `shm_unlink()`'d, cannot be
  reopened via its `/dev/fd/<fd>` pseudo-path either -- confirmed for real:
  `open("/dev/fd/<shm_fd>", ...)` fails with `EBADF`. Isolated from
  `dlopen` specifically by testing the same `/dev/fd` path against a
  REGULAR file's fd, which succeeds -- so the failure is specific to
  POSIX shared-memory objects not participating in Darwin's vnode/devfs
  layer, not a general `/dev/fd` limitation.
- macOS has no general-purpose `tmpfs` mounted by default (unlike Linux's
  `/dev/shm`); even `TMPDIR` is real-disk-backed (APFS) by default.

Given that, `ProtectedModule::Load` writes the decrypted bytes to a real
file and `unlink()`s it immediately after `dlopen()` returns (success or
failure). POSIX unlink-while-open semantics keep an already-successful
`dlopen()`'s mapping valid after the name is removed from the directory --
confirmed for real, including the case where the file is unlinked before
any symbol from it is even looked up. This narrows the on-disk exposure
window to the time between `write()` and `unlink()` (microseconds); it does
not eliminate it. A packer that never touches disk at all is not achievable
with `dlopen()` on this OS.

## Honest scope limits

- **macOS only.** The loader's `/dev/fd`/`shm_open` findings are
  Darwin-specific. A Linux equivalent (`dlopen()` against an ELF `ET_DYN`
  PIE executable or `.so`) is plausible and could likely use
  `memfd_create` to close the disk-exposure window entirely (Linux does
  not share macOS's `shm_open` limitation) -- untested. Windows has no
  `dlopen`/Mach-O equivalent at all (`LoadLibrary` + PE/COFF would need a
  substantially different implementation, and a plain `.exe` cannot be
  `LoadLibrary`'d the way a plain Mach-O executable can be `dlopen`'d).
  The top-level `CMakeLists.txt` gates this module behind `if(APPLE)`
  rather than claiming support it hasn't earned.
- **Only whole-binary granularity.** There is deliberately no way to seal
  "just one function" anymore (see above) -- the entire compiled artifact
  is the protected unit. A program that legitimately wants to ship most of
  its logic in the clear and protect only a small part needs to be built
  as two separate binaries (an unprotected launcher/host + a protected
  binary it loads), a real build-organization decision outside this
  module's scope, not a symbol-list argument this module used to accept.
- **Dependencies beyond OS frameworks are the developer's own concern.**
  If the protected program itself depends on additional custom dylibs
  (not system frameworks like IOKit/CoreFoundation), each of those is
  its own separate Mach-O file and would need its own `Seal`/`ProtectedModule::Load`
  round trip to also be protected -- untested against a real multi-dylib
  dependency chain.
- **`Symbol("main")` bypasses normal process startup.** Calling a
  `dlopen()`'d binary's `main()` directly does not go through `exec()`'s
  normal `argc`/`argv`/environment setup -- the caller constructs `argv`
  itself (see both tests). Global/static C++ initializers DO run
  correctly, because `dyld` runs them for any Mach-O image it loads,
  executable or dylib, as a normal part of loading -- verified for real
  via `quark_linkload_hwid_test.cpp`'s real C++ program.
- **No wrong-content_key ambiguity, but also no partial recovery.**
  `ProtectedModule::Load` returns `std::nullopt` uniformly for a bad key,
  a tampered blob, or a `dlopen` failure (missing framework, corrupt
  binary) -- by design, matching this codebase's "collapse distinct
  failure causes into one outward result" posture elsewhere (CLAUDE.md
  rule 5). Callers needing to distinguish these for diagnostics have no
  way to today.

## Layout

- `include/quark/linkload/loader.hpp`, `src/loader.cpp` -- the module's
  entire real surface: `ProtectedModule`, a move-only RAII wrapper around
  a `dlopen` handle (`dlclose`s on destruction). `Load` unseals, writes to
  a fresh path, `dlopen()`s, and unlinks immediately; `Symbol` is a
  `dlsym` wrapper.
- `tests/fixtures/simple_program.c` -- a plain, normally-compiled
  executable (zero Quark awareness) sealed and loaded whole, isolating the
  mechanism from real-program complexity.
- `tests/quark_linkload_simple_test.cpp` -- the isolated mechanism proof:
  seal -> wrong-key rejection -> correct-key load -> `dlsym("main")` ->
  call, on the simple fixture.
- `tests/quark_linkload_hwid_test.cpp` -- the real, complex-program proof:
  seals the entire compiled `HWID_Extractor` binary (real IOKit/
  DiskArbitration/CoreFoundation/`sysctlbyname` calls through
  `quark_platform_macos`, real C++ `std::optional`/`std::vector`/
  `std::string`, real file I/O) and proves the fully-protected copy's
  `main()` produces byte-identical hardware fingerprint JSON to a real,
  unprotected `fork`+`exec` run of the untouched original.
