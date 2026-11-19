# `cpp/common`: `quark_core` + the per-OS platform layers

This directory holds two architecturally distinct things, built as separate CMake targets from
the same source tree (see [CMakeLists.txt](CMakeLists.txt)):

1.  **`quark_core`** -- pure C++17 + statically-linked mbedTLS. Zero Win32/POSIX API calls. Builds
    and is genuinely, non-mocked tested on any OS (CLAUDE.md rule 1), because it has no OS
    dependency to fake.
2.  **`quark_platform_win` / `quark_platform_macos` / `quark_platform_linux`** -- the genuinely
    OS-specific capability layer (hardware fingerprinting, tamper-evident local storage), each
    implementing the same [`IHwidBackend`/`IWitnessStore`](include/quark/platform) contracts so
    `quark_core` and any consumer never need to know which OS they're running on. Only the target
    matching the host OS is configured (see the `if(WIN32)` / `if(APPLE)` / `if(UNIX AND NOT
    APPLE)` blocks in `CMakeLists.txt`) -- **do not assume every `.hpp`/`.cpp` file physically
    inside `cpp/common/` is part of `quark_core`**; several (`ads.*`, `registry.*`, `overlay.*`,
    `online.*`, `hwid.*`, everything under `src/platform_win/`) only compile into
    `quark_platform_win` and are Windows-only despite living in this directory.

---

## `quark_core` -- OS-agnostic crypto/licensing logic

### Cryptography & key derivation
*   [crypto.hpp](include/quark/crypto.hpp) / [crypto.cpp](src/crypto.cpp) -- thin mbedTLS
    wrapper: AES-256-GCM encrypt/decrypt, SHA-256, HMAC-SHA256, CSPRNG bytes, and `SecureZero`.
    This is the only file the rest of the codebase is allowed to touch mbedTLS internals through.
*   [token.hpp](include/quark/token.hpp) / [token.cpp](src/token.cpp) -- every domain-separated
    KDF derivation in the system (`DeriveStateKey`, `DeriveRegistryKey`, `DeriveAdsKey`,
    `DeriveOverlayKey`, `DeriveOnlineKey`, `DeriveHandoffSecret`, `DeriveContentKey`,
    `DeriveCoreEncKey`, `DeriveInitialSeal`, `DeriveChallengeMac`) -- all plain
    SHA-256/HMAC-SHA256 over a fixed-order, length-prefixed concatenation, never HKDF/PBKDF2
    (there's no low-entropy human password anywhere in this system).
*   [lamport.hpp](include/quark/lamport.hpp) / [lamport.cpp](src/lamport.cpp) -- builds and
    verifies the one-time-key hash chain (`H^0(x) .. H^n(x)`) that is the entire expiry mechanism
    (CLAUDE.md rule 6: no clock-trust, chain exhaustion only).

### State, witness, and generic payload codecs
*   [state.hpp](include/quark/state.hpp) / [state.cpp](src/state.cpp) -- `state.bin`'s
    AES-256-GCM codec, HWID-canonical-bytes as AAD.
*   [witness.hpp](include/quark/witness.hpp) / [witness_codec.cpp](src/witness_codec.cpp) --
    shared codec for the secondary anti-rollback witness records (`quark::witness::Seal/Unseal`),
    used identically by the Windows registry/ADS/overlay channels and the portable
    `FileWitnessStore` below.
*   [payload.hpp](include/quark/payload.hpp) / [payload_codec.cpp](src/payload_codec.cpp) --
    generic AES-256-GCM sealed-payload codec (no AAD -- the sealing key is already HWID-bound).
    This is the mechanism behind `quark_c_api`'s `quark_seal_payload`/`quark_unlock_and_decrypt`,
    and the codec `quark_codecipher` uses as its single, outer encryption layer around a
    `CodeRegion` (see [cpp/quark_codecipher/README.md](../quark_codecipher/README.md)).
*   [handoff.hpp](include/quark/handoff.hpp) / [handoff.cpp](src/handoff.cpp) -- the 136-byte
    QKH2 initial-frame and 40-byte challenge-frame codec used by the JVM pipeline
    (`DRM_Wrapper.exe` <-> `quark.jar`). Not used by `quark_c_api` consumers that don't need a
    pipe handoff.
*   [platform_file_witness_store.cpp](src/platform_file_witness_store.cpp) implements
    `quark::platform::FileWitnessStore` -- a plain-file-backed `IWitnessStore` used as one of the
    three witness channels on both macOS and Linux (no OS-specific code needed for it at all).

### Orchestration, config, and errors
*   [orchestrator.hpp](include/quark/orchestrator.hpp) / [orchestrator.cpp](src/orchestrator.cpp)
    -- `quark::orchestrator::RunUnlockFlow`: the entire HWID-collect -> `state.bin`-open ->
    three-witness cross-check -> chain-exhaustion -> key-verification -> roll-forward -> session-
    key-derivation sequence, as a **pure, non-exiting function** returning `quark::error::Code`.
    This is what `quark_c_api`'s `quark_unlock_and_decrypt` calls internally; it never terminates
    its caller's process (CLAUDE.md rule 5's "fail-deadly" is a library-host's decision, not a
    library's).
*   [config.hpp](include/quark/config.hpp) -- a minimal key=value config-file reader (not yet
    consumed by any executable; see `docs/PLAN.md` for the tracked follow-up).
*   [error.hpp](include/quark/error.hpp) / [error.cpp](src/error.cpp) -- the numbered error
    registry shared verbatim across every C++ and Java component and mirrored 1:1 into
    `quark_c_api`'s `QUARK_ERR_*` constants (enforced by `static_assert`s in `quark_c_api.cpp`).

### Cross-platform contracts (`include/quark/platform/`)
*   [hwid_backend.hpp](include/quark/platform/hwid_backend.hpp) -- `IHwidBackend`: `Collect()`
    returns a `Fingerprint` (an ordered list of `{name, value}` fields) or `nullopt` if *any*
    field failed to read (a partial fingerprint is rejected outright). `CanonicalBytes(fp)` joins
    every field's value with `0x1F` in collection order -- this exact byte string is the AAD/KDF
    input everywhere in the system.
*   [witness_store.hpp](include/quark/platform/witness_store.hpp) -- `IWitnessStore`:
    `Save`/`Load` a `witness::Record`, returning `kFound`/`kAbsent`/`kInvalid` (never a bare bool
    -- "absent" and "present but wrong key/tampered" must stay distinguishable to the four-way
    witness-absence logic in `RunUnlockFlow`).

Legacy note: [hwid.hpp](include/quark/hwid.hpp)/[hwid.cpp](src/hwid.cpp) define
`quark::hwid::Components`/`Collect()`/`CanonicalBytes()` -- the original, Windows-specific
16-field fingerprint predating `IHwidBackend`. It only compiles into `quark_platform_win` and is
kept for the existing Windows executables (`DRM_Wrapper`, `Dev_Keygen`, `HWID_Extractor`); new
cross-platform code should target `IHwidBackend`, not this type, directly.

---

## Platform layers

*   **Windows** (`quark_platform_win`) -- `hwid.cpp` (16-field CPUID/SMBIOS/disk/GPU/registry
    fingerprint), `registry.cpp`/`ads.cpp`/`overlay.cpp` (the three secondary witness channels),
    `online.cpp` (WinHTTP `paste.rs` client with ECDSA P-256 signature verification), plus thin
    `IHwidBackend`/`IWitnessStore` adapters in `src/platform_win/`. Fully implemented and shipped.
*   **macOS** (`quark_platform_macos`, [src/platform_macos](src/platform_macos)) --
    `sysctlbyname`/IOKit/DiskArbitration for HWID, xattrs for two of the three witness channels
    (the third is the portable `FileWitnessStore`). Verified for real on macOS hardware.
*   **Linux** (`quark_platform_linux`, [src/platform_linux](src/platform_linux)) -- `/proc`,
    `/etc/machine-id`, and world-readable `/sys/class/dmi/id/*` fields for HWID; `user.`-namespaced
    xattrs for two of the three witness channels. Verified for real inside a real Linux kernel.
    Deliberately does not read root-only DMI fields (`product_uuid`, `board_serial`).

See [CLAUDE.md](../../CLAUDE.md)'s "Cross-platform build & test strategy" and per-field HWID
tables for the full rationale behind each platform's field choices.

---

## API examples

### Cross-platform HWID collection
```cpp
#include "quark/platform/hwid_backend.hpp"
// #include "quark/platform/macos/hwid_backend_macos.hpp"  // pick the backend for your OS

quark::platform::macos::MacHwidBackend backend;
std::optional<quark::platform::Fingerprint> fp = backend.Collect();
if (fp) {
    std::vector<uint8_t> canonical = quark::platform::CanonicalBytes(*fp);
    // canonical is both the AES-GCM AAD and a KDF input everywhere else in Quark.
}
```

### AES-256-GCM encrypt/decrypt
```cpp
#include "quark/crypto.hpp"

quark::crypto::GcmCiphertext sealed =
    quark::crypto::Aes256GcmEncrypt(key, /*aad=*/canonical, plaintext);
// sealed.iv (12 bytes), sealed.ciphertext, sealed.tag (16 bytes)

std::optional<std::vector<uint8_t>> opened =
    quark::crypto::Aes256GcmDecrypt(key, sealed.iv, canonical, sealed.ciphertext, sealed.tag);
// nullopt on ANY failure -- wrong key, tampered ciphertext, and AAD mismatch (wrong machine)
// are all indistinguishable by design (CLAUDE.md rule 2).
```

### Generic sealed payload (what `quark_c_api`/`quark_vm` build on)
```cpp
#include "quark/payload.hpp"

std::vector<uint8_t> sealed = quark::payload::Seal(key, plaintext);
std::optional<std::vector<uint8_t>> opened = quark::payload::Unseal(key, sealed);
```

---

## Unit testing

```bash
ctest --test-dir sandbox/build-host --output-on-failure
```
`quark_core_tests` covers crypto round-trips, KDF domain separation, the Lamport chain,
`state.bin`/witness-codec round-trips on the real filesystem (relative paths only -- never
`std::filesystem::temp_directory_path()`, per CLAUDE.md rule 1's sandbox-only rule), and QKH2
frame encoding. `quark_platform_<os>_tests` runs the equivalent real-hardware checks for whichever
platform layer the current OS built.
