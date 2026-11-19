# `cpp/quark_c_api`: the language-agnostic C ABI over `quark_core`

`quark_c_api` is the public `extern "C"` entry point over `quark_core` (`cpp/common`) --
the plain-C surface any language with an FFI (Go/cgo, Python/ctypes-cffi, Java/JNI-Panama,
Rust/bindgen, C/C++ directly) uses to call into Quark's DRM/licensing engine in-process. It links
whichever `quark_platform_<os>` target the current OS already built, so it builds everywhere
`quark_core` plus that OS's platform layer builds.

## Non-negotiable library contract (see the file comment in `include/quark_c_api.h`)

*   **Never terminates its host process.** Every function returns a `quark_error_t`; `QUARK_OK`
    (0) means success, anything else means the operation did not complete and no output buffer was
    written. CLAUDE.md rule 5's "fail-deadly" is still the *recommended* posture for a host built
    on this library, but a shared library has no right to kill its host to enforce that -- that
    decision belongs to the caller, at the caller's call site.
*   **Never prompts for input, launches a subprocess, or writes a log file.** Every side effect is
    exactly what the function's own contract describes.
*   **Never accepts a caller-supplied HWID for the unlock path.** `quark_unlock_and_decrypt`
    always collects the fingerprint fresh, locally, from the exact machine it's running on --
    accepting one as a parameter there would let a caller bypass hardware binding entirely.
*   **`core_enc_key` never crosses this boundary.** This closes the exact boolean-trap gap a
    raw-key-returning API would leave open: if `quark_unlock_and_decrypt` instead handed back
    `core_enc_key` and trusted the caller to decrypt its own payload, a host that only checked "did
    this return `QUARK_OK`?" without actually using the key would have reintroduced "patch the
    return value, skip the check, done." There is no such shortcut here -- the function's entire
    externally-visible output *is* the decrypted payload.

## Error codes

`quark_error_t` (an `int32_t`) shares non-negative values 1:1 with `quark::error::Code`
(`cpp/common/include/quark/error.hpp`) -- a numbered code means the same thing everywhere in
Quark, across every language. Negative values (`QUARK_ERR_INVALID_ARGUMENT`,
`QUARK_ERR_BUFFER_TOO_SMALL`, `QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM`) are specific to this C
boundary itself (a misuse of the API's own contract) and can never collide with the shared
registry. A `static_assert` in [src/quark_c_api.cpp](src/quark_c_api.cpp) enforces the numeric
mapping stays correct at build time.

## Functions

*   `quark_error_describe(code)` -- human-readable description; never returns `NULL`.
*   `quark_hwid_collect(...)` -- collects this machine's hardware fingerprint via whichever
    platform backend this build links, writing the canonical AAD/KDF byte string to a
    caller-owned buffer (pass `NULL`/`0` first to learn the required size).
*   `quark_lamport_mint_chain(chain_length, ...)` -- dev-side: builds a fresh Lamport chain from a
    random seed and returns the anchor plus every intermediate one-time key.
*   `quark_state_mint(...)` -- dev-side: seals a fresh `state.bin` bound to a given HWID canonical
    byte string. Always mints a dev-mode license (empty online witness) -- this library has no
    portable HTTPS client yet.
*   `quark_seal_payload(...)` -- dev-side: seals your protected payload (bytecode, a `.qvm`
    program, a config blob, anything) so that only `quark_unlock_and_decrypt`, on the exact
    machine `hwid_canonical` identifies, with a valid unlock key, can recover it.
*   `quark_unlock_and_decrypt(...)` -- **the primary, recommended entry point, and the only way to
    reach a sealed payload's plaintext through this API.** Runs the complete unlock flow (HWID
    collection, `state.bin` authentication, three-witness cross-check, chain-exhaustion and
    key-verification) and decrypts `sealed_payload` in the same call, returning plaintext bytes if
    and only if every step succeeded.

`quark_witness_channel_t` describes a witness channel generically across OSes (`kind`: `FILE`,
`XATTR`, `REGISTRY`, `ADS`, `OVERLAY`) so a caller supplies three channel descriptors without
needing to know which OS it's running on -- `quark_c_api.cpp` maps `REGISTRY`/`ADS`/`OVERLAY` to
`QUARK_ERR_UNSUPPORTED_ON_THIS_PLATFORM` outside Windows.

## Example (C)

```c
#include "quark_c_api.h"

uint8_t hwid[4096];
size_t hwid_len = 0;
quark_hwid_collect(hwid, sizeof(hwid), &hwid_len);

uint8_t anchor[32], keys[10 * 32];
quark_lamport_mint_chain(10, anchor, keys, sizeof(keys));
quark_state_mint("state.bin", "my-build-secret", hwid, hwid_len, anchor, 10);

uint8_t sealed[256];
size_t sealed_len = 0;
quark_seal_payload("my-build-secret", hwid, hwid_len,
                    (const uint8_t*)"protected-bytes", 15,
                    sealed, sizeof(sealed), &sealed_len);

/* ... later, on the licensed machine, using the first unlock key from `keys` ... */
quark_witness_channel_t witnesses[3] = { /* three FILE/XATTR channels */ };
uint8_t plaintext[256];
size_t plaintext_len = 0;
quark_error_t err = quark_unlock_and_decrypt(
    "state.bin", "my-build-secret", witnesses, "the-hex-unlock-key",
    sealed, sealed_len, plaintext, sizeof(plaintext), &plaintext_len,
    /*content_key_out=*/NULL, /*session_id_out=*/NULL);
```

## Testing

[tests/quark_c_api_test.c](tests/quark_c_api_test.c) is a plain C program -- no C++, no
`quark_core` headers -- exercising the whole library exactly the way an external Go/Python/Java
binding would, against this real machine's real HWID and real file/xattr witness storage
(CLAUDE.md rule 1: no mocks). Run via `ctest --test-dir sandbox/build-host -R quark_c_api_test`.

## Not yet done

`quark_codecipher` (see [cpp/quark_codecipher/README.md](../quark_codecipher/README.md)) is not
yet wired into this header's public surface -- a Go/Python host cannot yet Capture/Materialize
protected native code through `quark_c_api` alone. Tracked in `docs/PLAN.md`'s Phase XVI as the
natural next step.
