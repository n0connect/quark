# Quark C/C++ Application Runtime (`quark-runtime-c`)

`quark-runtime-c` is the native C/C++ client runtime library (`quark_runtime.lib`). It mirrors the Java bootstrapper and SDK, allowing native C/C++ applications to be cryptographically shielded by `DRM_Wrapper`.

---

## Technical Details

Cross-platform: links `quark_core` for crypto (`quark::crypto::HmacSha256`,
`quark::token::DeriveContentKey`/`DeriveChallengeMac`) instead of Windows
CNG -- unlike `cpp/handoff_spy` (a deliberately independent test double),
this library is meant to be linked into a real protected application, so
there's no reason for it to hand-roll its own crypto.

The runtime implements the target-side of the QKH2 pipe-coupling protocol:
1.  **Handshake Parsing**: Reads the 136-byte QKH2 initial frame from stdin and derives the session-specific `content_key`.
2.  **Heartbeat Daemon**: Spawns a background thread (`std::thread` on every platform) that monitors stdin for `"CHAL"` blocks, computes HMAC-SHA256 tokens via `quark_core`, and returns them via stdout.
3.  **Process Termination**: If the stdin pipe breaks (e.g. `DRM_Wrapper` crashes or is killed), the heartbeat thread immediately terminates the process (`ExitProcess(-1)` on Windows, `_exit(-1)` elsewhere).
4.  **Active Verification**: Provides a native `quark_checkpoint` function. It calculates:
    $$\text{token} = \text{HMAC-SHA256}(\text{content\_key}, \text{"CP"} \mathbin{\Vert} \text{id} \mathbin{\Vert} \text{counter})$$
    and returns the first 8 bytes.

---

## API Documentation

### 1. Initialization
```c
#include "quark_runtime.h"

int main() {
    // 1. Parse initial handoff frame from stdin
    if (!quark_init()) {
        return 1; // Handshake failed, exit immediately
    }

    // 2. Launch background challenge-response thread
    quark_heartbeat_start();

    // 3. ... execute application logic ...
}
```

### 2. Checkpoints
Inject checkpoints into security-sensitive areas of your code:
```c
#include "quark_runtime.h"

int CalculatePremium(int base) {
    // Retrieve cryptographic token
    int64_t token = quark_checkpoint(0x1024);
    
    // Mask calculations with the derived token
    int multiplier = (int)(token ^ (token >> 32)) & 0xFF;
    return base * multiplier;
}
```
If the application is launched without `DRM_Wrapper` or with an invalid license, `quark_checkpoint` returns `0L`. This value will corrupt calculations downstream.

### 3. Encrypted Payload Decryption
If the application has encrypted segments, retrieve the `core_enc_key` to decrypt them in memory:
```c
const uint8_t* dec_key = quark_core_enc_key();
// Use dec_key (32 bytes) with AES-256-GCM to decrypt resources
```

---

## Compilation & Linking

Cross-platform -- links `quark_core` for crypto (HMAC-SHA256, SHA-256)
instead of Windows CNG:
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target quark_runtime
ctest --test-dir sandbox/build-host -R quark_runtime_e2e_test --output-on-failure
```
Produces `sandbox/build-host/cpp/quark-runtime-c/libquark_runtime.a` (or
`quark_runtime.lib` on Windows).

### Link Instructions
When compiling your protected C++ application:
1.  Include [quark_runtime.h](quark_runtime.h) in your sources.
2.  Link with `quark_runtime` (which pulls in `quark_core` transitively).
