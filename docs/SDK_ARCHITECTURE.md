# Quark SDK Architecture — Developer Integration Guide

This document describes how to protect a Java (or native C/C++) application
with Quark DRM using the SDK toolchain.

---

## Overview

Quark protects applications at two levels:

1. **Encryption barrier** — `core.enc` contains the protected class files
   encrypted with an AES-256-GCM key that only exists inside a valid
   `DRM_Wrapper.exe` session on the licensed machine. No key = no bytecode.

2. **Distributed checkpoint mesh** — `@QuarkCheckpoint`-annotated methods
   have HMAC-derived tokens injected at build time. Those tokens feed into
   real computations; patching them to `return 0` corrupts outputs rather
   than bypassing a boolean check.

---

## Toolchain Components

| Tool | Purpose |
|---|---|
| `quark-sdk.jar` | Compile-time annotations (`@QuarkProtected`, `@QuarkCheckpoint`) + stub `QuarkRuntime` |
| `quark-protect.jar` | Bytecode transformer: injects `QuarkRuntime.checkpoint(id)` into annotated methods |
| `quark-build.jar` | Bundle builder: packs class files into the `InMemoryClassLoader` wire format |
| `Dev_Keygen.exe` | License issuance: encrypts `app.bundle` → `core.enc` using `core_enc_key` |
| `quark.jar` | Runtime: `Bootstrap` + `QuarkHeartbeat` + real `QuarkRuntime` |

---

## Developer Workflow

### Step 1 — Annotate your code

Add `quark-sdk.jar` to your project's compile classpath. Annotate:

```java
import quark.sdk.QuarkProtected;
import quark.sdk.QuarkCheckpoint;

@QuarkProtected           // class will be included in core.enc
public final class BillingEngine {

    @QuarkCheckpoint(id = 0x1001)       // checkpoint injected at method entry
    public long computePrice(Order o) {
        return o.basePrice() * 100L;    // token XOR-ed into the return value
    }

    @QuarkCheckpoint(id = 0x1002)
    public Invoice generateInvoice(Order o) { ... }
}
```

Rules for `id`:
- Must be unique across all annotated methods in your application.
- Range `0x0001–0xEFFF` is for application use; `0xF000–0xFFFF` is reserved.

### Step 2 — Transform bytecode with quark-protect

After compiling, run `quark-protect` on your output JAR:

```
java -jar quark-protect.jar my-app.jar my-app-protected.jar
```

What it does to each `@QuarkCheckpoint` method:
- Injects at method entry: `long __q = QuarkRuntime.checkpoint(id);`
- At each numeric return site: XORs the return value with a fold of `__q`.

This means patching `QuarkRuntime.checkpoint` to return `0` corrupts every
protected method's outputs rather than making a boolean check pass.

### Step 3 — Build the app bundle with quark-build

```
java -jar quark-build.jar my-app-protected.jar app.bundle
```

To include only `@QuarkProtected` classes (leave others unencrypted):
```
java -jar quark-build.jar --only-annotated my-app-protected.jar app.bundle
```

`app.bundle` is a flat, length-prefixed binary — not a ZIP/JAR — so it cannot
be opened by standard archiving tools after decryption.

### Step 4 — Issue a license with Dev_Keygen

Once you have the customer's `hwid.json` (from `HWID_Extractor.exe`):

```
Dev_Keygen.exe hwid.json 100 out_dir \
    --kpriv kpriv.bin \
    --input-bundle app.bundle \
    --label "CustomerABC"
```

Outputs:
- `out_dir/state.bin` — Lamport chain anchor, sealed to this machine's HWID
- `out_dir/core.enc` — encrypted bundle, keyed to this machine + this paste
- `out_dir/unlock_keys.txt` — 100 one-time unlock keys

### Step 5 — Ship to customer

Bundle for the customer:
```
DRM_Wrapper.exe   (compiled with correct secret.hpp for this customer)
quark.jar
state.bin
core.enc
jre/               (bundled JRE; DRM_Wrapper launches jre\bin\javaw.exe)
```

---

## How QuarkRuntime.checkpoint Works at Runtime

```
token = HMAC-SHA256(key=content_key, msg="CP" || id(u32-LE) || counter(u32-LE))
```

- `content_key` is derived from `handoff_secret` (per-session, rolling with each Lamport step).
- `counter` increments per call, making each checkpoint's output unique within a session.
- `token` is a 64-bit value. Because it feeds into computations, wrong key → wrong token
  → wrong output — not a patchable `if` branch.

`Bootstrap` calls `QuarkRuntime.init(contentKey, sessionId)` before loading
protected classes, so by the time any `@QuarkCheckpoint` method runs, the
singleton is live.

---

## C/C++ Native Applications

For native code, use `quark_runtime.lib` (from `cpp/quark-runtime-c`):

```c
#include "quark_runtime.h"

int main() {
    if (!quark_init()) return 1;     // read 136-byte QKH2 frame from stdin
    quark_heartbeat_start();          // start background challenge-response thread

    int64_t token = quark_checkpoint(0x1001);  // HMAC token
    int64_t result = compute_price(order) ^ token;  // corrupt if wrong key
    ...
}
```

The C library mirrors `QuarkHeartbeat.java` byte-for-byte in the wire protocol;
`DRM_Wrapper.exe` cannot distinguish between a Java and a native protected process.

---

## Security Properties

| Property | How it holds |
|---|---|
| No bytecode without a valid license | `core.enc` GCM auth fails if `core_enc_key` is wrong |
| No key without this machine | `core_enc_key` derives from HWID (11 hardware fields); mismatch → wrong key |
| No key without the paste | `core_enc_key` includes `SHA256(online_secret)`; paste deleted → `online_secret` unknown |
| Session cannot outlive DRM_Wrapper | Pipe topology: `QuarkHeartbeat` calls `halt(-1)` if stdin breaks (parent died) |
| DRM_Wrapper cannot outlive Java | `TerminateProcess` on timeout or wrong HMAC |
| Checkpoint cannot be NOP-patched | Return values are XOR-ed with HMAC token; wrong token corrupts business logic |
| Replay protection on challenges | Fresh nonce per challenge; old responses fail the freshly generated nonce |
