# Cross-language protection matrix

Eight small demo programs that prove Quark's two protection methods actually
work, for real, in four languages each — not just the historical Java/JVM
pipeline. Every combination below has been verified end-to-end on macOS via
[`tools/e2e-test`](../tools/e2e-test/src/main/java/quark/test/CrossLangE2ETest.java)
(see that file's usage comment, and [README.md §13](../README.md#13-testing-and-verification-methodology)).

## The two methods

|  | Method 1: `method1_wrapper` | Method 2: `method2_embedded` |
|---|---|---|
| **Idea** | "Protect an already-written program." The program's own logic is unchanged; `DRM_Wrapper` launches it as an external child process over the QKH2 pipe protocol and gates whether it runs at all, and whether it stays alive. | "Protect a program at the source level." The program's own source calls `quark_c_api` directly (`quark_unlock_and_decrypt`) — no external wrapper, no pipe protocol. |
| **Java** | The real JVM pipeline: `DRM_Wrapper` → `quark.jar` (`Bootstrap`, `QuarkHeartbeat`) → decrypts `core.enc` in memory → `InMemoryClassLoader` → `java/test-app`'s `CoreEntryPoint`. Already covered by `java/test-app` + `java/drm-core`; no new example code needed. | [`java/method2_embedded/Method2Embedded.java`](java/method2_embedded/Method2Embedded.java) — the FFM/Panama API (`java.lang.foreign`, stable since JDK 22, no JNI glue code) calling `libquark_c` directly. |
| **C++** | [`cpp/method1_wrapper/main.cpp`](cpp/method1_wrapper/main.cpp) — links `quark-runtime-c` (`quark_init`/`quark_heartbeat_start`/`quark_checkpoint`), launched by `DRM_Wrapper` exactly like a JVM would be. | [`cpp/method2_embedded/main.cpp`](cpp/method2_embedded/main.cpp) — links `libquark_c` directly. |
| **C** | [`c/method1_wrapper/main.c`](c/method1_wrapper/main.c) — the same `quark_runtime.h` API, compiled with a plain C compiler instead of C++, proving the `extern "C"` boundary is genuinely language-neutral. | [`c/method2_embedded/main.c`](c/method2_embedded/main.c) — links `libquark_c` directly. |
| **Go** | [`go/method1_wrapper/main.go`](go/method1_wrapper/main.go) — **no cgo.** A from-scratch, pure-Go re-implementation of the QKH2 client wire format straight from [`docs/HANDOFF_PROTOCOL.md`](../docs/HANDOFF_PROTOCOL.md) (stdlib `crypto/sha256` + `crypto/hmac` only). The strongest demonstration that the protocol is genuinely language-agnostic: zero shared code with quark-runtime-c or quark.jar, and it still interoperates with the real `DRM_Wrapper` binary. | [`go/method2_embedded/main.go`](go/method2_embedded/main.go) — cgo bindings calling `libquark_c` directly. |

[`tools/quark_seal_tool.cpp`](tools/quark_seal_tool.cpp) is a small shared
dev-side helper the method-2 demos all use: it seals a plaintext file into
the exact wire format `quark_unlock_and_decrypt` expects
(`quark::payload`'s `"QPLD"` framing), using this machine's own real HWID.
This is deliberately **not** the same as `Dev_Keygen --input-bundle`'s
`core.enc` — that uses a different on-disk framing (`"QENC"`) for
`java/drm-core`'s `CoreDecryptor`, even though both share the same
`core_enc_key` derivation. The two are not interchangeable; discovering this
during development (a real `QUARK_ERR_PAYLOAD_DECRYPT_FAILED` failure, not a
hypothetical one) is why this tool exists instead of reusing `core.enc`
directly.

## Building

```bash
examples/build_all.sh
```

Requires the C++ tree already built (`cmake -S . -B sandbox/build-macos && cmake --build sandbox/build-macos`,
see the top-level [README.md §12](../README.md#12-build-instructions)) and
`java/drm-core`/`java/test-app`/`tools/quark-protect`/`tools/quark-build`
already built via Gradle. Output lands in `sandbox/examples_build/` (never
committed — build output belongs under `sandbox/`, per CLAUDE.md rule 1).

Written with OS detection in place (macOS and Linux both use the same
clang/gcc + cgo + Gradle toolchain shape) but **only exercised on macOS so
far** — Windows needs its own script (different compiler invocation, `.exe`/
`.dll` suffixes, `.lib` linkage) that has not been attempted without a
Windows machine to verify it on.

## Running the full matrix

```bash
cd tools && gradle :e2e-test:jar
java -cp tools/e2e-test/build/libs/e2e-test.jar quark.test.CrossLangE2ETest \
    sandbox/build-macos sandbox/examples_build "$(pwd)"
```

Each of the 8 scenarios runs in its own temp directory with a fresh
`--dev`-mode (paste.rs-free) license, and that directory — `state.bin`,
witness files, unlock keys — is deleted whether the scenario passes or
fails. Run `--scenario <name>` (e.g. `--scenario go_method1_wrapper`) to run
just one. No scenario here talks to `paste.rs`; see
[README.md §13.1](../README.md#131-a-note-on-pasters-usage-during-testing)
for why that is deliberate.
