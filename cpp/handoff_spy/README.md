# Quark Process Handoff Simulator (`handoff_spy`)

`handoff_spy` is a diagnostic and end-to-end testing utility. It acts as a mock Java virtual machine launcher, pretending to be `javaw.exe`. 

By placing the compiled binary at `jre\bin\javaw.exe`, `DRM_Wrapper` will invoke it during tests. This allows developers to validate the entire handoff, pipe redirection, and challenge-response heartbeat logic without spinning up a heavy Java process.

---

## Technical Design

To simulate a clean, isolated target process, `handoff_spy` is kept lightweight and independent:
1.  **No dependencies on `quark_common`, on any platform**: it never links `quark_common` or mbedTLS, by design -- the whole point of this tool is proving DRM_Wrapper's QKH2 implementation interoperates with an INDEPENDENT implementation of the same protocol. Sharing crypto code with the thing being tested would let a bug in that shared code hide from this test.
2.  **Cross-platform crypto**: Windows builds use the native Cryptography Next Generation (CNG) APIs (`bcrypt.dll`); macOS/Linux builds use a from-scratch, dependency-free SHA-256/HMAC-SHA256 implementation local to this file (see the header comment in `main.cpp`) -- not linked from mbedTLS/quark_core, for the same independence reason.
3.  **Pipe Verification**:
    *   Reads the 136-byte initial QKH2 frame from stdin and dumps the hex parameters to stderr.
    *   Reads the 40-byte `"CHAL"` frame.
    *   Computes:
        $$\text{HMAC-SHA256}(\text{content\_key}, \text{"RESP"} \mathbin{\Vert} \text{session\_id} \mathbin{\Vert} \text{counter} \mathbin{\Vert} \text{nonce})$$
    *   Writes the 32-byte response back to stdout.

---

## Configuration

By default, the spy completes one challenge cycle and exits. You can control the total number of challenge iterations using the `QUARK_SPY_CHALLENGES` environment variable:
```cmd
# Run spy for 5 challenge loops (approx. 2.5 minutes) before exiting
set QUARK_SPY_CHALLENGES=5
DRM_Wrapper.exe
```

Exit codes:
*   `0`: Challenge loop completed successfully with correct validations.
*   `1`: Malformed initial frame, wrong version, or pipe connection failure.

---

## Compilation

Cross-platform -- POSIX builds (macOS/Linux) use a from-scratch,
dependency-free SHA-256/HMAC-SHA256 implementation local to this program
(deliberately not linked from quark_core -- see the source file's header
comment on why sharing crypto code with the thing being tested would defeat
the point). Windows keeps its existing CNG (`bcrypt.dll`) implementation.

```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target handoff_spy
ctest --test-dir sandbox/build-host -R handoff_spy_e2e_test --output-on-failure
```

For manual DRM_Wrapper integration testing, copy the output binary to
`jre\bin\javaw.exe` (Windows) or the equivalent path your build expects on
macOS/Linux.
