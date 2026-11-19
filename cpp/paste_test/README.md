# Quark Online Witness Live HTTP Test (`Paste_Test`)

`Paste_Test` is a developer-only live integration test program. It exercises the entire HTTP network communication layer against the `paste.rs` witness backend, without executing any other DRM encryption or hardware checks.

> [!WARNING]
> This tool is strictly for local development and QA testing. Do not bundle or ship `Paste_Test.exe` to customers.

---

## Test Protocol & Flow

The integration runner executes the following lifecycle stages:

1.  **Generate Payload**: Generates a 32-byte random byte payload using `quark::crypto::RandomBytes`. This simulates the size of a production online activation secret.
2.  **Test 1 (POST)**: Calls `PostPaste` to upload the payload. Verifies that a valid, non-empty paste ID string (e.g. `abc12`) is returned.
3.  **Test 2 (GET)**: Triggers `FetchPaste` using the returned ID. Compares the retrieved string against the hex representation of the original payload to confirm cryptographic integrity.
4.  **Test 3 (DELETE)**: Submits an HTTP `DELETE` request for the paste ID to verify activation revocation capability.
5.  **Test 4 (Re-Fetch)**: Attempts to `FetchPaste` the deleted ID again. Verifies that the server correctly returns `std::nullopt` (HTTP 404), confirming revocation is active.

---

## Usage

Run the utility from a command prompt:
```cmd
Paste_Test.exe
```
Details of the POST, GET, DELETE steps and matching diagnostics are written directly to standard output.

---

## Compilation

Cross-platform -- uses `quark::online`'s portable, mbedTLS-based HTTPS
client (CA-pinned to paste.rs, see
[cpp/common/src/online_http.cpp](../common/src/online_http.cpp)) instead of
WinHTTP:
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target Paste_Test
./sandbox/build-host/cpp/paste_test/Paste_Test
```
Makes real, live HTTPS requests to `paste.rs` -- run manually, not part of
`ctest` (this repo doesn't make automated tests depend on live network
access; `Paste_Test` exists specifically to be the manually-run, real check).
