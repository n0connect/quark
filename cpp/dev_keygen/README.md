# Quark Developer Key & License Generator (`Dev_Keygen`)

`Dev_Keygen` is a developer-side CLI application used to configure core secrets, issue licenses, roll Lamport hash chains, create revocation/burn files, and encrypt compiled JVM class bundles (`core.enc`).

---

## Command Reference

`Dev_Keygen` has several subcommands supporting setup, license issuance, revocation, and class bundle encryption.

### 1. One-Time Project Setup (`--setup`)
Generates the global project KDF build secret and P-256 ECDSA keypair used to sign the online witness paste bin payloads:
```bash
# Output secret headers for compiling DRM_Wrapper and write the private key
Dev_Keygen --setup --out secret_generated.hpp --kpriv kpriv.bin
```
*   `secret_generated.hpp` contains code defining `kBuildSecret` and `kEcPublicKey` to replace values in [cpp/drm_wrapper/secret.hpp](../drm_wrapper/secret.hpp).
*   `kpriv.bin` contains the raw private key bytes. Keep this file secure and private.

### 2. Issue a Production License
Mints a new `state.bin` license bound to customer hardware, creates the one-time keys list, signs/seals the online-witness payload, posts it to `paste.rs`, and logs the record to a registry:
```bash
Dev_Keygen hwid.json 50 ./output --kpriv kpriv.bin --label "Enterprise Customer A" --input-bundle app.bundle
```
*   `hwid.json`: Customer's hardware configuration extracted via `HWID_Extractor.exe`.
*   `50`: Number of allowed launches (Lamport chain length).
*   `./output`: Destination directory where the following are generated:
    *   `state.bin`: The encrypted license file to be placed on the customer machine.
    *   `unlock_keys.txt`: Sequential list of 50 activation keys. These must be redeemed in order.
    *   `core.enc`: AES-256-GCM encrypted `app.bundle` class package.
*   `--kpriv`: Private key location to sign the online payload.
*   `--input-bundle`: Packs and encrypts class bytecode into `core.enc`.

### 3. Issue a Developer/Test License (`--dev`)
Issues a license in test mode. Skip paste bin uploads and ECDSA signatures. The online secret is defaulted to all-zero bytes:
```bash
Dev_Keygen hwid.json 10 ./output_dev --dev --label "QA Local Test" --input-bundle app.bundle
```
> **Warning**: Never use `--dev` mode in production environments. The derived encryption keys are deterministic and significantly reduce system security.

### 4. Create Revocation/Burn File (`--burn`)
Generates a special revocation license state structure. Replace the customer's `state.bin` with this file to deny any future launch:
```bash
Dev_Keygen --burn hwid.json ./revoke_output
```
This writes a `state.bin` with 0 remaining links and 1 original link. When used, it triggers a witness mismatch flag, blocking all launches immediately.

### 5. Registry Management (`--list` and `--revoke`)
Maintains a local registry `licenses.txt` detailing all issued assets:
```bash
# Print list of licenses in registry
Dev_Keygen --list --registry licenses.txt

# Delete a paste payload from paste.rs and mark record as revoked
Dev_Keygen --revoke <paste_id> --registry licenses.txt
```

---

## File Format Spec

### `state.bin` Layout
The binary file is formatted as:
```
offset  size  field
------  ----  -----------------------------------------------------------
     0    12  Initialization Vector (IV)
    12    32  Lamport Chain Anchor (redemption root)
    44     4  Remaining Links Count (u32 LE)
    48     4  Original Chain Length (u32 LE)
    52    32  Hardware ID Digest (SHA-256 of canonical HWID)
    84    64  Online Witness Paste ID String (null-padded)
   148    16  AES-256-GCM Authentication Tag
------  ----
   164        Total File Size
```
This whole structure is encrypted using `state_key` derived via HKDF-SHA256 from the build secret and target machine's hardware ID.

### `licenses.txt` Layout
A pipe-delimited database tracking keys:
```
paste_id | label | chain_length | issued_utc | status
```
Example:
```
abc12 | Enterprise Customer A | 50 | 2026-07-04T17:15:30Z | active
```

---

## Compilation

Cross-platform:
```bash
cmake -S . -B sandbox/build-host
cmake --build sandbox/build-host --target Dev_Keygen
```
Outputs `sandbox/build-host/cpp/dev_keygen/Dev_Keygen` (or `Dev_Keygen.exe`
on Windows). Reads hardware fingerprints in the format
`HWID_Extractor` now produces on any OS (`quark::platform::
FingerprintFromJson`, tagged with the platform that collected it).
