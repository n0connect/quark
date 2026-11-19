# Quark JVM Loader (`drm-core`)

`drm-core` is the runtime bootstrapper packaged as `quark.jar`. It runs before any other application code in the JVM, parses the initialization frame from the parent wrapper, spins up the liveness heartbeat thread, decrypts the core bytecode package in memory, and reflectively executes the entry point without writing class files to the local disk.

---

## File Registry & Components

*   [Bootstrap.java](src/main/java/quark/drmcore/Bootstrap.java): The first JVM entry point. Coordinates frame loading, key derivation, and launches the actual protected application core.
*   [HandoffFrame.java](src/main/java/quark/drmcore/HandoffFrame.java): Reads and validates the 136-byte QKH2 frame from the stdin stream.
*   [QuarkHeartbeat.java](src/main/java/quark/drmcore/QuarkHeartbeat.java): Operates the background thread responding to challenges sent from the C++ parent process.
*   [CoreDecryptor.java](src/main/java/quark/drmcore/CoreDecryptor.java): Handles AES-256-GCM decryption of `core.enc` with standard Java Cryptography Architecture (JCA) providers.
*   [InMemoryClassLoader.java](src/main/java/quark/drmcore/InMemoryClassLoader.java): Custom `java.lang.ClassLoader` subclass parsing a flat bundle of class files from a memory buffer.
*   [QuarkRuntime.java](src/main/java/quark/sdk/QuarkRuntime.java): Embedded stubs providing token computation interfaces to `@QuarkCheckpoint` methods.

---

## Detailed Launch Lifecycle

```
[DRM_Wrapper] ──(Launch JVM)──► [Bootstrap.main()]
                                     │
                             (Read 136 bytes stdin)
                                     │
                             [HandoffFrame.parse()] ──(Fail)──► [System.exit(1)]
                                     │
                            [QuarkHeartbeat.start()] ──(Spins daemon thread)
                                     │
                             (Redirect stdout -> stderr)
                                     │
                             [CoreDecryptor.decrypt()]
                                     │
                             [InMemoryClassLoader]
                                     │
                           (Reflectively Invoke Main)
                                     │
                             [CoreEntryPoint.start()]
```

### 1. Frame Parse & Pipe Control
`Bootstrap` reads exactly 136 bytes from the standard input stream (file descriptor 0) and processes the QKH2 metadata.
To prevent logging or application output from polluting the output challenge pipe (stdout / file descriptor 1), the JVM hijacks these descriptors:
*   Directs a dedicated `FileOutputStream` stream to the raw console `FileDescriptor.out` exclusively for challenge HMAC responses.
*   Redirects `System.out` to `System.err` using `System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.err)))`. All application console logs will surface on the console error descriptor, preventing challenge corruption.

### 2. Heartbeat Verification Thread
`QuarkHeartbeat` opens a background thread that reads the stdin stream for `"CHAL"` challenge blocks. Each block is 40 bytes.
Upon receipt, it computes:
$$\text{HMAC-SHA256}(\text{content\_key}, \text{"RESP"} \mathbin{\Vert} \text{session\_id} \mathbin{\Vert} \text{counter} \mathbin{\Vert} \text{nonce})$$
The resulting 32 bytes are flushed directly back to the wrapper parent via stdout.

### 3. Decryption and In-Memory Load
`Bootstrap` loads the stable binary blob `core.enc` from the local directory and decrypts it with `core_enc_key` under AES-256-GCM.
If the key is invalid, decryption throws `AEADBadTagException` and execution stops. There are no boolean conditional check traps.
On success, the decrypted buffer is fed to [InMemoryClassLoader.java](src/main/java/quark/drmcore/InMemoryClassLoader.java), defining the classes without writing them to disk. Finally, the bootstrapper invokes the real entry point class `quark.app.CoreEntryPoint#start` reflectively.

---

## Build

Compile the runtime bootstrapper using Gradle:
```bash
# Run compilation from java project directory
cd java
./gradlew :drm-core:jar
```
Outputs `java/drm-core/build/libs/drm-core.jar` (packaged as `quark.jar` for runtime distribution).
