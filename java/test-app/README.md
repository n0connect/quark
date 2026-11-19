# Quark E2E Integration Test Application (`test-app`)

`test-app` is a minimal, mock application used by the end-to-end integration test runner `e2e-test`. It stands in for the real customer application, verifying compilation, class bundle packaging, ASM bytecode instrumentation, and in-memory execution.

---

## Checked Interfaces & Annotations

The test entry point [CoreEntryPoint.java](src/main/java/quark/app/CoreEntryPoint.java) leverages all SDK security attributes:

### 1. `@QuarkProtected`
Marks the entire class to be compiled and packaged into the encrypted `core.enc` bundle:
```java
@QuarkProtected
public final class CoreEntryPoint { ... }
```

### 2. `@QuarkCheckpoint`
Applies instrumentation checks to the internal methods:
*   `multiply(int a, int b)` (Checkpoint `0x0001`): Multiplies inputs and returns a value XOR-masked with the derived checkpoint token.
*   `greet(String name)` (Checkpoint `0x0002`): Returns a string response. While string types are not XOR-masked by `quark-protect`, it verifies that the checkpoint invocation is still made to confirm overall process liveness.

---

## Test Execution

During execution, `e2e-test` runs the test application and validates outputs:
*   **Decryption Proof**: The program boots and logs `[test-app] PASS` if `core.enc` was decrypted successfully and loaded into the JVM.
*   **Arithmetic Blinding Check**: Confirms that protected numerical outputs are blinded by the token.
*   **Verification Ratchet**: The returned blinded values are used in subsequent math operations, demonstrating that tampering with checkpoints to return stub constants propagates errors and breaks downstream logic.

---

## Build

Compile the test application JAR via Gradle:
```bash
cd java
./gradlew :test-app:jar
```
Outputs `java/test-app/build/libs/test-app.jar`.
