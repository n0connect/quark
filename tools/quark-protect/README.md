# Quark Bytecode Instrumenter (`quark-protect`)

`quark-protect` is a bytecode transformation tool leveraging the **ASM 9** framework. It parses compiled Java archive files (JARs) and injects cryptographic validation checkpoints into classes and methods marked with developer annotations.

---

## The Cryptographic Interlocking Strategy

Instead of relying on easily-patched boolean checks like `if (isLicensed())`, `quark-protect` weaves the license verification directly into the application's runtime calculations:
1.  **Entry Insertion**: At the start of any method marked with `@QuarkCheckpoint(id = 0x123)`, the tool injects a call to `QuarkRuntime.checkpoint(0x123)`.
2.  **Return Value XOR Masking**: At every exit instruction returning a numeric value (int, long, float, double), the tool transforms the return statement. It masks the return value with a token derived from the checkpoint call:
    *   For `int` returns: `value ^ (int)(__token ^ (__token >>> 32))`
    *   For `long` returns: `value ^ __token`
3.  **Liveness Verification**: For void methods, the checkpoint call is still executed. This signals method liveness to the watchdog process, confirming the thread wasn't bypassed.

If the license is tampered with or key derivation fails, the checkpoint returns incorrect validation tokens. As a result, the application's internal arithmetic is corrupted, causing it to fail downstream.

---

## Bytecode Transformation Example

### Original Java Code
```java
@QuarkProtected
public class BillingEngine {
    @QuarkCheckpoint(id = 0x1005)
    public int calculateTotal(int price, int quantity) {
        return price * quantity;
    }
}
```

### Transformed Decompiled Representation
```java
@QuarkProtected
public class BillingEngine {
    public int calculateTotal(int price, int quantity) {
        long token = QuarkRuntime.checkpoint(4101); // 0x1005
        int rawResult = price * quantity;
        return rawResult ^ (int)(token ^ token >>> 32);
    }
}
```

---

## How to Run

Compile and execute the protector via command-line:
```bash
# Build the jar using Gradle
cd tools
./gradlew :quark-protect:jar

# Run the instrumentation pass
java -jar quark-protect/build/libs/quark-protect.jar <input.jar> <output.jar>
```

---

## Implementation Details

`quark-protect` processes target inputs using two primary ASM adapters:
*   `ClassVisitor`: Identifies the class annotations and filters candidates.
*   `AdviceAdapter`: Inserts bytecodes for the checkpoint stack setup, local variable allocation, and overrides `onMethodExit` to emit the correct XOR math sequences based on return type.
