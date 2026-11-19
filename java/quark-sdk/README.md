# Quark Java SDK (`quark-sdk`)

`quark-sdk` is the compile-time developer integration package packaged as `quark-sdk.jar`. It exposes target annotations and API stubs that developers incorporate into their source code to mark sensitive classes for encryption and weave security check validations.

---

## SDK Elements

### 1. Class-level Encryption: `@QuarkProtected`
Marks a class as a candidate for bytecode shielding:
```java
package quark.sdk;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface QuarkProtected {}
```
Classes decorated with this annotation are extracted by `quark-build` (using the `--only-annotated` option) and compiled into `core.enc`. They will not exist in the distribution JAR file, making decompilation impossible.

### 2. Method-level Validation: `@QuarkCheckpoint`
Marks specific methods as execution checkpoints:
```java
package quark.sdk;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface QuarkCheckpoint {
    int id(); // Must be unique across the application
}
```
At compile-time, the developer annotates methods with unique IDs (e.g. `0x1001`). The `quark-protect` instrumenter intercepts these methods, inserting live calls to `QuarkRuntime.checkpoint()` at entry points and masking return variables.

### 3. API Shadowing: `QuarkRuntime`
Presents a compile-time dummy stub representing the runtime verification coordinator:
```java
package quark.sdk;

public final class QuarkRuntime {
    public static long checkpoint(int id) {
        return 0L; // Stub returning 0
    }
}
```
During development, the stub returns `0L`.
At launch time, `Bootstrap` loads `quark.jar` (which contains the real [QuarkRuntime.java](../drm-core/src/main/java/quark/sdk/QuarkRuntime.java)) into the JVM memory space. This real class shadows the stub, computing actual session HMAC validations.

---

## Build

Build the developer SDK package using Gradle:
```bash
cd java
./gradlew :quark-sdk:jar
```
Outputs `java/quark-sdk/build/libs/quark-sdk.jar` for developer project dependencies.
