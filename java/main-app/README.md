# Quark Protected Application Example (`main-app`)

`main-app` provides a reference implementation of a Java application integrating the Quark DRM system. It demonstrates how to segregate sensitive application routines from user interface shells and resource packages, protecting core algorithms from static analysis.

---

## Architectural Concept: Code Decoupling

Standard Java protection relies on a boolean verification gate check. Such designs are vulnerable to simple bytecode patching (e.g. replacing a jump instruction).

Quark implements a secure alternative:
*   **The Main Shell (`main.jar`)**: Houses non-sensitive application components (UI, resources, libraries). This jar is distributed openly.
*   **The Encrypted Core (`core.enc`)**: Contains compiled class bytecodes for sensitive business logic classes like [CoreEntryPoint.java](src/main/java/quark/app/CoreEntryPoint.java).
*   **Dynamic Class Definition**: These core classes do not exist in the distributed jar. At boot time, the custom JRE loader (`quark.jar`) decrypts `core.enc` directly in memory and defines the classes.

Without the correct hardware-bound key, the classes cannot be decrypted, and the Java application crashes with a `ClassNotFoundException`.

---

## Developer Integration Flow

To integrate your application with the Quark build pipeline:

1.  **Define Entry Point**: Create your application entry point matching the signature:
    ```java
    package quark.app;

    public final class CoreEntryPoint {
        public static void start(String[] args) {
            // Your protected application business logic starts here
        }
    }
    ```
2.  **Separate Packages**: Place all core business classes under the package namespace alongside your entry point.
3.  **Compile**: Compile your project class files.
4.  **Bundle and Encrypt**: Run `quark-build` and `Dev_Keygen` to pack and encrypt the classes into `core.enc`. Refer to [tools/quark-build](../../tools/quark-build/README.md) for details.

---

## Build

Compile the sample application JAR via Gradle:
```bash
cd java
./gradlew :main-app:jar
```
Outputs `java/main-app/build/libs/main-app.jar`.
