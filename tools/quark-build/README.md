# Quark Application Bundler (`quark-build`)

`quark-build` is a packaging utility that extracts class files from a compiled Java archive (JAR) and compiles them into a single, flat, unencrypted JVM application bundle file (`app.bundle`).

This output bundle is subsequently processed and encrypted by `Dev_Keygen` to produce the production-ready `core.enc` file.

---

## Wire Format Specification

`quark-build` packages class files into the following binary sequence parsed by `InMemoryClassLoader`:

```
+───────────────────+─────────────────────────────────────────────────────────+
| Field             | Description                                             |
+───────────────────+─────────────────────────────────────────────────────────+
| count (u32 LE)    | Total number of class file records stored in the bundle  |
+───────────────────+─────────────────────────────────────────────────────────+
| Record 1..N:      |                                                         |
|   name_len (u16)  | Byte length of the class internal name (LE)             |
|   name (bytes)    | Class path name with '/' separators (e.g. quark/App)    |
|   class_len (u32) | Total bytes of raw compiled bytecode (LE)               |
|   class (bytes)   | Raw compiled class bytecode data stream                 |
+───────────────────+─────────────────────────────────────────────────────────+
```

---

## Command Reference

### 1. Build Bundle
Compile and run the bundler:
```bash
# Build the jar via Gradle
cd tools
./gradlew :quark-build:jar

# Package all classes from the target app JAR
java -jar quark-build/build/libs/quark-build.jar app-original.jar app.bundle
```

### 2. Selective Packaging (`--only-annotated`)
To reduce the final encrypted payload size and only shield core business logic classes, run with `--only-annotated`:
```bash
java -jar quark-build/build/libs/quark-build.jar --only-annotated app-original.jar app.bundle
```
This checks each class file in the JAR. Only classes decorated with the `@QuarkProtected` annotation are packed. Other classes are skipped.

---

## Output Hand-off
Once `app.bundle` is generated, encrypt it into a production state matching your license specifications using `Dev_Keygen`:
```bash
Dev_Keygen hwid.json 100 ./dist --kpriv kpriv.bin --input-bundle app.bundle
```
This produces the final `core.enc` file expected by the Java bootstrapper.
