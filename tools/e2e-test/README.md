# Quark Automated Integration Test Suite (`e2e-test`)

`e2e-test` is an integration test suite packaged as `e2e-test.jar`. It validates the complete native C++ and Java pipeline, confirming activation flow, anti-tampering measures, key exhaustion limits, and challenge-response execution.

---

## Prerequisites

The runner requires compiling all C++ native targets (Release configuration) and all Java subcomponents.
Ensure the following files exist in the build folder:
*   `Release/HWID_Extractor.exe`
*   `Release/Dev_Keygen.exe`
*   `Release/DRM_Wrapper.exe`
*   `Release/handoff_spy.exe`
*   `quark.jar`
*   `quark-protect.jar`
*   `quark-build.jar`
*   `test-app.jar`

---

## Test Scenarios

The test suite runs scenarios to verify safety boundaries:

| Scenario Name | Description | Verified Success Criteria |
| :--- | :--- | :--- |
| `happy_path` | Full flow with test stub | `handoff_spy` receives challenge, verifies and exits 0. |
| `wrong_key` | Invalid redemption token | `DRM_Wrapper` detects validation error and exits 1. |
| `exhausted` | Chain depletion verification | Chain length 1 is spent, 2nd launch is rejected. |
| `burned` | License revocation check | Revocation `state.bin` is written, launch is denied. |
| `tampered_state` | AES-GCM data corruption | Modifies byte in `state.bin`, decrypt throws bad tag. |
| `full_java` | End-to-end JRE boot | Runs real JVM, decrypts `core.enc` in-memory. |

---

## How to Run

Compile and drive the test suite with the following Gradle targets:
```bash
# Compile test tool
cd tools
./gradlew :e2e-test:jar

# Run the test suite against the target build folder
java -jar e2e-test/build/libs/e2e-test.jar <build_dir_path>
```

To run a specific test case, specify the `--scenario` flag:
```bash
java -jar e2e-test/build/libs/e2e-test.jar <build_dir_path> --scenario tampered_state
```

---

## Sandbox Isolation

To avoid conflicts during test execution, each test scenario is isolated:
*   Spawns a temporary subdirectory under the system temp directory.
*   Copies required binaries, libraries, and resources into the isolated sandbox folder.
*   Overrides registry and witness paths to prevent polluting the developer host state.
*   Cleans and deletes the temporary folders upon completion.

---

## `CrossLangE2ETest` -- the cross-language protection matrix

This module also builds `quark.test.CrossLangE2ETest`, a second, independent
runner that proves Quark's two protection methods work in Go, C, C++, and
Java (8 scenarios total), driving the demo programs in
[`examples/`](../../examples/README.md). It is not the `e2e-test.jar`
Main-Class (that stays `QuarkE2ETest`); run it explicitly:

```bash
java -cp e2e-test.jar quark.test.CrossLangE2ETest <build_dir> <examples_build_dir> <repo_root>
```

See [`examples/README.md`](../../examples/README.md) for the full
methodology, what each of the 8 scenarios proves, and how to build the demo
programs it drives.
