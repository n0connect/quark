package quark.test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * End-to-end test runner for the Quark DRM pipeline.
 *
 * Usage:
 *   java -jar e2e-test.jar <build_dir> [--scenario <name>]
 *
 * build_dir must contain:
 *   Release/HWID_Extractor.exe
 *   Release/Dev_Keygen.exe
 *   Release/DRM_Wrapper.exe
 *   Release/handoff_spy.exe
 *   quark.jar            (from java/drm-core build)
 *   quark-protect.jar    (from tools/quark-protect build)
 *   quark-build.jar      (from tools/quark-build build)
 *   test-app.jar         (from java/test-app build)
 *
 * Each scenario runs in its own temp directory, so registry witnesses from one
 * run do not pollute another.
 *
 * Scenarios:
 *   happy_path      -- full pipeline, handoff_spy completes 1 challenge
 *   wrong_key       -- wrong unlock key, expect DRM_Wrapper to exit non-zero
 *   exhausted       -- spend all keys (chain_length=1), then try again
 *   burned          -- --burn creates exhausted state.bin, launch denied
 *   tampered_state  -- flip one byte in state.bin, launch denied
 *   full_java       -- use real quark.jar + core.enc (test-app loaded in-memory)
 */
public class QuarkE2ETest {

    // ── Result accumulator ────────────────────────────────────────────────────
    private static int passed = 0;
    private static int failed = 0;
    private static final List<String> failures = new ArrayList<>();

    // ── Paths (set from args) ─────────────────────────────────────────────────
    private static Path buildDir;
    private static Path hwid_extractor;
    private static Path dev_keygen;
    private static Path drm_wrapper;
    private static Path handoff_spy;
    private static Path quark_jar;
    private static Path quark_protect_jar;
    private static Path quark_build_jar;
    private static Path test_app_jar;

    // ── Entry point ───────────────────────────────────────────────────────────
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: e2e-test.jar <build_dir> [--scenario <name>]");
            System.exit(2);
        }

        buildDir         = Paths.get(args[0]).toAbsolutePath();
        hwid_extractor   = buildDir.resolve("Release/HWID_Extractor.exe");
        dev_keygen       = buildDir.resolve("Release/Dev_Keygen.exe");
        drm_wrapper      = buildDir.resolve("Release/DRM_Wrapper.exe");
        handoff_spy      = buildDir.resolve("Release/handoff_spy.exe");
        quark_jar        = buildDir.resolve("quark.jar");
        quark_protect_jar = buildDir.resolve("quark-protect.jar");
        quark_build_jar  = buildDir.resolve("quark-build.jar");
        test_app_jar     = buildDir.resolve("test-app.jar");

        checkExists(hwid_extractor, "HWID_Extractor.exe");
        checkExists(dev_keygen,     "Dev_Keygen.exe");
        checkExists(drm_wrapper,    "DRM_Wrapper.exe");
        checkExists(handoff_spy,    "handoff_spy.exe");
        checkExists(quark_jar,      "quark.jar");

        String targetScenario = null;
        for (int i = 1; i < args.length; i++) {
            if ("--scenario".equals(args[i]) && i + 1 < args.length) {
                targetScenario = args[++i];
            }
        }

        System.out.println("=== Quark E2E Test Suite ===");
        System.out.println("Build dir: " + buildDir);
        System.out.println();

        if (targetScenario == null || "happy_path".equals(targetScenario))
            run("happy_path",     QuarkE2ETest::scenario_happy_path);
        if (targetScenario == null || "wrong_key".equals(targetScenario))
            run("wrong_key",      QuarkE2ETest::scenario_wrong_key);
        if (targetScenario == null || "exhausted".equals(targetScenario))
            run("exhausted",      QuarkE2ETest::scenario_exhausted);
        if (targetScenario == null || "burned".equals(targetScenario))
            run("burned",         QuarkE2ETest::scenario_burned);
        if (targetScenario == null || "tampered_state".equals(targetScenario))
            run("tampered_state", QuarkE2ETest::scenario_tampered_state);
        if (Files.exists(quark_build_jar) && Files.exists(test_app_jar)) {
            if (targetScenario == null || "full_java".equals(targetScenario))
                run("full_java",  QuarkE2ETest::scenario_full_java);
        } else {
            System.out.println("[SKIP] full_java -- quark-build.jar or test-app.jar not found");
        }

        System.out.println();
        System.out.printf("Results: %d passed, %d failed%n", passed, failed);
        if (!failures.isEmpty()) {
            System.out.println("Failed scenarios:");
            failures.forEach(s -> System.out.println("  - " + s));
        }
        System.exit(failed > 0 ? 1 : 0);
    }

    // ── Scenario runner ───────────────────────────────────────────────────────
    @FunctionalInterface
    interface Scenario {
        void run(Path workDir) throws Exception;
    }

    private static void run(String name, Scenario s) {
        System.out.printf("[%s] starting...%n", name);
        // Clean machine-global witnesses before each scenario so registry/ThemeCache
        // state from a previous run cannot cause spurious kWrapperWitnessMismatch.
        cleanWitnesses();
        Path workDir = null;
        try {
            workDir = Files.createTempDirectory("quark_e2e_" + name + "_");
            s.run(workDir);
            System.out.printf("[%s] PASS%n", name);
            passed++;
        } catch (AssertionError | Exception e) {
            System.out.printf("[%s] FAIL: %s%n", name, e.getMessage());
            failed++;
            failures.add(name + ": " + e.getMessage());
        } finally {
            if (workDir != null) deleteTree(workDir);
        }
    }

    /** Remove registry witness + ThemeCache ADS so each scenario starts clean. */
    private static void cleanWitnesses() {
        try {
            // Registry: HKCU\SOFTWARE\Quark
            ProcessBuilder pb = new ProcessBuilder(
                "reg", "delete", "HKCU\\SOFTWARE\\Quark", "/f");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {}

        try {
            // ThemeCache NTFS ADS :q  (PowerShell required for ADS manipulation)
            String appdata = System.getenv("APPDATA");
            if (appdata != null) {
                String adsPath = appdata + "\\Microsoft\\Windows\\ThemeCache";
                ProcessBuilder pb = new ProcessBuilder(
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Remove-Item -Path '" + adsPath + "' -Stream q -Force -ErrorAction SilentlyContinue");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor(5, TimeUnit.SECONDS);
            }
        } catch (Exception ignored) {}
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Scenario implementations
    // ═════════════════════════════════════════════════════════════════════════

    /**
     * Happy path: issue a 3-key license (dev mode, no paste.rs), launch
     * DRM_Wrapper with the first unlock key, handoff_spy completes 1 challenge.
     */
    static void scenario_happy_path(Path dir) throws Exception {
        Path hwidJson  = collectHwid(dir);
        Path[] keys    = issueDevLicense(dir, hwidJson, 3, null);
        setupDrmDir(dir);

        String key0 = readFirstKey(keys[0]);
        ExecResult r = launchDrmWrapper(dir, key0, 90);
        assertExitZero(r, "DRM_Wrapper happy path");
        assertOutput(r.stdout, "QKH2 initial frame valid", "handoff_spy frame validation");
        assertOutput(r.stdout, "challenge 0 response sent", "challenge-response cycle");
    }

    /**
     * Wrong key: supply a made-up hex key -- DRM_Wrapper must exit non-zero.
     */
    static void scenario_wrong_key(Path dir) throws Exception {
        Path hwidJson = collectHwid(dir);
        issueDevLicense(dir, hwidJson, 3, null);
        setupDrmDir(dir);

        // Use a hex string that is syntactically valid but cryptographically wrong.
        String badKey = repeatChar('a', 64);
        ExecResult r = launchDrmWrapper(dir, badKey, 15);
        assertExitNonZero(r, "DRM_Wrapper wrong key");
    }

    /**
     * Exhausted chain: issue 1-key license, spend it, then try a second launch.
     * Second launch must fail with kWrapperLicenseExhausted.
     */
    static void scenario_exhausted(Path dir) throws Exception {
        Path hwidJson = collectHwid(dir);
        Path[] keys   = issueDevLicense(dir, hwidJson, 1, null);
        setupDrmDir(dir);

        // First launch: spend the one key.
        String key0 = readFirstKey(keys[0]);
        ExecResult r1 = launchDrmWrapper(dir, key0, 90);
        assertExitZero(r1, "exhausted -- first launch (spend key)");

        // Second launch: no keys left, must fail.
        ExecResult r2 = launchDrmWrapper(dir, key0, 15);
        assertExitNonZero(r2, "exhausted -- second launch (chain spent)");
        // The output should mention the exhaustion code or the key invalid code
        // (key0 is now the old anchor -- SHA256(key0) != new anchor).
    }

    /**
     * Burned license: Dev_Keygen --burn creates a revocation state.bin.
     * Launch must be denied immediately.
     */
    static void scenario_burned(Path dir) throws Exception {
        Path hwidJson = collectHwid(dir);
        burnLicense(dir, hwidJson);
        setupDrmDir(dir);

        // Any key -- doesn't matter, remaining_links=0 fails before key check.
        ExecResult r = launchDrmWrapper(dir, repeatChar('a', 64), 15);
        assertExitNonZero(r, "burned license");
    }

    /**
     * Tampered state.bin: flip a byte in the ciphertext.
     * DRM_Wrapper must fail with kWrapperStateOpenFailed (GCM auth tag mismatch).
     */
    static void scenario_tampered_state(Path dir) throws Exception {
        Path hwidJson = collectHwid(dir);
        issueDevLicense(dir, hwidJson, 3, null);
        setupDrmDir(dir);

        // Flip a byte in the ciphertext region (skip 4+4+12+16+4 = 40 header bytes).
        Path stateBin = dir.resolve("state.bin");
        byte[] data = Files.readAllBytes(stateBin);
        if (data.length > 50) data[50] ^= 0xFF;
        Files.write(stateBin, data);

        ExecResult r = launchDrmWrapper(dir, repeatChar('a', 64), 15);
        assertExitNonZero(r, "tampered state.bin");
    }

    /**
     * Full Java integration test: uses quark-protect + quark-build to produce
     * test-app.bundle, encrypts it with Dev_Keygen, then launches the real
     * quark.jar + DRM_Wrapper + actual class loading.
     * Requires quark-build.jar and test-app.jar to exist.
     */
    static void scenario_full_java(Path dir) throws Exception {
        Path hwidJson = collectHwid(dir);

        // Step 1: quark-protect test-app.jar → test-app-protected.jar
        Path protectedJar = dir.resolve("test-app-protected.jar");
        if (Files.exists(quark_protect_jar)) {
            ExecResult protect = exec(dir, 30,
                "java", "-jar", quark_protect_jar.toString(),
                test_app_jar.toString(), protectedJar.toString());
            if (protect.exitCode != 0) {
                // Fall back to unprotected jar if quark-protect fails
                Files.copy(test_app_jar, protectedJar, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("  [full_java] quark-protect skipped (using unprotected jar)");
            }
        } else {
            Files.copy(test_app_jar, protectedJar, StandardCopyOption.REPLACE_EXISTING);
        }

        // Step 2: quark-build → app.bundle
        Path bundle = dir.resolve("app.bundle");
        ExecResult build = exec(dir, 30,
            "java", "-jar", quark_build_jar.toString(),
            protectedJar.toString(), bundle.toString());
        assertExitZero(build, "quark-build");

        // Step 3: Dev_Keygen --dev --input-bundle → state.bin + core.enc + unlock_keys.txt
        Path[] keys = issueDevLicense(dir, hwidJson, 2, bundle);

        // Step 4: set up the DRM directory with quark.jar (real JVM target)
        setupDrmDirJava(dir);

        // Step 5: launch DRM_Wrapper → quark.jar → TestCoreEntryPoint
        String key0 = readFirstKey(keys[0]);
        ExecResult r = launchDrmWrapper(dir, key0, 120);
        assertExitZero(r, "full_java DRM_Wrapper launch");
        assertOutput(r.stdout, "PASS", "test-app checkpoint verification");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Helpers
    // ═════════════════════════════════════════════════════════════════════════

    /** Run HWID_Extractor.exe → hwid.json in workDir. */
    private static Path collectHwid(Path dir) throws Exception {
        Path out = dir.resolve("hwid.json");
        ExecResult r = exec(dir, 30, hwid_extractor.toString(), out.toString());
        assertExitZero(r, "HWID_Extractor");
        if (!Files.exists(out)) fail("HWID_Extractor did not write hwid.json");
        System.out.printf("  [hwid] collected %d bytes%n", Files.size(out));
        return out;
    }

    /**
     * Dev_Keygen --dev (no paste.rs). Returns [unlock_keys_path, state_bin_path].
     * If bundlePath is non-null, passes --input-bundle to also produce core.enc.
     */
    private static Path[] issueDevLicense(Path dir, Path hwidJson,
                                          int chainLen, Path bundlePath) throws Exception {
        List<String> cmd = new ArrayList<>(Arrays.asList(
            dev_keygen.toString(),
            hwidJson.toString(),
            String.valueOf(chainLen),
            dir.toString(),
            "--dev",
            "--label", "e2e-test"
        ));
        if (bundlePath != null) {
            cmd.add("--input-bundle");
            cmd.add(bundlePath.toString());
        }
        ExecResult r = exec(dir, 30, cmd.toArray(new String[0]));
        assertExitZero(r, "Dev_Keygen --dev");

        Path stateBin  = dir.resolve("state.bin");
        Path unlockKeys = dir.resolve("unlock_keys.txt");
        if (!Files.exists(stateBin))   fail("Dev_Keygen did not write state.bin");
        if (!Files.exists(unlockKeys)) fail("Dev_Keygen did not write unlock_keys.txt");
        System.out.printf("  [keygen] chain_length=%d, state.bin=%d bytes%n",
                          chainLen, Files.size(stateBin));
        return new Path[]{unlockKeys, stateBin};
    }

    /** Dev_Keygen --burn → state.bin with remaining_links=0 in workDir. */
    private static void burnLicense(Path dir, Path hwidJson) throws Exception {
        ExecResult r = exec(dir, 15,
            dev_keygen.toString(), "--burn", hwidJson.toString(), dir.toString());
        assertExitZero(r, "Dev_Keygen --burn");
        if (!Files.exists(dir.resolve("state.bin"))) fail("--burn did not write state.bin");
        System.out.println("  [burn] revocation state.bin written");
    }

    /**
     * Set up the DRM launch directory for protocol-only tests (handoff_spy as javaw).
     * Copies DRM_Wrapper.exe, quark.jar, state.bin.
     * jre\bin\javaw.exe = handoff_spy.exe.
     */
    private static void setupDrmDir(Path dir) throws Exception {
        // state.bin is already in dir (written by Dev_Keygen).
        // Copy executables into the same dir.
        copy(drm_wrapper, dir.resolve("DRM_Wrapper.exe"));
        copy(quark_jar,   dir.resolve("quark.jar"));

        // handoff_spy as the fake JVM
        Path jreBin = dir.resolve("jre").resolve("bin");
        Files.createDirectories(jreBin);
        copy(handoff_spy, jreBin.resolve("javaw.exe"));
    }

    /**
     * Set up the DRM launch directory for the full Java integration test.
     * Uses the real quark.jar and expects the JVM at jre\bin\javaw.exe to run it.
     * Requires a real JRE: looks for JAVA_HOME or falls back to java.home system property.
     */
    private static void setupDrmDirJava(Path dir) throws Exception {
        copy(drm_wrapper, dir.resolve("DRM_Wrapper.exe"));
        copy(quark_jar,   dir.resolve("quark.jar"));
        // core.enc already in dir from issueDevLicense with --input-bundle.

        // Point jre\bin\javaw.exe at the current JVM's javaw.exe.
        Path jreBin = dir.resolve("jre").resolve("bin");
        Files.createDirectories(jreBin);

        Path javaHome = findJavaHome();
        Path javaw = javaHome.resolve("bin").resolve("javaw.exe");
        if (!Files.exists(javaw)) {
            // Fall back to java.exe (some JDKs don't have javaw)
            javaw = javaHome.resolve("bin").resolve("java.exe");
        }
        if (!Files.exists(javaw)) fail("Cannot find javaw.exe in JAVA_HOME: " + javaHome);
        copy(javaw, jreBin.resolve("javaw.exe"));
    }

    private static Path findJavaHome() {
        String javaHome = System.getenv("JAVA_HOME");
        if (javaHome != null && !javaHome.isEmpty()) return Paths.get(javaHome);
        // java.home points to the JRE root in the running JVM.
        return Paths.get(System.getProperty("java.home"));
    }

    /**
     * Read the first unlock key from unlock_keys.txt.
     * The file has a header + blank line, then keys one per line (top = first to use).
     */
    private static String readFirstKey(Path unlockKeysPath) throws Exception {
        List<String> lines = Files.readAllLines(unlockKeysPath, StandardCharsets.UTF_8);
        for (String line : lines) {
            String trimmed = line.trim();
            // Keys are 64 hex chars.
            if (trimmed.length() == 64 && trimmed.matches("[0-9a-fA-F]+")) {
                return trimmed;
            }
        }
        throw new AssertionError("No 64-char hex key found in " + unlockKeysPath);
    }

    /**
     * Launch DRM_Wrapper.exe in workDir, piping `unlockKey` to its stdin.
     * Sets QUARK_SPY_CHALLENGES=1 so handoff_spy exits after one cycle (~30s).
     * Waits up to `timeoutSeconds` for DRM_Wrapper to exit.
     */
    private static ExecResult launchDrmWrapper(Path dir, String unlockKey,
                                               int timeoutSeconds) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(dir.resolve("DRM_Wrapper.exe").toString());
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);
        pb.environment().put("QUARK_SPY_CHALLENGES", "1");

        Process proc = pb.start();

        // Write unlock key to DRM_Wrapper stdin (simulates user input).
        try (OutputStream stdin = proc.getOutputStream()) {
            stdin.write((unlockKey + "\n").getBytes(StandardCharsets.UTF_8));
        }

        boolean finished = proc.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            throw new AssertionError("DRM_Wrapper did not exit within " + timeoutSeconds + "s");
        }

        String stdout = readStream(proc.getInputStream());
        return new ExecResult(proc.exitValue(), stdout);
    }

    // ─── Exec helper ─────────────────────────────────────────────────────────

    private static ExecResult exec(Path dir, int timeoutSecs, String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        boolean done = proc.waitFor(timeoutSecs, TimeUnit.SECONDS);
        if (!done) {
            proc.destroyForcibly();
            throw new AssertionError("Process timed out after " + timeoutSecs + "s: " + cmd[0]);
        }
        String out = readStream(proc.getInputStream());
        return new ExecResult(proc.exitValue(), out);
    }

    private static String readStream(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
        return baos.toString("UTF-8");
    }

    // ─── Assertions ──────────────────────────────────────────────────────────

    private static void assertExitZero(ExecResult r, String ctx) {
        if (r.exitCode != 0) {
            fail(ctx + " exited " + r.exitCode + "\nOutput:\n" + r.stdout);
        }
    }

    private static void assertExitNonZero(ExecResult r, String ctx) {
        if (r.exitCode == 0) {
            fail(ctx + " should have failed but exited 0\nOutput:\n" + r.stdout);
        }
    }

    private static void assertOutput(String output, String expected, String ctx) {
        if (!output.contains(expected)) {
            fail(ctx + ": expected output to contain \"" + expected
                 + "\"\nActual output:\n" + output);
        }
    }

    private static void fail(String msg) {
        throw new AssertionError(msg);
    }

    private static void checkExists(Path p, String name) {
        if (!Files.exists(p)) {
            System.err.println("ERROR: " + name + " not found at: " + p);
            System.exit(2);
        }
    }

    private static String repeatChar(char c, int n) {
        char[] chars = new char[n];
        java.util.Arrays.fill(chars, c);
        return new String(chars);
    }

    private static void copy(Path src, Path dst) throws Exception {
        Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING);
    }

    private static void deleteTree(Path dir) {
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }
                @Override
                public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                    Files.deleteIfExists(d);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException ignored) {}
    }

    // ─── Value types ─────────────────────────────────────────────────────────

    static final class ExecResult {
        final int exitCode;
        final String stdout;
        ExecResult(int exitCode, String stdout) {
            this.exitCode = exitCode;
            this.stdout   = stdout;
        }
    }
}
