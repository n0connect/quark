package quark.test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Cross-language protection matrix: proves Quark actually protects a real
 * program in each of four languages (Go, C, C++, Java), using each of the
 * two protection methods this engine supports:
 *
 *   method1_wrapper  -- "protect an already-written program": DRM_Wrapper
 *                        launches the target as an external child process
 *                        over the QKH2 pipe protocol (see
 *                        docs/HANDOFF_PROTOCOL.md). The target's own logic
 *                        is unchanged; only whether it is allowed to run at
 *                        all, and whether it keeps responding to
 *                        challenges, is gated externally. Java uses the
 *                        real JVM pipeline (quark.jar + core.enc +
 *                        InMemoryClassLoader); Go/C/C++ link/implement the
 *                        QKH2 client side directly (quark-runtime-c for
 *                        C/C++, a from-scratch pure-Go client for Go) and
 *                        compute a checkpoint-style token from the derived
 *                        content_key.
 *
 *   method2_embedded -- "protect a program at the source level": the
 *                        program's own source calls quark_c_api directly
 *                        (quark_unlock_and_decrypt) -- no external wrapper,
 *                        no pipe protocol. Go via cgo, C/C++ linking
 *                        libquark_c directly, Java via the FFM/Panama API.
 *
 * Every scenario runs in its own temp directory with a fresh --dev-mode
 * (paste.rs-free) license, and every scenario's directory is deleted when
 * it finishes, win or lose -- see cleanWitnesses()/deleteTree() below and
 * README.md §13.1 on not exercising paste.rs during routine testing.
 *
 * Usage:
 *   java -cp e2e-test.jar quark.test.CrossLangE2ETest <build_dir> <examples_build_dir> <repo_root> [--scenario <name>]
 *
 * <build_dir>          the CMake build tree (e.g. sandbox/build-macos) --
 *                       must contain HWID_Extractor, Dev_Keygen, DRM_Wrapper.
 * <examples_build_dir> output of examples/build_all.sh (e.g.
 *                       sandbox/examples_build) -- must contain
 *                       quark_seal_tool, libquark_c.<so|dylib>, and the 6
 *                       native/Go method1/method2 binaries.
 * <repo_root>          the repository root -- used to locate
 *                       java/drm-core/build/libs/quark.jar,
 *                       java/test-app/build/libs/test-app.jar,
 *                       tools/quark-protect/build/libs/quark-protect.jar,
 *                       tools/quark-build/build/libs/quark-build.jar, and
 *                       examples/java/method2_embedded/Method2Embedded.class
 *                       (compiled into examples_build_dir by build_all.sh).
 */
public class CrossLangE2ETest {

    private static int passed = 0;
    private static int failed = 0;
    private static final List<String> failures = new ArrayList<>();

    private static Path buildDir;
    private static Path examplesDir;
    private static Path repoRoot;

    private static Path hwidExtractor, devKeygen, drmWrapper;
    private static Path quarkJarBuilt;      // java/drm-core/build/libs/quark.jar
    private static Path testAppJar, quarkProtectJar, quarkBuildJar;
    private static Path libquarkC;          // examples_build/libquark_c.<ext>
    private static Path sealTool;           // examples_build/quark_seal_tool
    private static String libExt;           // "dylib" or "so"

    // The same test/dev-only build secret compiled into cpp/drm_wrapper/secret.hpp
    // (kBuildSecret) -- Dev_Keygen and DRM_Wrapper are always built from this
    // exact source tree in this repo, so this is the real value, not a guess.
    private static final String BUILD_SECRET =
            "f31add891145c1e328d5ac0839610c47ee1de3f6ecb07a45cad5e40e654de9a5";

    private static final List<String> LANGS = Arrays.asList("cpp", "c", "go", "java");

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: CrossLangE2ETest <build_dir> <examples_build_dir> <repo_root> [--scenario <name>]");
            System.exit(2);
        }
        buildDir = Paths.get(args[0]).toAbsolutePath();
        examplesDir = Paths.get(args[1]).toAbsolutePath();
        repoRoot = Paths.get(args[2]).toAbsolutePath();

        String osName = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        boolean windows = osName.contains("win");
        boolean mac = osName.contains("mac");
        libExt = windows ? "dll" : (mac ? "dylib" : "so");
        String exeExt = windows ? ".exe" : "";

        hwidExtractor = buildDir.resolve("cpp/hwid_extractor/HWID_Extractor" + exeExt);
        devKeygen = buildDir.resolve("cpp/dev_keygen/Dev_Keygen" + exeExt);
        drmWrapper = buildDir.resolve("cpp/drm_wrapper/DRM_Wrapper" + exeExt);
        quarkJarBuilt = repoRoot.resolve("java/drm-core/build/libs/quark.jar");
        testAppJar = repoRoot.resolve("java/test-app/build/libs/test-app.jar");
        quarkProtectJar = repoRoot.resolve("tools/quark-protect/build/libs/quark-protect.jar");
        quarkBuildJar = repoRoot.resolve("tools/quark-build/build/libs/quark-build.jar");
        libquarkC = examplesDir.resolve("libquark_c." + libExt);
        sealTool = examplesDir.resolve("quark_seal_tool" + exeExt);

        for (Path p : Arrays.asList(hwidExtractor, devKeygen, drmWrapper, quarkJarBuilt,
                testAppJar, quarkProtectJar, quarkBuildJar, libquarkC, sealTool)) {
            checkExists(p);
        }

        String targetScenario = null;
        for (int i = 3; i < args.length; i++) {
            if ("--scenario".equals(args[i]) && i + 1 < args.length) targetScenario = args[++i];
        }

        System.out.println("=== Quark cross-language protection matrix ===");
        System.out.println("build_dir    = " + buildDir);
        System.out.println("examples_dir = " + examplesDir);
        System.out.println("os           = " + osName + " (lib ext: " + libExt + ")");
        System.out.println();

        for (String lang : LANGS) {
            String name1 = lang + "_method1_wrapper";
            if (targetScenario == null || targetScenario.equals(name1)) {
                run(name1, dir -> scenarioMethod1(lang, dir));
            }
            String name2 = lang + "_method2_embedded";
            if (targetScenario == null || targetScenario.equals(name2)) {
                run(name2, dir -> scenarioMethod2(lang, dir));
            }
        }

        System.out.println();
        System.out.printf("Results: %d passed, %d failed%n", passed, failed);
        if (!failures.isEmpty()) {
            System.out.println("Failed scenarios:");
            failures.forEach(s -> System.out.println("  - " + s));
        }
        System.exit(failed > 0 ? 1 : 0);
    }

    @FunctionalInterface
    interface Scenario {
        void run(Path workDir) throws Exception;
    }

    private static void run(String name, Scenario s) {
        System.out.printf("[%s] starting...%n", name);
        Path workDir = null;
        try {
            workDir = Files.createTempDirectory("quark_crosslang_" + name + "_");
            s.run(workDir);
            System.out.printf("[%s] PASS%n", name);
            passed++;
        } catch (AssertionError | Exception e) {
            System.out.printf("[%s] FAIL: %s%n", name, e);
            failed++;
            failures.add(name + ": " + e);
        } finally {
            // Always clean up -- no license/witness artifact should outlive its scenario.
            if (workDir != null) deleteTree(workDir);
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Method 1: external wrapper (DRM_Wrapper launches the target process)
    // ═════════════════════════════════════════════════════════════════════

    private static void scenarioMethod1(String lang, Path dir) throws Exception {
        Path hwidJson = collectHwid(dir);

        if (lang.equals("java")) {
            scenarioMethod1Java(dir, hwidJson);
            return;
        }

        // Native/Go: no core.enc, no real quark.jar -- just a placeholder
        // that satisfies DRM_Wrapper's jar-integrity check (Step 1.5), whose
        // hash we override via config since this isn't the real shipped jar.
        String[] keys = issueDevLicense(dir, hwidJson, 1);
        Path targetBinary = examplesDir.resolve(lang + "_method1_wrapper");
        checkExists(targetBinary);

        Path placeholderJar = dir.resolve("quark.jar");
        Files.write(placeholderJar, "placeholder".getBytes(StandardCharsets.UTF_8));
        String jarSha = sha256Hex(placeholderJar);

        Files.copy(drmWrapper, dir.resolve(drmWrapper.getFileName()), StandardCopyOption.REPLACE_EXISTING);
        writeDrmConfig(dir, targetBinary.toString(), "", jarSha);
        touchWitnessHost(dir);

        LaunchedProcess proc = launchDrmWrapperLongRunning(dir, keys[0]);
        try {
            waitForOutput(proc, "CHECKPOINT_RESULT=", 5);
        } finally {
            proc.process.destroy();
            proc.process.waitFor(5, TimeUnit.SECONDS);
        }
    }

    private static void scenarioMethod1Java(Path dir, Path hwidJson) throws Exception {
        // Mirrors the manually-verified pipeline: quark-protect -> quark-build
        // -> Dev_Keygen --input-bundle -> real DRM_Wrapper -> real JVM ->
        // real in-memory class load.
        Path protectedJar = dir.resolve("test-app-protected.jar");
        ExecResult protect = exec(dir, 30, "java", "-jar", quarkProtectJar.toString(),
                testAppJar.toString(), protectedJar.toString());
        assertExitZero(protect, "quark-protect");

        Path bundle = dir.resolve("app.bundle");
        ExecResult build = exec(dir, 30, "java", "-jar", quarkBuildJar.toString(),
                protectedJar.toString(), bundle.toString());
        assertExitZero(build, "quark-build");

        String[] keys = issueDevLicenseWithBundle(dir, hwidJson, 1, bundle);

        Files.copy(drmWrapper, dir.resolve(drmWrapper.getFileName()), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(quarkJarBuilt, dir.resolve("quark.jar"), StandardCopyOption.REPLACE_EXISTING);
        String jarSha = sha256Hex(dir.resolve("quark.jar"));

        String javaHome = System.getProperty("java.home");
        String javaBin = Paths.get(javaHome, "bin", "java").toString();
        writeDrmConfig(dir, javaBin, "-cp quark.jar quark.drmcore.Bootstrap", jarSha);
        touchWitnessHost(dir);

        LaunchedProcess proc = launchDrmWrapperLongRunning(dir, keys[0]);
        try {
            waitForOutput(proc, "[test-app] PASS", 8);
        } finally {
            proc.process.destroy();
            proc.process.waitFor(5, TimeUnit.SECONDS);
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Method 2: source-embedded (the program calls quark_c_api itself)
    // ═════════════════════════════════════════════════════════════════════

    private static void scenarioMethod2(String lang, Path dir) throws Exception {
        Path hwidJson = collectHwid(dir);
        String[] keys = issueDevLicense(dir, hwidJson, 1);

        String marker = "quark-method2-" + lang + "-" + System.nanoTime();
        Path plaintextFile = dir.resolve("secret_message.txt");
        Files.write(plaintextFile, marker.getBytes(StandardCharsets.UTF_8));

        Path sealedFile = dir.resolve("sealed_payload.bin");
        ExecResult seal = exec(dir, 15, sealTool.toString(), BUILD_SECRET,
                plaintextFile.toString(), sealedFile.toString());
        assertExitZero(seal, "quark_seal_tool");

        Path witnessHost = dir.resolve("witness_host.bin");
        Path witnessFile = dir.resolve("witness_file.bin");
        Files.write(witnessHost, new byte[0]);

        List<String> cmd = new ArrayList<>();
        if (lang.equals("java")) {
            cmd.addAll(Arrays.asList("java", "--enable-native-access=ALL-UNNAMED",
                    "-cp", examplesDir.toString(), "Method2Embedded", libquarkC.toString()));
        } else {
            cmd.add(examplesDir.resolve(lang + "_method2_embedded").toString());
        }
        cmd.addAll(Arrays.asList(
                dir.resolve("state.bin").toString(), BUILD_SECRET, keys[0],
                sealedFile.toString(), witnessHost.toString(), witnessFile.toString(),
                "com.quark.witness1", "com.quark.witness2"));

        Map<String, String> env = new HashMap<>();
        if (libExt.equals("dylib")) env.put("DYLD_LIBRARY_PATH", examplesDir.toString());
        else if (libExt.equals("so")) env.put("LD_LIBRARY_PATH", examplesDir.toString());

        ExecResult r = exec(dir, 15, env, cmd.toArray(new String[0]));
        assertExitZero(r, lang + " method2_embedded");
        if (!r.stdout.contains(marker)) {
            fail(lang + " method2_embedded: expected decrypted output to contain marker \"" + marker
                    + "\", got:\n" + r.stdout);
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Shared helpers
    // ═════════════════════════════════════════════════════════════════════

    private static Path collectHwid(Path dir) throws Exception {
        Path out = dir.resolve("hwid.json");
        ExecResult r = exec(dir, 30, hwidExtractor.toString(), out.toString());
        assertExitZero(r, "HWID_Extractor");
        if (!Files.exists(out)) fail("HWID_Extractor did not write hwid.json");
        return out;
    }

    /** Dev_Keygen --dev (no paste.rs, no bundle). Returns the unlock keys, top (first) to bottom. */
    private static String[] issueDevLicense(Path dir, Path hwidJson, int chainLen) throws Exception {
        ExecResult r = exec(dir, 30, devKeygen.toString(), hwidJson.toString(),
                String.valueOf(chainLen), dir.toString(), "--dev", "--label", "crosslang-e2e");
        assertExitZero(r, "Dev_Keygen --dev");
        return readKeys(dir);
    }

    private static String[] issueDevLicenseWithBundle(Path dir, Path hwidJson, int chainLen, Path bundle)
            throws Exception {
        ExecResult r = exec(dir, 30, devKeygen.toString(), hwidJson.toString(),
                String.valueOf(chainLen), dir.toString(), "--dev", "--label", "crosslang-e2e",
                "--input-bundle", bundle.toString());
        assertExitZero(r, "Dev_Keygen --dev --input-bundle");
        return readKeys(dir);
    }

    private static String[] readKeys(Path dir) throws Exception {
        Path unlockKeys = dir.resolve("unlock_keys.txt");
        if (!Files.exists(dir.resolve("state.bin"))) fail("Dev_Keygen did not write state.bin");
        if (!Files.exists(unlockKeys)) fail("Dev_Keygen did not write unlock_keys.txt");
        List<String> keys = new ArrayList<>();
        for (String line : Files.readAllLines(unlockKeys, StandardCharsets.UTF_8)) {
            String t = line.trim();
            if (t.length() == 64 && t.matches("[0-9a-fA-F]+")) keys.add(t);
        }
        if (keys.isEmpty()) fail("no 64-hex-char unlock key found in " + unlockKeys);
        return keys.toArray(new String[0]);
    }

    private static void writeDrmConfig(Path dir, String jvmPath, String jvmArgs, String jarSha256Hex)
            throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("state_path = state.bin\n");
        sb.append("quark_jar_path = quark.jar\n");
        sb.append("quark_jar_sha256_hex = ").append(jarSha256Hex).append('\n');
        sb.append("jvm_path = ").append(jvmPath).append('\n');
        sb.append("jvm_args = ").append(jvmArgs).append('\n');
        sb.append("challenge_interval_ms = 500\n");
        sb.append("challenge_timeout_ms = 2000\n");
        sb.append("witness_xattr_host_path = quark_witness_host.bin\n");
        sb.append("witness_xattr1_attr = com.quark.witness1\n");
        sb.append("witness_xattr2_attr = com.quark.witness2\n");
        sb.append("witness_file_path = quark_witness_file.bin\n");
        Files.write(dir.resolve("drm_wrapper.conf"), sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void touchWitnessHost(Path dir) throws Exception {
        Files.write(dir.resolve("quark_witness_host.bin"), new byte[0]);
    }

    private static String sha256Hex(Path file) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(Files.readAllBytes(file));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** A DRM_Wrapper process launched for a method-1 scenario: it never exits on
     *  its own (heartbeat loop keeps parent + child alive), so the caller is
     *  responsible for reading enough output then destroying it. */
    private static final class LaunchedProcess {
        final Process process;
        final StringBuffer output = new StringBuffer();
        LaunchedProcess(Process process) { this.process = process; }
    }

    private static LaunchedProcess launchDrmWrapperLongRunning(Path dir, String unlockKey) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(dir.resolve(drmWrapper.getFileName()).toString());
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        LaunchedProcess lp = new LaunchedProcess(p);

        try (OutputStream stdin = p.getOutputStream()) {
            stdin.write((unlockKey + "\n").getBytes(StandardCharsets.UTF_8));
        }

        Thread reader = new Thread(() -> {
            byte[] buf = new byte[4096];
            InputStream in = p.getInputStream();
            try {
                int n;
                while ((n = in.read(buf)) != -1) {
                    lp.output.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                }
            } catch (IOException ignored) {
            }
        }, "drm-wrapper-output-reader");
        reader.setDaemon(true);
        reader.start();

        return lp;
    }

    private static void waitForOutput(LaunchedProcess lp, String expected, int timeoutSeconds) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (System.nanoTime() < deadline) {
            if (lp.output.toString().contains(expected)) return;
            if (!lp.process.isAlive()) {
                fail("process exited before producing \"" + expected + "\" -- output:\n" + lp.output);
            }
            Thread.sleep(50);
        }
        fail("timed out after " + timeoutSeconds + "s waiting for \"" + expected + "\" -- output so far:\n" + lp.output);
    }

    private static ExecResult exec(Path dir, int timeoutSecs, String... cmd) throws Exception {
        return exec(dir, timeoutSecs, Collections.emptyMap(), cmd);
    }

    private static ExecResult exec(Path dir, int timeoutSecs, Map<String, String> extraEnv, String... cmd)
            throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);
        pb.environment().putAll(extraEnv);
        Process proc = pb.start();
        boolean done = proc.waitFor(timeoutSecs, TimeUnit.SECONDS);
        if (!done) {
            proc.destroyForcibly();
            throw new AssertionError("process timed out after " + timeoutSecs + "s: " + cmd[0]);
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

    private static void assertExitZero(ExecResult r, String ctx) {
        if (r.exitCode != 0) fail(ctx + " exited " + r.exitCode + "\nOutput:\n" + r.stdout);
    }

    private static void fail(String msg) { throw new AssertionError(msg); }

    private static void checkExists(Path p) {
        if (!Files.exists(p)) {
            System.err.println("ERROR: required artifact not found: " + p);
            System.exit(2);
        }
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
        } catch (IOException ignored) {
        }
    }

    static final class ExecResult {
        final int exitCode;
        final String stdout;
        ExecResult(int exitCode, String stdout) { this.exitCode = exitCode; this.stdout = stdout; }
    }
}
