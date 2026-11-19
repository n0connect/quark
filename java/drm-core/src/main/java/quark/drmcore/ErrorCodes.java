package quark.drmcore;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * quark.jar's half of Quark's shared error-code registry. Mirrors
 * {@code cpp/common/include/quark/error.hpp} exactly for the 5xxx range --
 * the numbers, and what they mean, must never drift between the two halves,
 * because a code seen in {@code debug-crash.txt} or a terminal must mean the
 * same thing regardless of which of the four Quark programs wrote it.
 *
 * <p>Numbering convention (see {@code error.hpp} for the full table):
 * 1xxx/2xxx/3xxx/4xxx are produced by the C++ side; <b>5xxx is this side's
 * range</b>, and is the only range this class defines codes for.
 *
 * <p>Per CLAUDE.md rule 5 (fail-deadly): reporting a code never changes the
 * outcome -- every call site that reports one of these still ends in
 * {@code System.exit(1)}, no recovery, no behavioral branch. What this adds
 * is *visibility* (one line on the terminal, one line in
 * {@code debug-crash.txt}), not a new way out.
 */
final class ErrorCodes {

    static final int FRAME_READ_FAILED = 5001;       // stdin read timed out, hit EOF early, or had trailing bytes
    static final int FRAME_INVALID = 5002;           // bad magic and/or unsupported version
    static final int CORE_ENC_READ_FAILED = 5003;    // could not read core.enc from disk
    static final int CORE_ENC_DECRYPT_FAILED = 5004; // AES-GCM auth/decrypt failed -- wrong key, tampering, or both
    static final int CLASS_LOAD_FAILED = 5005;       // decrypted bundle did not yield a loadable CoreEntryPoint
    static final int ENTRY_POINT_FAILED = 5006;      // CoreEntryPoint#start threw or could not be invoked

    private static final Path CRASH_LOG_PATH = Paths.get("debug-crash.txt");
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String COMPONENT = "quark.jar";

    private ErrorCodes() {}

    /** The single source of truth for "what does code N mean" -- see error.hpp's Describe(). */
    static String describe(int code) {
        switch (code) {
            case FRAME_READ_FAILED:
                return "reading the handoff frame from stdin timed out or was incomplete";
            case FRAME_INVALID:
                return "the handoff frame had a bad magic value or unsupported version";
            case CORE_ENC_READ_FAILED:
                return "could not read core.enc from disk";
            case CORE_ENC_DECRYPT_FAILED:
                return "core.enc failed to authenticate/decrypt with the derived key";
            case CLASS_LOAD_FAILED:
                return "the decrypted bundle did not yield a loadable application core";
            case ENTRY_POINT_FAILED:
                return "the application's entry point could not be invoked";
            default:
                return "unrecognized error code";
        }
    }

    /**
     * The one funnel every failure path in quark.jar goes through -- the
     * Java mirror of {@code quark::error::Report}. Appends one line to
     * {@code debug-crash.txt} next to the running JVM's working directory,
     * and mirrors "[QUARK-ERR-NNNN] quark.jar: <description>" to stderr.
     *
     * <p>{@code detail} must stay short and non-sensitive (e.g. a byte count
     * or a file name) -- never key material, never the handoff secret.
     */
    static void report(int code, String detail) {
        String description = describe(code);
        String line = "[" + LocalDateTime.now().format(TIMESTAMP_FORMAT) + "] "
                + "component=" + COMPONENT + " "
                + "code=" + code + " (QUARK-ERR-" + code + ") "
                + description
                + (detail != null && !detail.isEmpty() ? " detail=" + detail : "");

        try {
            Files.write(CRASH_LOG_PATH,
                    (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
            // A failed crash-log write is not itself a new failure worth
            // recursing over -- the terminal line below is the fallback.
        }

        PrintStream err = System.err;
        if (detail != null && !detail.isEmpty()) {
            err.printf("[QUARK-ERR-%d] %s: %s (%s)%n", code, COMPONENT, description, detail);
        } else {
            err.printf("[QUARK-ERR-%d] %s: %s%n", code, COMPONENT, description);
        }
    }

    static void report(int code) {
        report(code, null);
    }
}
