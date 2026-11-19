package quark.drmcore;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Entry point launched by DRM_Wrapper.exe via the QKH2 protocol.
 *
 * <p>Flow (mirrors {@code docs/HANDOFF_PROTOCOL.md} section 6):
 * <ol>
 *   <li>Read exactly {@link HandoffFrame#FRAME_LENGTH} bytes from stdin.
 *       Do NOT read until EOF -- the pipe stays open for challenge frames.</li>
 *   <li>Validate magic {@code "QKH2"} and version {@code 2}.</li>
 *   <li>Derive {@code content_key} for challenge-response HMAC.</li>
 *   <li>Start {@link QuarkHeartbeat} (non-daemon) before any further work;
 *       it takes ownership of stdin. DRM_Wrapper will kill us if it doesn't
 *       get a response within 10 s of the first challenge.</li>
 *   <li>Decrypt {@code core.enc} using {@code core_enc_key} (AES-256-GCM).
 *       Wrong key = GCM auth failure = no application. No boolean trap.</li>
 *   <li>Zero all key material, load decrypted classes, invoke entry point.</li>
 * </ol>
 *
 * <p>CLAUDE.md rule 3 ("no boolean trap"): the derived {@code core_enc_key}
 * IS the AES key for {@code core.enc}. If it's wrong the JVM crashes with a
 * GCM auth exception -- there is no "licensed: true/false" check here.
 */
public final class Bootstrap {

    private static final long FRAME_READ_TIMEOUT_MILLIS = 5_000;
    private static final String CORE_ENTRY_POINT = "quark.app.CoreEntryPoint";
    private static final Path CORE_ENC_PATH = Paths.get("core.enc");

    private Bootstrap() {}

    public static void main(String[] args) {
        byte[] raw = readExactFromStdin(HandoffFrame.FRAME_LENGTH);
        if (raw == null) {
            ErrorCodes.report(ErrorCodes.FRAME_READ_FAILED);
            System.exit(1);
            return;
        }

        HandoffFrame frame = HandoffFrame.parse(raw);
        zero(raw);
        if (frame == null) {
            ErrorCodes.report(ErrorCodes.FRAME_INVALID);
            System.exit(1);
            return;
        }

        byte[] contentKey = null;
        byte[] coreEncKey = null;
        byte[] decrypted  = null;
        try {
            contentKey = frame.deriveContentKey();
            coreEncKey = frame.getCoreEncKey();

            // The child's stdout (fd 1) IS the QKH2 binary response pipe back to
            // DRM_Wrapper (CLAUDE.md rule 4). Capture a dedicated stream to that fd
            // for the heartbeat, then redirect System.out -> System.err so that any
            // protected-application code printing to stdout cannot inject bytes into
            // the response stream and break the challenge protocol. App stdout thus
            // surfaces on the inherited console (stderr) instead of corrupting fd 1.
            OutputStream responsePipe = new FileOutputStream(FileDescriptor.out);
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.err), true));

            // Start heartbeat BEFORE decryption -- DRM_Wrapper will issue the
            // first challenge ~30 s after launch; if there's no response in 10 s
            // it calls TerminateProcess. QuarkHeartbeat takes ownership of stdin;
            // Bootstrap must not read from stdin after this point.
            QuarkHeartbeat.start(System.in, responsePipe, contentKey, frame.getSessionId());

            // Wire QuarkRuntime (for @QuarkCheckpoint calls from protected code).
            quark.sdk.QuarkRuntime.init(contentKey, frame.getSessionId());

            // contentKey copy now owned by QuarkHeartbeat and QuarkRuntime; zero ours.
            zero(contentKey);
            contentKey = null;

            frame.zero();  // zeros handoffSecret, sessionId, initialSeal, coreEncKey copy

            byte[] encrypted;
            try {
                encrypted = Files.readAllBytes(CORE_ENC_PATH);
            } catch (Exception e) {
                ErrorCodes.report(ErrorCodes.CORE_ENC_READ_FAILED, CORE_ENC_PATH.toString());
                System.exit(1);
                return;
            }

            try {
                decrypted = CoreDecryptor.decrypt(encrypted, coreEncKey);
            } catch (Exception e) {
                // Wrong key (wrong machine, stale state, tampered file) and a
                // corrupted file are -- and must remain -- indistinguishable.
                ErrorCodes.report(ErrorCodes.CORE_ENC_DECRYPT_FAILED);
                System.exit(1);
                return;
            } finally {
                zero(coreEncKey);
                coreEncKey = null;
            }

            Class<?> entry;
            try {
                InMemoryClassLoader loader = new InMemoryClassLoader(Bootstrap.class.getClassLoader());
                entry = loader.defineFromDecryptedBundle(decrypted, CORE_ENTRY_POINT);
            } catch (Exception e) {
                ErrorCodes.report(ErrorCodes.CLASS_LOAD_FAILED);
                System.exit(1);
                return;
            }
            zero(decrypted);
            decrypted = null;

            try {
                entry.getMethod("start", String[].class).invoke(null, (Object) args);
            } catch (Exception e) {
                ErrorCodes.report(ErrorCodes.ENTRY_POINT_FAILED);
                System.exit(1);
            }
        } catch (Exception e) {
            ErrorCodes.report(ErrorCodes.FRAME_INVALID);
            System.exit(1);
        } finally {
            frame.zero();
            zero(contentKey);
            zero(coreEncKey);
            zero(decrypted);
        }
    }

    /**
     * Reads exactly {@code length} bytes from stdin, or returns {@code null}
     * on short-read or timeout. Does NOT check for EOF after reading -- the
     * QKH2 pipe stays open for subsequent challenge frames.
     */
    private static byte[] readExactFromStdin(int length) {
        final byte[][] result = new byte[1][];
        Thread reader = new Thread(() -> {
            byte[] buf = new byte[length];
            int total = 0;
            try {
                InputStream in = System.in;
                while (total < length) {
                    int n = in.read(buf, total, length - total);
                    if (n < 0) return;  // EOF before frame complete
                    total += n;
                }
                result[0] = buf;
            } catch (IOException ignored) {
                // result[0] left null
            }
        }, "quark-frame-reader");
        reader.setDaemon(true);
        reader.start();

        try {
            reader.join(FRAME_READ_TIMEOUT_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
        return result[0];
    }

    private static void zero(byte[] data) {
        if (data != null) {
            java.util.Arrays.fill(data, (byte) 0);
        }
    }
}
