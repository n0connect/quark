package quark.drmcore;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * QKH2 heartbeat thread -- the Java half of the mutual-assured-destruction
 * contract described in {@code docs/HANDOFF_PROTOCOL.md}.
 *
 * <p>This non-daemon thread owns stdin after Bootstrap hands it off. It loops:
 * read a 40-byte "CHAL" frame, compute
 * {@code HMAC-SHA256(content_key, "RESP"||session_id||counter||nonce)},
 * write the 32-byte response to stdout.
 *
 * <p>If {@code stdin.read()} returns -1 or throws, the parent process died.
 * We call {@code Runtime.getRuntime().halt(-1)} immediately -- no recovery,
 * no cleanup, no {@code exit(1)} path that could be caught by a shutdown hook.
 *
 * <p>A companion watchdog daemon thread fires {@code halt(-1)} if no
 * challenge has been answered within 60 seconds (belt-and-suspenders against
 * a frozen/patched heartbeat that silently stops responding).
 */
final class QuarkHeartbeat extends Thread {

    private static final byte[] CHAL_MAGIC = {'C', 'H', 'A', 'L'};
    private static final int CHAL_FRAME_SIZE = 40;  // 4+4+32
    private static final int RESPONSE_SIZE   = 32;
    private static final long WATCHDOG_MILLIS = 60_000L;

    private final InputStream  stdin;
    private final OutputStream stdout;
    private final byte[]       contentKey;  // zeroed when this thread exits
    private final byte[]       sessionId;

    // Watchdog reads this; volatile ensures visibility without locking.
    private volatile long lastResponseMillis = System.currentTimeMillis();

    private QuarkHeartbeat(InputStream stdin, OutputStream stdout,
                           byte[] contentKey, byte[] sessionId) {
        super("quark-heartbeat");
        this.stdin      = stdin;
        this.stdout     = stdout;
        this.contentKey = contentKey;
        this.sessionId  = sessionId;
        setDaemon(false);  // non-daemon: JVM cannot exit while this thread lives
    }

    /**
     * Starts the heartbeat and its watchdog. Both are handed copies of
     * {@code contentKey} (caller may zero their copy after this returns).
     *
     * @param contentKey  HMAC key for challenge-response (32 bytes). A defensive
     *                    copy is made; the caller's array is not retained.
     * @param sessionId   session context for all challenge MACs (32 bytes). Copied.
     */
    static void start(InputStream stdin, OutputStream stdout,
                      byte[] contentKey, byte[] sessionId) {
        byte[] keyCopy     = Arrays.copyOf(contentKey, contentKey.length);
        byte[] sessionCopy = Arrays.copyOf(sessionId,  sessionId.length);

        QuarkHeartbeat hb = new QuarkHeartbeat(stdin, stdout, keyCopy, sessionCopy);
        hb.start();

        Thread watchdog = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(WATCHDOG_MILLIS / 2);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (System.currentTimeMillis() - hb.lastResponseMillis > WATCHDOG_MILLIS) {
                    Runtime.getRuntime().halt(-1);
                }
            }
        }, "quark-heartbeat-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    @Override
    public void run() {
        try {
            loop();
        } finally {
            Arrays.fill(contentKey, (byte) 0);
            Arrays.fill(sessionId, (byte) 0);
        }
    }

    private void loop() {
        byte[] chalBuf = new byte[CHAL_FRAME_SIZE];
        for (;;) {
            // Read exactly 40 bytes. readFully-style loop.
            int got = 0;
            while (got < CHAL_FRAME_SIZE) {
                int n;
                try {
                    n = stdin.read(chalBuf, got, CHAL_FRAME_SIZE - got);
                } catch (IOException e) {
                    // Pipe broken -- parent died.
                    Runtime.getRuntime().halt(-1);
                    return;
                }
                if (n < 0) {
                    // EOF on stdin -- parent closed the pipe (died or killed us).
                    Runtime.getRuntime().halt(-1);
                    return;
                }
                got += n;
            }

            // Validate "CHAL" magic.
            if (chalBuf[0] != CHAL_MAGIC[0] || chalBuf[1] != CHAL_MAGIC[1]
                    || chalBuf[2] != CHAL_MAGIC[2] || chalBuf[3] != CHAL_MAGIC[3]) {
                Runtime.getRuntime().halt(-1);
                return;
            }

            // counter is at offset 4, nonce at offset 8.
            ByteBuffer bb = ByteBuffer.wrap(chalBuf, 4, 36).order(ByteOrder.LITTLE_ENDIAN);
            int counter = bb.getInt();  // u32 LE → Java int (sign bit irrelevant for HMAC)
            byte[] nonce = new byte[32];
            bb.get(nonce);

            byte[] response = computeResponse(counter, nonce);
            Arrays.fill(nonce, (byte) 0);

            if (response == null) {
                Runtime.getRuntime().halt(-1);
                return;
            }

            try {
                stdout.write(response, 0, RESPONSE_SIZE);
                stdout.flush();
            } catch (IOException e) {
                // Parent's read end is gone.
                Runtime.getRuntime().halt(-1);
                return;
            } finally {
                Arrays.fill(response, (byte) 0);
            }

            lastResponseMillis = System.currentTimeMillis();
        }
    }

    /**
     * HMAC-SHA256(key=content_key, msg = "RESP" || session_id || counter(LE u32) || nonce)
     *
     * <p>Mirrors {@code quark::token::DeriveChallengeMac} byte-for-byte.
     */
    private byte[] computeResponse(int counter, byte[] nonce) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(contentKey, "HmacSHA256"));

            mac.update("RESP".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            mac.update(sessionId);

            // counter as little-endian u32
            byte[] ctrLE = new byte[4];
            ctrLE[0] = (byte) (counter & 0xFF);
            ctrLE[1] = (byte) ((counter >>> 8) & 0xFF);
            ctrLE[2] = (byte) ((counter >>> 16) & 0xFF);
            ctrLE[3] = (byte) ((counter >>> 24) & 0xFF);
            mac.update(ctrLE);

            mac.update(nonce);
            return mac.doFinal();
        } catch (Exception e) {
            return null;
        }
    }
}
