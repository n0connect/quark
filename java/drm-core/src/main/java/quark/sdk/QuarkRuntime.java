package quark.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Real implementation of {@code QuarkRuntime} -- shipped inside {@code quark.jar}
 * and loaded by the JVM before any protected application classes. Shadows the
 * compile-time stub in {@code quark-sdk.jar}.
 *
 * <p>{@link Bootstrap} calls {@link #init} after starting {@link quark.drmcore.QuarkHeartbeat}.
 * Protected code calls {@link #checkpoint(int)} via injected bytecode from
 * {@code quark-protect}; the returned token feeds into real computations so
 * a wrong (or zero) key corrupts outputs instead of tripping a boolean check.
 */
public final class QuarkRuntime {

    private static volatile byte[] contentKey;
    private static volatile byte[] sessionId;
    private static final AtomicInteger counter = new AtomicInteger(0);

    private QuarkRuntime() {}

    /**
     * Called by {@code Bootstrap} after the QKH2 handshake. Makes defensive
     * copies; the caller may zero the originals after returning.
     */
    public static void init(byte[] key, byte[] sid) {
        contentKey = Arrays.copyOf(key, key.length);
        sessionId  = Arrays.copyOf(sid, sid.length);
    }

    /**
     * Computes {@code HMAC-SHA256(key=content_key, "CP" || id(u32-LE) || counter(u32-LE))}
     * and returns the first 8 bytes as a little-endian {@code long}.
     *
     * <p>If {@code init()} has not been called (e.g. the app was started without
     * DRM_Wrapper), returns {@code 0} -- the stub value -- which corrupts any
     * computation that feeds this token in as a real value.
     */
    public static long checkpoint(int id) {
        byte[] key = contentKey;
        byte[] sid = sessionId;
        if (key == null || sid == null) return 0L;

        int cnt = counter.getAndIncrement();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update("CP".getBytes(StandardCharsets.US_ASCII));
            mac.update(new byte[]{(byte) id, (byte)(id >> 8), (byte)(id >> 16), (byte)(id >> 24)});
            mac.update(new byte[]{(byte) cnt, (byte)(cnt >> 8), (byte)(cnt >> 16), (byte)(cnt >> 24)});
            byte[] result = mac.doFinal();

            long v = 0L;
            for (int i = 0; i < 8; i++) {
                v |= ((long)(result[i] & 0xFF)) << (i * 8);
            }
            return v;
        } catch (Exception e) {
            return 0L;
        }
    }
}
