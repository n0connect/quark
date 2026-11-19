package quark.drmcore;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;

/**
 * The Java mirror of {@code cpp/common/include/quark/handoff.hpp} -- the QKH2
 * wire format that crosses the C++/Java boundary. Both halves must agree on
 * this byte-for-byte; see {@code docs/HANDOFF_PROTOCOL.md}.
 *
 * <p>Wire format, exactly {@link #FRAME_LENGTH} bytes, written by
 * DRM_Wrapper.exe. The write end is kept open after this frame -- no EOF
 * is signalled. Bootstrap must NOT check for EOF (pipe carries challenge frames next).
 * <pre>
 *   offset  size  field
 *   ------  ----  -----------------------------------------------------------
 *        0     4  magic          = "QKH2"
 *        4     4  version        = 2, little-endian u32
 *        8    32  handoff_secret   (derive content_key from this; challenges only)
 *       40    32  session_id       (random; context for all challenge MACs)
 *       72    32  initial_seal     (HMAC-SHA256 proof of full DRM flow; stored for @QuarkCheckpoint)
 *      104    32  core_enc_key     (stable per license; decrypt core.enc with this)
 *   ------  ----
 *      136        FRAME_LENGTH
 * </pre>
 */
final class HandoffFrame {

    private static final byte[] MAGIC = {'Q', 'K', 'H', '2'};
    private static final int VERSION = 2;
    static final int FRAME_LENGTH = 4 + 4 + 32 + 32 + 32 + 32;  // 136

    private final byte[] handoffSecret;  // → deriveContentKey(); zero after QuarkHeartbeat exits
    private final byte[] sessionId;      // kept alive for QuarkHeartbeat
    private final byte[] initialSeal;    // kept for @QuarkCheckpoint context
    private final byte[] coreEncKey;     // → CoreDecryptor; zero after decrypt

    private HandoffFrame(byte[] handoffSecret, byte[] sessionId,
                         byte[] initialSeal, byte[] coreEncKey) {
        this.handoffSecret = handoffSecret;
        this.sessionId     = sessionId;
        this.initialSeal   = initialSeal;
        this.coreEncKey    = coreEncKey;
    }

    /**
     * Parses the QKH2 initial frame, validating magic and version.
     *
     * @return the parsed frame, or {@code null} if the bytes are not a
     *         well-formed QKH2 frame (caller treats this as {@code System.exit(1)}).
     */
    static HandoffFrame parse(byte[] raw) {
        if (raw == null || raw.length != FRAME_LENGTH) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);

        byte[] magic = new byte[MAGIC.length];
        buf.get(magic);
        if (!java.util.Arrays.equals(magic, MAGIC)) {
            return null;
        }
        if (buf.getInt() != VERSION) {
            return null;
        }

        byte[] handoffSecret = new byte[32];
        byte[] sessionId     = new byte[32];
        byte[] initialSeal   = new byte[32];
        byte[] coreEncKey    = new byte[32];
        buf.get(handoffSecret);
        buf.get(sessionId);
        buf.get(initialSeal);
        buf.get(coreEncKey);
        return new HandoffFrame(handoffSecret, sessionId, initialSeal, coreEncKey);
    }

    /**
     * content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret)
     *
     * <p>Mirrors {@code quark::token::DeriveContentKey}. Used ONLY for QKH2
     * challenge-response HMAC; changes every Lamport step (per-session).
     * Zero the returned array when QuarkHeartbeat exits.
     */
    byte[] deriveContentKey() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update("QUARK-CORE-CONTENT-KEY".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        sha256.update(handoffSecret);
        return sha256.digest();
    }

    /** The per-session random context for all challenge MACs. Kept alive for QuarkHeartbeat. */
    byte[] getSessionId() {
        return sessionId;
    }

    /** Proof of full DRM flow; stored for @QuarkCheckpoint. Java cannot independently verify it. */
    byte[] getInitialSeal() {
        return initialSeal;
    }

    /**
     * The AES-256 key for decrypting core.enc in memory. Stable per license
     * (excludes the rolling Lamport anchor). Zero after CoreDecryptor.decrypt() returns.
     *
     * <p>Returns a defensive COPY: the caller (Bootstrap) calls {@link #zero()}
     * before decrypting core.enc, which would otherwise wipe the very key it is
     * about to use (the frame's field and the returned reference would alias the
     * same array). The caller owns the returned copy and must zero it itself.
     */
    byte[] getCoreEncKey() {
        return coreEncKey.clone();
    }

    void zero() {
        java.util.Arrays.fill(handoffSecret, (byte) 0);
        java.util.Arrays.fill(sessionId, (byte) 0);
        java.util.Arrays.fill(initialSeal, (byte) 0);
        java.util.Arrays.fill(coreEncKey, (byte) 0);
    }
}
