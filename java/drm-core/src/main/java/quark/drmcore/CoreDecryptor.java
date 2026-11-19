package quark.drmcore;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * In-memory AES-256-GCM decryption of {@code core.enc}.
 *
 * <p>File layout (mirrors the framing {@code quark::state} uses on the C++
 * side, so both halves of this codebase share one mental model of "sealed
 * blob"):
 * <pre>
 *   magic      : 4 bytes  "QENC"
 *   version    : u32 LE   format version (currently 1)
 *   iv         : 12 bytes GCM nonce
 *   ciphertext : remaining bytes, with the 16-byte GCM tag appended
 *                (this is the layout javax.crypto's GCM mode expects/produces
 *                directly -- no separate tag field to juggle on this side)
 * </pre>
 *
 * <p>No AAD here -- unlike {@code state.bin}, {@code core.enc} is not bound to
 * a specific machine (the token already is, transitively, via the C++ side's
 * derivation chain). Re-introducing a HWID check here would just resurrect
 * the "boolean trap" the architecture explicitly forbids.
 */
final class CoreDecryptor {

    private static final byte[] MAGIC = {'Q', 'E', 'N', 'C'};
    private static final int VERSION = 1;
    private static final int IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private CoreDecryptor() {}

    static byte[] decrypt(byte[] sealed, byte[] key32) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(sealed).order(ByteOrder.LITTLE_ENDIAN);

        byte[] magic = new byte[MAGIC.length];
        buf.get(magic);
        if (!java.util.Arrays.equals(magic, MAGIC)) {
            throw new java.io.IOException("bad magic");
        }
        int version = buf.getInt();
        if (version != VERSION) {
            throw new java.io.IOException("unsupported version");
        }

        byte[] iv = new byte[IV_LENGTH];
        buf.get(iv);

        byte[] ciphertextAndTag = new byte[buf.remaining()];
        buf.get(ciphertextAndTag);

        SecretKeySpec keySpec = new SecretKeySpec(key32, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // Throws AEADBadTagException on any tampering or wrong key -- exactly
        // the same "no distinguishable failure mode" property the C++ side's
        // mbedtls_gcm_auth_decrypt has.
        return cipher.doFinal(ciphertextAndTag);
    }
}
