import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DecTest {
    public static void main(String[] args) throws Exception {
        byte[] sealed = Files.readAllBytes(Paths.get(args[0]));   // core.enc
        byte[] key = hex(args[1]);                                 // core_enc_key hex
        System.out.println("core.enc size = " + sealed.length + " bytes, key len = " + key.length);

        ByteBuffer buf = ByteBuffer.wrap(sealed).order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[4]; buf.get(magic);
        System.out.println("magic = " + new String(magic, "US-ASCII"));
        int version = buf.getInt();
        System.out.println("version = " + version);
        byte[] iv = new byte[12]; buf.get(iv);
        System.out.println("iv = " + toHex(iv));
        byte[] ct = new byte[buf.remaining()]; buf.get(ct);
        System.out.println("ciphertext+tag = " + ct.length + " bytes");

        SecretKeySpec ks = new SecretKeySpec(key, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, ks, new GCMParameterSpec(128, iv));
        try {
            byte[] pt = c.doFinal(ct);
            System.out.println("DECRYPT SUCCESS: plaintext = " + pt.length + " bytes");
            System.out.println("first bytes: " + toHex(java.util.Arrays.copyOf(pt, Math.min(16, pt.length))));
        } catch (Exception e) {
            System.out.println("DECRYPT FAILED: " + e);
        }
    }
    static byte[] hex(String s){ byte[] b=new byte[s.length()/2]; for(int i=0;i<b.length;i++) b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16); return b; }
    static String toHex(byte[] b){ StringBuilder sb=new StringBuilder(); for(byte x:b) sb.append(String.format("%02x",x)); return sb.toString(); }
}
