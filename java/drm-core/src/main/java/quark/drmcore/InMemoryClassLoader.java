package quark.drmcore;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

/**
 * Defines classes directly from a decrypted in-memory byte buffer -- nothing
 * is ever written to disk (CLAUDE.md 4.2: "diskte hiçbir iz bırakmadan").
 *
 * <p>Decrypted bundle layout (a flat, length-prefixed table of class files --
 * intentionally not a zip/jar; we don't want a familiar on-disk format making
 * it easy to recognize what {@code core.enc} becomes once decrypted):
 * <pre>
 *   count : u32 LE
 *   repeated `count` times:
 *     name_len  : u16 LE
 *     name      : `name_len` bytes, UTF-8 binary class name (e.g. "quark/app/CoreEntryPoint")
 *     class_len : u32 LE
 *     class     : `class_len` bytes of raw .class data
 * </pre>
 */
final class InMemoryClassLoader extends ClassLoader {

    private final Map<String, byte[]> pendingClassBytes = new HashMap<>();

    InMemoryClassLoader(ClassLoader parent) {
        super(parent);
    }

    /** Parses the bundle, defines every contained class, and returns {@code entryPointBinaryName} loaded. */
    Class<?> defineFromDecryptedBundle(byte[] bundle, String entryPointBinaryName) throws ClassNotFoundException {
        ByteBuffer buf = ByteBuffer.wrap(bundle).order(ByteOrder.LITTLE_ENDIAN);
        int count = buf.getInt();
        for (int i = 0; i < count; i++) {
            int nameLen = buf.getShort() & 0xFFFF;
            byte[] nameBytes = new byte[nameLen];
            buf.get(nameBytes);
            String internalName = new String(nameBytes, java.nio.charset.StandardCharsets.UTF_8);

            int classLen = buf.getInt();
            byte[] classBytes = new byte[classLen];
            buf.get(classBytes);

            pendingClassBytes.put(internalName.replace('/', '.'), classBytes);
        }
        return loadClass(entryPointBinaryName);
    }

    @Override
    protected Class<?> findClass(String binaryName) throws ClassNotFoundException {
        byte[] bytes = pendingClassBytes.remove(binaryName);
        if (bytes == null) {
            throw new ClassNotFoundException(binaryName);
        }
        try {
            return defineClass(binaryName, bytes, 0, bytes.length);
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }
}
