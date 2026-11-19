package quark.build;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * Bundles the class files from an input JAR into the Quark InMemoryClassLoader
 * wire format ({@code app.bundle}), which is then encrypted to {@code core.enc}
 * by {@code dev_keygen --input-bundle}.
 *
 * <p>Bundle format (mirrors {@code InMemoryClassLoader.defineFromDecryptedBundle}):
 * <pre>
 *   count     : u32 LE   -- number of class entries
 *   repeated count times:
 *     name_len  : u16 LE  -- byte length of internal class name
 *     name      : bytes   -- binary name with '/' separators (e.g. "quark/app/CoreEntryPoint")
 *     class_len : u32 LE  -- byte length of .class data
 *     class     : bytes   -- raw .class file bytes
 * </pre>
 *
 * <p>Usage:
 * <pre>
 *   java -jar quark-build.jar [--only-annotated] input.jar output.bundle
 * </pre>
 *
 * {@code --only-annotated}: only include classes annotated with {@code @QuarkProtected}.
 */
public final class QuarkBuild {

    public static void main(String[] args) throws Exception {
        boolean onlyAnnotated = false;
        List<String> positional = new ArrayList<>();

        for (String a : args) {
            if (a.equals("--only-annotated")) onlyAnnotated = true;
            else positional.add(a);
        }

        if (positional.size() != 2) {
            System.err.println("Usage: quark-build [--only-annotated] <input.jar> <output.bundle>");
            System.exit(2);
        }

        Path inputJar   = Paths.get(positional.get(0));
        Path outputPath = Paths.get(positional.get(1));

        List<ClassEntry> entries = loadClasses(inputJar, onlyAnnotated);
        if (entries.isEmpty()) {
            System.err.println("ERROR: no class files found in " + inputJar);
            System.exit(1);
        }

        byte[] bundle = buildBundle(entries);
        Files.write(outputPath, bundle);

        System.out.printf("quark-build: packed %d classes (%d bytes) → %s%n",
                entries.size(), bundle.length, outputPath);
    }

    private static final class ClassEntry {
        final String internalName;
        final byte[] classBytes;
        ClassEntry(String internalName, byte[] classBytes) {
            this.internalName = internalName;
            this.classBytes = classBytes;
        }
    }

    private static byte[] drainStream(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
        return baos.toByteArray();
    }

    private static List<ClassEntry> loadClasses(Path jar, boolean onlyAnnotated) throws IOException {
        List<ClassEntry> result = new ArrayList<>();
        try (JarFile jf = new JarFile(jar.toFile())) {
            Enumeration<JarEntry> entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry je = entries.nextElement();
                if (!je.getName().endsWith(".class")) continue;

                byte[] bytes;
                try (InputStream is = jf.getInputStream(je)) {
                    bytes = drainStream(is);
                }

                // internal name: strip ".class" suffix
                String internalName = je.getName().substring(0, je.getName().length() - 6);

                if (onlyAnnotated && !hasQuarkProtectedAnnotation(bytes)) continue;

                result.add(new ClassEntry(internalName, bytes));
            }
        }
        return result;
    }

    // Simple annotation check: scan the constant pool for the QuarkProtected descriptor.
    private static boolean hasQuarkProtectedAnnotation(byte[] classBytes) {
        String target = "Lquark/sdk/QuarkProtected;";
        String classStr = new String(classBytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        return classStr.contains(target);
    }

    private static byte[] buildBundle(List<ClassEntry> entries) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);

        // count (u32 LE)
        writeU32LE(out, entries.size());

        for (ClassEntry e : entries) {
            byte[] nameBytes = e.internalName.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            // name_len (u16 LE)
            writeU16LE(out, nameBytes.length);
            // name bytes
            out.write(nameBytes);
            // class_len (u32 LE)
            writeU32LE(out, e.classBytes.length);
            // class bytes
            out.write(e.classBytes);
        }

        out.flush();
        return baos.toByteArray();
    }

    private static void writeU32LE(DataOutputStream out, int v) throws IOException {
        out.write(v & 0xFF);
        out.write((v >> 8) & 0xFF);
        out.write((v >> 16) & 0xFF);
        out.write((v >> 24) & 0xFF);
    }

    private static void writeU16LE(DataOutputStream out, int v) throws IOException {
        out.write(v & 0xFF);
        out.write((v >> 8) & 0xFF);
    }
}
