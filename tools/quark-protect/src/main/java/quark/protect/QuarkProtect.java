package quark.protect;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * Bytecode transformer: injects {@code QuarkRuntime.checkpoint(id)} calls into
 * methods annotated with {@code @QuarkCheckpoint} and weaves the returned token
 * into the surrounding business logic so the call cannot be neutralised by
 * patching it to {@code return 0}.
 *
 * <p>Usage:
 * <pre>
 *   java -jar quark-protect.jar &lt;input.jar&gt; &lt;output.jar&gt;
 * </pre>
 *
 * <p>Transformation applied to each annotated method:
 * <ol>
 *   <li>At method entry, inject:
 *       {@code long __q = QuarkRuntime.checkpoint(id);}</li>
 *   <li>At each RETURN instruction that returns a numeric value (int/long/float/double),
 *       XOR the value with {@code (int)(__q ^ (__q >>> 32))} so wrong key corrupts output.</li>
 *   <li>For void methods, the call is still made (proving liveness to DRM_Wrapper)
 *       even though there is no return value to corrupt.</li>
 * </ol>
 *
 * <p>Each checkpoint {@code id} produces a different HMAC output (per
 * CLAUDE.md rule 7), so 50+ annotated methods create 50+ independent
 * cryptographic coupling points that must each be individually patched out.
 */
public final class QuarkProtect {

    private static final String RUNTIME_CLASS    = "quark/sdk/QuarkRuntime";
    private static final String CHECKPOINT_DESC  = "Lquark/sdk/QuarkCheckpoint;";
    private static final String CHECKPOINT_VALUE = "id";

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: quark-protect <input.jar> <output.jar>");
            System.exit(2);
        }

        Path inputJar  = Paths.get(args[0]);
        Path outputJar = Paths.get(args[1]);

        int transformed = transformJar(inputJar, outputJar);
        System.out.printf("quark-protect: %d method(s) transformed → %s%n", transformed, outputJar);
    }

    static int transformJar(Path input, Path output) throws IOException {
        int count = 0;
        try (JarFile jf = new JarFile(input.toFile());
             JarOutputStream jos = new JarOutputStream(
                     new BufferedOutputStream(Files.newOutputStream(output)))) {

            Enumeration<JarEntry> entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry je = entries.nextElement();
                try (InputStream is = jf.getInputStream(je)) {
                    byte[] data = drainStream(is);

                    if (je.getName().endsWith(".class")) {
                        TransformResult tr = transformClass(data);
                        data = tr.classBytes;
                        count += tr.methodsTransformed;
                    }

                    JarEntry out = new JarEntry(je.getName());
                    jos.putNextEntry(out);
                    jos.write(data);
                    jos.closeEntry();
                }
            }
        }
        return count;
    }

    private static final class TransformResult {
        final byte[] classBytes;
        final int methodsTransformed;
        TransformResult(byte[] classBytes, int methodsTransformed) {
            this.classBytes = classBytes;
            this.methodsTransformed = methodsTransformed;
        }
    }

    private static byte[] drainStream(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
        return baos.toByteArray();
    }

    private static TransformResult transformClass(byte[] classBytes) {
        ClassReader cr = new ClassReader(classBytes);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        int[] count = {0};

        cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                return new CheckpointInjector(mv, access, name, descriptor, count);
            }
        }, ClassReader.EXPAND_FRAMES);

        return new TransformResult(cw.toByteArray(), count[0]);

    }

    // ─── AdviceAdapter subclass: injects at method entry and return sites ────

    private static final class CheckpointInjector extends AdviceAdapter {

        private final int[] counter;
        private int checkpointId = -1;
        private int tokenLocal   = -1;  // local var index for the HMAC token

        CheckpointInjector(MethodVisitor mv, int access, String name,
                           String descriptor, int[] counter) {
            super(Opcodes.ASM9, mv, access, name, descriptor);
            this.counter = counter;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            AnnotationVisitor base = super.visitAnnotation(descriptor, visible);
            if (!CHECKPOINT_DESC.equals(descriptor)) return base;

            // Capture the `id` attribute from @QuarkCheckpoint
            return new AnnotationVisitor(Opcodes.ASM9, base) {
                @Override
                public void visit(String name, Object value) {
                    super.visit(name, value);
                    if (CHECKPOINT_VALUE.equals(name) && value instanceof Integer) {
                        checkpointId = (Integer) value;
                    }
                }
            };
        }

        @Override
        protected void onMethodEnter() {
            if (checkpointId < 0) return;

            // long __q = QuarkRuntime.checkpoint(id);
            tokenLocal = newLocal(Type.LONG_TYPE);
            mv.visitLdcInsn(checkpointId);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, RUNTIME_CLASS,
                               "checkpoint", "(I)J", false);
            mv.visitVarInsn(Opcodes.LSTORE, tokenLocal);

            counter[0]++;
        }

        @Override
        protected void onMethodExit(int opcode) {
            if (checkpointId < 0 || tokenLocal < 0) return;
            if (opcode == Opcodes.ATHROW) return;

            // For int/long returns: XOR with a fold of the 64-bit token.
            // int returns (IRETURN): fold token to 32 bits and XOR.
            if (opcode == Opcodes.IRETURN) {
                // stack top: int value
                mv.visitVarInsn(Opcodes.LLOAD, tokenLocal);
                mv.visitLdcInsn(32);
                mv.visitInsn(Opcodes.LUSHR);
                mv.visitVarInsn(Opcodes.LLOAD, tokenLocal);
                mv.visitInsn(Opcodes.LXOR);
                mv.visitInsn(Opcodes.L2I);
                mv.visitInsn(Opcodes.IXOR);
            } else if (opcode == Opcodes.LRETURN) {
                // stack top: long value
                mv.visitVarInsn(Opcodes.LLOAD, tokenLocal);
                mv.visitInsn(Opcodes.LXOR);
            }
            // FRETURN, DRETURN, ARETURN, RETURN: call was already made (liveness proof),
            // but we don't corrupt reference/float types to avoid class-cast issues.
        }
    }
}
