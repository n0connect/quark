// Method 2 ("protect a program at the source level"), Java, via the FFM API
// (java.lang.foreign -- "Panama", stable since JDK 22, no JNI glue code
// required). This program's own source calls quark_unlock_and_decrypt()
// directly against libquark_c -- no DRM_Wrapper, no JVM pipeline, no
// core.enc/InMemoryClassLoader. Protection lives in the program, not around
// it, exactly like the Go/C/C++ method-2 demos, just via a different FFI.
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Method2Embedded {

    public static void main(String[] args) throws Throwable {
        if (args.length != 9) {
            System.err.println("usage: Method2Embedded <libquark_c_path> <state_path> <build_secret> "
                    + "<unlock_key_hex> <sealed_payload_path> <witness_host_path> <witness_file_path> "
                    + "<xattr1_attr> <xattr2_attr>");
            System.exit(2);
        }
        String libPath      = args[0];
        String statePath    = args[1];
        String buildSecret  = args[2];
        String unlockKey    = args[3];
        String sealedPath   = args[4];
        String witnessHost  = args[5];
        String witnessFile  = args[6];
        String attr1        = args[7];
        String attr2        = args[8];

        byte[] sealed = Files.readAllBytes(Path.of(sealedPath));

        System.load(libPath);

        Linker linker = Linker.nativeLinker();
        SymbolLookup lookup = SymbolLookup.loaderLookup();

        MethodHandle unlockAndDecrypt = linker.downcallHandle(
                lookup.find("quark_unlock_and_decrypt").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,   // state_path
                        ValueLayout.ADDRESS,   // build_secret
                        ValueLayout.ADDRESS,   // witnesses[3]
                        ValueLayout.ADDRESS,   // candidate_key
                        ValueLayout.ADDRESS,   // sealed_payload
                        ValueLayout.JAVA_LONG, // sealed_payload_len
                        ValueLayout.ADDRESS,   // plaintext_out
                        ValueLayout.JAVA_LONG, // plaintext_cap
                        ValueLayout.ADDRESS,   // plaintext_len_out
                        ValueLayout.ADDRESS,   // content_key_out (nullable)
                        ValueLayout.ADDRESS)); // session_id_out (nullable)

        MethodHandle errorDescribe = linker.downcallHandle(
                lookup.find("quark_error_describe").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment cStatePath = arena.allocateFrom(statePath);
            MemorySegment cBuildSecret = arena.allocateFrom(buildSecret);
            MemorySegment cUnlockKey = arena.allocateFrom(unlockKey);
            MemorySegment cWitnessHost = arena.allocateFrom(witnessHost);
            MemorySegment cWitnessFile = arena.allocateFrom(witnessFile);
            MemorySegment cAttr1 = arena.allocateFrom(attr1);
            MemorySegment cAttr2 = arena.allocateFrom(attr2);

            MemorySegment cSealed = arena.allocate(sealed.length);
            MemorySegment.copy(sealed, 0, cSealed, ValueLayout.JAVA_BYTE, 0, sealed.length);

            // quark_witness_channel_t { int32 kind; char* path; char* attr_name; char magic[4]; char* name; }
            long channelSize = 8 + 8 + 8 + 4 + 4 /* padding */ + 8; // matches the C struct's layout on LP64
            MemorySegment witnesses = arena.allocate(channelSize * 3);

            writeWitness(witnesses, channelSize, 0, /*XATTR*/ 1, cWitnessHost, cAttr1, "QWX1", arena);
            writeWitness(witnesses, channelSize, 1, /*XATTR*/ 1, cWitnessHost, cAttr2, "QWX2", arena);
            writeWitness(witnesses, channelSize, 2, /*FILE*/ 0, cWitnessFile, MemorySegment.NULL, "QWF0", arena);

            long plaintextCap = 4096;
            MemorySegment plaintextOut = arena.allocate(plaintextCap);
            MemorySegment plaintextLenOut = arena.allocate(ValueLayout.JAVA_LONG);

            int rc = (int) unlockAndDecrypt.invoke(
                    cStatePath, cBuildSecret, witnesses, cUnlockKey,
                    cSealed, (long) sealed.length,
                    plaintextOut, plaintextCap, plaintextLenOut,
                    MemorySegment.NULL, MemorySegment.NULL);

            if (rc != 0) {
                MemorySegment desc = (MemorySegment) errorDescribe.invoke(rc);
                String message = desc.reinterpret(256).getString(0);
                System.err.printf("quark_unlock_and_decrypt failed: %d (%s)%n", rc, message);
                System.exit(1);
            }

            long plaintextLen = plaintextLenOut.get(ValueLayout.JAVA_LONG, 0);
            byte[] plaintext = new byte[(int) plaintextLen];
            MemorySegment.copy(plaintextOut, ValueLayout.JAVA_BYTE, 0, plaintext, 0, (int) plaintextLen);
            System.out.write(plaintext);
            System.out.flush();
        }
    }

    // Layout must match quark_c_api.h's quark_witness_channel_t byte-for-byte
    // on this platform's LP64 ABI: {int32 kind (+4 pad); char* path;
    // char* attr_name; char magic[4] (+4 pad); char* name;}.
    private static void writeWitness(MemorySegment base, long stride, int index, int kind,
                                      MemorySegment path, MemorySegment attrName, String magic,
                                      Arena arena) {
        long offset = index * stride;
        base.set(ValueLayout.JAVA_INT, offset, kind);
        base.set(ValueLayout.ADDRESS, offset + 8, path);
        base.set(ValueLayout.ADDRESS, offset + 16, attrName);
        MemorySegment magicSeg = arena.allocateFrom(magic);
        MemorySegment.copy(magicSeg, 0, base, offset + 24, 4);
        base.set(ValueLayout.ADDRESS, offset + 32, MemorySegment.NULL); // name (diagnostics only)
    }
}
