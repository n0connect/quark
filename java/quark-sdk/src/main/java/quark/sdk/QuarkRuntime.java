package quark.sdk;

/**
 * Compile-time stub for {@code QuarkRuntime}. At runtime, this class is
 * shadowed by the real implementation in {@code quark.jar} (loaded by the JVM
 * before the protected application classes).
 *
 * <p>Developer code should never call {@code QuarkRuntime.checkpoint} directly;
 * the {@code quark-protect} bytecode transformer injects the calls automatically
 * at every {@link QuarkCheckpoint}-annotated method entry.
 */
public final class QuarkRuntime {

    private QuarkRuntime() {}

    /**
     * Returns an HMAC-derived token for checkpoint {@code id}.
     * The real implementation (in {@code quark.jar}) computes:
     * <pre>
     *   HMAC-SHA256(key=content_key, msg = "CP" || id (u32-LE) || counter (u32-LE))
     * </pre>
     * This stub always returns {@code 0} and is replaced at runtime.
     */
    public static long checkpoint(int id) {
        return 0L;
    }
}
