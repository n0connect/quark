package quark.app;

/**
 * Reference shape of the "core" class whose .class bytes get pre-encrypted
 * into {@code core.enc} at build time and reconstituted in memory by
 * {@code drm-core}'s {@code InMemoryClassLoader}.
 *
 * <p>This is intentionally a thin seam, not the whole application: per
 * CLAUDE.md 4.2/§5, only the classes that encode the actual protected business
 * logic need to live behind the encryption boundary. Everything else (UI
 * shell, libraries, resources) ships as ordinary classes in {@code main.jar}
 * and simply calls into whatever this entry point exposes once it's loaded --
 * which is exactly what makes "patch the bytecode to skip the check" fail:
 * there is no check to skip, only a class that doesn't exist until it's
 * correctly decrypted.
 */
public final class CoreEntryPoint {

    private CoreEntryPoint() {}

    /** Invoked via reflection by {@code quark.drmcore.Bootstrap} once this class is loaded from memory. */
    public static void start(String[] args) {
        // Real implementation: the protected business logic lives here (and/or
        // in sibling classes bundled into the same encrypted blob). Anything
        // placed here never exists as recoverable bytecode outside of a
        // successful unlock -- that's the actual protection, not a flag check.
        System.out.println("Quark: core unlocked, application running.");
    }
}
