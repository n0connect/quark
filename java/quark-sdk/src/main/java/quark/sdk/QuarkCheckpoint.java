package quark.sdk;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method as a Quark cryptographic checkpoint. The {@code quark-protect}
 * bytecode transformer injects a {@link QuarkRuntime#checkpoint(int)} call at
 * the method's entry point and weaves its return value into the method's
 * surrounding computations.
 *
 * <p>The injected call computes:
 * <pre>
 *   HMAC-SHA256(key=content_key, msg = "CP" || id (u32-LE) || session_counter (u32-LE))
 * </pre>
 *
 * <p>Because the return value feeds into real business logic, patching the
 * {@code QuarkRuntime.checkpoint} call to return {@code 0} corrupts outputs
 * rather than bypassing a boolean check. Use a unique {@code id} per method
 * to ensure each checkpoint produces a distinct HMAC output.
 *
 * <p>Example:
 * <pre>{@code
 * @QuarkCheckpoint(id = 0x1001)
 * public Invoice generateInvoice(Order order) { ... }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface QuarkCheckpoint {
    /**
     * Unique identifier for this checkpoint. Must be distinct across all
     * annotated methods in the protected application. Values 0x0001–0xEFFF
     * are reserved for application use; 0xF000–0xFFFF are reserved for
     * Quark internal use.
     */
    int id();
}
