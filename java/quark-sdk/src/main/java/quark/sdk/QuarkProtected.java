package quark.sdk;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class as protected by Quark DRM. The {@code quark-build} tool
 * includes classes annotated with this at the class level in the encrypted
 * {@code core.enc} bundle -- they will not exist as recoverable bytecode until
 * a successful unlock.
 *
 * <p>Optional; {@code quark-build} can also be configured to encrypt all
 * classes in the input JAR regardless of annotation.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface QuarkProtected {
}
