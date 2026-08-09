package secure;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Auditable suppression for a known secure-log finding.
 *
 * <p>Suppressed findings remain in text, JSON, and SARIF output. A non-blank reason is required.
 * The optional expiration uses ISO-8601 form {@code yyyy-MM-dd}; expired suppressions fail closed.</p>
 */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.CONSTRUCTOR})
public @interface SuppressSecureLog {
    String reason();
    String ticket() default "";
    String expires() default "";
}
