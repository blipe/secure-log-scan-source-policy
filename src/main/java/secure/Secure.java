package secure;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks data that must not reach log output or diagnostic context unless it has passed through
 * an approved {@link Sanitize} boundary.
 *
 * <p>The annotation may be placed on fields, method returns, parameters, record components,
 * or types. It may also be used as a meta-annotation on a corporate annotation such as
 * {@code @Pii}.</p>
 */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER,
        ElementType.RECORD_COMPONENT, ElementType.TYPE, ElementType.ANNOTATION_TYPE})
public @interface Secure {
    /** Optional reason or data class, e.g. "PII", "token", or "secret". */
    String value() default "";
}
