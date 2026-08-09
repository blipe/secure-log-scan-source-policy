package secure;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method whose return value is approved for log output or diagnostic context even when it is
 * derived from an {@link Secure} value.
 *
 * <p>The scanner treats this annotation as an explicit trust boundary. The
 * optional text is reported for review and audit; the scanner does not attempt
 * to prove the implementation.</p>
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface Sanitize {
    String description() default "";
    String justification() default "";
}
