package sanitizedonly;

import org.slf4j.MDC;
import secure.Sanitize;
import secure.Secure;

public final class ContextSanitizedOnly {
    static final class Bean {
        @Secure String ssn = "111-22-3333";
    }

    @Sanitize(
        description = "Context-safe correlation code",
        justification = "CTX-ONLY-1"
    )
    static String clean(String value) {
        return Integer.toHexString(value.hashCode());
    }

    static void capture() {
        Bean bean = new Bean();
        MDC.put("ssnToken", clean(bean.ssn));
    }
}
