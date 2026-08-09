package sanitizedonly;

import secure.Sanitize;
import secure.Secure;

public final class SanitizedOnly {
    static final class Bean {
        @Secure String ssn = "111-22-3333";
    }

    @Sanitize(
            description = "Log-safe correlation code",
            justification = "SEC-ONLY-1"
    )
    static String clean(String value) {
        return Integer.toHexString(value.hashCode());
    }

    static void log() {
        Bean bean = new Bean();
        System.out.println(clean(bean.ssn));
    }
}
