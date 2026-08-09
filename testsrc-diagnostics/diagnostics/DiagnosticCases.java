package diagnostics;

import org.slf4j.MDC;
import secure.Secure;

public final class DiagnosticCases {
    @Secure
    String ssn;

    public void directMdc() {
        MDC.put("customer.ssn", ssn);
    }

    public void helperPath() {
        write(ssn);
    }

    private static void write(String value) {
        System.out.println(value);
    }
}
