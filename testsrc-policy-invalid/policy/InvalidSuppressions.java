package policy;

import secure.Secure;
import secure.SuppressSecureLog;

public final class InvalidSuppressions {
    @Secure String value = "x";

    @SuppressSecureLog(reason = "", ticket = "SEC-0")
    void blankReason() {
        System.out.println(value);
    }

    @SuppressSecureLog(reason = "Expired exception", expires = "2020-01-01")
    void expired() {
        System.out.println(value);
    }

    @SuppressSecureLog(reason = "Missing ticket")
    void missingTicket() {
        System.out.println(value);
    }
}
