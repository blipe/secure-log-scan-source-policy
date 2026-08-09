package app;

import secure.Secure;

public final class AppBean {
    @Secure("PII")
    public String ssn;
}
