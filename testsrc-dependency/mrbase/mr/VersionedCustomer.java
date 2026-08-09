package mr;

import secure.Secure;

public class VersionedCustomer {
    @Secure("PII")
    public String ssn;

    @Override
    public String toString() {
        return "customer";
    }
}
