package dep;

import secure.Secure;

public class Customer {
    @Secure("PII")
    public String ssn;

    public Customer(String ssn) {
        this.ssn = ssn;
    }

    @Override
    public String toString() {
        return "Customer[ssn=" + ssn + "]";
    }
}
