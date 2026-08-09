package policy;

import secure.Sanitize;
import secure.Secure;
import secure.SuppressSecureLog;

public final class PolicyCases {
    @Pii String metaField = "meta";
    @Secure String field = "field";

    @Secure
    static String secureReturn() {
        return "method";
    }

    static void methodReturnSource() {
        System.out.println(secureReturn());
    }

    static void parameterSource(@Secure String value) {
        System.out.println(value);
    }

    static void metaParameterSource(@Pii String value) {
        System.out.println(value);
    }

    record Customer(@Secure String ssn) {}

    static void recordComponentSource(Customer customer) {
        System.out.println(customer.ssn());
    }

    @Secure
    record SecretEnvelope(String value) {}

    static void typeSource(SecretEnvelope envelope) {
        System.out.println(envelope);
    }

    @Sanitize(description = "last four", justification = "policy LOG-4")
    static String mask(String value) {
        return "***" + value.substring(Math.max(0, value.length() - 4));
    }

    static void sanitizedParameter(@Secure String value) {
        System.out.println(mask(value));
    }

    @SuppressSecureLog(reason = "Regulated audit output", ticket = "SEC-42", expires = "2099-12-31")
    static void suppressedMethod(PolicyCases value) {
        System.out.println(value.field);
    }

    @SuppressSecureLog(reason = "Central audited helper", ticket = "SEC-43")
    static void suppressedHelper(String value) {
        System.out.println(value);
    }

    static void callsSuppressedHelper(PolicyCases value) {
        suppressedHelper(value.field);
    }

    static void activeFinding(PolicyCases value) {
        System.out.println(value.metaField);
    }

    interface Contract {
        @Secure String read();
        void consume(@Secure String value);
    }

    static final class ContractImpl implements Contract {
        @Override public String read() { return "contract"; }
        @Override public void consume(String value) { System.out.println(value); }
    }

    static void inheritedReturnContract(ContractImpl impl) {
        System.out.println(impl.read());
    }

    @SuppressSecureLog(reason = "Type-level approved diagnostic", ticket = "SEC-44")
    static final class SuppressedType {
        @Secure String value = "type";
        void log() {
            System.out.println(value);
        }
    }
}
