package sanitize;

import secure.Sanitize;
import secure.Secure;

import java.util.Arrays;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Logger;

public final class SanitizeCases {
    private static final Logger LOG = Logger.getLogger(SanitizeCases.class.getName());

    static final class Bean {
        @Secure String ssn = "111-22-3333";
        @Secure String account = "account-7";
        String derived;
    }

    static final class Rendered {
        String value;
        @Override public String toString() { return "Rendered[" + value + "]"; }
    }

    record SanitizedRecord(String value) { }

    @Sanitize(
            description = "Stable one-way log correlation value",
            justification = "Approved security utility SEC-1421"
    )
    static String hash(String value) {
        return Integer.toHexString(value.hashCode());
    }

    @Sanitize(description = "Returns a display-safe representation")
    static String sanitizeObject(Bean bean) {
        return "bean:" + hash(bean.ssn);
    }

    @Sanitize
    static String leakingSanitizer(String value) {
        System.out.println(value);
        return value;
    }

    static String passThrough(String value) {
        return value;
    }

    static void directUnsafe() {
        Bean bean = new Bean();
        System.out.println(bean.ssn);
    }

    static void simpleSanitized() {
        Bean bean = new Bean();
        System.out.println(hash(bean.ssn));
    }

    static void helperPreservesSanitized() {
        Bean bean = new Bean();
        System.out.println(passThrough(hash(bean.ssn)));
    }

    static void fieldPreservesSanitized() {
        Bean bean = new Bean();
        bean.derived = hash(bean.ssn);
        System.out.println(bean.derived);
    }

    static void arrayPreservesSanitized() {
        Bean bean = new Bean();
        String[] values = {hash(bean.ssn)};
        System.out.println(Arrays.toString(values));
    }

    static void lambdaPreservesSanitized() {
        Bean bean = new Bean();
        Supplier<String> supplier = () -> hash(bean.ssn);
        System.out.println(supplier.get());
    }

    static void methodReferencePreservesSanitized() {
        Bean bean = new Bean();
        Function<String, String> function = SanitizeCases::hash;
        System.out.println(function.apply(bean.ssn));
    }

    static void loggerPreservesSanitized() {
        Bean bean = new Bean();
        LOG.info(hash(bean.ssn));
    }

    static void objectSanitizer() {
        Bean bean = new Bean();
        System.out.println(sanitizeObject(bean));
    }


    static void stringConcatPreservesSanitized() {
        Bean bean = new Bean();
        System.out.println("ssn-token=" + hash(bean.ssn));
    }

    static void objectRenderingPreservesSanitized() {
        Bean bean = new Bean();
        Rendered rendered = new Rendered();
        rendered.value = hash(bean.ssn);
        System.out.println(rendered);
    }

    static void recordRenderingPreservesSanitized() {
        Bean bean = new Bean();
        System.out.println(new SanitizedRecord(hash(bean.ssn)));
    }

    static void loggerSupplierPreservesSanitized() {
        Bean bean = new Bean();
        LOG.info(() -> hash(bean.ssn));
    }

    static void optionalCallbackPreservesSanitized() {
        Bean bean = new Bean();
        java.util.Optional.of(hash(bean.ssn)).ifPresent(System.out::println);
    }

    static void branchMergeBecomesUnsafe(boolean raw) {
        Bean bean = new Bean();
        String value = raw ? bean.ssn : hash(bean.ssn);
        System.out.println(value);
    }

    static void separateOriginsRemainSeparate() {
        Bean bean = new Bean();
        System.out.println(hash(bean.ssn) + ":" + bean.account);
    }

    static void ordinaryMethodIsUnsafe() {
        Bean bean = new Bean();
        System.out.println(passThrough(bean.ssn));
    }

    static void unsafeDominatesMixedValue() {
        Bean bean = new Bean();
        System.out.println(hash(bean.ssn) + ":" + bean.ssn);
    }

    static void sanitizerMayNotLeakInput() {
        Bean bean = new Bean();
        System.out.println(leakingSanitizer(bean.ssn));
    }

    static void untrackedValue() {
        System.out.println("ordinary");
    }
}
