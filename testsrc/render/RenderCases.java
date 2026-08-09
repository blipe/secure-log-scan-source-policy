package render;

import secure.Secure;
import java.util.*;
import java.util.logging.Level;

public class RenderCases {
    static final java.util.logging.Logger JUL = java.util.logging.Logger.getLogger("test");
    static final Logger LOG = new Logger();

    static final class Logger {
        void info(String pattern, Object value) { }
        void info(String pattern, Object... values) { }
    }

    static class Customer {
        @Secure String ssn;
        Customer(String ssn) { this.ssn = ssn; }
        @Override public String toString() { return "Customer[ssn=" + ssn + "]"; }
    }

    record Credential(@Secure String token) { }
    record Envelope(Customer customer) { }

    static class Holder { Object value; List<Object> items; }
    static class Safe {
        final String value;
        Safe(String value) { this.value = value; }
        @Override public String toString() { return "Safe[" + value + "]"; }
    }

    static void directObject() {
        Customer c = new Customer("111");
        System.out.println(c);
    }

    static void placeholderObject() {
        Customer c = new Customer("111");
        LOG.info("customer={}", c);
    }

    static void julPlaceholderObject() {
        Customer c = new Customer("111");
        JUL.log(Level.INFO, "customer={0}", c);
    }

    static void logUnknown(Object value) {
        LOG.info("value={}", value);
    }

    static void throughObjectHelper() {
        logUnknown(new Customer("111"));
    }

    static void recordRendering() {
        System.out.println(new Credential("token"));
    }

    static void nestedRecordRendering() {
        System.out.println(new Envelope(new Customer("111")));
    }

    static void collectionRendering() {
        List<Object> values = new ArrayList<>();
        values.add(new Customer("111"));
        LOG.info("values={}", values);
    }

    static void collectionThroughField() {
        Holder h = new Holder();
        h.items = new ArrayList<>();
        h.items.add(new Customer("111"));
        LOG.info("items={}", h.items);
    }

    static void objectFieldRendering() {
        Holder h = new Holder();
        h.value = new Customer("111");
        LOG.info("value={}", h.value);
    }

    static void arrayRendering() {
        Object[] values = {new Customer("111")};
        LOG.info("values={}", values);
    }

    static void builderRendering() {
        StringBuilder b = new StringBuilder();
        b.append(new Customer("111"));
        JUL.info(b.toString());
    }

    static void supplierRendering() {
        Customer c = new Customer("111");
        JUL.log(Level.INFO, () -> c.ssn);
    }

    static void throwableRendering() {
        Customer c = new Customer("111");
        RuntimeException ex = new RuntimeException(c.ssn);
        ex.printStackTrace();
    }

    static void safeHashCode() {
        Customer c = new Customer("111");
        System.out.println(c.hashCode());
    }

    static void safeCollectionSize() {
        List<Object> values = new ArrayList<>();
        values.add(new Customer("111"));
        System.out.println(values.size());
    }

    static void safeObject() {
        System.out.println(new Safe("ok"));
    }
}
