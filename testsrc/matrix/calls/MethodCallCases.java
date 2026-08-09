package matrix.calls;

import secure.Secure;

public final class MethodCallCases {
    @Secure private static String secret = "call-secret";

    private MethodCallCases() { }

    static void staticCall() { logStatic(secret); }
    private static void logStatic(String value) { System.out.println(value); }

    static void virtualCall() { new VirtualLogger().log(secret); }
    static class VirtualLogger { void log(String value) { System.out.println(value); } }

    static void finalCall() { new FinalLogger().log(secret); }
    static final class FinalLogger { final void log(String value) { System.out.println(value); } }

    static void privateCall() { new PrivateLogger().entry(secret); }
    static final class PrivateLogger {
        void entry(String value) { log(value); }
        private void log(String value) { System.out.println(value); }
    }

    interface LoggerContract { void log(String value); }
    static final class LoggerImpl implements LoggerContract {
        @Override public void log(String value) { System.out.println(value); }
    }
    static void interfaceCall() { LoggerContract logger = new LoggerImpl(); logger.log(secret); }

    interface DefaultLogger {
        default void log(String value) { System.out.println(value); }
    }
    static final class DefaultLoggerImpl implements DefaultLogger { }
    static void defaultInterfaceCall() { new DefaultLoggerImpl().log(secret); }

    static class BaseLogger { void log(String value) { System.out.println(value); } }
    static final class ChildLogger extends BaseLogger {
        void callSuper(String value) { super.log(value); }
    }
    static void superCall() { new ChildLogger().callSuper(secret); }

    static void overloadedCall() { overloaded(secret); }
    private static void overloaded(int safe) { System.out.println(safe); }
    private static void overloaded(String value) { System.out.println(value); }

    static void varargsCall() { varargs("prefix", 1, secret); }
    private static void varargs(String prefix, Object... values) {
        System.out.printf(prefix + "%s%n", values);
    }

    static void genericMethodCall() { System.out.println(identity(secret)); }
    private static <T> T identity(T value) { return value; }

    static void boundedGenericCall() { System.out.println(bounded(secret)); }
    private static <T extends CharSequence> T bounded(T value) { return value; }

    static void wideSlotArguments() { logWide(1L, 2.0d, secret); }
    private static void logWide(long first, double second, String value) { System.out.println(value); }

    static void constructorThenGetter() { System.out.println(new Holder(secret).get()); }
    static final class Holder {
        private String value;
        Holder(String value) { this.value = value; }
        String get() { return value; }
        Holder set(String value) { this.value = value; return this; }
    }

    static void setterThenGetter() {
        Holder holder = new Holder("safe");
        holder.set(secret);
        System.out.println(holder.get());
    }

    static void fluentChain() { System.out.println(new Holder("safe").set(secret).get()); }

    static void factoryReturn() { System.out.println(create(secret).get()); }
    private static Holder create(String value) { return new Holder(value); }

    static void parameterReordering() { reorder("safe", secret); }
    private static void reorder(String first, String second) { logStatic(second); }

    static void objectParameterRendering() { renderObject(new Rendered(secret)); }
    private static void renderObject(Object value) { System.out.println(value); }
    static final class Rendered {
        private final String value;
        Rendered(String value) { this.value = value; }
        @Override public String toString() { return "Rendered[" + value + "]"; }
    }

    static void recursiveSinkSummary() { recursiveLog(secret, 1); }
    private static void recursiveLog(String value, int depth) {
        if (depth == 0) System.out.println(value);
        else recursiveLog(value, depth - 1);
    }

    static void mutualSinkSummary() { mutualA(secret, 1); }
    private static void mutualA(String value, int depth) {
        if (depth == 0) System.out.println(value);
        else mutualB(value, depth - 1);
    }
    private static void mutualB(String value, int depth) { mutualA(value, depth - 1); }

    static void covariantBridgeCall() {
        ValueProvider provider = new StringValueProvider();
        System.out.println(provider.value());
    }
    interface ValueProvider { Object value(); }
    static final class StringValueProvider implements ValueProvider {
        @Override public String value() { return secret; }
    }


    interface PrivateInterfaceLogger {
        default void entry(String value) { privateLog(value); }
        private void privateLog(String value) { System.out.println(value); }
        static void staticLog(String value) { System.out.println(value); }
    }
    static final class PrivateInterfaceLoggerImpl implements PrivateInterfaceLogger { }
    static void privateInterfaceCall() { new PrivateInterfaceLoggerImpl().entry(secret); }
    static void staticInterfaceCall() { PrivateInterfaceLogger.staticLog(secret); }

    static synchronized void synchronizedMethodCall() { logStatic(secret); }

    static void safeOverloadSelection() { overloaded(7); }
    static void safeUnusedArgument() { ignore(secret, "safe"); }
    private static void ignore(String ignored, String logged) { System.out.println(logged); }
}
