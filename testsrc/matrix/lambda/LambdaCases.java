package matrix.lambda;

import secure.Secure;

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class LambdaCases {
    @Secure private static String secret = "lambda-secret";
    private static final Logger JUL = Logger.getLogger("lambda");

    private LambdaCases() { }

    @FunctionalInterface interface Action { void run(); }
    @FunctionalInterface interface Sink<T> { void accept(T value); }
    @FunctionalInterface interface Source<T> { T get(); }
    @FunctionalInterface interface Mapper<T, R> { R apply(T value); }
    @FunctionalInterface interface PairSink<A, B> { void accept(A first, B second); }

    private static void invoke(Action action) { action.run(); }
    private static <T> void invokeSink(Sink<T> sink, T value) { sink.accept(value); }
    private static <T> T invokeSource(Source<T> source) { return source.get(); }
    private static <T, R> R invokeMapper(Mapper<T, R> mapper, T value) { return mapper.apply(value); }
    private static <A, B> void invokePair(PairSink<A, B> sink, A first, B second) { sink.accept(first, second); }

    static void capturingRunnableLambda() {
        String captured = secret;
        Action action = () -> System.out.println(captured);
        invoke(action);
    }

    static void parameterConsumerLambda() {
        invokeSink(value -> System.out.println(value), secret);
    }

    static void supplierLambdaReturn() {
        Source<String> source = () -> secret;
        System.out.println(invokeSource(source));
    }

    static void mapperLambdaReturn() {
        String mapped = invokeMapper(value -> value, secret);
        System.out.println(mapped);
    }

    static void blockLambda() {
        invokeSink(value -> {
            String copy = value.trim();
            System.out.println(copy);
        }, secret);
    }

    static void staticMethodReference() { invokeSink(LambdaCases::logValue, secret); }
    private static void logValue(String value) { System.out.println(value); }

    static final class Printer {
        void print(String value) { System.out.println(value); }
        String identity(String value) { return value; }
    }

    static void boundMethodReference() {
        Printer printer = new Printer();
        Sink<String> sink = printer::print;
        invokeSink(sink, secret);
    }

    static void unboundMethodReference() {
        PairSink<Printer, String> sink = Printer::print;
        invokePair(sink, new Printer(), secret);
    }

    static void boundReturningMethodReference() {
        Printer printer = new Printer();
        Mapper<String, String> mapper = printer::identity;
        System.out.println(invokeMapper(mapper, secret));
    }

    static final class SecretHolder {
        private final String value;
        SecretHolder(String value) { this.value = value; }
        String get() { return value; }
        @Override public String toString() { return "SecretHolder[" + value + "]"; }
    }

    static void getterMethodReference() {
        SecretHolder holder = new SecretHolder(secret);
        Source<String> source = holder::get;
        System.out.println(invokeSource(source));
    }

    static void constructorReference() {
        Mapper<String, SecretHolder> factory = SecretHolder::new;
        System.out.println(invokeMapper(factory, secret));
    }

    static void nestedLambda() {
        Source<Source<String>> outer = () -> () -> secret;
        System.out.println(invokeSource(invokeSource(outer)));
    }

    static void lambdaReturnedFromMethod() {
        System.out.println(invokeSource(makeSource(secret)));
    }
    private static Source<String> makeSource(String value) { return () -> value; }

    static void lambdaStoredInField() {
        CallbackHolder holder = new CallbackHolder();
        holder.action = value -> System.out.println(value);
        invokeSink(holder.action, secret);
    }
    static final class CallbackHolder { Sink<String> action; }

    static void julSupplierLambda() { JUL.log(Level.INFO, () -> secret); }

    static void jdkConsumerDirectInvocation() {
        Consumer<String> consumer = value -> System.out.println(value);
        consumer.accept(secret);
    }

    static void jdkSupplierDirectInvocation() {
        Supplier<String> supplier = () -> secret;
        System.out.println(supplier.get());
    }

    static void jdkFunctionDirectInvocation() {
        Function<String, String> function = value -> value;
        System.out.println(function.apply(secret));
    }

    static void jdkBiConsumerDirectInvocation() {
        BiConsumer<String, String> consumer = (first, second) -> System.out.println(second);
        consumer.accept("safe", secret);
    }


    static void iterableForEachLambda() {
        java.util.List.of(secret).forEach(value -> System.out.println(value));
    }

    static void optionalIfPresentLambda() {
        java.util.Optional.of(secret).ifPresent(value -> System.out.println(value));
    }

    static void streamForEachLambda() {
        java.util.stream.Stream.of(secret).forEach(value -> System.out.println(value));
    }

    static void mapForEachLambda() {
        java.util.Map.of("key", secret).forEach((key, value) -> System.out.println(value));
    }

    static void collectionRemoveIfLambda() {
        java.util.List<String> values = new java.util.ArrayList<>(java.util.List.of(secret));
        values.removeIf(value -> {
            System.out.println(value);
            return false;
        });
    }

    static void capturedThisLambda() {
        new InstanceOwner().invoke(secret);
    }
    static final class InstanceOwner {
        void invoke(String value) {
            Action action = () -> {
                touch();
                System.out.println(value);
            };
            action.run();
        }
        private void touch() { }
    }

    static void multipleCaptureLambda() {
        String first = "safe";
        String second = secret;
        long wide = 9L;
        Action action = () -> System.out.println(first + wide + second);
        action.run();
    }

    static void serializableIntersectionLambda() {
        String captured = secret;
        Action action = (Action & java.io.Serializable) () -> System.out.println(captured);
        action.run();
    }

    static void safeIterableCallbackIgnoresValue() {
        java.util.List.of(secret).forEach(value -> System.out.println("safe"));
    }

    static void safeLambdaNotInvoked() {
        Sink<String> sink = value -> System.out.println(value);
        String ignored = secret;
        System.out.println("safe");
    }

    static void safeLambdaIgnoresParameter() {
        invokeSink(value -> System.out.println("safe"), secret);
    }

    static void safeMethodReferenceTarget() {
        Sink<String> sink = LambdaCases::ignoreValue;
        invokeSink(sink, secret);
    }
    private static void ignoreValue(String ignored) { System.out.println("safe"); }
}
