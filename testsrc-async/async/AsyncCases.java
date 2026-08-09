package async;

import external.Registry;
import secure.Sanitize;
import secure.Secure;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public final class AsyncCases {
    @Secure private static String secret = "async-secret";
    private static final Logger LOG = new Logger();

    private AsyncCases() { }

    static final class Logger {
        void info(String value) { }
        LoggingEventBuilder atInfo() { return new LoggingEventBuilder(); }
    }

    static final class LoggingEventBuilder {
        LoggingEventBuilder addArgument(Object value) { return this; }
        LoggingEventBuilder addArgument(Supplier<?> value) { return this; }
        LoggingEventBuilder addKeyValue(String key, Object value) { return this; }
        LoggingEventBuilder addKeyValue(String key, Supplier<?> value) { return this; }
        void log(String message) { }
    }

    @Sanitize(description = "masked", justification = "test")
    static String sanitize(String value) { return "***" + value.length(); }

    static void executorExecute(Executor executor) {
        String captured = secret;
        executor.execute(() -> LOG.info(captured));
    }


    private static void dispatch(Executor executor, Runnable callback) {
        executor.execute(callback);
    }

    static void executorThroughHelper(Executor executor) {
        String captured = secret;
        dispatch(executor, () -> LOG.info(captured));
    }

    private static <T> CompletionStage<T> transform(CompletionStage<T> stage,
                                                     java.util.function.Function<T, T> mapper) {
        return stage.thenApply(mapper);
    }

    static void completionStageThroughHelper() {
        transform(CompletableFuture.completedStage(secret), value -> value)
                .thenAccept(LOG::info);
    }

    static void executorSubmitRunnable(ExecutorService executor) {
        String captured = secret;
        executor.submit(() -> LOG.info(captured));
    }

    static void executorSubmitCallable(ExecutorService executor) {
        String captured = secret;
        executor.submit(() -> {
            LOG.info(captured);
            return captured.length();
        });
    }

    static void scheduledExecute(ScheduledExecutorService executor) {
        String captured = secret;
        executor.schedule(() -> LOG.info(captured), 1, TimeUnit.SECONDS);
    }

    static void scheduledAtFixedRate(ScheduledExecutorService executor) {
        String captured = secret;
        executor.scheduleAtFixedRate(() -> LOG.info(captured), 0, 1, TimeUnit.SECONDS);
    }

    static void threadConstructorStart() {
        String captured = secret;
        Thread thread = new Thread(() -> LOG.info(captured));
        thread.start();
    }

    static void threadFactoryStart(ThreadFactory factory) {
        String captured = secret;
        Thread thread = factory.newThread(() -> LOG.info(captured));
        thread.start();
    }

    static void completableRunAsync() {
        String captured = secret;
        CompletableFuture.runAsync(() -> LOG.info(captured));
    }

    static void completableSupplyAsync() {
        String captured = secret;
        CompletableFuture.supplyAsync(() -> {
            LOG.info(captured);
            return captured;
        });
    }

    static void completableThenAccept() {
        CompletableFuture.completedFuture(secret)
                .thenAccept(LOG::info);
    }

    static void completableThenApplyThenAccept() {
        CompletableFuture.completedFuture(secret)
                .thenApply(value -> value)
                .thenAccept(LOG::info);
    }

    static void completionStageWhenComplete() {
        CompletionStage<String> stage = CompletableFuture.completedStage(secret);
        stage.whenComplete((value, failure) -> LOG.info(value));
    }

    static void completionStageHandleThenAccept() {
        CompletionStage<String> stage = CompletableFuture.completedStage(secret);
        stage.handle((value, failure) -> value)
                .thenAccept(LOG::info);
    }

    static void forkJoinExecute(ForkJoinPool pool) {
        String captured = secret;
        pool.execute(() -> LOG.info(captured));
    }

    static void invokeAllCallbacks(ExecutorService executor) throws InterruptedException {
        String captured = secret;
        List<Callable<Integer>> tasks = List.of(
                () -> { LOG.info(captured); return 1; },
                () -> 2);
        executor.invokeAll(tasks);
    }


    private static void lazyLog(Supplier<?> supplier) {
        LOG.atInfo().addArgument(supplier).log("value={}");
    }

    static void fluentSupplierThroughHelper() {
        lazyLog(() -> secret);
    }

    static void sanitizedFluentSupplierThroughHelper() {
        lazyLog(() -> sanitize(secret));
    }

    static void fluentSupplierArgument() {
        LOG.atInfo().addArgument(() -> secret).log("secret={}");
    }

    static void fluentSupplierKeyValue() {
        LOG.atInfo().addKeyValue("secret", () -> secret).log("message");
    }

    static void nestedAsync() {
        String captured = secret;
        CompletableFuture.runAsync(() ->
                CompletableFuture.runAsync(() -> LOG.info(captured)));
    }

    static void callbackStoredInFieldThenExecuted(Executor executor) {
        Holder holder = new Holder();
        String captured = secret;
        holder.task = () -> LOG.info(captured);
        executor.execute(holder.task);
    }

    static final class Holder { Runnable task; }

    static void sanitizedAcrossAsync(Executor executor) {
        String value = sanitize(secret);
        executor.execute(() -> LOG.info(value));
    }

    static void sanitizedCompletableChain() {
        CompletableFuture.completedFuture(secret)
                .thenApply(AsyncCases::sanitize)
                .thenAccept(LOG::info);
    }

    static void sanitizedFluentSupplier() {
        LOG.atInfo().addArgument(() -> sanitize(secret)).log("secret={}");
    }

    static void unknownCallbackEscape(Registry registry) {
        String captured = secret;
        registry.register(() -> LOG.info(captured));
    }

    static void unknownSupplierEscape(Registry registry) {
        String captured = secret;
        registry.registerSupplier(() -> {
            LOG.info(captured);
            return captured;
        });
    }

    static void unknownSanitizedCallbackEscape(Registry registry) {
        String value = sanitize(secret);
        registry.register(() -> LOG.info(value));
    }

    static void safeUnusedDirectFieldLambda() {
        Runnable unused = () -> LOG.info(secret);
        LOG.info("safe");
    }

    static void safeUnusedCapturedLambda() {
        String captured = secret;
        Runnable unused = () -> LOG.info(captured);
        LOG.info("safe");
    }

    static void safeThreadNeverStarted() {
        String captured = secret;
        Thread unused = new Thread(() -> LOG.info(captured));
        LOG.info("safe");
    }

    static void safeExecutorCallbackIgnoresCapture(Executor executor) {
        String captured = secret;
        executor.execute(() -> LOG.info("safe"));
        if (captured.isEmpty()) LOG.info("safe");
    }

    static void safeUnknownCallbackHasNoSink(Registry registry) {
        String captured = secret;
        registry.register(() -> captured.length());
    }

    static void safeFluentSupplier() {
        LOG.atInfo().addArgument(() -> "safe").log("value={}");
    }
}
