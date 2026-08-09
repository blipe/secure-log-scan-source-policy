package exceptions;

import secure.Sanitize;
import secure.Secure;

import java.io.PrintWriter;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class ExceptionGraphCases {
    private static final Logger LOG = Logger.getLogger(ExceptionGraphCases.class.getName());

    static final class Bean {
        @Secure
        String ssn;

        Bean(String ssn) {
            this.ssn = ssn;
        }
    }

    static final class MessageException extends RuntimeException {
        private final String detail;

        MessageException(String detail) {
            this.detail = detail;
        }

        @Override
        public String getMessage() {
            return detail;
        }
    }

    static final class LocalizedException extends RuntimeException {
        private final String detail;

        LocalizedException(String detail) {
            this.detail = detail;
        }

        @Override
        public String getLocalizedMessage() {
            return detail;
        }
    }

    static final class TextException extends RuntimeException {
        private final String detail;

        TextException(String detail) {
            this.detail = detail;
        }

        @Override
        public String toString() {
            return "TextException[" + detail + "]";
        }
    }

    static final class HiddenException extends RuntimeException {
        @SuppressWarnings("unused")
        private final String detail;

        HiddenException(String detail) {
            super("constant");
            this.detail = detail;
        }
    }

    static final class Holder {
        Throwable throwable;
        CompletableFuture<String> stage;
    }

    @Sanitize(description = "Exception-safe masked value", justification = "EX-11")
    static String mask(String value) {
        return "***";
    }

    static void directMessage(Bean bean) {
        new RuntimeException(bean.ssn).printStackTrace();
    }

    static void causeConstructor(Bean bean) {
        new RuntimeException("outer", new RuntimeException(bean.ssn)).printStackTrace();
    }

    static void causeOnlyConstructor(Bean bean) {
        new RuntimeException(new RuntimeException(bean.ssn)).printStackTrace();
    }

    static void initCause(Bean bean) {
        RuntimeException root = new RuntimeException("outer");
        root.initCause(new RuntimeException(bean.ssn));
        root.printStackTrace();
    }

    static void suppressed(Bean bean) {
        RuntimeException root = new RuntimeException("outer");
        root.addSuppressed(new RuntimeException(bean.ssn));
        root.printStackTrace();
    }

    static void nestedSuppressedCause(Bean bean) {
        RuntimeException root = new RuntimeException("outer");
        root.addSuppressed(new RuntimeException("suppressed", new RuntimeException(bean.ssn)));
        root.printStackTrace();
    }

    static void directGetMessage(Bean bean) {
        System.out.println(new RuntimeException(bean.ssn).getMessage());
    }

    static void directGetLocalizedMessage(Bean bean) {
        System.out.println(new RuntimeException(bean.ssn).getLocalizedMessage());
    }

    static void getCauseMessage(Bean bean) {
        Throwable root = new RuntimeException("outer", new RuntimeException(bean.ssn));
        System.out.println(root.getCause().getMessage());
    }

    static void getSuppressedMessage(Bean bean) {
        Throwable root = new RuntimeException("outer");
        root.addSuppressed(new RuntimeException(bean.ssn));
        for (Throwable suppressed : root.getSuppressed()) {
            System.out.println(suppressed.getMessage());
        }
    }

    static void customGetMessage(Bean bean) {
        new MessageException(bean.ssn).printStackTrace();
    }

    static void customLocalizedMessage(Bean bean) {
        new LocalizedException(bean.ssn).printStackTrace();
    }

    static void customToString(Bean bean) {
        new TextException(bean.ssn).printStackTrace();
    }

    static void helperSuppressed(Bean bean) {
        RuntimeException root = new RuntimeException("outer");
        attachSuppressed(root, new RuntimeException(bean.ssn));
        root.printStackTrace();
    }

    static void helperCause(Bean bean) {
        RuntimeException root = new RuntimeException("outer");
        attachCause(root, new RuntimeException(bean.ssn));
        root.printStackTrace();
    }

    static void returnedException(Bean bean) {
        makeException(bean.ssn).printStackTrace();
    }

    static void fieldStoredException(Bean bean) {
        Holder holder = new Holder();
        holder.throwable = new RuntimeException(bean.ssn);
        holder.throwable.printStackTrace();
    }

    static void exceptionArray(Bean bean) {
        Throwable[] failures = {new RuntimeException(bean.ssn)};
        failures[0].printStackTrace();
    }

    static void julThrowableArgument(Bean bean) {
        LOG.log(Level.SEVERE, "failure", new RuntimeException(bean.ssn));
    }

    static void printStackTraceWriter(Bean bean, PrintWriter writer) {
        new RuntimeException(bean.ssn).printStackTrace(writer);
    }

    static void printStackTraceStream(Bean bean) {
        new RuntimeException(bean.ssn).printStackTrace(System.err);
    }

    static void failedFutureExceptionally(Bean bean) {
        CompletableFuture.<String>failedFuture(new RuntimeException(bean.ssn))
                .exceptionally(error -> {
                    error.printStackTrace();
                    return "recovered";
                });
    }

    static void failedFutureWhenComplete(Bean bean) {
        CompletableFuture.<String>failedFuture(new RuntimeException(bean.ssn))
                .whenComplete((value, error) -> error.printStackTrace());
    }

    static void failedFutureHandle(Bean bean) {
        CompletableFuture.<String>failedFuture(new RuntimeException(bean.ssn))
                .handle((value, error) -> {
                    error.printStackTrace();
                    return "recovered";
                });
    }

    static void failedFutureThroughThenApply(Bean bean) {
        CompletableFuture.<String>failedFuture(new RuntimeException(bean.ssn))
                .thenApply(String::trim)
                .exceptionally(error -> {
                    error.printStackTrace();
                    return "recovered";
                });
    }

    static void returnedFailedFuture(Bean bean) {
        failedStage(bean.ssn).exceptionally(error -> {
            error.printStackTrace();
            return "recovered";
        });
    }

    static void fieldStoredFailedFuture(Bean bean) {
        Holder holder = new Holder();
        holder.stage = CompletableFuture.failedFuture(new RuntimeException(bean.ssn));
        holder.stage.whenComplete((value, error) -> error.printStackTrace());
    }

    static void sanitizedMessage(Bean bean) {
        new RuntimeException(mask(bean.ssn)).printStackTrace();
    }

    static void sanitizedSuppressed(Bean bean) {
        RuntimeException root = new RuntimeException("outer");
        root.addSuppressed(new RuntimeException(mask(bean.ssn)));
        root.printStackTrace();
    }

    static void sanitizedFailedFuture(Bean bean) {
        CompletableFuture.<String>failedFuture(new RuntimeException(mask(bean.ssn)))
                .exceptionally(error -> {
                    error.printStackTrace();
                    return "recovered";
                });
    }

    static void untrackedException() {
        new RuntimeException("ordinary").printStackTrace();
    }

    static void hiddenFieldIsNotRendered(Bean bean) {
        new HiddenException(bean.ssn).printStackTrace();
    }

    static void messageOnlyHasNoCause(Bean bean) {
        Throwable cause = new RuntimeException(bean.ssn).getCause();
        if (cause != null) {
            cause.printStackTrace();
        }
    }

    static void completedFutureValueIsNotFailure(Bean bean) {
        CompletableFuture.completedFuture(bean.ssn)
                .whenComplete((value, error) -> {
                    if (error != null) {
                        error.printStackTrace();
                    }
                });
    }

    static void unusedFailureObject(Bean bean) {
        new RuntimeException(bean.ssn);
    }

    private static void attachSuppressed(Throwable root, Throwable suppressed) {
        root.addSuppressed(suppressed);
    }

    private static void attachCause(Throwable root, Throwable cause) {
        root.initCause(cause);
    }

    private static RuntimeException makeException(String value) {
        return new RuntimeException(value);
    }

    private static CompletableFuture<String> failedStage(String value) {
        return CompletableFuture.failedFuture(new RuntimeException(value));
    }
}
