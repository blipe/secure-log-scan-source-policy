package matrix.logging;

import secure.Secure;

import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class LoggingIdiomsCases {
    @Secure private static String secret = "logging-secret";
    private static final Logger JUL = Logger.getLogger("matrix");
    private static final AppLogger APP = new AppLogger();
    private static final System.Logger SYSTEM_LOGGER = System.getLogger("matrix-system");

    private LoggingIdiomsCases() { }

    static final class AppLogger {
        void trace(String message) { }
        void debug(String message) { }
        void info(String message) { }
        void info(String pattern, Object value) { }
        void warn(String pattern, Object... values) { }
        void error(String message, Throwable throwable) { }
        EventBuilder atInfo() { return new EventBuilder(); }
    }

    static final class EventBuilder {
        EventBuilder addArgument(Object value) { return this; }
        EventBuilder addKeyValue(String key, Object value) { return this; }
        void log(String message) { }
        void log(String message, Object... values) { }
    }

    static void print() { System.out.print(secret); }
    static void println() { System.out.println(secret); }
    static void printf() { System.out.printf("secret=%s%n", secret); }
    static void format() { System.out.format("secret=%s%n", secret); }
    static void append() { System.out.append(secret); }

    static void printWriter() {
        PrintWriter writer = new PrintWriter(System.out);
        writer.println(secret);
        writer.flush();
    }

    static void julConvenience() { JUL.warning(secret); }
    static void julLogMessage() { JUL.log(Level.INFO, secret); }
    static void julSingleParameter() { JUL.log(Level.INFO, "secret={0}", secret); }
    static void julParameterArray() { JUL.log(Level.INFO, "secret={0}", new Object[]{secret}); }
    static void julLogp() { JUL.logp(Level.INFO, "Source", "method", secret); }
    static void julLogrb() {
        JUL.logrb(Level.INFO, "Source", "method", (java.util.ResourceBundle) null, secret);
    }

    static void appDirect() { APP.info(secret); }
    static void appPlaceholder() { APP.info("secret={}", secret); }
    static void appVarargs() { APP.warn("a={} b={}", "safe", secret); }

    static void fluentArgument() {
        APP.atInfo().addArgument(secret).log("secret={}");
    }

    static void fluentKeyValue() {
        APP.atInfo().addKeyValue("secret", secret).log("message");
    }

    static void fluentLogArgument() {
        APP.atInfo().log("secret={}", secret);
    }

    static void throwableArgument() {
        APP.error("failure", new IllegalStateException(secret));
    }

    static void explicitStringConcat() { APP.info("secret=" + secret); }
    static void stringFormat() { APP.info(String.format("secret=%s", secret)); }
    static void stringFormatted() { APP.info("secret=%s".formatted(secret)); }


    static void systemLoggerMessage() { SYSTEM_LOGGER.log(System.Logger.Level.INFO, secret); }
    static void systemLoggerPlaceholder() { SYSTEM_LOGGER.log(System.Logger.Level.INFO, "secret={0}", secret); }
    static void systemLoggerSupplier() { SYSTEM_LOGGER.log(System.Logger.Level.INFO, () -> secret); }

    static void safeLoggerLiteral() { APP.info("safe"); }
    static void safeFluentLiteral() { APP.atInfo().addArgument("safe").log("value={}"); }
}
