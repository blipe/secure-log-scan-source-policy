package context;

import org.apache.logging.log4j.CloseableThreadContext;
import org.apache.logging.log4j.ThreadContext;
import org.slf4j.MDC;
import org.slf4j.spi.MDCAdapter;
import secure.Sanitize;
import secure.Secure;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

public final class MdcCases {
    static final class Bean {
        @Secure String ssn = "111-22-3333";
        @Secure String account = "account-7";

        @Override public String toString() {
            return "Bean[ssn=" + ssn + "]";
        }
    }

    @Sanitize(
        description = "Stable one-way diagnostic-context correlation value",
        justification = "Approved context sanitizer CTX-1"
    )
    static String sanitize(String value) {
        return "token-" + value.hashCode();
    }

    static void directMdcPut() {
        Bean bean = new Bean();
        MDC.put("ssn", bean.ssn);
    }

    static void secureMdcKey() {
        Bean bean = new Bean();
        MDC.put(bean.account, "value");
    }

    static void putCloseable() {
        Bean bean = new Bean();
        try (MDC.MDCCloseable ignored = MDC.putCloseable("ssn", bean.ssn)) {
            ignored.hashCode();
        }
    }

    static void setContextMapMutable() {
        Bean bean = new Bean();
        Map<String, String> values = new HashMap<>();
        values.put("ssn", bean.ssn);
        MDC.setContextMap(values);
    }

    static void setContextMapFactory() {
        Bean bean = new Bean();
        MDC.setContextMap(Map.of("ssn", bean.ssn));
    }

    static void pushByKey() {
        Bean bean = new Bean();
        MDC.pushByKey("ssn", bean.ssn);
    }

    static void adapterPut(MDCAdapter adapter) {
        Bean bean = new Bean();
        adapter.put("ssn", bean.ssn);
    }

    static void adapterSetContextMap(MDCAdapter adapter) {
        Bean bean = new Bean();
        adapter.setContextMap(Map.of("ssn", bean.ssn));
    }

    static void adapterPushByKey(MDCAdapter adapter) {
        Bean bean = new Bean();
        adapter.pushByKey("ssn", bean.ssn);
    }

    static void threadContextPut() {
        Bean bean = new Bean();
        ThreadContext.put("ssn", bean.ssn);
    }

    static void threadContextPutIfNull() {
        Bean bean = new Bean();
        ThreadContext.putIfNull("ssn", bean.ssn);
    }

    static void threadContextPutAll() {
        Bean bean = new Bean();
        ThreadContext.putAll(Map.of("ssn", bean.ssn));
    }

    static void threadContextPush() {
        Bean bean = new Bean();
        ThreadContext.push(bean.ssn);
    }

    static void threadContextFormattedPush() {
        Bean bean = new Bean();
        ThreadContext.push("ssn={}", bean.ssn);
    }

    static void threadContextPushAll() {
        Bean bean = new Bean();
        ThreadContext.pushAll(List.of(bean.ssn));
    }

    static void threadContextSetStack() {
        Bean bean = new Bean();
        List<String> values = new ArrayList<>();
        values.add(bean.ssn);
        ThreadContext.setStack(values);
    }

    static void closeableStaticPut() {
        Bean bean = new Bean();
        try (CloseableThreadContext.Instance ignored = CloseableThreadContext.put("ssn", bean.ssn)) {
            ignored.hashCode();
        }
    }

    static void closeableStaticPutAll() {
        Bean bean = new Bean();
        try (CloseableThreadContext.Instance ignored = CloseableThreadContext.putAll(Map.of("ssn", bean.ssn))) {
            ignored.hashCode();
        }
    }

    static void closeableStaticPush() {
        Bean bean = new Bean();
        try (CloseableThreadContext.Instance ignored = CloseableThreadContext.push("ssn={}", bean.ssn)) {
            ignored.hashCode();
        }
    }

    static void closeableInstanceChain() {
        Bean bean = new Bean();
        try (CloseableThreadContext.Instance ignored = CloseableThreadContext.put("safe", "value")
                .put("ssn", bean.ssn)
                .push(bean.account)) {
            ignored.hashCode();
        }
    }

    static void legacyMdcObjectRendering() {
        Bean bean = new Bean();
        org.apache.log4j.MDC.put("bean", bean);
    }

    static void legacyNdc() {
        Bean bean = new Bean();
        org.apache.log4j.NDC.push(bean.ssn);
    }

    static void jbossLoggingMdc() {
        Bean bean = new Bean();
        org.jboss.logging.MDC.put("bean", bean);
    }

    static void jbossLoggingNdc() {
        Bean bean = new Bean();
        org.jboss.logging.NDC.push(bean.ssn);
    }

    static void jbossLoggerProvider(org.jboss.logging.LoggerProvider provider) {
        Bean bean = new Bean();
        provider.putMdc("bean", bean);
        provider.pushNdc(bean.account);
    }

    static void jbossLogManagerMdc() {
        Bean bean = new Bean();
        org.jboss.logmanager.MDC.put("ssn", bean.ssn);
    }

    static void jbossLogManagerNdc() {
        Bean bean = new Bean();
        org.jboss.logmanager.NDC.push(bean.ssn);
    }

    static void jbossExtLogRecord(org.jboss.logmanager.ExtLogRecord record) {
        Bean bean = new Bean();
        record.putMdc("ssn", bean.ssn);
    }

    static void helper(String value) {
        MDC.put("ssn", value);
    }

    static void throughHelper() {
        Bean bean = new Bean();
        helper(bean.ssn);
    }

    static void lambdaCapture() {
        Bean bean = new Bean();
        String value = bean.ssn;
        Runnable capture = () -> MDC.put("ssn", value);
        capture.run();
    }

    static void methodReference() {
        Bean bean = new Bean();
        BiConsumer<String, String> capture = MDC::put;
        capture.accept("ssn", bean.ssn);
    }

    static void sanitizedMdcPut() {
        Bean bean = new Bean();
        MDC.put("ssnToken", sanitize(bean.ssn));
    }

    static void sanitizedThroughHelper() {
        Bean bean = new Bean();
        helper(sanitize(bean.ssn));
    }

    static void sanitizedContextMap() {
        Bean bean = new Bean();
        MDC.setContextMap(Map.of("ssnToken", sanitize(bean.ssn)));
    }

    static void sanitizedThreadContextStack() {
        Bean bean = new Bean();
        ThreadContext.pushAll(List.of(sanitize(bean.ssn)));
    }

    static void sanitizedMethodReference() {
        Bean bean = new Bean();
        BiConsumer<String, String> capture = MDC::put;
        capture.accept("ssnToken", sanitize(bean.ssn));
    }

    static void differentOriginsRemainSeparate() {
        Bean bean = new Bean();
        MDC.setContextMap(Map.of(
            "rawSsn", bean.ssn,
            "accountToken", sanitize(bean.account)
        ));
    }

    static void sameOriginUnsafeDominates() {
        Bean bean = new Bean();
        MDC.setContextMap(Map.of(
            "rawSsn", bean.ssn,
            "ssnToken", sanitize(bean.ssn)
        ));
    }

    static void captureThenClearStillFails() {
        Bean bean = new Bean();
        MDC.put("ssn", bean.ssn);
        MDC.clear();
    }

    static void clearAndRemoveAreNotCapture() {
        Bean bean = new Bean();
        MDC.remove(bean.ssn);
        MDC.clear();
        MDC.clearDequeByKey(bean.ssn);
        ThreadContext.remove(bean.ssn);
        ThreadContext.removeAll(List.of(bean.ssn));
        ThreadContext.clearAll();
        ThreadContext.clearMap();
        ThreadContext.clearStack();
        org.apache.log4j.MDC.remove(bean.ssn);
        org.apache.log4j.MDC.clear();
        org.apache.log4j.NDC.clear();
        org.apache.log4j.NDC.remove();
    }

    static void uninvokedLambdaIsNotCapture() {
        Bean bean = new Bean();
        String value = bean.ssn;
        Runnable capture = () -> MDC.put("ssn", value);
        if (capture == null) throw new AssertionError();
    }

    static void jbossClearRemoveAreNotCapture(org.jboss.logging.LoggerProvider provider,
                                               org.jboss.logmanager.ExtLogRecord record) {
        Bean bean = new Bean();
        org.jboss.logging.MDC.remove(bean.ssn);
        org.jboss.logging.MDC.clear();
        org.jboss.logging.NDC.clear();
        org.jboss.logmanager.MDC.remove(bean.ssn);
        org.jboss.logmanager.MDC.clear();
        org.jboss.logmanager.NDC.clear();
        provider.removeMdc(bean.ssn);
        provider.clearNdc();
        record.removeMdc(bean.ssn);
    }

    static void possibleUnknownContextCapture() {
        Bean bean = new Bean();
        String encoded = java.util.Base64.getEncoder().encodeToString(
                bean.ssn.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MDC.put("ssn", encoded);
    }

    static void untrackedContext() {
        MDC.put("requestId", "req-1");
        ThreadContext.put("requestId", "req-1");
    }
}
