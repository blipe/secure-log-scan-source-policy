package org.slf4j;

import java.util.Map;

public final class MDC {
    private MDC() {}
    public static void put(String key, String value) {}
    public static MDCCloseable putCloseable(String key, String value) { return new MDCCloseable(); }
    public static void setContextMap(Map<String, String> values) {}
    public static void pushByKey(String key, String value) {}
    public static void remove(String key) {}
    public static void clear() {}
    public static void clearDequeByKey(String key) {}
    public static final class MDCCloseable implements AutoCloseable {
        @Override public void close() {}
    }
}
