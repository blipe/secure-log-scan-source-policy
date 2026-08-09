package org.apache.logging.log4j;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public final class ThreadContext {
    private ThreadContext() {}
    public static void put(String key, String value) {}
    public static void putIfNull(String key, String value) {}
    public static void putAll(Map<String, String> values) {}
    public static void push(String value) {}
    public static void push(String pattern, Object... values) {}
    public static void pushAll(List<String> values) {}
    public static void setStack(Collection<String> values) {}
    public static void remove(String key) {}
    public static void removeAll(Iterable<String> keys) {}
    public static void clearAll() {}
    public static void clearMap() {}
    public static void clearStack() {}
}
