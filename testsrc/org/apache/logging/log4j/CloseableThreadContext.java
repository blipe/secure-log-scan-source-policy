package org.apache.logging.log4j;

import java.util.List;
import java.util.Map;

public final class CloseableThreadContext {
    private CloseableThreadContext() {}
    public static Instance put(String key, String value) { return new Instance(); }
    public static Instance putAll(Map<String, String> values) { return new Instance(); }
    public static Instance push(String value) { return new Instance(); }
    public static Instance push(String pattern, Object... values) { return new Instance(); }
    public static Instance pushAll(List<String> values) { return new Instance(); }

    public static final class Instance implements AutoCloseable {
        public Instance put(String key, String value) { return this; }
        public Instance putAll(Map<String, String> values) { return this; }
        public Instance push(String value) { return this; }
        public Instance push(String pattern, Object... values) { return this; }
        public Instance pushAll(List<String> values) { return this; }
        @Override public void close() {}
    }
}
