package org.slf4j.spi;

import java.util.Map;

public interface MDCAdapter {
    void put(String key, String value);
    void setContextMap(Map<String, String> values);
    void pushByKey(String key, String value);
    void remove(String key);
    void clear();
    void clearDequeByKey(String key);
}
