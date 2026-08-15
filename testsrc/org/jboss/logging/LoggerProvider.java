package org.jboss.logging;

public interface LoggerProvider {
    Object putMdc(String key, Object value);
    void pushNdc(String value);
    Object removeMdc(String key);
    void clearNdc();
}
