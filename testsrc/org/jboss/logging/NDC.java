package org.jboss.logging;

public final class NDC {
    private NDC() {}
    public static void push(String value) {}
    public static String pop() { return null; }
    public static void clear() {}
}
