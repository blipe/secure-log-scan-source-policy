package models;

import java.util.function.Consumer;
import java.util.function.Function;

public final class ExternalApis {
    private ExternalApis() {}

    public static void audit(Object value) {}

    public static void context(String key, Object value) {}

    public static String serialize(Object value) {
        return "external";
    }

    public static void dispatch(Runnable callback) {}

    public static <T> void consume(T value, Consumer<T> callback) {}

    public static <T, R> R transform(T value, Function<T, R> callback) {
        return null;
    }

    public static void fill(Box target, Object value) {}

    public static String mask(String value) {
        return value;
    }

    public static void directOnly(Object value) {}

    public static final class Box {
        public void addExternal(Object value) {}

        @Override
        public String toString() {
            return "Box";
        }
    }
}
