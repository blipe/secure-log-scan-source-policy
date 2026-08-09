package matrix.types;

import secure.Secure;

import java.io.Serializable;

public class TypeStructureCases {
    @Secure private static final String STATIC_FINAL_SECRET = "static-final";
    @Secure private volatile String volatileSecret = "volatile";
    @Secure private transient String transientSecret = "transient";
    @Secure private int primitiveSecret = 42;
    @Secure private char[] charArraySecret = {'s', 'e', 'c'};

    static void staticFinalField() { System.out.println(STATIC_FINAL_SECRET); }
    void volatileField() { System.out.println(volatileSecret); }
    void transientField() { System.out.println(transientSecret); }
    void primitiveField() { System.out.println(primitiveSecret); }
    void charArrayField() { System.out.println(charArraySecret); }

    static final class StaticNested {
        @Secure String value = "nested";
        @Override public String toString() { return "StaticNested[" + value + "]"; }
    }

    final class Inner {
        @Secure String value = "inner";
        @Override public String toString() { return "Inner[" + value + "]"; }
    }

    static void staticNestedClass() { System.out.println(new StaticNested()); }
    void innerClass() { System.out.println(new Inner()); }

    static void localClass() {
        class Local {
            @Secure String value = "local";
            @Override public String toString() { return "Local[" + value + "]"; }
        }
        System.out.println(new Local());
    }

    static void anonymousClass() {
        Object value = new Object() {
            @Secure String secret = "anonymous";
            @Override public String toString() { return "Anonymous[" + secret + "]"; }
        };
        System.out.println(value);
    }

    interface Renderable {
        String value();
        default String render() { return "Renderable[" + value() + "]"; }
    }

    static final class RenderableImpl implements Renderable {
        @Secure String secret = "interface";
        @Override public String value() { return secret; }
    }

    static void interfaceDefaultMethod() {
        Renderable value = new RenderableImpl();
        System.out.println(value.render());
    }

    abstract static class AbstractValue {
        abstract String value();
        @Override public String toString() { return "Abstract[" + value() + "]"; }
    }

    static final class ConcreteValue extends AbstractValue {
        @Secure String secret = "abstract";
        @Override String value() { return secret; }
    }

    static void abstractDispatch() { System.out.println(new ConcreteValue()); }

    sealed interface SealedValue permits SealedImpl { String value(); }
    static final class SealedImpl implements SealedValue {
        @Secure String secret = "sealed";
        @Override public String value() { return secret; }
        @Override public String toString() { return "Sealed[" + value() + "]"; }
    }

    static void sealedType() {
        SealedValue value = new SealedImpl();
        System.out.println(value);
    }

    record SecureRecord(@Secure String token) { }
    static void recordType() { System.out.println(new SecureRecord("record")); }

    enum SecureEnum {
        VALUE("enum-secret");
        @Secure private final String code;
        SecureEnum(String code) { this.code = code; }
        @Override public String toString() { return "SecureEnum[" + code + "]"; }
    }

    static void enumType() { System.out.println(SecureEnum.VALUE); }

    static final class Box<T> {
        final T value;
        Box(T value) { this.value = value; }
        @Override public String toString() { return "Box[" + value + "]"; }
    }

    static final class SecretValue implements Serializable {
        @Secure String value = "generic";
        @Override public String toString() { return "SecretValue[" + value + "]"; }
    }

    static void genericType() { System.out.println(new Box<>(new SecretValue())); }

    interface Provider<T> { T get(); }
    static final class SecretProvider implements Provider<SecretValue> {
        private final SecretValue value = new SecretValue();
        @Override public SecretValue get() { return value; }
    }

    static void genericBridgeMethod() {
        Provider<SecretValue> provider = new SecretProvider();
        System.out.println(provider.get());
    }

    static void multidimensionalArray() {
        String[][] values = {{STATIC_FINAL_SECRET}};
        System.out.println(values[0][0]);
    }

    static void safeClassLiteral() { System.out.println(SecretValue.class); }
    static void safeEnumName() { System.out.println(SecureEnum.VALUE.name()); }
    static void safeRecordHashCode() { System.out.println(new SecureRecord("record").hashCode()); }
}
