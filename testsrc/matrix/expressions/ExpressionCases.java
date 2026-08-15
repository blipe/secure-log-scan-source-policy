package matrix.expressions;

import secure.Secure;

import java.util.Objects;
import java.util.StringJoiner;

public final class ExpressionCases {
    @Secure private static String stringSecret = "expression-secret";
    @Secure private static int intSecret = 73;
    @Secure private static long longSecret = 99L;
    @Secure private static byte[] bytesSecret = {1, 2, 3};

    private ExpressionCases() { }

    static void parenthesizedAssignment() {
        String value;
        System.out.println((value = stringSecret));
    }

    static void referenceCast() {
        Object value = stringSecret;
        System.out.println((String) value);
    }

    static void primitiveArithmetic() { System.out.println(intSecret + 1); }
    static void primitiveUnary() { System.out.println(-intSecret); }
    static void primitiveConversion() { System.out.println((double) longSecret); }
    static void compoundAssignment() {
        int value = intSecret;
        value += 2;
        System.out.println(value);
    }

    static void boxing() {
        Integer value = intSecret;
        System.out.println(value);
    }

    static void unboxing() {
        Integer value = intSecret;
        System.out.println(value.intValue());
    }

    static void objectArrayLoad() {
        Object[] values = {stringSecret};
        System.out.println(values[0]);
    }

    static void primitiveArrayRendering() { System.out.println(java.util.Arrays.toString(bytesSecret)); }

    static void stringConcat() { System.out.println("secret=" + stringSecret); }
    static void concatWithPrimitive() { System.out.println("secret=" + intSecret); }
    static void stringValueOf() { System.out.println(String.valueOf(stringSecret)); }
    static void objectsToString() { System.out.println(Objects.toString(stringSecret)); }
    static void stringFormat() { System.out.println(String.format("secret=%s", stringSecret)); }
    static void stringFormatted() { System.out.println("secret=%s".formatted(stringSecret)); }
    static void stringJoin() { System.out.println(String.join(",", "safe", stringSecret)); }

    static void stringBuilder() {
        StringBuilder builder = new StringBuilder("secret=");
        builder.append(stringSecret);
        System.out.println(builder);
    }

    static void stringBuffer() {
        StringBuffer buffer = new StringBuffer();
        buffer.append(stringSecret);
        System.out.println(buffer.toString());
    }

    static void stringJoiner() {
        StringJoiner joiner = new StringJoiner(",");
        joiner.add(stringSecret);
        System.out.println(joiner);
    }

    static void textBlockConcat() {
        String text = """
                token=%s
                """.formatted(stringSecret);
        System.out.println(text);
    }

    static void unknownTransformationIsConservative() {
        byte[] encoded = java.util.Base64.getEncoder().encode(stringSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.println(java.util.Base64.getEncoder().encodeToString(encoded));
    }

    static void safeLiteralExpression() { System.out.println("safe=" + 7); }
    static void safeClassObject() { System.out.println(ExpressionCases.class); }
    static void safeArrayIdentity() { System.out.println(new Object[]{stringSecret}); }
}
