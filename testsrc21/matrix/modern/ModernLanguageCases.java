package matrix.modern;

import secure.Secure;

public final class ModernLanguageCases {
    @Secure private static String secret = "modern-secret";

    private ModernLanguageCases() { }

    record Token(@Secure String value) { }
    sealed interface Message permits TextMessage, EmptyMessage { }
    record TextMessage(@Secure String text) implements Message { }
    record EmptyMessage() implements Message { }

    static void instanceofPattern() {
        Object value = new Token(secret);
        if (value instanceof Token token) System.out.println(token.value());
    }

    static void recordPattern() {
        Object value = new Token(secret);
        if (value instanceof Token(String token)) System.out.println(token);
    }

    static void patternSwitch() {
        Message message = new TextMessage(secret);
        String value = switch (message) {
            case TextMessage(String text) -> text;
            case EmptyMessage ignored -> "safe";
        };
        System.out.println(value);
    }

    static void nullPatternSwitch() {
        Object value = new Token(secret);
        String rendered = switch (value) {
            case null -> "safe";
            case Token(String token) -> token;
            default -> "other";
        };
        System.out.println(rendered);
    }

    static void safePatternTypeOnly() {
        Object value = new Object();
        if (value instanceof Token) System.out.println("safe");
    }
}
