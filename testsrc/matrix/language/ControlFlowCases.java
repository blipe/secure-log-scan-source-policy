package matrix.language;

import secure.Secure;

public final class ControlFlowCases {
    @Secure private static String secret = "control-secret";
    private static final Object LOCK = new Object();

    private ControlFlowCases() { }

    static void straightLine() {
        String value = secret;
        System.out.println(value);
    }

    static void ifElse() {
        String value;
        if (System.nanoTime() > 0) value = secret;
        else value = "safe";
        System.out.println(value);
    }

    static void conditionalExpression() {
        String value = System.nanoTime() > 0 ? secret : "safe";
        System.out.println(value);
    }

    static void switchStatement() {
        String value;
        switch ((int) System.nanoTime()) {
            case 1: value = secret; break;
            case 100: value = "safe"; break;
            default: value = "other";
        }
        System.out.println(value);
    }

    static void switchExpression() {
        String value = switch ((int) System.nanoTime()) {
            case 1 -> secret;
            case 2, 3 -> "safe";
            default -> {
                yield "other";
            }
        };
        System.out.println(value);
    }

    static void stringSwitch() {
        String value = switch (System.getProperty("matrix.mode", "secret")) {
            case "secret" -> secret;
            default -> "safe";
        };
        System.out.println(value);
    }

    static void classicForLoop() {
        String[] values = {"safe", secret};
        for (int i = 0; i < values.length; i++) System.out.println(values[i]);
    }

    static void enhancedForLoop() {
        String[] values = {"safe", secret};
        for (String value : values) System.out.println(value);
    }

    static void whileLoop() {
        String value = secret;
        int count = 0;
        while (count++ < 1) System.out.println(value);
    }

    static void doWhileLoop() {
        String value = secret;
        int count = 0;
        do {
            System.out.println(value);
        } while (count++ < 0);
    }

    static void labeledFlow() {
        String value = "safe";
        outer:
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                value = secret;
                break outer;
            }
        }
        System.out.println(value);
    }

    static void tryCatch() {
        String value = secret;
        try {
            if (System.nanoTime() == 0) throw new IllegalStateException();
        } catch (IllegalStateException ex) {
            value = "safe";
        }
        System.out.println(value);
    }

    static void tryFinally() {
        String value = secret;
        try {
            value = value.trim();
        } finally {
            System.out.println(value);
        }
    }

    static void tryWithResources() throws Exception {
        try (Resource ignored = new Resource()) {
            ignored.touch();
            System.out.println(secret);
        }
    }

    static void synchronizedBlock() {
        synchronized (LOCK) {
            System.out.println(secret);
        }
    }

    static void recursiveCall() {
        System.out.println(recurse(secret, 2));
    }

    private static String recurse(String value, int depth) {
        return depth == 0 ? value : recurse(value, depth - 1);
    }

    static void mutualRecursion() {
        System.out.println(even(secret, 2));
    }

    private static String even(String value, int depth) {
        return depth == 0 ? value : odd(value, depth - 1);
    }

    private static String odd(String value, int depth) {
        return depth == 0 ? value : even(value, depth - 1);
    }

    static void safeControlOnly() {
        if (System.nanoTime() > 0) System.out.println("safe-a");
        else System.out.println("safe-b");
    }

    static void safeNullAndTypeChecks() {
        Object value = new Object();
        if (value != null && value instanceof String) System.out.println("safe");
    }

    private static final class Resource implements AutoCloseable {
        void touch() { }
        @Override public void close() { }
    }
}
