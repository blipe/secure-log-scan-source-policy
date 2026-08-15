package possibleonly;

import secure.Secure;

public final class PossibleOnly {
    @Secure private static final String SECRET = "possible-only-secret";

    private PossibleOnly() { }

    static void inlinedConstant() {
        System.out.println(SECRET);
    }

    static void identicalLiteralWithoutFieldReference() {
        System.out.println("possible-only-secret");
    }

    static void unknownTransformation() {
        byte[] encoded = java.util.Base64.getEncoder().encode(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.println(java.util.Base64.getEncoder().encodeToString(encoded));
    }
}
