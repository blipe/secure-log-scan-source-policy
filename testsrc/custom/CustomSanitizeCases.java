package custom;

import secure.Secure;

public final class CustomSanitizeCases {
    @Secure private static String secret = "custom-sanitizer";

    @Cleansed(
            description = "Configured sanitizer annotation",
            justification = "CUSTOM-7"
    )
    static String clean(String value) {
        return Integer.toHexString(value.hashCode());
    }

    static void configuredSanitizer() {
        System.out.println(clean(secret));
    }
}
