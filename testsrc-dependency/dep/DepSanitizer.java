package dep;

import secure.Sanitize;

public final class DepSanitizer {
    private DepSanitizer() {}

    @Sanitize(description = "Dependency mask", justification = "DEP-42")
    public static String mask(String value) {
        return "***" + value.substring(Math.max(0, value.length() - 2));
    }
}
