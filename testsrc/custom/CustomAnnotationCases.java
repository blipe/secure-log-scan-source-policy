package custom;

public final class CustomAnnotationCases {
    @Confidential private static String secret = "custom-secret";
    private CustomAnnotationCases() { }
    static void configuredAnnotation() { System.out.println(secret); }
}
