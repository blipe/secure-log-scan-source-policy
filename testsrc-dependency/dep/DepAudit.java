package dep;

public final class DepAudit {
    private DepAudit() {}

    public static void log(String value) {
        System.out.println(value);
    }
}
