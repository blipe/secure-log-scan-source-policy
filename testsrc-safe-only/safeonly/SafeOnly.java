package safeonly;

public final class SafeOnly {
    private SafeOnly() { }
    static void first() { System.out.println("safe"); }
    static String second() { return "safe"; }
}
