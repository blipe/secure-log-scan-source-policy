package dep;

import secure.Secure;

public final class DepLeak {
    @Secure("DEPENDENCY_SECRET")
    static String secret = "dependency-secret";

    public static void leakInsideDependency() {
        System.out.println(secret);
    }
}
