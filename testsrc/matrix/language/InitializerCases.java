package matrix.language;

import secure.Secure;

public final class InitializerCases {
    @Secure private static String staticSecret = "static-initializer";
    @Secure private String instanceSecret = "instance-initializer";

    static {
        System.out.println(staticSecret);
    }

    {
        System.out.println(instanceSecret);
    }

    InitializerCases() { }

    static void constructorInvocation() {
        new ConstructorLogger(staticSecret);
    }

    static final class ConstructorLogger {
        ConstructorLogger(String value) { System.out.println(value); }
    }
}
