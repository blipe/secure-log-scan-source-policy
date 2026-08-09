package matrix.types;

import secure.Secure;

public final class ConstantInliningCases {
    private ConstantInliningCases() { }

    static final class Constants {
        @Secure static final String STRING_SECRET = "cross-class-constant";
        @Secure static final int INT_SECRET = 2048;
        private Constants() { }
    }

    static void crossClassStringConstant() { System.out.println(Constants.STRING_SECRET); }
    static void crossClassPrimitiveConstant() { System.out.println(Constants.INT_SECRET); }
}
