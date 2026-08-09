package analysis;

import secure.Secure;

public final class LongChainCases {
    @Secure private static String secret = "long-chain-secret";

    private LongChainCases() { }

    static void leakThroughSixtyCalls() { System.out.println(m1()); }

    static String m1() { return m2(); }
    static String m2() { return m3(); }
    static String m3() { return m4(); }
    static String m4() { return m5(); }
    static String m5() { return m6(); }
    static String m6() { return m7(); }
    static String m7() { return m8(); }
    static String m8() { return m9(); }
    static String m9() { return m10(); }
    static String m10() { return m11(); }
    static String m11() { return m12(); }
    static String m12() { return m13(); }
    static String m13() { return m14(); }
    static String m14() { return m15(); }
    static String m15() { return m16(); }
    static String m16() { return m17(); }
    static String m17() { return m18(); }
    static String m18() { return m19(); }
    static String m19() { return m20(); }
    static String m20() { return m21(); }
    static String m21() { return m22(); }
    static String m22() { return m23(); }
    static String m23() { return m24(); }
    static String m24() { return m25(); }
    static String m25() { return m26(); }
    static String m26() { return m27(); }
    static String m27() { return m28(); }
    static String m28() { return m29(); }
    static String m29() { return m30(); }
    static String m30() { return m31(); }
    static String m31() { return m32(); }
    static String m32() { return m33(); }
    static String m33() { return m34(); }
    static String m34() { return m35(); }
    static String m35() { return m36(); }
    static String m36() { return m37(); }
    static String m37() { return m38(); }
    static String m38() { return m39(); }
    static String m39() { return m40(); }
    static String m40() { return m41(); }
    static String m41() { return m42(); }
    static String m42() { return m43(); }
    static String m43() { return m44(); }
    static String m44() { return m45(); }
    static String m45() { return m46(); }
    static String m46() { return m47(); }
    static String m47() { return m48(); }
    static String m48() { return m49(); }
    static String m49() { return m50(); }
    static String m50() { return m51(); }
    static String m51() { return m52(); }
    static String m52() { return m53(); }
    static String m53() { return m54(); }
    static String m54() { return m55(); }
    static String m55() { return m56(); }
    static String m56() { return m57(); }
    static String m57() { return m58(); }
    static String m58() { return m59(); }
    static String m59() { return m60(); }
    static String m60() { return secret; }
}
