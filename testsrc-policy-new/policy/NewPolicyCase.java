package policy;

import secure.Secure;

public final class NewPolicyCase {
    @Secure String value = "new";
    void newlyIntroducedFinding() {
        System.out.println(value);
    }
}
