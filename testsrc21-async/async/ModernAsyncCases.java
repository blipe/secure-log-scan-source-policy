package async;

import secure.Secure;

public final class ModernAsyncCases {
    @Secure private static String secret = "modern-async-secret";
    private ModernAsyncCases() { }

    static void startVirtualThread() throws InterruptedException {
        Thread thread = Thread.startVirtualThread(() -> System.out.println(secret));
        thread.join();
    }

    static void virtualBuilderStart() throws InterruptedException {
        Thread thread = Thread.ofVirtual().start(() -> System.out.println(secret));
        thread.join();
    }

    static void virtualBuilderUnstartedThenStart() throws InterruptedException {
        Thread thread = Thread.ofVirtual().unstarted(() -> System.out.println(secret));
        thread.start();
        thread.join();
    }
}
