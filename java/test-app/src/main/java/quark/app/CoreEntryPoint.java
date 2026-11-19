package quark.app;

import quark.sdk.QuarkCheckpoint;
import quark.sdk.QuarkProtected;

/**
 * Minimal protected application for end-to-end testing. Stands in for the real
 * main-app: Bootstrap loads {@code quark.app.CoreEntryPoint} by name, so this
 * class MUST keep that exact fully-qualified name (see
 * {@code Bootstrap.CORE_ENTRY_POINT}).
 *
 * <p>quark-protect injects checkpoint tokens into the annotated methods;
 * if core_enc_key is wrong the class never loads, so this code never runs.
 */
@QuarkProtected
public final class CoreEntryPoint {

    @QuarkCheckpoint(id = 0x0001)
    public long multiply(int a, int b) {
        return (long) a * b;
    }

    @QuarkCheckpoint(id = 0x0002)
    public String greet(String name) {
        return "Hello, " + name + "!";
    }

    public static void start(String[] args) {
        CoreEntryPoint app = new CoreEntryPoint();

        // Call checkpoint-protected methods. multiply() returns 6*7=42 XOR-ed with
        // an HMAC token injected by quark-protect -- the exact numeric value is
        // intentionally blinded and must not be compared to a known constant here.
        // The security property is: wrong content_key → wrong token → wrong XOR →
        // wrong downstream computation (not detectable as a simple boolean failure).
        long blindedProduct = app.multiply(6, 7);
        String greeting = app.greet("Quark");

        System.out.println("[test-app] multiply(6,7) = " + blindedProduct + " (XOR-blinded by checkpoint)");
        System.out.println("[test-app] greet = " + greeting);

        // String methods are not XOR-blinded (quark-protect only XORs int/long returns).
        if (!greeting.equals("Hello, Quark!")) {
            System.err.println("[test-app] FAIL: greet result corrupted");
            Runtime.getRuntime().halt(2);
        }

        // Use the blinded product in a downstream computation (demonstrates the
        // anti-tamper property: patch checkpoint to 0 and this feeds wrong data
        // into whatever real business logic sits here).
        long downstream = blindedProduct ^ (blindedProduct >>> 32);
        System.out.println("[test-app] downstream value = " + downstream);

        System.out.println("[test-app] PASS");
    }
}
