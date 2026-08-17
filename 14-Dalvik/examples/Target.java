// examples/Target.java
//
// The source the labs build, disassemble and patch.
//
// WHY IT LOOKS LIKE THIS
//     Every method here exists to produce a specific bytecode shape you are
//     meant to recognise. The comment above each one names the shape. There is
//     deliberately NO Android dependency, so you can compile and dex it with
//     nothing but a JDK and the Android build-tools -- no Gradle, no emulator,
//     no project.
//
// BUILD IT AND DISASSEMBLE IT
//     # host -- javac, then d8, then baksmali. Three commands, no project.
//     javac -d classes/ Target.java
//     d8 --release --output . classes/com/example/tour/*.class
//     baksmali d classes.dex -o smali/
//     less smali/com/example/tour/Target.smali
//
//     `d8` ships in Android SDK build-tools. `--release` matters: a debug build
//     adds .line and .local directives everywhere and roughly doubles the
//     listing length. Build both and diff them once -- it is instructive.
//
// COMPARE AGAINST JVM BYTECODE
//     javap -c -p classes/com/example/tour/Target.class
//
//     Put javap's output beside baksmali's for sum() and count the instructions
//     in each. That comparison is README section 2.3, and doing it yourself is
//     worth more than reading it.

package com.example.tour;

public class Target {

    // ---------------------------------------------------------------------
    // Shape: sget-boolean / if-eqz. A field-backed gate -- the simplest thing
    // a patch can defeat, and extremely common in real applications.
    // ---------------------------------------------------------------------
    private static boolean premium = false;

    // Shape: a fill-array-data payload. THIS is where hardcoded keys live, and
    // `strings` will never find it because the bytes are not text.
    private static final byte[] KEY = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
        (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c
    };

    // Shape: const-string, sitting in the class's encoded_array as a
    // compile-time constant. Greppable, and the first thing anyone looks for.
    private static final String ENDPOINT = "https://api.example.com/v1/";

    private final Object lock = new Object();
    private boolean open = true;

    // ---------------------------------------------------------------------
    // Shape: const-string + invoke-virtual String.equals + move-result +
    //        return. The canonical two-line patch target.
    // Lab 02 patch #1: make this always return true.
    // ---------------------------------------------------------------------
    public static boolean checkPin(String pin) {
        return "1337".equals(pin);
    }

    // ---------------------------------------------------------------------
    // Shape: sget-boolean + return. Even simpler than checkPin.
    // Lab 02 patch #2.
    // ---------------------------------------------------------------------
    public static boolean isPremium() {
        return premium;
    }

    // ---------------------------------------------------------------------
    // Shape: the loop from README section 2.3. Compare this method's Smali
    // against `javap -c` on the same method -- 9 instructions against 18, at
    // the same total byte count. That comparison IS the register-machine
    // argument.
    // ---------------------------------------------------------------------
    static int sum(int[] a) {
        int t = 0;
        for (int i = 0; i < a.length; i++) {
            t += a[i];
        }
        return t;
    }

    // ---------------------------------------------------------------------
    // Shape: arithmetic in every form -- add-int, mul-int/lit8,
    // add-int/lit16, xor-int/2addr, ushr-int/lit8.
    // ---------------------------------------------------------------------
    public static int mix(int a, int b) {
        int r = a * 31;
        r = r ^ b;
        r = r + 1000;
        r = r >>> 8;
        return 100 - r;               // becomes rsub-int, not sub-int
    }

    // ---------------------------------------------------------------------
    // Shape: WIDE VALUES. A long occupies two adjacent registers and two p
    // numbers. Work out the frame on paper before you look at the Smali.
    //   static, ins_size = 2 (one long) -- so p0 is the low half and there is
    //   no p1 you can name on its own.
    // ---------------------------------------------------------------------
    public static long expiry(long base) {
        return base + 86400L;
    }

    // ---------------------------------------------------------------------
    // Shape: the frame example from README section 9.2.
    //   instance + String + long + String = ins_size 5.
    //   With .registers 9 the mapping is p0=v4 p1=v5 p2=v6 p3=v7 p4=v8.
    //   The SECOND String is p4, not p3.
    // ---------------------------------------------------------------------
    public boolean transfer(String to, long amount, String memo) {
        if (amount <= 0) {
            return false;
        }
        if (!open) {
            return false;
        }
        return to.length() > 0 && memo != null;
    }

    // ---------------------------------------------------------------------
    // Shape: new-array + fill-array-data + an .array-data payload of width 1.
    // Lab 02 asks you to find this payload with grep, not with strings.
    // ---------------------------------------------------------------------
    public static byte[] key() {
        return KEY.clone();
    }

    // ---------------------------------------------------------------------
    // Shape: packed-switch, with a DENSE key set, and a default that is
    // fall-through rather than a payload entry.
    // ---------------------------------------------------------------------
    public static String route(int code) {
        if (code < 0) {
            return "negative";
        }
        switch (code) {
            case 0: return "zero";
            case 1: return "one";
            case 2: return "two";
            default: return "many";
        }
    }

    // ---------------------------------------------------------------------
    // Shape: sparse-switch, because the keys are scattered. Keys in the
    // payload are sorted ascending so the runtime can binary-search them.
    // ---------------------------------------------------------------------
    public static String status(int http) {
        switch (http) {
            case 200: return "ok";
            case 404: return "not found";
            case 500: return "server error";
            default: return "unknown";
        }
    }

    // ---------------------------------------------------------------------
    // Shape: TWO switches. A switch on a String compiles to a sparse-switch on
    // hashCode(), then String.equals() to resolve hash collisions, then a
    // packed-switch on the resulting index. The const-string values in the
    // first stage are your actual case labels.
    // ---------------------------------------------------------------------
    public static int role(String name) {
        switch (name) {
            case "admin": return 3;
            case "staff": return 2;
            case "user":  return 1;
            default:      return 0;
        }
    }

    // ---------------------------------------------------------------------
    // Shape: try / catch / finally. The finally body appears MORE THAN ONCE in
    // the Smali -- once on the normal path and once inside a .catchall handler
    // that rethrows. That duplication is the compiler, not obfuscation.
    // ---------------------------------------------------------------------
    public static int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        } finally {
            trace("parse done");
        }
    }

    // ---------------------------------------------------------------------
    // Shape: monitor-enter / monitor-exit, plus a .catchall that also exits
    // the monitor so the lock is released on the exception path.
    // ---------------------------------------------------------------------
    public int bump(int[] counter) {
        synchronized (lock) {
            counter[0] = counter[0] + 1;
            return counter[0];
        }
    }

    // ---------------------------------------------------------------------
    // Shape: the StringBuilder chain. Every `+` on strings becomes
    // new-instance StringBuilder / invoke-direct <init> / a run of append()
    // calls each followed by move-result-object / toString().
    //
    // On a recent toolchain with a high minSdk this may instead compile to a
    // single invoke-custom. Which one you get tells you about the build
    // configuration, so check.
    // ---------------------------------------------------------------------
    public static String label(String user, int n) {
        return "user=" + user + ":" + n + "@" + ENDPOINT;
    }

    // ---------------------------------------------------------------------
    // Shape: instance-of + check-cast. Note that check-cast validates and does
    // NOT write a register -- it exists so the verifier can narrow the type.
    // ---------------------------------------------------------------------
    public static String describe(Object o) {
        if (o instanceof String) {
            String s = (String) o;
            return "string:" + s.length();
        }
        return "other";
    }

    // ---------------------------------------------------------------------
    // Shape: a method with more than five argument WORDS, forcing the
    // /range invoke form at every call site. Count words, not parameters:
    // three longs is six words.
    // ---------------------------------------------------------------------
    public static long wide6(long a, long b, long c) {
        return a + b + c;
    }

    public static long callWide() {
        return wide6(1L, 2L, 3L);       // becomes invoke-static/range
    }

    // ---------------------------------------------------------------------
    // Shape: an ENUM. Compiles to a class extending java.lang.Enum with a
    // synthetic static [L...; field named $VALUES, built in <clinit>.
    // ---------------------------------------------------------------------
    public enum Tier {
        FREE, PLUS, PRO
    }

    public static int tierRank(Tier t) {
        switch (t) {
            case PRO:  return 3;
            case PLUS: return 2;
            default:   return 1;
        }
    }

    // ---------------------------------------------------------------------
    // Shape: an inner class touching the outer class's private field. The
    // compiler generates a `synthetic static` bridge named access$NNN, whose
    // whole body is one sget/sput and a return.
    // ---------------------------------------------------------------------
    static final class Inner {
        boolean peek() {
            return premium;             // reaches the outer private via a bridge
        }
        void grant() {
            premium = true;
        }
    }

    // ---------------------------------------------------------------------
    // Shape: a LAMBDA. Depending on the toolchain and minSdk this becomes
    // either a synthetic class implementing the functional interface, or an
    // invoke-custom with LambdaMetafactory as the bootstrap. Either way the
    // body ends up in a synthetic private static method named
    // lambda$makeChecker$0 or similar.
    // ---------------------------------------------------------------------
    public interface Check {
        boolean test(String s);
    }

    public static Check makeChecker() {
        return s -> s != null && s.length() >= 4;
    }

    // ---------------------------------------------------------------------
    // Shape: GENERICS ARE ERASED. The Smali signature is
    // (Ljava/util/List;)Ljava/lang/Object; -- the `<T>` survives only in a
    // system annotation, Ldalvik/annotation/Signature;. Look for it.
    // ---------------------------------------------------------------------
    public static <T> T firstOf(java.util.List<T> list) {
        return list.isEmpty() ? null : list.get(0);
    }

    // ---------------------------------------------------------------------
    // Shape: a plain private static helper, reached by invoke-direct. Seeing
    // invoke-direct on something that is not <init> tells you the target is
    // private, with no other evidence needed.
    // ---------------------------------------------------------------------
    private static void trace(String msg) {
        System.out.println("[TARGET] " + msg);
    }

    // ---------------------------------------------------------------------
    // A main() so the class is runnable on a desktop JVM. Lab 01 uses this to
    // confirm behaviour before and after a patch, without a device.
    // ---------------------------------------------------------------------
    public static void main(String[] args) {
        System.out.println("checkPin(\"1337\")  = " + checkPin("1337"));
        System.out.println("checkPin(\"0000\")  = " + checkPin("0000"));
        System.out.println("isPremium()       = " + isPremium());
        System.out.println("sum([1,2,3,4])    = " + sum(new int[] {1, 2, 3, 4}));
        System.out.println("mix(7, 11)        = " + mix(7, 11));
        System.out.println("expiry(0)         = " + expiry(0L));
        System.out.println("route(1)          = " + route(1));
        System.out.println("status(404)       = " + status(404));
        System.out.println("role(\"staff\")     = " + role("staff"));
        System.out.println("parse(\"x\")        = " + parse("x"));
        System.out.println("label(\"bob\", 9)   = " + label("bob", 9));
        System.out.println("describe(\"hi\")    = " + describe("hi"));
        System.out.println("callWide()        = " + callWide());
        System.out.println("tierRank(PRO)     = " + tierRank(Tier.PRO));
        System.out.println("key().length      = " + key().length);
        System.out.println("checker(\"abcd\")   = " + makeChecker().test("abcd"));
        Target t = new Target();
        System.out.println("transfer(...)     = " + t.transfer("acct", 100L, "memo"));
        System.out.println("bump()            = " + t.bump(new int[] {0}));
    }
}
