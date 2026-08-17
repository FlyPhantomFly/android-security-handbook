/*
 * ReflectionDemo.java
 * ===================
 *
 * WHAT THIS DOES
 * --------------
 * Demonstrates, end to end, every reflection construct a reverse engineer meets in Android
 * applications, and annotates each one with the exact artefact it leaves behind in JADX output
 * and in Smali. It covers:
 *
 *   1. Ordinary, non-reflective access, as a baseline for comparison.
 *   2. Class.forName with a plain literal name.
 *   3. getDeclaredField + setAccessible(true) reading a private field.
 *   4. getDeclaredMethod + setAccessible(true) invoking a private method.
 *   5. getDeclaredConstructor + newInstance building an object whose constructor is private.
 *   6. Reading a private STATIC field, which needs a null receiver.
 *   7. A deliberately obfuscated lookup: the class name is Base64-encoded and the method name is
 *      built by character arithmetic, so neither appears in the string table.
 *   8. What happens when you forget setAccessible(true).
 *   9. InvocationTargetException unwrapping, which is the single most common reflection mistake.
 *
 * Companion material:
 *   ../labs/lab-03-reflection-hunt.md   - the CTF that makes you find item 7 from Smali alone
 *   ../scripts/find-reflection.sh       - greps an APK for every fingerprint listed below
 *   ../cheatsheet.md                    - section 8, the reflection API table
 *
 * HOW TO RUN
 * ----------
 *   Single file, no compilation step, JDK 11 or newer:
 *
 *       # host
 *       java ReflectionDemo.java
 *
 *   Or compile first, which is what you want if you then intend to feed it to d8 and jadx:
 *
 *       # host
 *       javac -g ReflectionDemo.java
 *       java ReflectionDemo
 *       javap -c -p ReflectionDemo.class | less
 *
 *   To see the DEX form referenced in the comments below:
 *
 *       # host
 *       d8 --min-api 21 *.class --output .
 *       baksmali d classes.dex -o smali_out
 *       grep -rn 'forName\|setAccessible\|reflect/Method;->invoke' smali_out/
 *
 * Requires JDK 17+ (tested on 17, 21 and 24). No external dependencies.
 */

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class ReflectionDemo {

    public static void main(String[] args) throws Exception {
        section("0. Baseline: ordinary access, no reflection");
        baseline();

        section("1. Class.forName with a literal name");
        forNameLiteral();

        section("2. Reading a private instance field");
        readPrivateField();

        section("3. Invoking a private instance method");
        invokePrivateMethod();

        section("4. Constructing an object whose constructor is private");
        usePrivateConstructor();

        section("5. Reading a private static field");
        readPrivateStaticField();

        section("6. Enumerating everything a class declares");
        enumerateMembers();

        section("7. Obfuscated lookup: encoded class name, computed method name");
        obfuscatedLookup();

        section("8. What happens without setAccessible(true)");
        withoutSetAccessible();

        section("9. Unwrapping InvocationTargetException");
        unwrapTargetException();

        section("Done");
        System.out.println("Now run: javap -c -p ReflectionDemo.class");
        System.out.println("and compare each method against the comments in the source.");
    }

    // ------------------------------------------------------------------------------------------
    // 0. BASELINE
    // ------------------------------------------------------------------------------------------
    /*
     * This is what a normal call looks like, and it is the thing everything below is hiding from.
     *
     * IN JADX:  vault.publicHint()          -- exactly as written, fully readable
     * IN SMALI: invoke-virtual {v0}, LSecretVault;->publicHint()Ljava/lang/String;
     *
     * The callee's fully qualified name, its parameter types, and its return type are all baked
     * into the single instruction. A cross-reference search in JADX finds every caller instantly.
     * That is precisely the property an author using reflection is trying to destroy.
     */
    private static void baseline() {
        SecretVault vault = SecretVault.create("baseline-token");
        System.out.println("direct call    -> " + vault.publicHint());
    }

    // ------------------------------------------------------------------------------------------
    // 1. Class.forName WITH A LITERAL
    // ------------------------------------------------------------------------------------------
    /*
     * The least-hidden form of reflection. The class name is a string literal, so it lands in the
     * DEX string table and grep finds it immediately.
     *
     * IN JADX:  Class<?> cls = Class.forName("SecretVault");
     * IN SMALI: const-string v0, "SecretVault"
     *           invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
     *           move-result-object v0
     *
     * TRIAGE RULE: when the register feeding forName was loaded by const-string, you are done in
     * one step. When it was loaded by move-result-object, the name is computed and you must read
     * the method that produced it. See section 7.
     *
     * NOTE ON SIDE EFFECTS: the single-argument forName INITIALISES the class, meaning it runs
     * <clinit>. Malware relies on this: merely "looking up" a class can execute code. The
     * three-argument overload lets you pass initialize=false to suppress that, and its Smali
     * signature is forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;
     */
    private static void forNameLiteral() throws Exception {
        Class<?> cls = Class.forName("SecretVault");
        System.out.println("resolved class -> " + cls.getName());
        System.out.println("simple name    -> " + cls.getSimpleName());
        System.out.println("class loader   -> " + cls.getClassLoader());
        // On Android this final line prints a dalvik.system.PathClassLoader, and seeing a
        // dalvik.system.DexClassLoader or InMemoryDexClassLoader here instead means code was
        // loaded from outside the original APK. That is always worth investigating.
    }

    // ------------------------------------------------------------------------------------------
    // 2. READING A PRIVATE INSTANCE FIELD
    // ------------------------------------------------------------------------------------------
    /*
     * SecretVault.token is declared private. The language forbids reading it from here. Reflection
     * does it anyway in three lines. This is the concrete demonstration of the claim made
     * throughout this chapter: `private` is a compile-time contract, not a security boundary.
     *
     * IN JADX:  Field f = cls.getDeclaredField("token");
     *           f.setAccessible(true);
     *           Object v = f.get(vault);
     *
     * IN SMALI: const-string v1, "token"
     *           invoke-virtual {v0, v1}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
     *           move-result-object v1
     *           const/4 v2, 0x1
     *           invoke-virtual {v1, v2}, Ljava/lang/reflect/Field;->setAccessible(Z)V
     *           invoke-virtual {v1, v3}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
     *
     * GREP FINGERPRINT: Ljava/lang/reflect/Field;->setAccessible(Z)V
     * Note that in DEX the owner type printed is the concrete class (Field or Method), even though
     * setAccessible is inherited from AccessibleObject. Grep for the bare name so that both the
     * Field and Method owners are caught, and so that an AccessibleObject owner is caught too:
     *     grep -rn 'setAccessible' smali_out/
     *
     * getDeclaredField vs getField:
     *   getDeclaredField - any field DECLARED on this exact class, including private ones,
     *                      but NOT inherited fields.
     *   getField         - public fields only, including inherited ones.
     * Seeing getDeclaredField is therefore mild evidence on its own that the target is non-public.
     */
    private static void readPrivateField() throws Exception {
        SecretVault vault = SecretVault.create("tok_live_9f3a2b");

        Class<?> cls = vault.getClass();
        Field tokenField = cls.getDeclaredField("token");

        System.out.println("field modifiers -> " + Modifier.toString(tokenField.getModifiers()));
        System.out.println("field type      -> " + tokenField.getType().getName());

        tokenField.setAccessible(true);              // the access check is now disabled
        Object value = tokenField.get(vault);        // vault is the receiver; null for static

        System.out.println("private token   -> " + value);

        // Writing works exactly the same way, and works even on a final field on most
        // configurations. There is no runtime that makes `private final` tamper-proof against
        // code running inside the same process.
        tokenField.set(vault, "overwritten-by-reflection");
        System.out.println("after write     -> " + vault.publicHint());
    }

    // ------------------------------------------------------------------------------------------
    // 3. INVOKING A PRIVATE INSTANCE METHOD
    // ------------------------------------------------------------------------------------------
    /*
     * IN JADX:  Method m = cls.getDeclaredMethod("derive", String.class, int.class);
     *           m.setAccessible(true);
     *           Object r = m.invoke(vault, "seed", 3);
     *
     * IN SMALI (the parameter-types array is the part beginners misread):
     *           const/4 v2, 0x2
     *           new-array v3, v2, [Ljava/lang/Class;
     *           const/4 v4, 0x0
     *           const-class v5, Ljava/lang/String;          # String.class
     *           aput-object v5, v3, v4
     *           const/4 v4, 0x1
     *           sget-object v5, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;   # int.class
     *           aput-object v5, v3, v4
     *           invoke-virtual {v0, v1, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
     *
     * HOW TO READ THE SIGNATURE OUT OF SMALI WITHOUT THE SOURCE:
     *   - const-class Ljava/lang/String;   means a String parameter.
     *   - sget-object Ljava/lang/Integer;->TYPE  means a primitive int parameter.
     *     Every primitive has such a TYPE constant: Integer.TYPE, Long.TYPE, Boolean.TYPE,
     *     Character.TYPE, Byte.TYPE, Short.TYPE, Float.TYPE, Double.TYPE, Void.TYPE.
     *     Confusing Integer.class with Integer.TYPE is the classic reflection bug: they are
     *     different Class objects and only one of them matches an `int` parameter.
     *   - The array length tells you the arity.
     *   - At the invoke site, a null receiver means the method is static.
     */
    private static void invokePrivateMethod() throws Exception {
        SecretVault vault = SecretVault.create("tok_live_9f3a2b");

        Method derive = SecretVault.class.getDeclaredMethod("derive", String.class, int.class);
        derive.setAccessible(true);

        // Autoboxing: the int literal 3 becomes Integer.valueOf(3) because invoke takes Object[].
        Object result = derive.invoke(vault, "salt", 3);

        System.out.println("private derive  -> " + result);
        System.out.println("return type     -> " + derive.getReturnType().getName());
        System.out.println("param types     -> " + Arrays.toString(derive.getParameterTypes()));
    }

    // ------------------------------------------------------------------------------------------
    // 4. PRIVATE CONSTRUCTOR
    // ------------------------------------------------------------------------------------------
    /*
     * A private constructor is the standard way to enforce "you must use the factory method" or
     * "this is a singleton". Reflection ignores both intentions.
     *
     * IN SMALI: invoke-virtual {v0, v1}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;
     *           invoke-virtual {v2, v3}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;
     *
     * SECURITY CONSEQUENCE: singletons enforced only by a private constructor can be duplicated.
     * If a class caches an authorisation decision in a singleton, an attacker inside the process
     * can build a second instance with different state. The defensive pattern is to throw from the
     * constructor when an instance already exists, or to use an enum singleton, which the runtime
     * itself refuses to instantiate reflectively.
     */
    private static void usePrivateConstructor() throws Exception {
        Constructor<SecretVault> ctor = SecretVault.class.getDeclaredConstructor(String.class);
        System.out.println("ctor modifiers  -> " + Modifier.toString(ctor.getModifiers()));

        ctor.setAccessible(true);
        SecretVault forged = ctor.newInstance("forged-instance");

        System.out.println("forged object   -> " + forged.publicHint());
        System.out.println("same class?     -> " + (forged.getClass() == SecretVault.class));
    }

    // ------------------------------------------------------------------------------------------
    // 5. PRIVATE STATIC FIELD
    // ------------------------------------------------------------------------------------------
    /*
     * The only difference from section 2 is the receiver: static members are read with a null
     * receiver, because there is no instance.
     *
     * IN SMALI: const/4 v2, 0x0
     *           invoke-virtual {v1, v2}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
     *                                ^^ the null receiver
     *
     * WHERE THIS MATTERS: static fields are where apps cache decisions. `private static boolean
     * sIsRooted`, `private static String sSessionToken`, `private static long sLicenceExpiry`.
     * All are readable, and all are writable, by anything running in the process. This is exactly
     * what Frida and Xposed do when they "bypass" a root check: they are not breaking cryptography,
     * they are writing a boolean.
     */
    private static void readPrivateStaticField() throws Exception {
        Field counter = SecretVault.class.getDeclaredField("instanceCount");
        counter.setAccessible(true);

        System.out.println("static count    -> " + counter.get(null));   // null receiver

        counter.set(null, 9999);
        System.out.println("after tamper    -> " + counter.get(null));
        System.out.println("class agrees?   -> " + SecretVault.reportCount());
    }

    // ------------------------------------------------------------------------------------------
    // 6. ENUMERATION
    // ------------------------------------------------------------------------------------------
    /*
     * getDeclaredFields and getDeclaredMethods return everything, including synthetic members the
     * compiler generated. This is how you discover a class's real surface at runtime, and it is
     * also how you spot compiler artefacts described in ../cheatsheet.md section 10.
     *
     * On Android, calling these on framework classes triggers the hidden-API restrictions
     * introduced in API 28: non-SDK members are blocklisted or greylisted, and access is logged or
     * denied. Apps that want hidden APIs anyway use "double reflection" - reflecting on
     * Class.getDeclaredMethod itself - so that the caller appears to be the platform. Seeing
     * reflection used to call reflection is a strong signal of deliberate restriction bypass.
     */
    private static void enumerateMembers() {
        System.out.println("fields:");
        for (Field f : SecretVault.class.getDeclaredFields()) {
            System.out.printf("  %-10s %-20s %s%s%n",
                    Modifier.toString(f.getModifiers()),
                    f.getType().getSimpleName(),
                    f.getName(),
                    f.isSynthetic() ? "   <- SYNTHETIC, compiler generated" : "");
        }
        System.out.println("methods:");
        for (Method m : SecretVault.class.getDeclaredMethods()) {
            System.out.printf("  %-10s %-20s %s%s%n",
                    Modifier.toString(m.getModifiers()),
                    m.getReturnType().getSimpleName(),
                    m.getName(),
                    m.isSynthetic() ? "   <- SYNTHETIC" : "");
        }
    }

    // ------------------------------------------------------------------------------------------
    // 7. THE OBFUSCATED LOOKUP
    // ------------------------------------------------------------------------------------------
    /*
     * This is the interesting one, and it is the subject of ../labs/lab-03-reflection-hunt.md.
     *
     * Neither the class name nor the method name appears anywhere in the compiled artefact as a
     * readable string. Confirm that for yourself after compiling:
     *
     *     # host
     *     javap -v -p ReflectionDemo.class | grep '= String'
     *
     * You will see the Base64 blob, but you will NOT see the decoded class name and you will NOT
     * see the method name.
     *
     * IN JADX the shape is unmistakable even though the names are gone:
     *
     *     Class<?> cls = Class.forName(new String(Base64.getDecoder().decode("U2VjcmV0VmF1bHQ="),
     *                                             StandardCharsets.UTF_8));
     *     char[] cArr = {'c', 'n', 'l', 'q', 'n', 'j'};   // or similar
     *     ... loop applying arithmetic ...
     *     Method m = cls.getDeclaredMethod(new String(cArr), int.class);
     *     m.setAccessible(true);
     *     m.invoke(null, 24301);
     *
     * IN SMALI the fingerprint to grep for is the CO-LOCATION of these five:
     *
     *     Ljava/util/Base64$Decoder;->decode(     (Android: Landroid/util/Base64;->decode()
     *     Ljava/lang/Class;->forName(
     *     Ljava/lang/Class;->getDeclaredMethod(
     *     Ljava/lang/reflect/Method;->setAccessible(Z)V
     *     Ljava/lang/reflect/Method;->invoke(
     *
     * Any one alone is unremarkable. All five inside one method is intent.
     *
     * WHY THIS DOES NOT ACTUALLY WORK AS PROTECTION: the runtime demands a plaintext class name.
     * Whatever transformation the author applies must be undone before Class.forName is called.
     * A single Frida hook on Class.forName prints the answer regardless of the encoding scheme.
     * Obfuscation raises your cost; it does not move the boundary at which plaintext must exist.
     */
    private static void obfuscatedLookup() throws Exception {
        // Step 1: the class name, hidden as Base64. Decodes to "SecretVault".
        String hiddenClass = new String(
                Base64.getDecoder().decode("U2VjcmV0VmF1bHQ="),
                StandardCharsets.UTF_8);

        // Step 2: the method name, built by character arithmetic. The constants in the compiled
        // code are the values BEFORE the shift, so the readable name never exists as a literal
        // anywhere in the class file or the DEX string table. Work out what it spells from the
        // code rather than from a comment - that is exactly the exercise lab 03 sets.
        char[] nameChars = { 'c', 'l', 'j', 'g', 'q', 'r' };
        for (int i = 0; i < nameChars.length; i++) {
            nameChars[i] = (char) (nameChars[i] + 2);
        }
        String hiddenMethod = new String(nameChars);

        // Step 3: resolve and call, with the access check disabled.
        Class<?> cls = Class.forName(hiddenClass);
        Method m = cls.getDeclaredMethod(hiddenMethod, int.class);
        m.setAccessible(true);
        Object out = m.invoke(null, 0x5eed);     // null receiver: the target is static

        System.out.println("hidden class    -> " + hiddenClass);
        System.out.println("hidden method   -> " + hiddenMethod);
        System.out.println("hidden result   -> " + out);
    }

    // ------------------------------------------------------------------------------------------
    // 8. FORGETTING setAccessible(true)
    // ------------------------------------------------------------------------------------------
    /*
     * Without setAccessible(true) the access check runs and throws IllegalAccessException. This is
     * why setAccessible is such a reliable grep target: any reflective access to a non-public
     * member must call it, so its presence is not optional decoration.
     *
     * IN SMALI you would see getDeclaredField followed directly by Field;->get with no
     * setAccessible(Z)V in between, and a .catch for IllegalAccessException.
     */
    private static void withoutSetAccessible() {
        try {
            Field f = SecretVault.class.getDeclaredField("token");
            // Deliberately NOT calling f.setAccessible(true).
            Object v = f.get(SecretVault.create("never-read"));
            System.out.println("unexpectedly read -> " + v);
        } catch (IllegalAccessException e) {
            System.out.println("IllegalAccessException, as expected:");
            System.out.println("  " + e.getMessage());
        } catch (NoSuchFieldException e) {
            System.out.println("field vanished: " + e);
        }
    }

    // ------------------------------------------------------------------------------------------
    // 9. InvocationTargetException
    // ------------------------------------------------------------------------------------------
    /*
     * When a reflectively invoked method throws, the exception does NOT propagate directly. It is
     * wrapped in InvocationTargetException, and the real exception is in getCause().
     *
     * This is the single most common reflection mistake, and it matters to you as an analyst
     * because a stack trace in logcat from reflective code looks like
     *
     *     java.lang.reflect.InvocationTargetException
     *         at java.lang.reflect.Method.invoke(Native Method)
     *         at com.example.Loader.run(Loader.java:42)
     *     Caused by: java.lang.SecurityException: ...
     *
     * and the interesting frame is always under "Caused by", never at the top.
     */
    private static void unwrapTargetException() throws Exception {
        Method boom = SecretVault.class.getDeclaredMethod("alwaysFails");
        boom.setAccessible(true);
        try {
            boom.invoke(null);
        } catch (InvocationTargetException e) {
            System.out.println("wrapper  -> " + e.getClass().getName());
            System.out.println("real one -> " + e.getCause().getClass().getName()
                                              + ": " + e.getCause().getMessage());
        }
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("=== " + title + " " + "=".repeat(Math.max(0, 60 - title.length())));
    }
}

/*
 * The target class. Everything interesting in it is private, which under the language rules means
 * unreachable from ReflectionDemo, and which in practice means nothing of the sort.
 *
 * In JADX this appears as a separate top-level class file, because it is a separate top-level
 * class - being declared in the same .java file has no effect on the compiled output. Confirm
 * that after compiling: `ls *.class` shows both ReflectionDemo.class and SecretVault.class.
 */
class SecretVault {

    /* Private static mutable state: the classic target for a runtime bypass. */
    private static int instanceCount = 0;

    /* A private instance field holding something credential-shaped. */
    private String token;

    /* Private constructor: "you must use the factory". Section 4 ignores this. */
    private SecretVault(String token) {
        this.token = token;
        instanceCount++;
    }

    static SecretVault create(String token) {
        return new SecretVault(token);
    }

    static int reportCount() {
        return instanceCount;
    }

    /* Public surface. Deliberately reveals only a masked view of the token. */
    String publicHint() {
        int keep = Math.min(4, token.length());
        return token.substring(0, keep) + "*".repeat(Math.max(0, token.length() - keep));
    }

    /*
     * A private method with a mixed signature: one reference parameter and one primitive. Section
     * 3 calls it, and the primitive is what forces the Integer.TYPE detail described there.
     */
    private String derive(String salt, int rounds) {
        String acc = salt + ":" + token;
        for (int i = 0; i < rounds; i++) {
            acc = Integer.toHexString(acc.hashCode()) + ":" + acc.length();
        }
        return acc;
    }

    /*
     * The target of the obfuscated lookup in section 7. Its name never appears as a string literal
     * in the calling class, and the payload it decodes never appears as a string literal anywhere.
     * The bytes below are the flag from ../labs/lab-03-reflection-hunt.md, XORed with the low byte
     * of the seed the caller passes in.
     *
     * IN SMALI this array is emitted as a fill-array-data instruction pointing at an .array-data
     * payload block at the end of the method, which baksmali prints in full. That makes it easier
     * to read than the equivalent char-by-char aput sequence, not harder.
     */
    private static String enlist(int seed) {
        final byte[] sealed = {
                (byte) 0xab, (byte) 0xa1, (byte) 0xac, (byte) 0xaa, (byte) 0x96, (byte) 0x9f,
                (byte) 0xde, (byte) 0x8b, (byte) 0x81, (byte) 0xde, (byte) 0x8e, (byte) 0x99,
                (byte) 0xdc, (byte) 0xdd, (byte) 0x83, (byte) 0xb2, (byte) 0xdc, (byte) 0x9e,
                (byte) 0xb2, (byte) 0x83, (byte) 0xdd, (byte) 0x99, (byte) 0xb2, (byte) 0xdd,
                (byte) 0x8f, (byte) 0x8b, (byte) 0x98, (byte) 0x9e, (byte) 0x8e, (byte) 0xd9,
                (byte) 0x99, (byte) 0xdc, (byte) 0xdd, (byte) 0x83, (byte) 0x90
        };
        byte key = (byte) (seed & 0xFF);
        byte[] out = new byte[sealed.length];
        for (int i = 0; i < sealed.length; i++) {
            out[i] = (byte) (sealed[i] ^ key);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    /* Used by section 9 to demonstrate InvocationTargetException wrapping. */
    private static void alwaysFails() {
        throw new IllegalStateException("vault sealed by policy");
    }
}
