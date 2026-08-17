/*
 * ============================================================================
 * NullSafetyDemo.kt — chapter 05 (Kotlin), Android Pentesting Notes
 * ============================================================================
 *
 * WHAT THIS FILE DOES
 *   Demonstrates every part of Kotlin's null-safety system and, for each one,
 *   states exactly what the compiler emits and what that looks like in JADX.
 *   It runs to completion and prints a labelled line for every case, including
 *   the ones that throw, so you can compare the exception types side by side.
 *
 *   Covered:
 *     1. Non-null types and the compiler-inserted Intrinsics.checkNotNullParameter
 *     2. Nullable types, the safe call ?., and the Elvis operator ?:
 *     3. The not-null assertion !! and Intrinsics.checkNotNull
 *     4. Platform types coming from Java interop (the hole in the guarantee)
 *     5. lateinit and Intrinsics.throwUninitializedPropertyAccessException
 *     6. Safe patterns that produce a useful failure instead of a mystery one
 *     7. Safe casts, smart casts, and null-safe equality via Intrinsics.areEqual
 *
 * HOW TO RUN IT
 *   This file needs a tiny Java class to create a genuine platform type, because
 *   platform types can only come from unannotated Java. Create it first:
 *
 *     # host — save as JavaConfig.java next to this file
 *     import java.util.HashMap;
 *     import java.util.Map;
 *     public class JavaConfig {
 *         private static final Map<String, String> V = new HashMap<>();
 *         static { V.put("region", "eu-west-1"); }
 *         public static String getValue(String key) { return V.get(key); }
 *     }
 *
 *   Then, from the directory containing both files:
 *
 *     # host — compile both, produce a self-contained jar, run it
 *     kotlinc NullSafetyDemo.kt JavaConfig.java -include-runtime -d nullsafety.jar
 *     java -jar nullsafety.jar
 *
 *   To study the emitted bytecode instead of running it:
 *
 *     # host — compile to class files, then decompile
 *     kotlinc NullSafetyDemo.kt JavaConfig.java -d out/
 *     jar cf nullsafety-classes.jar -C out .
 *     jadx --no-res -d jadx_out nullsafety-classes.jar
 *     cat jadx_out/sources/NullSafetyDemoKt.java
 *
 *   To see the raw JVM bytecode rather than reconstructed Java:
 *
 *     # host
 *     javap -p -c -cp out/ NullSafetyDemoKt
 *
 * WHERE THIS FITS
 *   Chapter README:  ../README.md
 *   Cheat sheet:     ../cheatsheet.md
 *   Hands-on lab:    ../labs/lab-02-null-safety-in-jadx.md
 *   Prerequisite:    ../../04-Java/README.md
 * ============================================================================
 */

import java.util.Locale

// ---------------------------------------------------------------------------
// SECTION 1 — Non-null parameters
// ---------------------------------------------------------------------------

/*
 * A public function with non-null reference parameters.
 *
 * COMPILER EMITS
 *   One call to Intrinsics.checkNotNullParameter per non-null REFERENCE
 *   parameter, in declaration order, as the very first statements of the method,
 *   before any user code. The second argument is a String constant holding the
 *   original parameter name.
 *
 *   Primitives (Int, Long, Boolean, ...) get NO check, because a JVM primitive
 *   cannot be null. Nullable parameters get NO check either.
 *
 * IN JADX
 *   public static final String authenticate(String username, String password, int attempt) {
 *       Intrinsics.checkNotNullParameter(username, "username");
 *       Intrinsics.checkNotNullParameter(password, "password");
 *       return "auth:" + username.length() + ":" + password.length() + ":" + attempt;
 *   }
 *
 *   Note there is no check for `attempt` — it is an int.
 *
 * WHY THE CHECK EXISTS
 *   Kotlin's non-null guarantee is enforced by the type checker at compile time,
 *   which cannot constrain Java callers, reflection, deserialisers, or JNI. The
 *   check turns a contract violation into an immediate, attributable failure at
 *   the boundary instead of an unexplainable NullPointerException five frames in.
 *
 * PENTESTER VALUE
 *   Those "username" / "password" strings are String constants. R8 renames
 *   classes and methods but not string constants, so in a fully obfuscated app
 *   these lines still tell you what every parameter of every public function was
 *   called in the original source.
 */
fun authenticate(username: String, password: String, attempt: Int): String {
    return "auth:${username.length}:${password.length}:$attempt"
}

/*
 * A private function with the same parameter types.
 *
 * COMPILER EMITS
 *   Usually NOTHING. When a function is private (or internal and the whole
 *   module is compiled together), the compiler can see every call site and prove
 *   the contract already holds, so it omits the check.
 *
 * IN JADX
 *   private static final String internalHash(String salt, String value) {
 *       return salt + "|" + value.hashCode();
 *   }
 *
 * CONSEQUENCE FOR ANALYSIS
 *   The absence of checkNotNullParameter does NOT mean the parameter is nullable.
 *   It usually means the function is not part of the public API surface. Use it
 *   as a visibility hint, not as a nullability hint.
 */
private fun internalHash(salt: String, value: String): String = "$salt|${value.hashCode()}"

// ---------------------------------------------------------------------------
// SECTION 2 — Nullable types, safe calls, and the Elvis operator
// ---------------------------------------------------------------------------

/*
 * A nullable parameter used with a safe call and an Elvis fallback.
 *
 * COMPILER EMITS
 *   No Intrinsics check on the parameter at all. The `?.` becomes an ordinary
 *   null test and a branch; the `?:` becomes a second null test on the result of
 *   the first expression. Nullability here is control flow, not an assertion.
 *
 *   The extra checkNotNullExpressionValue on the uppercase() result appears
 *   because java.lang.String.toUpperCase is a Java method with an unannotated
 *   return type, so Kotlin treats it as a platform type and inserts a check when
 *   the result is used where a non-null value is required.
 *
 * IN JADX
 *   public static final String greet(String name) {
 *       String upper;
 *       if (name != null) {
 *           upper = name.toUpperCase(Locale.ROOT);
 *           Intrinsics.checkNotNullExpressionValue(upper, "toUpperCase(...)");
 *       } else {
 *           upper = null;
 *       }
 *       return upper == null ? "ANONYMOUS" : upper;
 *   }
 *
 * READING TIP
 *   A chain of `if (x != null)` tests with no Intrinsics calls between them is
 *   the decompiled form of a Kotlin safe-call chain such as a?.b?.c?.d.
 */
fun greet(name: String?): String = name?.uppercase(Locale.ROOT) ?: "ANONYMOUS"

/*
 * A safe-call chain across three levels of nullability.
 *
 * COMPILER EMITS
 *   Nested null tests with early exit, NOT nested method calls. Each `?.` short
 *   circuits the whole remaining chain.
 *
 * IN JADX
 *   public static final Integer chainLength(Profile p) {
 *       Address a;
 *       String c;
 *       if (p == null || (a = p.getAddress()) == null || (c = a.getCity()) == null) {
 *           return null;
 *       }
 *       return Integer.valueOf(c.length());
 *   }
 *
 *   Note the return type is java.lang.Integer, not int. Any nullable Kotlin
 *   primitive becomes its boxed Java counterpart, which is a reliable way to spot
 *   `Int?` versus `Int` in decompiled code.
 */
class Address(val city: String?)
class Profile(val address: Address?)

fun chainLength(p: Profile?): Int? = p?.address?.city?.length

// ---------------------------------------------------------------------------
// SECTION 3 — The not-null assertion, !!
// ---------------------------------------------------------------------------

/*
 * The !! operator.
 *
 * COMPILER EMITS
 *   Intrinsics.checkNotNull(value) immediately before the value is used. There
 *   are two overloads: (Object) and (Object, String). The one-argument form is
 *   what a bare !! produces.
 *
 * IN JADX
 *   public static final int forceLength(String maybe) {
 *       Intrinsics.checkNotNull(maybe);
 *       return maybe.length();
 *   }
 *
 *   On older compilers you may instead see:
 *       if (maybe == null) { Intrinsics.throwNpe(); }
 *
 * FAILURE MODE
 *   Throws NullPointerException with the message
 *   "null cannot be cast to non-null type kotlin.String". The message names the
 *   TYPE but not the variable, which is why !! produces less useful crash
 *   reports than an explicit check with a message.
 *
 * SECURITY NOTE
 *   By itself this is a reliability bug, not a vulnerability. It becomes a
 *   finding when the value is attacker-controlled AND the crash is reachable
 *   from outside the app, typically through an exported component. See
 *   ../faq.md question 16 and ../../22-Intents/README.md.
 */
fun forceLength(maybe: String?): Int = maybe!!.length

// ---------------------------------------------------------------------------
// SECTION 4 — Platform types (the hole)
// ---------------------------------------------------------------------------

/*
 * A value returned by unannotated Java code.
 *
 * WHAT KOTLIN SEES
 *   The type of JavaConfig.getValue(...) is `String!`, a PLATFORM TYPE. Kotlin
 *   does not know whether it can be null, so it refuses to guess and lets you
 *   treat it as either. You can assign it straight into a non-null `String`.
 *
 * COMPILER EMITS
 *   NOTHING. No check on the assignment, no check on the declaration, no
 *   annotation enforcement. This is the single hole in Kotlin's null guarantee.
 *
 * IN JADX
 *   public static final int readRegion() {
 *       return JavaConfig.getValue("region").length();
 *   }
 *
 *   Compare that with forceLength above: the !! version at least emits a check.
 *   The platform-type version emits nothing at all, so a null propagates
 *   silently and fails at whatever line first dereferences it.
 *
 * WHERE THIS BITES ON ANDROID
 *   Every value from the framework is a platform type unless annotated:
 *     intent.getStringExtra(...)      bundle.getString(...)
 *     cursor.getString(...)           jsonObject.optString(...)
 *     sharedPrefs.getString(...)      any JNI return value
 *     findViewById(...)               getSystemService(...)
 *   These are exactly the attacker-controlled inputs, which is why the hole
 *   matters far more than !! does in practice.
 *
 * NOTE ON THIS FILE
 *   When JavaConfig is absent the demo prints a simulated result instead of
 *   crashing, so the file still runs standalone. Compile JavaConfig.java
 *   alongside it to see the real behaviour.
 */
fun readPlatformValue(key: String): String {
    // Reflection is used here only so this file compiles with or without
    // JavaConfig.java present. In real code you would simply write:
    //     val v: String = JavaConfig.getValue(key)
    // and the compiler would emit no check whatsoever.
    return try {
        val cls = Class.forName("JavaConfig")
        val m = cls.getDeclaredMethod("getValue", String::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = m.invoke(null, key) as String   // platform type into a non-null slot
        result
    } catch (e: ClassNotFoundException) {
        // Simulated stand-in so the demo runs on its own.
        if (key == "region") "eu-west-1" else throw NullPointerException(
            "simulated platform-type null for key '$key' (compile JavaConfig.java for the real thing)"
        )
    }
}

// ---------------------------------------------------------------------------
// SECTION 5 — lateinit
// ---------------------------------------------------------------------------

/*
 * lateinit: a non-null property initialised after construction.
 *
 * WHY IT EXISTS
 *   Android hands you objects whose real initialisation happens in onCreate,
 *   not in the constructor. Without lateinit you would have to declare the
 *   property nullable and then write ?. or !! at every single use site.
 *
 * COMPILER EMITS
 *   A plain nullable field, a getter that null-checks and calls
 *   Intrinsics.throwUninitializedPropertyAccessException("<propertyName>") when
 *   unset, and a setter guarded by checkNotNullParameter(value, "<set-?>").
 *
 * IN JADX
 *   public final class Session {
 *       public String userId;                       // note: nullable in reality
 *
 *       public final String getUserId() {
 *           String s = this.userId;
 *           if (s != null) { return s; }
 *           Intrinsics.throwUninitializedPropertyAccessException("userId");
 *           return null;
 *       }
 *
 *       public final void setUserId(String v) {
 *           Intrinsics.checkNotNullParameter(v, "<set-?>");
 *           this.userId = v;
 *       }
 *   }
 *
 * READING TIP
 *   The literal string "<set-?>" is the compiler's internal name for a property
 *   setter's implicit value parameter. Seeing it proves the enclosing method is a
 *   generated setter rather than hand-written code.
 *
 * PENTESTER VALUE
 *   throwUninitializedPropertyAccessException takes the ORIGINAL property name as
 *   a String constant, so grepping for it enumerates every lateinit property in
 *   an obfuscated app together with its real name. It is also a crash oracle: if
 *   you can reach a code path that reads the property before the initialising
 *   path has run, you have a reliable denial of service.
 *
 * RESTRICTIONS
 *   lateinit cannot be applied to primitives (there is no null to represent
 *   "unset"), to val, or to nullable types.
 */
class Session {
    lateinit var userId: String

    // isInitialized compiles to a plain null test on the backing field, with no
    // Intrinsics call. In JADX: `return this.userId != null;`
    fun isReady(): Boolean = this::userId.isInitialized

    fun describe(): String = "session for $userId"
}

// ---------------------------------------------------------------------------
// SECTION 6 — Safe patterns
// ---------------------------------------------------------------------------

/*
 * Elvis with an explicit error: the recommended replacement for !!.
 *
 * COMPILER EMITS
 *   A plain null test and a throw of IllegalStateException carrying YOUR message.
 *   `error(msg)` is a stdlib inline function equivalent to
 *   `throw IllegalStateException(msg.toString())`, so it leaves no call behind.
 *
 * IN JADX
 *   public static final int readOrFail(String key) {
 *       String v = JavaConfig.getValue(key);
 *       if (v == null) {
 *           throw new IllegalStateException(("configuration key '" + key + "' is missing").toString());
 *       }
 *       return v.length();
 *   }
 *
 *   The redundant-looking `.toString()` on a String is an artefact of `error()`
 *   accepting Any and calling toString on it. Seeing it is a reliable marker
 *   that the source used error(), require(), or check().
 */
fun readOrFail(key: String): Int {
    val v = runCatching { readPlatformValue(key) }.getOrNull()
        ?: error("configuration key '$key' is missing")
    return v.length
}

/*
 * Safe cast and smart cast.
 *
 * COMPILER EMITS
 *   `as?` becomes `x instanceof T ? (T) x : null`.
 *   A smart cast after an `is` check emits a checkcast but no null test, because
 *   `instanceof` already excludes null.
 *
 * IN JADX
 *   public static final String describeAny(Object value) {
 *       String s = value instanceof String ? (String) value : null;
 *       if (s != null) { return "string of length " + s.length(); }
 *       if (value instanceof Integer) { return "int " + ((Number) value).intValue(); }
 *       return "unknown";
 *   }
 */
fun describeAny(value: Any?): String {
    val asString = value as? String
    if (asString != null) return "string of length ${asString.length}"
    if (value is Int) return "int $value"          // smart cast: no explicit cast in source
    return "unknown"
}

/*
 * Null-safe equality.
 *
 * COMPILER EMITS
 *   Intrinsics.areEqual(a, b) for `==` on nullable reference types. This is a
 *   null-safe equals(), NOT reference identity. Kotlin's `===` is the identity
 *   comparison and emits a plain bytecode reference comparison instead.
 *
 * IN JADX
 *   return Intrinsics.areEqual(a, b);
 *
 * COMMON MISREADING
 *   Analysts new to Kotlin see Intrinsics.areEqual and assume it is a special
 *   security-relevant comparison. It is not: it is `a == null ? b == null : a.equals(b)`.
 *   It is emphatically NOT constant-time, so a token comparison written with ==
 *   is theoretically timing-observable, exactly as String.equals is in Java.
 */
fun sameToken(a: String?, b: String?): Boolean = a == b

// ---------------------------------------------------------------------------
// SECTION 7 — let / also as null-handling idioms
// ---------------------------------------------------------------------------

/*
 * ?.let { } — run a block only when the value is non-null.
 *
 * COMPILER EMITS
 *   Nothing recognisable as `let`. `let` is an inline function, so its body is
 *   pasted into the caller and the lambda object never exists. What remains is a
 *   null test and the body.
 *
 * IN JADX
 *   public static final String upperOrDefault(String s) {
 *       if (s == null) { return "NONE"; }
 *       String upper = s.toUpperCase(Locale.ROOT);
 *       Intrinsics.checkNotNullExpressionValue(upper, "toUpperCase(...)");
 *       return upper;
 *   }
 *
 * CONSEQUENCE FOR HOOKING
 *   You cannot set a breakpoint on `let`, `run`, `apply`, `also`, `with`,
 *   `takeIf`, or `takeUnless`. All of them are inline and leave no call. See
 *   ../faq.md question 12.
 */
fun upperOrDefault(s: String?): String = s?.let { it.uppercase(Locale.ROOT) } ?: "NONE"

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

private fun show(label: String, block: () -> Any?) {
    val text = runCatching(block).fold(
        onSuccess = { "OK      $it" },
        onFailure = { raw ->
            // Reflection wraps the real failure in InvocationTargetException;
            // unwrap it so the printed exception type is the one the compiler's
            // check actually threw.
            val e = (raw as? java.lang.reflect.InvocationTargetException)?.targetException
                ?: (raw.cause as? NullPointerException)
                ?: raw
            "THREW   ${e::class.java.name}: ${e.message}"
        }
    )
    println("  %-34s %s".format(label, text))
}

fun main() {
    println("=".repeat(78))
    println("NullSafetyDemo — what the compiler emits, and what happens at runtime")
    println("=".repeat(78))

    println("\n[1] Non-null parameters — Intrinsics.checkNotNullParameter")
    show("authenticate(valid args)") { authenticate("alice", "hunter2", 1) }
    show("internalHash(private fn)") { internalHash("s", "v") }
    show("authenticate(null via Java)") {
        // Kotlin will not let us pass null directly, so we go through reflection,
        // exactly as a Java caller or a deserialiser would.
        val m = Class.forName("NullSafetyDemoKt")
            .getDeclaredMethod("authenticate", String::class.java, String::class.java, Int::class.java)
        m.invoke(null, null, "hunter2", 1)
    }

    println("\n[2] Nullable types — safe call and Elvis, no Intrinsics at all")
    show("greet(null)") { greet(null) }
    show("greet(\"bob\")") { greet("bob") }
    show("chainLength(null)") { chainLength(null) }
    show("chainLength(no city)") { chainLength(Profile(Address(null))) }
    show("chainLength(full)") { chainLength(Profile(Address("Lisbon"))) }

    println("\n[3] Not-null assertion — Intrinsics.checkNotNull")
    show("forceLength(\"abc\")") { forceLength("abc") }
    show("forceLength(null)") { forceLength(null) }

    println("\n[4] Platform types — NO check emitted, crash at point of use")
    show("readPlatformValue(region)") { readPlatformValue("region") }
    show("readPlatformValue(apiKey)") { readPlatformValue("apiKey") }

    println("\n[5] lateinit — throwUninitializedPropertyAccessException")
    val s = Session()
    show("isReady() before init") { s.isReady() }
    show("describe() before init") { s.describe() }
    s.userId = "u-1001"
    show("isReady() after init") { s.isReady() }
    show("describe() after init") { s.describe() }

    println("\n[6] Safe patterns — a failure you can actually diagnose")
    show("readOrFail(region)") { readOrFail("region") }
    show("readOrFail(apiKey)") { readOrFail("apiKey") }
    show("describeAny(\"hello\")") { describeAny("hello") }
    show("describeAny(42)") { describeAny(42) }
    show("describeAny(null)") { describeAny(null) }
    show("sameToken(null, null)") { sameToken(null, null) }
    show("sameToken(\"a\", null)") { sameToken("a", null) }

    println("\n[7] Scope functions — inlined, nothing to hook")
    show("upperOrDefault(null)") { upperOrDefault(null) }
    show("upperOrDefault(\"kt\")") { upperOrDefault("kt") }

    println(
        """

        ${"=".repeat(78)}
        THE ONE THING TO REMEMBER

        Case [3], the !! operator, has a reputation as the dangerous one, and it
        does throw. But case [4], a platform type assigned to a non-null variable,
        emits no check at all. It fails later, somewhere else, with a message that
        names neither the variable nor its source. The silent case is the one to
        hunt for during a review.
        ${"=".repeat(78)}
        """.trimIndent()
    )
}
