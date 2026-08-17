package com.artlab.kotlindemo

import android.util.Log
import kotlin.properties.Delegates

/**
 * DecompilationComparison.kt — every Kotlin construct that surprises a reverse
 * engineer, in one compilable file, each annotated with what JADX will show.
 *
 * WHAT IT DEMONSTRATES
 *   The gap between Kotlin source and decompiled Java. Build this, decompile
 *   it, and compare against the comments. The comments are the answer key.
 *
 * HOW TO USE IT
 *   1. Put this file in an Android module and build a RELEASE APK:
 *        ./gradlew assembleRelease
 *
 *   2. Decompile it:
 *        jadx -d out app-release.apk
 *
 *   3. Open out/sources/com/artlab/kotlindemo/ and compare each construct
 *      against the "DECOMPILES TO" comment above it.
 *
 *   4. Then rebuild with minifyEnabled true and repeat, to see what R8 does
 *      on top. See ../../42-R8/README.md.
 *
 * WHY THIS IS WORTH DOING ONCE
 *   Reading about `companion object` becoming a `Companion` static nested
 *   class is not the same as seeing it. After this exercise the patterns are
 *   recognisable at a glance, which is the whole point of chapter 05.
 */

// ===========================================================================
// 1. NULL SAFETY — the Intrinsics fingerprint
// ===========================================================================

class NullSafety(private val nullableToken: String?) {

    /*
     * DECOMPILES TO:
     *   public final boolean login(String username, String password) {
     *       Intrinsics.checkNotNullParameter(username, "username");
     *       Intrinsics.checkNotNullParameter(password, "password");
     *       return username.length() > 0 && password.length() >= 8;
     *   }
     *
     * The two Intrinsics lines exist in NO source file — the compiler adds
     * them for every non-null parameter of a public function.
     *
     * KEY POINT FOR RE: the string literals "username" and "password" are the
     * ORIGINAL parameter names, and obfuscators leave them alone because
     * removing them would change exception messages. Harvesting these is one
     * of the highest-yield tricks against an obfuscated Kotlin app.
     */
    fun login(username: String, password: String): Boolean =
        username.isNotEmpty() && password.length >= 8

    /*
     * DECOMPILES TO a sequence of null checks. Specifically:
     *   ?.        -> `x != null ? ... : null`
     *   ?:        -> a ternary or an if/else supplying the fallback
     *   !!        -> Intrinsics.checkNotNull(x)
     */
    fun tokenLength(): Int {
        val safeCall = nullableToken?.length ?: 0
        val assertion = nullableToken!!.length          // -> Intrinsics.checkNotNull
        return safeCall + assertion
    }

    /*
     * DECOMPILES TO:
     *   Intrinsics.checkNotNullExpressionValue(result, "...");
     *
     * This variant guards values coming back from PLATFORM TYPES — Java APIs
     * whose nullability Kotlin cannot know. Its presence tells you the code
     * crossed a Java boundary here, which is often where null-safety
     * guarantees actually break. See README section 10, "Senior".
     */
    fun fromJavaApi(): String {
        val s: String = System.getProperty("java.vm.name") ?: "unknown"
        return s.uppercase()
    }
}

// ===========================================================================
// 2. COMPANION OBJECT — becomes a static nested class
// ===========================================================================

class ApiClient private constructor(private val baseUrl: String) {

    /*
     * DECOMPILES TO:
     *
     *   public final class ApiClient {
     *       public static final Companion Companion = new Companion(null);
     *       private static final String DEFAULT_URL = "https://api.example.com";
     *
     *       public static final class Companion {
     *           private Companion() {}
     *           public  Companion(DefaultConstructorMarker m) { this(); }
     *           public final ApiClient createWith(String url) { ... }
     *       }
     *   }
     *
     * THREE THINGS TO NOTICE:
     *   a) `companion object` -> static nested class literally named Companion,
     *      plus a static field of the same name holding the instance.
     *   b) `const val` is HOISTED to the outer class AND inlined at every use
     *      site. Patching the field does not change behaviour — you must patch
     *      each call site.
     *   c) DefaultConstructorMarker is compiler plumbing to create a
     *      non-colliding overload. Always null. Ignore it when reading.
     */
    companion object {
        private const val DEFAULT_URL = "https://api.example.com"

        // @JvmStatic adds an EXTRA forwarding method on the outer class, so
        // the same function appears twice in decompiled output.
        @JvmStatic
        fun create(): ApiClient = ApiClient(DEFAULT_URL)

        fun createWith(url: String): ApiClient = ApiClient(url)
    }

    fun endpoint(path: String): String = "$baseUrl/$path"
}

// ===========================================================================
// 3. OBJECT DECLARATION — becomes an INSTANCE singleton
// ===========================================================================

/*
 * DECOMPILES TO:
 *   public final class ConfigRegistry {
 *       public static final ConfigRegistry INSTANCE = new ConfigRegistry();
 *       private ConfigRegistry() {}
 *       ...
 *   }
 *
 * FOR HOOKING: reach it through the static INSTANCE field, not by constructing
 * it. In Frida:  Java.use("...ConfigRegistry").INSTANCE.value
 */
object ConfigRegistry {
    private val entries = mutableMapOf<String, String>()
    fun put(k: String, v: String) { entries[k] = v }
    fun get(k: String): String? = entries[k]
}

// ===========================================================================
// 4. DATA CLASS — generates toString() that prints EVERYTHING
// ===========================================================================

/*
 * DECOMPILES TO a class with generated:
 *   equals(Object), hashCode(), toString(), copy(...), component1(), component2()
 *
 * THE SECURITY POINT: the generated toString() renders EVERY property.
 *
 *   Log.d(TAG, "$session")
 *
 * produces:
 *
 *   Session(userId=42, token=eyJhbGciOi..., expiresAt=1700000000)
 *
 * The developer wrote one innocuous-looking log line; the compiler leaked the
 * token. This is a recurring real-world finding — see README section 9.5 and
 * ../../33-Storage/README.md for severity guidance.
 */
data class Session(
    val userId: Long,
    val token: String,          // <-- will appear in toString()
    val expiresAt: Long
)

/*
 * THE FIX: override toString() to redact, or do not make it a data class.
 */
data class SafeSession(
    val userId: Long,
    val token: String,
    val expiresAt: Long
) {
    override fun toString(): String =
        "SafeSession(userId=$userId, token=***, expiresAt=$expiresAt)"
}

// ===========================================================================
// 5. SEALED CLASS — the complete, exhaustive state set
// ===========================================================================

/*
 * DECOMPILES TO an abstract class plus nested subclasses.
 *
 * FOR RE THIS IS A GIFT: `sealed` means the subclass set is CLOSED, so the
 * decompiled nested classes are the complete list of states this type can
 * ever hold. You do not have to wonder whether you have found them all.
 */
sealed class AuthState {
    object Unauthenticated : AuthState()
    data class Authenticated(val session: Session) : AuthState()
    data class Failed(val reason: String, val retryable: Boolean) : AuthState()
}

// ===========================================================================
// 6. DEFAULT ARGUMENTS — generates a $default bridge with a bitmask
// ===========================================================================

class HttpRequester {

    /*
     * ONE Kotlin function becomes TWO JVM methods:
     *
     *   public final String request(String url, String method, int timeout, int retries)
     *   public static  String request$default(
     *       HttpRequester obj, String url, String method, int timeout,
     *       int retries, int mask, Object marker) {
     *           if ((mask & 2) != 0) method  = "GET";
     *           if ((mask & 4) != 0) timeout = 30;
     *           if ((mask & 8) != 0) retries = 3;
     *           return obj.request(url, method, timeout, retries);
     *   }
     *
     * The `mask` is a bitmask of OMITTED arguments: bit n set means the caller
     * did not supply parameter n, so the default applies.
     *
     * FOR HOOKING: hooking `request` shows resolved values. Hooking
     * `request$default` shows the mask, which tells you whether a caller
     * EXPLICITLY passed a value or merely accepted the default — occasionally
     * the more interesting question. See scripts/hook-kotlin.js kt.defaults().
     */
    fun request(
        url: String,
        method: String = "GET",
        timeout: Int = 30,
        retries: Int = 3
    ): String = "$method $url t=$timeout r=$retries"
}

// ===========================================================================
// 7. EXTENSION FUNCTIONS — become STATIC methods on a file-named class
// ===========================================================================

/*
 * DECOMPILES TO a static method on a class named after the FILE:
 *
 *   public final class DecompilationComparisonKt {
 *       public static final String maskMiddle(String $this$maskMiddle) { ... }
 *   }
 *
 * TWO SURPRISES FOR A REVERSE ENGINEER:
 *   a) The function is NOT on String — it is on <FileName>Kt.
 *   b) The receiver becomes the FIRST PARAMETER, conventionally named
 *      `$this$<functionName>`.
 *
 * So a search for "maskMiddle" on the String class finds nothing. You must
 * look at the file-level class. See scripts/hook-kotlin.js kt.extension().
 */
fun String.maskMiddle(): String =
    if (length <= 8) "*".repeat(length)
    else take(4) + "*".repeat(length - 8) + takeLast(4)

// ===========================================================================
// 8. INLINE FUNCTIONS — vanish entirely at COMPILE time
// ===========================================================================

/*
 * DECOMPILES TO... nothing. There is no `measure` method in the output.
 * Its body is spliced into every call site by the KOTLIN COMPILER.
 *
 * CRITICAL DISTINCTION (README section 10, "Senior"):
 *   - Kotlin `inline`     = compile-time. The method never exists in the DEX.
 *                           NO amount of forcing the interpreter brings it back.
 *   - ART runtime inlining = the optimizing compiler folding a real method into
 *                           its caller. REVERSIBLE with
 *                           `cmd package compile -m verify -f <pkg>`.
 *
 * When a hook target is simply absent from decompiled output, suspect the
 * first. When it is present but the hook does not fire, suspect the second.
 * See ../../13-ART/README.md section 3.17.
 */
inline fun <T> measure(label: String, block: () -> T): T {
    val start = System.nanoTime()
    val result = block()
    Log.d("PERF", "$label took ${(System.nanoTime() - start) / 1000}us")
    return result
}

// ===========================================================================
// 9. DELEGATES — by lazy and observable
// ===========================================================================

class SettingsStore {

    /*
     * `by lazy` DECOMPILES TO a Lazy field plus a null check on first access:
     *
     *   private final Lazy expensive$delegate = LazyKt.lazy(new Function0() {...});
     *   public final String getExpensive() {
     *       return (String) this.expensive$delegate.getValue();
     *   }
     *
     * FOR RE: initialisation happens inside the Function0, not where the
     * property is declared. Follow the lambda to find the real logic.
     */
    val expensive: String by lazy {
        Log.d("SettingsStore", "computing expensive value")
        buildString { repeat(3) { append("segment$it-") } }
    }

    /*
     * `by Delegates.observable` DECOMPILES TO an ObservableProperty subclass.
     *
     * FOR RE THIS IS USEFUL: it gives you a SINGLE interception point for
     * every write to this property, wherever in the codebase it happens.
     * Hook afterChange and you see all of them.
     */
    var authState: AuthState by Delegates.observable<AuthState>(
        AuthState.Unauthenticated
    ) { _, old, new ->
        // NOTE: this logs the data class, which renders the token.
        // Deliberate — it is the finding demonstrated in section 4 above.
        Log.d("SettingsStore", "authState $old -> $new")
    }
}

// ===========================================================================
// 10. LAMBDAS — become synthetic classes with generated names
// ===========================================================================

class EventBus {

    /*
     * DECOMPILES TO a synthetic class. Under R8 the naming is typically:
     *
     *   EventBus$$ExternalSyntheticLambda0
     *   $r8$lambda$aBcDeF...
     *
     * These names carry no meaning. Do not waste time trying to interpret
     * them — read what they DO. See ../../42-R8/README.md.
     */
    private val handlers = mutableListOf<(String) -> Unit>()

    fun subscribe(handler: (String) -> Unit) { handlers.add(handler) }

    fun publish(event: String) {
        handlers.forEach { it(event) }
    }

    fun demo() {
        subscribe { Log.d("EventBus", "got $it") }
        subscribe(::handleTyped)          // method reference -> also synthetic
        publish("hello")
    }

    private fun handleTyped(event: String) {
        Log.d("EventBus", "typed handler: $event")
    }
}

// ===========================================================================
// 11. `internal` IS NOT A SECURITY BOUNDARY
// ===========================================================================

/*
 * DECOMPILES TO a PUBLIC method with a mangled name:
 *
 *   public final void resetEverything$app_release()
 *
 * `internal` means "visible within the compilation module" — a COMPILE-TIME
 * rule enforced by the Kotlin compiler only. At the bytecode level it is
 * public and fully callable by anyone, including from Frida.
 *
 * Do not treat `internal` as access control. Same lesson as `private` in Java:
 * it is a design tool, not a security boundary. See README section 11.
 */
class MaintenanceOps {
    internal fun resetEverything() {
        Log.w("MaintenanceOps", "everything reset")
    }
}

// ===========================================================================
// Entry point tying it together, so the file is exercisable.
// ===========================================================================

object Demo {
    fun run() {
        val client = ApiClient.create()
        Log.d("Demo", client.endpoint("v1/login"))

        val store = SettingsStore()
        Log.d("Demo", store.expensive)

        // This assignment triggers the observable delegate, which logs the
        // data class, which renders the token. The whole leak chain in one line.
        store.authState = AuthState.Authenticated(
            Session(userId = 42, token = "eyJhbGciOiJIUzI1NiJ9.secret", expiresAt = 0)
        )

        Log.d("Demo", "masked: " + "4111111111111111".maskMiddle())

        measure("http") { HttpRequester().request("https://example.com") }

        ConfigRegistry.put("env", "prod")
        EventBus().demo()
    }
}
