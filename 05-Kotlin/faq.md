# Kotlin — Frequently Asked Questions

Questions real learners ask while working through chapter [05 — Kotlin](README.md), including the ones
people feel embarrassed to ask. Every answer is written to stand alone, so you can jump straight to
the question you have.

---

## Language and motivation

### 1. If Kotlin compiles to the same bytecode as Java, why bother learning it at all?

Because the bytecode is the same but the *source* is not, and almost everything you will read, patch,
or write in modern Android is Kotlin source. More importantly for a reverse engineer, the Kotlin
compiler does not translate your code one-to-one: it inserts runtime null checks, generates whole
classes you never wrote, rewrites suspending functions into state machines, and copies inline function
bodies into their callers. Those transformations are exactly what makes decompiled Kotlin look strange,
and you cannot interpret JADX output without knowing which parts the developer wrote and which parts
the compiler added.

There is a second, practical reason. Kotlin's null-safety rules mean a huge class of Java bugs simply
cannot be expressed. When you audit a Kotlin codebase you can stop hunting for ordinary null-pointer
dereferences and spend that time on the places where the developer deliberately opted out of safety,
which is a much shorter and much more interesting list.

> **🧠 Mental Model**
> Java is a language that describes bytecode fairly directly. Kotlin is a language that describes
> *intent*, and the compiler writes a considerable amount of Java-equivalent code on your behalf. When
> you decompile, you are reading the compiler's Java, not the developer's Kotlin.

### 2. Is Kotlin slower than Java?

For practical purposes, no. Both languages compile to the same JVM bytecode and then to the same DEX,
and the Android Runtime executes them identically — it has no idea which language produced a method.
There is no Kotlin interpreter, no Kotlin virtual machine, and no translation layer at runtime.

There are small, measurable differences, and they are worth knowing because they show up in profiling:

| Cost | Cause | Mitigation |
|---|---|---|
| Extra method calls at entry | `Intrinsics.checkNotNullParameter` on every public function | R8 can remove them in release builds with the right configuration |
| Boxing | `Int?` becomes `java.lang.Integer`, generic collections box primitives | Use non-null primitives and specialised arrays such as `IntArray` |
| Object allocation for lambdas | Capturing lambdas allocate; non-capturing ones do not | Mark the higher-order function `inline` |
| Larger APK | `kotlin-stdlib` adds roughly a megabyte before shrinking | R8 strips unused stdlib classes aggressively |
| Coroutine machinery | Every suspend function allocates a continuation object | Unavoidable, and far cheaper than a thread |

Against this, inline functions frequently make Kotlin *faster* than the equivalent Java, because a
Kotlin `list.filter { }.map { }` chain marked inline compiles to plain loops with no callback objects
at all, whereas the Java Streams equivalent allocates several pipeline objects.

### 3. Do I still need to learn Java?

Yes, and you should learn it first, which is why [chapter 04](../04-Java/README.md) comes before this
one. Three reasons make this non-negotiable for a security researcher.

First, JADX and every other decompiler produce *Java*, not Kotlin. No matter what language the app was
written in, the thing on your screen is Java-shaped, so Java is the language you actually read during
an assessment. Second, the entire Android framework — `Activity`, `Context`, `Binder`, `PackageManager`
— is written in Java, and you will be reading AOSP source constantly. Third, real applications are
mixed: an app started in 2016 will have a Java core with Kotlin added on top, and the interop seam
between them is where the interesting bugs live.

Think of it as reading versus writing. You read Java and you write Kotlin.

### 4. What is a platform type and why does it break null safety?

> **📖 Definition**
> A **platform type**, written `T!` in error messages but never written by hand in source, is a type
> that came from Java and whose nullability the Kotlin compiler does not know. Kotlin declines to
> guess: it lets you treat the value as either nullable or non-null, and inserts **no** runtime check.

Java has no notion of nullable and non-null types. When Kotlin calls `someJavaObject.getName()`, the
declared return type is `String`, which in Java means "a string, or null, we never said". Kotlin has
three options: assume nullable (which would force `?.` on every single Java call and make interop
unbearable), assume non-null (which would insert a check that crashes at a point the developer never
chose), or defer to the developer. It chooses the third, and calls the result a platform type.

The consequence is a genuine hole in the guarantee. This compiles and crashes:

```kotlin
// host — compiles cleanly, throws at runtime
val name: String = javaApi.getName()   // platform type assigned to a non-null type
println(name.length)                    // NullPointerException if getName returned null
```

The crash is a plain `NullPointerException` from the JVM, not a Kotlin `IllegalStateException`, and it
happens at the point of use rather than the point of assignment, which makes it harder to trace.

> **⚠️ Warning**
> Every value crossing the Java-to-Kotlin boundary is a platform type unless the Java side is annotated
> with `@Nullable` or `@NonNull`. That includes all of `android.*`, all of `org.json.*`, everything
> returned by JNI, and every value your app reads from an `Intent`, a `Bundle`, or a `Cursor` — in other
> words, precisely the attacker-controlled inputs.

> **🔍 Pentester's Note**
> Platform types are the highest-value place to look for crashes in an otherwise null-safe app. Find
> the Kotlin function that reads `intent.getStringExtra("x")` into a non-null `String`, send an Intent
> without that extra, and you have a reproducible denial of service. Chapter
> [26 — Intent](../26-Intent/README.md) covers how to deliver it.

### 5. What is the difference between `val` and `var`, and is `val` the same as Java's `final`?

`val` means the *reference* cannot be reassigned; `var` means it can. For a local variable, `val` is
exactly Java's `final`. For a property, `val` generates a private final field and a getter with no
setter, while `var` generates a non-final field with both a getter and a setter.

`val` says nothing about the object the reference points at. A `val` holding a `MutableList` can still
have elements added to it. Immutability in Kotlin is shallow by default and lives in the type
(`List` versus `MutableList`), not in the declaration keyword.

### 6. If `List` is read-only, why can Java code still modify it?

Because `kotlin.collections.List` and `kotlin.collections.MutableList` are the *same class at runtime*
— both are `java.util.List`. The read-only view exists only in the Kotlin type checker. When the list
crosses into Java, the checker is no longer involved, and Java sees a perfectly ordinary mutable
`java.util.ArrayList`.

> **🔬 Under the Hood**
> Kotlin maps its collection interfaces onto the Java ones through the compiler's built-in mapping
> table rather than by generating wrapper classes. `List<String>` has the JVM descriptor
> `Ljava/util/List;`. This is why decompiled Kotlin shows plain `java.util.List` everywhere and gives
> you no hint about which side of the read-only split the developer intended. If you need genuine
> runtime immutability, you must call `Collections.unmodifiableList` explicitly.

---

## Reading decompiled output

### 7. Why does JADX show `Intrinsics.checkNotNullParameter` at the top of nearly every method?

Because Kotlin's non-null guarantee is a *compile-time* guarantee, and compile-time guarantees stop at
the module boundary. Nothing prevents Java code, reflection, a deserialiser, or a JNI call from passing
`null` into a Kotlin function whose parameter is declared non-null. To keep the promise honest, the
compiler emits a defensive check at the start of every function that is visible outside the file, so a
violation fails immediately at the boundary with a clear message rather than five frames deeper with a
mysterious one.

The emitted shape is always the same:

```java
// jadx output
public final void login(String username, String password) {
    Intrinsics.checkNotNullParameter(username, "username");
    Intrinsics.checkNotNullParameter(password, "password");
    ...
}
```

Private and internal functions frequently skip the check, because the compiler can prove every caller
within the module already satisfies the contract.

> **🔍 Pentester's Note**
> Those string literals are the single most useful free gift in a Kotlin APK. String constants are not
> renamed by R8, so even in a fully obfuscated app where the class is `a` and the method is `b`, the
> line `Intrinsics.checkNotNullParameter(str, "encryptionKey")` tells you exactly what the first
> parameter is. Grep for `checkNotNullParameter` across the whole jadx output and read the second
> argument of every hit before you read anything else.

### 8. What is `checkNotNullExpressionValue` and how is it different?

`checkNotNullParameter` guards values coming *in*; `checkNotNullExpressionValue` guards values coming
*back* from a call. It appears when Kotlin code uses the result of a platform-typed expression in a
position that requires non-null.

```java
// jadx output
SharedPreferences prefs = ctx.getSharedPreferences("cfg", 0);
Intrinsics.checkNotNullExpressionValue(prefs, "getSharedPreferences(\"cfg\", MODE_PRIVATE)");
```

The second argument is the **original Kotlin source text of the expression**, captured verbatim by the
compiler. That is even more informative than a parameter name, because it hands you a fragment of the
developer's real source code, including argument names such as `MODE_PRIVATE` that were compiled away
to the integer `0`. In a heavily obfuscated app these strings are often the only surviving source-level
information.

### 9. Why does a `companion object` show up as a `Companion` inner class?

Because the JVM has no concept of "static members that can implement an interface, be extended, and be
passed around as an object", which is what a Kotlin companion is. Kotlin therefore implements it as a
real object: a static nested class named `Companion`, one instance of it, and a static field on the
outer class holding that instance.

```kotlin
// source
class TokenStore {
    companion object {
        fun create(): TokenStore = TokenStore()
    }
}
```

```java
// jadx output — the shape you will actually see
public final class TokenStore {
    public static final Companion Companion = new Companion(null);

    public static final class Companion {
        private Companion() {}
        public /* synthetic */ Companion(DefaultConstructorMarker m) { this(); }
        public final TokenStore create() { return new TokenStore(); }
    }
}
```

Call sites become `TokenStore.Companion.create()`. If the developer annotated the member `@JvmStatic`,
the compiler additionally generates a genuine `public static TokenStore create()` on `TokenStore` that
simply forwards to the companion instance, so both call forms exist.

> **🔍 Pentester's Note**
> This directly changes your Frida target. To hook `TokenStore.Companion.create()` you must
> `Java.use("com.app.TokenStore$Companion")` — note the dollar sign — and hook `create` there. Hooking
> `create` on `com.app.TokenStore` silently does nothing unless `@JvmStatic` was used. If your hook
> never fires, this is the first thing to check.

### 10. Why can I not find my extension function as a method on the class?

Because extension functions are not members. They are static functions that take the receiver as their
first parameter, and they live on the file facade class, not on the type being extended.

```kotlin
// source, in file StringUtils.kt
fun String.isValidToken(): Boolean = this.length == 32
```

```java
// jadx output — class StringUtilsKt, not class String
public final class StringUtilsKt {
    public static final boolean isValidToken(String $this$isValidToken) {
        Intrinsics.checkNotNullParameter($this$isValidToken, "$this$isValidToken");
        return $this$isValidToken.length() == 32;
    }
}
```

Two things follow. First, extension dispatch is *static*: which extension runs is decided at compile
time from the declared type, so an extension can never be overridden polymorphically. Second, when you
are searching for a function you saw in the source, search the file facade `<FileName>Kt` rather than
the class, and remember the parameter named `$this$<functionName>` is the receiver.

### 11. What is `DefaultConstructorMarker` and why does it appear as an unused parameter?

It is a marker type from `kotlin.jvm.internal` whose only purpose is to make a synthetic constructor
signature unique so it cannot collide with a real one the developer wrote. Its value is always `null`
and it is never read.

It appears in two situations. When a constructor has default arguments, the compiler emits a synthetic
constructor taking all parameters plus an `int` bitmask plus a `DefaultConstructorMarker`. When a class
is `sealed`, its constructor is private, and a synthetic package-visible constructor taking a
`DefaultConstructorMarker` is generated so subclasses in the same file can reach it.

```java
// jadx output
public /* synthetic */ User(String name, int age, int i, DefaultConstructorMarker marker) {
    if ((i & 2) != 0) { age = 18; }     // bit 1 set means "age was omitted, use the default"
    this(name, age);
}
```

The `int` is the bitmask: bit *n* set means parameter *n* was not supplied by the caller and the default
should be substituted. Reading the bitmask at a call site tells you exactly which arguments the
developer left out.

### 12. Why did my breakpoint or Frida hook on an inline function never fire?

Because after inlining there is no function left to hook. An `inline fun` is not called; its body is
copied into the caller by the compiler, at every call site, before any bytecode is emitted. There is no
method entry, no stack frame, and no symbol for a hook to attach to.

```kotlin
// source
inline fun <T> measure(block: () -> T): T {
    val start = System.nanoTime()
    val r = block()
    Log.d("perf", "${System.nanoTime() - start}")
    return r
}
fun doWork() = measure { computeHash() }
```

```java
// jadx output — measure has vanished from doWork entirely
public final String doWork() {
    long start = System.nanoTime();
    String r = computeHash();
    Log.d("perf", String.valueOf(System.nanoTime() - start));
    return r;
}
```

The compiler usually still emits a public copy of `measure` so that Java callers and other modules can
use it, which is why you can *see* the method in JADX while hooking it accomplishes nothing.

Your options, in order of preference:

| Approach | How | When it works |
|---|---|---|
| Hook the callee | Hook `computeHash`, not `measure` | Almost always; the inner call survives |
| Hook the caller | Hook `doWork` and inspect arguments and return | When you only need inputs and outputs |
| Native interception | `Interceptor.attach` on the ART-compiled address found via `DebugSymbol` or a pattern scan | Advanced; see [chapter 13 — ART](../13-ART/README.md) |
| Patch the DEX | Rewrite the inlined body in smali and rebuild | When you need permanent behaviour change |

This applies to every scope function too. `let`, `run`, `apply`, `also`, and `with` are all inline, so
none of them ever appear as calls, and there is nothing to hook inside them.

### 13. How do I hook a `suspend` function with Frida?

A `suspend` function is not a special JVM construct — the compiler rewrites it into an ordinary method
with one extra parameter and a different return type. Once you know the rewritten signature you can
hook it like any other method.

```kotlin
// source
suspend fun fetchToken(userId: String): String { ... }
```

```java
// the actual JVM signature after compilation
public final Object fetchToken(String userId, Continuation<? super String> $completion)
```

Note two things. The return type becomes `Object`, because the method may return either the real result
or the `COROUTINE_SUSPENDED` sentinel. And the last parameter is a `kotlin.coroutines.Continuation`.

```javascript
// Frida REPL or -l script — hook the entry of a suspend function
Java.perform(function () {
    var Repo = Java.use('com.app.TokenRepository');
    Repo.fetchToken.overload('java.lang.String', 'kotlin.coroutines.Continuation')
        .implementation = function (userId, cont) {
            console.log('[+] fetchToken called with userId=' + userId);
            var ret = this.fetchToken(userId, cont);
            console.log('[+] fetchToken returned (may be COROUTINE_SUSPENDED): ' + ret);
            return ret;
        };
});
```

The catch is that hooking the entry point only shows you the arguments. If the function suspends, your
`ret` will be the sentinel object and the real result arrives later, on a different thread, through the
continuation. To see the result you hook the resume path instead:

```javascript
// Frida REPL — see every coroutine resumption in the process
Java.perform(function () {
    var Base = Java.use('kotlin.coroutines.jvm.internal.BaseContinuationImpl');
    Base.resumeWith.implementation = function (result) {
        console.log('[resume] ' + this.$className + ' <- ' + result);
        return this.resumeWith(result);
    };
});
```

The full, defensive version of both hooks is in [scripts/hook-kotlin.js](scripts/hook-kotlin.js), and
[lab 03](labs/lab-03-coroutine-state-machine.md) walks through using it to recover a secret held in a
continuation's fields.

### 14. What is the `label` field I keep seeing inside `invokeSuspend`?

It is the program counter of the coroutine state machine. When the compiler rewrites a suspending
function, it cannot keep the execution state on the thread stack, because the thread will be released
at the first suspension and the function may resume on a completely different one. So it moves the
whole body into a single method, `invokeSuspend`, splits it at every suspension point, and stores an
integer telling the method where to continue.

```java
// jadx output — the canonical shape
public final Object invokeSuspend(Object $result) {
    Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
    switch (this.label) {
        case 0:
            ResultKt.throwOnFailure($result);
            this.label = 1;
            if (api.login(this) == coroutine_suspended) return coroutine_suspended;
            break;
        case 1:
            ResultKt.throwOnFailure($result);
            this.label = 2;
            if (api.fetch(this) == coroutine_suspended) return coroutine_suspended;
            break;
        case 2:
            ResultKt.throwOnFailure($result);
            return Unit.INSTANCE;
        default:
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
    }
}
```

To read it, treat `case 0` as the code from the start of the function to the first suspension, `case 1`
as the code between the first and second suspension, and so on. `$result` in each case holds the value
produced by the *previous* suspension point. Any local variable that must survive a suspension is
promoted to a field on the continuation class, typically named `L$0`, `L$1`, `I$0`, and so on — which is
exactly where you look for secrets at runtime.

> **🔬 Under the Hood**
> The `default` branch throwing `IllegalStateException("call to 'resume' before 'invoke' with coroutine")`
> is a fixed string in the Kotlin compiler. Grepping a DEX for that exact sentence is a fast way to
> count how many suspending code blocks an app contains.

### 15. Why does JADX show a class called `$WhenMappings` that I never wrote?

Because `when` over an `enum` needs to compile to a `tableswitch`, and a `tableswitch` needs dense
integer constants known at compile time. Enum ordinals are not compile-time constants across module
boundaries — recompiling the enum could renumber them — so the compiler generates a lookup array that
is populated at class-initialisation time and indexes into it.

```java
// jadx output
final class WhenMappings {
    public static final int[] $EnumSwitchMapping$0;
    static {
        int[] arr = new int[Status.values().length];
        arr[Status.OK.ordinal()] = 1;
        arr[Status.FAIL.ordinal()] = 2;
        $EnumSwitchMapping$0 = arr;
    }
}
// call site
switch (WhenMappings.$EnumSwitchMapping$0[status.ordinal()]) { case 1: ... case 2: ... }
```

To read the original code, use the static initialiser as your decoder ring: the array assignment tells
you that `case 1` corresponds to `Status.OK` and `case 2` to `Status.FAIL`. Note the mapping is 1-based
because index 0 is reserved for "not one of the handled constants", which becomes the `else` branch.

---

## Security

### 16. Is `!!` a security issue?

By itself, `!!` is a reliability issue, and reliability issues become security issues when an attacker
controls whether they trigger. The operator compiles to `Intrinsics.checkNotNull`, which throws a
`NullPointerException` when the value is null. A thrown exception in an Android app is not memory
corruption and does not give an attacker code execution, so the honest severity is usually low.

It becomes worth reporting when three conditions line up:

| Condition | Why it matters |
|---|---|
| The value comes from outside the app | Intent extras, IPC, network responses, deep links, content providers |
| The crash is reachable by another app or a remote party | An unexported component that only the app itself can reach is not attacker-reachable |
| The crashing component is a service, receiver, or provider | Repeated crashes become a denial of service against a component other apps depend on |

The classic pattern is an exported `Activity` or `BroadcastReceiver` that does
`intent.getStringExtra("id")!!`. Any installed app can send an `Intent` without that extra and crash
the target on demand. If the target is a persistent service — a VPN client, a password manager's
autofill service, a device-management agent — the availability impact is real.

> **🔍 Pentester's Note**
> When triaging, grep the decompiled output for `Intrinsics.checkNotNull(` (the one-argument form, which
> is `!!`, as opposed to `checkNotNullParameter`) and cross-reference each hit against the exported
> components in `AndroidManifest.xml`. See [chapter 26 — Intent](../26-Intent/README.md) for delivery
> and [chapter 30 — Activities](../30-Activities/README.md) for exposure analysis.

### 17. Does R8 or ProGuard remove the `Intrinsics` calls, and does that hurt my analysis?

R8 can remove them, and it often does in release builds, because it recognises `Intrinsics` methods as
side-effect-free assertions when it can prove the argument is non-null. Whether it does depends on the
optimisation level, the `-assumenosideeffects` rules in the project's ProGuard configuration, and how
much of the call graph R8 can see.

In practice, on real-world release APKs you will still find a great many of them, for two reasons. R8
only removes a check when it can *prove* the value is never null, which it usually cannot do for values
crossing a public API or coming from Java. And library code compiled by a third party before shrinking
frequently ships with its checks intact.

Even when the checks are stripped, the other fingerprints remain. `@Metadata` annotations, `Companion`
classes, `INSTANCE` fields, `DefaultConstructorMarker`, and the coroutine state machines are structural
and cannot be optimised away without changing behaviour.

### 18. Can an app hide the fact that it is written in Kotlin?

Not completely, though it can make the evidence thinner. The `@Metadata` annotation can be stripped with
a ProGuard rule, class and method names can be renamed, and `kotlin-stdlib` classes can be repackaged so
that `kotlin/jvm/internal/Intrinsics` becomes something like `a/b/c`. Applications that want to defeat
casual analysis do exactly this.

What survives is structure. A method whose body is a `switch` on an integer field, which returns a
sentinel object obtained from a static getter, and which is invoked from a `resumeWith` override, is a
coroutine state machine no matter what the classes are called. A static nested class with a private
constructor plus a single static instance field on its outer class is a companion object. Data-class
`toString` methods that concatenate field names and values in the exact source order are recognisable
by shape.

> **🧠 Mental Model**
> Names are cheap to change and structure is expensive. Build your Kotlin identification on structural
> patterns and treat names as a convenience, and obfuscation stops mattering nearly as much.
> [Lab 01](labs/lab-01-spot-the-kotlin.md) drills exactly this.

### 19. Why does the app log look like it is leaking data even though nobody wrote a log statement for those fields?

Almost certainly a data class. Kotlin generates `toString()` for every `data class`, and that generated
implementation prints **every property in the primary constructor**, by name, with its value.

```kotlin
// source
data class Session(val userId: String, val authToken: String, val refresh: String)
```

```java
// generated toString, as seen in jadx
public String toString() {
    return "Session(userId=" + this.userId + ", authToken=" + this.authToken +
           ", refresh=" + this.refresh + ")";
}
```

A single `Log.d("net", "$session")` therefore writes the auth token to logcat. The developer wrote one
innocuous-looking line; the compiler supplied the leak. This is one of the most common findings in
Kotlin app reviews and maps to MASVS-STORAGE.

> **🔍 Pentester's Note**
> Search the decompiled output for `toString()` methods whose returned string contains `token`, `key`,
> `password`, `pin`, `secret`, or `session`, then search for call sites that pass the enclosing type to
> any `Log`, `println`, `Timber`, or crash-reporting call. Also check `Crashlytics`-style custom keys,
> which frequently receive whole data-class instances.

### 20. Where do secrets end up hiding in Kotlin code specifically?

There are four places that do not exist in Java and that people therefore forget to check.

| Location | Why it hides things | How to look |
|---|---|---|
| `companion object` private fields | Compiled to `private static final` on the outer class, reached through `access$` bridges | Read the outer class's `<clinit>` and its `access$get...$cp` methods |
| `by lazy` delegates | The value does not exist until first access, so static analysis sees only a lambda | At runtime, read the `Lazy` field's `_value` with Frida after triggering the feature |
| Coroutine continuation fields | Locals alive across a suspension are promoted to `L$0`, `L$1`, … on the continuation object | Hook `resumeWith` and enumerate the continuation's fields |
| Inlined bodies | Constants from an inline function are copied into every caller | Search for the constant, not the function |

### 21. Should I decompile to Kotlin instead of Java? Are there tools that do that?

There are projects that attempt Kotlin-flavoured output, and JADX itself has partial Kotlin
reconstruction (it can restore some `@Metadata`-derived information such as original parameter names).
For assessment work, prefer the Java output anyway.

The reason is fidelity. Java output shows you what actually executes: the synthetic `$default` bridge,
the state machine, the inlined body. Kotlin-reconstructed output shows you a guess at what the developer
wrote, which is friendlier to read but hides exactly the machinery you need to hook. Read the Java, and
keep the Kotlin construct mapping table from [cheatsheet.md](cheatsheet.md) beside you to translate
back mentally.

Do turn on JADX's `--deobf` and its Kotlin metadata options when you want original names; that is
reconstruction of *names*, not of *structure*, and names are pure gain.

### 22. Do coroutines create threads? Is `Dispatchers.IO` a thread per call?

No on both counts, and this trips up almost everyone. A coroutine is a resumable computation, not a
thread. Thousands of coroutines can share a handful of threads, because a suspended coroutine occupies
no thread at all — its state lives in a heap-allocated continuation object, and the thread is returned
to the pool.

`Dispatchers.IO` is a shared elastic thread pool with a default limit of 64 threads (or the number of
CPU cores, whichever is larger). Launching a thousand coroutines on it does not create a thousand
threads; it queues work onto the pool. `Dispatchers.Default` is sized to the CPU count with a minimum
of two, and `Dispatchers.Main` is a single-thread dispatcher backed by the Android main looper described
in [chapter 09 — Android App Internals](../09-Android-App-Internals/README.md).

The practical consequence for dynamic analysis is that thread identity is meaningless inside a
coroutine. Code before and after a single `withContext` boundary can run on different threads, so any
Frida logic that keys state off `Thread.currentThread().getId()` will misbehave. Key off the
continuation object instead.

### 23. What is structured concurrency and why should I care as a reverse engineer?

> **📖 Definition**
> **Structured concurrency** means every coroutine belongs to a `CoroutineScope` and cannot outlive it.
> Cancelling the scope cancels every child; a child's failure propagates to the parent; and the parent
> does not complete until all children have.

You care because it makes the coroutine hierarchy an accurate map of the application's asynchronous
work, and because scope cancellation is a control point. In an Android app the common scopes are
`lifecycleScope` (tied to an `Activity` or `Fragment`), `viewModelScope` (tied to a `ViewModel`), and
custom application scopes. If you can reach and cancel a scope from a hook, you cancel every network
call, poll, and timer inside it — which is a very direct way to neutralise, say, a licence-check loop
or an anti-tamper heartbeat without touching the check itself.

It also explains a common analysis surprise: a suspend function whose work simply stops mid-way with no
exception in the log. That is cancellation, delivered as a `CancellationException` that the framework
deliberately swallows because it is considered normal control flow rather than an error.

### 24. Why does the same Kotlin lambda sometimes appear as a class and sometimes vanish?

Whether a lambda survives compilation depends on whether the function receiving it is `inline`.

| Situation | Result in DEX |
|---|---|
| Passed to an `inline` function | The lambda body is pasted into the caller; no class exists |
| Passed to a non-inline function, captures nothing | A class extending `Lambda` with a static `INSTANCE` field, allocated once |
| Passed to a non-inline function, captures variables | A class extending `Lambda` with fields for the captured values, allocated per call |
| Marked `noinline` inside an inline function | A class, even though the enclosing function is inlined |
| Used as a `suspend` block | A class extending `SuspendLambda` with `invokeSuspend` and a `label` |
| A method reference such as `::foo` | A class extending `FunctionReferenceImpl` |

The names follow a predictable pattern: `Outer$methodName$1`, `Outer$methodName$1$2` for nesting. If you
see `LoginActivity$onCreate$1`, you are looking at the first lambda written inside `onCreate`, and the
captured variables are its fields.

### 25. I hooked a method and the hook fires, but the argument I print is an obfuscated object. How do I read it?

Use the Kotlin-generated members. If it is a data class, `toString()` is generated for you and prints
every property with its original name, so `console.log(obj.toString())` frequently gives you the whole
object in one line even under obfuscation. If it is not a data class, enumerate its fields reflectively:

```javascript
// Frida REPL — dump all fields of an arbitrary object
Java.perform(function () {
    var obj = /* the instance you captured */ null;
    var cls = obj.getClass();
    var fields = cls.getDeclaredFields();
    for (var i = 0; i < fields.length; i++) {
        fields[i].setAccessible(true);
        console.log('  ' + fields[i].getName() + ' = ' + fields[i].get(obj));
    }
});
```

For a continuation object specifically, the interesting fields are `label`, `L$0` through `L$n`, and
`completion`. [Lab 03](labs/lab-03-coroutine-state-machine.md) uses exactly this to recover a token.

---

## Getting set up

### 26. Do I need Android Studio to follow this chapter?

No. Everything in the labs and examples runs from the command line with the standalone Kotlin compiler,
the Android SDK build-tools (for `d8`), JADX, and Frida. Android Studio is convenient for writing apps
and for its bundled decompiler, but it is not required to compile a `.kt` file, turn it into DEX, and
read the result.

The minimum toolchain is listed here for reference.

| Tool | Purpose | Check it works |
|---|---|---|
| JDK 17 or newer | Runs the compiler and the resulting jars | `java -version` |
| `kotlinc` | Compiles Kotlin to class files or a jar | `kotlinc -version` |
| Android SDK build-tools | Provides `d8` for class-to-DEX conversion | `d8 --version` |
| JADX | Decompiles DEX to Java | `jadx --version` |
| `apktool` | Unpacks resources and produces smali | `apktool --version` |
| Python 3 | Runs `scripts/detect-kotlin.py` | `python3 --version` |
| Frida | Runtime instrumentation | `frida --version` |

### 27. `kotlinc` says my jar runs but `java -jar` cannot find the main class. What did I do wrong?

Almost certainly you forgot `-include-runtime`, or you are looking for the wrong class name. A top-level
`fun main()` in `Foo.kt` compiles into a class named `FooKt`, not `Foo` and not `Main`. Either build a
self-contained jar, in which case the manifest records the entry point for you:

```bash
# host
kotlinc Foo.kt -include-runtime -d foo.jar
java -jar foo.jar
```

or compile to class files and name the facade explicitly, remembering to put the stdlib on the
classpath:

```bash
# host
kotlinc Foo.kt -d out/
java -cp out/:$KOTLIN_HOME/lib/kotlin-stdlib.jar FooKt
```

If you used `@file:JvmName("Application")` at the top of the file, the class is `Application`, not
`FooKt` — which is itself a small reminder of how much the compiler moves things around.

---

## See also

- [cheatsheet.md](cheatsheet.md) — the mapping tables referenced throughout these answers.
- [mindmap.md](mindmap.md) — where each of these topics sits in the chapter.
- [labs/](labs/) — three hands-on exercises that make these answers concrete.
- [../04-Java/faq.md](../04-Java/faq.md) — the Java questions that come logically before these.
