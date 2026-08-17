# Kotlin — Cheat Sheet

Printable reference for chapter [05 — Kotlin](README.md). Companion chapters:
[04 — Java](../04-Java/README.md), [12 — DEX Internals](../12-DEX-Internals/README.md),
[13 — ART](../13-ART/README.md).

---

## 1. Kotlin construct to JVM/DEX construct mapping

| Kotlin construct | What the compiler actually emits | What you see in JADX |
|---|---|---|
| `val x: Int = 1` (local) | Local slot, no accessor | `int x = 1;` |
| `val x: Int` (property) | Private field + `getX()` | `private final int x;` and `public final int getX()` |
| `var x: Int` (property) | Private field + `getX()` + `setX(int)` | `private int x;` plus both accessors |
| `@JvmField val x` | Public field, no accessor | `public final int x;` |
| `const val X = 1` | `public static final` constant, inlined at use sites | `public static final int X = 1;` and literal `1` at call sites |
| Top-level `fun foo()` in `Utils.kt` | Class `UtilsKt` with `public static foo()` | `public final class UtilsKt { public static void foo() }` |
| `@file:JvmName("U")` | Renames that class to `U` | `public final class U { ... }` |
| `fun f(a: Int, b: Int = 2)` | `f(int,int)` + synthetic `f$default(int,int,int,Object)` | Calls become `f$default(a, 0, 2, null)` |
| Named arguments | Nothing — resolved at compile time | Positional args only; names are gone |
| `data class P(val a: Int)` | Class + `equals`/`hashCode`/`toString`/`copy`/`copy$default`/`component1` | All six methods present, `toString` returns `"P(a=" + a + ")"` |
| `sealed class S` | Abstract class, private/protected constructor, `DefaultConstructorMarker` param | `public abstract class S { private S() {} ... S(DefaultConstructorMarker m) { this(); } }` |
| `enum class E` + `when(e)` | Adds a synthetic class `$WhenMappings` with `int[] $EnumSwitchMapping$0` | `switch (WhenMappings.$EnumSwitchMapping$0[e.ordinal()])` |
| `object Singleton` | Final class with `public static final Singleton INSTANCE` initialised in `<clinit>` | `Singleton.INSTANCE.method()` at call sites |
| `companion object` | Static nested class `Companion` + `private static final` outer field | `public static final Foo$Companion Companion;` |
| `companion object Named` | Static nested class with that name | `Foo$Named` |
| `fun String.shout(): String` | `public static String shout(String $this$shout)` on `FileNameKt` | Receiver becomes parameter 1, not a member of `String` |
| Extension property | Static getter taking receiver as first parameter | `public static int getLen(String $this$len)` |
| Lambda `{ ... }` | Class implementing `Function0..FunctionN`, or invokedynamic on newer targets | `new Foo$bar$1()` extending `Lambda` / `FunctionReferenceImpl` |
| Non-capturing lambda | Singleton lambda class with `INSTANCE` | `Foo$bar$1.INSTANCE` |
| `inline fun` | Body copied into every caller; no method call remains | Caller contains the body verbatim; the function may still exist as a public copy |
| `crossinline` / `noinline` | Controls whether the lambda is inlined too | `noinline` lambdas still appear as `Function` objects |
| `reified T` | Only usable from `inline`; type baked into caller as a class literal | `Object.class` / `String.class` literals appear at call sites |
| `suspend fun f(): T` | `f(Continuation<? super T>)` returning `Object` | Extra last parameter `Continuation`, return type becomes `Object` |
| `suspend` lambda / body | Class extending `SuspendLambda`/`ContinuationImpl` with `invokeSuspend` and `int label` | `invokeSuspend`, `switch (this.label)`, `IntrinsicsKt.getCOROUTINE_SUSPENDED()` |
| `by lazy { }` | Field of type `Lazy`, `LazyKt.lazy(...)`, `getX()` calls `.getValue()` | `private final Lazy x$delegate;` |
| `by SomeInterface` (delegation) | Field holding delegate + forwarding methods generated per interface method | Every interface method forwards to `this.$$delegate_0` |
| `by Delegates.observable` | `ObservableProperty` subclass field, `getValue`/`setValue` calls | `ReadWriteProperty` field plus `KProperty[]` array |
| `lateinit var x: T` | Nullable field + null check on read | `throwUninitializedPropertyAccessException("x")` |
| `internal` visibility | `public` with name mangling `foo$module_name` | `public final void foo$app_debug()` |
| Nested private access from inner class | Synthetic `access$getFoo$p(Outer)` bridge | `access$` prefixed static methods |
| `String` template `"$a b"` | `StringBuilder` chain, or `Intrinsics.stringPlus` for two operands | `new StringBuilder().append(a).append(" b").toString()` |
| `Int?` | `java.lang.Integer` (boxed) | `Integer` instead of `int` |
| `Nothing` / `TODO()` | `throw new NotImplementedError(...)` | Method ends in an unconditional throw |

---

## 2. Null-safety operators

| Syntax | Name | Meaning | Emitted code |
|---|---|---|---|
| `T` | Non-null type | Value can never be null | `@NotNull` annotation + `Intrinsics.checkNotNullParameter` on public entry |
| `T?` | Nullable type | Value may be null | `@Nullable` annotation, no check |
| `T!` | Platform type | Nullability unknown, from Java | **No check at all** — nothing is emitted |
| `a?.b` | Safe call | Evaluate `b` only if `a != null`, else `null` | `if (a != null) a.b() else null` |
| `a?.b ?: c` | Safe call + Elvis | Fall back to `c` when null | `x = a != null ? a.b() : c` |
| `a ?: throw E()` | Elvis throw | Fail fast on null | `if (a == null) throw new E();` |
| `a!!` | Not-null assertion | Crash if null | `Intrinsics.checkNotNull(a)` then use |
| `a?.let { }` | Safe scope call | Run block only if non-null | Null check plus a lambda or inlined body |
| `as?` | Safe cast | `null` instead of `ClassCastException` | `x instanceof T ? (T) x : null` |
| `lateinit var` | Deferred init | Non-null property initialised later | `throwUninitializedPropertyAccessException` on unset read |
| `?.let { } ?: run { }` | Null branch | If/else on nullability | Two branches, both inlined |

---

## 3. `kotlin.jvm.internal.Intrinsics` methods and what each one tells you

Package: `kotlin/jvm/internal/Intrinsics`. Presence of **any** of these in a DEX proves Kotlin.

| Method | Signature (JVM) | Emitted when | What it tells the analyst |
|---|---|---|---|
| `checkNotNullParameter` | `(Object, String)V` | First lines of any `public`/`protected` function with a non-null parameter | Names the **original Kotlin parameter name** even after ProGuard renames methods |
| `checkNotNullExpressionValue` | `(Object, String)V` | After a call to a Java/platform API whose result is used as non-null | The `String` argument is the **original expression source text** |
| `checkNotNull` | `(Object)V` / `(Object,String)V` | From `!!` | Marks a developer's manual not-null assertion — an attacker-reachable crash point |
| `checkNotNullExpressionValue` vs `checkExpressionValueIsNotNull` | Both exist | Old name used by Kotlin < 1.4 | Cheap way to fingerprint the compiler generation |
| `checkParameterIsNotNull` | `(Object, String)V` | Kotlin < 1.4 name for `checkNotNullParameter` | Same fingerprinting value |
| `throwUninitializedPropertyAccessException` | `(String)V` | Reading a `lateinit` property before assignment | Names the property; a reliable crash oracle |
| `throwNpe` / `throwJavaNpe` | `()V` | Older `!!` lowering | Legacy compiler |
| `areEqual` | `(Object,Object)Z` | `==` on nullable references | Null-safe `equals`; **not** reference identity |
| `compare` | `(II)I`, `(JJ)I` | `compareTo` on primitives | Ordinary numeric comparison |
| `stringPlus` | `(String,Object)String` | `"a" + x` with exactly two operands | Concatenation without a `StringBuilder` |
| `checkHasClass` | `(String)V` | Multiplatform / optional dependency guards | Optional runtime dependency present |
| `checkNotNullReturnValue` | `(Object,String)V` | Non-null return from an overridden platform method | Return contract enforcement |

> Rule of thumb: `checkNotNullParameter` argument strings survive most obfuscation because they are
> string constants, so they leak original parameter names even when class and method names are `a`, `b`, `c`.

---

## 4. Scope functions

| Function | Receiver inside block | Argument form | Returns | Typical use |
|---|---|---|---|---|
| `let` | `it` (lambda parameter) | `x.let { it }` | Lambda result | Null-safe transform, scoping a temp |
| `run` | `this` | `x.run { }` | Lambda result | Compute a value using the object's members |
| `run` (no receiver) | none | `run { }` | Lambda result | Group statements into an expression |
| `with` | `this` | `with(x) { }` | Lambda result | Many calls on one object |
| `apply` | `this` | `x.apply { }` | The receiver `x` | Configure and return an object |
| `also` | `it` | `x.also { }` | The receiver `x` | Side effect such as logging, keep the value |
| `takeIf` | `it` | `x.takeIf { }` | `x` or `null` | Conditional null |
| `takeUnless` | `it` | `x.takeUnless { }` | `x` or `null` | Inverted conditional null |

All eight are `inline`, so **none of them exist as a call in the DEX** — their bodies are pasted into the caller.

---

## 5. JADX fingerprints — is this class Kotlin?

| Fingerprint | Where it appears | Confidence |
|---|---|---|
| `@Metadata(mv = {...}, k = 1, xi = ..., d1 = {...}, d2 = {...})` | Class annotation | Certain — emitted on every Kotlin class |
| `@Metadata(k = 2)` | Class annotation | Certain — a file facade (`FooKt`) |
| `@Metadata(k = 3)` | Class annotation | Certain — a synthetic class such as a lambda |
| `kotlin/jvm/internal/Intrinsics` in string pool | DEX strings | Certain |
| `Intrinsics.checkNotNullParameter(x, "x")` | First lines of methods | Certain |
| `kotlin/Unit`, `Unit.INSTANCE` | Return values of void lambdas | Certain |
| `DefaultConstructorMarker` | Extra constructor parameter | Certain — default args or sealed class |
| `$default` suffix (`foo$default`) | Static synthetic methods | Certain — default arguments |
| Inner class named `Companion` | Nested class | Certain — `companion object` |
| `public static final X INSTANCE` in `<clinit>` | Static field | Strong — `object` declaration |
| `extends kotlin.jvm.internal.Lambda` | Class hierarchy | Certain — a capturing lambda |
| `implements Function0` … `FunctionN` | Class hierarchy | Certain |
| `FunctionReferenceImpl`, `PropertyReference1Impl` | Class hierarchy | Certain — `::foo` references |
| `$WhenMappings` with `$EnumSwitchMapping$0` | Nested synthetic class | Certain — `when` over an enum |
| `access$getFoo$p`, `access$setFoo$p` | Static synthetic methods | Strong — private member touched from a nested class |
| `Continuation`, `ContinuationImpl`, `SuspendLambda` | Class hierarchy / parameters | Certain — coroutines |
| `invokeSuspend(Object)` + `int label` + `switch (this.label)` | Method body | Certain — suspend state machine |
| `IntrinsicsKt.getCOROUTINE_SUSPENDED()` | Method body | Certain — coroutines |
| `Reflection.getOrCreateKotlinClass` | Method body | Strong — `::class` used |
| `KProperty[] $$delegatedProperties` | Static field | Certain — property delegation |
| `this.$$delegate_0` | Instance field | Certain — interface delegation `by` |
| `kotlin-stdlib` classes under `kotlin/` in the DEX | Package listing | Strong (may be absent if only `-jvm` subset shipped) |
| `NotImplementedError` | Thrown | Strong — `TODO()` left in production |
| Method name mangling `foo$app_release` | Method names | Strong — `internal` visibility |

---

## 6. Coroutines — builders, dispatchers, jobs

| Builder | Scope required | Returns | Blocks caller | Notes |
|---|---|---|---|---|
| `launch { }` | `CoroutineScope` | `Job` | No | Fire and forget; exceptions propagate to parent |
| `async { }` | `CoroutineScope` | `Deferred<T>` | No | Result via `await()`; exception deferred to `await()` |
| `runBlocking { }` | none (creates one) | `T` | **Yes** | Bridge from blocking code; never on the Android main thread |
| `withContext(ctx) { }` | inside `suspend` | `T` | Suspends | Switch dispatcher without a new coroutine |
| `coroutineScope { }` | inside `suspend` | `T` | Suspends | Fails all children if one fails |
| `supervisorScope { }` | inside `suspend` | `T` | Suspends | Child failure does not cancel siblings |
| `flow { }` | none | `Flow<T>` | No | Cold stream; nothing runs until collected |
| `produce { }` | `CoroutineScope` | `ReceiveChannel<T>` | No | Hot channel-backed stream |

| Dispatcher | Backing threads | Use for |
|---|---|---|
| `Dispatchers.Main` | Android main/UI looper | UI updates |
| `Dispatchers.Main.immediate` | Main, without re-dispatch if already there | Avoiding a frame delay |
| `Dispatchers.Default` | CPU-count-sized pool (min 2) | CPU-bound work |
| `Dispatchers.IO` | Elastic pool, default 64 threads | Disk and network |
| `Dispatchers.Unconfined` | Caller's thread until first suspension | Testing and advanced cases only |
| `newSingleThreadContext` | One dedicated thread | Serialised access; must be closed |

| Job API | Effect |
|---|---|
| `job.cancel()` | Requests cancellation; cooperative only |
| `job.cancelAndJoin()` | Cancels and waits for completion |
| `job.join()` | Suspends until finished |
| `job.isActive` / `isCompleted` / `isCancelled` | State query |
| `SupervisorJob()` | Child failure does not cancel the parent |
| `NonCancellable` | Context for cleanup that must run after cancellation |
| `ensureActive()` / `yield()` | Cancellation check points inside a loop |

| Flow operator | Behaviour |
|---|---|
| `map`, `filter`, `transform` | Per-element, runs in the collector's context |
| `flowOn(ctx)` | Changes the context of **upstream** operators only |
| `collect { }` | Terminal; a `suspend` call |
| `stateIn` / `shareIn` | Cold to hot conversion |
| `catch { }` | Upstream exception handling |
| `buffer`, `conflate` | Backpressure strategies |

---

## 7. Java interop annotations

| Annotation | Applied to | Effect on emitted bytecode | Why a pentester cares |
|---|---|---|---|
| `@JvmStatic` | Member of `object` / `companion object` | Adds a real `static` method on the outer class | Hook target becomes `Outer.method` instead of `Outer$Companion.method` |
| `@JvmField` | Property | Exposes a public field, removes getter/setter | Frida reads the field directly; no accessor to hook |
| `@JvmOverloads` | Function with default arguments | Generates one real overload per default parameter | Multiple overloads appear; `Java.use` needs `.overload(...)` |
| `@JvmName("x")` | Function / file / getter | Renames the JVM symbol | Kotlin name and DEX name differ |
| `@file:JvmName("X")` | File | Renames `FooKt` to `X` | Facade class name is not derivable from the filename |
| `@file:JvmMultifileClass` | File | Merges several files into one facade | Methods from many sources in one class |
| `@Throws(E::class)` | Function | Adds a `throws` clause to the method descriptor | Only affects Java callers |
| `@JvmSuppressWildcards` / `@JvmWildcard` | Types | Controls generic wildcard emission | Changes the exact overload signature |
| `@JvmInline value class` | Class | Erased to its single underlying field; methods get mangled names `foo-impl` | Parameters look like `String` not the wrapper |
| `@Volatile`, `@Synchronized` | Field / function | Maps to `volatile` / `ACC_SYNCHRONIZED` | Concurrency review |

---

## 8. Command reference

### Compile and run Kotlin on the host

```bash
# host — compile a single file to a jar and run it
kotlinc NullSafetyDemo.kt -include-runtime -d demo.jar
java -jar demo.jar

# host — script-style run without producing a jar
kotlin NullSafetyDemo.kt

# host — compile to a directory of .class files (better for decompiler study)
kotlinc DecompiledComparison.kt -d out/

# host — compile with coroutines on the classpath
kotlinc CoroutinesDemo.kt -cp kotlinx-coroutines-core-jvm-1.8.1.jar:kotlin-stdlib.jar -include-runtime -d coro.jar
java -cp coro.jar:kotlinx-coroutines-core-jvm-1.8.1.jar CoroutinesDemoKt

# host — see the JVM bytecode the compiler produced
javap -p -c -v -cp out/ FooKt

# host — keep parameter names and disable optimisations for readable output
kotlinc Foo.kt -d out/ -Xno-optimize -java-parameters
```

### Turn class files into DEX and back

```bash
# host — d8 ships with the Android SDK build-tools
d8 --output . out/*.class --lib $ANDROID_HOME/platforms/android-34/android.jar
# produces classes.dex

# host — release-mode d8 (this is what shrinks and changes what you see)
d8 --release --min-api 24 --output . out/*.class

# host — disassemble a DEX to smali
baksmali d classes.dex -o smali_out/

# host — reassemble smali to DEX
smali a smali_out/ -o classes.new.dex
```

### Decompile and inspect

```bash
# host — full APK decompile to Java-like source
jadx -d out_jadx target.apk

# host — decompile a single dex/jar, no resources, deobfuscate names
jadx --no-res --deobf -d out_jadx classes.dex

# host — GUI
jadx-gui target.apk

# host — resources plus smali
apktool d target.apk -o out_apktool
apktool b out_apktool -o rebuilt.apk

# host — list DEX classes without decompiling
unzip -l target.apk | grep -E 'classes.*\.dex'
```

### Grep patterns that prove Kotlin

```bash
# host — on jadx output
grep -rl "kotlin.Metadata" out_jadx/sources/ | wc -l
grep -rn "Intrinsics.checkNotNullParameter" out_jadx/sources/ | head
grep -rn "IntrinsicsKt.getCOROUTINE_SUSPENDED" out_jadx/sources/
grep -rn "\$WhenMappings" out_jadx/sources/
grep -rn "DefaultConstructorMarker" out_jadx/sources/

# host — on the raw APK, no decompilation needed
strings -a target.apk | grep -c "kotlin/jvm/internal/Intrinsics"
unzip -p target.apk classes.dex | strings -a | grep -E "checkNotNullParameter|COROUTINE_SUSPENDED"

# host — the scripted version in this chapter
python3 scripts/detect-kotlin.py target.apk

# host — smali-level
grep -rn "Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter" out_apktool/smali*/
grep -rn "invokeSuspend" out_apktool/smali*/
```

### Frida quick invocations

```bash
# host — spawn and inject the chapter's hook script
frida -U -f com.target -l scripts/hook-kotlin.js

# host — attach to a running process instead
frida -U -n "App Name" -l scripts/hook-kotlin.js

# host — no pause on spawn
frida -U -f com.target -l scripts/hook-kotlin.js --no-pause
```

```javascript
// Frida REPL — one-liners for Kotlin targets
Java.perform(() => { Java.use('kotlin.jvm.internal.Intrinsics').checkNotNullParameter.overload('java.lang.Object','java.lang.String').implementation = function(){}; });
Java.perform(() => { console.log(Java.use('com.target.Config').INSTANCE.value()); });     // object declaration
Java.perform(() => { console.log(Java.use('com.target.Foo$Companion').$className); });    // companion object
Java.perform(() => { Java.choose('com.target.User', { onMatch: o => console.log(o.toString()), onComplete(){} }); }); // data class toString
```

### Smali shapes worth memorising

| Smali line | Kotlin origin |
|---|---|
| `invoke-static {p1, v0}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter(Ljava/lang/Object;Ljava/lang/String;)V` | Non-null parameter |
| `sget-object v0, Lcom/x/Foo;->INSTANCE:Lcom/x/Foo;` | `object` declaration |
| `sget-object v0, Lcom/x/Foo;->Companion:Lcom/x/Foo$Companion;` | `companion object` |
| `invoke-static {v0, v1, v2, v3, v4}, Lcom/x/FooKt;->bar$default(...)` | Default arguments |
| `iget v0, p0, Lcom/x/Foo$run$1;->label:I` then `packed-switch` | Coroutine state machine |
| `invoke-static {}, Lkotlin/coroutines/intrinsics/IntrinsicsKt;->getCOROUTINE_SUSPENDED()Ljava/lang/Object;` | Suspension point |

---

## 9. Quick decision table — "what do I do with this decompiled method?"

| You see | It means | Next step |
|---|---|---|
| `Intrinsics.checkNotNullParameter(a, "token")` | Parameter was named `token` in source | Use the string names to rebuild the API contract |
| `foo$default(x, null, 2, null)` | Caller used defaults | The `int` argument is a bitmask of which parameters were omitted |
| `switch (this.label)` inside `invokeSuspend` | Suspend function body | Each `case` is the code between two suspension points |
| No method body at the call site, code pasted inline | `inline fun` | You cannot hook it; hook its callee or patch the caller |
| `Foo$Companion.access$getSecret$cp(...)` | Private companion state read | The real value lives in a static field on `Foo` |
| `WhenMappings.$EnumSwitchMapping$0[e.ordinal()]` | `when` over enum | Map ordinals back to enum constant names |
| `throw new NotImplementedError` | `TODO()` shipped | Dead or unreachable feature branch |
| `Lazy` field plus `getValue()` | `by lazy` | The initialiser runs once, on first access |
