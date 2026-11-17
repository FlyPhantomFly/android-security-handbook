# Lab 01 — Spot the Kotlin

Part of chapter [05 — Kotlin](../README.md). Sits alongside
[lab 02](lab-02-null-safety-in-jadx.md) and [lab 03](lab-03-coroutine-state-machine.md).

---

## Objective

Given a compiled artefact that mixes Java and Kotlin sources, decide **with certainty and without
guessing** which classes were written in Kotlin, and state the specific evidence for each decision.

By the end you will be able to look at any decompiled class and answer "Kotlin or Java?" in a few
seconds, using five independent signals: the `@Metadata` annotation, `Intrinsics` calls, the `Companion`
nested class, the `INSTANCE` static field, and `DefaultConstructorMarker` parameters. You will also
understand which of those signals survive obfuscation and which do not, which matters because the real
APKs you assess will be obfuscated.

> **Mental Model**
> The compiler cannot hide its own footprints. Every convenience Kotlin gives the developer costs some
> generated code, and generated code has a fixed shape. You are learning to read a signature, not to
> guess a style.

---

## Prerequisites

- [Chapter 04 — Java](../../04-Java/README.md), specifically how a `.java` file becomes a `.class` file.
- [Chapter 12 — DEX Internals](../../12-DEX-Internals/README.md) is helpful but not required.
- Comfort running commands in a terminal. If `cd`, `ls`, and paths are unfamiliar, revisit
  [chapter 02 — Linux Basics](../../02-Linux-Basics/README.md) first.

| Tool | Minimum version | Verify with |
|---|---|---|
| JDK | 17 | `java -version` |
| `kotlinc` | 1.9 | `kotlinc -version` |
| `javac` | 17 | `javac -version` |
| JADX | 1.4 | `jadx --version` |
| Python 3 | 3.8 | `python3 --version` |

**Estimated time:** 45 to 60 minutes.

---

## Setup

Create a working directory and two source files — one Java, one Kotlin — that deliberately contain the
constructs you are learning to recognise.

```bash
# host
mkdir -p ~/kotlin-lab-01/src && cd ~/kotlin-lab-01
```

Write the Java half first.

```java
// host — save as ~/kotlin-lab-01/src/LegacyStore.java
package com.example.mixed;

import java.util.HashMap;
import java.util.Map;

public class LegacyStore {
    private static final LegacyStore SHARED = new LegacyStore();
    private final Map<String, String> data = new HashMap<>();

    private LegacyStore() { }

    public static LegacyStore getShared() { return SHARED; }

    public void put(String key, String value) {
        if (key == null) { throw new IllegalArgumentException("key"); }
        data.put(key, value);
    }

    public String get(String key) { return data.get(key); }
}
```

Now the Kotlin half. Every construct here maps to something you will hunt for in the decompiled output.

```kotlin
// host — save as ~/kotlin-lab-01/src/ModernStore.kt
package com.example.mixed

// 1. data class -> generated equals/hashCode/toString/copy/componentN
data class Credential(val user: String, val token: String, val expires: Long = 0L)

// 2. sealed class -> private constructor plus DefaultConstructorMarker
sealed class Result {
    data class Ok(val value: String) : Result()
    data class Err(val reason: String) : Result()
}

// 3. object declaration -> static INSTANCE field
object Clock {
    fun now(): Long = System.currentTimeMillis()
}

// 4. class with a companion object -> nested Companion class
class ModernStore private constructor() {
    private val entries = mutableMapOf<String, Credential>()

    // 5. non-null parameters -> Intrinsics.checkNotNullParameter
    fun save(key: String, cred: Credential) {
        entries[key] = cred
    }

    // 6. default argument -> synthetic load$default bridge
    fun load(key: String, fallback: Credential? = null): Result {
        val found = entries[key] ?: fallback ?: return Result.Err("missing")
        return Result.Ok(found.token)
    }

    companion object {
        private const val VERSION = 3
        fun create(): ModernStore = ModernStore()
        fun version(): Int = VERSION
    }
}

// 7. extension function -> static method on ModernStoreKt taking the receiver first
fun String.masked(): String = if (length <= 4) "****" else take(2) + "****" + takeLast(2)

// 8. top-level main -> class ModernStoreKt
fun main() {
    val s = ModernStore.create()
    s.save("a", Credential("alice", "abcdef123456"))
    println(s.load("a"))
    println("abcdef123456".masked())
    println(Clock.now())
    println(ModernStore.version())
    LegacyStore.getShared().put("j", "from java")
    println(LegacyStore.getShared().get("j"))
}
```

Compile both halves into one jar. The Kotlin compiler is told about the Java sources so it can resolve
`LegacyStore`, and `javac` is then told about the Kotlin output so the reverse direction resolves too.

```bash
# host
mkdir -p out
kotlinc src/ModernStore.kt src/LegacyStore.java -include-runtime -d mixed.jar
```

If `kotlinc` refuses the mixed input on your version, compile in two passes instead.

```bash
# host — two-pass fallback
kotlinc src/ModernStore.kt src/LegacyStore.java -d out/
javac -cp out/ -d out/ src/LegacyStore.java
cd out && jar cf ../mixed.jar . && cd ..
```

Confirm the jar runs before you decompile anything. An artefact you have not executed is an artefact you
cannot reason about.

```bash
# host
java -jar mixed.jar
```

---

## Steps

### Step 1 — Inventory the classes before decompiling

List the class files inside the jar. Do this first, because the *set of class names* is itself evidence.

```bash
# host
unzip -l mixed.jar | grep -E '^\s+[0-9]+.*com/example/mixed' | awk '{print $4}'
```

Record which names you did not write. Write down your prediction for what each one is before you look
inside. You should see roughly eleven entries for a two-file project, and that ratio alone is a signal.

### Step 2 — Decompile with JADX

```bash
# host
jadx --no-res -d jadx_out mixed.jar
ls jadx_out/sources/com/example/mixed/
```

JADX will warn about a few synthetic constructs. Warnings are normal here and are not a sign that
anything is wrong.

### Step 3 — Signal one: the `@Metadata` annotation

This is the strongest and simplest signal. Every class the Kotlin compiler produces carries
`kotlin.Metadata`; no class `javac` produces ever does.

```bash
# host
grep -rl "kotlin.Metadata" jadx_out/sources/com/example/mixed/
grep -rL "kotlin.Metadata" jadx_out/sources/com/example/mixed/
```

The first command lists Kotlin-origin classes. The second lists everything else, which should be
`LegacyStore.java` and nothing more.

Open one hit and look at the annotation itself.

```java
// jadx_out/sources/com/example/mixed/Credential.java — expected shape
@Metadata(d1 = {"\u0000...\n"}, d2 = {"Lcom/example/mixed/Credential;", "", "user", "",
          "token", "expires", "", "(Ljava/lang/String;Ljava/lang/String;J)V", ...},
          k = 1, mv = {1, 9, 0}, xi = 48)
public final class Credential { ... }
```

Read the fields as follows.

| Field | Meaning | Values you will see |
|---|---|---|
| `k` | Kind of class | `1` a real class, `2` a file facade such as `ModernStoreKt`, `3` a synthetic class such as a lambda, `4` a multifile facade part, `5` a multifile facade |
| `mv` | Metadata version, tracking the compiler generation | `{1, 9, 0}` for Kotlin 1.9 |
| `d1` | Encoded declaration data | An escaped binary blob; not human-readable |
| `d2` | String table for `d1` | **Human-readable**: original names, JVM signatures, parameter names |
| `xi` | Extra integer flags | `48` is common on modern releases |

> **Pentester's Note**
> The `d2` array is a free gift. Even when R8 has renamed the class to `a` and the methods to `b` and
> `c`, the `d2` strings often still contain the original Kotlin names and signatures, because the
> default shrinker rules do not rewrite annotation string constants unless explicitly told to. Read
> `d2` before you read any code.

### Step 4 — Signal two: `Intrinsics` calls

```bash
# host
grep -rn "Intrinsics\." jadx_out/sources/com/example/mixed/ | head -30
```

Open `ModernStore.java` and find `save`. The expected shape is this.

```java
// jadx_out/sources/com/example/mixed/ModernStore.java — expected shape
public final void save(String key, Credential cred) {
    Intrinsics.checkNotNullParameter(key, "key");
    Intrinsics.checkNotNullParameter(cred, "cred");
    this.entries.put(key, cred);
}
```

Note what the second argument gives you: the original Kotlin parameter names, `key` and `cred`, as
string constants. Write down every distinct string you find across the whole output. That list is a
partial reconstruction of the application's API surface.

Now look at `Credential.equals`, which shows the other `Intrinsics` method you must recognise.

```java
// expected shape — generated by the data class
public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof Credential)) return false;
    Credential c = (Credential) other;
    if (!Intrinsics.areEqual(this.user, c.user)) return false;
    if (!Intrinsics.areEqual(this.token, c.token)) return false;
    return this.expires == c.expires;
}
```

`Intrinsics.areEqual` is a null-safe `equals`, not reference identity. Reading it as `==` is a common
beginner mistake.

### Step 5 — Signal three: the `Companion` nested class

```bash
# host
ls jadx_out/sources/com/example/mixed/ | grep -i companion
grep -rn "Companion" jadx_out/sources/com/example/mixed/ModernStore.java
```

Expected shape:

```java
// expected shape
public final class ModernStore {
    public static final Companion Companion = new Companion(null);
    private static final int VERSION = 3;
    private final Map<String, Credential> entries = new LinkedHashMap();

    private ModernStore() { }

    public /* synthetic */ ModernStore(DefaultConstructorMarker $constructor_marker) {
        this();
    }

    public static final /* synthetic */ int access$getVERSION$cp() {
        return VERSION;
    }

    public static final class Companion {
        private Companion() { }
        public /* synthetic */ Companion(DefaultConstructorMarker $constructor_marker) {
            this();
        }
        public final ModernStore create() {
            return new ModernStore(null);
        }
        public final int version() {
            return ModernStore.access$getVERSION$cp();
        }
    }
}
```

Three things to internalise here. The companion's members are *instance* methods on a nested class, not
statics on the outer class, unless `@JvmStatic` was used. The private constant `VERSION` is reached
through a synthetic bridge named `access$getVERSION$cp`, where `cp` means "companion property". And the
private constructor is paired with a synthetic one taking `DefaultConstructorMarker`.

### Step 6 — Signal four: `INSTANCE` and the object declaration

```bash
# host
cat jadx_out/sources/com/example/mixed/Clock.java
```

```java
// expected shape
public final class Clock {
    public static final Clock INSTANCE = new Clock();

    private Clock() { }

    public final long now() {
        return System.currentTimeMillis();
    }
}
```

The recognisable pattern is a final class, a private constructor, and a `public static final` field of
the class's own type, assigned in the static initialiser. Call sites read `Clock.INSTANCE.now()`.

Be careful: this is also how a hand-written Java singleton looks, which is why `LegacyStore` in this lab
uses `SHARED` rather than `INSTANCE`. On its own the field name is suggestive, not conclusive; combine
it with `@Metadata` before you commit.

### Step 7 — Signal five: `DefaultConstructorMarker` and `$default` bridges

```bash
# host
grep -rn "DefaultConstructorMarker\|\$default" jadx_out/sources/com/example/mixed/
```

Look at `Credential`, which has a defaulted third parameter, and at `ModernStore.load`.

```java
// expected shape — the default-argument bridge on a constructor
public /* synthetic */ Credential(String user, String token, long expires, int i, DefaultConstructorMarker m) {
    this(user, token, (i & 4) != 0 ? 0L : expires);
}
```

```java
// expected shape — the default-argument bridge on a method
public static /* synthetic */ Result load$default(ModernStore store, String key,
                                                  Credential fallback, int i, Object obj) {
    if (obj != null) {
        throw new UnsupportedOperationException(
            "Super calls with default arguments not supported in this target, function: load");
    }
    if ((i & 2) != 0) { fallback = null; }
    return store.load(key, fallback);
}
```

Decode the `int` at a call site. It is a bitmask where bit *n* set means "parameter *n* was omitted".
A call written `Credential("alice", "abc")` becomes `new Credential("alice", "abc", 0L, 4, null)`,
because bit 2 (value `4`) marks the third parameter as defaulted.

### Step 8 — Signal six: the file facade and the extension function

```bash
# host
cat jadx_out/sources/com/example/mixed/ModernStoreKt.java
```

```java
// expected shape
public final class ModernStoreKt {
    public static final String masked(String $this$masked) {
        Intrinsics.checkNotNullParameter($this$masked, "$this$masked");
        if ($this$masked.length() <= 4) {
            return "****";
        }
        return StringsKt.take($this$masked, 2) + "****" + StringsKt.takeLast($this$masked, 2);
    }

    public static final void main() { ... }

    public static void main(String[] strArr) { main(); }
}
```

The class name `ModernStoreKt` exists nowhere in your source. It is the *file facade*: the compiler's
home for top-level declarations, named after the file with `Kt` appended. The extension function is a
static method whose first parameter is named `$this$masked`. This is why searching the `String` class
for `masked` finds nothing.

### Step 9 — Build the verdict table

Produce a table like this for every class in the output, and fill the evidence column with a specific
signal rather than an impression.

| Class | Origin | Primary evidence | Secondary evidence |
|---|---|---|---|
| `LegacyStore` | Java | No `@Metadata` | No `Intrinsics` call anywhere |
| `Credential` | Kotlin | `@Metadata(k = 1)` | `component1`, `copy$default`, `Intrinsics.areEqual` |
| `Result` | Kotlin | `@Metadata(k = 1)` | Abstract, private constructor, `DefaultConstructorMarker` |
| `Result$Ok` | Kotlin | `@Metadata(k = 1)` | Data-class members, extends `Result` |
| `Result$Err` | Kotlin | `@Metadata(k = 1)` | Data-class members |
| `Clock` | Kotlin | `@Metadata(k = 1)` | `public static final Clock INSTANCE` |
| `ModernStore` | Kotlin | `@Metadata(k = 1)` | `Companion` field, `access$getVERSION$cp` |
| `ModernStore$Companion` | Kotlin | `@Metadata(k = 1)` | Nested, private constructor, marker overload |
| `ModernStoreKt` | Kotlin | `@Metadata(k = 2)` | Static-only, extension with `$this$masked` |

### Step 10 — Repeat against a real APK

Everything above was on a jar you built, where you knew the answer. Now do it blind.

```bash
# host — pull any installed app from a connected device
adb shell pm list packages | head -40
adb shell pm path com.some.package
adb pull /data/app/.../base.apk target.apk

# host — score it without decompiling
python3 ../Android-Security-Handbook/05-Kotlin/scripts/detect-kotlin.py target.apk

# host — then confirm with jadx
jadx --no-res -d apk_out target.apk
grep -rl "kotlin.Metadata" apk_out/sources/ | wc -l
grep -rl "kotlin.Metadata" apk_out/sources/com/some/package/ | wc -l
```

Compare the two counts. The first includes bundled Kotlin libraries; the second tells you whether the
*application's own* code is Kotlin. Reporting "this app is Kotlin" because a bundled library is Kotlin
is a mistake that will cost you credibility.

---

## Hints

<details>
<summary>Hint 1 — I get no output from the grep commands</summary>

Check your paths. JADX writes decompiled Java under `<outdir>/sources/`, and resources under
`<outdir>/resources/`. If you used `-d jadx_out`, your sources are in
`jadx_out/sources/com/example/mixed/`. Also confirm the decompile actually succeeded by listing the
directory rather than assuming it exists.
</details>

<details>
<summary>Hint 2 — JADX shows a class I cannot open, or shows an error comment</summary>

JADX falls back to a comment containing raw smali when it cannot reconstruct Java for a method. This
happens with some synthetic bridges. It is not a failure: the smali is often *more* informative. If it
bothers you, decompile the same input with `--show-bad-code` to force output.
</details>

<details>
<summary>Hint 3 — How do I tell a Kotlin `object` from a Java singleton?</summary>

Look for `@Metadata` first; that settles it. If the annotation has been stripped, use these secondary
tells: the Kotlin form always has a `private` constructor with no parameters, always names the field
exactly `INSTANCE`, always assigns it in `<clinit>` as the first statement, and the class is always
`final`. A hand-written Java singleton usually has lazy initialisation, a `getInstance()` accessor, or
synchronisation — none of which Kotlin generates.
</details>

<details>
<summary>Hint 4 — The app I pulled has no `kotlin/` package at all but I am sure it is Kotlin</summary>

R8 relocates and shrinks `kotlin-stdlib` aggressively. `kotlin/jvm/internal/Intrinsics` may have been
renamed to something like `a/a/a/b`. Fall back to structural signals: a class with a static field of its
own type assigned in `<clinit>`, methods whose first two statements are two calls to the same
two-argument static void method with a string constant, and any `switch` on an `int` field named `label`
inside a method returning `Object`.
</details>

---

## Success criteria

You have completed this lab when all of the following are true.

1. You can produce the verdict table from step 9 for `mixed.jar` without looking at your source files.
2. For each of the five signals, you can state one situation in which it is absent even though the class
   is Kotlin. (For example, `Intrinsics.checkNotNullParameter` is absent from a private function.)
3. You can decode a `$default` call's bitmask argument and say which parameters the caller omitted.
4. You can explain, in one sentence each, what `access$getVERSION$cp` and `$this$masked` are.
5. You have run the exercise against one real APK you did not build, and you can state separately how
   much of it is Kotlin application code versus Kotlin library code.

---

## Solution

<details>
<summary>Full solution — expected outputs and verdicts</summary>

### Class inventory produced by step 1

```
com/example/mixed/Clock.class
com/example/mixed/Credential.class
com/example/mixed/LegacyStore.class
com/example/mixed/ModernStore.class
com/example/mixed/ModernStore$Companion.class
com/example/mixed/ModernStoreKt.class
com/example/mixed/Result.class
com/example/mixed/Result$Err.class
com/example/mixed/Result$Ok.class
```

Nine classes from two source files. You wrote four type names in Kotlin (`Credential`, `Result`,
`Clock`, `ModernStore`) plus two nested ones, and the compiler added `ModernStore$Companion` and
`ModernStoreKt` on its own. That gap between "types I wrote" and "classes that exist" is the first
signal, available before any decompilation.

### `@Metadata` results

```
$ grep -rl "kotlin.Metadata" jadx_out/sources/com/example/mixed/
jadx_out/sources/com/example/mixed/Clock.java
jadx_out/sources/com/example/mixed/Credential.java
jadx_out/sources/com/example/mixed/ModernStore.java
jadx_out/sources/com/example/mixed/ModernStoreKt.java
jadx_out/sources/com/example/mixed/Result.java

$ grep -rL "kotlin.Metadata" jadx_out/sources/com/example/mixed/
jadx_out/sources/com/example/mixed/LegacyStore.java
```

Nested classes are emitted inside their outer class's `.java` file by JADX, so `Result$Ok`,
`Result$Err`, and `ModernStore$Companion` do not appear as separate files. Each still carries its own
`@Metadata` annotation inside the file.

`ModernStoreKt` is the only one with `k = 2`. Everything else is `k = 1`.

### The full `Credential` decompilation

```java
// jadx_out/sources/com/example/mixed/Credential.java
@Metadata(d1 = {...}, d2 = {...}, k = 1, mv = {1, 9, 0}, xi = 48)
public final class Credential {
    private final long expires;
    private final String token;
    private final String user;

    public Credential(String user, String token, long expires) {
        Intrinsics.checkNotNullParameter(user, "user");
        Intrinsics.checkNotNullParameter(token, "token");
        this.user = user;
        this.token = token;
        this.expires = expires;
    }

    public /* synthetic */ Credential(String str, String str2, long j, int i,
                                      DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, (i & 4) != 0 ? 0L : j);
    }

    public static /* synthetic */ Credential copy$default(Credential credential, String str,
            String str2, long j, int i, Object obj) {
        if ((i & 1) != 0) { str = credential.user; }
        if ((i & 2) != 0) { str2 = credential.token; }
        if ((i & 4) != 0) { j = credential.expires; }
        return credential.copy(str, str2, j);
    }

    public final String component1() { return this.user; }
    public final String component2() { return this.token; }
    public final long component3() { return this.expires; }

    public final Credential copy(String user, String token, long expires) {
        Intrinsics.checkNotNullParameter(user, "user");
        Intrinsics.checkNotNullParameter(token, "token");
        return new Credential(user, token, expires);
    }

    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof Credential)) return false;
        Credential credential = (Credential) other;
        return Intrinsics.areEqual(this.user, credential.user)
            && Intrinsics.areEqual(this.token, credential.token)
            && this.expires == credential.expires;
    }

    public int hashCode() {
        return (((this.user.hashCode() * 31) + this.token.hashCode()) * 31)
            + Long.hashCode(this.expires);
    }

    public String toString() {
        return "Credential(user=" + this.user + ", token=" + this.token
             + ", expires=" + this.expires + ")";
    }

    public final long getExpires() { return this.expires; }
    public final String getToken()  { return this.token; }
    public final String getUser()   { return this.user; }
}
```

The `toString` implementation is the security-relevant one: a single log statement that interpolates a
`Credential` writes the token to logcat. This is the finding described in
[faq.md question 19](../faq.md).

### Answers to the success criteria

**Criterion 2 — when each signal is absent despite the class being Kotlin.**

| Signal | Absent when |
|---|---|
| `@Metadata` | A ProGuard rule strips runtime-visible annotations, or the class is a synthetic bridge the compiler chose not to annotate |
| `Intrinsics.checkNotNullParameter` | The function is `private` or `internal` and the compiler proved all callers safe, all parameters are primitives or nullable, or R8 removed the check |
| `Companion` | The class has no companion object, or the companion was named something else with `companion object Named` |
| `INSTANCE` | The class is not an `object` declaration, or R8 inlined the singleton entirely |
| `DefaultConstructorMarker` | No constructor or function has default arguments and the class is not sealed |

**Criterion 3 — the bitmask.** In `new Credential("alice", "abcdef123456", 0L, 4, null)`, the fourth
argument `4` is binary `100`, so bit index 2 is set, which corresponds to the third parameter
`expires`. The caller therefore wrote `Credential("alice", "abcdef123456")` and let `expires` default.
A value of `0` would mean every parameter was supplied explicitly, and a value of `6` (binary `110`)
would mean the second and third were both omitted.

**Criterion 4 — the two synthetic names.**

`access$getVERSION$cp` is a synthetic static bridge on `ModernStore` that lets the nested `Companion`
class read the outer class's `private static final int VERSION`. The JVM has no notion of "nested class
may see the outer class's privates" at the bytecode level in older class-file versions, so the compiler
generates a package-visible accessor and routes the read through it. The `$cp` suffix means "companion
property".

`$this$masked` is the parameter name the compiler assigns to the receiver of an extension function. The
Kotlin source wrote `this` inside `String.masked()`; since the compiled function is a static method, the
receiver had to become an ordinary first parameter, and the compiler names it `$this$` plus the function
name so it cannot collide with a real parameter.

**Criterion 5 — separating application Kotlin from library Kotlin.** Count `@Metadata` hits under the
application's own package prefix separately from the total. A useful phrasing for a report is: "Of 4,812
classes carrying `kotlin.Metadata`, 611 are under `com.example.app`; the remainder belong to bundled
libraries including `androidx`, `okhttp3`, and `kotlinx.coroutines`. The application's own code is
therefore predominantly Kotlin." Never report the raw total as if it described the app.

### Why the ordering of signals matters

Rank your evidence by how expensive it is for a defender to remove.

| Rank | Signal | Cost to remove | Removable? |
|---|---|---|---|
| 1 | Structural shape of generated members | Would change behaviour | No |
| 2 | Coroutine state machines | Would change behaviour | No |
| 3 | `Companion` / `INSTANCE` / `$default` structure | Would change behaviour | Renameable, not removable |
| 4 | `Intrinsics` call sites | Small behaviour change on contract violation | Partly, via R8 |
| 5 | `Intrinsics` string arguments | None | Only with explicit string obfuscation |
| 6 | `@Metadata` annotation | None | Yes, with one ProGuard rule |

Build your conclusions on ranks 1 to 3 and treat ranks 4 to 6 as convenience. That habit is what makes
the technique work on hardened applications rather than only on lab jars.

</details>

---

**Next:** [Lab 02 — Null safety in JADX](lab-02-null-safety-in-jadx.md)
