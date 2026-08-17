# Lab 02 — Null Safety in JADX, and Breaking It with Frida

Part of chapter [05 — Kotlin](../README.md). Follows
[lab 01](lab-01-spot-the-kotlin.md); precedes [lab 03](lab-03-coroutine-state-machine.md).

---

## Objective

Prove to yourself, by experiment rather than by assertion, that Kotlin's null safety is a *compile-time*
guarantee backed by a *thin runtime check*, and that removing the runtime check turns a clean
`IllegalStateException` at a well-defined boundary into an unpredictable `NullPointerException` deep
inside unrelated code.

Concretely you will:

1. Write Kotlin functions that exercise non-null parameters, platform types, `!!`, and `lateinit`.
2. Compile them and read the exact `Intrinsics` calls the compiler emitted for each.
3. Run the program on an Android device inside a trivial app harness.
4. Use Frida to neutralise `Intrinsics.checkNotNullParameter`.
5. Observe where the program crashes instead, and explain why that location is worse for a defender and
   better for an attacker.

> **🧠 Mental Model**
> Kotlin's type system is a *contract*. `Intrinsics.checkNotNullParameter` is the *bouncer at the door*
> who enforces the contract for anyone who did not sign it — Java callers, reflection, deserialisers,
> JNI. Removing the bouncer does not make the building safe; it just means violations are discovered
> somewhere further inside, by whoever trips over them.

---

## Prerequisites

- [Lab 01](lab-01-spot-the-kotlin.md) completed, so `@Metadata` and `Intrinsics` are already familiar.
- [Chapter 04 — Java](../../04-Java/README.md) for what a `NullPointerException` is.
- A rooted device or emulator with a `frida-server` running. Setup is covered in
  [53 — Frida](../../53-Frida/README.md); if you want more than this lab needs, the official
  Frida Android guide covers the same ground.

| Tool | Purpose | Verify with |
|---|---|---|
| `kotlinc` | Compile the demo | `kotlinc -version` |
| JDK 17+ | Run the jar half of the lab | `java -version` |
| Android SDK build-tools | `d8`, `aapt2`, `zipalign`, `apksigner` | `d8 --version` |
| JADX | Read the emitted checks | `jadx --version` |
| `adb` | Talk to the device | `adb devices` |
| Frida | Host tooling | `frida --version` |
| `frida-server` | On the device, matching the host version | `adb shell "/data/local/tmp/frida-server --version"` |

**Estimated time:** 90 minutes. The first 40 minutes need no device.

---

## Setup

### Part A — a host-only project (no device needed)

```bash
# host
mkdir -p ~/kotlin-lab-02/src && cd ~/kotlin-lab-02
```

Write a small Java class that returns `null` from a method whose Kotlin-visible type will be a platform
type. This is the crucial ingredient: without a Java source, you cannot create a platform type at all.

```java
// host — save as ~/kotlin-lab-02/src/JavaConfig.java
package com.example.nulls;

import java.util.HashMap;
import java.util.Map;

/**
 * Stands in for android.content.Intent, android.os.Bundle, org.json.JSONObject,
 * a Cursor, or any JNI return value. None of them are annotated for nullability,
 * so every value they hand to Kotlin is a platform type.
 */
public class JavaConfig {
    private static final Map<String, String> VALUES = new HashMap<>();

    static {
        VALUES.put("region", "eu-west-1");
        // note: "apiKey" is deliberately never populated
    }

    /** Returns null when the key is absent. Kotlin sees this as String! */
    public static String getValue(String key) {
        return VALUES.get(key);
    }
}
```

Now the Kotlin side. Each function is numbered so you can match it to the decompiled output later.

```kotlin
// host — save as ~/kotlin-lab-02/src/NullDemo.kt
package com.example.nulls

class Session {
    // 5. lateinit -> nullable field plus a throwUninitializedPropertyAccessException on read
    lateinit var userId: String

    fun describe(): String = "session for $userId"
}

// 1. Non-null parameters on a public function.
//    Emits Intrinsics.checkNotNullParameter for BOTH parameters, in declaration order.
fun authenticate(username: String, password: String): String {
    return "auth:${username.length}:${password.length}"
}

// 2. Nullable parameter with a safe call and an Elvis fallback.
//    Emits NO check at all; the null case is a branch, not an exception.
fun greet(name: String?): String {
    return name?.uppercase() ?: "ANONYMOUS"
}

// 3. Platform type assigned to a non-null local.
//    THE HOLE. Emits nothing. The crash, if any, happens at the point of use.
fun readRegion(): Int {
    val region: String = JavaConfig.getValue("region")   // present -> fine
    return region.length
}

fun readApiKey(): Int {
    val key: String = JavaConfig.getValue("apiKey")      // absent -> null in a non-null slot
    return key.length                                     // NullPointerException here, not above
}

// 4. Explicit not-null assertion.
//    Emits Intrinsics.checkNotNull, throwing NullPointerException with a message.
fun forceApiKey(): Int {
    return JavaConfig.getValue("apiKey")!!.length
}

// 6. The safe way to do exactly what 3 and 4 do.
//    The failure is explicit, attributable, and carries a useful message.
fun readApiKeySafely(): Int {
    val key = JavaConfig.getValue("apiKey")
        ?: error("apiKey missing from configuration")
    return key.length
}

fun main() {
    println(authenticate("alice", "hunter2"))
    println(greet(null))
    println(greet("bob"))
    println("region length = " + readRegion())

    runCatching { readApiKey() }
        .onFailure { println("3. platform type  -> " + it::class.java.name + ": " + it.message) }

    runCatching { forceApiKey() }
        .onFailure { println("4. not-null (!!)  -> " + it::class.java.name + ": " + it.message) }

    runCatching { Session().describe() }
        .onFailure { println("5. lateinit       -> " + it::class.java.name + ": " + it.message) }

    runCatching { readApiKeySafely() }
        .onFailure { println("6. explicit check -> " + it::class.java.name + ": " + it.message) }
}
```

Compile and run.

```bash
# host
kotlinc src/NullDemo.kt src/JavaConfig.java -include-runtime -d nulls.jar
java -jar nulls.jar
```

Expected output:

```
auth:5:7
ANONYMOUS
BOB
region length = 8
3. platform type  -> java.lang.NullPointerException: null
4. not-null (!!)  -> java.lang.NullPointerException: null cannot be cast to non-null type kotlin.String
5. lateinit       -> kotlin.UninitializedPropertyAccessException: lateinit property userId has not been initialized
6. explicit check -> java.lang.IllegalStateException: apiKey missing from configuration
```

Read that output carefully before continuing. Four different failures, four different exception types,
and only case 6 tells you what went wrong.

---

## Steps

### Step 1 — Decompile and match each function to its emitted check

```bash
# host
jadx --no-res -d jadx_out nulls.jar
cat jadx_out/sources/com/example/nulls/NullDemoKt.java
```

Expected shape, function by function.

```java
// 1. authenticate — two checks, in parameter order, before anything else
public static final String authenticate(String username, String password) {
    Intrinsics.checkNotNullParameter(username, "username");
    Intrinsics.checkNotNullParameter(password, "password");
    return "auth:" + username.length() + ":" + password.length();
}

// 2. greet — no check whatsoever; nullability became a branch
public static final String greet(String name) {
    String upper;
    if (name != null) {
        upper = name.toUpperCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(upper, "toUpperCase(...)");
    } else {
        upper = null;
    }
    return upper == null ? "ANONYMOUS" : upper;
}

// 3. readRegion / readApiKey — NO CHECK AT ALL on the assignment
public static final int readRegion() {
    return JavaConfig.getValue("region").length();
}

public static final int readApiKey() {
    return JavaConfig.getValue("apiKey").length();
}

// 4. forceApiKey — the !! became an explicit checkNotNull
public static final int forceApiKey() {
    String value = JavaConfig.getValue("apiKey");
    Intrinsics.checkNotNull(value);
    return value.length();
}

// 6. readApiKeySafely — an ordinary branch and a thrown IllegalStateException
public static final int readApiKeySafely() {
    String key = JavaConfig.getValue("apiKey");
    if (key == null) {
        throw new IllegalStateException("apiKey missing from configuration".toString());
    }
    return key.length();
}
```

And the `lateinit` property:

```java
// jadx_out/sources/com/example/nulls/Session.java
public final class Session {
    public String userId;

    public final String getUserId() {
        String str = this.userId;
        if (str != null) {
            return str;
        }
        Intrinsics.throwUninitializedPropertyAccessException("userId");
        return null;
    }

    public final void setUserId(String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.userId = str;
    }

    public final String describe() {
        return "session for " + getUserId();
    }
}
```

Fill in this table from what you see. Do not copy it from below — derive it.

| Function | Kotlin construct | Emitted `Intrinsics` call | Exception on violation |
|---|---|---|---|
| `authenticate` | Non-null parameter | `checkNotNullParameter(v, "name")` | `NullPointerException` with a descriptive message |
| `greet` | Nullable parameter | none | none; a branch is taken |
| `greet` | `uppercase()` result | `checkNotNullExpressionValue(v, "toUpperCase(...)")` | `NullPointerException` |
| `readApiKey` | Platform type to non-null | **none** | `NullPointerException` at the point of use |
| `forceApiKey` | `!!` | `checkNotNull(v)` | `NullPointerException` |
| `Session.getUserId` | `lateinit` read | `throwUninitializedPropertyAccessException("userId")` | `UninitializedPropertyAccessException` |
| `Session.setUserId` | `lateinit` write | `checkNotNullParameter(v, "<set-?>")` | `NullPointerException` |
| `readApiKeySafely` | Elvis with `error()` | none | `IllegalStateException` with your message |

> **🔬 Under the Hood**
> Notice `checkNotNullParameter(str, "<set-?>")` on the setter. `<set-?>` is the compiler's internal
> name for a property setter's implicit value parameter, because the developer never named it. Seeing
> that exact string in decompiled output tells you the enclosing method is a generated property setter,
> not a hand-written function — which is a quick way to skip past accessor noise when reading a large
> class.

### Step 2 — Confirm the difference between the platform-type hole and `!!`

Run these two commands and note that the first shows *nothing*.

```bash
# host
grep -n "readApiKey" -A3 jadx_out/sources/com/example/nulls/NullDemoKt.java
grep -n "forceApiKey" -A4 jadx_out/sources/com/example/nulls/NullDemoKt.java
```

This is the single most important observation in the lab. The developer who wrote
`val key: String = JavaConfig.getValue("apiKey")` **believes** they declared a non-null value, and the
Kotlin type checker agrees with them for the rest of the function. But nothing checks it. The `!!`
version is, counter-intuitively, the *safer* of the two, because at least the failure is attributed to
the assertion.

> **🔍 Pentester's Note**
> When reviewing a Kotlin Android app, the highest-yield search is not for `!!`. It is for non-null
> Kotlin locals assigned from framework getters: `intent.getStringExtra`, `bundle.getString`,
> `cursor.getString`, `jsonObject.getString`, `sharedPrefs.getString`, and every JNI method. Those
> assignments emit no check and crash later, at a place the developer never considered.

### Step 3 — Wrap the code in a minimal Android app

To use Frida you need the code running on a device. The smallest useful harness is one activity that
calls each function on a button press.

```kotlin
// host — save as ~/kotlin-lab-02/app/src/main/java/com/example/nulls/MainActivity.kt
package com.example.nulls

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this)
        layout.orientation = LinearLayout.VERTICAL

        layout.addView(Button(this).apply {
            text = "1. authenticate(non-null)"
            setOnClickListener {
                // The interesting case: pass a value that will be null at runtime.
                // Reflection is used so the Kotlin compiler cannot reject it.
                val m = NullDemoKt::class.java
                    .getDeclaredMethod("authenticate", String::class.java, String::class.java)
                try {
                    Log.i(TAG, "result=" + m.invoke(null, null, "hunter2"))
                } catch (t: Throwable) {
                    Log.e(TAG, "threw: " + (t.cause ?: t))
                }
            }
        })

        layout.addView(Button(this).apply {
            text = "2. readApiKey(platform type)"
            setOnClickListener {
                try { Log.i(TAG, "len=" + readApiKey()) }
                catch (t: Throwable) { Log.e(TAG, "threw: $t") }
            }
        })

        layout.addView(Button(this).apply {
            text = "3. lateinit before init"
            setOnClickListener {
                try { Log.i(TAG, Session().describe()) }
                catch (t: Throwable) { Log.e(TAG, "threw: $t") }
            }
        })

        setContentView(layout)
    }

    companion object { private const val TAG = "NullLab" }
}
```

Build it however you prefer. If you are comfortable with Gradle, create an ordinary app module with
`applicationId "com.example.nulls"` and drop in `MainActivity.kt`, `NullDemo.kt`, and `JavaConfig.java`.
If you would rather stay on the command line, the manual path is:

```bash
# host — manual APK assembly, no Gradle
kotlinc -cp $ANDROID_HOME/platforms/android-34/android.jar \
        src/NullDemo.kt src/JavaConfig.java app/src/main/java/com/example/nulls/MainActivity.kt \
        -d classes/
d8 --lib $ANDROID_HOME/platforms/android-34/android.jar \
   --output . $(find classes -name '*.class') \
   $KOTLIN_HOME/lib/kotlin-stdlib.jar
aapt2 link -I $ANDROID_HOME/platforms/android-34/android.jar \
   --manifest AndroidManifest.xml -o app-unsigned.apk
zip -u app-unsigned.apk classes.dex
zipalign -f 4 app-unsigned.apk app-aligned.apk
apksigner sign --ks debug.keystore --ks-pass pass:android --out app.apk app-aligned.apk
adb install -r app.apk
```

A minimal `AndroidManifest.xml` for the manual path:

```xml
<!-- host — AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.nulls">
    <application android:label="NullLab">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Verify the app runs and that each button logs an exception.

```bash
# host
adb logcat -c && adb logcat -s NullLab
```

### Step 4 — Watch the checks fire, before changing anything

Attach Frida and log every call to the `Intrinsics` methods without altering behaviour. Always observe
before you interfere.

```javascript
// host — save as observe.js, run with: frida -U -f com.example.nulls -l observe.js
Java.perform(function () {
    var Intrinsics = Java.use('kotlin.jvm.internal.Intrinsics');

    Intrinsics.checkNotNullParameter
        .overload('java.lang.Object', 'java.lang.String')
        .implementation = function (value, name) {
            console.log('[checkNotNullParameter] name="' + name + '" isNull=' + (value === null));
            return this.checkNotNullParameter(value, name);
        };

    Intrinsics.checkNotNullExpressionValue
        .overload('java.lang.Object', 'java.lang.String')
        .implementation = function (value, expr) {
            console.log('[checkNotNullExpressionValue] expr="' + expr + '" isNull=' + (value === null));
            return this.checkNotNullExpressionValue(value, expr);
        };

    console.log('[*] observers installed');
});
```

```bash
# host
frida -U -f com.example.nulls -l observe.js
```

Press button 1. You will see the check fire with `name="username"` and `isNull=true`, immediately
followed by the app's own `NullPointerException`. The exception message names the parameter and the
method, which is exactly the diagnostic value the check exists to provide.

Press button 2. **No check fires at all**, and you still get a crash. That is the platform-type hole,
observed live.

### Step 5 — Neutralise the checks and observe the new failure mode

Now replace the implementations with no-ops.

```javascript
// host — save as bypass.js, run with: frida -U -f com.example.nulls -l bypass.js
//
// WHAT THIS DOES
//   Replaces Kotlin's compiler-inserted null assertions with empty functions, so a
//   null value that violates a non-null contract is allowed to travel further into
//   the program instead of being rejected at the function boundary.
//
// WHY YOU WOULD DO THIS
//   Some apps use the check as a cheap input validator or as part of an anti-tamper
//   path. Neutralising it lets you feed values the developer assumed were impossible
//   and see what the code does with them. It is an exploration tool, not a fix.
//
// WARNING
//   This makes the app less stable, not more. Expect crashes in unrelated code.

'use strict';

function neutralise(className, methodName, argTypes) {
    try {
        var klass = Java.use(className);
        var target = klass[methodName];
        if (target === undefined) {
            console.log('[-] ' + className + '.' + methodName + ' not present');
            return;
        }
        if (argTypes) {
            target.overload.apply(target, argTypes).implementation = function () {
                console.log('[bypass] ' + methodName + '(' + Array.prototype.slice.call(arguments)
                    .map(function (a) { return a === null ? 'null' : String(a); }).join(', ') + ')');
                return;   // do nothing: the contract violation is allowed through
            };
        } else {
            target.implementation = function () { return; };
        }
        console.log('[+] neutralised ' + className + '.' + methodName);
    } catch (e) {
        console.log('[-] failed on ' + className + '.' + methodName + ': ' + e.message);
    }
}

Java.perform(function () {
    var I = 'kotlin.jvm.internal.Intrinsics';

    // Modern names (Kotlin 1.4 and later)
    neutralise(I, 'checkNotNullParameter',       ['java.lang.Object', 'java.lang.String']);
    neutralise(I, 'checkNotNullExpressionValue', ['java.lang.Object', 'java.lang.String']);
    neutralise(I, 'checkNotNull',                ['java.lang.Object']);
    neutralise(I, 'checkNotNull',                ['java.lang.Object', 'java.lang.String']);
    neutralise(I, 'checkNotNullReturnValue',     ['java.lang.Object', 'java.lang.String']);

    // Legacy names (Kotlin 1.3 and earlier) — harmless if absent
    neutralise(I, 'checkParameterIsNotNull',        ['java.lang.Object', 'java.lang.String']);
    neutralise(I, 'checkExpressionValueIsNotNull',  ['java.lang.Object', 'java.lang.String']);
    neutralise(I, 'checkNotNullFromJava',           ['java.lang.Object', 'java.lang.String']);

    // The lateinit guard is a throw, not a check; neutralising it lets a null
    // lateinit property escape into the rest of the program.
    try {
        Java.use(I).throwUninitializedPropertyAccessException
            .overload('java.lang.String').implementation = function (name) {
                console.log('[bypass] lateinit "' + name + '" read before init, allowing null through');
                return;
            };
        console.log('[+] neutralised throwUninitializedPropertyAccessException');
    } catch (e) {
        console.log('[-] lateinit guard not hookable: ' + e.message);
    }

    console.log('[*] null-check bypass active. Expect NullPointerExceptions elsewhere.');
});
```

```bash
# host
frida -U -f com.example.nulls -l bypass.js
```

Press button 1 again and watch what changed. The `checkNotNullParameter` call is logged but throws
nothing, so `authenticate` proceeds with `username == null`, and the crash now comes from
`username.length()` inside the method body. Compare the two stack traces side by side.

```
# adb logcat — BEFORE the bypass
java.lang.NullPointerException: Parameter specified as non-null is null:
  method com.example.nulls.NullDemoKt.authenticate, parameter username
    at com.example.nulls.NullDemoKt.authenticate(NullDemo.kt)
    at java.lang.reflect.Method.invoke(Native Method)
    at com.example.nulls.MainActivity$onCreate$1$1.onClick(MainActivity.kt:22)

# adb logcat — AFTER the bypass
java.lang.NullPointerException:
  Attempt to invoke virtual method 'int java.lang.String.length()' on a null object reference
    at com.example.nulls.NullDemoKt.authenticate(NullDemo.kt)
    at java.lang.reflect.Method.invoke(Native Method)
    at com.example.nulls.MainActivity$onCreate$1$1.onClick(MainActivity.kt:22)
```

Press button 3 with the bypass active. The `lateinit` guard no longer throws
`UninitializedPropertyAccessException`, so `getUserId()` returns `null`, and `describe()` happily builds
the string `"session for null"` — no crash at all. The program is now operating on state its author
believed impossible.

### Step 6 — Write down the security conclusion

Answer these three questions in your notes before reading the solution.

1. Which of the four failure modes (checked parameter, platform type, `!!`, `lateinit`) produced the
   *most* useful message to a defender reading a crash report, and which produced the least?
2. If an application relies on `Intrinsics.checkNotNullParameter` as a security control — for example,
   to reject a null token before an authorisation decision — is that control adequate? Why not?
3. In which of the four cases did the bypass change the program's *behaviour* rather than merely the
   *location of its crash*?

---

## Hints

<details>
<summary>Hint 1 — Frida says "Java.use failed: class not found"</summary>

Either the app is not Kotlin, or it does not ship `kotlin-stdlib`, or the stdlib has been repackaged by
R8. Confirm the class exists first:

```javascript
// Frida REPL
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (n) { if (n.indexOf('Intrinsics') !== -1) console.log(n); },
        onComplete: function () { console.log('done'); }
    });
});
```

If the result is a name like `a.a.a.b`, hook that name instead. Match it by its method shape: a static
`void` method taking `(Object, String)`.
</details>

<details>
<summary>Hint 2 — the overload call throws "no such overload"</summary>

Print the available overloads before guessing:

```javascript
// Frida REPL
Java.perform(function () {
    var I = Java.use('kotlin.jvm.internal.Intrinsics');
    I.checkNotNull.overloads.forEach(function (o) { console.log(o.toString()); });
});
```

`checkNotNull` genuinely has two overloads, `(Object)` and `(Object, String)`, and which one is used
depends on whether the `!!` had a source expression the compiler could name.
</details>

<details>
<summary>Hint 3 — nothing is logged even though I know the app is Kotlin</summary>

Two common causes. R8 may have removed the checks in a release build, in which case there is nothing to
hook; verify by grepping the decompiled release APK. Or the code path you are exercising is `private`,
where the compiler omits the check because it can prove all callers are safe.
</details>

<details>
<summary>Hint 4 — I cannot build the APK and I only have the jar</summary>

Do the whole lab on the desktop JVM instead. `frida` works against a local `java` process: run
`java -jar nulls.jar` in one terminal with a `Thread.sleep` at the start, then attach with
`frida -n java -l bypass.js`. Every hook in this lab is on `kotlin.jvm.internal.Intrinsics`, which is
identical on the JVM and on ART. You lose only the Android-specific framing.
</details>

---

## Success criteria

1. You can point at the decompiled source of all six numbered functions and state, without running
   anything, which `Intrinsics` method each one emits and why.
2. You have logged `checkNotNullParameter` firing with `isNull=true` and can read the parameter name out
   of the log line.
3. You have produced two different stack traces for the *same* button press — one with the check active
   and one with it neutralised — and can explain why the second is harder to diagnose.
4. You have demonstrated at least one case where the bypass caused the program to continue running with
   an impossible value rather than crashing.
5. You can state, in one sentence, why `val x: String = javaCall()` is more dangerous than
   `val x: String = javaCall()!!`.

---

## Solution

<details>
<summary>Full solution — outputs, answers, and the reasoning</summary>

### Expected observe.js output for button 1

```
[*] observers installed
[checkNotNullParameter] name="username" isNull=true
```

Then the app logs:

```
E NullLab : threw: java.lang.NullPointerException: Parameter specified as non-null is null:
            method com.example.nulls.NullDemoKt.authenticate, parameter username
```

The message is generated by `Intrinsics` itself, which reconstructs the method name from the stack trace
and appends the parameter name it was given. This is why the string constant matters so much: it is the
only place the parameter name survives compilation.

### Expected observe.js output for button 2

```
[*] observers installed
```

Nothing else. No `Intrinsics` method is called on the platform-type path, and yet the app still logs:

```
E NullLab : threw: java.lang.NullPointerException: Attempt to invoke virtual method
            'int java.lang.String.length()' on a null object reference
```

### Answers to step 6

**Question 1 — message quality.**

| Case | Message quality | Why |
|---|---|---|
| `lateinit` | Best | Names the exact property: "lateinit property userId has not been initialized" |
| Non-null parameter | Very good | Names the method and the parameter |
| Explicit `?: error(...)` | Very good | Carries the developer's own message |
| `!!` | Poor | "null cannot be cast to non-null type kotlin.String" — no indication of *which* value |
| Platform type | Worst | An ordinary JVM `NullPointerException` at an arbitrary point of use, with no Kotlin context at all |

The ranking is the opposite of what most developers expect. `!!` has a reputation as the dangerous
operator, but the silent platform-type assignment is strictly worse, because it produces a less
informative failure at a less predictable location.

**Question 2 — is `checkNotNullParameter` a security control?**

No, and treating it as one is a design error. It is a *contract assertion*, intended to convert a
programming mistake into a fast, attributable failure. It is inadequate as a security control for four
reasons:

1. It only checks for `null`. An empty string, a whitespace string, a 10-megabyte string, or a string
   containing a path traversal sequence all pass unchallenged.
2. It can be removed by R8 in release builds, so the control may not exist in the shipped artefact.
3. It is trivially neutralised at runtime by exactly the script in this lab, and by Xposed modules, and
   by a one-instruction DEX patch.
4. Its failure mode is an exception, which in many code paths is caught and swallowed by a broad
   `try { } catch (Throwable) { }` higher up.

A real validation for an authorisation token needs an explicit check on format, length, signature, and
expiry, performed server-side. This maps to `MASVS-AUTH` and `MASVS-CODE`.

**Question 3 — where did behaviour change rather than crash location?**

Only the `lateinit` case. Neutralising `throwUninitializedPropertyAccessException` makes `getUserId()`
return `null` and lets `describe()` produce `"session for null"` — the program continues, with corrupted
state, and no exception is raised anywhere.

The other three cases only *moved* the crash. That distinction matters when you are choosing what to
attack: a bypass that makes the program continue with attacker-influenced impossible state is far more
valuable than one that merely relocates a crash.

### Answer to success criterion 5

`val x: String = javaCall()` is more dangerous than `val x: String = javaCall()!!` because the first form
inserts no runtime check at all, so a null propagates silently into the rest of the function and fails at
whatever unrelated line first dereferences it, with a message that names neither the variable nor the
source of the value. The `!!` form inserts `Intrinsics.checkNotNull` at the assignment, so the failure
happens at the boundary, at a line the developer explicitly wrote, and is therefore attributable. Both
are worse than an Elvis operator with an explicit error, but the unchecked platform-type assignment is
the one that produces unexplainable crash reports.

### Bonus — finding these patterns at scale in a real APK

```bash
# host — every not-null assertion in the app's own package
grep -rn "Intrinsics.checkNotNull(" jadx_out/sources/com/target/ | wc -l

# host — every lateinit property, with its original name
grep -rhn "throwUninitializedPropertyAccessException(\"" jadx_out/sources/com/target/ \
  | sed -E 's/.*throwUninitializedPropertyAccessException\("([^"]+)".*/\1/' | sort -u

# host — the high-value pattern: framework getter feeding a non-null Kotlin local
grep -rn -A2 "getStringExtra\|getSerializableExtra\|getParcelableExtra" jadx_out/sources/com/target/ \
  | grep -B1 "\.length()\|\.equals(\|\.charAt("
```

The last command is approximate and will produce false positives. Treat it as a triage filter that tells
you which files to open, not as a finding generator. Cross-reference every hit against the exported
components in `AndroidManifest.xml` before you call anything a vulnerability; see
[chapter 26 — Intent](../../26-Intent/README.md).

</details>

---

**Next:** [Lab 03 — Coroutine state machine](lab-03-coroutine-state-machine.md)
