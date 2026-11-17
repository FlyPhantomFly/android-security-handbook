# Lab 04 — CTF: The Silent Vault

**Difficulty:** Advanced
**Time:** 4–8 hours
**Prerequisites:** [Lab 03](lab-03-native-instrumentation.md), all of
[Chapter 53 §7](../README.md#7-dynamic-analysis)

---

## The challenge

You are given an app with a single text field and an **Unlock** button. Somewhere inside it, a secret
is checked. When you enter the right value, the app displays a flag.

Your reflexes will not work:

- Hooking the obvious validation method does nothing. It installs cleanly and never fires.
- `Java.use` on the class you can see in JADX throws `ClassNotFoundException`.
- Hooking `String.equals` produces thousands of hits and none of them are yours.
- Attaching with `-n` shows you an app that appears to do nothing at all.
- `strings` on the APK contains no flag.

The app has **no anti-Frida code whatsoever**. There is no `TracerPid` check, no port scan, no thread
enumeration, no `/proc/self/maps` parsing. Verify this yourself before you go hunting for it — that
verification is part of the challenge.

**Recover the flag.**

---

## Rules

1. **Find three independent solutions.** One is luck. Three means you understand the mechanisms.
2. You may not decompile and read the flag out of a constant. There is no such constant; the flag is
   derived. But even if there were, that is not the lesson.
3. No brute force over the full keyspace.
4. For each of the four obstacles below, you must be able to **name the mechanism** in one sentence
   before you are allowed to call the lab finished.

---

## The four obstacles, and what each teaches

| # | Obstacle | Chapter reference |
|---|---|---|
| 1 | The validator method is inlined and your hook never fires | [§7.4.1](../README.md#741-failure-1--the-method-was-inlined) |
| 2 | The real logic lives in a DEX loaded into an `InMemoryDexClassLoader` | [§7.4.2](../README.md#742-failure-2--classnotfoundexception-and-the-classloader-problem) |
| 3 | The final comparison happens in native code with a dynamically registered JNI method | [§7.4.3](../README.md#743-failure-3--the-wrong-overload), [Lab 03](lab-03-native-instrumentation.md) |
| 4 | The key material is derived in `attachBaseContext` and zeroed immediately afterwards | [§7.4.4](../README.md#744-failure-4--attaching-instead-of-spawning), [§7.6](../README.md#76-finding-things-in-memory-memoryscan-and-processenumerateranges) |

Each obstacle maps to exactly one section of the chapter. If you are stuck, the reference tells you
which one to re-read — not which command to type.

---

## Building the challenge

Build it yourself. Implementing the defence is how you understand it.

### `app/src/main/java/com/fridalab/vault/App.java`

```java
package com.fridalab.vault;

import android.app.Application;
import android.content.Context;
import android.util.Log;
import dalvik.system.InMemoryDexClassLoader;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class App extends Application {

    private static final String TAG = "VAULT";
    public static ClassLoader pluginLoader = null;

    // OBSTACLE 4: the key is derived here — before any Activity exists — and
    // the byte[] is zeroed as soon as the derived value is stored.
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        byte[] material = new byte[32];
        for (int i = 0; i < material.length; i++) {
            material[i] = (byte) ((i * 37 + 0x5A) ^ 0xA7);
        }
        Keys.install(material);
        java.util.Arrays.fill(material, (byte) 0);      // wiped

        // OBSTACLE 2: the real validator is defined in a child ClassLoader.
        try {
            InputStream in = base.getAssets().open("core.dex");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();
            pluginLoader = new InMemoryDexClassLoader(
                    ByteBuffer.wrap(bos.toByteArray()), base.getClassLoader());
            Log.i(TAG, "core loaded");
        } catch (Throwable t) {
            Log.e(TAG, "core load failed: " + t);
        }
    }
}
```

### `app/src/main/java/com/fridalab/vault/Keys.java`

```java
package com.fridalab.vault;

public final class Keys {

    private static int derived = 0;

    /** Called once, from attachBaseContext, before anything else. */
    public static void install(byte[] material) {
        int acc = 0x1337;
        for (byte b : material) {
            acc = (acc * 31) ^ (b & 0xff);
        }
        derived = acc;
    }

    public static int get() {
        return derived;
    }
}
```

### `app/src/main/java/com/fridalab/vault/Gate.java`

```java
package com.fridalab.vault;

public final class Gate {

    // OBSTACLE 1: tiny, private, static, no side effects. The optimizing
    // compiler will inline this into its caller under -m speed, and your hook
    // on it will never fire.
    private static boolean same(int a, int b) {
        return a == b;
    }

    static boolean check(int candidate) {
        return same(candidate, Keys.get());
    }
}
```

### The core DEX — `core/com/fridalab/core/Validator.java`

```java
package com.fridalab.core;

public class Validator {

    static {
        System.loadLibrary("vault");
    }

    // OBSTACLE 3: dynamically registered, so no Java_* symbol exists.
    private native boolean finalCheck(String input, int derivedKey);

    private static int mix(String s) {
        int acc = 0x1337;
        for (int i = 0; i < s.length(); i++) {
            acc = (acc * 31) ^ (s.charAt(i) & 0xff);
        }
        return acc;
    }

    public String open(String input, int derivedKey) {
        if (input == null || input.length() < 4) return null;
        if (!finalCheck(input, derivedKey)) return null;

        // The flag is DERIVED from the input, so a wrong input cannot produce it
        // and there is no plaintext flag constant anywhere.
        StringBuilder sb = new StringBuilder("FRIDA{");
        int h = mix(input);
        for (int i = 0; i < 8; i++) {
            sb.append(Integer.toHexString((h >>> (i * 4)) & 0xf));
        }
        sb.append('}');
        return sb.toString();
    }
}
```

### `app/src/main/cpp/vault.cpp`

```cpp
#include <jni.h>
#include <string.h>
#include <android/log.h>

#define TAG "VAULT"

static jboolean nativeFinalCheck(JNIEnv *env, jobject thiz,
                                 jstring input, jint derivedKey) {
    const char *s = env->GetStringUTFChars(input, nullptr);
    if (s == nullptr) return JNI_FALSE;

    int acc = 0x1337;
    for (size_t i = 0; i < strlen(s); i++) {
        acc = (acc * 31) ^ (s[i] & 0xff);
    }
    env->ReleaseStringUTFChars(input, s);

    // The comparison that decides everything.
    return (acc == derivedKey) ? JNI_TRUE : JNI_FALSE;
}

static JNINativeMethod kMethods[] = {
    { "finalCheck", "(Ljava/lang/String;I)Z", (void *) nativeFinalCheck }
};

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass c = env->FindClass("com/fridalab/core/Validator");
    if (c == nullptr) return JNI_ERR;
    env->RegisterNatives(c, kMethods, 1);
    __android_log_print(ANDROID_LOG_INFO, TAG, "JNI_OnLoad done");
    return JNI_VERSION_1_6;
}
```

### `MainActivity` — reflection into the child loader

```java
package com.fridalab.vault;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.*;

import java.lang.reflect.Method;

public class MainActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        final EditText in = new EditText(this);
        in.setHint("secret");
        final TextView out = new TextView(this);
        Button go = new Button(this);
        go.setText("Unlock");

        go.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String s = in.getText().toString();
                // The cheap Java gate first — this is the one you will
                // reflexively hook, and it is inlined.
                if (!Gate.check(mixLocal(s))) {
                    out.setText("locked");
                    return;
                }
                try {
                    Class<?> c = App.pluginLoader.loadClass("com.fridalab.core.Validator");
                    Object inst = c.getDeclaredConstructor().newInstance();
                    Method m = c.getMethod("open", String.class, int.class);
                    Object flag = m.invoke(inst, s, Keys.get());
                    out.setText(flag == null ? "locked" : flag.toString());
                } catch (Throwable t) {
                    out.setText("error: " + t);
                }
            }
        });

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.addView(in); root.addView(go); root.addView(out);
        setContentView(root);
    }

    private static int mixLocal(String s) {
        int acc = 0x1337;
        for (int i = 0; i < s.length(); i++) acc = (acc * 31) ^ (s.charAt(i) & 0xff);
        return acc;
    }
}
```

### Build

```bash
# host — the core DEX
javac -source 8 -target 8 -d core_build core/com/fridalab/core/Validator.java
$ANDROID_HOME/build-tools/34.0.0/d8 --output core_out core_build/com/fridalab/core/Validator.class
cp core_out/classes.dex app/src/main/assets/core.dex

# host — the app
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk

# host — put it in the hardest state: full AOT with inlining
adb shell cmd package compile -m speed -f com.fridalab.vault
adb shell am force-stop com.fridalab.vault
```

---

## Your first attempts will fail. Record why.

Before reading further, spend thirty minutes failing productively. Try:

```javascript
// attempt-1.js
Java.perform(function () {
  Java.use("com.fridalab.vault.Gate").same.implementation = function (a, b) {
    console.log("[same] " + a + " vs " + b);
    return true;
  };
});
```

```javascript
// attempt-2.js
Java.perform(function () {
  Java.use("com.fridalab.core.Validator").open.implementation = function (s, k) {
    console.log("[open] " + s);
    return this.open(s, k);
  };
});
```

```bash
frida -U -n com.fridalab.vault -l attempt-1.js
```

For each attempt, write down: what you expected, what happened, and **which of the four obstacles it
hit**. That table is the actual deliverable of this lab.

---

## Solution paths

There are at least five. Find three. Each is deliberately un-detailed — the point is that you know
which chapter section to open.

### Path A — Defeat the inlining, then read the expected value

The Java gate compares your input's hash against `Keys.get()`. If you can see the value it is compared
*against*, you have the answer.

- Make the hook fire ([§7.4.1](../README.md#741-failure-1--the-method-was-inlined)).
- Read `Keys.get()` directly — it is a static method with no arguments.
- Then invert the mix function to find an input with that hash. (The mix is `acc = acc*31 ^ c`; it is
  not cryptographic. A short search over 4-character inputs suffices — that is not brute force over
  the keyspace, it is arithmetic.)

### Path B — Reach into the child ClassLoader and hook `Validator.open`

- Enumerate loaders ([§7.4.2](../README.md#742-failure-2--classnotfoundexception-and-the-classloader-problem)).
- Obtain a factory bound to the `InMemoryDexClassLoader`.
- Hook `open` and force it to run regardless of `finalCheck`, or read what it returns when
  `finalCheck` is made to return `true`.

### Path C — Recover the JNI registration and neutralise `finalCheck`

- Recover the `RegisterNatives` table ([Lab 03](lab-03-native-instrumentation.md), §7).
- `Interceptor.attach` on the recovered address and `retval.replace(ptr(1))` in `onLeave`.
- Note carefully: this makes `open` produce a flag, but the flag is *derived from your input*. So a
  forced `true` gives you **a** flag, not **the** flag. Understanding why is part of the lab. What do
  you need to do to get the flag for the *correct* input?

### Path D — Catch the key before it is wiped

- Spawn with `-f` ([§7.4.4](../README.md#744-failure-4--attaching-instead-of-spawning)).
- Hook `Keys.install(byte[])` and dump `material` before `Arrays.fill` runs.
- Or hook `attachBaseContext` and read the array from there.
- Or — the harder, more instructive route — do not hook at all: scan memory for the 32-byte pattern
  while the app is starting ([§7.6](../README.md#76-finding-things-in-memory-memoryscan-and-processenumerateranges)),
  using the snapshot/diff workflow in `scripts/memory-secret-scanner.js`.

### Path E — Use `Java.choose` and reflection as an oracle

- Find a live `Validator` instance on the heap, or construct one via the child loader's factory.
- Call `open(candidate, Keys.get())` yourself, in a loop, from inside Frida — no UI interaction.
- This is the "turn the app into an oracle" pattern from
  [§7.8](../README.md#78-nativefunction-and-nativecallback-calling-into-and-out-of-the-target).

---

## Hints

Consult these only after a genuine attempt.

<details>
<summary>Hint 1 — "attempt-1.js installs and never fires"</summary>

No error was thrown, so it is not a ClassLoader or overload problem. Did you spawn or attach? Did you
check the compilation state? The build instructions deliberately set `-m speed`.
</details>

<details>
<summary>Hint 2 — "attempt-2.js throws ClassNotFoundException"</summary>

Read the exception text. It lists the `DexPathList` it searched. Is `core.dex` in that list? Where did
`core.dex` come from, and which loader owns it?
</details>

<details>
<summary>Hint 3 — "I hooked open() and got a flag, but it is not the flag"</summary>

Correct, and this is the most important realisation in the lab. Read `Validator.open` again: the flag
is computed from `input`. Forcing the check to pass with the wrong input produces a *different* flag.
You need either the right input, or the value the right input must hash to.
</details>

<details>
<summary>Hint 4 — "I need to invert the mix function"</summary>

`acc = (acc * 31) ^ (c & 0xff)`, starting from `0x1337`. It is fully determined and reversible
character by character if you work backwards from the target, or you can search over short inputs
directly. Neither is brute force over a keyspace; both are arithmetic.`Keys.get()` gives
you the target directly, so you only need to solve for one value.
</details>

<details>
<summary>Hint 5 — "Keys.install runs before my script loads"</summary>

That is only true if you attached. With `-f`, your script's top-level code runs before
`attachBaseContext`. Confirm by hooking `Application.attachBaseContext` and checking that it prints.
</details>

<details>
<summary>Hint 6 — "nat.table() finds no RegisterNatives"</summary>

`System.loadLibrary("vault")` is in `Validator`'s static initialiser, which runs when
`App.pluginLoader.loadClass(...)` is followed by instantiation — i.e. on the first button press, not
at startup. Arm the hook and *then* press the button.
</details>

---

## Success criteria

- [ ] You recovered the flag.
- [ ] You did it **three independent ways**, and can state which chapter section each relies on.
- [ ] You wrote the failure table: for each early attempt, what you expected, what happened, and which
      obstacle it hit.
- [ ] You can name each of the four mechanisms in one sentence, without the word "somehow".
- [ ] You verified that the app contains no anti-Frida code, and can say how you verified it.
- [ ] You can explain why forcing `finalCheck` to return `true` gives you a flag but not *the* flag.
- [ ] You can explain what a defender would have to change to make each of your three solutions harder,
      and honestly assess how much time that would cost an attacker.

---

## The write-up

Finish by writing the finding as you would for a client. It must contain:

1. The **mechanism** of the weakness, not the tool. ("The unlock decision and the flag derivation both
   execute entirely within the app process, so any code executing in that process can obtain the flag
   without knowing the secret.")
2. The exact class and method where the decision is made.
3. Why the four obstacles are *analysis friction*, not security controls.
4. A remediation that would actually work. (There is one, and it is not "add more obstacles". Think
   about where the decision would have to move.)

The last point is the one that separates a report from a stunt.

---

## Cleanup

```bash
adb shell cmd package compile --reset com.fridalab.vault
adb shell am force-stop com.fridalab.vault
adb uninstall com.fridalab.vault
```
