# Lab 02 — The Four Failure Modes

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-first-contact.md),
[Chapter 53 §7.4](../README.md#74-the-four-failure-modes-exhaustively),
[13-ART §3.15–§3.17](../../13-ART/README.md#315-artmethod--the-most-important-structure-in-android-security)

---

## Objective

Reproduce, deliberately, each of the four reasons a Frida hook fails to fire. For each one you will:

1. Build the failure.
2. Observe the symptom **without** knowing which failure it is.
3. Diagnose it from the symptom alone, using the decision tree.
4. Fix it.
5. Write one paragraph explaining the mechanism.

This is the most valuable lab in the chapter. Every hour you spend here saves several later, because
these four account for nearly every "Frida doesn't work" you will ever hit.

---

## Why build the failures instead of finding them

Because a failure you built is a failure you can *vary*. When you can turn inlining on and off with a
single command and watch the hook start and stop firing, the mechanism stops being something you read
and becomes something you have seen. A failure you merely encounter in a client app teaches you a
workaround; a failure you constructed teaches you the model.

---

## Setup

Same device setup as [Lab 01](lab-01-first-contact.md). Confirm the pipe:

```bash
# host
frida-ps -U | head -3
```

---

## The target app

### `app/src/main/java/com/fridalab/modes/App.java`

```java
package com.fridalab.modes;

import android.app.Application;
import android.content.Context;
import android.util.Log;

public class App extends Application {
    private static final String TAG = "MODES";

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        // FAILURE 4 lives here: this runs before any Activity.
        Log.i(TAG, "attachBaseContext: seed=" + Vault.seedAtStartup());
        // FAILURE 2 lives here: a second DEX is loaded at runtime.
        PluginLoader.load(this);
    }
}
```

### `app/src/main/java/com/fridalab/modes/Vault.java`

```java
package com.fridalab.modes;

import android.util.Log;

public final class Vault {

    private static final String TAG = "MODES";
    private static int seed = 0;

    /** FAILURE 4 target: only ever called from attachBaseContext. */
    public static int seedAtStartup() {
        seed = 0x5A17;
        for (int i = 0; i < 7; i++) seed = (seed * 31) ^ (i * 0x9E37);
        return seed;
    }

    /**
     * FAILURE 1 target.
     * Tiny, static, final class, no side effects: a textbook inlining
     * candidate for ART's optimizing compiler.
     */
    private static boolean matches(int a, int b) {
        return a == b;
    }

    private static int hash(String s) {
        int acc = 0x5A17;
        for (int i = 0; i < s.length(); i++) {
            acc = (acc * 31) ^ (s.charAt(i) * 0x9E37);
        }
        return acc;
    }

    /** FAILURE 3 target: three overloads, only one of which the UI calls. */
    public static boolean unlock(String code) {
        return matches(hash(code), seed);
    }

    public static boolean unlock(String code, boolean strict) {
        if (!strict) return unlock(code);
        return matches(hash(code + code), seed);
    }

    public static boolean unlock(byte[] code) {
        return unlock(new String(code));
    }

    public static void report(String what) {
        Log.i(TAG, "report: " + what);
    }
}
```

### `app/src/main/java/com/fridalab/modes/PluginLoader.java`

```java
package com.fridalab.modes;

import android.content.Context;
import android.util.Log;
import dalvik.system.InMemoryDexClassLoader;

import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

/**
 * FAILURE 2 setup: loads plugin.dex from assets into an
 * InMemoryDexClassLoader — a CHILD of the app's PathClassLoader. Classes
 * defined here are invisible to Java.use by default.
 */
public final class PluginLoader {

    private static final String TAG = "MODES";
    public static ClassLoader loader = null;

    public static void load(Context ctx) {
        try {
            InputStream in = ctx.getAssets().open("plugin.dex");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();

            ByteBuffer bb = ByteBuffer.wrap(bos.toByteArray());
            loader = new InMemoryDexClassLoader(bb, ctx.getClassLoader());

            Class<?> c = loader.loadClass("com.fridalab.plugin.Engine");
            Log.i(TAG, "plugin loaded: " + c.getName());

            // Call it so the class is genuinely initialised.
            c.getMethod("greet").invoke(c.getDeclaredConstructor().newInstance());
        } catch (Throwable t) {
            Log.e(TAG, "plugin load failed: " + t);
        }
    }
}
```

### The plugin — a separate module compiled to `plugin.dex`

`plugin/com/fridalab/plugin/Engine.java`:

```java
package com.fridalab.plugin;

public class Engine {
    public String greet() {
        return "engine-v1";
    }
    public String decrypt(String blob) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < blob.length(); i++) {
            sb.append((char) (blob.charAt(i) ^ 0x2A));
        }
        return sb.toString();
    }
}
```

Build it into a DEX and drop it in `app/src/main/assets/plugin.dex`:

```bash
# host — compile the plugin to a standalone DEX
mkdir -p plugin_build
javac -source 8 -target 8 -d plugin_build plugin/com/fridalab/plugin/Engine.java

# d8 ships with the Android build tools
$ANDROID_HOME/build-tools/34.0.0/d8 \
    --output plugin_out \
    plugin_build/com/fridalab/plugin/Engine.class

cp plugin_out/classes.dex app/src/main/assets/plugin.dex
```

### `MainActivity` — calls exactly one overload

```java
package com.fridalab.modes;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.*;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        final EditText in = new EditText(this);
        final TextView out = new TextView(this);
        Button go = new Button(this);
        go.setText("Unlock");
        go.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                // Note: the ONE-argument overload.
                boolean ok = Vault.unlock(in.getText().toString());
                out.setText(ok ? "UNLOCKED" : "locked");
                Vault.report("attempt");
            }
        });
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.addView(in); root.addView(go); root.addView(out);
        setContentView(root);
    }
}
```

```bash
# host — build a RELEASE build. Debug builds behave differently for failure 1.
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
```

---

## Part 1 — Failure 1: inlining

### Reproduce it

```bash
# host — force FULL AOT compilation with aggressive inlining
adb shell cmd package compile -m speed -f com.fridalab.modes
adb shell am force-stop com.fridalab.modes
adb shell dumpsys package dexopt | grep -A3 com.fridalab.modes
#   arm64: [status=speed] [reason=cmdline]
```

`hook1.js`:

```javascript
Java.perform(function () {
  var Vault = Java.use("com.fridalab.modes.Vault");

  // `matches` is private and static — Frida can still hook it.
  Vault.matches.implementation = function (a, b) {
    console.log("[matches] " + a + " == " + b + " ?");
    return this.matches(a, b);
  };

  // A control: this one is NOT an inlining candidate (it calls into Log).
  Vault.report.implementation = function (what) {
    console.log("[report] " + what + "   <-- control hook, should always fire");
    return this.report(what);
  };

  console.log("[+] hooks installed");
});
```

```bash
# host
frida -U -f com.fridalab.modes -l hook1.js --no-pause
```

Press Unlock.

### Observe

Record exactly what you see. Expected: `[report]` fires, `[matches]` does not, and no error is
printed at any point.

### Diagnose

Work the decision tree from [§7.4](../README.md#74-the-four-failure-modes-exhaustively):

- Was an error thrown? No.
- Does the hook ever print? Never.
- Does it print if you respawn with `-f`? You already used `-f`.
- Does it print after `cmd package compile -m verify -f`? **Test it.**

```bash
# host
adb shell cmd package compile -m verify -f com.fridalab.modes
adb shell am force-stop com.fridalab.modes
frida -U -f com.fridalab.modes -l hook1.js --no-pause
```

Press Unlock again.

### Confirm the mechanism directly

Do not take the fix on faith. Read the entry point:

```bash
# host
frida -U -f com.fridalab.modes \
      -l ../../13-ART/scripts/artmethod-inspect.js --no-pause
```

```javascript
// in the REPL
art.inspect("com.fridalab.modes.Vault", "matches")
art.inspect("com.fridalab.modes.Vault", "unlock")
```

Compare the reported state under `-m speed` and under `-m verify`. Under `verify` you should see
`INTERPRETED`; under `speed` you should see an AOT-compiled entry point.

### Write it up

One paragraph. It must contain the words `entry_point_from_quick_compiled_code_`, "call instruction",
and "inlined", and must not contain "somehow".

### The variant that has no runtime fix

Enable R8 in `build.gradle`:

```groovy
buildTypes {
    release {
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
    }
}
```

Rebuild, reinstall, and check whether `matches` still exists:

```bash
# host
apktool d -o work app-release.apk
grep -rn "matches" work/smali*/com/fridalab/modes/Vault.smali
```

If it is gone, no compiler filter will bring it back. **Find the callers and hook those instead.**

---

## Part 2 — Failure 2: the wrong ClassLoader

### Reproduce it

`hook2.js`:

```javascript
Java.perform(function () {
  var Engine = Java.use("com.fridalab.plugin.Engine");   // will throw
  Engine.decrypt.implementation = function (blob) {
    var r = this.decrypt(blob);
    console.log("[engine] " + blob + " -> " + r);
    return r;
  };
});
```

```bash
# host
frida -U -f com.fridalab.modes -l hook2.js --no-pause
```

### Observe

`Error: java.lang.ClassNotFoundException: Didn't find class "com.fridalab.plugin.Engine" on path: DexPathList[...]`

Note that the error names the *path* it searched. Read it: the paths listed are the app's own
`base.apk` — the plugin DEX is not among them.

### Diagnose

```javascript
// Frida REPL
Java.perform(function () {
  Java.enumerateClassLoaders({
    onMatch: function (l) { console.log(l); },
    onComplete: function () {}
  });
});
```

You should see a `BootClassLoader`, a `PathClassLoader` for `base.apk`, and an
`InMemoryDexClassLoader`. Draw the delegation tree on paper and mark which loader
`Java.classFactory.loader` points at, and which one holds `Engine`. Then state, in one sentence, why
the direction of delegation makes the class invisible.

### Fix it three ways

```javascript
// Fix A — per-loader class factory (preferred)
Java.perform(function () {
  Java.enumerateClassLoaders({
    onMatch: function (loader) {
      try { loader.loadClass("com.fridalab.plugin.Engine"); } catch (e) { return; }
      var Engine = Java.ClassFactory.get(loader).use("com.fridalab.plugin.Engine");
      Engine.decrypt.implementation = function (b) {
        var r = this.decrypt(b);
        console.log("[A] " + b + " -> " + r);
        return r;
      };
      console.log("[A] hooked via " + loader);
    },
    onComplete: function () {}
  });
});
```

```javascript
// Fix B — swap the global loader, then RESTORE it
Java.perform(function () {
  var target = null;
  Java.enumerateClassLoaders({
    onMatch: function (l) {
      try { l.loadClass("com.fridalab.plugin.Engine"); target = l; } catch (e) {}
    },
    onComplete: function () {}
  });
  var prev = Java.classFactory.loader;
  Java.classFactory.loader = target;
  var Engine = Java.use("com.fridalab.plugin.Engine");
  Java.classFactory.loader = prev;              // ALWAYS restore
  Engine.decrypt.implementation = function (b) { /* ... */ return this.decrypt(b); };
});
```

```javascript
// Fix C — wait for the class, for when it does not exist yet
Java.perform(function () {
  var CL = Java.use("java.lang.ClassLoader");
  var done = false;
  CL.loadClass.overload("java.lang.String", "boolean").implementation =
    function (name, resolve) {
      var c = this.loadClass(name, resolve);
      if (!done && name === "com.fridalab.plugin.Engine") {
        done = true;
        console.log("[C] defined by " + this);
        var E = Java.ClassFactory.get(this).use(name);
        E.decrypt.implementation = function (b) {
          var r = this.decrypt(b); console.log("[C] " + b + " -> " + r); return r;
        };
      }
      return c;
    };
});
```

### The experiment that proves Fix B is dangerous

After Fix B, and **without** restoring the loader, try:

```javascript
Java.use("javax.crypto.Cipher");
```

Record what happens. Then explain why leaving `Java.classFactory.loader` reassigned breaks unrelated
modules.

---

## Part 3 — Failure 3: the wrong overload

### Reproduce it

`hook3.js`:

```javascript
Java.perform(function () {
  var Vault = Java.use("com.fridalab.modes.Vault");
  Vault.unlock.overload("java.lang.String", "boolean").implementation =
    function (code, strict) {
      console.log("[unlock/2] " + code + " strict=" + strict);
      return true;
    };
  console.log("[+] installed");
});
```

Press Unlock. Nothing fires — no error either.

Now try:

```javascript
Vault.unlock.implementation = function (c) { return true; };
```

Read the error. It lists every overload.

### Diagnose and fix

```javascript
// Frida REPL — list first, ALWAYS
Java.perform(function () {
  Java.use("com.fridalab.modes.Vault").unlock.overloads.forEach(function (ov, i) {
    console.log("[" + i + "] unlock(" +
      ov.argumentTypes.map(function (t) { return t.className; }).join(", ") +
      ") : " + ov.returnType.className);
  });
});
```

```javascript
// Fix — hook every overload and see which one the UI actually calls
Java.perform(function () {
  var Vault = Java.use("com.fridalab.modes.Vault");
  Vault.unlock.overloads.forEach(function (ov) {
    var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(", ");
    ov.implementation = function () {
      var args = [].slice.call(arguments).map(String);
      console.log("[hit] unlock(" + sig + ")  args=[" + args.join(", ") + "]");
      return ov.apply(this, arguments);        // NOT Vault.unlock(...)
    };
  });
});
```

### The recursion trap

Deliberately write the bug:

```javascript
var Vault = Java.use("com.fridalab.modes.Vault");
Vault.unlock.overload("java.lang.String").implementation = function (c) {
  return Vault.unlock(c);            // WRONG
};
```

Press Unlock. Record the crash. Then explain in one sentence why `this.unlock(c)` behaves differently
from `Vault.unlock(c)`, in terms of which `ArtMethod` each dispatches through.

### The `byte[]` overload

Hook `unlock([B)` and note the type string. Write down why it is `"[B"` and not `"byte[]"`.

---

## Part 4 — Failure 4: attaching instead of spawning

### Reproduce it

`hook4.js`:

```javascript
Java.perform(function () {
  var Vault = Java.use("com.fridalab.modes.Vault");
  Vault.seedAtStartup.implementation = function () {
    var r = this.seedAtStartup();
    console.log("[seed] seedAtStartup() -> 0x" + r.toString(16));
    return r;
  };
  console.log("[+] installed");
});
```

```bash
# host — RUN A: attach
adb shell am force-stop com.fridalab.modes
adb shell am start -n com.fridalab.modes/.MainActivity
sleep 3
frida -U -n com.fridalab.modes -l hook4.js
```

```bash
# host — RUN B: spawn
adb shell am force-stop com.fridalab.modes
frida -U -f com.fridalab.modes -l hook4.js --no-pause
```

### Observe and diagnose

Fill in:

| | Run A (`-n`) | Run B (`-f`) |
|---|---|---|
| `[+] installed` printed | | |
| `[seed]` printed | | |
| Error printed | | |

Then answer: what would you have concluded about this app if you had only ever run A? (The honest
answer is "that the seed is never derived", which is wrong, and which is exactly the kind of wrong
conclusion that ends up in a report.)

### The child-process variant

Add to the manifest:

```xml
<service android:name=".RemoteService" android:process=":remote" android:exported="false"/>
```

with a `RemoteService` that calls `Vault.seedAtStartup()` in its `onCreate`. Start it from
`MainActivity`. Confirm with `frida-ps -Ua` that a second process exists, and that your `-f` session
does not see it. Then instrument it with child gating:

```python
# host — gate.py
import frida, sys, time

AGENT = open("hook4.js").read()

def on_msg(m, d): print(m)

device = frida.get_usb_device(timeout=10)
device.enable_child_gating()

def attach(pid, label):
    s = device.attach(pid)
    sc = s.create_script(AGENT)
    sc.on("message", on_msg)
    sc.load()
    print(f"[+] instrumented {label} pid={pid}")
    return sc

device.on("child-added", lambda c: (
    print(f"[+] child {c.pid} {c.identifier}"),
    attach(c.pid, c.identifier or str(c.pid)),
    device.resume(c.pid)
))

pid = device.spawn(["com.fridalab.modes"])
attach(pid, "main")
device.resume(pid)
time.sleep(60)
```

---

## Part 5 — Blind diagnosis

Have a colleague (or your future self, after a week) apply **one** of these changes without telling
you which:

1. `cmd package compile -m speed -f com.fridalab.modes`
2. Move `Engine` into the plugin DEX and hook it by name
3. Change `MainActivity` to call `unlock(String, boolean)` instead of `unlock(String)`
4. Use `-n` instead of `-f`

Then diagnose from the symptom alone, using only the decision tree, and record how many steps it took.
Under four steps means you have internalised it.

---

## Hints

<details>
<summary>Hint — under -m speed the hook on `unlock` fires but `matches` does not</summary>

Correct, and instructive. `unlock` is called from `MainActivity` across a class boundary and is large
enough that the compiler kept the call. `matches` is two instructions and private, so it was inlined
into `unlock`. Inlining is per-call-site, not per-method.
</details>

<details>
<summary>Hint — `Java.ClassFactory.get` is not a function</summary>

You are on an older Frida. Use Fix B (swap and restore `Java.classFactory.loader`), and note in your
write-up why Fix A is preferable when available.
</details>

<details>
<summary>Hint — the plugin DEX will not build</summary>

`d8` requires class files compiled for Java 8 or lower bytecode in some configurations. Check
`javac -source 8 -target 8`. If `d8` is not on your PATH, find it under
`$ANDROID_HOME/build-tools/<version>/`.
</details>

---

## Success criteria

- [ ] You reproduced all four failures deliberately and recorded the symptom of each.
- [ ] For each failure you can state the symptom, the mechanism, and the fix in one sentence, without
      the word "somehow".
- [ ] You confirmed failure 1 by reading the method's entry point, not just by observing the fix work.
- [ ] You drew the ClassLoader delegation tree and can explain the direction of visibility.
- [ ] You triggered the recursion crash on purpose and can explain it in terms of `ArtMethod` dispatch.
- [ ] You filled in the Run A / Run B table for failure 4.
- [ ] You diagnosed at least one blind case in under four decision-tree steps.
- [ ] You can state why "the app detected Frida" is the *last* hypothesis, not the first.

---

## Cleanup

```bash
adb shell cmd package compile --reset com.fridalab.modes
adb shell am force-stop com.fridalab.modes
adb uninstall com.fridalab.modes
```
