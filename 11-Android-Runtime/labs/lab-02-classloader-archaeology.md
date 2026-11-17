# Lab 02 — ClassLoader Archaeology

> **Difficulty:** Intermediate · **Time:** 90–150 minutes · **Chapter:** [11 — Android Runtime](../README.md)

In [Lab 01](lab-01-observing-the-runtime.md) you watched the runtime from outside. Now you go inside a
live process and dig through the object graph that decides *which bytes become which class*. Nothing
is loaded by magic: every class arrives through a `ClassLoader`, every `ClassLoader` holds an ordered
list of DEX files, and that list is walked in a defined order. When an app hides code, patches itself,
or ships a plugin system, it manipulates this graph. You cannot attack what you cannot enumerate.

---

## Objective

Build a small app with a deliberately interesting loader topology, attach
[Frida](../../53-Frida/README.md) to it, and:

1. Enumerate every `ClassLoader` alive in the process and print each parent chain.
2. Reach into `BaseDexClassLoader.pathList`, then `DexPathList.dexElements`, and print the path of
   every DEX file the process has open.
3. Load a class that exists in **two** loaders and prove by identity, not assertion, which one won.

> **Definition — ClassLoader.** A *ClassLoader* turns a class name such as `com.example.Greeter`
> into a loaded, executable class. It is not a file reader; it is a namespace authority. Two classes
> with identical names loaded by two different ClassLoaders are different types to the runtime,
> cannot be cast to one another, and each carry their own static fields. That rule explains most
> "impossible" `ClassCastException` messages in Android.

---

## Prerequisites

- [Lab 01](lab-01-observing-the-runtime.md) completed.
- Android Studio or a Gradle setup that can build and install a debug APK; see
  [08 — Build System](../../08-Build-System/README.md).
- `d8` on your `PATH`, from `$ANDROID_HOME/build-tools/<version>/`, plus a JDK 17+ with `javac`.
- `frida-server` running on a rooted device or emulator (API 28+) with a matching host client. If
  that is not yet routine, work through [53 — Frida](../../53-Frida/README.md) first.

---

## Setup

### Step A — Create the app

New project, package `com.example.loaderlab`, minSdk 26, language Java.

```java
// file: app/src/main/java/com/example/loaderlab/Greeter.java — compiled into base.apk, runs on the device
package com.example.loaderlab;

public class Greeter {
    public static String who() {
        return "greeter-from-base-apk";
    }
}
```

```java
// file: app/src/main/java/com/example/loaderlab/MainActivity.java — runs on the device
package com.example.loaderlab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import dalvik.system.DexClassLoader;

public class MainActivity extends Activity {

    public static final String TAG = "LoaderLab";

    /** Copied out of assets so we can hand DexClassLoader a real filesystem path. */
    private File stageAsset(String name) throws Exception {
        File out = new File(getFilesDir(), name);
        try (InputStream in = getAssets().open(name);
             OutputStream os = new FileOutputStream(out)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
        }
        return out;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        setContentView(tv);
        StringBuilder sb = new StringBuilder();
        try {
            String path = stageAsset("greeter2.dex").getAbsolutePath();
            // Loader A's parent is the app loader, which already defines Greeter.
            DexClassLoader childOfApp = new DexClassLoader(path, null, null, getClassLoader());
            // Loader B's parent is the boot loader, which does NOT define Greeter.
            DexClassLoader childOfBoot =
                    new DexClassLoader(path, null, null, String.class.getClassLoader());

            Class<?> viaApp  = childOfApp.loadClass("com.example.loaderlab.Greeter");
            Class<?> viaBoot = childOfBoot.loadClass("com.example.loaderlab.Greeter");

            sb.append("direct         : ").append(Greeter.who()).append('\n')
              .append("via childOfApp : ").append(viaApp.getMethod("who").invoke(null)).append('\n')
              .append("via childOfBoot: ").append(viaBoot.getMethod("who").invoke(null)).append('\n')
              .append("same class?    : ").append(viaApp == viaBoot).append('\n');
            Log.i(TAG, sb.toString());
        } catch (Throwable t) {
            Log.e(TAG, "setup failed", t);
            sb.append("error: ").append(t);
        }
        tv.setText(sb.toString());
    }
}
```

### Step B — Build the shadowing DEX

A second `Greeter` with the same fully-qualified name and a different body. It must not be part of the
app module, or the build would fail on a duplicate class.

```java
// file: ~/loaderlab-alt/com/example/loaderlab/Greeter.java — compiled by hand on your host machine
package com.example.loaderlab;

public class Greeter {
    public static String who() {
        return "greeter-from-secondary-dex";
    }
}
```

```bash
# runs on your host machine
mkdir -p ~/loaderlab-alt/com/example/loaderlab ~/loaderlab-alt/classes
javac -d ~/loaderlab-alt/classes ~/loaderlab-alt/com/example/loaderlab/Greeter.java
"$ANDROID_HOME/build-tools/34.0.0/d8" --min-api 26 \
    --output ~/loaderlab-alt ~/loaderlab-alt/classes/com/example/loaderlab/Greeter.class
mkdir -p ~/AndroidStudioProjects/LoaderLab/app/src/main/assets
cp ~/loaderlab-alt/classes.dex \
   ~/AndroidStudioProjects/LoaderLab/app/src/main/assets/greeter2.dex
```

```bash
# runs on your host machine
./gradlew installDebug
adb logcat -c && adb shell am start -n com.example.loaderlab/.MainActivity && adb logcat -s LoaderLab
```

> **Warning.** `DexClassLoader`'s second parameter, `optimizedDirectory`, has been deprecated since
> API 26 and is ignored by the runtime. Passing `null` is correct on modern Android. Code online that
> passes `getCodeCacheDir()` is not wrong, merely obsolete.

---

## Steps

### Step 1 — Enumerate the loaders, their parent chains, and their DEX files

The interesting state is private, but Frida's Java bridge exposes private fields as `.value`, so no
reflection boilerplate is needed.

```javascript
// Frida script — save as chain.js, run: frida -U -n com.example.loaderlab -l chain.js
Java.perform(function () {
    var BDCL = Java.use('dalvik.system.BaseDexClassLoader');
    var DPL  = Java.use('dalvik.system.DexPathList');
    var EL   = Java.use('dalvik.system.DexPathList$Element');

    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            // (a) the parent chain, innermost first
            var cur = loader, depth = 0;
            while (cur !== null) {
                console.log("  ".repeat(depth) + "- " + cur.$className + " @" + cur.hashCode());
                cur = cur.getParent();
                depth++;
            }
            // (b) the DEX files this loader has open
            try {
                var pl  = Java.cast(Java.cast(loader, BDCL).pathList.value, DPL);
                var els = pl.dexElements.value;
                for (var i = 0; i < els.length; i++) {
                    var df = Java.cast(els[i], EL).dexFile.value;
                    console.log("    dex[" + i + "] = " + (df === null ? "<none>" : df.getName()));
                }
            } catch (e) { console.log("    (not a BaseDexClassLoader)"); }
            console.log("");
        },
        onComplete: function () { console.log("[*] enumeration complete"); }
    });
});
```

Every chain terminates at `java.lang.BootClassLoader`, whose `getParent()` returns `null`. That is
the root of the namespace: the classes ART mapped out of the boot image in
[Lab 01](lab-01-observing-the-runtime.md), such as `java.lang.String` and `android.app.Activity`. You
should also see the app's loader listing `/data/app/~~…/com.example.loaderlab-…/base.apk`, and two
further loaders each listing `/data/user/0/com.example.loaderlab/files/greeter2.dex`.

> **Mental Model.** The loader chain is a chain of librarians, not a chain of shelves. When you ask
> a librarian for a book she does not look on her own shelf first — she asks her supervisor, who asks
> hers, all the way to the head librarian. Only when everyone above says "we don't have it" does she
> check her own shelf. That upward-first rule is **parent delegation**, and it is why an app cannot
> replace `java.lang.String` by shipping its own copy.

> **Under the Hood.** `BaseDexClassLoader` holds one field, `pathList`, of type `DexPathList`.
> `DexPathList` holds an array `dexElements`, and each `Element` wraps one open `DexFile`. The
> `DexFile` object is a thin Java handle over a native cookie pointing at ART's internal structures.
> `findClass` walks `dexElements` **in order** and returns the first match, which is the entire
> mechanism behind hot-patching frameworks: they prepend an element. The framework sources are
> `libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java` and
> `libcore/dalvik/src/main/java/dalvik/system/DexPathList.java`.

`DexFile.getName()` returns the path the file was opened from. For a loader created from a byte buffer
rather than a file, the name is a synthetic string with no `/` in it — the tell you will exploit in
[Lab 03](lab-03-dynamic-dex-loading-and-hooking.md).

### Step 2 — Prove parent delegation by identity

The app's own logcat output tells the story first.

| Line | Value | Why |
|---|---|---|
| `direct` | `greeter-from-base-apk` | The compiler bound the call to the app loader's class |
| `via childOfApp` | `greeter-from-base-apk` | Delegation reached the app loader, which had it |
| `via childOfBoot` | `greeter-from-secondary-dex` | Delegation reached the boot loader, which did not |
| `same class?` | `false` | Two distinct `Class` objects, same name, different loaders |

Now confirm the same fact from Frida, so you are not trusting code you wrote, and hook both copies.

```javascript
// Frida script — save as delegation.js, run: frida -U -n com.example.loaderlab -l delegation.js
Java.perform(function () {
    var TARGET = "com.example.loaderlab.Greeter";
    var distinct = {};

    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            var cls;
            try { cls = loader.loadClass(TARGET); }
            catch (e) { return; }              // this loader cannot see Greeter at all

            var definer = cls.getClassLoader();
            distinct["" + cls.hashCode()] = definer.$className + "@" + definer.hashCode();
            console.log("asked " + loader.$className + "@" + loader.hashCode() +
                        " -> Class@" + cls.hashCode() +
                        " defined by " + definer.$className + "@" + definer.hashCode());

            // Bind a factory to the DEFINING loader, then hook the class it really owns.
            var G = Java.ClassFactory.get(definer).use(TARGET);
            G.who.implementation = function () {
                var orig = this.who();
                console.log("[hook] original returned: " + orig);
                return "HOOKED(" + orig + ")";
            };
        },
        onComplete: function () {
            console.log("\n[*] distinct " + TARGET + " Class objects: " +
                        Object.keys(distinct).length);
        }
    });
});
```

Two distinct `Class` objects means two distinct types. Ask ART to cast one to the other and it
refuses, even though `getName()` returns the identical string for both. Restart the activity with the
script attached and both greetings should be wrapped in `HOOKED(...)`.

> **Pentester's Note.** When an app appears to have a check you already patched, and the patch has
> no effect, count the loaders. Packers and commercial protectors routinely install a loader whose
> `dexElements` ordering means the class Frida hooked is not the class that executes. `Java.use()`
> resolves through Frida's chosen loader; if the target lives elsewhere you hooked a namesake. The fix
> is `Java.ClassFactory.get(loader)`, exactly as above.

---

## Hints

- `Java.enumerateClassLoaders` reports only loaders that are reachable and alive. A loader created and
  dropped before you attached will not appear. Spawn with `frida -U -f com.example.loaderlab` and
  `%resume` so you are attached before `onCreate` runs.
- If `Java.cast(loader, BaseDexClassLoader)` throws for a loader you expected to succeed, it is
  probably a custom loader extending `ClassLoader` directly. Print `loader.$className` before casting.
- `Element.dexFile` is not named identically on every release. If the field access throws, list the
  real names from Frida with `EL.class.getDeclaredFields()` and adapt.
- `ClassNotFoundException` inside `onMatch` is expected for most loaders. Catch it and continue rather
  than aborting the enumeration.
- If the app crashes in `stageAsset`, `assets/greeter2.dex` is missing. Check with
  `unzip -l app-debug.apk | grep greeter2`.

---

## Success Criteria

1. You can print the full parent chain of every loader, ending at `BootClassLoader`.
2. You can print the path of every DEX file open in the process using only `pathList` and
   `dexElements`, with no `Java.reflect` boilerplate.
3. Your Frida output shows **two** distinct `Class` objects for `com.example.loaderlab.Greeter`, with
   different hash codes and different defining loaders.
4. You can explain in complete sentences, without the word "somehow", why `childOfApp` returned the
   base APK's `Greeter` while `childOfBoot` returned the secondary DEX's.
5. You have hooked `Greeter.who()` in both loaders and seen both hooks fire.

---

## Solution

<details>
<summary>Reveal solution</summary>

### What the enumeration shows

```text
# example output — hash codes differ on your device
- dalvik.system.PathClassLoader @87654321        <- the app's own loader
  - java.lang.BootClassLoader @12345678
- dalvik.system.DexClassLoader @11223344         <- childOfApp
  - dalvik.system.PathClassLoader @87654321
    - java.lang.BootClassLoader @12345678
- dalvik.system.DexClassLoader @44332211         <- childOfBoot
  - java.lang.BootClassLoader @12345678
```

The `PathClassLoader` is the app's own loader, created by `ActivityThread` when the process was
specialised after the Zygote fork. The shape of the tree is the whole answer: `childOfBoot`
deliberately bypasses the app loader, so nothing above it knows `com.example.loaderlab.Greeter`
exists.

### Why delegation produces the observed result

`ClassLoader.loadClass`, implemented in
`libcore/ojluni/src/main/java/java/lang/ClassLoader.java`, is essentially this algorithm:

1. Ask whether this loader has already defined the class. If yes, return it.
2. Otherwise ask the parent, which applies the same algorithm recursively.
3. Only if the parent chain fails, call this loader's own `findClass`, which for a
   `BaseDexClassLoader` walks `pathList.dexElements` in order.

For `childOfApp`, step 2 reaches the app's `PathClassLoader`, which finds `Greeter` inside `base.apk`.
`findClass` on `childOfApp` is therefore never called and `greeter2.dex` is never consulted, even
though it sits in that loader's `dexElements`.

For `childOfBoot`, step 2 reaches `BootClassLoader`, which knows only boot-image classes and throws
`ClassNotFoundException`. Step 3 then runs, `findClass` walks `dexElements`, finds `Greeter` in
`greeter2.dex`, and **defines** it. Defining is the key verb: the loader that calls `defineClass` is
recorded as the class's defining loader forever, and that is what `Class.getClassLoader()` returns.

Because the two `Class` objects were defined by different loaders, ART treats them as unrelated types
with separate static field storage, and a cast between them throws `ClassCastException` with a message
naming the same class twice — one of the most confusing errors a beginner meets, and now one you can
explain. Note also that `delegation.js` hooks `definer`, not `loader`; hooking the loader that was
merely *asked* would install the same hook twice on one class and never touch the other.

### What to take into a real engagement

- The number of `BaseDexClassLoader` instances measures how much code the app loads outside its own
  APK. One loader is an ordinary app; five or six usually means a plugin framework, a packer, or an ad
  SDK shipping its own DEX.
- `dexElements` ordering is attackable. Prepending an element to an existing loader's array is the
  classic hot-patch primitive, and it lets your class win without touching any file on disk.
- Obfuscators rename app classes but cannot rename `pathList` or `dexElements`, because those are
  framework fields the app does not own. Loader archaeology therefore survives obfuscation that
  defeats name-based searching; see [40 — Obfuscation](../../40-Obfuscation/README.md).

</details>

---

**Next:** [Lab 03 — Dynamic DEX Loading and Hooking](lab-03-dynamic-dex-loading-and-hooking.md) —
build an app that never writes its real code to disk, then take that code anyway.
