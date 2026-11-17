# Lab 01 — First Contact

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 53 §1–§3](../README.md#1-introduction),
[13-ART §3.10](../../13-ART/README.md#310-forcing-compilation-with-cmd-package-compile),
a rooted device or emulator

---

## Objective

By the end of this lab you will have:

1. Deployed a version- and ABI-matched `frida-server` and proven the pipe works.
2. Hooked a Java method and read its arguments and return value.
3. **Proved experimentally** that `-f` and `-n` are not interchangeable, by observing code that only
   one of them can see.
4. Changed a method's return value and observed the app's behaviour change.

The third item is the point of the lab. Everyone reads that spawning is better than attaching; very few
people have *watched* the difference happen.

---

## Setup

### The device

Any rooted Android device or emulator, API 26 or later. An emulator image **without** Google Play
(the "AOSP" images) is rooted by default via `adb root`, which makes this lab friction-free:

```bash
# host — start an emulator and get root
emulator -avd Pixel_API_34_AOSP -writable-system &
adb wait-for-device
adb root
adb shell getenforce            # Permissive is fine for this lab
```

On a physical device, use Magisk — see [62-Magisk](../../62-Magisk/README.md).

### frida-server

```bash
# host
python3 -m pip install --upgrade frida-tools
frida --version                                   # note this EXACTLY

VER=$(frida --version)
ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
echo "host frida=$VER   device abi=$ABI"
```

Download `frida-server-${VER}-android-<arch>.xz` from
https://github.com/frida/frida/releases matching that ABI (`arm64-v8a` → `arm64`,
`armeabi-v7a` → `arm`, `x86_64` → `x86_64`).

```bash
# host
unxz frida-server-*.xz
adb push frida-server-* /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server -D'"
```

```bash
# host — the smoke test. If this prints a process list, you are ready.
frida-ps -U | head
```

> **If it fails, stop here and fix it.** Do not proceed to write hooks against a broken pipe — you
> will spend an hour debugging your JavaScript when the problem is your setup. Use the table in
> [§7.1.3](../README.md#713-selinux-and-the-execute-permission).

---

## The target app

Build this yourself. It is deliberately tiny, and building it teaches you where the interesting code
lives.

### `app/src/main/java/com/fridalab/first/App.java`

```java
package com.fridalab.first;

import android.app.Application;
import android.content.Context;
import android.util.Log;

public class App extends Application {

    private static final String TAG = "FRIDALAB";

    // Static initialiser: the FIRST app code to run in the process.
    static {
        Log.i(TAG, "STAGE 1: static initialiser of App");
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Log.i(TAG, "STAGE 2: attachBaseContext");
        // This is where a packer would decrypt its DEX and where anti-debug
        // checks live.no Activity exists yet.
        Secrets.deriveStartupKey();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "STAGE 3: Application.onCreate");
    }
}
```

### `app/src/main/java/com/fridalab/first/Secrets.java`

```java
package com.fridalab.first;

import android.util.Log;

public final class Secrets {

    private static final String TAG = "FRIDALAB";
    private static String startupKey = null;

    /**
     * Called from attachBaseContext — i.e. before any Activity exists.
     * If you attach with -n you will NEVER see this run.
     */
    public static void deriveStartupKey() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append((char) ('a' + ((i * 7 + 3) % 26)));
        }
        startupKey = sb.toString();
        Log.i(TAG, "startup key derived (length " + startupKey.length() + ")");
    }

    public static String getStartupKey() {
        return startupKey;
    }

    /** Called when the user presses the button — i.e. long after startup. */
    public static boolean checkPin(String pin) {
        boolean result = "1337".equals(pin);
        Log.i(TAG, "checkPin(" + pin + ") = " + result);
        return result;
    }

    /** An overloaded method — you will need .overload() for this one. */
    public static boolean checkPin(String pin, boolean strict) {
        if (strict) return "13371337".equals(pin);
        return checkPin(pin);
    }
}
```

### `app/src/main/java/com/fridalab/first/MainActivity.java`

```java
package com.fridalab.first;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {

    private EditText input;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        input = new EditText(this);
        input.setHint("PIN");
        status = new TextView(this);
        status.setText("locked");
        Button go = new Button(this);
        go.setText("Unlock");

        go.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                boolean ok = Secrets.checkPin(input.getText().toString());
                status.setText(ok ? "UNLOCKED" : "locked");
            }
        });

        android.widget.LinearLayout root = new android.widget.LinearLayout(this);
        root.setOrientation(android.widget.LinearLayout.VERTICAL);
        root.addView(input);
        root.addView(go);
        root.addView(status);
        setContentView(root);
    }
}
```

### `AndroidManifest.xml` — the `android:name` matters

```xml
<application
    android:name=".App"
    android:label="FridaLab01">
    <activity android:name=".MainActivity" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

```bash
# host
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## Steps

### Step 1 — Prove the app runs and see the three stages

```bash
# host — watch the app's own logging
adb logcat -c
adb logcat -s FRIDALAB &
adb shell am start -n com.fridalab.first/.MainActivity
```

You should see STAGE 1, STAGE 2, the key derivation, then STAGE 3. Note the order: the static
initialiser and `attachBaseContext` both precede `onCreate`, and all three precede any Activity.

### Step 2 — Force the interpreter

```bash
# host
adb shell cmd package compile -m verify -f com.fridalab.first
adb shell am force-stop com.fridalab.first
adb shell dumpsys package dexopt | grep -A3 com.fridalab.first
```

Confirm the status line says `verify`. You are removing one variable before you introduce any others.

### Step 3 — Your first hook

Create `hook.js`:

```javascript
// hook.js — observe checkPin
Java.perform(function () {
  console.log("[+] agent running in " +
    Java.use("android.app.ActivityThread").currentPackageName());

  var Secrets = Java.use("com.fridalab.first.Secrets");

  // ALWAYS list the overloads before hooking. There are two checkPin methods.
  Secrets.checkPin.overloads.forEach(function (ov, i) {
    console.log("  [" + i + "] checkPin(" +
      ov.argumentTypes.map(function (t) { return t.className; }).join(", ") +
      ") : " + ov.returnType.className);
  });

  Secrets.checkPin.overload("java.lang.String").implementation = function (pin) {
    console.log("[>] checkPin(\"" + pin + "\")");
    var r = this.checkPin(pin);       // this. — NOT Secrets.
    console.log("[<] -> " + r);
    return r;
  };

  console.log("[+] hook installed");
});
```

```bash
# host
frida -U -f com.fridalab.first -l hook.js --no-pause
```

Type a PIN in the app, press Unlock, and watch the output. Try `1337` and something else.

**Checkpoint:** you should see both overloads listed and your `[>]`/`[<]` lines on each button press.

### Step 4 — The experiment: `-f` versus `-n`

This is the core of the lab. Add a second hook to `hook.js`:

```javascript
// hook.js — add this block
Java.perform(function () {
  var Secrets = Java.use("com.fridalab.first.Secrets");

  Secrets.deriveStartupKey.implementation = function () {
    console.log("[!!] deriveStartupKey() CALLED — we were early enough");
    this.deriveStartupKey();
    console.log("[!!] startup key = " + Secrets.getStartupKey());
  };

  var App = Java.use("android.app.Application");
  App.attachBaseContext.overload("android.content.Context").implementation =
    function (ctx) {
      console.log("[!!] Application.attachBaseContext reached");
      return this.attachBaseContext(ctx);
    };
});
```

**Run A — attach:**

```bash
# host
adb shell am force-stop com.fridalab.first
adb shell am start -n com.fridalab.first/.MainActivity
sleep 3
frida -U -n com.fridalab.first -l hook.js
```

**Run B — spawn:**

```bash
# host
adb shell am force-stop com.fridalab.first
frida -U -f com.fridalab.first -l hook.js --no-pause
```

Record what you see in each run:

| Output line | Run A (`-n`) | Run B (`-f`) |
|---|---|---|
| `[+] hook installed` | | |
| `[!!] Application.attachBaseContext reached` | | |
| `[!!] deriveStartupKey() CALLED` | | |
| `[>] checkPin(...)` after pressing the button | | |

**Write down, in one sentence, why the table looks the way it does.** If your sentence contains the
word "somehow", read [§7.4.4](../README.md#744-failure-4--attaching-instead-of-spawning) again and
rewrite it.

### Step 5 — Change a decision

```javascript
// hook.js — replace the checkPin hook with this
Secrets.checkPin.overload("java.lang.String").implementation = function (pin) {
  var real = this.checkPin(pin);
  console.log("[force] checkPin(\"" + pin + "\") real=" + real + " -> true");
  return true;
};
```

Re-run with `-f`, type any PIN, press Unlock. The UI should say `UNLOCKED` while your log shows
`real=false`.

That pair of facts — the real answer was `false` and the app proceeded anyway — is what a finding
looks like. Not "I bypassed it", but "the authorisation decision is a client-side boolean and the app
honours it without any server confirmation".

### Step 6 — The overload trap

Try hooking the *other* `checkPin` deliberately:

```javascript
Secrets.checkPin.overload("java.lang.String", "boolean").implementation =
  function (pin, strict) {
    console.log("[strict] checkPin(" + pin + ", " + strict + ")");
    return this.checkPin(pin, strict);
  };
```

Nothing fires, because the Activity calls the one-argument version. Now try assigning
`.implementation` on the group without `.overload(...)`:

```javascript
Secrets.checkPin.implementation = function (pin) { return true; };
```

Read the error carefully. That message is the one you will see most often in your career.

---

## Hints

<details>
<summary>Hint 1 — `frida-ps -U` prints nothing</summary>

The server is not running, is the wrong ABI, or is being blocked. Check in this order:

```bash
adb shell "su -c 'ps -A | grep frida'"
adb shell "su -c '/data/local/tmp/frida-server'"    # run in foreground, read the error
adb shell "su -c 'dmesg | grep -i avc | tail'"
```
</details>

<details>
<summary>Hint 2 — `unable to communicate with remote frida-server`</summary>

Version mismatch. `frida --version` on the host must exactly equal the `frida-server` release you
downloaded. Re-download; do not try to work around it.
</details>

<details>
<summary>Hint 3 — the hook installs but `checkPin` never fires</summary>

Did you press the button? If yes: did you run `cmd package compile -m verify -f`? A debug build is
normally interpreted anyway, so this is unlikely here, but form the habit.

Also check you are hooking `com.fridalab.first.Secrets`, not `MainActivity`.
</details>

<details>
<summary>Hint 4 — `attachBaseContext` never prints even with -f</summary>

You hooked `android.app.Application.attachBaseContext`. Because `App` overrides it, the *subclass*
method runs — and calls `super.attachBaseContext`, which is the one you hooked. If it still does not
fire, hook `com.fridalab.first.App.attachBaseContext` directly and compare.

This is a small preview of the "wrong class in the hierarchy" problem from
[§7.4.3](../README.md#743-failure-3--the-wrong-overload).
</details>

---

## Success criteria

You have finished when all of the following are true.

- [ ] `frida-ps -U` lists processes, and you can state your host and device Frida versions from memory.
- [ ] You can name your device's ABI and explain why it determines which `frida-server` you need.
- [ ] Your hook prints both `checkPin` overloads with their exact argument types.
- [ ] You have filled in the Run A / Run B table and can explain every cell.
- [ ] You forced `checkPin` to return `true` and saw the UI unlock with a wrong PIN.
- [ ] You can explain, without notes, why `Secrets.checkPin(pin)` inside the hook would be a bug.
- [ ] You ran `cmd package compile --reset com.fridalab.first` at the end.

---

## Going further

1. Hook `Secrets.getStartupKey` and print the derived key without touching `deriveStartupKey`.
2. Add a `Java.choose` call to find live `MainActivity` instances and read `status`'s text.
3. Modify the app so the PIN check happens in `attachBaseContext`, and confirm that only `-f` can see
   it.
4. Run the app under `frida-trace -U -f com.fridalab.first -j "com.fridalab.*!*"` and compare the
   discovery experience with writing hooks by hand.

---

## Cleanup

```bash
adb shell cmd package compile --reset com.fridalab.first
adb shell am force-stop com.fridalab.first
adb uninstall com.fridalab.first
adb shell "su -c 'pkill frida-server'"
```
