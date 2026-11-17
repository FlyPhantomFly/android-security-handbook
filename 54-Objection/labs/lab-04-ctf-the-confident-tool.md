# Lab 04 — CTF: The Confident Tool

**Difficulty:** Advanced
**Time:** 4–8 hours
**Prerequisites:** [lab-01](lab-01-first-session.md), [lab-02](lab-02-objection-versus-a-script.md)
and [lab-03](lab-03-mapping-the-envelope.md) completed. You can write and debug a Frida agent.
[53-Frida](../../53-Frida/README.md) §3.9 and §7.4 available for reference.

---

## The scenario

`com.pentest.ch54.ctf` is a licence-gated notes application. It refuses to reveal its content
and displays:

> **This device is not secure.**

You have a rooted phone, a matching `frida-server`, and Objection.

**Every Objection command you run will report success. None of them will change anything.**

That is not a bug in your setup and it is not a trick. It is four stacked defences, each chosen
because it sits in a different blind spot of a canned tool. Your job is to find all four, defeat
them, and recover the flag.

**Flag format:** `CH54{...}`

> You build this application yourself, from sources you write in Part 0. Nothing here is pointed
> at third-party software. See [SECURITY.md](../../SECURITY.md) for authorised-testing scope.

---

## Objective

Recover the flag **three independent ways**, and — this is the graded part — write up which
defence defeated which tool and why. A flag with no explanation scores zero in this lab, because
the explanation is the deliverable everywhere except a CTF.

---

## Part 0 — Build the challenge (45 min)

The challenge app ships at [`../examples/ctf-app/`](../examples/ctf-app/) — four files, listed
below so you can see what you are building. It uses the same build pipeline as the rest of the
chapter; point `build.sh` at `ctf-app` instead of `target-app`, or copy the `build_app` function
from [`30-Activities/examples/build.sh`](../../30-Activities/examples/build.sh) if you want both
apps in one script.

> **Build it, then close the files, and do not read Part 2.** The whole value of the CTF is
> meeting the defences blind and finding them by observation. The sources are shipped so the
> lab is runnable, not so you can read the answers — every defence is discoverable from the
> recon script in Part 2 without opening a single `.java` file.

The four files, for reference:

### `examples/ctf-app/AndroidManifest.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.pentest.ch54.ctf">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <application android:label="CH54 CTF" android:name=".CtfApp" android:allowBackup="false">
        <activity android:name=".VaultActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### `examples/ctf-app/CtfApp.java`

```java
package com.pentest.ch54.ctf;

import android.app.Application;
import android.content.Context;
import android.util.Log;

public class CtfApp extends Application {
    public static boolean secure = true;

    // DEFENCE 1. This runs before Application.onCreate, before any Activity, and
    // before an ATTACHING tool can possibly have installed a hook.
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        secure = Guard.earlyVerdict();
        Log.i("CH54CTF", "early verdict recorded: " + secure);
    }
}
```

### `examples/ctf-app/Guard.java`

```java
package com.pentest.ch54.ctf;

import android.os.Build;
import android.util.Log;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

public final class Guard {
    static final String TAG = "CH54CTF";
    private Guard() { }

    // DEFENCE 2. A path that is not on any canned list.
    static boolean magiskPath() {
        return new File("/sbin/magisk").exists()
            || new File("/data/adb/magisk").exists()
            || new File("/data/adb/modules").exists();
    }

    // DEFENCE 3. The ProcessBuilder route. Nothing in a stock root bypass
    // touches this, because stock bypasses hook Runtime.exec(String).
    static boolean whichSu() {
        try {
            Process p = new ProcessBuilder("/system/bin/which", "su").start();
            BufferedReader r = new BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            String line = r.readLine();
            r.close();
            return line != null && line.length() > 0;
        } catch (Exception e) { return false; }
    }

    // DEFENCE 4. procfs. Not a File.exists() call, not an exec, not a String.contains.
    static boolean mounts() {
        try {
            BufferedReader r = new BufferedReader(new FileReader("/proc/self/mounts"));
            String line; boolean hit = false;
            while ((line = r.readLine()) != null) {
                if (line.contains("magisk") || line.contains("KSU")) { hit = true; break; }
            }
            r.close();
            return hit;
        } catch (Exception e) { return false; }
    }

    static boolean testKeys() {
        String t = Build.TAGS;
        return t != null && t.indexOf("test-keys") >= 0;   // indexOf, not contains
    }

    /** Returns true when the device looks CLEAN. */
    static boolean earlyVerdict() {
        boolean bad = magiskPath() | whichSu() | mounts() | testKeys();
        Log.i(TAG, "guard: magisk=" + magiskPath() + " which=" + whichSu()
                 + " mounts=" + mounts() + " tags=" + testKeys());
        return !bad;
    }
}
```

### `examples/ctf-app/VaultActivity.java`

```java
package com.pentest.ch54.ctf;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class VaultActivity extends Activity {

    // The flag is NOT a string constant. It is derived, so that a strings dump
    // and a heap search before unlock both come up empty.
    private static String reveal() throws Exception {
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) { key[i] = (byte) (0x41 + i); }
        byte[] iv = new byte[16];
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return new String(c.doFinal(android.util.Base64.decode(BLOB, 0)), "UTF-8");
    }

    // Produce BLOB yourself with the helper in Part 0.1 so YOUR flag is unique.
    private static final String BLOB = "<paste your base64 ciphertext here>";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);
        try {
            if (!CtfApp.secure) { throw new IllegalStateException("not secure"); }
            tv.setText(reveal());
            Log.i(Guard.TAG, "vault opened");
        } catch (Exception e) {
            tv.setText("This device is not secure.");
            Log.i(Guard.TAG, "vault refused: " + e.getClass().getSimpleName());
        }
        setContentView(tv);
    }
}
```

### Part 0.1 — generate your own flag

```bash
# host -- key is 0x41..0x50, IV is 16 zero bytes, AES-128-CBC
python3 -B - <<'PY'
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
flag = b"CH54{read_the_agent_not_the_output}"     # change this
key = bytes(range(0x41, 0x51)); iv = b"\x00" * 16
p = padding.PKCS7(128).padder(); data = p.update(flag) + p.finalize()
e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
print(base64.b64encode(e.update(data) + e.finalize()).decode())
PY
```

Paste the output into `BLOB`, build, install, and **close the source files**.

```bash
# host
cd ../examples && OUTDIR=/tmp/ch54 ./build.sh --install
adb shell am start -n com.pentest.ch54.ctf/.VaultActivity
```

You should see **This device is not secure.**

---

## Part 1 — Fail with Objection, thoroughly (60 min)

Do this properly. The point is to experience four different commands reporting success while
nothing changes.

### Task 1.1

```bash
# host
adb shell am force-stop com.pentest.ch54.ctf
objection -S <serial> -g com.pentest.ch54.ctf explore
```
```
# objection REPL
env
android root disable
android hooking set return_value com.pentest.ch54.ctf.Guard.earlyVerdict true
android hooking set return_value com.pentest.ch54.ctf.Guard.magiskPath false
android hooking watch class com.pentest.ch54.ctf.Guard --dump-return
android intent launch_activity com.pentest.ch54.ctf.VaultActivity
```

Every command returns cleanly. The Activity still refuses.

### Task 1.2 — record the symptom precisely

For each command, write down what it *reported* and what *changed*. You should have a column of
"success" against a column of "nothing".

### Question 1.1

`android hooking set return_value ...Guard.earlyVerdict true` reported success. Why did the app
not open?

<details>
<summary>Hint 1</summary>
When does `earlyVerdict()` run? Look at the logcat timestamps relative to when you connected.
</details>

<details>
<summary>Hint 2</summary>
Objection attaches to a running process and spawns a stopped one. Which did it do? What runs
before your hook exists either way?
</details>

<details>
<summary>Answer</summary>

`earlyVerdict()` is called from `Application.attachBaseContext`, which runs **before**
`Application.onCreate` and before any Activity. Its result is stored in the static field
`CtfApp.secure`.

Even when Objection *spawns* the process, the hook is installed after `script.load()` and the
process is resumed immediately afterwards — but the REPL command that installs the
`set return_value` hook is typed *seconds later*, long after `attachBaseContext` has run.
Hooking a method that already ran and whose result was cached in a static changes nothing.

This is failure mode 3 (chapter §7.3) in its hardest form: not merely "you attached late" but
"the decision is *cached*", so re-triggering the Activity does not re-run the check.

**The reason the flag is not "hook the gate" is that the gate is a memory of a decision,
not a decision.**
</details>

---

## Part 2 — Find the four defences (90 min)

### Task 2.1 — instrument, do not bypass

Write a Frida script that **reports and changes nothing**, spawned with `-f` so it is in place
before `attachBaseContext`:

```javascript
// ctf-recon.js -- observe only
Java.perform(function () {
    ['java.io.File', 'java.lang.ProcessBuilder', 'java.io.FileReader'].forEach(function (n) {
        console.log('[+] ' + n + ' available');
    });

    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var p = this.getAbsolutePath(); var r = this.exists();
        console.log('[File.exists] ' + p + ' -> ' + r);
        return r;
    };

    var PB = Java.use('java.lang.ProcessBuilder');
    PB.start.implementation = function () {
        console.log('[ProcessBuilder] ' + this.command().toString());
        return this.start();
    };

    var FR = Java.use('java.io.FileReader');
    FR.$init.overload('java.lang.String').implementation = function (p) {
        console.log('[FileReader] ' + p);
        return this.$init(p);
    };
});
```

```bash
# host
adb shell am force-stop com.pentest.ch54.ctf
frida -U -f com.pentest.ch54.ctf -l ctf-recon.js
```

### Task 2.2

From the output alone, list every probe the app makes and classify each against your capability
statement from [lab-03](lab-03-mapping-the-envelope.md).

### Question 2.1

Name all four defences and say, for each, which canned-tool blind spot it exploits.

<details>
<summary>Answer</summary>

| # | Defence | Blind spot |
|---|---|---|
| 1 | The verdict is computed in `attachBaseContext` and **cached in a static field** | Timing. Any hook installed after connect is too late, and re-launching the Activity does not re-run the check |
| 2 | `File.exists("/sbin/magisk")`, `/data/adb/magisk`, `/data/adb/modules` | None of these is on the thirteen-path list, which is matched by exact string equality |
| 3 | `new ProcessBuilder("/system/bin/which","su").start()` | Stock bypasses hook `Runtime.exec(String)`. `ProcessBuilder` is two frames below it |
| 4 | Reading `/proc/self/mounts` with a `FileReader` | procfs is not `File.exists()`, not an `exec`, and not `String.contains`. No canned root command touches it |

A fifth, minor one: `Build.TAGS.indexOf("test-keys")` rather than `.contains(...)`, so even the
one string hook a canned tool installs does not apply.
</details>

---

## Part 3 — Recover the flag, three ways (90 min)

Each route must be genuinely independent — a different mechanism, not the same idea twice.

### Route 1 — defeat the guard at the right moment

Hook the four probes **before** `attachBaseContext` runs. `frida -f` is mandatory.

<details>
<summary>Hint</summary>
Your script's top-level `Java.perform` runs at `script.load()`, which happens while the process
is still suspended. That is early enough. Objection's REPL is not, because you type the command
after the resume.
</details>

<details>
<summary>Solution sketch</summary>

```javascript
// route1.js -- frida -U -f com.pentest.ch54.ctf -l route1.js
Java.perform(function () {
    var BAD = ['/sbin/magisk', '/data/adb/magisk', '/data/adb/modules'];

    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        if (BAD.indexOf(this.getAbsolutePath()) >= 0) { return false; }
        return this.exists();
    };

    var PB = Java.use('java.lang.ProcessBuilder');
    PB.start.implementation = function () {
        if (this.command().toString().indexOf('su') >= 0) {
            throw Java.use('java.io.IOException').$new('nope');
        }
        return this.start();
    };

    var FR = Java.use('java.io.BufferedReader');
    FR.readLine.implementation = function () {
        var l = this.readLine();
        if (l !== null && (l.indexOf('magisk') >= 0 || l.indexOf('KSU') >= 0)) { return ''; }
        return l;
    };
});
```

Note the `BufferedReader.readLine` hook: you cannot usefully hook "reading /proc/self/mounts",
so you filter the *lines*. That is the kind of move a canned tool cannot make, because it
requires knowing what the app is looking for.
</details>

### Route 2 — overwrite the cached verdict

Do not fight the guard at all. Let it run, then change its answer before `VaultActivity` reads it.

<details>
<summary>Hint</summary>
`CtfApp.secure` is a public static boolean. Frida can write static fields. What is the latest
moment you could set it and still win?
</details>

<details>
<summary>Solution sketch</summary>

```javascript
// route2.js
Java.perform(function () {
    var Vault = Java.use('com.pentest.ch54.ctf.VaultActivity');
    Vault.onCreate.implementation = function (b) {
        Java.use('com.pentest.ch54.ctf.CtfApp').secure.value = true;   // flip the cache
        return this.onCreate(b);
    };
});
```

This works even on **attach**, because it does not care when the guard ran. That is the general
lesson: when a decision is cached, attack the cache, not the decider — and it is the move that
turns a "too late to hook" situation into a solvable one.
</details>

### Route 3 — never let the app decide

Do not touch the guard or the cache. Call `reveal()` yourself.

<details>
<summary>Hint</summary>
`reveal()` is private and static. Frida does not care about `private`. What do you need in order
to call a static method on a class that is already loaded?
</details>

<details>
<summary>Solution sketch</summary>

```javascript
// route3.js -- attach is fine; the app need not be "unlocked" at all
Java.perform(function () {
    var V = Java.use('com.pentest.ch54.ctf.VaultActivity');
    console.log('FLAG: ' + V.reveal());
});
```

If `reveal()` has been inlined or renamed, fall back to hooking
`javax.crypto.Cipher.doFinal([B)[B` and printing the plaintext — the key never has to be
recovered, because you borrow the app's own crypto. That is the pattern
[53's `sign-oracle.js`](../../53-Frida/scripts/sign-oracle.js) generalises.
</details>

### Task 3.1

Get the flag by all three routes. Record which ones work under **attach** and which require
**spawn**.

### Question 3.1

Route 2 works on attach; route 1 does not. Why, and what does that tell you about choosing an
approach when you cannot control process start-up?

<details>
<summary>Answer</summary>

Route 1 must intercept the probes, and the probes happen in `attachBaseContext` — before an
attaching session exists. Route 2 only has to change a value between the moment the guard writes
it and the moment `VaultActivity` reads it, and that window is open every time the Activity
starts.

The general rule: **when you are late, stop attacking the computation and start attacking the
place the result was stored.** Cached decisions, static fields, `SharedPreferences` and
singletons are all later, wider windows than the check itself.
</details>

---

## Part 4 — The write-up (45 min)

This is the graded deliverable. A flag alone scores zero.

### Task 4.1

Produce a document containing:

1. **The four defences**, each with the evidence line from your recon output that revealed it.
2. **For each defence, the specific canned-tool blind spot it exploits**, referenced to your
   lab-03 capability statement.
3. **Why every Objection command reported success.** Be precise: distinguish "the hook installed
   but the class was not the decider", "the hook installed too late", and "the hook was never
   applicable".
4. **Three routes**, with which need spawn and which do not.
5. **The remediation you would give the developer** — and confirm that "these defences worked
   against a stock tool" is not the same as "these defences work". You defeated all four in an
   afternoon.

### Question 4.1

The app defeated every canned command. Is that a security control worth keeping? Write the
paragraph you would send the client.

<details>
<summary>A model answer</summary>

> The four checks are well chosen: each sits outside the envelope of stock instrumentation
> tooling, and together they defeat every default command that tooling offers. That is a real
> and measurable increase in cost against untargeted, scaled abuse — a scripted attacker using
> defaults will fail.
>
> It is not a defence against a targeted attacker. All four were identified in about ninety
> minutes with a read-only observation script, and defeated three independent ways: intercepting
> the probes before they ran, overwriting the cached verdict, and calling the protected routine
> directly without unlocking anything. The third route did not require defeating any check at
> all.
>
> Keep the checks if the threat you care about is scale. Do not treat them as protecting the
> content: the content was recoverable while every check was still reporting "not secure".
> [37 §1.4](../../37-RootDetection/README.md) states the position we agree with — this cannot be
> won on the client. If the notes matter, gate them on a server-side authorisation that the
> device cannot forge.
</details>

---

## Success criteria

- [ ] You built the challenge without reading Part 2 first.
- [ ] You produced at least four Objection commands that reported success and changed nothing.
- [ ] You identified all four defences from **observation**, not from the source.
- [ ] You recovered the flag by three genuinely independent routes.
- [ ] You recorded which routes work under attach and which need spawn, and can explain why.
- [ ] Your write-up explains *why each tool failed*, not just that it did.
- [ ] Your remediation paragraph distinguishes "raises cost" from "protects the content".
- [ ] The app is uninstalled and the device is as you found it.

---

## Clean-up

```bash
# host
adb uninstall com.pentest.ch54.ctf
adb shell "su -c 'pm uninstall com.pentest.ch54.ctf'"
cd ../examples && ./build.sh --uninstall
```

---

## Extension work

1. **Add a fifth defence that beats your own route 2.** Make the verdict non-cacheable — re-check
   inside `reveal()`. Then beat it again.
2. **Move one check to native code** with the NDK
   (`access("/sbin/magisk", F_OK)` in `JNI_OnLoad`). No Java hook, canned or hand-written, will
   see it. That is the handoff to [53](../../53-Frida/README.md) and
   [37 §7.5](../../37-RootDetection/README.md).
3. **Write the objection plugin you wish existed** — one that runs the four probes' worth of
   hooks and prints a coverage report. Then ask yourself why it is not in the tool.
4. **Try it on an unrooted device** via `objection patchapk`, and note which of the four defences
   the changed signature would have tripped if the app checked it
   ([38-TamperDetection](../../38-TamperDetection/README.md)).

---

## The lesson

Every tool in this chapter reported success at every step, and the app never moved. Not one of
those reports was a lie — the hooks really did install; the classes really were present. They
were answers to a question you had not asked.

**The tool tells you what it did. Only the application tells you what happened.**
