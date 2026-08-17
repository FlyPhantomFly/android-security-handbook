# Lab 02 — Your first module, built offline

> **Difficulty:** Intermediate
> **Time:** 2–3 hours
> **Needs LSPosed installed?** **No** for sections 1–5, which are the ones that teach the mechanism.
> Sections 6–8 run the module and need LSPosed on a rooted device with Zygisk enabled.
> **Needs a network?** **No.** Not once. That is deliberate — the build path here uses `javac` and
> `d8` and synthesises the Xposed API rather than downloading it.

---

## Objective

Build both halves of the system and read them back:

1. **The target** — `com.pentest.ch63.vault`, a deliberately vulnerable application with five
   specific defects, each of which chapter 63 analyses as a vulnerability class.
2. **The module** — an APK that hooks it, from an empty directory to a DEX you can disassemble.
3. **The analyst's view** — what your own module looks like to somebody triaging it, which is the
   fastest way to internalise what a module can and cannot hide.

By the end you will have written a module, and — more usefully — you will have seen the exact
bytecode your `findAndHookMethod` call compiles to, and one measured result that changes how you read
somebody else's module forever.

---

## Setup

You need:

- JDK 11 or newer (`javac`, `java`).
- Android SDK build-tools, for `d8`. The script finds it from `$ANDROID_HOME`,
  `$ANDROID_SDK_ROOT`, or `$LOCALAPPDATA/Android/Sdk` on Windows.
- Optionally `baksmali` (ships with apktool) for section 5.
- Android Studio, for section 1, if you want a real installable APK.

```bash
# host
cd 63-LSPosed
chmod +x scripts/build-xposed-module.sh
javac -version
```

---

## Section 1 — Build the target

The target's two interesting classes ship with this lab:

| File | Role |
|---|---|
| [`VaultGate.java`](VaultGate.java) | The gate. Five deliberate defects, each labelled in the source |
| [`AuditLog.java`](AuditLog.java) | Four overloads of `record()`, a countable static side effect, and one method that runs from a `ContentProvider` |

### 1.1 Project layout

Create an Android Studio project with:

- **Package** `com.pentest.ch63.vault`
- **Minimum SDK** 27
- **Language** Java

Copy the two files above into `app/src/main/java/com/pentest/ch63/vault/`, then add the pieces the
lab needs around them.

`MainActivity.java` — a PIN box and a button:

```java
package com.pentest.ch63.vault;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final String TAG = "VaultMain";
    private final VaultGate gate = new VaultGate();

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);

        final EditText pin = new EditText(this);
        pin.setHint("PIN");
        root.addView(pin, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        final TextView out = new TextView(this);
        out.setText("locked");

        Button go = new Button(this);
        go.setText("Unlock");
        go.setOnClickListener(v -> {
            boolean ok = gate.isUnlocked(pin.getText().toString());
            out.setText(ok ? "UNLOCKED  flag: CH63{" + secret() + "}" : "denied");
            Log.i(TAG, "isUnlocked -> " + ok
                    + "  successes=" + gate.successfulUnlocks()
                    + "  failures=" + gate.failedAttempts()
                    + "  auditRecords=" + AuditLog.recordCount());
        });

        root.addView(go);
        root.addView(out);
        setContentView(root);

        AuditLog.record("activity", "created");
    }

    /** Only reachable once the gate has actually opened at least once. */
    private String secret() {
        return gate.successfulUnlocks() > 0 ? "the_gate_really_opened" : "not_yet";
    }
}
```

`AuditProvider.java` — this is the one that makes Lab 03's timing section work:

```java
package com.pentest.ch63.vault;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

/**
 * A ContentProvider declared in the app's own manifest is created by
 * ActivityThread BEFORE Application.onCreate.  This is the androidx.startup
 * pattern, and it is why an SDK that initialises from a provider is invisible
 * to a hook installed in onCreate.
 */
public class AuditProvider extends ContentProvider {
    @Override public boolean onCreate() {
        Log.i("AuditProvider", "onCreate -- before Application.onCreate");
        AuditLog.flushOnDemand();
        return true;
    }
    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
    @Override public String getType(Uri u) { return null; }
    @Override public Uri insert(Uri u, ContentValues v) { return null; }
    @Override public int delete(Uri u, String s, String[] a) { return 0; }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
```

And in `AndroidManifest.xml`, inside `<application>`:

```xml
<activity android:name=".MainActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>

<provider
    android:name=".AuditProvider"
    android:authorities="com.pentest.ch63.vault.audit"
    android:exported="false"/>
```

### 1.2 Install and confirm the baseline

```bash
# host
adb install -r app-debug.apk
adb shell am start -n com.pentest.ch63.vault/.MainActivity
adb logcat -c && adb logcat -s VaultMain VaultGate AuditLog AuditProvider
```

Type a wrong PIN and press Unlock.

**Expected:**

```
I AuditProvider: onCreate -- before Application.onCreate
I AuditLog     : [1] flushOnDemand ran (from a ContentProvider, before Application.onCreate)
I AuditLog     : [2] activity -> created
I VaultGate    : device posture evaluated once: ok=true
I AuditLog     : [3] unlock -> denied (1)
I VaultMain    : isUnlocked -> false  successes=0  failures=1  auditRecords=3
```

**Task 1.1.** Note the ordering. `AuditProvider.onCreate` ran **first**, before anything in
`MainActivity`. Write down which entry point a module would need in order to hook something that
happens there. (Answer: not `Application.onCreate` — `handleLoadPackage`.)

**Task 1.2.** Press Unlock three more times with a wrong PIN. What happens on the fourth? Which field
holds that state, and is it a `static`?

> **⚠️ If `adb install` fails with `INSTALL_FAILED_USER_RESTRICTED`,** push and install as root:
> ```bash
> adb push app-debug.apk /data/local/tmp/vault.apk
> adb shell "su -c 'pm install -r /data/local/tmp/vault.apk'"    # or: su 0 pm install -r ...
> ```

---

## Section 2 — Read the target the way an attacker would

Before writing a single line of module code, do the static work. This is the habit that makes the
module a five-minute job instead of an afternoon.

```bash
# host
jadx -d out app-debug.apk
grep -rn "isUnlocked\|matches\|sDeviceOk\|loadExpectedPin" out/sources/
```

**Task 2.1.** Answer these four questions from the decompiled source alone:

1. What is the **exact signature** of `isUnlocked`? (You need it for `findAndHookMethod`.)
2. What is the exact signature of `matches`, and what is its **second argument**?
3. Is `sDeviceOk` an instance field or a static? What type exactly — `boolean` or `Boolean`?
4. How many overloads does `AuditLog.record` have?

**Task 2.2.** Decode `loadExpectedPin` by hand. It is a single-byte XOR. Write down the PIN.

Then check yourself:

```bash
python3 -B -c "
enc=[0x55,0x5F,0x59,0x5C,0x40,0x1B,0x0C,0x18,0x01,0x19]
print(''.join(chr(b^0x6D) for b in enc))"
```

> **🔍 That you *can* do this is the point.** XOR-encoding a constant is not encryption; it costs a
> static analyst about ninety seconds. But note what it *does* buy the developer: it removes the PIN
> from `strings app-debug.apk`, which defeats the laziest possible search. The honest severity of
> "secret is XOR-encoded rather than encrypted" is Low on its own and irrelevant next to the fact
> that the comparison happens on-device at all.

---

## Section 3 — Write the module

### 3.1 The minimum module

Create a **second** Android Studio project:

- **Package** `com.pentest.ch63.module`
- **Minimum SDK** 27
- No Activity. A module needs no components at all.

`app/build.gradle`:

```gradle
dependencies {
    compileOnly 'de.robv.android.xposed:api:82'
}
```

> **⚠️ `compileOnly`, never `implementation`.** The framework supplies `de.robv.android.xposed.*` at
> runtime inside the target process. A module that packages its own copy calls its *own*
> `XposedBridge`, a different class from the one LSPosed loaded, and every hook goes into nothing.
> The symptom is a module that loads cleanly, throws nothing, logs nothing and hooks nothing.
> Verify: `unzip -l module.apk | grep de/robv` must return **empty**.

Copy [`../examples/AndroidManifest.xml`](../examples/AndroidManifest.xml)'s four `<meta-data>`
elements into your manifest, and
[`../examples/xposed_init`](../examples/xposed_init) into `app/src/main/assets/xposed_init`.

Then write the module. Start with the smallest thing that can possibly work:

```java
package com.pentest.ch63.module;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class FirstModule implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        // UNCONDITIONAL. Log before any filtering, before any hook.
        XposedBridge.log("CH63 loaded into " + lpparam.packageName
                + " (process " + lpparam.processName + ")");
    }
}
```

**Task 3.1.** Build, install, enable in the LSPosed manager with scope
`com.pentest.ch63.vault` **only**, force-stop the vault app, launch it, and find that line in
LSPosed's log.

**Do not skip this step.** The unconditional log is the difference between "my hook does not work"
and "my module never loaded", and those have completely different fixes. Chapter §7.4 makes it step 5
of the diagnostic for exactly this reason.

### 3.2 The observing hook

Now add the hook that changes nothing, which is the one that produces findings:

```java
XposedHelpers.findAndHookMethod("com.pentest.ch63.vault.VaultGate",
        lpparam.classLoader,                 // NOT null. Not the boot loader.
        "isUnlocked",
        String.class,                        // the parameter type
        new XC_MethodHook() {                // the callback MUST be last
            @Override protected void beforeHookedMethod(MethodHookParam p) {
                XposedBridge.log("CH63 isUnlocked(\"" + p.args[0] + "\")");
            }
            @Override protected void afterHookedMethod(MethodHookParam p) {
                XposedBridge.log("CH63   -> " + p.getResult());
            }
        });
```

**Task 3.2.** Deliberately break it three ways, one at a time, and record the exact exception:

| Break | Predicted failure |
|---|---|
| Pass `null` instead of `lpparam.classLoader` | ? |
| Put the callback **before** `String.class` in the varargs | ? |
| Use `CharSequence.class` instead of `String.class` | ? |

The third one is worth dwelling on. The signature must match **exactly**; Xposed does not do
overload resolution for you.

### 3.3 The hook that learns the secret

```java
XposedHelpers.findAndHookMethod("com.pentest.ch63.vault.VaultGate",
        lpparam.classLoader, "matches", String.class, String.class,
        new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam p) {
                XposedBridge.log("CH63 matches(entered=\"" + p.args[0]
                        + "\", expected=\"" + p.args[1] + "\")");
            }
        });
```

**Task 3.3.** `matches` is `private`. Does the hook work? Why?

**Task 3.4.** Compare this hook with a hook that forces `isUnlocked` to return `true`. Which one
produces a result you can reproduce on a clean device with no module installed? Write the sentence
you would put in a report for each.

### 3.4 Beat the check without hooking at all

```java
Class<?> gate = XposedHelpers.findClassIfExists(
        "com.pentest.ch63.vault.VaultGate", lpparam.classLoader);
if (gate != null) {
    XposedBridge.log("CH63 sDeviceOk before = "
            + XposedHelpers.getStaticObjectField(gate, "sDeviceOk"));
    XposedHelpers.setStaticObjectField(gate, "sDeviceOk", Boolean.TRUE);
}
```

**Task 3.5.** What does `sDeviceOk` print as, *before* you set it, and why? (Hint: when does
`handleLoadPackage` run relative to `VaultGate.isUnlocked`?)

**Task 3.6.** No hook was installed by that code. Name three anti-hooking controls it therefore walks
straight past.

### 3.5 All four overloads at once

```java
Class<?> audit = XposedHelpers.findClass("com.pentest.ch63.vault.AuditLog",
        lpparam.classLoader);
XposedBridge.hookAllMethods(audit, "record", new XC_MethodHook() {
    @Override protected void beforeHookedMethod(MethodHookParam p) {
        StringBuilder sb = new StringBuilder("CH63 record(");
        for (int i = 0; i < p.args.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(p.args[i]);
        }
        XposedBridge.log(sb.append(')').toString());
    }
});
```

**Task 3.7.** How many `Unhook` objects does `hookAllMethods` return here? Predict, then log
`.size()`.

**Task 3.8.** Now prove the original still runs. Read `AuditLog.sRecordCount` before and after
exercising the app. If the count rises, your callback is a **hook**; if you had used
`XC_MethodReplacement`, it would not. This is the managed-layer twin of chapter 65's `guard_counter`
reading 4 after four calls.

---

## Section 4 — Build it offline, with no Gradle

You do not need Android Studio, a network, or the real API jar to produce a module's DEX. This
section is how the chapter's own §6 listings were made.

```bash
# host, from the chapter root
./scripts/build-xposed-module.sh --out /tmp/ch63 --keep --decompile
```

**Measured:**

```
[*] build directory: /tmp/ch63
[+] d8: .../build-tools/35.0.1/lib/d8.jar
[+] javac: javac 24.0.2
[*] no --api-jar given; generating a source-compatible stub API
[*] compiling 13 source files
[+] compiled: 27 class files
[*] dexing 9 module class files (API classes excluded, as compileOnly would)
[+] classes.dex: 11272 bytes
```

**Task 4.1.** Explain the second-to-last line. **27 classes were compiled and 9 were dexed.** What
are the other 18, and what Gradle keyword does excluding them correspond to?

**Task 4.2.** Point the script at your own module instead:

```bash
./scripts/build-xposed-module.sh --src /path/to/your/module/src --out /tmp/mine --keep --decompile
```

If it fails to compile, the error is a real compile error and you have found a bug in your module
before ever touching a device. That is the value of this path: **the feedback loop is seconds, not a
build-install-force-stop-relaunch cycle.**

**Task 4.3.** If you have the real jar, pass `--api-jar`. Compare the DEX size. Explain why it barely
changes.

---

## Section 5 — What your module looks like to an analyst

This is the half of the lab most module tutorials skip, and it is the half a security professional
needs.

### 5.1 The API fingerprint

```
--- 1. Every de.robv type this DEX references -------------------
Lde/robv/android/xposed/IXposedHookLoadPackage;
Lde/robv/android/xposed/IXposedHookZygoteInit$StartupParam;
Lde/robv/android/xposed/IXposedHookZygoteInit;
Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;
Lde/robv/android/xposed/XC_MethodHook$Unhook;
Lde/robv/android/xposed/XC_MethodHook;
Lde/robv/android/xposed/XposedBridge;
Lde/robv/android/xposed/XposedHelpers;
Lde/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam;
```

**Task 5.1.** Why can obfuscation never remove these nine names?

(Because the framework supplies those classes at runtime. R8 renames what the module *owns*, never
what it *imports*. This is a structural property of the linkage, not an oversight.)

### 5.2 The call sites

```
     28 XposedBridge;->log(Ljava/lang/String;)V
      7 XC_MethodHook;-><init>()V
      4 XposedHelpers;->findAndHookMethod(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/String;[Ljava/lang/Object;)...
      3 XC_MethodHook$MethodHookParam;->getResult()Ljava/lang/Object;
      2 XposedBridge;->hookAllMethods(Ljava/lang/Class;Ljava/lang/String;Lde/robv/android/xposed/XC_MethodHook;)Ljava/util/Set;
      1 XposedHelpers;->getObjectField(...)
      1 XposedHelpers;->findClassIfExists(...)
      1 XposedHelpers;->findClass(...)
      1 XposedHelpers;->findAndHookMethod(Ljava/lang/Class;Ljava/lang/String;[Ljava/lang/Object;)...
      1 XC_MethodHook$MethodHookParam;->hasThrowable()Z
      1 XC_MethodHook$MethodHookParam;->getThrowable()Ljava/lang/Throwable;
```

**Task 5.2.** Seven `XC_MethodHook.<init>` calls. Count the installations: four string-form
`findAndHookMethod` + one class-form + two `hookAllMethods` = seven. **Why is that agreement worth
checking**, and what would it mean if there were eight constructors and six installations?

### 5.3 The smali

```smali
.method private hookPinComparison(Lde/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam;)V
    .registers 7

    const-string v0, "com.pentest.ch63.vault.VaultGate"

    iget-object p1, p1, Lde/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam;->classLoader:Ljava/lang/ClassLoader;

    const-string v1, "matches"

    const-class v2, Ljava/lang/String;

    const-class v3, Ljava/lang/String;

    new-instance v4, Lcom/pentest/ch63/module/VaultUnlockModule$3;

    invoke-direct {v4, p0}, Lcom/pentest/ch63/module/VaultUnlockModule$3;-><init>(...)V

    filled-new-array {v2, v3, v4}, [Ljava/lang/Object;

    move-result-object v2

    invoke-static {v0, p1, v1, v2}, Lde/robv/android/xposed/XposedHelpers;->findAndHookMethod(...)
```

**Task 5.3.** Read six facts off that listing without decompiling anything:

1. What class does it hook?
2. What method?
3. What signature?
4. Is the target an application class or a framework class — and how can you tell from **one line**?
5. Where is the callback in the varargs array?
6. Does the module handle failure?

### 5.4 The measurement that changes how you read modules

```bash
grep -rc 'setResult' /tmp/ch63/smali/com/pentest/ch63/module/
```

**Measured:**

```
LateClassHookModule$1.smali:0
LateClassHookModule$2.smali:0
LateClassHookModule$3.smali:0
LateClassHookModule.smali:0
VaultUnlockModule$1.smali:0
VaultUnlockModule$2.smali:0
VaultUnlockModule$3.smali:0
VaultUnlockModule$4.smali:0
VaultUnlockModule.smali:0
```

**Zero.** But open [`../examples/VaultUnlockModule.java`](../examples/VaultUnlockModule.java) and
search for `setResult`. It is there:

```java
private static final boolean OBSERVE = true;
...
if (!OBSERVE) {
    param.setResult(Boolean.TRUE);
    XposedBridge.log(TAG + "   FORCED result=true (original skipped)");
}
```

`OBSERVE` is a `static final boolean` initialised to a compile-time constant, so `javac` folded the
condition and **eliminated the whole branch**. The field survives, carrying its value:

```smali
.field private static final OBSERVE:Z = true
```

The code inside the `if` is not in the DEX at all.

**Task 5.4.** Flip `OBSERVE` to `false`, rebuild, and re-run the grep. Then answer the question this
sets up:

> You are handed a module APK and asked whether it is safe to enable. You grep its DEX for
> `setResult` and `XC_MethodReplacement` and find nothing. **What have you actually learned?**

The answer is the reason chapter §6.3 is a warning callout: you have learned what **this build**
does. You have learned nothing about what the author can ship tomorrow, from the same source, with a
one-character change, the same package name and the same signature. **When the question is trust, the
artefact to review is the source and the build, not the APK.**

### 5.5 Run the chapter's triage tool on your own module

```bash
python3 -B scripts/detect-xposed-module.py /path/to/your/module.apk --verbose
```

**Task 5.5.** Does it report exactly what you declared? If your `xposedscope` is not recovered, read
the note it prints and follow the `apktool` command it gives you. A tool that says "I could not read
this" is more useful than one that guesses.

---

## Section 6 — Run it (needs LSPosed)

```bash
# host
adb install -r module.apk
# enable it in the manager; scope: com.pentest.ch63.vault ONLY
adb shell am force-stop com.pentest.ch63.vault
adb shell am start -n com.pentest.ch63.vault/.MainActivity
```

**Task 6.1.** Type a wrong PIN. Read the module's log. You should see the correct PIN in the
`matches(...)` line.

**Task 6.2.** Now type the PIN you just learned, **with the module disabled**, on a device where
nothing is hooking anything. It should unlock.

That second step is the deliverable. **The hook was a means of learning the PIN; the finding is the
PIN, and it reproduces with no instrumentation.** Chapter 65's CTF grades exactly this distinction
Silver versus Gold, and it is the difference between a demo and a report.

**Task 6.3.** Deliberately forget `am force-stop` after a module change. Observe that nothing
happens. Then force-stop and observe that it does. Internalise this; it is the single most common
"LSPosed is broken" report.

---

## Section 7 — Prove your hook is a hook

```java
// In afterHookedMethod on isUnlocked:
Object count = XposedHelpers.getStaticObjectField(
        XposedHelpers.findClass("com.pentest.ch63.vault.AuditLog", lpparam.classLoader),
        "sRecordCount");
XposedBridge.log("CH63 AuditLog.sRecordCount = " + count);
```

**Task 7.1.** Exercise the app four times with the observing hook. Note the count.

**Task 7.2.** Now change the `isUnlocked` hook to call `param.setResult(Boolean.TRUE)` in
`beforeHookedMethod`, and exercise it four more times. What happens to `sRecordCount`?

**Expected:** it stops rising. `setResult` in `before` **skips the original body**, and the original
body is what called `AuditLog.record`. Your bypass silently disabled a side effect you were not
thinking about.

**Task 7.3.** Write down one realistic scenario where that silent side-effect loss would make you
report a wrong conclusion.

---

## Section 8 — Clean up

```bash
# host
adb uninstall com.pentest.ch63.module
adb uninstall com.pentest.ch63.vault
# and, in the manager: confirm the module is gone from the list
adb shell 'su 0 ls /data/adb/modules'      # unchanged from before you started
rm -rf /tmp/ch63 /tmp/mine
```

**Task 8.1.** Verify that the LSPosed scope table no longer references your module. On a client
device this step is not optional and belongs in the report.

---

## Success criteria

- [ ] The vault app runs and logs its baseline, with `AuditProvider.onCreate` **before**
      `MainActivity`.
- [ ] You decoded the PIN statically, by hand, before hooking anything.
- [ ] A module loads and prints an unconditional line from `handleLoadPackage`.
- [ ] You broke `findAndHookMethod` three ways and can state each exception from memory.
- [ ] You beat the cached decision **without installing a hook**.
- [ ] You built a module's DEX with no network and no Gradle.
- [ ] You read your own `findAndHookMethod` call in smali and named its target from `const-string`.
- [ ] You can explain why grepping a module for `setResult` proves very little.
- [ ] You demonstrated the PIN working on a clean device.
- [ ] You removed everything and verified the removal.

---

## Next

[Lab 03 — Scope, timing, and the five ways a module fails](lab-03-scope-timing-and-failure.md) gives
you five modules that are all correct and all accomplish nothing, and the diagnostic order that finds
each.

---

| | |
|---|---|
| **Chapter** | [63-LSPosed](../README.md) — §3.6 API, §3.12 packaging, §6 what it compiles to |
| **Sources** | [`VaultGate.java`](VaultGate.java) · [`AuditLog.java`](AuditLog.java) · [`../examples/`](../examples/README.md) |
| **Scripts** | [`../scripts/build-xposed-module.sh`](../scripts/build-xposed-module.sh) · [`../scripts/detect-xposed-module.py`](../scripts/detect-xposed-module.py) |
| **See also** | [65-Hooking](../../65-Hooking/README.md) §7.8 for "verify the hook installed, fired, and changed something" — the same three checks in the native world |
