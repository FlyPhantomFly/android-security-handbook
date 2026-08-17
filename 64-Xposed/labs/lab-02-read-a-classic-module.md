# Lab 02 — Read a classic module, then build one

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 2 to 4 hours |
| **Needs classic Xposed?** | **No.** It cannot be installed |
| **Needs LSPosed?** | **No** to build, read and analyse — which is Parts 1 to 4. **Yes** for the optional Part 5, which runs it |
| **Needs a device?** | **No** for Parts 1 to 4 |
| **You come out with** | A module built entirely offline from 2015-era source, its complete type-reference and target lists extracted from its own DEX, a Smali reading of one hook installation, and a demonstration of the `compileOnly` failure — the one that produces no error anywhere |

---

## Why this lab exists

Chapter 64's second reason to exist is that **the Xposed API outlived the Xposed framework by eight
years and counting.** That is easy to assert and easy to disbelieve. This lab makes you compile
source that would have built against `XposedBridge.jar` on an Android 5 device, with a 2026
toolchain, and then read the result back out of its own bytecode.

The second thing it teaches is a triage skill you will use on real APKs: **a `de.robv` string in a
DEX can mean "this is a module" or "this is looking for modules", and those are opposite
intentions.** Part 4 makes you tell them apart.

---

## Setup

You need a JDK (11 or newer) and the Android SDK's `d8`. You do **not** need Gradle, Android Studio,
a network connection, or the real Xposed API jar.

```bash
# host
cd 64-Xposed
javac -version                                  # 11 or newer
ls "${ANDROID_HOME:-$LOCALAPPDATA/Android/Sdk}/build-tools"    # any recent version
```

If `javac` is missing, install a JDK. If `d8` cannot be found, set `ANDROID_HOME`, or point `$D8`
directly at a `build-tools/*/lib/d8.jar`.

---

## Part 1 — Read the source before you build it

Open [`../examples/ClassicXposedModule.java`](../examples/ClassicXposedModule.java) and read it
through once without building anything.

### 1.1 Find the three `[GLOBAL-ERA]` markers

The file carries three comments marked `[GLOBAL-ERA]`. Each marks a place where classic Xposed's
design shows through. Find all three and answer, for each:

| Marker | Question to answer |
|---|---|
| In `initZygote` | What did this method have that no modern equivalent gets for free, and what did a mistake here do to the device? |
| The commented-out framework hook | Why is it commented out rather than deleted, and what would enabling it cost on a modern device? |
| The `packageName` guard at the top of `handleLoadPackage` | Under classic Xposed, what exactly stood between this module and every other process on the phone? |

Write your three answers down. Then check them against chapter README §3.9. **If you disagree with
the chapter, say why** — the interesting case is the middle one, where "it is rated Critical by
63-LSPosed" is the answer and "it is dangerous" is not.

### 1.2 Predict the bytecode

Before you compile, predict — in writing — the answers to these:

1. How many classes will `javac` produce from this one source file?
2. Which `de.robv` types will the DEX **reference**?
3. Which of those will the DEX **define**?
4. Will the string `"com.pentest.ch64.vault.VaultGate"` appear in the DEX in plaintext?
5. Will the string `"isUnlocked"`?

Keep the predictions. Part 3 checks them.

---

## Part 2 — Build it, offline

```bash
# host
./scripts/build-classic-module.sh --keep --out /tmp/ch64-build
```

Read the output carefully. Three lines carry the whole lesson:

```
[*] compiling 12 source files
[+] compiled: 21 class files
[*] dexing 4 class files (17 API classes excluded, as compileOnly would)
```

(Your counts will be lower without `--with-detector`. Run it both ways and note the difference.)

### 2.1 What just happened

- You had no `de.robv.android.xposed:api:82` jar, so the script **generated a source-compatible
  stub** — ten source files that define the API's shape and nothing else. Every stub method throws.
- `javac` compiled your module against it. That is the *compile* half of `compileOnly`.
- The script then **deleted every `de/robv/**` class before dexing.** That is the *only* half.

### 2.2 Prove the exclusion

```bash
# host
python3 -B -c "
import re
d = open('/tmp/ch64-build/dex/classes.dex','rb').read()
print('DEX bytes:', len(d))
refs = sorted({m.decode() for m in re.findall(rb'Lde/robv/android/xposed/[A-Za-z0-9\$/_]+;', d)})
print('de.robv types REFERENCED:', len(refs))
for r in refs: print('  ', r)
"
```

Expected — measured on the chapter's host, JDK 24 and build-tools 35.0.1, `--min-api 21`:

```
DEX bytes: 10940
de.robv types REFERENCED: 10
   Lde/robv/android/xposed/IXposedHookLoadPackage;
   Lde/robv/android/xposed/IXposedHookZygoteInit$StartupParam;
   Lde/robv/android/xposed/IXposedHookZygoteInit;
   Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;
   Lde/robv/android/xposed/XC_MethodHook$Unhook;
   Lde/robv/android/xposed/XC_MethodHook;
   Lde/robv/android/xposed/XC_MethodReplacement;
   Lde/robv/android/xposed/XposedBridge;
   Lde/robv/android/xposed/XposedHelpers;
   Lde/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam;
```

Now confirm it defines **none** of them:

```bash
# host — a class DEFINITION appears in the class_defs section; a reference does
# not. The cheap proxy: does the DEX contain the SOURCE FILE name of any
# de.robv class?  A defined class carries one; a referenced one does not.
python3 -B -c "
import re
d = open('/tmp/ch64-build/dex/classes.dex','rb').read()
for name in [b'XposedBridge.java', b'XposedHelpers.java', b'XC_MethodHook.java']:
    print(name.decode(), 'present' if name in d else 'ABSENT')
"
```

**Success criterion:** all three report `ABSENT`. The DEX names ten types it cannot resolve on its
own. On an ordinary app that is a broken build; on a module it is the format.

### 2.3 Now break it deliberately

Rebuild **without** the exclusion, to see the failure that produces no error:

```bash
# host — build a DEX that DOES contain the API classes
mkdir -p /tmp/ch64-broken && cd /tmp/ch64-broken
cp -r /tmp/ch64-build/classes ./classes 2>/dev/null || \
  { cd - >/dev/null; ./scripts/build-classic-module.sh --keep --out /tmp/ch64-broken; cd /tmp/ch64-broken; }
```

If `--keep` already removed the classes tree, rerun the build script with `--keep` and comment out
the `rm -rf "$CLASSES/de/robv"` line in a **copy** of the script, then dex the whole tree.

You now have a DEX that both **references and defines** `de.robv.android.xposed.XposedBridge`.

Answer, in writing, before reading on: **what happens at runtime, and at which stage do you find out?**

> The answer is the chapter's §3.7 warning. The module loads cleanly. `handleLoadPackage` is called.
> `findAndHookMethod` is called. Every hook installs — into the module's own copy of `XposedBridge`,
> which the framework has never heard of. Nothing is hooked, nothing is logged, and no stage of the
> build, the install or the load reports a problem. **You find out when the app behaves normally and
> you cannot work out why.** This is the single most common first-module failure.

---

## Part 3 — Read the module out of its own DEX

### 3.1 The target list

```bash
# host
python3 -B -c "
import re
d = open('/tmp/ch64-build/dex/classes.dex','rb').read()
for m in sorted({x.decode() for x in re.findall(rb'[a-z][a-z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){2,}', d)}):
    if len(m) >= 10: print(m)
"
```

Check this against your Part 1.2 predictions. You should see `com.pentest.ch64.vault.VaultGate` and
`com.pentest.ch64.vault.RootCheck` in plaintext.

**Why they are there, and why they always will be:** reflection is string-based. A module names its
targets with strings because it has no other way to name a class it cannot import. Obfuscating the
*module* renames the module's own identifiers and cannot touch a string that names somebody else's
class.

### 3.2 The Smali

```bash
# host — find a baksmali. apktool ships one under Resources/; MobSF ships one;
# Ghidra ships one. Any will do.
java -jar <path/to/baksmali.jar> d /tmp/ch64-build/dex/classes.dex -o /tmp/ch64-smali
find /tmp/ch64-smali -name '*.smali'
```

Open `com/pentest/ch64/module/ClassicXposedModule.smali` and find `hookTheDecision`. Read it against
this checklist — each row is a fact you can establish without decompiling:

| What to find | What it tells you |
|---|---|
| `const-string v0, "com.pentest.ch64.vault.VaultGate"` | The target class |
| `iget-object p1, p1, L…LoadPackageParam;->classLoader:` | It hooks an **app** class. A framework hook passes `null` here |
| `const-string v1, "isUnlocked"` | The target method |
| `const-class v?, Ljava/lang/String;` | The signature |
| `new-array` … `aput-object <the callback> , v3, <last index>` | The varargs array, with **the callback last** — the API contract, in bytecode |
| `.catchall` around the whole thing | The module defends against `NoSuchMethodError`. Its absence in a module you are triaging means the author never tested against a changed target |

**Success criterion:** you can name the target class, method and signature of every hook in the module
using only the `.smali` files, without opening the `.java`.

### 3.3 Observation versus modification, in the bytecode

Open `replaceTheAnswer` in the same file. Find these three:

```smali
const-string v0, "com.pentest.ch64.vault.RootCheck"
const-string v1, "isRooted"
sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;
invoke-static {v2}, Lde/robv/android/xposed/XC_MethodReplacement;->returnConstant(…)
```

**You now know, without running anything, exactly what this module does to `isRooted`.** The target,
the method, and the value it will return are all constants sitting next to each other.

Now note the asymmetry, because it is the trap: finding `XC_MethodReplacement` is strong evidence a
module modifies behaviour. **Not** finding it is weak evidence of anything.
[63-LSPosed §6.3](../../63-LSPosed/README.md) measured a `private static final boolean` guard causing
`javac` to fold the condition away entirely — the dangerous branch was **absent from the DEX** and one
character away in the source, and `grep` returned **0 across all nine classes**.

**Exercise.** Reproduce that. Add to `ClassicXposedModule.java`:

```java
private static final boolean OBSERVE = true;
// ... inside a hook callback:
if (!OBSERVE) {
    param.setResult(Boolean.TRUE);
}
```

Rebuild, and grep the DEX for `setResult`. Then change `OBSERVE` to `false`, rebuild, and grep again.

**Success criterion:** you can state, in one sentence, why triaging a module APK answers "what does
this build do" and not "what can this author ship".

### 3.4 The anonymous callback's free cross-reference

Open `ClassicXposedModule$1.smali` and find:

```smali
.super Lde/robv/android/xposed/XC_MethodHook;
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = L…ClassicXposedModule;->hookTheDecision(…)V
```

Two gifts: the **superclass** names the API even if every identifier the module owns is renamed, and
`EnclosingMethod` walks you from any callback straight back to its installation site — and therefore
to the target strings.

R8 strips `EnclosingMethod` under a default configuration. **Note what that means for triage:** a
module built with obfuscation on is worth *more* attention, not less, because module obfuscation buys
the author nothing except making review harder.

---

## Part 4 — Tell a module from a detector

This is the triage skill. Rebuild with the detector included:

```bash
# host
./scripts/build-classic-module.sh --with-detector --keep --out /tmp/ch64-both
python3 -B -c "
import re
d = open('/tmp/ch64-both/dex/classes.dex','rb').read()
for m in sorted({x.decode() for x in re.findall(rb'[a-z][a-z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){2,}', d)}):
    if len(m) >= 10: print(m)
"
```

You now see two populations in one list:

```
com.pentest.ch64.vault.RootCheck      <- the MODULE's target
com.pentest.ch64.vault.VaultGate      <- the MODULE's target
de.robv.android.xposed.installer      <- the DETECTOR's signature list
io.va.exposed                         <- the DETECTOR's signature list
me.weishu.exp                         <- the DETECTOR's signature list
org.lsposed.manager                   <- the DETECTOR's signature list
org.meowcat.edxposed.manager          <- the DETECTOR's signature list
```

**A string naming a hooking framework can mean the APK IS a module, or that it is LOOKING FOR
modules. Opposite intentions, identical constants.**

### 4.1 The disambiguator

Answer these two questions about any APK and you have the answer:

| Question | A module | A detector |
|---|---|---|
| Does it **reference** `de.robv.android.xposed.XC_MethodHook`, `IXposedHook*`, `XposedHelpers`? | **Yes** | No |
| Does it have `assets/xposed_init` and `xposedmodule` meta-data? | **Yes** | No |
| Does it reference `java.io.File`, `PackageManager.getPackageInfo`, `Throwable.getStackTrace` around those strings? | Rarely | **Yes** |

Run the scanner over the fixture and confirm it reports both populations:

```bash
# host — wrap the DEX in a zip and scan it
python3 -B - <<'PY'
import zipfile
z = zipfile.ZipFile('/tmp/ch64-fixture.apk', 'w')
z.write('/tmp/ch64-both/dex/classes.dex', 'classes.dex', zipfile.ZIP_STORED)
z.close()
print('written')
PY
python3 -B scripts/xposed-detection-scan.py /tmp/ch64-fixture.apk --verbose
```

**Success criterion:** it reports **STRONG** with twelve or more distinct signatures. You can point at
which of them come from the module half and which from the detector half.

---

## Part 5 (optional) — Actually run it

**Requires LSPosed, and a device you are willing to root.** Everything above works without it; this
part is the payoff if you have the setup.

> **⚠️ Do not attempt to install classic Xposed.** It requires disabling Verified Boot, which is not
> reversible in practice and can brick a relocked device. Chapter README §3.2 and
> [61-Fastboot](../../61-Fastboot/README.md) cover why.

1. Build the lab target application. It needs three classes:

```java
// com.pentest.ch64.vault.VaultGate
public final class VaultGate {
    private static Boolean sDeviceOk = null;          // the cache example 9.2 attacks
    public boolean isUnlocked(String pin) {
        if (sDeviceOk == null) { sDeviceOk = !RootCheck.isRooted(); }
        if (!sDeviceOk) { return false; }
        return "2468".equals(pin);
    }
}
// com.pentest.ch64.vault.RootCheck
public final class RootCheck {
    public static boolean isRooted() { return new java.io.File("/system/xbin/su").exists(); }
}
```

2. Package `ClassicXposedModule` into an APK with the manifest from
   [`../examples/AndroidManifest.xml`](../examples/AndroidManifest.xml) and the asset from
   [`../examples/xposed_init`](../examples/xposed_init).
3. Install, enable in the LSPosed manager, **scope it to the lab app only** — never `android`.
4. `adb shell am force-stop com.pentest.ch64.vault`, then relaunch. **The force-stop is not
   optional**: modules load at process start, and forgetting it is the single most common reason a
   module "does not work" and then mysteriously works the next morning.
5. Read the module's output in the LSPosed log.

**What you have just demonstrated:** source written against a framework that stopped being supported
at API 27, loaded and hooking on API 35, unchanged. That is chapter §1.6's second reason, run rather
than read.

---

## Success criteria

| # | Criterion | Check against |
|---|---|---|
| 1 | You answered the three `[GLOBAL-ERA]` questions before building | Part 1.1 |
| 2 | Your Part 1.2 predictions were checked against the real DEX, and you noted where you were wrong | Part 3.1 |
| 3 | The DEX references ten `de.robv` types and defines none of them | Part 2.2 |
| 4 | You can explain, without notes, what happens if the API is packaged into the module | Part 2.3 |
| 5 | You named the target class, method and signature of every hook from Smali alone | Part 3.2 |
| 6 | You reproduced the compile-time-constant elimination and can state its consequence for triage | Part 3.3 |
| 7 | You can tell a module from a detector using the type-reference list | Part 4.1 |
| 8 | The scanner reports STRONG with 12+ signatures on your fixture | Part 4.1 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `javac: invalid flag: C:/Users/.../Android` | A path with a space in a javac `@argfile`, unquoted | Quote each path inside the argfile. The shipped script does, and says why |
| `d8` fails with `InvalidPathException: Illegal char <">` | **d8's argfile does not share javac's grammar** and does not strip quotes | Pass d8 a jar, or an unquoted argfile from a space-free directory. The shipped script uses a jar |
| `could not find d8.jar` | `ANDROID_HOME` unset | Set it, or set `$D8` to the jar directly |
| `--with-detector` fails with `cannot find symbol: uid` | An API stub that types `appInfo` as `Object` | The shipped stub types it as `ApplicationInfo` and puts `android.jar` on the classpath. Do the same |
| `strings` finds nothing in the DEX | On Windows, `strings` is likely a Sysinternals build: it cannot open MSYS paths and emits CRLF | Use the Python extractors above |
| `baksmali` not found | It is rarely on `PATH` | apktool, MobSF and Ghidra all ship one. **Do not use jadx on a bare `classes.dex`**: 63-LSPosed measured jadx 1.5.3 producing no output, exiting 0, and hanging on a `.jar` |
| The module loads but hooks nothing | Almost always the `compileOnly` failure | Part 2.3. Check `unzip -l module.apk \| grep de/robv` is **empty** |
| The module does nothing after you enable it | The target process was already running | `adb shell am force-stop <pkg>` |

---

## Cleanup

```bash
# host
rm -rf /tmp/ch64-build /tmp/ch64-both /tmp/ch64-broken /tmp/ch64-smali /tmp/ch64-fixture.apk
```

If you did Part 5: uninstall the module, remove it from the LSPosed manager, clear its scope, and
record that you did. **A module left enabled is state you added to somebody's device.**

---

## Where to go next

- [Lab 03 — Why the mechanism broke](lab-03-why-the-mechanism-broke.md) — you have built a module
  for a framework you cannot install; now measure exactly why you cannot.
- [63-LSPosed Lab 02](../../63-LSPosed/labs/lab-02-your-first-module.md) — the same build, from the
  modern framework's side. Reading the two DEX reference lists side by side is the fastest way to see
  what a decade did and did not change.
- [12-DEX-Internals](../../12-DEX-Internals/README.md) — the format you have been reading by hand.
