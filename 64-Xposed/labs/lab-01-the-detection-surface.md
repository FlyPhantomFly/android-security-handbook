# Lab 01 — The detection surface that outlived the framework

| | |
|---|---|
| **Difficulty** | Beginner → Intermediate |
| **Time** | 2 to 3 hours, honestly |
| **Needs classic Xposed?** | **No.** It cannot be installed. That is the point of the lab |
| **Needs LSPosed?** | **No** |
| **Needs a device?** | **Yes** — any Android device or emulator you control, rooted or not |
| **Needs root?** | Only for the third column of the table. The lab tells you what you lose without it |
| **You come out with** | A probe APK that measures from `untrusted_app`, a three-vantage artefact table for your own device, a scanned APK corpus with every high-confidence hit adjudicated by hand, and a number: what fraction of your corpus's Xposed hits were real |

---

## Why this lab exists

Chapter 64 makes three claims that would be worthless if you took them on trust:

1. Every classic-Xposed artefact is **absent** on a modern device — and absent in a specific way,
   `ENOENT` rather than `EACCES`, which is what makes the checks *dead* rather than merely *blind*.
2. A naive sweep for Xposed-detection code has a **100% false-positive rate**, twice over, for two
   different reasons.
3. A detection probe verified from `adb shell` **has not been verified**.

This lab makes you produce all three numbers yourself, on your own device, with your own corpus. If
your numbers disagree with the chapter's, **your device is right and the chapter is wrong** — write
it down.

---

## Setup

```bash
# host
cd 64-Xposed
adb devices -l                      # identify the device. Record model and API level.
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
```

Record those two values now, at the top of your notes. Every result in this lab is gated on them, and
this repository has documented cases where an unrecorded device taught the exact opposite of the
truth.

**Check whether you have root, and which `su` convention:**

```bash
# host — TRY BOTH. The emulator's su rejects -c in a way that reads as "not rooted".
adb shell 'su 0 id'   || echo "su 0 failed"
adb shell "su -c 'id'" || echo "su -c failed"
```

If neither returns `uid=0`, you are unrooted. **You can still do the whole lab** — you lose the root
column of Part 1, and Part 1 tells you exactly what that costs you.

---

## Part 1 — The three-vantage artefact table

### 1.1 Run the probe

```bash
# host
./scripts/xposed-artefact-probe.sh --serial <your-serial>
```

Read the output. Then run it again with an app vantage:

```bash
# host — find a debuggable third-party package first
adb shell 'pm list packages -3'
# then, for each candidate, until one works:
adb shell 'run-as <package> id'
```

```bash
# host
./scripts/xposed-artefact-probe.sh --serial <your-serial> --as-package <debuggable-package>
```

> **If `run-as` refuses**, read the message carefully. `package not debuggable` and `package not an
> application` are **different refusals**: the first means `FLAG_DEBUGGABLE` is off, the second means
> it is a system app. Reading the second as the first loses a genuine finding. If you have no
> debuggable app at all, Part 1.3 builds one.

### 1.2 What to look for

Fill in this table from your own output. The reference column is what the chapter measured on an
`sdk_gphone16k_x86_64` AVD, Android 15 / API 35.

| Path | Chapter's result (root / shell / app) | Yours |
|---|---|---|
| `/system/framework/XposedBridge.jar` | `ENOENT` / `ENOENT` / `ENOENT` | |
| `/system/xposed.prop` | `ENOENT` / `ENOENT` / `ENOENT` | |
| `/system/lib64/libxposed_art.so` | `ENOENT` / `ENOENT` / `ENOENT` | |
| `/system/bin/app_process` | `PRESENT` / `PRESENT` / `PRESENT` | |
| `/system/bin/app_process.orig` | `ENOENT` / `ENOENT` / `ENOENT` | |
| `/data/adb/modules` | `PRESENT` / `EACCES` / `EACCES` | |
| `/data/adb/lspd` | `ENOENT` / `EACCES` / `EACCES` | |

**The question this table exists to answer** is not "is Xposed installed" — it is not. It is:

> Two paths both make `new File(p).exists()` return `false` from an app. Which of the two could
> *ever* have returned `true`, and how do you know?

Write the answer in one sentence before moving on. If you cannot, reread the last two rows against
the first three, and confirm that the root column is the only one that can distinguish absence from
refusal.

### 1.3 Build a real probe app

`run-as` is not an app. Its SELinux domain is `runas_app`, not `untrusted_app`, and it has its own
rules. To measure what an application actually sees, you need an application.

Create a minimal project — Android Studio's "Empty Activity" template is fine — and put this in the
`Activity`:

```java
// PASTE INTO YOUR PROBE APP'S onCreate.
// Note: this deliberately does NOT use File.exists(), because exists() is what
// the whole lab is about. It distinguishes the two failures.
String[] paths = {
    "/system/framework/XposedBridge.jar",
    "/system/xposed.prop",
    "/system/lib64/libxposed_art.so",
    "/system/bin/app_process",
    "/system/bin/app_process.orig",
    "/data/adb/modules",
    "/data/adb/lspd",
};
StringBuilder sb = new StringBuilder();
for (String p : paths) {
    java.io.File f = new java.io.File(p);
    String verdict;
    if (f.exists()) {
        verdict = "PRESENT";
    } else {
        // exists() said false. WHY? Try to open the PARENT and see which
        // errno the message names. This is the distinction exists() destroys.
        try {
            java.io.File parent = f.getParentFile();
            String[] listing = (parent == null) ? null : parent.list();
            verdict = (listing == null) ? "false (parent unlistable -> probably EACCES)"
                                        : "false (parent listable -> probably ENOENT)";
        } catch (SecurityException e) {
            verdict = "false (SecurityException -> EACCES)";
        }
    }
    sb.append(p).append("  ").append(verdict).append('\n');
    android.util.Log.i("CH64PROBE", p + "  " + verdict);
}
// Also: the one check that is worth keeping.
try {
    Class.forName("de.robv.android.xposed.XposedBridge", false, getClassLoader());
    android.util.Log.i("CH64PROBE", "XposedBridge RESOLVABLE in this process");
} catch (ClassNotFoundException e) {
    android.util.Log.i("CH64PROBE", "XposedBridge not resolvable (clean)");
}
```

Install and run it, then:

```bash
# host
adb logcat -d -s CH64PROBE
```

> **If installation fails with `INSTALL_FAILED_USER_RESTRICTED`** on a physical device, that is an
> OEM "Install via USB" policy and not a fault in your APK. It is bypassable with root:
> ```bash
> adb push app.apk /data/local/tmp/probe.apk
> adb shell "su -c 'pm install -r /data/local/tmp/probe.apk'"
> adb shell rm -f /data/local/tmp/probe.apk        # clean up after yourself
> ```

### 1.4 Compare the three vantages

Put your `run-as` results and your probe-app results side by side.

**Success criterion:** you can state, for at least one path, whether `run-as` and a real app agree —
and if they do not, you have found something worth writing down. In the chapter's measurements they
agreed on every row, which is a useful negative result and *not* a guarantee.

---

## Part 2 — Sweep a real corpus

### 2.1 Build the corpus

```bash
# host
./scripts/pull-apk-corpus.sh --serial <your-serial> --out /tmp/ch64-corpus
# or, on a real phone, the population that actually matters:
./scripts/pull-apk-corpus.sh --serial <your-serial> --third-party-only --out /tmp/ch64-corpus
```

Record the number pulled and the number that failed. Check the manifest for the failures — they
should all be RRO overlay or resource-only packages, which carry no DEX. **A failure on a real
application is a gap in your sweep, not a curiosity.**

### 2.2 Scan it

```bash
# host
python3 -B scripts/xposed-detection-scan.py /tmp/ch64-corpus --recursive --substring-audit
```

Record four numbers:

| | Chapter's (237 stock system APKs, API 35) | Yours |
|---|---|---|
| APKs scanned | 237 | |
| Reaching STRONG | 1 | |
| `classes*.dex` STORED / DEFLATED | 234 / 16 | |
| Substring audit: `xposed` / explained by `exposed` / unexplained | 1141 / 1141 / **0** | |

### 2.3 Adjudicate the STRONG band **by hand**

This is the part that matters and the part everybody skips.

```bash
# host
python3 -B scripts/xposed-detection-scan.py /tmp/ch64-corpus --recursive --min-tier 1 --verbose
```

For every STRONG hit, look at the printed context and decide:

- Is the string in a **module** (it also references `de.robv.android.xposed.XC_MethodHook`)?
- Is it in a **detector** (it references `java.io.File` and `PackageManager` instead)?
- Is it **neither** — a root manager, a security tool, an analysis library naming known packages?
- Or is it a **false positive** — the signature matched something that is not what it claims?

**Success criterion:** you can name, for each STRONG hit, which of those four it is, and you have not
accepted any on the tool's word.

> In the chapter's corpus there was exactly one STRONG hit and it was category three: the Magisk
> manager naming `org.lsposed.manager`, a module it interoperates with. Correctly flagged, correctly
> dismissed.

### 2.4 Break the scanner deliberately

A detector you have only seen succeed is a detector you do not understand. Do both of these.

**Break it in the false-negative direction.** Take
[`../examples/XposedDetector.java`](../examples/XposedDetector.java) and change one path constant to
be assembled at runtime instead of written literally:

```java
// Was:  "/system/framework/XposedBridge.jar"
// Now:
String p = "/system/frame" + "work/Xposed" + "Bridge.jar";
```

Rebuild, rescan the fixture, and observe the signature vanish. **String concatenation of compile-time
constants is folded by `javac`, so this specific change will NOT work** — which is itself the lesson.
Make the pieces non-constant (read one from a resource, or build it in a loop) and watch it disappear
properly. Now you know what string encryption does to your sweep, and why §8's numbers are a floor
rather than a count.

**Break it in the false-positive direction.** Add a signature to the STRONG tier matching a short
token — `rob`, or `xp`, or `art` — and rerun over the corpus. Count the hits. The chapter's own
scanner shipped `vxp` in STRONG and produced **16 false hits**, every one an R8-generated class name
like `Lvxp;` and `Lavxp;`. Reproduce that class of error on purpose so you recognise it when it
happens by accident.

**Success criterion:** you can state the rule this produces in one sentence. (The chapter's version:
*never put a token shorter than about eight characters in a high-confidence tier, because obfuscators
manufacture short tokens and the better-protected the app the likelier the collision.*)

---

## Part 3 — From a hit to a finding

Pick one application from your corpus that reached STRONG or MEDIUM, or use the fixture from
[`../examples/README.md`](../examples/README.md) if your corpus is clean.

### 3.1 Find the consumption site

```bash
# host
apktool d -f -o /tmp/ch64-smali <the apk>
grep -rn 'XposedBridge.jar\|libxposed\|xposed.prop\|de/robv' /tmp/ch64-smali/smali*/ | head -20
```

From each hit, find the enclosing method, then find that method's callers, then answer:

| Question | Why it decides the finding |
|---|---|
| Is the result used at all? | A check nothing reads is dead code, not a control |
| Does a `true` **block** (`System.exit`, `finish()`) or merely log? | Blocking gives an attacker a tight feedback loop |
| Is the value put into a `Bundle`/JSON and sent? | **This is the good design.** The finding then moves server-side and is probably out of scope |

### 3.2 Answer "on what devices can this fire?"

For every classic-only path the app checks, you already have the answer: Part 1's table.

### 3.3 Write the finding

Write it out, properly, in the shape the chapter README §9.4 gives. Then check it against these:

- [ ] Does it name the **device and API level** you measured on?
- [ ] Does it say **`ENOENT` or `EACCES`**, not "the file does not exist"?
- [ ] Does it say which **vantage** produced each result?
- [ ] Does it rate the **consequence of what the check gates**, not the check?
- [ ] Does it avoid the sentence "the application can be hooked"?
- [ ] If you demonstrated a bypass, does it name the framework you **actually used**?

---

## Success criteria

| # | Criterion | Check against |
|---|---|---|
| 1 | You recorded your device model and API level before measuring anything | Your notes |
| 2 | You produced a three-vantage artefact table for your own device | Part 1.2 |
| 3 | You can state, in one sentence, why `/system/framework/XposedBridge.jar` returning `false` and `/data/adb/lspd` returning `false` are different results | Part 1.2 |
| 4 | You built and ran a probe app as `untrusted_app`, and compared it against `run-as` | Part 1.3–1.4 |
| 5 | You scanned a corpus and recorded four numbers | Part 2.2 |
| 6 | You adjudicated every STRONG hit by hand and classified each into one of four categories | Part 2.3 |
| 7 | You broke the scanner in both directions and can state the resulting rule | Part 2.4 |
| 8 | You wrote a finding that passes all six checkboxes in Part 3.3 | Part 3.3 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `su: invalid uid/gid '-c'` | The emulator's `su` takes `su 0 <cmd>` | Try both forms. The probe script does |
| `adb shell su -c 'cmd'` prints the wrong thing | The outer shell strips the quotes and `su` eats the flag | `adb shell "su -c 'cmd'"` | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- symptom table: the first cell IS the wrong form, the third is the fix -->
| The artefact table prints one row and stops | `adb shell` inherits stdin and eats the loop's input | Already fixed in the shipped script with `< /dev/null`. If you wrote your own loop, this is why |
| `run-as: package not an application` | It is a **system** app, even though it is debuggable | Pick a third-party app, or build the probe in Part 1.3 |
| The corpus pull is slow | You are on a physical device over USB | `--third-party-only`, or `--max-mib 50` |
| `pull-apk-corpus.sh` reports failures | Usually RRO overlay packages with no DEX | Check `MANIFEST.txt`. A real app failing is a gap |
| The scanner finds nothing in an app you are sure checks for Xposed | String encryption, or a runtime-assembled class name | Part 2.4's first exercise. Report the limit, do not report "clean" |
| `grep` says "Binary file matches" and shows nothing | It is a DEX | Use `grep -a`, or the Python extractor in README §8.6 |

---

## Cleanup

```bash
# host
rm -rf /tmp/ch64-corpus /tmp/ch64-smali        # somebody's licensed software; do not keep it
adb uninstall <your probe package>
adb shell 'ls /data/local/tmp'                  # confirm you left nothing behind
```

**Record what you installed and that you removed it.** A probe app left on a device is state you
added to somebody's phone, and on a client engagement it is a finding against you.

---

## Where to go next

- [Lab 02 — Read a classic module, then build one](lab-02-read-a-classic-module.md) — the other half
  of the `de.robv` string ambiguity you met in Part 2.3.
- [63-LSPosed Lab 01](../../63-LSPosed/labs/lab-01-mapping-the-injection-chain.md) — the same
  three-vantage discipline applied to the **modern** framework's footprint.
- [37-RootDetection](../../37-RootDetection/README.md) — the general detection taxonomy this lab's
  Part 3 specialises.
