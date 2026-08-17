# Lab 04 — CTF: The Ghost of `app_process`

| | |
|---|---|
| **Difficulty** | CTF |
| **Time** | 3 to 5 hours |
| **Needs classic Xposed?** | **No.** Two of the four flags are *about* the fact that you cannot have it |
| **Needs LSPosed?** | **Optional.** Bronze and Silver need nothing but a device and static analysis. Gold needs no module either — see the note at the end |
| **Needs a device?** | **Yes** for Bronze and Silver. Platinum is a writing exercise |
| **You get** | Four flags, and one lesson that is worth more than the flags |

---

## Scenario

You are assessing **VaultPay**, an internal payments application. Its security documentation says:

> *"VaultPay implements comprehensive runtime integrity verification, including detection of the
> Xposed instrumentation framework, and refuses to release payment credentials on a compromised
> device."*

Your rules of engagement cover the application and the test device. They do not cover the backend.

Your job is to decide whether that sentence is true, and to write what you find in a form the
development team can act on.

> **⚠️ Authorised testing only.** VaultPay is a lab application you build from the source in this
> file. It targets nothing you do not own. Do not point any of this at real software.

---

## Building the target

Create a standard Android project, `com.pentest.ch64.vaultpay`, minSdk 21, and add these four files.
Everything the CTF needs is here; nothing is hidden from you except the flags themselves, which are
derived rather than stored.

### `IntegrityGate.java`

```java
package com.pentest.ch64.vaultpay;

import android.content.Context;
import android.content.pm.PackageManager;
import java.io.File;

/**
 * VaultPay's "comprehensive runtime integrity verification".
 *
 * Four checks. The security documentation counts four. Count what actually
 * runs, and then count what actually CAN run.
 */
public final class IntegrityGate {

    // Evaluated once. Cached for the life of the process.
    private static Boolean sTrusted = null;

    /** CHECK 1 */
    static boolean xposedFilesPresent() {
        String[] p = {
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/system/xposed.prop",
            "/system/bin/app_process.orig",
        };
        for (String s : p) { if (new File(s).exists()) return true; }
        return false;
    }

    /** CHECK 2 */
    static boolean managerInstalled(Context ctx) {
        String[] pkgs = {
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager",
        };
        PackageManager pm = ctx.getPackageManager();
        for (String s : pkgs) {
            try { pm.getPackageInfo(s, 0); return true; }
            catch (PackageManager.NameNotFoundException ignored) { }
        }
        return false;
    }

    /** CHECK 3 */
    private static final long EXPECTED_APP_PROCESS = 46592L;   // from the dev's Pixel, 2019
    static boolean appProcessTampered() {
        File f = new File("/system/bin/app_process");
        return f.exists() && f.length() != EXPECTED_APP_PROCESS;
    }

    /** CHECK 4 */
    static boolean hookOnStack() {
        for (StackTraceElement e : new Throwable().getStackTrace()) {
            if (e.getClassName().contains("de.robv.android.xposed")) return true;
        }
        return false;
    }

    public static boolean isTrusted(Context ctx) {
        if (sTrusted == null) {
            sTrusted = !(xposedFilesPresent()
                      || managerInstalled(ctx)
                      || appProcessTampered()
                      || hookOnStack());
        }
        return sTrusted;
    }
}
```

### `VaultPay.java`

```java
package com.pentest.ch64.vaultpay;

import android.content.Context;

public final class VaultPay {

    /** The thing the security documentation says is protected. */
    public String releaseCredential(Context ctx, String pin) {
        if (!IntegrityGate.isTrusted(ctx)) {
            return "REFUSED: device integrity check failed";
        }
        if (!"7214".equals(pin)) {
            return "REFUSED: bad pin";
        }
        return Flag.bronze();
    }
}
```

### `Flag.java`

```java
package com.pentest.ch64.vaultpay;

/**
 * Flags are DERIVED, not stored, so that finding the string in the DEX is not
 * the same as solving the challenge. Each method's inputs are things you must
 * have measured.
 */
public final class Flag {

    static String bronze() {
        return "CH64{" + rot13("gur_tubfg_bs_ncc_cebprff") + "}";
    }

    /**
     * SILVER. You must supply the number of IntegrityGate's four checks that
     * can return true on the device you are testing. Get it wrong and this
     * returns nothing useful.
     */
    public static String silver(int checksThatCanFire) {
        if (checksThatCanFire < 0 || checksThatCanFire > 4) return "(out of range)";
        String[] table = {
            "abg_bar_bs_gurz",       // 0
            "bar_yvir_purpx",        // 1
            "gjb_yvir_purpxf",       // 2
            "guerr_yvir_purpxf",     // 3
            "nyy_sbhe_yvir",         // 4
        };
        return "CH64{" + rot13(table[checksThatCanFire]) + "}";
    }

    /**
     * GOLD. You must supply the size, in bytes, of the app_process binary that
     * is ACTUALLY on the device, and the number of checks that fire.
     */
    public static String gold(long realAppProcessSize, int checksThatFire) {
        long h = (realAppProcessSize * 31L + checksThatFire) % 100000L;
        return "CH64{baseline_" + h + "_is_not_a_control}";
    }

    private static String rot13(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c >= 'a' && c <= 'z')      b.append((char) ('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z') b.append((char) ('A' + (c - 'A' + 13) % 26));
            else                            b.append(c);
        }
        return b.toString();
    }
}
```

### `MainActivity.java`

```java
package com.pentest.ch64.vaultpay;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        String out = new VaultPay().releaseCredential(this, "0000");
        tv.setText(out);
        setContentView(tv);

        // The gate logs its individual verdicts. That is deliberate: a real
        // detector that cannot say WHICH signal fired is not evidence, and
        // this CTF wants you to have the same information a good one would
        // give its own developers.
        Log.i("VAULTPAY", "files="     + IntegrityGate.xposedFilesPresent());
        Log.i("VAULTPAY", "manager="   + IntegrityGate.managerInstalled(this));
        Log.i("VAULTPAY", "appproc="   + IntegrityGate.appProcessTampered());
        Log.i("VAULTPAY", "stack="     + IntegrityGate.hookOnStack());
        Log.i("VAULTPAY", "trusted="   + IntegrityGate.isTrusted(this));
    }
}
```

Build it, install it, and run it. **Read the logcat before you do anything else** — the challenge
starts from what you see there.

```bash
# host
adb logcat -c && adb shell am start -n com.pentest.ch64.vaultpay/.MainActivity
adb logcat -d -s VAULTPAY
```

---

## 🥉 Bronze — release the credential

**Objective:** make `releaseCredential` return the flag.

**Constraints:** none. Any technique.

**Hint 1.** Read the logcat output first. One of the four checks is firing on a clean device. Work
out which, and why, before you touch anything.

**Hint 2.** The PIN is in the source you just compiled. This flag is not about the PIN.

**Hint 3.** `isTrusted` caches into a `static Boolean`. A module runs before the application's first
line of code. See README §9.2 — **there is a route that installs no hook at all.**

<details>
<summary><b>Bronze solution</b></summary>

The check that fires on a clean modern device is **check 3**, `appProcessTampered()`. Its baseline
constant `46592L` came from the developer's 2019 Pixel; on your device `app_process` is a different
size, so `f.length() != EXPECTED_APP_PROCESS` is **true**, so `isTrusted` returns **false**.

**VaultPay refuses to work on a clean, unmodified device**, and it does so because of its own
integrity check. That is the real bug and it is not a bypass — it is a **false positive in production**.

Three ways to the flag:

1. **The field write, no hook** (README §9.2):
   ```java
   Class<?> gate = XposedHelpers.findClassIfExists(
           "com.pentest.ch64.vaultpay.IntegrityGate", lpparam.classLoader);
   XposedHelpers.setStaticObjectField(gate, "sTrusted", Boolean.TRUE);
   ```
   Nothing is hooked. No dispatcher on the stack, no altered entry point.

2. **Replace the gate**:
   ```java
   XposedHelpers.findAndHookMethod("com.pentest.ch64.vaultpay.IntegrityGate",
           lpparam.classLoader, "isTrusted", Context.class,
           XC_MethodReplacement.returnConstant(Boolean.TRUE));
   ```

3. **No instrumentation at all.** Read `Flag.bronze()` from the DEX and evaluate the ROT13 by hand.
   It is `CH64{the_ghost_of_app_process}`. **This is the correct answer for a report**: you did not
   need to bypass anything, because the credential release is gated by a client-side check and the
   flag string ships in the APK.

</details>

---

## 🥈 Silver — how many of the four can fire?

**Objective:** call `Flag.silver(n)` with the correct `n` for **your** device, and get the flag.

`n` is the number of `IntegrityGate`'s four checks that **can return `true`** on the device you are
testing. Not the number that *do* return true right now — the number that *could*, on that device,
under any circumstances an attacker could arrange.

**Constraints:** you must justify each of the four decisions with a measurement, not an argument.

**Hint 1.** [Lab 01](lab-01-the-detection-surface.md) and [Lab 03](lab-03-why-the-mechanism-broke.md)
give you every measurement you need. Run `scripts/xposed-artefact-probe.sh` if you have not.

**Hint 2.** Check 2 has a failure mode that has nothing to do with Xposed and everything to do with
the API level you are on. Read `AndroidManifest.xml`. What is *not* in it?

**Hint 3.** "Can fire" and "is a working control" are different questions. Check 3 fires. Is it
detecting anything?

<details>
<summary><b>Silver solution</b></summary>

Work through all four:

| Check | Can it fire? | Evidence |
|---|---|---|
| **1** `xposedFilesPresent()` | **No** | All five paths measured `ENOENT` **to root** on a modern device (Lab 01 Part 1). `/` is `ro` with `veritymode=enforcing` (Lab 03 Part 1), so nothing could have written them. LSPosed never creates any of them |
| **2** `managerInstalled()` | **No** (API 30+) | `getPackageInfo` throws `NameNotFoundException` for a package not declared in `<queries>`, **even when it is installed**. VaultPay declares no `<queries>`. On API < 30 this one *can* fire |
| **3** `appProcessTampered()` | **Yes** — and it fires on a clean device | `app_process` is not 46592 bytes on your device. Lab 03 Part 2.2 |
| **4** `hookOnStack()` | **Yes** | It looks for `de.robv.android.xposed` frames, which LSPosed's compatibility layer does produce when a module is hooking. It is the only check on the list that is looking for the right thing |

So on **API 30 or later: `n = 2`.** On **API 21 to 29: `n = 3`**, because check 2 becomes live.

```
CH64{two_live_checks}       (API 30+)
CH64{three_live_checks}     (API 21 to 29)
```

**The finding underneath the flag:** VaultPay advertises four integrity checks. Two cannot fire at
all on its supported platform. Of the two that can, one fires on every clean device (a false
positive) and only one is looking for something real. **The security documentation's sentence is
false, and the failure is not that the checks are bypassable — it is that they expired and nobody
noticed.**

</details>

---

## 🥇 Gold — the baseline that never existed

**Objective:** call `Flag.gold(realSize, checksThatFire)` with the true values for your device.

- `realSize` is the actual byte size of the `app_process` binary the device is running.
- `checksThatFire` is how many of the four return `true` **on a clean device with no instrumentation
  at all**.

**Constraints:** **no module, no Frida, no hooking.** If you find yourself installing something to
solve this, stop and reread the objective.

**Hint 1.** You do not need the app to compute this for you. You need two numbers and a calculator.

**Hint 2.** Careful with `realSize`. `/system/bin/app_process` may be a symlink. Which size does
`File.length()` see, and which one *should* the check be comparing against? The two are different
questions and the CTF wants the one the check actually reads.

**Hint 3.** `checksThatFire` on a clean device is not the same as Silver's `n`. Read the logcat you
captured at the start.

<details>
<summary><b>Gold solution</b></summary>

```bash
# host
adb shell 'ls -l /system/bin/app_process /system/bin/app_process64'
adb logcat -d -s VAULTPAY
```

On the chapter's AVD:

```
lrwxr-xr-x 1 root shell    13 /system/bin/app_process -> app_process64
-rwxr-xr-x 1 root shell 51616 /system/bin/app_process64
```

`new File("/system/bin/app_process").length()` follows the symlink in Java, so it reads **51616**.

`checksThatFire` on a clean device is **1** — only `appProcessTampered()`.

```
h = (51616 * 31 + 1) % 100000 = (1600096 + 1) % 100000 = 1600097 % 100000 = 97
CH64{baseline_97_is_not_a_control}
```

Compute it for your own device; the number will differ, and **that is the flag's entire point.**

**The lesson the flag name states:** the constant embedded in the check is not a control. It is a
device fingerprint from one developer's phone in 2019, frozen into an APK, comparing itself against
every device in the world and disagreeing with almost all of them. The remediation is not "update the
constant" — there is no constant that is right — it is **report the value and let something with
population data decide**, which is what `examples/XposedDetector.java`'s
`appProcessLooksReplaced()` does and says so in its comment.

**And note that you solved Gold with `ls` and arithmetic.** No root, no module, no Frida, no hook.
The strongest finding in this CTF required no instrumentation at all, which is the same shape as
[65-Hooking](../../65-Hooking/README.md)'s CTF reserving Gold for the solution that learns the secret
and then does not need the hook.

</details>

---

## 🏆 Platinum — write the report

**Objective:** no flag string. Produce the finding.

**Constraints:** one page. It must be something a developer would act on, and it must survive a
sceptical reviewer asking "so what?"

<details>
<summary><b>Platinum solution — a model answer</b></summary>

> **Finding: client-side integrity checks are non-functional; credential release is unprotected.**
> **Severity: High** (rated against the credential, not against the checks).
>
> **Summary.** VaultPay's `IntegrityGate` implements four runtime integrity checks. On the supported
> platform, **two cannot fire under any circumstances**, a third fires on every clean device, and only
> one detects the condition it names. `releaseCredential()` is gated on their conjunction, so payment
> credential release is effectively enforced by a single client-side check which is bypassable in one
> line.
>
> **Evidence** (device: `<model>`, Android `<release>` / API `<n>`):
>
> | Check | Result | Evidence |
> |---|---|---|
> | `xposedFilesPresent` | **Cannot fire.** All five paths `ENOENT` to root; `/` mounted `ro` with `veritymode=enforcing`. These are artefacts of a framework unsupported above API 27 | probe output, attached |
> | `managerInstalled` | **Cannot fire on API 30+.** No `<queries>` element is declared, so `getPackageInfo` throws for these packages even when installed | manifest, attached |
> | `appProcessTampered` | **Fires on a clean device.** Baseline `46592` does not match this device's `51616`. `app_process` is also a symlink, and its size varies per release, per ABI and per vendor | `ls -l`, attached |
> | `hookOnStack` | Functional, and the only check looking for a current framework. Defeatable by hooking `Throwable.getStackTrace` | — |
>
> **Impact.** The documented control — *"refuses to release payment credentials on a compromised
> device"* — does not hold. Additionally, `appProcessTampered` generates a false positive on
> unmodified devices, so any user-visible refusal it drives is a support incident, not a defence.
>
> **Reproduction.** Credential release was obtained by writing a single static field, with **no hook
> installed**; and independently, the credential value was recovered from the APK's own constant pool
> with no instrumentation of any kind.
>
> **Remediation, in priority order.**
> 1. **Move the decision off the device.** Release credentials only against a server decision made on
>    a hardware-attested posture report bound to a server-chosen nonce. This is the only change that
>    alters the outcome rather than the cost.
> 2. **Delete checks 1 and 2**, or record a premise for each and a review date. A check whose premise
>    has expired occupies the budget of one that works and creates false confidence.
> 3. **Replace check 3's constant with a report.** Send the observed value with the build fingerprint;
>    let population data judge it. There is no constant that is correct across devices.
> 4. **Do not cache the verdict in a `static`.** One field write defeats it permanently, before the
>    application's first line of code runs.
> 5. **Report, do not block.** Blocking gives an attacker a tight feedback loop against a visible
>    signal; reporting gives the defender population telemetry and the attacker nothing.
>
> **What is explicitly NOT the finding.** That the application can be instrumented on a rooted device
> — that is a property of the platform and is out of scope absent a stated resilience requirement.

</details>

---

## Instructor notes

<details>
<summary><b>Design rationale — read after attempting</b></summary>

**Why check 3 fires on a clean device.** This is the CTF's spine and it is deliberately the *first*
thing a solver meets in logcat. Most integrity CTFs train you to think "the check fires, I must
bypass it". Here the correct first move is to ask *why* it fired, and the answer is that it is
broken, not that you are detected. A tester who reflexively bypasses learns nothing; a tester who
investigates finds the real defect in five minutes.

**Why the flags are derived rather than stored.** `Flag.bronze()` is ROT13 so that `strings` finds
nothing useful, but Silver and Gold take *measurements as arguments*. You cannot brute-force Silver
without deciding what "can fire" means, and you cannot compute Gold without having read the real
binary. **The flag is a receipt for a measurement.**

**Why Gold forbids instrumentation.** Because the best finding in the whole exercise needs none, and
the constraint is what makes that visible. This mirrors [65-Hooking](../../65-Hooking/README.md)'s
CTF, which grades a bypass as Silver and reserves Gold for the solution that does not need the hook.

**Why check 4 is left working.** A CTF where every control is broken teaches cynicism. One of the
four is looking for the right thing in the right place, and Silver forces the solver to notice it
rather than dismissing the whole class. The report in Platinum then has something to preserve, which
is what makes it a report rather than a complaint.

**The `n` that depends on API level.** Silver's answer differs between API 29 and API 30 because of
package visibility. That is on purpose: it forces the solver to record the device before answering,
which is this repository's standing discipline, and it means two solvers with different phones get
different flags and must reconcile them.

**Grading.**

| Award | Requirement |
|---|---|
| Bronze | The flag, by any route |
| Silver | The correct `n` **with a stated justification per check** |
| Gold | The correct value, computed with **no instrumentation** |
| Platinum | A report that rates the credential rather than the checks, and whose top remediation is server-side |

A solver who reaches Gold by hooking `Flag.gold` has not solved Gold.

</details>

---

## Cleanup

```bash
# host
adb uninstall com.pentest.ch64.vaultpay
```

If you built a module for Bronze: uninstall it, remove it from the LSPosed manager, clear its scope,
and record that you did.

---

## Where to go next

- [63-LSPosed Lab 04](../../63-LSPosed/labs/lab-04-ctf-the-invisible-module.md) — the same discipline
  pointed at the modern framework, where the defences actually work.
- [67-BypassingProtections](../../67-BypassingProtections/README.md) — the arms race, and its cost
  model.
- [38-TamperDetection](../../38-TamperDetection/README.md) — why runtime instrumentation leaves
  nothing in the APK, and what that means for the checks that look there.
