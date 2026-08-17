# Lab 01 — Map the runtime receiver surface

> **Objective.** Enumerate every broadcast receiver registered at runtime on a live Android
> device, prove that no static tool can see them, and quantify the gap with your own
> numbers rather than this chapter's.

| | |
|---|---|
| **Difficulty** | Beginner to Intermediate |
| **Time** | 45–90 minutes |
| **Needs an installed lab app?** | **No.** Everything runs against a stock device as it ships. |
| **Needs root?** | No. `dumpsys activity broadcasts` is readable by uid 2000. |
| **Chapter sections** | [§2.2](../README.md#22-the-two-registration-paths--the-visibility-gap), [§7.2](../README.md#72-the-headline-enumerating-runtime-receivers), [§7.3](../README.md#73-proving-the-gap-static-view-versus-runtime-view) |

---

## Why this lab exists

Almost every Android security tool works from the APK. Give it a file and it tells you
which components the app declares. That model is correct for Activities, Services and
ContentProviders, because those *must* be declared in `AndroidManifest.xml` — there is no
other way to create one.

Broadcast receivers break the model. `Context.registerReceiver()` creates a fully functional
receiver at runtime, with no manifest entry, no `exported` attribute, and nothing in the APK
except the bytecode of the call itself. It is reachable by other apps exactly as a
manifest-declared receiver is, and below API 33 it is reachable *unconditionally* unless the
developer supplied a permission.

This lab makes that concrete. You will produce a number — the fraction of the broadcast
surface on your own device that no APK-based tool can see — and you will produce it by
measuring, not by reading.

---

## Setup

### What you need

| Requirement | Check |
|---|---|
| An Android device or emulator, API 21+ | `adb devices -l` |
| `adb` on PATH | `adb version` |
| Python 3.7+ | `python3 --version` |
| USB debugging enabled | the device shows as `device`, not `unauthorized` |

Root is **not** required. An installed lab app is **not** required — that is the point of
this lab. If your device refuses `adb install` (the device used to write this chapter does,
with `INSTALL_FAILED_USER_RESTRICTED`), this lab still works completely.

### Step 0 — record your device, before anything else

Every version-gated statement below depends on this, and a chapter's claim measured on one
API level is not evidence about another.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```

Write the four values down. Reference values from the device this chapter was written
against:

```
M2101K6P
11
30
```

> **⚠️ If your API level is 33 or higher**, some observations below will differ — runtime
> registrations may carry an export flag, and apps targeting 33+ must supply one. Note the
> difference when you see it; it is a finding about your device, not a mistake in the lab.

---

## Part 1 — Read the raw table

Before running any tool, look at the data. A parser you do not understand is a parser you
cannot trust.

### 1.1 Dump it

```bash
# host
adb shell "dumpsys activity broadcasts" > broadcasts.txt
wc -l broadcasts.txt
```

Reference: **15,592 lines** on the measured device. Yours will differ; anything from a few
thousand upward is normal.

### 1.2 Find the sections

```bash
# host
grep -n "^  [A-Z][a-z].*:$\|^  Broadcast parameters\|^  Historical broadcasts" broadcasts.txt | head
```

You should see something close to:

```
2:  Registered Receivers:
6793:  Receiver Resolver Table:
9934:  Broadcast parameters (key=bcast_fg_constants, observing=true):
9941:  Historical broadcasts [foreground]:
11896:  Historical broadcasts summary [foreground]:
12827:  Broadcast parameters (key=bcast_bg_constants, observing=true):
12834:  Historical broadcasts [background]:
```

| Section | What is in it |
|---|---|
| `Registered Receivers:` | **The runtime registration table.** This is the part no other tool can read. |
| `Receiver Resolver Table:` | The same filters, indexed by scheme and MIME type, for fast matching. |
| `Broadcast parameters` | The queue tuning constants — timeouts. |
| `Historical broadcasts` | A ring buffer of recent broadcasts, with senders and extras. |

### 1.3 Read one record by hand

```bash
# host
sed -n '2,12p' broadcasts.txt
```

Reference output:

```
  Registered Receivers:
  * ReceiverList{f745bed 31369 com.android.systemui/1000/u-1 remote:a077a04}
    app=31369:com.android.systemui/1000 pid=31369 uid=1000 user=-1
    Filter #0: BroadcastFilter{edb8a22}
      Action: "android.intent.action.USER_UNLOCKED"
  * ReceiverList{c017dae 31369 com.android.systemui/1000/u0 remote:e2af629}
    app=31369:com.android.systemui/1000 pid=31369 uid=1000 user=0
    Filter #0: BroadcastFilter{381b74f}
      Action: "android.net.wifi.supplicant.STATE_CHANGE"
```

Decode the first record field by field. This is worth doing once by hand:

| Token | Meaning |
|---|---|
| `ReceiverList{...}` | One registering `IIntentReceiver`. One per `registerReceiver` call. |
| `f745bed` | An identity hash. Useless except for matching records within one dump. |
| `31369` | The pid of the registering process. |
| `com.android.systemui` | The process name — usually but **not always** the package name. |
| `/1000/` | The uid. 1000 is `system`. 10000–19999 is a third-party app. |
| `u-1` | The user id. `-1` is `USER_ALL`; `0` is the primary user. |
| `remote:a077a04` | `remote` means a separate process; `local` means inside `system_server`. |
| `Filter #0` | One `IntentFilter` from this registration. A receiver may register several. |
| `Action: "..."` | What it listens for. |

**Now list what is not there.** There is no class name and no export flag. AMS holds a
Binder proxy to a `LoadedApk$ReceiverDispatcher$InnerReceiver`, not to your
`BroadcastReceiver` — see [§4.4](../README.md#44-delivery-iintentreceiver-loadedapkreceiverdispatcher-activitythread)
— so the class name genuinely does not exist on the system_server side. And below API 33
there is no export concept for runtime receivers at all.

### 1.4 Find a guarded registration

```bash
# host
grep -B4 "requiredPermission=" broadcasts.txt | head -20
```

Reference:

```
    app=20578:com.miui.analytics/u0a114 pid=20578 uid=10114 user=0
    Filter #0: BroadcastFilter{e30a12f}
      Action: "com.xiaomi.onetrack.DEBUG"
      requiredPermission=com.xiaomi.onetrack.permissions.DEBUG_MODE
```

`requiredPermission` is the **receiver-side** control: a sender must hold this permission
for the delivery to happen. **Its absence means any app can send to that receiver.**

Count both:

```bash
# host
echo "filters total          : $(grep -c 'Filter #' broadcasts.txt)"
echo "filters with a perm    : $(grep -c 'requiredPermission=' broadcasts.txt)"
```

Reference: 1,306 filters, 275 with a permission — so roughly four in five had none.

> **✅ Checkpoint 1.**
> You can name the four sections of the dump, decode a `ReceiverList` line without help,
> and state the two things the dump does not contain.

---

## Part 2 — Parse it properly

### 2.1 Run the enumerator

```bash
# host
cd 29-BroadcastReceivers/scripts
python3 -B receiver-surface.py --brief
```

Read the header first:

```
=== DEVICE ====================================================================
  model=M2101K6P  Android 11  API 30
  API < 33: runtime-registered receivers have NO export flag.
  Every registration below is reachable by any sender unless a
  requiredPermission is shown.
```

Then the summary:

```
=== SUMMARY ===================================================================
  ReceiverList registrations                      : 1281
  IntentFilters across them                       : 1438
  action strings (with duplicates)                : 2868
  distinct action strings                         : 800
  filters WITH a sender permission                : 211
    of which AndroidX NOT_EXPORTED backport       : 36
  filters with NO sender permission               : 1227
  registrations owned by third-party apps         : 472
    third-party AND at least one unguarded filter : 364
```

**Record your own numbers in a table.** You will compare against them in Part 5.

| Metric | Your device | Reference (M2101K6P, API 30) |
|---|---|---|
| ReceiverList registrations | | 1,281 |
| IntentFilters | | 1,438 |
| Distinct actions | | 800 |
| Filters with no permission | | 1,227 |
| Third-party registrations | | 472 |

### 2.2 The surface is alive

Run it again, right now, without touching the device.

```bash
# host
python3 -B receiver-surface.py --brief | grep "ReceiverList registrations"
```

Reference: a snapshot taken minutes earlier on the same **idle** device read 1,151
registrations against 1,281. Processes start and die; registrations go with them.

> **⚠️ Warning**
> This is why "the app has N receivers" is a claim with a timestamp on it. A receiver you
> failed to find may simply not have been registered when you looked. Re-run while
> exercising the target — that is not optional thoroughness, it is the difference between
> finding a receiver and not.

### 2.3 Narrow to what matters

Platform processes are noise for most assessments. Filter to third-party apps that have at
least one unguarded filter:

```bash
# host
python3 -B receiver-surface.py --third-party --unprotected --brief
```

Pick one entry and read it properly:

```
--- com.miui.calculator  (1 registration, uid 10141)
  com.miui.calculator   pid=4303 uid=10141 (third-party app) user=0  [remote]
    Filter #0: NO sender permission  <-- any app that can name the action reaches this receiver
        action: android.intent.action.LOCALE_CHANGED
```

An unguarded runtime receiver in a preinstalled app. **Hold that thought — Part 4 decides
whether it means anything.**

### 2.4 Look for the AndroidX shim

```bash
# host
grep -o "[a-z0-9.]*DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" broadcasts.txt | sort | uniq -c
```

Reference:

```
     16 com.google.android.gms.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
      2 com.google.android.youtube.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
    101 com.miui.securitycenter.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
```

This is `ContextCompat.registerReceiver(..., RECEIVER_NOT_EXPORTED)` running on a device
where the flag does not exist. The library emulates it by inventing a signature permission
that only the app itself holds.

**This is a positive finding.** If you see one in an assessment, do not report it as an
unknown custom permission — the developer explicitly asked for a non-exported receiver and
the library honoured it.

> **✅ Checkpoint 2.**
> You have your device's numbers, you have observed the surface change between two
> snapshots of an idle device, and you can recognise the AndroidX backport permission.

---

## Part 3 — Prove the gap

This is the part that matters. Everything so far could be dismissed as "the manifest
probably says the same thing". Show that it does not.

### 3.1 The two views, on one action

`cmd package query-receivers` queries PackageManagerService — the **manifest** resolver.
It knows nothing about runtime registrations. So comparing it against the AMS table
isolates exactly the invisible portion.

Pick an action you saw in Part 1.

```bash
# host
ACTION=android.intent.action.USER_UNLOCKED

echo "--- static (PackageManager / manifests) ---"
adb shell "cmd package query-receivers --brief -a $ACTION"

echo "--- runtime (AMS registration table) ---"
adb shell "dumpsys activity broadcasts" \
  | sed -n '/Registered Receivers:/,/Receiver Resolver Table:/p' \
  | grep -c "Action: \"$ACTION\""
```

Reference:

```
--- static (PackageManager / manifests) ---
No receivers found
--- runtime (AMS registration table) ---
29
```

**Zero, according to every manifest on the device. Twenty-nine, in reality.**

### 3.2 Repeat on three actions

```bash
# host
for a in android.media.VOLUME_CHANGED_ACTION \
         android.intent.action.USER_UNLOCKED \
         android.net.wifi.supplicant.STATE_CHANGE; do
  echo "=== $a"
  echo -n "  static  : "; adb shell "cmd package query-receivers --brief -a $a" | head -1
  echo -n "  runtime : "
  adb shell "dumpsys activity broadcasts" \
    | sed -n '/Registered Receivers:/,/Receiver Resolver Table:/p' \
    | grep -c "Action: \"$a\""
done
```

Reference:

```
=== android.media.VOLUME_CHANGED_ACTION
  static  : No receivers found
  runtime : 6
=== android.intent.action.USER_UNLOCKED
  static  : No receivers found
  runtime : 29
=== android.net.wifi.supplicant.STATE_CHANGE
  static  : No receivers found
  runtime : 4
```

Three actions, zero manifest listeners, thirty-nine real ones.

### 3.3 Now measure it at scale

```bash
# host — one PackageManager query per distinct action; takes several minutes
python3 -B receiver-surface.py --third-party --runtime-only --brief | tee runtime-only.txt
```

The tail of the output is the number this lab exists to produce:

```
  299 of 431 distinct actions have live runtime registrations and NO
  manifest-declared receiver anywhere on this device.
```

**Sixty-nine per cent** of the third-party broadcast surface on a stock, unmodified device
is invisible to every tool that works from an APK.

Compute your own percentage and write it down.

### 3.4 Read the number correctly

Before you quote it anywhere, understand what it does and does not say.

**It does not say** those 299 actions are secret, undocumented or malicious. Several of
them are perfectly public Android actions — `android.app.action.ENTER_CAR_MODE`,
`android.bluetooth.adapter.action.BLE_STATE_CHANGED` and so on.

**It does say** that on this device, at this moment, the only listeners for those actions
are runtime registrations. A static audit of every APK on the device would have concluded
that nothing listens for them, and would have been wrong 299 times.

It is a statement about *tooling coverage*, not about the apps' intent. Framed that way it
is defensible in any report; framed as "299 hidden receivers" it is not.

> **✅ Checkpoint 3.**
> You have a percentage, from your own device, for how much of the broadcast surface is
> invisible to static analysis — and you can state precisely what that percentage means.

---

## Part 4 — Turn leads into non-findings (the important half)

You now have a list of unguarded receivers. Most of them are worthless, and knowing *why*
is the skill this lab is really teaching.

### 4.1 Take the calculator

From Part 2.3: `com.miui.calculator`, uid 10141, registered at runtime for
`android.intent.action.LOCALE_CHANGED`, **no sender permission**.

Every precondition for a forgery finding appears to be present. Test it.

```bash
# host
adb shell "am broadcast -a android.intent.action.LOCALE_CHANGED"
```

Reference:

```
Broadcasting: Intent { act=android.intent.action.LOCALE_CHANGED flg=0x400000 }

Exception occurred while executing 'broadcast':
java.lang.SecurityException: Permission Denial: not allowed to send broadcast
android.intent.action.LOCALE_CHANGED from pid=9017, uid=2000
```

`LOCALE_CHANGED` is a **protected broadcast**. `ActivityManagerService` refuses it for any
non-platform caller, before any receiver is consulted. The receiver is genuinely unguarded
and genuinely unreachable.

**This is not a finding.** Write it down as informational and move on. Learning to close a
lead this fast is worth more than learning to open one.

### 4.2 Now find one that is not protected

```bash
# host — take your unguarded third-party actions and classify them
python3 -B receiver-surface.py --third-party --unprotected --json \
  | python3 -c 'import json,sys
d=json.load(sys.stdin)
acts=set()
for r in d["receivers"]:
    for f in r["filters"]:
        if f["requiredPermission"] is None:
            acts.update(f["actions"])
print("\n".join(sorted(acts)))' > actions.txt

wc -l actions.txt
bash protected-broadcast-map.sh --check actions.txt | tee classified.txt
```

The `forgeable` rows are your candidate list. On the measured device those included things
like `analytics.deviceid`, `AUTO_START_MNG_INFO_CLICKED` and
`com.google.android.chimera.MODULE_CONFIGURATION_CHANGED` — vendor and SDK actions with no
platform protection.

### 4.3 The three questions, for each candidate

| Question | How to answer |
|---|---|
| **Is the action forgeable on this device?** | `protected-broadcast-map.sh --is <action>` — done in 4.2 |
| **What does the receiver do with it?** | Hook it. Lab 02 covers this; `scripts/hook-broadcast.js` with `bc.deliveries()` |
| **Can an unprivileged app reach it?** | Only provable from an app. `adb shell` is uid 2000 and is privileged |

If you cannot answer all three, you have a lead. Leads are not findings.

> **⚠️ Warning — do not send forgeable broadcasts blindly on a device you care about.**
> Every "forgeable" action in your list has real listeners in real apps. Sending one
> delivers it. On a personal phone that can clear caches, reset counters or trigger
> uploads. Do the sending half on an emulator, or against a lab app you built.

> **✅ Checkpoint 4.**
> You closed at least one unguarded receiver as *not a finding* because its action is
> protected, and you produced a shortlist of actions that genuinely are forgeable.

---

## Part 5 — Watch the surface move

A single snapshot is a photograph of a moving thing. Prove it to yourself.

### 5.1 Baseline

```bash
# host
python3 -B receiver-surface.py --third-party --brief --json > before.json
python3 -c "import json;d=json.load(open('before.json'));print(len(d['receivers']),'registrations')"
```

### 5.2 Exercise the device

Open a couple of apps you have on the device. A browser and a media app are good choices —
both register connectivity and screen-state receivers. Change a setting. Toggle Wi-Fi.

### 5.3 Diff

```bash
# host
python3 -B receiver-surface.py --third-party --brief --json > after.json
python3 - <<'PY'
import json
b = {(r["process"], a) for r in json.load(open("before.json"))["receivers"]
     for f in r["filters"] for a in f["actions"]}
a = {(r["process"], a) for r in json.load(open("after.json"))["receivers"]
     for f in r["filters"] for a in f["actions"]}
print("APPEARED :", len(a - b))
for x in sorted(a - b)[:15]: print("  +", x[0], x[1])
print("VANISHED :", len(b - a))
for x in sorted(b - a)[:15]: print("  -", x[0], x[1])
PY
```

Every line under `APPEARED` is a receiver that would have been missing from a report
written from your first snapshot.

**The operational lesson:** when you assess an app, run the enumerator *while driving the
app through its features*, and union the results. One snapshot at launch is not an
inventory.

---

## Part 6 — The history: who sent what

The registration table tells you who is listening. The history tells you who spoke.

### 6.1 Read it

```bash
# host
python3 -B receiver-surface.py --history --limit 15
```

Then with payloads:

```bash
# host
python3 -B receiver-surface.py --history --with-extras --limit 15
```

### 6.2 Prove that extras are recorded in cleartext

```bash
# host
adb shell "am broadcast -a com.lab01.PROBE --es token SUPERSECRET123 --ei n 42"
adb shell "dumpsys activity broadcasts" | grep -A6 "com.lab01.PROBE"
```

Reference:

```
BroadcastRecord{2439c45 u0 com.lab01.PROBE} to user 0
Intent { act=com.lab01.PROBE flg=0x400010 (has extras) }
  extras: Bundle[{n=42, token=SUPERSECRET123}]
caller=null null pid=9127 uid=2000
```

Two facts in one output:

- **`caller=… uid=2000`** — the sender. This is the only attribution that exists anywhere
  on the system. It is *not* available inside `onReceive` (see
  [§3.9](../README.md#39-caller-identity--measured-not-argued)).
- **`extras: Bundle[{n=42, token=SUPERSECRET123}]`** — the payload, verbatim. Any secret an
  app puts in a broadcast extra is readable, after the fact, by anything with shell access.

`com.lab01.PROBE` is a custom action nothing listens for, so this probe is harmless.

### 6.3 The forensic point

The history is a ring buffer — 50 records per queue on the measured device — and a reboot
destroys it. In an incident or a malware triage, capture it **first**:

```bash
# host
adb shell "dumpsys activity broadcasts" > evidence-$(date +%Y%m%d-%H%M%S).txt
```

Then analyse offline, as many times as you like:

```bash
# host
python3 -B receiver-surface.py --dumpsys-file evidence-*.txt --history --with-extras
```

---

## Hints

<details>
<summary><b>Hint 1 — the enumerator parses zero registrations</b></summary>

The `ReceiverList` line format varies slightly between releases. Look at your own dump:

```bash
grep -m1 "ReceiverList{" broadcasts.txt
```

Compare it against `RE_RECEIVER_LIST` near the top of `receiver-surface.py`. The user id is
written `u0` / `u-1` with a literal `u` prefix; a release that omits it will not match.
The script tells you to check exactly this regex when it parses nothing — that message is
there because it happened during development.
</details>

<details>
<summary><b>Hint 2 — `cmd package query-receivers` is not recognised</b></summary>

It requires API 29 or higher. On older devices use the resolver table instead:

```bash
adb shell "dumpsys package" | sed -n '/Receiver Resolver Table/,/Service Resolver Table/p' | grep -i "your.ACTION"
```

Slower and noisier, but the same information.
</details>

<details>
<summary><b>Hint 3 — `--runtime-only` is taking forever</b></summary>

It makes one `adb` round trip per distinct action. Several hundred actions at roughly a
third of a second each is minutes, not seconds. Bound it:

```bash
python3 -B receiver-surface.py --third-party --runtime-only --limit 60
```

The percentage from a 60-action sample is a fair estimate.
</details>

<details>
<summary><b>Hint 4 — every third-party app on my device shows zero registrations</b></summary>

Their processes are not running. A runtime registration dies with its process. Open a few
apps and re-run — that is Part 5, and it is the whole point.
</details>

<details>
<summary><b>Hint 5 — I want the receiver's class name</b></summary>

You cannot get it from `dumpsys`, at all, on any release. AMS holds a Binder proxy to an
`InnerReceiver`, not to your class ([§4.4](../README.md#44-delivery-iintentreceiver-loadedapkreceiverdispatcher-activitythread)).
Hook `registerReceiver` instead:

```bash
frida -U -f com.example.target -l ../scripts/hook-broadcast.js
# then: bc.registrations()
```

That is Lab 02.
</details>

---

## Success criteria

You have finished this lab when you can do all of the following without looking anything up:

- [ ] Name the four sections of `dumpsys activity broadcasts` and say what each contains.
- [ ] Decode a `ReceiverList{...}` line into pid, process, uid, user and local/remote.
- [ ] State the **two** things the dump does not contain, and why neither is a bug.
- [ ] Quote your own device's registration count, filter count and unguarded-filter count.
- [ ] Show two snapshots of the same idle device with different counts, and explain why.
- [ ] Produce your own "N of M actions are runtime-only" figure, and state precisely what
      it does and does not claim.
- [ ] Point at one unguarded receiver on your device and explain, with a measurement, why
      it is **not** a finding.
- [ ] Produce a list of actions on your device that genuinely are forgeable.
- [ ] Show the broadcast history recording a sender uid and a cleartext extra.
- [ ] Explain why `adb shell` is not a valid proxy for an attacker app.

---

## What you should take away

**One.** The manifest is a lower bound on an app's broadcast surface, sometimes a very poor
one. On the measured device, 69 % of third-party broadcast actions had no manifest listener
at all.

**Two.** `dumpsys activity broadcasts` is the only reader of that surface, and it has two
permanent blind spots — class names and, below API 33, export state. Hooking fills both.

**Three.** The surface is *live*. Any count is a timestamped observation, and any receiver
you did not find may simply not have existed when you looked.

**Four.** An unguarded receiver is a lead. A protected action closes it instantly. Learning
to close leads fast is what makes the open ones credible.

---

## Next

- [Lab 02 — Forge a broadcast at a vulnerable receiver](lab-02-forge-a-broadcast.md) — take
  a lead all the way to a demonstrated, persisted state change.
- [Lab 03 — Ordered broadcasts and interception](lab-03-ordered-broadcasts-and-interception.md)
  — priority, `abortBroadcast()` and the result channel.
- [Lab 04 — CTF: the receiver that is not there](lab-04-ctf-the-receiver-that-is-not-there.md)
