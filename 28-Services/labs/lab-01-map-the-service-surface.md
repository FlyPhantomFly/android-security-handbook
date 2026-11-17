# Lab 01 — Map the service surface

> **Objective:** enumerate every service on a real Android device, work out which
> ones an ordinary app could reach, and — the part that actually matters —
> separate the *controls* from the *leads*. Finish able to defend, out loud, why
> 325 exported services is not 325 findings.

| | |
|---|---|
| **Difficulty** | Beginner |
| **Time** | 45–75 minutes |
| **Needs** | A device or emulator with `adb`. **No root. No app to install. No Frida.** |
| **Measured against** | Redmi `M2101K6P`, Android 11 / API 30, arm64 |
| **Reads** | [README §3.1](../README.md), [§7.1](../README.md), [§7.2](../README.md), [§5.7](../README.md) |
| **Uses** | [`../scripts/service-recon.py`](../scripts/service-recon.py) |

---

## 0. Why this lab exists

Every later lab needs a target. Choosing one badly wastes a day: you can spend an
afternoon building an attacker app against a service that turns out to return
`null` from `onBind`, or that is guarded by a signature permission you were never
going to hold.

More importantly, this lab teaches the discipline that the rest of the chapter
depends on. The enumeration step is easy and produces a big, alarming number. The
skill is in what you do with the number.

> **Mental Model**
> Enumeration produces **doors**. A finding needs **a door, a room behind it, and
> something in the room**. This lab is entirely about doors, and it ends by
> making you say out loud how many of them you have *not* opened.

---

## 1. Setup

```bash
# host
adb devices -l
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.model
```

Expected on the reference device:

```text
List of devices attached
84f7a024   device product:sweetin model:M2101K6P device:sweetin transport_id:1
11
30
M2101K6P
```

**Write your API level down now.** Several results below are version-gated, and
the single most common way to produce a wrong answer in this chapter is to quote
a measurement from one API level as though it applied to another.

Create a working directory on the host:

```bash
# host
mkdir -p ~/ch28-lab01 && cd ~/ch28-lab01
```

---

## 2. Step 1 — what is running right now

```bash
# adb shell
dumpsys activity services > /dev/null 2>&1 && echo ok
```

```bash
# host -- capture it
adb shell dumpsys activity services > services.txt
wc -l services.txt
grep -c "ServiceRecord{" services.txt
```

On the reference device this produced several thousand lines and over a hundred
`ServiceRecord` entries.

Now read one record properly. Every field is a field of
`ServiceRecord.java` — see [README §4.4](../README.md).

```bash
# host
grep -A16 "ServiceRecord{" services.txt | head -20
```

```text
* ServiceRecord{6bd0055 u0 com.google.android.gms/.nearby.presence.service.LifeCycleService}
  intent={cmp=com.google.android.gms/.nearby.presence.service.LifeCycleService}
  packageName=com.google.android.gms
  processName=com.google.android.gms.persistent
  app=ProcessRecord{5244c96 27584:com.google.android.gms.persistent/u0a185}
  allowWhileInUsePermissionInFgs=true
  startForegroundCount=0
  createTime=-1d3h58m27s585ms startingBgTimeout=--
  startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=3
  callerPackage=com.google.android.gms
  restartCount=1 restartDelay=-3d9h15m51s794ms crashCount=0
```

**Q1.** Which field tells you *who started* this service? Which tells you whether
it has ever been promoted to the foreground? Which tells you it is running in a
process of its own rather than the app's main one?

<details>
<summary>Answer</summary>

`callerPackage=com.google.android.gms` — who started it.
`startForegroundCount=0` — it has never been a foreground service.
`processName=com.google.android.gms.persistent` differs from `packageName`, so
`android:process` is set. That is a separate process with the **same UID**; it is
not a security boundary ([21 §3.12](../../21-App-Sandbox/README.md)), but it does
mean you would attach a debugger to a different pid.
</details>

### 2.1 Find the bound ones

```bash
# host
grep -B4 -A12 "Bindings:" services.txt | head -40
```

```text
* ServiceRecord{1e9f96d u0 com.google.android.gms/.chimera.PersistentInternalBoundBrokerService}
  Bindings:
  * IntentBindRecord{ca81b6b CREATE}:
    intent={act=com.google.android.gms.trustlet.onbody.service.BIND pkg=com.google.android.gms}
    binder=android.os.BinderProxy@bb076c8
    requested=true received=true hasBound=true doRebind=false
    * Client AppBindRecord{503b361 ProcessRecord{...27584:...gms.persistent/u0a185}}
      Per-process Connections:
        ConnectionRecord{dd8f633 u0 CR ...}
  * IntentBindRecord{1411e86 CREATE}:
    intent={act=com.google.android.gms.trustlet.bluetooth.service.BIND pkg=com.google.android.gms}
    binder=android.os.BinderProxy@1ab0347
```

**Q2.** Why are there **two** `IntentBindRecord` entries for one service, and what
does that tell you about how many times `onBind` ran?

<details>
<summary>Answer</summary>

`IntentBindRecord` is keyed by `Intent.filterEquals()` — action, data, type,
package, component, categories, but **not** extras. The two clients used
different actions (`...onbody.service.BIND` and `...bluetooth.service.BIND`), so
the framework treated them as two distinct Intents, called `onBind` **twice**,
and cached two different `BinderProxy` objects.

This is [README §3.3](../README.md) visible on a live device, and it has a direct
consequence for testing: if a service switches on `intent.getAction()`, the
action you send changes what you get back — sometimes including whether you get
anything at all.
</details>

**Q3.** One of those lines reads `binder=android.os.BinderProxy@bb076c8`. What
would it mean if it read `binder=null`?

<details>
<summary>Answer</summary>

`onBind` returned `null` for that Intent — the service refused it. That is a
*stronger* signal than any manifest attribute, because it is what the code
actually did rather than what the declaration permits. It is also exactly the
behaviour you will meet in Lab 02, where `bindService` returns `true` and no
connection is ever established.
</details>

---

## 3. Step 2 — what *could* be reached

`dumpsys activity services` shows what is **running**. That is not the attack
surface. The attack surface is what could be *started or bound*, which lives in
the package manager.

```bash
# host
adb shell dumpsys package r > resolver.txt
sed -n '/^Service Resolver Table:/,/^Provider Resolver Table:/p' resolver.txt > srt.txt
wc -l srt.txt
```

Reference device: 2,255 lines.

```bash
# host -- the structure
grep -nE "^  [A-Z]" srt.txt | head
```

```text
2:  Full MIME Types:
8:  Base MIME Types:
13:  Schemes:
115:  Non-Data Actions:
```

```bash
# host -- how many distinct actions resolve to a service?
sed -n '/Non-Data Actions:/,$p' srt.txt | grep -cE "^      \S+:$"
```

Reference device: **826**.

**Q4.** A service is declared with `android:exported="true"` and **no**
`<intent-filter>`. Does it appear in this table? Is it reachable?

<details>
<summary>Answer</summary>

**No, and yes.** The resolver table only knows about components that declared a
filter. A service with `exported="true"` and no filter is invisible here and is
fully reachable by **explicit component name** — which is exactly how the prober
in Lab 02 binds things.

This is the single biggest blind spot of any device-side enumeration, and it is
why [README §8](../README.md) insists on reading the manifest as well. The
`--component` option of `service-recon.py` exists for exactly this case.
</details>

### 3.1 One action, in detail

```bash
# adb shell
pm query-services -a android.accessibilityservice.AccessibilityService
```

```text
9 services found:
  Service #0:
    ServiceInfo:
      name=com.android.settings.accessibility.accessibilitymenu.AccessibilityMenuService
      packageName=com.android.settings
      enabled=true exported=true directBootAware=true
      permission=android.permission.BIND_ACCESSIBILITY_SERVICE
      flags=0x0
```

**Q5.** This service is `exported=true`. Is that a finding?

<details>
<summary>Answer</summary>

**No — it is a control observed, and it should be written up as one.**

An accessibility service *must* be exported, because `system_server` has to be
able to bind it. It is safe because `android:permission` names
`BIND_ACCESSIBILITY_SERVICE`, which only the system holds. This is the canonical
demonstration that "exported" on its own carries no information.

Nine such services on the reference device, all system or Google components, all
correctly guarded.
</details>

### 3.2 Query a specific component, filter or no filter

```bash
# adb shell
pm query-services -n com.android.settings/.wifi.MiuiWifiService
```

```text
1 services found:
  Service #0:
    ServiceInfo:
      name=com.android.settings.wifi.MiuiWifiService
      packageName=com.android.settings
      processName=com.android.settings:remote
      enabled=true exported=true directBootAware=true
      permission=com.xiaomi.permission.ACCESS_WIFI
```

This is the **authoritative** value of `exported`, computed by the platform. It
beats anything `apktool` reconstructs from a binary manifest.

---

## 4. Step 3 — is the permission real?

This is the step everybody skips and it is where the value is.

```bash
# adb shell
pm list permissions -f -g | grep -A4 "permission:com.xiaomi.permission.ACCESS_WIFI"
```

```text
  + permission:com.xiaomi.permission.ACCESS_WIFI
    package:com.miui.rom
    label:null
    description:null
    protectionLevel:signature
```

`signature` — a real gate. Now try a different one:

```bash
# adb shell
pm list permissions -f -g | grep -A4 "permission:android.permission.INTERNET"
```

```text
  + permission:android.permission.INTERNET
    package:android
    protectionLevel:normal|instant
```

**Q6.** A service declares `android:permission="android.permission.INTERNET"`.
How much protection does that provide?

<details>
<summary>Answer</summary>

**None.** `INTERNET` is `protectionLevel=normal`, granted at install to any app
that requests it, with no prompt and no review. Essentially every app on the
device holds it. As a service guard it is exactly equivalent to declaring no
permission at all.

It is not a mistake anybody makes deliberately. It happens when a developer
copies a permission name from their own `<uses-permission>` line into
`android:permission`, which looks superficially reasonable.

On the reference device, **five exported services were guarded this way**.
</details>

> **Warning — a real bug found while writing this lab**
> `pm list permissions -f` **without `-g`** prints permissions that belong to a
> permission *group* indented under a group heading, and a naive parser misses
> them entirely. The first version of `service-recon.py` reported
> `android.permission.RECORD_AUDIO` as "not declared on this device", which is
> both wrong and alarming. Always pass `-g`, and if you write your own parser,
> accept the indented `  + permission:` form as well as the flush-left one.

---

## 5. Step 4 — do it all at once

Doing the join by hand for 826 actions is not a good use of an afternoon.

```bash
# host, from the chapter directory
python3 scripts/service-recon.py > all.txt
```

It reports progress on stderr and takes roughly 30 seconds; a single
`cmd package query-services` call measured at about 30 ms on device, and the
script batches 30 per `adb` invocation because the round trip costs far more than
the query.

```text
Service Resolver Table: 826 queryable actions
device: M2101K6P  Android 11 (API 30)  arm64-v8a

SUMMARY
  services seen via an intent action : 839
  OPEN                              : 325
  WEAK-PERM                         : 16
  DANGEROUS                         : 1
  UNKNOWN-PERM                      : 2
  SIGNATURE                         : 108
  SYSTEM-BIND                       : 76
  NOT-EXPORTED                      : 287
  DISABLED                          : 24
  distinct packages with an OPEN one : 94
```

The verdicts:

| Verdict | Meaning |
|---|---|
| `OPEN` | exported, **no permission at all** |
| `WEAK-PERM` | exported behind a `normal` permission — not a gate |
| `DANGEROUS` | exported behind a `dangerous` permission — a prompt, not a wall |
| `UNKNOWN-PERM` | the permission is not declared by anything installed, so **nobody** can hold it here |
| `SIGNATURE` | exported behind a signature-level permission |
| `SYSTEM-BIND` | guarded by a `BIND_*` permission only the system holds |
| `NOT-EXPORTED` | same-UID callers only |
| `DISABLED` | `enabled=false` |

---

## 6. Step 5 — triage, which is the actual skill

### 6.1 The wrong instinct

The wrong instinct is to open `--open` and start at the top of 325 rows.

```bash
# host
python3 scripts/service-recon.py --open | head -20
```

You will find Bluetooth, telephony, the Play Store, the launcher, and ninety
other packages. Almost all of them are exported because something legitimately
binds them.

### 6.2 The right instinct

```bash
# host
python3 scripts/service-recon.py --weak | grep -E "WEAK-PERM|DANGEROUS|UNKNOWN"
```

Sixteen rows on the reference device. Read them.

```text
WEAK-PERM  com.vendor.officesuite/...work.exportpdf...   com.vendor.officesuite.permission.BIND_CONVERT_SERVICE   [normal]
WEAK-PERM  com.android.vending/...services.LicensingService com.android.vending.CHECK_LICENSE                     [normal|instant]
WEAK-PERM  com.google.android.gms/...analytics.service...   android.permission.INTERNET                           [normal|instant]
WEAK-PERM  com.xiaomi.midrop/...fileserver.FileServer       android.permission.INTERNET                           [normal|instant]
WEAK-PERM  com.xiaomi.account/...XiaomiAuthService          com.xiaomi.permission.AUTH_SERVICE                    [normal]
...
DANGEROUS  com.android.soundrecorder/...RecorderService     android.permission.RECORD_AUDIO       [dangerous|instant]
```

**Q7.** Why is this set worth more of your time than the 325 `OPEN` rows?

<details>
<summary>Answer</summary>

Because in every one of them **a developer tried**. They wrote a permission, they
declared it, they applied it to the service — and it does not do what they think.

That makes the finding:

- **specific** — you can name the exact attribute and the exact protection level;
- **credible** — you are not telling them their design is wrong, you are telling
  them one word in it is;
- **cheap to fix** — `normal` becomes `signature`, one line, one release;
- **easy to explain to a non-specialist** — "any app can hold this permission by
  asking for it".

An `OPEN` row, by contrast, needs you to bind it and demonstrate an effect before
it is worth anything at all.
</details>

### 6.3 Explain one

```bash
# host
python3 scripts/service-recon.py --explain com.android.keychain/com.android.keychain.KeyChainService
```

```text
COMPONENT     com.android.keychain/com.android.keychain.KeyChainService
VERDICT       OPEN
WHY           exported with no permission -- any app can bind
EXPORTED      true
ENABLED       true
PERMISSION    (none)
PROCESS       (app main process)
ACTIONS       android.security.IKeyChainService
```

**Q8.** This is the system credential store, `OPEN`, no permission. Draft the
finding.

<details>
<summary>Answer</summary>

**Draft nothing yet.** You have a door and no evidence about the room.

Lab 02 binds this exact service from an unprivileged app and measures the result:
`bindService` returns **`true`** and `onServiceConnected` **never fires**,
because its `onBind` returns a binder only for the action it expects and we sent
a bare component Intent.

A finding written from this table alone would have been a critical-severity claim
about a service the reporter could not reach. That is the single most useful
negative result in the whole chapter, and it is why the script's own summary says
`OPEN is a WORK QUEUE, not a finding`.
</details>

---

## 7. Step 6 — the system-bound services

```bash
# host
python3 scripts/service-recon.py --json | python3 -c "
import json,sys,collections
rows=json.load(sys.stdin)
c=collections.Counter(r['permission'] for r in rows if r['verdict']=='SYSTEM-BIND')
for p,n in c.most_common(): print('%4d  %s' % (n,p))
"
```

```text
  11  android.permission.BIND_QUICK_SETTINGS_TILE
   9  android.permission.BIND_ACCESSIBILITY_SERVICE
   6  android.permission.BIND_WALLPAPER
   4  android.permission.BIND_NOTIFICATION_LISTENER_SERVICE
   4  android.permission.BIND_NFC_SERVICE
   4  android.permission.BIND_INPUT_METHOD
   ...
```

**Q9.** Nine accessibility services are installed and exported. Is anything wrong?

<details>
<summary>Answer</summary>

Not from this alone. **Installed and declared** is not **enabled**. Check:

```bash
# adb shell
settings get secure enabled_accessibility_services      # -> null
settings get secure accessibility_enabled               # -> 0
settings get secure enabled_notification_listeners
```

On the reference device the first two read `null` and `0`: nothing is enabled.
The nine are latent capability, not active capability.

Those two commands are the highest-yield single check in a suspected-fraud
triage, because the packages listed there can read every word on the screen and,
if their `res/xml` config asks for `canPerformGestures`, drive the UI. See
[README §3.13](../README.md).
</details>

---

## 8. Step 7 — capture it, so you can work offline

```bash
# host
python3 scripts/service-recon.py --capture ./snap
ls -la snap/
python3 scripts/service-recon.py --fixture ./snap --weak
```

The `--fixture` run needs no device at all. Two reasons this matters: you can
analyse on a plane, and you can **diff two captures** — before and after an OTA,
or a target app's version 3.1 against 3.2 — which is how you find a service that
was quietly exported in an update.

```bash
# host -- the diff that finds a regression
python3 scripts/service-recon.py --fixture ./before --csv > before.csv
python3 scripts/service-recon.py --fixture ./after  --csv > after.csv
diff <(cut -d, -f1,2 before.csv | sort) <(cut -d, -f1,2 after.csv | sort)
```

---

## 9. Success criteria

You have finished when you can do all six without looking anything up:

- [ ] State your device's API level and name one behaviour in this chapter that
      it cannot exhibit.
- [ ] Produce the counts for your own device: total, `OPEN`, `WEAK-PERM`,
      `SIGNATURE`, `SYSTEM-BIND`, `NOT-EXPORTED`.
- [ ] Name one service on your device that is exported **and correctly
      protected**, and say what protects it.
- [ ] Name one service that is exported behind a permission that is **not** a
      gate, and quote its `protectionLevel`.
- [ ] Explain why a service with `exported="true"` and no `<intent-filter>` does
      not appear in your enumeration, and how you would find it.
- [ ] Say, in one sentence, why your `OPEN` count is not a finding count.

---

## 10. Common mistakes in this lab

| Mistake | Why it is wrong |
|---|---|
| Treating `dumpsys activity services` as the attack surface | It shows what is **running**, not what is **reachable**. The resolver table is the surface |
| Stopping at `exported=true` | It carries no information on its own. 76 correctly-guarded services on the reference device are `exported=true` |
| Reading the permission **name** and not its **level** | `com.example.permission.BIND_SECRET_SERVICE` at `normal` is not a gate, however it is named |
| Using `pm list permissions -f` without `-g` | Grouped permissions are silently missed. This produced a real false "undeclared permission" result while writing this lab |
| Assuming apktool's `android:exported` | It is a reconstruction. `pm query-services -n` gives the platform's computed value |
| Reporting the `OPEN` count as a headline metric | It will be gamed by setting `exported="false"` on services nobody could reach anyway, and it will miss the one service that is correctly exported and hands out a token |

---

## 11. What this lab deliberately does not do

- **It does not bind anything.** There is no `am bind-service`, and `adb shell`
  is not an app: it is exempt from package-visibility filtering and has a
  different SELinux context and permission set. Everything you conclude here is
  about *declarations*. Lab 02 tests *reality*, and the two disagree more often
  than you would like.
- **It does not read any APK.** Services with no intent filter, and the meaning
  of any transaction code, both require the code. [README §8](../README.md).
- **It does not touch a running service's state.** Nothing here sends a
  transaction. That is deliberate: enumeration should be safe to run on a client
  device, and sweeping transaction codes is not.

---

## Next

[Lab 02 — Bind from an unprivileged app](lab-02-bind-from-an-unprivileged-app.md)
takes the shortlist you just built and finds out which of those doors actually
open.
