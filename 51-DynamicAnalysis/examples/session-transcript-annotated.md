# Annotated session transcript

A real dynamic pass, command by command, with **what each observation proves** — and, just as often,
what it does not.

**Target.** An anonymised commercial field-management application, version 1.9, already installed on
the test device. Written throughout as `com.vendor.fieldmgr`. Preference values are redacted and the
APK hash is omitted; **every flag, uid, SELinux context, count, timing and percentage below is the
real measured value.**

**Device.** Physical `i9000S`, Android 13 / API 33, arm64, SELinux Enforcing, **not rooted, no
`frida-server`**.

**Discipline.** Observation only. Nothing was hooked, instrumented, repackaged or bypassed. The two
mutations performed — `am force-stop` and `am start` — are named at the point of use and were
reversed.

> **How to read this file.** Each block is: the command, its real output, and a **Proves** line. The
> `Proves` line is the point. A command with no `Proves` line is reconnaissance, and reconnaissance
> is not evidence.

---

## Stage 1 — Prepare

### 1.1 Which device is this?

```bash
# host
adb devices -l
adb shell "getprop ro.product.model; getprop ro.build.version.release; getprop ro.build.version.sdk"
```

```
80062527052150   device product:i9000S model:i9000S device:i9000S transport_id:1
i9000S
13
33
```

**Proves.** The device is an `i9000S` on API 33. Nothing more — but this repository has had **two
physical devices swapped mid-project without warning**, and they differ in root, in Frida
availability and in API level. A version-gated claim written against the wrong device is not a
mistake you can detect later.

### 1.2 What can it do?

```bash
# host
adb shell "getprop ro.build.version.security_patch; getprop ro.debuggable; getenforce"
adb shell "which su; su -c id"
adb shell "ps -A -o NAME" | grep -i frida
adb shell "mount | grep cacerts"
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
```

```
2021-11-05
0
Enforcing
/system/bin/sh: su: inaccessible or not found
(no output)
(no output)
deviceLocked=0
```

**Proves**, line by line:

| Output | What it establishes |
|---|---|
| `2021-11-05` | **The security patch level is four and a half years behind the platform release.** On a fleet device this is a finding in its own right, and it means public platform issues are in play. It is also a reminder that release and patch level are independent — never infer one from the other |
| `ro.debuggable 0` | The *build* is not debuggable, so any debuggable app found later is individually debuggable, not a consequence of the build |
| `Enforcing` | SELinux is on. Reachability results are not inflated by a permissive device |
| `su: inaccessible or not found` | **No root.** Every root-only row of the capability matrix is closed, and the rest of this session must work without them |
| no frida process | Altitude 3 is unavailable without rebuilding an app — which is out of scope here |
| no `cacerts` mount | **Trust-store questions *can* be answered honestly on this device.** The repository's other device fails this check and cannot |
| `deviceLocked=0` | The screen is unlocked, so app-originated Activity starts will not be silently refused |

**What it does not prove.** Nothing here says anything about any application. This is forty seconds of
establishing what your later sentences are allowed to claim.

---

## Stage 1b — Identify the target

### 1.3 What is installed?

```bash
# host
adb shell "pm list packages -3" ; adb shell "pm list packages" | wc -l
```

```
package:com.vendor.fieldapp
package:com.vendor.fieldmgr
187
```

**Proves.** 187 packages installed, of which exactly **two** are third-party. This is a vendor
appliance rather than a consumer phone, which is worth knowing before you interpret anything else on
it.

### 1.4 The platform's own record

```bash
# host
adb shell "dumpsys package com.vendor.fieldmgr" | grep -E \
  "versionName|versionCode|targetSdk|minSdk|^ *flags=|userId=|codePath"
```

```
    userId=10150
    codePath=/data/app/~~z0up5iFqU_...==/com.vendor.fieldmgr-9aaZV1tX...==
    versionCode=9 minSdk=21 targetSdk=33
    versionName=1.9
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA TEST_ONLY ALLOW_BACKUP ]
```

**Proves.** Four separate things, none of which is a file's claim about itself — this is what
PackageManagerService **parsed and applied**:

- `DEBUGGABLE` — `android:debuggable="true"` survived into the installed build.
- `TEST_ONLY` — the APK was built with `android:testOnly`, so it can only be installed with
  `pm install -t`. **This build was never meant to leave a lab.**
- `ALLOW_BACKUP` — `allowBackup` is not disabled.
- `userId=10150` — an application uid, which matters in §1.6.

**What it does not prove.** That anything is exploitable. Four flags is four leads.

### 1.5 The one-word debuggable detector

```bash
# host
adb jdwp
```

```
2863
```

**Proves.** Exactly one process on this device has an open JDWP transport, and ART opens that
transport only when the runtime flags say the process is debuggable. So this is an **exact
enumerator, not a heuristic** — and it needed no APK, no decompiler and no manifest.

And the package-level sweep:

```bash
# adb shell
for p in $(pm list packages | sed s/package://); do
  f=$(dumpsys package $p 2>/dev/null | grep -m1 "flags="); case "$f" in *DEBUGGABLE*) echo "$p $f";; esac
done
```

```
com.ubx.gpstest        flags=[ SYSTEM DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ]
com.vendor.fieldmgr    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA TEST_ONLY ALLOW_BACKUP ]
com.udroid.poskey      flags=[ SYSTEM DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
com.ubx.factorykit     flags=[ SYSTEM DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
com.udroid.portinstall flags=[ SYSTEM DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
```

**Proves.** Five packages carry `DEBUGGABLE`, and **four are OEM system applications shipped
debuggable on a retail device**. That is a device-posture finding and it belongs in a report about the
device, not about any app.

**Note the discrepancy with `adb jdwp`**, which returned one pid: the other four were simply not
running. `adb jdwp` enumerates debuggable **processes**; the loop enumerates debuggable **packages**.
Run both.

### 1.6 Can you get inside it? — and the two refusals

```bash
# host
adb shell "run-as com.vendor.fieldmgr id"
adb shell "run-as com.ubx.factorykit id"
adb shell "run-as com.vendor.fieldapp id"
```

```
uid=10150(u0_a150) gid=10150(u0_a150) groups=10150(u0_a150),1004(input),1007(log),1011(adb),
  1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),
  3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs),
  50150(all_a150) context=u:r:runas_app:s0:c150,c256,c512,c768

run-as: package not an application: com.ubx.factorykit

run-as: package not debuggable: com.vendor.fieldapp
```

**Proves.** Three things, and the second is the one nobody knows:

1. Channel 04 is **open** for the target, with no root.
2. **`run-as` refuses in two distinct ways.** `com.ubx.factorykit` **is** debuggable — the sweep above
   showed the flag — and `run-as` still refused it, because its uid is a system uid below 10000. The
   message says `not an application`, which reads exactly like `not debuggable` to anyone skimming.
   **The rule is `FLAG_DEBUGGABLE` *and* an application uid**, not just the flag.
3. The SELinux context is `u:r:runas_app:s0:c150,c256,c512,c768` — **not** the app's own domain.
   `run-as` transitions to a dedicated domain, so it reads the data directory without simply "being"
   the app.

> **On the four MCS categories.** Chapters 21 and 22 give an app's MCS pair as `c[appId & 0xff]` and
> `c[256 + (appId >> 8)]`. For appId 150 that is `c150,c256` — which matches exactly. The additional
> `c512,c768` encode the **user id** and are the API 31+ four-category form. The two-category formula
> is not wrong; it is the first half of a four-category label on a device this new. Anyone parsing MCS
> pairs from API 31+ needs to expect four.

---

## Stage 1c — The denominator

```bash
# host
adb pull /data/app/~~z0up5iFqU_...==/com.vendor.fieldmgr-9aaZV1tX...==/base.apk t.apk
# 1 file pulled. 14.1 MB/s (4853571 bytes in 0.328s)
aapt2 dump xmltree --file AndroidManifest.xml t.apk > mf.txt
awk '/E: (activity|activity-alias|service|receiver|provider) /{k=$2; next}
     /E: /{ if ($2 !~ /^(intent-filter|meta-data|action|category|data)$/) k=""; next }
     k != "" && /android:name\(0x01010003\)=/ {
        match($0,/="[^"]+"/); print k" "substr($0,RSTART+2,RLENGTH-3); k="" }' mf.txt | sort -u
```

```
activity com.vendor.fieldmgr.MachineAccessActivty
activity com.vendor.fieldmgr.MainActivity
provider androidx.core.content.FileProvider
receiver com.vendor.fieldmgr.AcRunOnStartUp
```

**Proves.** The shipped artefact declares **four** components. (The `Activty` typo is the
application's, not a transcription error — it is a useful reminder that you are reading somebody's
real code.)

Now the same question asked of the device:

```bash
# host
adb shell "dumpsys package com.vendor.fieldmgr" | grep -oE "com.vendor.fieldmgr/[A-Za-z0-9_.\$]+" | sort -u
```

```
com.vendor.fieldmgr/androidx.core.content.FileProvider
com.vendor.fieldmgr/com.vendor.fieldmgr.MainActivity
com.vendor.fieldmgr/com.vendor.fieldmgr.AcRunOnStartUp
```

**Three.**

**Proves.** The device's resolver tables are **missing `MachineAccessActivty`**, because it carries no
`<intent-filter>` and those tables exist to index components that can win an Intent. It is entirely
real; it is started by explicit Intent from inside the app.

**This one-component gap becomes a 17-point coverage difference at the end of this transcript.**

---

## Stage 2 — Baseline and control

```bash
# host — 45 seconds of nothing, so that the next 45 mean something
bash scripts/session-recorder.sh -p com.vendor.fieldmgr -o ./ev/control --wait 45
```

```
session-recorder 1.0
  package     com.vendor.fieldmgr
  private-fs  run-as  (the package is debuggable and has an app uid, so run-as gives a shell with its identity)
  evidence    ./ev/control
```

The resulting report, in full for the channels that matter:

```
### 04 Private filesystem
No file under the private data directory was created, deleted or rewritten.
That is a real negative result and it is bounded by the window length.

### 06 Runtime-registered receivers
No change.

### 07 Services
No change. No service of this app started, stopped or gained a client.

### 08 Network counters
  dummy0        rx +0             tx +5877
  lo            rx +4017          tx +4017

### 09 Logcat during the window
No log lines were attributed to this app during the window.
```

**Proves.** On this device, over 45 idle seconds:

- Roughly **4 KB of loopback and 6 KB on `dummy0`** move for free. Any network claim below that floor
  is unattributable.
- **Every other channel is silent.** Therefore any private-filesystem, receiver, service or grant
  change in a subsequent run **is** attributable.

That second sentence is what a control run buys, and it costs one command.

**And the baseline itself:**

```
files/content.zip                                       0     d41d8cd98f00b204e9800998ecf8427e
shared_prefs/com.vendor.fieldmgr_preferences.xml      380     205c47b71132a9d2a255811583eaf136
```

**Proves.** Two files, one of them zero bytes. (`d41d8cd9…` is the MD5 of the empty string, which is
worth recognising on sight.) The digest is captured as well as the size **because a preferences file
rewritten to the same length is exactly the change you are hunting**, and size alone misses it.

---

## Stage 4–5 — Exercise, twice, and the first attempt fails

### Run A — a warm launch

```bash
# host
bash scripts/session-recorder.sh -p com.vendor.fieldmgr -o ./ev/warm \
  --exec 'adb shell am start -W -n com.vendor.fieldmgr/.MainActivity >/dev/null;
          sleep 25; adb shell input keyevent KEYCODE_HOME; sleep 8'
```

Every channel: no change. One log line. **This looks like a clean negative result.**

It is not. Re-running with the `am start -W` output captured rather than discarded:

```
Starting: Intent { cmp=com.vendor.fieldmgr/.MainActivity }
Warning: Activity not started, intent has been delivered to currently running top-most instance.
Status: ok
LaunchState: UNKNOWN (0)
Activity: com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity
TotalTime: 0
WaitTime: 32
Complete
```

**Proves.** Read the `Activity:` line. **The Activity in front belonged to
`com.android.permissioncontroller`, not to the app.** A pending runtime-permission dialog absorbed the
launch. The app's UI was never reached.

**This run is void, not negative**, and the two are indistinguishable in the delta report. A careless
reading would have produced a false negative about the app's launch-path behaviour.

> **The lesson, in one sentence:** `>/dev/null` on `am start -W` threw away the only evidence that the
> exercise had not happened.

### The single log line

```
08-12 09:47:34.750  1234  1419 I ActivityTaskManager: START u0 {flg=0x10000000
    cmp=com.vendor.fieldmgr/.MainActivity} from uid 2000
```

**Proves.** `from uid 2000` is **the shell** — subtraction 3, your own tooling. This is not the app
launching itself and it is not another app launching it. Any reachability claim built on this line is
a claim about `adb`, and [60-ADB](../../60-ADB/README.md) measured how privileged that party is: the
`com.android.shell` package requests **200 permissions**, 16 of them runtime permissions pre-granted
`SYSTEM_FIXED`.

### Run B — a cold start

```bash
# host — [MUTATES] force-stop restarts the app. Reversible, and named as a mutation.
bash scripts/session-recorder.sh -p com.vendor.fieldmgr -o ./ev/final \
  --exec 'adb shell am force-stop com.vendor.fieldmgr; sleep 3;
          adb shell am start -W -n com.vendor.fieldmgr/.MainActivity;
          sleep 35'
```

```
### 03 Process
**Appeared during the window:**
  pid 30140
  ProcessRecord{30140:com.vendor.fieldmgr/u0a150}

**Gone by the end of the window:**
  pid (no process -- the app is not running)

### 04 Private filesystem
No file under the private data directory was created, deleted or rewritten.

### 09 Logcat during the window
44 line(s) captured
```

**Proves.**

- **Channel 03 proves the exercise happened.** The process went from not-running to running, pid
  30140. Without this, channel 04's silence would be void exactly as run A was.
- **Channel 04's silence is now attributable.** Across a cold start and 35 seconds of foreground life,
  the application created, deleted and rewrote **nothing** under its private data directory. Its
  existing 380-byte preferences file kept the digest `205c47b7…f136` at both ends.

**What it does not prove.** That the app never writes. It establishes that it does not write **on the
launch path**, which is a bounded and useful sentence and is not the same thing.

---

## Stage 6 — Correlate the 44 log lines

Every line, classified. This is the stage, and it is done by hand.

```
08-12 09:50:21.481 I ActivityManager: Force stopping com.vendor.fieldmgr appid=10150 user=0: from pid 29987
08-12 09:50:21.483 I ActivityManager: Killing 29855:com.vendor.fieldmgr/u0a150 (adj 900): stop ... from pid 29987
```

**Subtraction 3 — your own tooling.** `from pid 29987` is the `adb shell` that ran `force-stop`. Two
lines that look like the platform acting on the app and are in fact the tester acting on it.

```
08-12 09:50:21.487 I game_scn: collectForegroundAppList packName=com.vendor.fieldmgr, ... state:DEAD
08-12 09:50:21.487 I mtkpower_client: [Legacy][PowerHal_Wrap_notifyAppState] ... pid=29855 state:3
08-12 09:50:21.488 I libPowerHal: [perfNotifyAppState] pack:com.vendor.fieldmgr, ... STATE_DEAD
08-12 09:50:24.779 I PowerHalWrapper: amsBoostNotify pid:1614, activity:...GrantPermissionsActivity, ...
```

**Subtraction 2 — the platform.** MediaTek power and thermal management, present for every app on
this device. Fourteen lines of it. Recognising these shapes once saves an hour every session
afterwards.

```
08-12 09:50:21.488 W UsageStatsService: Unexpected activity event reported! (...event : 23 ...)
08-12 09:50:21.488 W InputManager-JNI: Input channel object '...' was disposed without first being removed
08-12 09:50:21.487 W ActivityTaskManager: Force removing ActivityRecord{...}: app died, no saved state
```

**Subtraction 2 — the platform.** Bookkeeping complaints about a process teardown *you* caused.

```
08-12 09:50:24.764 I ActivityTaskManager: START u0 {flg=0x10000000 cmp=com.vendor.fieldmgr/.MainActivity} from uid 2000
```

**Subtraction 3 — your own tooling**, again.

### The result

| Classification | Lines |
|---|---|
| Your own tooling (`from pid 29987`, `from uid 2000`) | 3 |
| Platform: vendor power and thermal | 14 |
| Platform: lifecycle and bookkeeping | 3 |
| Platform: remaining chatter | 24 |
| **Emitted by the application itself** | **0** |

**Proves.** **Forty-four log lines and not one of them is the app's.** Combined with channel 04's
silence, the launch path persists nothing and logs nothing.

**What it does not prove.** That the app never logs. It is a bounded negative on one path, and the
coverage figure below is what bounds it.

---

## Stage 0 — Coverage, both ways

```bash
# host — the correct denominator
python3 -B scripts/coverage-reporter.py -p com.vendor.fieldmgr \
        --components entrypoints.txt --logcat ev/final/09-logcat.txt
```

```
| Inventory source | static pass (`entrypoints.txt`), 4 component(s) |
| Components in inventory | 4 |
| Reached | **2 (50%)** |
| Not reached | 2 |

## Activities (1 of 2 reached)
| `MainActivity`         | yes    | the platform was asked to start this Activity (`logcat`) |
| `MachineAccessActivty` | **no** | -- |

## Receivers (0 of 1 reached)
| `AcRunOnStartUp`       | **no** | -- |

## Providers (1 of 1 reached)
| `FileProvider`         | yes    | the ContentProvider was published into a process (`dumpsys-providers`) |
```

```bash
# host — and the denominator the device offers
python3 -B scripts/coverage-reporter.py -p com.vendor.fieldmgr --logcat ev/final/09-logcat.txt
```

```
| Inventory source | device resolver tables -- **incomplete, see the note below** |
| Components in inventory | 3 |
| Reached | **2 (67%)** |
```

**Proves.** Same session. Same evidence. Same two components reached.

```
against the DEVICE denominator (3):   2/3 = 67%
against the STATIC denominator (4):   2/4 = 50%
```

**The flattering figure came from letting the device define the denominator.** Seventeen points on a
four-component application; on a real app with dozens of filterless internal screens the gap is much
larger and always in the same direction.

**And note the wording the tool chose for `MainActivity`: "the platform was *asked* to start this
Activity".** Not "the Activity ran". That distinction is precisely what caught run A, and it is why
the tool prints what the evidence proves rather than a tick.

---

## Stage 7 — Validate

Two observations survive correlation.

### O-1 — the debuggable, test-only build

| Question | Answer | Evidence |
|---|---|---|
| Real? | Yes | `dumpsys package … flags=[ DEBUGGABLE … TEST_ONLY … ]`; `run-as` returned uid 10150 |
| Reachable? | Yes — a process attribute, not code | `adb jdwp` returned the pid; `run-as` executed |
| Who? | Anyone with ADB access to the unlocked device. **Not** remote, **not** another app | Demonstrated from the host over USB |
| So what? | Read/write of the private directory and a Java debugger on the live process | Channel 04, read below |

```bash
# host — question 4, answered rather than assumed
adb shell "run-as com.vendor.fieldmgr cat /data/data/com.vendor.fieldmgr/shared_prefs/*.xml"
```

```xml
<map>
    <string name="appname">REDACTED</string>
    <boolean name="Permission_Overlay" value="true" />
    <string name="packagename">REDACTED</string>
    <string name="dty_deviceid">REDACTED</string>
    <string name="showdelay">REDACTED</string>
    <string name="tmp_file_name">REDACTED</string>
</map>
```

**Proves.** Six device-configuration strings. **No credential, no session token, no personal data.**

That negative is as important as a positive would have been, and it is what makes the severity
argument honest rather than reflexive. **Verdict: FINDING, High** — on the exposure, not on today's
payload. `TEST_ONLY` means nobody designed what lives in that directory, and a future build may put a
session there while the exposure is already in place.

### O-2 — the network counters

```
dummy0        rx +0             tx +5519
lo            rx +3954          tx +3954
```

Against the control run's `+5,877` and `+4,017` over a comparable window.

**Verdict: REJECTED — background.** Within noise. This is subtraction 1 doing its job, and without the
control run it would have been a paragraph in a report about "network activity observed during the
session".

---

## What this session did not establish

Stated as plainly as the findings, because a reader will otherwise assume the opposite:

- **Two of four components were never reached.** `MachineAccessActivty` and `AcRunOnStartUp`. No
  statement here, positive or negative, applies to them.
- **Component coverage is not code coverage.** Branch coverage inside `MainActivity` was not measured.
- **No network content was captured.** No proxy was used. Counters prove bytes moved; they say nothing
  about what was in them.
- **The heap was not examined.**
- **Nothing about completeness.** "The app writes nothing on launch" is one path. How many *other*
  write sites exist is a static question — see [52-StaticAnalysis](../../52-StaticAnalysis/README.md).
- **Nothing about the server.**

---

## The three things this transcript is for

1. **A void run and a negative run are indistinguishable in the report.** Run A produced nine silent
   channels and had not happened. `am start -W`'s `Activity:` line was the only evidence, and it had
   been sent to `/dev/null`.
2. **A control run turns silence into a result.** Channel 04's silence in run B is a finding-grade
   sentence *because* the control run established that the device is quiet on that channel.
3. **The denominator decides the number.** 67% and 50% are the same session. Only one of them is
   honest, and it is not the one the device hands you.
