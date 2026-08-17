# 51 — Dynamic Analysis · Cheat Sheet

Printable. The runtime observation catalogue: **what to capture, with which command, and what it
proves.** Full reasoning in [README.md](README.md).

---

## The pipeline

| # | Stage | One command that starts it |
|---|---|---|
| 1 | Prepare | `adb shell "getprop ro.build.version.sdk; getenforce; which su"` |
| 1b | Identify | `adb shell "dumpsys package $PKG \| grep -E 'flags=\|granted='"` |
| 1c | Denominator | `aapt2 dump xmltree --file AndroidManifest.xml base.apk` |
| 2 | Baseline + control | `bash scripts/session-recorder.sh -p $PKG -o ev/control --wait 45` |
| 3 | Instrument | lowest altitude that works |
| 4-5 | Exercise + observe | `bash scripts/session-recorder.sh -p $PKG -o ev/s01 --exec '<script>'` |
| **6** | **Correlate** | **by hand: `ev/s01/DELTA.md` vs `ev/control/DELTA.md`** |
| 7 | Validate | four questions, per observation |
| 8 | Report | evidence + severity + coverage statement |
| 0 | Coverage | `python3 -B scripts/coverage-reporter.py -p $PKG -c entrypoints.txt --logcat ev/s01/09-logcat.txt` |

---

## Device posture — 40 seconds, run it first

| Command | What it decides |
|---|---|
| `adb devices -l` | Which device. **They get swapped** |
| `adb shell getprop ro.product.model` | Record it in the evidence directory |
| `adb shell getprop ro.build.version.sdk` | Every version-gated claim after this |
| `adb shell getprop ro.build.version.security_patch` | Independent of the release. A stale one is a finding |
| `adb shell getprop ro.debuggable` | `1` makes **every** app debuggable |
| `adb shell getenforce` | Permissive changes what is reachable |
| `adb shell "which su; su -c id"` | Whether root-only rows are open |
| `adb shell "ps -A -o NAME" \| grep -i frida` | Whether altitude 3 is available |
| `adb shell mount \| grep cacerts` | **A hit voids every trust-store claim** |
| `adb shell dumpsys trust \| grep -o "deviceLocked=[01]"` | A locked device silently refuses app-originated starts |

---

## The nine channels

| # | Channel | Command | Proves | Needs |
|---|---|---|---|---|
| 01 | Identity | `dumpsys package $PKG \| grep -E 'versionName\|codePath\|flags='` | What the platform parsed and applied | shell |
| 02 | Grants | `dumpsys package $PKG \| grep granted=` | The **answer** to each request, not the request | shell |
| 03 | Process | `pidof $PKG`; `dumpsys activity processes \| grep -A3 $PKG` | The app was alive for the window | shell |
| 04 | Private FS | `run-as $PKG find /data/data/$PKG -type f -exec stat -c%s,%Y,%n {} +` | What was persisted | run-as / root |
| 05 | External FS | `find /sdcard/Android/data/$PKG -type f -exec stat -c%s,%Y,%n {} +` | What escaped the sandbox | shell |
| 06 | Receivers | `dumpsys activity broadcasts` | What it listens for **now**. No file records this | shell |
| 07 | Services | `dumpsys activity services $PKG` | Running services **and their bound clients** | shell |
| 08 | Network | `cat /proc/net/dev`; a proxy | Counters prove traffic; only a proxy proves content | shell / proxy |
| 09 | Logcat | `adb logcat -d -b all -T "$LOG_START"` | More than any other single channel, and free | shell |

### What a silence does NOT mean

| Channel | Silence does not rule out |
|---|---|
| 03 | The app did nothing |
| 04 | The app stores nothing — it may hold it in memory, or write on a path you did not drive |
| 06 | No receiver was registered — one registered in `onResume` and dropped in `onPause` is in **neither** snapshot |
| 08 | No request — a request smaller than platform chatter is invisible in counters |
| 09 | The app logged nothing — the process name may differ from the package, and **the ring wraps** |

---

## Altitudes — pick the lowest that works

| Alt | Instruments | Detectable | Needs | Use when |
|---|---|---|---|---|
| **0** | `dumpsys`, `logcat`, `pm`, `am` | No | shell | The platform already records it |
| **1** | Proxy | Partly | user-CA trust | It crosses the network |
| **2** | `run-as`, `jdb`/JDWP, Studio profiler | No | debuggable | Private storage, heap, live objects |
| **3** | Frida, Objection | **Yes** | root or gadget | It never leaves the process |

**Rule:** write down why altitude *n* was insufficient before you go to *n+1*. That note is your
methodology section.

---

## The unrooted path

| Capability | Command | Precondition |
|---|---|---|
| Find every debuggable process | `adb jdwp` | none |
| Find every debuggable package | `for p in $(pm list packages \| sed s/package://); do dumpsys package $p \| grep -m1 flags=; done` | none |
| Shell as the app | `adb shell "run-as $PKG id"` | `FLAG_DEBUGGABLE` **and** uid ≥ 10000 |
| Read private storage | `adb shell "run-as $PKG cat /data/data/$PKG/shared_prefs/x.xml"` | same |
| Java debugger | `adb forward tcp:8700 jdwp:<pid>` then `jdb -attach localhost:8700` | debuggable |
| Heap dump | `am dumpheap $PKG /data/local/tmp/h.hprof` → `hprof-conv` | debuggable |
| Make a device-side port listen (no root) | `adb reverse tcp:27042 tcp:27042` | none |

### `run-as` refuses in two different ways

| Message | Cause | Fix |
|---|---|---|
| `package not debuggable: X` | `FLAG_DEBUGGABLE` clear | Rebuild debuggable, or use another channel |
| `package not an application: X` | Flag **is** set; uid < 10000 (system app) | None. `run-as` refuses system packages by design |
| `unknown package: X` | Not installed, or wrong name | Check `pm list packages` |

---

## Correlation — three subtractions, four questions

### Subtract

| # | Subtract | How |
|---|---|---|
| 1 | The control run | A window of equal length, app idle |
| 2 | The platform | Vendor power/thermal tags, `UsageStatsService`, `InputManager-JNI`, lifecycle bookkeeping |
| 3 | **Your own tooling** | `from uid 2000` is you. `from pid NNNN` is your shell. Your proxy, your hooks |

### Then ask

| # | Question | Fails ⇒ |
|---|---|---|
| 1 | Did the control run show it too? | Discard: background |
| 2 | Does it line up in **time** with a script step? | Requeue with a narrower window |
| 3 | Can you make it happen again? | Record, do not report |
| 4 | **Can you make it NOT happen?** | Your attribution is wrong |

### Cross-channel pairs that produce findings

| A | B | Proves |
|---|---|---|
| Proxy: token issued at T | Ch 04: file written at T+0.4s | The token is persisted to disk |
| Ch 04: file created | Ch 09: same value logged | The credential is in two places |
| Ch 06: receiver at T | Ch 09: app foregrounded at T | Lifecycle-scoped — a snapshot will miss it |
| Ch 08: counters moved | Proxy: nothing | Traffic that is not HTTP through your proxy |
| Ch 03: process died | Ch 09: native abort | The app is fighting you → 67 §7.3 |

---

## Validation — four questions

| # | Question | Runtime answer | If "no" |
|---|---|---|---|
| 1 | Real? | You reproduced it. Twice | Reject |
| 2 | Reachable? | It happened during ordinary use, with the stack or log line | Downgrade |
| 3 | Who? | **From an app, not `adb shell`** | Downgrade heavily |
| 4 | So what? | The asset. **This is the severity** | Informational |

### Severity grid

| | Not reachable | App only | Another app | Network |
|---|---|---|---|---|
| **No asset** | Informational | Informational | Informational | Low |
| **Device metadata** | Informational | Informational | Low | Low |
| **User data** | Informational | Low | Medium | High |
| **Credentials / financial** | Low | Medium | High | Critical |

---

## The known-value storage sweep

```bash
PKG=com.example.target ; VALUE='Zq7!kestrel-marker-91'
adb shell "run-as $PKG grep -rl -- '$VALUE' /data/data/$PKG"
adb shell "run-as $PKG grep -c -- '$VALUE' /data/data/$PKG/databases/app.db-wal"
adb shell "grep -rl -- '$VALUE' /sdcard/Android/data/$PKG /sdcard/Download 2>/dev/null"
adb logcat -d -b all | grep -F -- "$VALUE"
adb shell uiautomator dump /sdcard/ui.xml && adb shell "grep -c -- '$VALUE' /sdcard/ui.xml"
```

| # | Channel | Path | Needs |
|---|---|---|---|
| 1 | `shared_prefs/` | `/data/data/<pkg>/shared_prefs/*.xml` | run-as |
| 2 | `databases/` | `*.db` **and `-wal` and `-shm`** | run-as |
| 3 | `files/` | `/data/data/<pkg>/files/` | run-as |
| 4 | `cache/`, `code_cache/` | `/data/data/<pkg>/cache/` | run-as |
| 5 | `no_backup/` | `/data/data/<pkg>/no_backup/` | run-as |
| 6 | External | `/sdcard/Android/data/<pkg>/`, `media/`, `Download/` | **nothing** |
| 7 | logcat | all buffers | nothing |
| 8 | WebView | `app_webview/Local Storage/`, `app_webview/Default/Cookies` | run-as |
| 9 | Accessibility tree | `uiautomator dump` | nothing |
| 10 | Third-party SDK stores | under `files/`, `cache/`, own names | run-as |
| 11 | Heap | `am dumpheap` → `hprof-conv` → `strings` | debuggable |
| 12 | Recents thumbnail | task snapshot | — |

---

## Did the exercise actually happen?

| Check | Command | Bad answer |
|---|---|---|
| What ended up in front | `am start -W` → read the **`Activity:`** line | A package that is not yours |
| Focused window | `dumpsys window \| grep mCurrentFocus` | `NotificationShade`, `GrantPermissionsActivity` |
| Still alive | `pidof $PKG` | empty |
| Delivered, not started | `am start -W` output | `Warning: Activity not started, …` |

**"Nothing changed" and "nothing ran" produce identical delta reports.**

---

## Coverage

| | |
|---|---|
| Denominator, **right** | `aapt2 dump xmltree --file AndroidManifest.xml base.apk` — includes filterless components |
| Denominator, **flattering** | `dumpsys package $PKG` resolver tables — **intent-filtered components only** |
| Measured gap | Same session: **67% (device) vs 50% (static)** |
| Grain | Screen < **Component** < Method < Instruction |
| Command | `python3 -B scripts/coverage-reporter.py -p $PKG -c entrypoints.txt --logcat ev/s01/09-logcat.txt` |

**100% component coverage is not a clean bill of health.** It means you drove every front door.

---

## Handoffs

| Situation | Go to |
|---|---|
| Need the hook mechanism, spawn vs attach, `Stalker` | [53-Frida](../53-Frida/README.md) §3, §7 |
| Hook installed, nothing fires | [53-Frida](../53-Frida/README.md) §7.4 — **then** ask if you exercised the path |
| Process dies on attach | [67](../67-BypassingProtections/README.md) §7.2, `bypass-triage.py` |
| Death with **no** lifecycle event | [67](../67-BypassingProtections/README.md) §7.3 — the check ran before Java |
| Need the command, not the method | [77-UsefulCommands](../77-UsefulCommands/README.md) |
| Need completeness, versions, or an unrun build | [52-StaticAnalysis](../52-StaticAnalysis/README.md) |
| Need a native offset read | [57-Ghidra](../57-Ghidra/README.md) |
| Need the report template or the rubric | [80-Appendix](../80-Appendix/README.md) |

---

## Measured numbers worth quoting

| Number | What it is | Source |
|---|---|---|
| **214 / 321 (67%)** | Runtime-only broadcast actions, i9000S API 33 | this chapter §9.4 |
| **299 / 431 (69%)** | Same measurement, Redmi API 30 | [29](../29-BroadcastReceivers/README.md) |
| **263 / 308** | Runtime filters with no sender permission, API 33 | this chapter §5.5.3 |
| **67% vs 50%** | Same session's coverage, device vs static denominator | this chapter §9.4 |
| **4 of 4** | Components in the manifest; the device showed **3** | this chapter §9.4 |
| **12 of 14 / 4** | Apps with a pinning surface / apps that pin | [36](../36-CertificatePinning/README.md) |
| **132 of 132** | High-confidence storage hits that were false positives | [33](../33-Storage/README.md) |
| **61,832 bytes** | WAL holding 4 "deleted" secrets after logout | [33](../33-Storage/README.md) |
| **`TracerPid: 0`** | Throughout a live `jdb` session | [38](../38-TamperDetection/README.md) |
| **`0x38883e44` → `0x38883e46`** | `ApplicationInfo.flags`, release vs debuggable | [38](../38-TamperDetection/README.md) |
| **200 / 16** | Permissions `com.android.shell` requests / pre-granted `SYSTEM_FIXED` | [60](../60-ADB/README.md) |
| **2,104 / 61** | jadx's real refused-method count vs its console summary | [56](../56-JADX/README.md) |
| **139** | Certificates in a tmpfs-replaced system CA store | [44](../44-NetworkSecurityConfig/README.md) |

---

## Language for the report

| Do not write | Write |
|---|---|
| "The app is clean" | "No attributable change was observed on the exercised paths" |
| "The app does not log the token" | "The token did not appear in logcat during a 40-minute window covering login, browse and checkout" |
| "The method is unreachable" | "No static path was found, and the method did not execute during the window described in §N" |
| "An attacker can start this component" | "The component started when invoked from `adb shell` (uid 2000); reachability from an unprivileged app was [demonstrated / not established]" |
| "The app implements pinning" | "A `CertificatePinner` is present; interception with a user-store CA succeeded, so it is not applied to this client" |
| "Coverage: 67%" | "Component coverage 50% (2 of 4) against the manifest inventory; these 2 were not reached: …" |
| "We bypassed the root check" | "The control was defeated at seam N; the server does not re-verify, so the protected asset is exposed" |
| "Private storage was clean" | "Private storage was **not captured**: the package is not debuggable and the device is not rooted" |

---

## Never

- Never `logcat -c` on someone's daily driver.
- Never claim reachability from an `adb shell` command.
- Never claim anything about trust stores without `mount | grep cacerts` first.
- Never report a coverage figure without naming the denominator's source.
- Never instrument, modify or bypass a third-party app you were not authorised to touch — observe.
- Never leave a proxy, a grant change, `am set-debug-app`, a pushed binary or an `adb reverse` behind.
- Never report a delta you did not compare against a control run.
- Never write "no issues found".
