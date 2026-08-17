# 30 — Activities: Cheat Sheet

Dense reference. Prose is in [README.md](README.md).
Every line marked **M** was measured on a Redmi M2101K6P, Android 11 / API 30, MIUI 12.5.

---

## Launch modes

| Mode | int in `dumpsys` | New instance? | Which task | Clears above? |
|---|---|---|---|---|
| `standard` | 0 | always | caller's | no |
| `singleTop` | 1 | only if **not already at the top** of the target task | caller's | no |
| `singleTask` | 2 | only if none exists in the affinity group | the affinity-matching task (**not always a new one — M**) | **yes** |
| `singleInstance` | 3 | only if none exists | **its own, alone, forever** | n/a |
| `singleInstancePerTask` | 4 (API 31+) | one per task | per task | yes, within the task |

| Measured behaviour | Result |
|---|---|
| `standard` x3 | 3 instances, 1 task, `sz=4` **M** |
| `singleTop` on top x3 | 1 instance, 2 x `onNewIntent` **M** |
| `singleTop` after something stacked above | **new instance; two coexist** **M** |
| `singleTask` re-entered | `onNewIntent`, same instance, `sz` 4 → 3 **M** |
| `singleInstance` then a `standard` start | standard goes to the *other* task **M** |

---

## `taskAffinity`

| Fact | Value |
|---|---|
| Default | the **package name** |
| Hardening | `android:taskAffinity=""` → shows as `taskAffinity=null` **M** |
| Runtime form on API 30 | `<uid>:<declared>` e.g. `10196:com.android.chrome` **M** |
| Set on `<application>` | inherited by every `<activity>` |
| Consulted when | a task is **chosen or created** only |
| NOT consulted when | `standard`/`singleTop` started from an Activity with no flags |

```xml
<application android:taskAffinity="">   <!-- the one-line app-wide hardening -->
```

---

## Task-affecting `FLAG_ACTIVITY_*`

| Flag | Hex | Effect |
|---|---|---|
| `NEW_TASK` | `0x10000000` | choose/create a task by affinity; **without it the callee joins the caller's task** |
| `MULTIPLE_TASK` | `0x08000000` | with NEW_TASK, always make a fresh task |
| `CLEAR_TOP` | `0x04000000` | destroy everything above an existing instance |
| `SINGLE_TOP` | `0x20000000` | force singleTop behaviour → forces `onNewIntent` |
| `CLEAR_TASK` | `0x00008000` | empty the target task first |
| `REORDER_TO_FRONT` | `0x00020000` | move an instance up without destroying |
| `NO_HISTORY` | `0x40000000` | do not retain in the stack |
| `TASK_ON_HOME` | `0x00004000` | Back goes to the launcher |
| `LAUNCH_ADJACENT` | `0x00001000` | split-screen |
| `RETAIN_IN_RECENTS` | `0x00002000` | keep in Recents after finishing |
| `EXCLUDE_FROM_RECENTS` | `0x00800000` | hide the task from Recents |
| `FORWARD_RESULT` | `0x02000000` | **result goes to the caller's caller** |
| `GRANT_READ_URI_PERMISSION` | `0x00000001` | issue a read grant |
| `GRANT_WRITE_URI_PERMISSION` | `0x00000002` | issue a write grant |
| `GRANT_PERSISTABLE_URI_PERMISSION` | `0x00000040` | grant may be persisted |
| `GRANT_PREFIX_URI_PERMISSION` | `0x00000080` | grant applies beneath the path |

---

## Caller identity

| Mechanism | Tier | Trustworthy | Available |
|---|---|---|---|
| `Binder.getCallingUid()` in a Service transaction | 1 kernel | **yes** | Service only |
| `getCallingActivity()` / `getCallingPackage()` | 2 system | yes | **only after `startActivityForResult`** |
| `PendingIntent.getCreatorPackage()` | 2 system | yes | PendingIntent receiver |
| `getLaunchedFromPackage()` / `getLaunchedFromUid()` | 2 system | yes | **API 34+** |
| `getReferrer()` / `EXTRA_REFERRER` | 3 message | **no** | any |
| any extra | 3 message | **no** | any |
| `Binder.getCallingUid()` in `onCreate` | — | **returns your own uid** **M** | any |

---

## `dumpsys` field map

| Field | Meaning |
|---|---|
| `Task{<hash> #<id> ... A=<affinity> ... sz=<n>}` | task header; `A=` absent → no affinity |
| `affinity=` / `rootAffinity=` | the task's effective affinity |
| `Hist #n` | one Activity; `#0` is the root |
| `taskAffinity=` on a `Hist` line | that Activity's effective affinity |
| `launchMode=` | resolved launch mode, as an int |
| `launchedFromUid` / `launchedFromPackage` | **who started it** — best attribution field |
| `realActivity=` | the component the task resolves to from Recents |
| `mNeverRelinquishIdentity` | inverse of `relinquishTaskIdentity` |
| `ResumedActivity:` | what is on screen |

> The dump prints the whole graph **twice** (per display, then a summary). Key by task id.

---

## Commands

```bash
# --- the task graph -------------------------------------------------------
adb shell "dumpsys activity activities" | grep -E "^\s+\* Task\{"     # tasks
adb shell "dumpsys activity activities" | grep -E "Hist #"            # stacks
adb shell "dumpsys activity activities" | grep -E "taskAffinity=|affinity=" | sort -u
adb shell "dumpsys activity activities" | grep -E "launchedFrom"      # attribution
adb shell "dumpsys activity activities" | grep -E "ResumedActivity"   # on screen
adb shell "dumpsys activity recents"                                  # dead processes
adb shell "dumpsys activity starter"

# --- this chapter's tools -------------------------------------------------
python3 -B scripts/task-affinity-map.py                  # full report
python3 -B scripts/task-affinity-map.py --check          # namespacing verdict only
python3 -B scripts/task-affinity-map.py --recents --json
python3 -B scripts/task-affinity-map.py -p com.example.target
frida -U -f com.example.target -l scripts/activity-trace.js

# --- starting things ------------------------------------------------------
adb shell "am start -n pkg/.Activity"
adb shell "am start -W -n pkg/.Activity"                  # wait, print result
adb shell "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d 'https://x/y'"
adb shell "am start -n pkg/.A --es k v --ei n 42 --ez b true --eu u 'content://x/y'"
adb shell "am start -f 0x10000000 -n pkg/.A"              # NEW_TASK
adb shell "am start --activity-clear-top    -n pkg/.A"
adb shell "am start --activity-single-top   -n pkg/.A"    # forces onNewIntent
adb shell "am start --activity-no-history   -n pkg/.A"
adb shell "am stack list"                                 # where available

# --- windows / overlays ---------------------------------------------------
adb shell "cmd appops query-op SYSTEM_ALERT_WINDOW allow"
adb shell "appops get <pkg> SYSTEM_ALERT_WINDOW"
adb shell "su -c 'appops set <pkg> SYSTEM_ALERT_WINDOW allow'"   # device you own
adb shell "dumpsys window windows" | grep -E "Window\{|mOwnerUid"
adb shell "dumpsys window | grep mCurrentFocus"
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"

# --- static ---------------------------------------------------------------
aapt2 dump xmltree --file AndroidManifest.xml t.apk | grep -E 'E: activity|launchMode|taskAffinity|exported'
apktool d -f -o work t.apk
grep -n 'android:taskAffinity=""' work/AndroidManifest.xml
grep -rn --include='*.smali' -A6 'Intent;->getParcelableExtra' work/smali* | grep -A5 'check-cast .*Intent;'
grep -rn "setFilterTouchesWhenObscured\|FLAG_SECURE" out/sources/
```

---

## `am start` — three limits

| Limit | Consequence | Escape |
|---|---|---|
| runs in the shell process, no task | **always implies `FLAG_ACTIVITY_NEW_TASK`** | a real Activity (`CrossStartActivity`) |
| no `--eparcelable` | Parcelable intent-redirection is invisible to it | a real app (`DeputyExploitActivity`) |
| runs as uid 2000 (privileged) | reachability from `am` ≠ reachability from an app | repeat from an unprivileged app |

---

## Attack quick-reference

| Attack | Needs | Mitigated by | Measured on API 30 |
|---|---|---|---|
| Task hijack (`taskAffinity` + `singleTask`) | malware installed | uid-namespaced affinities; `taskAffinity=""` | **FAILS** **M** |
| Task hijack (`allowTaskReparenting`) | malware installed | same | **FAILS** **M** |
| Mixed-package task (no `NEW_TASK`) | malware installed; victim Activity exported | `singleTask` on the victim screen; do not export | **WORKS** **M** |
| Confused deputy — reachability | any app; deputy exported | selector, not Intent | **WORKS** **M** |
| Grant laundering | any app; deputy + `grantUriPermissions="true"` | selector; API 35 `requireContentUriPermissionFromCaller` | **WORKS** **M** |
| Tapjacking | `SYSTEM_ALERT_WINDOW` granted | `filterTouchesWhenObscured` | not executed (device locked) |
| Result-channel abuse | attacker wins resolution of an implicit outbound Intent | explicit Intent + signature pin + validate | documented |

---

## Defences, one line each

```xml
<application android:taskAffinity="">                       <!-- no affinity to squat -->
<activity android:launchMode="singleTask"/>                 <!-- cannot be pulled into a foreign task -->
<activity android:exported="false"/>                        <!-- not an entry point -->
<activity android:permission="...signature level..."/>      <!-- system_server enforces it -->
<activity android:requireContentUriPermissionFromCaller="read"/>   <!-- API 35: kills laundering -->
<Button android:filterTouchesWhenObscured="true"/>          <!-- discard obscured taps -->
```

```java
getWindow().setFlags(FLAG_SECURE, FLAG_SECURE);        // BEFORE setContentView
view.setFilterTouchesWhenObscured(true);               // per view, incl. dialogs
setIntent(intent);                                     // first line of onNewIntent
String dest = getIntent().getStringExtra("dest");      // selector, never an Intent
```

---

## Severity anchors

| Finding | Rating | Precondition to state in the title |
|---|---|---|
| Deputy launders grants on a token-bearing provider | High | "any installed app" |
| Deputy reachable from a browsable deep link | High | **no installed app needed** |
| No `taskAffinity=""`, devices measured NOT namespacing | Medium | "requires malicious app" |
| No `taskAffinity=""`, devices measured namespacing | Low / Info | "mitigated on tested devices" |
| Consent screen, no obscured-touch filtering, money button | Medium | "requires SYSTEM_ALERT_WINDOW grant" |
| Mixed-package task, victim shows account data | Medium | "requires malicious app" |
| Exported Activity, no demonstrated consequence | Info | say what would raise it |

---

## Gotchas

- `onNewIntent` does **not** update `getIntent()`. Call `setIntent()`.
- `singleTop` allows **two** instances in one task.
- `singleTask` does **not** always create a task; it **does** destroy everything above it.
- `getPackage()` is `null` on an Intent that only sets a `ComponentName`.
- `FLAG_GRANT_*` applies to `getData()` and `getClipData()` — not to extras.
- A null cursor on API 30+ usually means **package visibility**, not a missing provider. **M**
- `appops` grants are **reset by reinstall**. **M**
- `<activity-alias>` has its **own** `exported` and `permission`.
- `FLAG_SECURE` must be set **before** `setContentView`.
- `excludeFromRecents` does **not** stop the task snapshot; `FLAG_SECURE` does.
- On a **locked** device an app is `TPSL` (top-sleeping) and counts as background — `startService` is refused, even via root. **M**
- `INSTALL_FAILED_USER_RESTRICTED` is an OEM gate, not a bad APK. Root: `su -c 'pm install -r ...'`. **M**
