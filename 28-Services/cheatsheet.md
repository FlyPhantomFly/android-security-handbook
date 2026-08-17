# 28 — Services — Cheat Sheet

Printable. Tables and commands only. Everything marked **M** was measured on a
Redmi `M2101K6P`, Android 11 / API 30; everything else is documented.

---

## The three shapes

| | Started | Bound | Foreground |
|---|---|---|---|
| Entry | `startService()` / `startForegroundService()` | `bindService()` | `startForeground()` on a started service |
| Callback | `onStartCommand(intent, flags, startId)` | `onBind(intent)` → `IBinder` | same object |
| Channel back | none | direct Binder handle | none |
| Lifetime | until `stopSelf`/`stopService` | while ≥1 client bound | while started |
| Caller identity available | **no** | **no** in `onBind`, **yes** in `Stub` methods | no |

Both claims must be released before `onDestroy` runs.

## `onStartCommand` return values

| Constant | Value | After a kill | Intent |
|---|---|---|---|
| `START_STICKY_COMPATIBILITY` | 0 | recreated, no guarantee `onStartCommand` runs | n/a |
| `START_STICKY` | 1 | recreated, `onStartCommand` called | **null** |
| `START_NOT_STICKY` | 2 | not recreated | n/a |
| `START_REDELIVER_INTENT` | 3 | recreated, `flags` has `START_FLAG_REDELIVERY` | the original |

## `bindService` flags

| Flag | Hex | Effect |
|---|---|---|
| `BIND_AUTO_CREATE` | `0x0001` | create if absent. **Without it, nothing happens** |
| `BIND_DEBUG_UNBIND` | `0x0002` | keep a bind stack trace |
| `BIND_NOT_FOREGROUND` | `0x0004` | no foreground scheduling bump |
| `BIND_ABOVE_CLIENT` | `0x0008` | service more important than client |
| `BIND_ALLOW_OOM_MANAGEMENT` | `0x0010` | killable as if unbound |
| `BIND_WAIVE_PRIORITY` | `0x0020` | do not affect priority |
| `BIND_IMPORTANT` | `0x0040` | client cannot function without it |
| `BIND_ADJUST_WITH_ACTIVITY` | `0x0080` | importance follows the Activity |
| `BIND_NOT_PERCEPTIBLE` | `0x0100` | API 29+, lower band |
| `BIND_INCLUDE_CAPABILITIES` | `0x1000` | API 29+, **pass while-in-use location/camera/mic through** |
| `BIND_EXTERNAL_SERVICE` | `0x80000000` | run under the **client's** uid |

## `<service>` attributes

| Attribute | Default | Tester note |
|---|---|---|
| `android:exported` | `true` if `<intent-filter>` present, else `false` | mandatory from API 31 with a filter |
| `android:permission` | none | **check the protection level**, not the name |
| `android:process` | app main | **not** a security boundary |
| `android:isolatedProcess` | `false` | positive finding |
| `android:externalService` | `false` | runs as the client |
| `android:useAppZygote` | `false` | isolated uid moves to 90000–98999 |
| `android:foregroundServiceType` | none | mandatory for `targetSdk` 34+ |
| `android:directBootAware` | `false` | reachable before first unlock |
| `android:enabled` | `true` | flippable at runtime |
| `android:stopWithTask` | `true` for most | `false` = survives task swipe |

## Where identity is and is not available

| Location | `Binder.getCallingUid()` |
|---|---|
| `onCreate`, `onBind`, `onStartCommand`, `onUnbind`, `onRebind`, `onDestroy` | **your own uid** — useless **M** |
| An AIDL `Stub` method | **the real caller** **M** |
| An `onTransact` override | the real caller |
| A worker thread the method spawned | your own uid |
| `Handler.handleMessage` | your own uid — use `msg.sendingUid` instead |

## `bindService` outcomes

| Return | Exception | `onServiceConnected` | Meaning |
|---|---|---|---|
| `true` | — | fires | reachable |
| `true` | — | **never** | `onBind` returned null (`onNullBinding` API 28+) **M** |
| `false` | `SecurityException` | never | not exported, or permission not held **M** |
| `false` | **none** | never | **package visibility** (API 30+, `targetSdk` 30+) **M** |

## Transaction codes

| Code | Meaning |
|---|---|
| `1 .. N` | methods in `.aidl` declaration order, from `FIRST_CALL_TRANSACTION` = 1 |
| `1598968902` | `'_NTF'` `INTERFACE_TRANSACTION` — `getInterfaceDescriptor()` |
| `1598311760` | `'_DMP'` `DUMP_TRANSACTION` |
| `1598246212` | `'_CMD'` `SHELL_COMMAND_TRANSACTION` |
| `1599098439` | `'_PNG'` `PING_TRANSACTION` |

## Reading an empty-parcel probe

| Result | Meaning |
|---|---|
| `ok=true`, `SecurityException: Binder invocation to an incorrect interface` | AIDL `Stub`; write the descriptor and retry |
| `ok=false`, empty reply | raw `Binder`, code unhandled; keep sweeping |
| `ok=true`, reply, no exception | the method ran with no token and no arguments |
| descriptor `''` | raw `Binder`; **no token enforced at all** |

## AIDL vs Messenger vs local Binder

| | local `Binder` | `Messenger` | AIDL |
|---|---|---|---|
| Cross-process | raw `transact` only | yes | yes |
| Typed | same process only | no | yes |
| Sync return | same process only | **no** | yes |
| Threading | caller's | **one Handler thread** | **Binder pool, concurrent** |
| Reentrant | n/a | no | **yes** |
| Identity | `onTransact` | `msg.sendingUid` | per method |
| Reply redirectable | n/a | **yes, `msg.replyTo`** | no |

## Version matrix

| API | Change | Status |
|---|---|---|
| 21 | `Message.sendingUid` populated | D |
| 26 | background `startService` throws; `startForegroundService` + **5 s** deadline | D |
| 28 | `FOREGROUND_SERVICE` permission; `onNullBinding` | D |
| 29 | `foregroundServiceType`; `BIND_INCLUDE_CAPABILITIES`; App Zygote | **M** (uids 90000) |
| 30 | `camera`/`microphone` types; **package visibility** | **M** |
| 30 | `dumpsys activity services` prints **no** `foregroundServiceType` | **M** |
| 31 | explicit `android:exported` mandatory; no background FGS start | D |
| 33 | FGS notifications user-dismissible | D |
| 34 | `foregroundServiceType` **mandatory**, per-type permissions, `shortService` | D |

## Isolated process — measured

```text
 4550 u0_i0     u:r:isolated_app:s0:c512,c768  com.android.chrome:sandboxed_process0
11259 u0_i9003  u:r:isolated_app:s0:c512,c768  com.google.android.webview:sandboxed_process0
Uid: 90000   (App Zygote)      Uid: 99003 / 99046   (ordinary isolated)
Groups:      (empty -- hence no AID_INET, hence no network)
```

## Commands — enumeration

```bash
# adb shell
dumpsys activity services                          # every running service
dumpsys activity services com.example.app
dumpsys activity processes                         # oom_adj bands
dumpsys jobscheduler
dumpsys accessibility
settings get secure enabled_accessibility_services
settings get secure enabled_notification_listeners

dumpsys package r | sed -n '/Service Resolver Table:/,/Provider Resolver Table:/p'
pm query-services -a android.accessibilityservice.AccessibilityService
pm query-services -n com.example.app/.SyncService
pm list permissions -f -g | grep -A4 "permission:com.example.permission.SYNC"
```

## Commands — driving

```bash
# adb shell
am start-service            -n com.example.app/.SyncService --es job x
am start-foreground-service -n com.example.app/.SyncService
am stop-service             -n com.example.app/.SyncService
am kill com.example.app                     # force the START_STICKY path
```

There is **no** `am bind-service`. Binding needs an app.

## Commands — this chapter's tools

```bash
# host
python3 scripts/service-recon.py                 # rank everything
python3 scripts/service-recon.py --open --weak
python3 scripts/service-recon.py --explain com.example.app/.SyncService
python3 scripts/service-recon.py --capture ./snap && python3 scripts/service-recon.py --fixture ./snap

sh examples/attacker-app/build.sh install
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
    --es targets 'pkg/cls,pkg/cls' --es tokencodes '1+3'
adb logcat -d -s CH28

frida -U -n com.example.app -l scripts/trace-service-lifecycle.js --runtime=v8
```

## Greps

```bash
# host, over a jadx dump
grep -rln "extends Service\b" out/sources/
grep -rn  "extends .*\.Stub\b" out/sources/

# services with a Binder interface and NO caller check anywhere -- the finding list
grep -rln "extends .*\.Stub\b" out/sources/ > /tmp/s
grep -rln "getCallingUid\|checkCallingPermission\|checkSignatures\|hasSigningCertificate" out/sources/ > /tmp/c
comm -23 <(sort /tmp/s) <(sort /tmp/c)

# the check in the wrong place
grep -rn -B8 "getCallingUid" out/sources/ | grep -E "onBind|onStartCommand|onCreate"

# Messenger
grep -rn "new Messenger(\|sendingUid\|replyTo" out/sources/

# accessibility capability
grep -rn "canPerformGestures\|canRetrieveWindowContent\|typeAllMask" out/res/xml/

# smali
grep -rl "^\.super Landroid/app/Service;" out/smali*/
```

## Severity rubric — stop at the first "no"

| # | Question |
|---|---|
| 1 | Does `onServiceConnected` fire from an unprivileged app? |
| 2 | Does the binder expose methods (descriptor, or a hand-written `onTransact`)? |
| 3 | Does any method do something the caller could not do itself? |
| 4 | Does that method lack a `getCallingUid`/`checkSignatures`/permission check? |
| 5 | Can you demonstrate the effect? |

Severity = severity of the **demonstrated effect**, never of the export.

## Measured device totals

| | |
|---|---|
| Services reachable by an intent action | 839 |
| OPEN (exported, no permission) | **325** across 94 packages |
| WEAK-PERM (`normal` permission) | **16**, five of them `android.permission.INTERNET` |
| DANGEROUS | 1 |
| SIGNATURE | 108 |
| SYSTEM-BIND (`BIND_*`, system only) | 76, of which 9 accessibility |
| NOT-EXPORTED | 287 |
| DISABLED | 24 |

## Gotchas

| Symptom | Cause |
|---|---|
| `bindService` false, silent | package visibility |
| `bindService` true, no connection | `onBind` returned null |
| `am start-service` → `Error: app is in background` | API 26 background restriction, not a control |
| Service never restarts after a kill | OEM power manager (**M**: MIUI `AutoStartManagerService: Reject RestartService`) |
| App killed 5 s after `startForegroundService` | `startForeground` not called |
| `onDestroy` never runs after `stopSelf` | a client is still bound |
| NPE in `onStartCommand`, only in the field | `START_STICKY` null Intent |
| Duplicate entries in a `HashMap` in an AIDL impl | Binder pool concurrency |
| Frida script prints its banner and nothing else | QuickJS timers; use `--runtime=v8` |
| Target SIGSEGVs under Frida | do not hook `Handler.dispatchMessage`; use `Handler$MessengerImpl.send` |
| Frida hook makes the service stop answering | a Binder call from inside `execTransact` — reentrancy |
| `d8` NPE on `String.length()` | build-tools 34.0.0; use 35.0.1+ |
| `aidl` "directory src/ is not found" on Windows | pass backslash paths |
| `aapt2` "not well-formed (invalid token)" | a `--` inside an XML comment |
| `INSTALL_FAILED_USER_RESTRICTED` | OEM install restriction; `su -c 'pm install'` or enable Install via USB |
