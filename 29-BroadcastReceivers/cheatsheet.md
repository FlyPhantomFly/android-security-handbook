# 29 — Broadcast Receivers — Cheat Sheet

Measured values are from a **Redmi `M2101K6P`, Android 11 / API 30**, rooted, frida-server 16.1.6.

---

## Enumeration

| Goal | Command |
|---|---|
| Device facts (always first) | `adb shell getprop ro.build.version.sdk; adb shell getprop ro.build.version.release` |
| **Runtime** receivers, whole device | `adb shell dumpsys activity broadcasts` |
| Runtime receivers, parsed | `python3 scripts/receiver-surface.py` |
| One package | `python3 scripts/receiver-surface.py --package com.example.target` |
| Only third-party, only unguarded | `python3 scripts/receiver-surface.py --third-party --unprotected` |
| Who listens for one action, now | `python3 scripts/receiver-surface.py --action android.intent.action.SCREEN_ON` |
| **Runtime-only** actions (the gap) | `python3 scripts/receiver-surface.py --third-party --runtime-only` |
| **Static** receivers for an action | `adb shell cmd package query-receivers --brief -a <ACTION>` |
| Static receivers of one package | `adb shell dumpsys package <pkg>` then read `Receiver Resolver Table` |
| Broadcast history + senders + extras | `python3 scripts/receiver-surface.py --history --with-extras` |
| Raw history | `adb shell dumpsys activity broadcasts \| sed -n '/Historical broadcasts/,$p'` |
| Queue timeouts on this device | `adb shell dumpsys activity broadcasts \| grep -A6 bcast_fg_constants` |
| Offline analysis | `adb shell dumpsys activity broadcasts > bc.txt; python3 scripts/receiver-surface.py --dumpsys-file bc.txt` |

---

## Protected broadcasts

| Goal | Command |
|---|---|
| Platform's static list | `bash scripts/protected-broadcast-map.sh` |
| One action | `bash scripts/protected-broadcast-map.sh --is android.intent.action.BOOT_COMPLETED` |
| Classify a list | `bash scripts/protected-broadcast-map.sh --check actions.txt` |
| Ask the platform (SENDS) | `bash scripts/protected-broadcast-map.sh --check actions.txt --verify --i-will-send` |
| Manual probe | `adb shell "am broadcast -a <ACTION>"` |
| Raw list from framework-res | `adb pull /system/framework/framework-res.apk f.apk && aapt2 dump xmltree --file AndroidManifest.xml f.apk \| grep -A2 protected-broadcast` |

**Reading the probe result**

| Output | Meaning |
|---|---|
| `SecurityException: Permission Denial: not allowed to send broadcast X from pid=N, uid=2000` | **Protected.** AMS refused. No app can forge it. |
| `Broadcast completed: result=N` | **Forgeable.** Any app can send it. |
| `...from unknown caller.` | A **different** check (e.g. `AppWidgetService`), not the AMS protected list. |

**Measured PROTECTED (uid 2000 refused):** `BOOT_COMPLETED` · `PACKAGE_ADDED` · `AIRPLANE_MODE` ·
`CONNECTIVITY_CHANGE` · `BATTERY_LOW` · `SCREEN_ON` · `USER_PRESENT` · `MY_PACKAGE_REPLACED` ·
`MEDIA_MOUNTED` · `SMS_RECEIVED` · `HEADSET_PLUG` · `LOCALE_CHANGED` · `ACL_CONNECTED` ·
`SIM_STATE_CHANGED` · `android.net.wifi.STATE_CHANGE` · `DREAMING_STARTED`

**Measured FORGEABLE (delivered):** `com.android.vending.INSTALL_REFERRER` ·
`com.google.android.c2dm.intent.RECEIVE` · `android.intent.action.PROVIDER_CHANGED` ·
`android.intent.action.MEDIA_SCANNER_SCAN_FILE` · every custom action

**Counts:** 532 distinct `<protected-broadcast>` in `framework-res.apk` on the measured device.

---

## Sending

| Goal | Command |
|---|---|
| Implicit | `adb shell "am broadcast -a com.example.ACTION"` |
| Targeted (escapes API 26 limits) | `adb shell "am broadcast -a com.example.ACTION -p com.example.target"` |
| Explicit — bypasses the filter | `adb shell "am broadcast -n com.example.target/.Recv"` |
| With extras | `--es k v` `--ei k 1` `--el k 1` `--ez k true` `--ef k 1.5` `--esa k a,b` `--eia k 1,2` `--eu k content://x` |
| Receiver permission | `--receiver-permission android.permission.INTERNET` |
| Raw flags | `-f 0x20` (include stopped packages) |
| As a user | `--user 0` |

> `am broadcast` sends an **ORDERED** broadcast (measured: `ordered=true`). `am broadcast --help`
> throws `IllegalArgumentException: Unknown option: --help`; use `adb shell am help`.

---

## Frida

```bash
frida -U -f com.example.target -l scripts/hook-broadcast.js
```

| REPL call | What it gives you |
|---|---|
| `bc.watch()` | registrations + deliveries + sends + ordered controls |
| `bc.registrations()` | **class name**, filter, priority, export state — none of which `dumpsys` has |
| `bc.deliveries()` | every `onReceive`, via the dispatcher, incl. unloaded classes |
| `bc.sends()` | `sendBroadcast*` with the `receiverPermission` argument |
| `bc.ordered()` | `abortBroadcast` / `setResultCode` / `setResultData` / `goAsync` |
| `bc.sticky()` | sticky sends and retained Intents |
| `bc.local()` | `LocalBroadcastManager`, if bundled |
| `bc.senderProbe()` | proves `Binder.getCallingUid()` is 1000, not the sender |
| `bc.stacks(true)` | add Java stack traces |
| `bc.summary()` | table of everything seen |

---

## `dumpsys activity broadcasts` record format

```
* ReceiverList{<hash> <pid> <process>/<uid>/u<userId> local|remote:<hash>}
  app=<pid>:<process>/<uidName> pid=<pid> uid=<uid> user=<userId>
  Filter #0: BroadcastFilter{<hash>}
    Action: "..."
    Category: "..."
    Scheme: "..."
    requiredPermission=<permission>      <-- absent means ANY app can send
```

```
Historical Broadcast <queue> #N:
  BroadcastRecord{<hash> u<user> <action>} to user <n>
  Intent { act=<action> flg=0x... (has extras) }
    extras: Bundle[{...}]                <-- CLEARTEXT
  caller=<pkg> <pid>:<proc>/<uid> pid=<pid> uid=<uid>   <-- the ONLY sender attribution
  resultTo=... resultCode=N resultData=...
  resultAbort=<bool> ordered=<bool> sticky=<bool> initialSticky=<bool>
  Deliver +Nms #k: BroadcastFilter{...}
```

| Section | Contains |
|---|---|
| `Registered Receivers:` | Every runtime registration |
| `Receiver Resolver Table:` | The same filters indexed by scheme / MIME type |
| `Broadcast parameters (key=bcast_fg_constants)` | Foreground queue tuning |
| `Historical broadcasts [foreground]` / `[background]` | 50 records per queue |
| `Historical broadcasts summary` | One-line-per-record form, with extras |

**Absent from the dump:** the receiver's **class name**, and any **export flag** below API 33.

---

## API / registration matrix

| Overload | Since | Below API 33 | API 33+, `targetSdk` 33+ |
|---|---|---|---|
| `registerReceiver(r, f)` | 1 | **EXPORTED** | throws for non-system actions |
| `registerReceiver(r, f, flags)` | 26 | exported (flag bits absent) | must be `RECEIVER_EXPORTED` or `RECEIVER_NOT_EXPORTED` |
| `registerReceiver(r, f, perm, handler)` | 1 | guarded by `perm` | guarded, plus flag required |
| `registerReceiver(r, f, perm, handler, flags)` | 26 | guarded | guarded + explicit export |

| Constant | Value |
|---|---|
| `Context.RECEIVER_VISIBLE_TO_INSTANT_APPS` | `0x1` |
| `Context.RECEIVER_EXPORTED` | `0x2` |
| `Context.RECEIVER_NOT_EXPORTED` | `0x4` |

**AndroidX pre-33 backport of `NOT_EXPORTED`:** a self-defined signature permission named
`<package>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`. Seeing it is a **positive**.
Measured: 119 filters across 3 packages on one device.

---

## Intent flags for broadcasts

| Flag | Value | Effect |
|---|---|---|
| `FLAG_RECEIVER_REGISTERED_ONLY` | `0x40000000` | manifest receivers skipped |
| `FLAG_RECEIVER_NO_ABORT` | `0x08000000` | ordered, but `abortBroadcast()` ignored |
| `FLAG_RECEIVER_FOREGROUND` | `0x10000000` | foreground queue, 10 s timeout |
| `FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS` | `0x00200000` | instant apps may receive |
| `FLAG_EXCLUDE_STOPPED_PACKAGES` | `0x00000010` | default for system broadcasts |
| `FLAG_INCLUDE_STOPPED_PACKAGES` | `0x00000020` | **wakes dormant apps** |

Worked example: `flg=0x50200010` = `REGISTERED_ONLY` + `FOREGROUND` + `VISIBLE_TO_INSTANT_APPS`
+ `EXCLUDE_STOPPED_PACKAGES`.

---

## Queue constants (measured)

| Constant | foreground | background |
|---|---|---|
| `bcast_timeout` | **10 s** | **60 s** |
| `bcast_slow_time` | 5 s | 5 s |
| `bcast_deferral` | 5 s | 5 s |
| `bcast_deferral_decay_factor` | 0.75 | 0.75 |
| `bcast_allow_bg_activity_start_timeout` | 10 s | 10 s |

Timeouts apply to **ordered** broadcasts only.

---

## The two permission checks

| | Set by | Checked against | Stops | In the manifest? |
|---|---|---|---|---|
| `sendBroadcast(i, receiverPermission)` | sender | every receiver | **eavesdropping** | **No** |
| `<receiver android:permission>` / `registerReceiver(..., broadcastPermission, ...)` | receiver | the sender | **forgery** | manifest: yes; runtime: only as `requiredPermission=` in `dumpsys` |

Both are enforced in `BroadcastQueue.deliverToRegisteredReceiverLocked()`.
Neither means anything unless `protectionLevel="signature"`.

---

## Ordered broadcasts

```java
sendOrderedBroadcast(intent, receiverPermission, resultReceiver, scheduler,
                     initialCode, initialData, initialExtras);
```

| Inside `onReceive` | Effect |
|---|---|
| `getResultCode()` / `getResultData()` / `getResultExtras(false)` | read what earlier receivers left |
| `setResultCode()` / `setResultData()` / `setResultExtras()` | change what later receivers, and the **sender**, see |
| `abortBroadcast()` | stop the chain; nobody downstream is told |
| `clearAbortBroadcast()` | undo an earlier abort |
| `goAsync()` | extend past `onReceive` — **must** call `PendingResult.finish()` |

Priority: `<intent-filter android:priority="N">` or `filter.setPriority(N)`.
Higher first. Above 1000 is documented as reserved for the system; nothing enforces it.
Measured in the wild: `priority=2147483647` on `BOOT_COMPLETED`.

---

## Static analysis greps

```bash
# runtime registrations — the manifest does not have these
grep -rn "registerReceiver" out/sources/
grep -rnE "registerReceiver\s*\([^,]+,\s*[^,)]+\)" out/sources/       # 2-arg == exported pre-33
grep -rn "RECEIVER_NOT_EXPORTED\|ContextCompat.registerReceiver" out/sources/

# smali — survives obfuscation; action strings cannot be renamed
grep -rn "registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)" work/smali*/
grep -rn -B2 "IntentFilter;-><init>(Ljava/lang/String;)V" work/smali*/ | grep const-string

# interception primitives
grep -rn "setPriority" out/sources/
grep -rn "abortBroadcast\|setResultData\|setResultExtras" out/sources/

# leaks
grep -rn "sendBroadcast(" out/sources/ | grep -v "setPackage\|LocalBroadcast"
grep -rn "sendStickyBroadcast\|BROADCAST_STICKY" out/sources/ work/AndroidManifest.xml

# receivers with no action check
for f in $(grep -rl "extends BroadcastReceiver" out/sources/); do
  grep -q "getAction" "$f" || echo "NO ACTION CHECK: $f"; done
```

---

## Severity rubric

| Situation | Severity |
|---|---|
| Exported receiver, protected action only, action checked | Informational |
| Forgeable action, `onReceive` only logs | Low |
| Forgeable action, transient in-memory change | Low / Medium |
| Forgeable action persists attacker data used later | **High** |
| Forgeable action triggers a real-world effect (payment, wipe, send) | **High / Critical** |
| Token leaked via `setResultData` on an ordered broadcast | **High** |
| Sticky broadcast carrying anything sensitive | **High** |

**Not a finding on its own:** an exported receiver. On the measured device 1,227 of 1,438
runtime filters had no protection at all.

---

## Measured device numbers (one snapshot)

| Metric | Value |
|---|---|
| `ReceiverList` registrations | 1,281 |
| `IntentFilter`s across them | 1,438 |
| Action strings (with duplicates) | 2,868 |
| Distinct action strings | 800 |
| Filters with a sender permission | 211 (36 of them the AndroidX shim) |
| Filters with **no** sender permission | 1,227 |
| Third-party registrations | 472 (364 with an unguarded filter) |
| **Third-party actions that are runtime-only** | **299 of 431** |
| Static receivers for `BOOT_COMPLETED` | 214, top priority `2147483647` |
| `<protected-broadcast>` in `framework-res.apk` | 532 distinct |

A snapshot minutes earlier on the same idle device read 1,151 / 1,306 / 2,677.
**The surface is live. Quote it with a timestamp.**

---

## Quick decision tree

```
Found a receiver?
 |- In the manifest?  -> 32-Manifest audits the declaration
 |- Runtime only?     -> receiver-surface.py found it; hook to get the class name
 v
Which actions?
 |- Protected on THIS device?  -> not forgeable -> informational, stop
 |- Forgeable?                 -> continue
 v
Guarded by a permission?
 |- signature  -> not reachable, stop
 |- normal     -> add <uses-permission>, continue
 |- none       -> continue
 v
Send it FROM AN APP (not adb shell)
 v
Did observable state change?
 |- no   -> Low / informational
 |- yes, transient   -> Low / Medium
 |- yes, persistent  -> HIGH.  Now write the fix.
```
