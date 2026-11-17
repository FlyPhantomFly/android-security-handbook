# 29 — Broadcast Receivers — FAQ

Real questions, including the ones people are embarrassed to ask. Measured figures come
from a **Redmi `M2101K6P`, Android 11 / API 30**.

---

### 1. What is the difference between a broadcast and an Intent? They look like the same thing.

They are not the same *kind* of thing, and the confusion is entirely reasonable because the
API reuses one class for both.

An **`Intent` is a message object** — a bundle of fields: an action string, some data, a
type, categories, a component name, flags and extras. It is inert. It describes something
you want to happen.

A **broadcast is a delivery mode** — one of several ways to hand an `Intent` to the system.

The *same* `Intent` object, unchanged, behaves completely differently depending on which
method you pass it to:

```java
Intent i = new Intent("com.example.THING");
startActivity(i);     // delivered to exactly ONE component; the user sees a screen
startService(i);      // delivered to exactly ONE service
sendBroadcast(i);     // delivered to EVERY component whose filter matches
```

So: the Intent is the envelope and its contents. `startActivity` is posting it to one
address. `sendBroadcast` is stapling it to every notice board in the country.

[26-Intent](../26-Intent/README.md) owns the envelope — its twelve fields, how the system
decides which components match, and what happens when a hostile app controls one. This
chapter owns what happens once you choose the broadcast delivery mode.

---

### 2. Why does my receiver not fire?

Nine reasons, in the order they actually occur. Work down the list.

| # | Cause | How to confirm | Fix |
|---|---|---|---|
| 1 | **The action string does not match.** A typo, or the wrong case. | `adb shell dumpsys activity broadcasts \| grep "your.ACTION"` — if nothing, you are not registered for it | Copy-paste the string from one place to both |
| 2 | **API 26 implicit-broadcast limits.** A manifest receiver no longer gets most implicit broadcasts. | Is the broadcast implicit, and is your receiver in the manifest? | Register at runtime, or have the sender use `setPackage()` |
| 3 | **The app is in the "stopped" state.** Freshly installed and never opened, or force-stopped. `FLAG_EXCLUDE_STOPPED_PACKAGES` is the default for system broadcasts. | Open the app once, then retry | Nothing you can do as the receiver; the sender may set `FLAG_INCLUDE_STOPPED_PACKAGES` |
| 4 | **`FLAG_RECEIVER_REGISTERED_ONLY` on the broadcast.** Manifest receivers are skipped entirely. | Check `flg=` in the history: `0x40000000` set | Register at runtime instead |
| 5 | **A permission is blocking it.** Either you demanded one the sender lacks, or the sender demanded one you lack. | `dumpsys activity broadcasts` shows your `requiredPermission=`; check the sender's `receiverPermission` | Match them, or drop them |
| 6 | **A higher-priority receiver aborted the chain.** Ordered broadcasts only. | `resultAbort=true` in the history record | See question 12 |
| 7 | **The receiver was never registered** because the code path did not run, or it was unregistered in `onPause`. | Hook `registerReceiver` with `scripts/hook-broadcast.js` | — |
| 8 | **The component is disabled.** `setComponentEnabledSetting` overrides the manifest. | `adb shell dumpsys package <pkg> \| grep -i enabled` | `pm enable <pkg>/<class>` while testing |
| 9 | **`targetSdk 33+` and you passed no export flag.** The call throws at registration time. | Look for a `SecurityException` in logcat at startup, not at delivery | Pass `RECEIVER_EXPORTED` or `RECEIVER_NOT_EXPORTED` |

The single most useful debugging command:

```bash
# host — is the platform even aware of your registration?
adb shell "dumpsys activity broadcasts" | grep -B6 "your.ACTION"
```

If your process is not in that output, nothing about delivery matters yet.

---

### 3. Can I see who sent a broadcast?

**Not from inside `onReceive`. Yes, from `dumpsys`.**

Inside the receiver, the answer is no, and it is not a limitation you can engineer around.
Every broadcast is re-dispatched by `ActivityManagerService`, so the Binder transaction that
reaches your process comes *from `system_server`*. Measured, with Frida, inside a real app
on the device:

```
[senderProbe] Binder.getCallingUid() = 1000   <-- system_server, NOT the app that sent it
              Binder.getCallingPid() = 0
              Process.myUid()        = 10141   (this app)
```

uid 1000 is the system. The originating app's uid is nowhere in the delivery.

The sender *is* recorded, in exactly one place — AMS's broadcast history:

```bash
# host
adb shell "dumpsys activity broadcasts" | grep -A6 "your.ACTION"
```

```
BroadcastRecord{2439c45 u0 com.pentest.PROBE_EXTRAS} to user 0
Intent { act=com.pentest.PROBE_EXTRAS flg=0x400010 (has extras) }
  extras: Bundle[{n=42, token=SUPERSECRET123}]
caller=null null pid=9127 uid=2000
```

`uid=2000` is the sender — in that measurement, `adb shell`. Reading this requires shell,
root, or the `DUMP` permission (which is `signature|privileged`, so not available to an
ordinary app).

**The design consequence for developers:** if your receiver needs to know who called, a
broadcast is the wrong mechanism. Use a bound service, where
[Binder caller identity is unforgeable](../25-Binder/README.md) and directly available.

---

### 4. What is a sticky broadcast, and why is everyone rude about it?

A **sticky broadcast** is one that the system *keeps* after delivering it. Anyone who
registers a matching filter later — minutes later, in a process that did not exist at the
time — is immediately handed the retained `Intent` as the return value of
`registerReceiver()`.

```java
Intent last = registerReceiver(myReceiver, filter);
// non-null == a sticky broadcast was waiting for you
```

That sounds useful. "Late subscribers get the last known value" is a real problem and this
solves it.

The reason it is deprecated (since API 21) is that **a sticky broadcast cannot be
protected, structurally**. When it is replayed at registration time there is no sender any
more, so:

- `sendBroadcast(intent, receiverPermission)` cannot be enforced — there is nobody to
  enforce it on behalf of;
- `setPackage()` cannot constrain it — retention is global;
- the only way to remove it is `removeStickyBroadcast()` by the original sender, and by
  then anyone who wanted it has it.

So any value ever placed in a sticky broadcast is readable by every app on the device until
reboot. Sending one only needs `BROADCAST_STICKY`, which is `protectionLevel="normal"` —
granted automatically to anyone who asks.

There is a second, quieter problem: because the value arrives at *registration* time rather
than at *event* time, a receiver can be handed a stale value and mistake it for a fresh
event.

The surviving legitimate use is reading the platform's own retained battery state:

```java
// still works, still the idiom
Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
int level = battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
```

A null receiver, purely to harvest the sticky value.

No app-level sticky broadcasts were retained on the measured device, which is what you
should expect on a modern build. **Finding one in a target is itself worth reporting** — it
means a decade-old deprecated API is in use and nobody reviewed it.

---

### 5. Why did my implicit broadcast stop working on newer Android?

Because of **API 26 (Android 8.0)**, and there are two separate changes that get conflated.

**Change 1: implicit broadcasts no longer wake manifest-declared receivers.** If your
receiver is in `AndroidManifest.xml` and the broadcast is implicit — no `setPackage()`, no
`setComponent()` — it will not be delivered. Full stop, with a short exemption list.

**Change 2: background execution limits.** Even when a receiver does fire, what it can do
afterwards is constrained — it cannot freely start a background service, which is what most
receivers did with the broadcast.

Three ways out, in the order you should consider them:

| Route | How | When it is right |
|---|---|---|
| **Register at runtime** | `registerReceiver()` while the app is alive | The correct answer in most cases. Your app is running anyway. |
| **Make the broadcast explicit** | `intent.setPackage("com.example.target")` or `setComponent(...)` on the **sender's** side | When you control the sender and genuinely need to wake a stopped app. |
| **Use the exemption list** | `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED`, `MY_PACKAGE_REPLACED`, SMS/MMS delivery, `ACTION_NEW_OUTGOING_CALL`, `USB_ACCESSORY_ATTACHED`, `ACTION_LOCALE_CHANGED` and a few others still reach manifest receivers | When one of them happens to be the event you want. |
| **Use `WorkManager` / `JobScheduler`** | Constraints like "when the network returns" are first-class | Almost always better than a connectivity receiver. |

> **Security note.** The `setPackage()` escape is available to attackers too. "We target
> API 26+, so our manifest receivers are unreachable" is wrong: the limits removed
> *incidental* reachability from the whole device, not *deliberate* reachability from
> someone who knows your package name. Your package name is in the launcher.

---

### 6. What is the difference between a static and a dynamic receiver, in one sentence each?

- **Static (manifest-declared):** it is a fact about the APK, it is visible to every tool,
  and receiving a broadcast can start your process even if the user has never opened the
  app.
- **Dynamic (context-registered):** it exists only while your process does, it appears in
  no manifest and in no APK, and the only way to enumerate it is
  `dumpsys activity broadcasts`.

The security difference that matters: a static receiver has an `exported` attribute in the
manifest, so a reviewer can see it. A dynamic receiver, **below API 33, has no export
concept at all** — it is reachable by any app unless the developer supplied a
`broadcastPermission`.

---

### 7. Is an exported receiver a vulnerability?

**No.** It is a precondition.

On the measured device, out of 1,438 live runtime filters, **1,227 had no protection
whatsoever**. That is the normal state of an Android phone, not a list of 1,227
vulnerabilities.

Three things must be true before you have a finding:

1. **The action is forgeable on that device** — not a `<protected-broadcast>`. Check;
   do not assume. Measured forgeable and frequently assumed protected:
   `com.android.vending.INSTALL_REFERRER`, `com.google.android.c2dm.intent.RECEIVE`,
   `android.intent.action.PROVIDER_CHANGED`.
2. **You reached it from an unprivileged app** — not from `adb shell`, which runs at uid
   2000 and is more privileged than an app.
3. **Something observable changed.** A log line is not impact. A value written to
   `SharedPreferences` that the app uses on its next network call is.

Report the consequence. A report full of "exported component" entries is how a security
team learns to skim your reports.

---

### 8. What does `abortBroadcast()` actually do, and can I use it to block another app?

It stops an **ordered** broadcast from reaching any lower-priority receiver. Nobody
downstream receives it, and nobody is told why — from their perspective the broadcast
never happened.

Yes, you can use it against another app, subject to three conditions:

1. The broadcast must be **ordered**. `abortBroadcast()` on a parallel broadcast does
   nothing useful.
2. You must **register at a higher priority** than the target. Priority is a plain integer
   with no authorisation check; `Integer.MAX_VALUE` is a real value seen on a real device
   (measured: `priority=2147483647` on `BOOT_COMPLETED`, on a stock Android 11 build).
3. The sender must **not** have set `FLAG_RECEIVER_NO_ABORT` (`0x08000000`), and must not
   have required a `receiverPermission` you do not hold — you cannot intercept what you
   cannot receive.

The classic instance is SMS/OTP interception. That specific path is now restricted to the
default SMS app, but the pattern applies to any ordered broadcast between two ordinary
apps.

---

### 9. Does `am broadcast` behave like a real app sending a broadcast?

**No, in two ways that will mislead you.**

**It sends an ordered broadcast.** Measured: a plain `adb shell am broadcast -a X` produces
a history record reading `resultAbort=false ordered=true sticky=false initialSticky=false`,
and a Frida hook inside the receiving app confirmed `ordered=true` at delivery. An app
calling `sendBroadcast()` sends an *unordered* one. So `am broadcast` will show you
result-channel behaviour an ordinary app cannot trigger — and may miss behaviour that only
occurs on the parallel path.

**It runs as uid 2000 (shell), not as an app.** Shell holds capabilities no app has.
Measured on the same device: root (uid 0) successfully sent
`android.intent.action.LOCALE_CHANGED`, a protected broadcast, while uid 2000 was refused —
so the answer changes with privilege level.

The one thing you *can* rely on: because uid 2000 is *more* privileged than an app, a
refusal at uid 2000 means an app is refused too. A shell "denied" is a reliable
"protected".

Reproduce every finding from a real, permissionless app, or from drozer, whose agent is an
ordinary app.

---

### 10. How do I find receivers in an app that is obfuscated?

Do not grep for class names — they are gone. Grep for the things obfuscation cannot touch.

**Action strings survive, always.** They are protocol values; both ends must agree on them,
so R8 cannot rename them.

```bash
# host — every action string handed to an IntentFilter constructor
grep -rn -B2 "IntentFilter;-><init>(Ljava/lang/String;)V" work/smali*/ | grep const-string
```

**Framework call sites survive.** `registerReceiver`, `sendBroadcast` and `abortBroadcast`
are resolved by name against `android.jar`.

```bash
# host
grep -rn "registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)" work/smali*/
```

**And the platform's own bookkeeping is completely obfuscation-proof**, because the app has
to register with AMS to receive anything at all:

```bash
# host
python3 scripts/receiver-surface.py --package com.example.target
frida -U -f com.example.target -l scripts/hook-broadcast.js     # then bc.watch()
```

A packed or dynamically-loaded app cannot hide from these two.

---

### 11. Why can I not just grep for `extends BroadcastReceiver`?

Because a large fraction of real receivers are **anonymous inner classes**, which do not
match that pattern:

```java
registerReceiver(new BroadcastReceiver() {          // compiles to Outer$1
    @Override public void onReceive(Context c, Intent i) { ... }
}, filter);
```

This is not a hypothetical. Measured on a stock device, a preinstalled calculator's only
runtime receiver was `com.miui.calculator.CalculatorApplication$1` — an anonymous inner
class inside the `Application` subclass. A name-based sweep would have reported the app as
having no receivers.

Grep for the **call site** (`registerReceiver`) rather than the class, and use the
dispatcher hook in `scripts/hook-broadcast.js`, which catches every delivery regardless of
what the handling class is called or whether it was loaded when you attached.

---

### 12. What is `LocalBroadcastManager` and should I care about it?

It is an in-process event bus with a `BroadcastReceiver`-shaped API. Its traffic **never
reaches ActivityManagerService**: no Binder transaction, no queue, no `dumpsys` entry, and
no possibility of another app sending or receiving it.

As a pentester, care about it for one reason: **seeing it is good news, and you should say
so.** An app that moved from `sendBroadcast` to `LocalBroadcastManager` removed an entire
attack class. Reporting its traffic as "an undocumented IPC channel" is wrong and will
damage your credibility.

It is deprecated in AndroidX in favour of `LiveData`, `StateFlow` or a plain observer, for
architectural reasons rather than security ones. All of those are equally invisible to
other apps.

---

### 13. My receiver causes an ANR. Why, and how long do I actually have?

`onReceive` runs on the **main thread**, and the platform enforces a deadline. Measured on
the device rather than quoted:

```
Broadcast parameters (key=bcast_fg_constants):   bcast_timeout = +10s0ms
Broadcast parameters (key=bcast_bg_constants):   bcast_timeout = +1m0s0ms
```

**10 seconds** on the foreground queue, **60 seconds** on the background queue. The
foreground queue is used when the sender set `FLAG_RECEIVER_FOREGROUND` (`0x10000000`).

Note the timeout applies to **ordered** broadcasts — the queue waits for each receiver in
turn. It is also a denial-of-service primitive: a malicious receiver that deliberately
sleeps holds up every downstream receiver for the full timeout.

`goAsync()` moves the work off the main thread and keeps the process alive, but **does not
lift the deadline**:

```java
final PendingResult pending = goAsync();
new Thread(() -> {
    try { doWork(); } finally { pending.finish(); }    // forgetting this leaks, then ANRs
}).start();
```

For anything that takes real time, schedule it with `WorkManager` and return immediately.

---

### 14. What is the difference between `android:permission` on a receiver and the permission argument to `sendBroadcast`?

They protect against **opposite things**, and only one of them is visible in a manifest.

| | `sendBroadcast(intent, perm)` | `<receiver android:permission="...">` |
|---|---|---|
| Set by | the **sender** | the **receiver** |
| Checked against | every candidate **receiver** | the **sender** |
| Prevents | **eavesdropping** — other apps overhearing your broadcast | **forgery** — other apps driving your receiver |
| Visible in a manifest? | **No.** It is an argument at a call site | Yes, for manifest receivers. For runtime ones it appears as `requiredPermission=` in `dumpsys activity broadcasts` |

Both are checked in the same framework method,
`BroadcastQueue.deliverToRegisteredReceiverLocked()`, against opposite parties. You
generally need both, and setting one is the common half-fix.

Neither means anything unless the permission's `protectionLevel` is `signature`. A
`normal` permission is granted to any app that declares `<uses-permission>` for it.

---

### 15. Which broadcasts can I actually forge?

Everything except the ones on that device's protected list. **Check on the device** — the
set is the union of every `<protected-broadcast>` declared by every system package
installed, and OEMs add their own.

```bash
# host — no side effects
bash scripts/protected-broadcast-map.sh --is com.example.ACTION_SYNC

# host — the authoritative test: attempt to send and read the error
adb shell "am broadcast -a com.example.ACTION_SYNC"
```

| Output | Meaning |
|---|---|
| `SecurityException: Permission Denial: not allowed to send broadcast X from pid=N, uid=2000` | Protected. No app can forge it. |
| `Broadcast completed: result=0` | Forgeable. |
| `...from unknown caller.` | A different, service-specific check. Statically it may not be in the protected list at all — measured for `android.appwidget.action.APPWIDGET_UPDATE`. |

Measured on the device: 532 distinct protected actions in `framework-res.apk`, and these
four commonly-assumed-protected actions were **delivered**:
`com.android.vending.INSTALL_REFERRER`, `com.google.android.c2dm.intent.RECEIVE`,
`android.intent.action.PROVIDER_CHANGED`, `android.intent.action.MEDIA_SCANNER_SCAN_FILE`.

---

### 16. Does putting `<protected-broadcast>` in my app's manifest protect my custom action?

**No. It does nothing at all.** The element is honoured only for packages signed with the
platform key. In a third-party APK it is inert.

Its presence in an ordinary app's manifest is a *tell*: the developer copied a system
manifest and believed the copy was doing something. Verify:

```bash
# host
bash scripts/protected-broadcast-map.sh --is com.example.vault.ACTION_SYNC_CONFIG
```

To actually protect a custom action, use a `signature`-level permission on the receiver,
`setPackage()` on the send, `RECEIVER_NOT_EXPORTED` on the registration, or all three.

---

### 17. I found a receiver with `requiredPermission=com.foo.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`. Is that a suspicious custom permission?

**No — it is the opposite, and misreporting it will cost you credibility.**

It is the AndroidX backport of `RECEIVER_NOT_EXPORTED`. `ContextCompat.registerReceiver()`
cannot use the real flag below API 33 because the flag does not exist there, so it emulates
it: it registers with a self-defined **signature** permission named
`<package>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`. Only the app itself holds it, so only
the app can reach the receiver.

Seeing it means the developer explicitly asked for a non-exported receiver and the library
honoured it on an old device. Measured on the device: **119 filters** carrying it, across
`com.google.android.gms`, `com.google.android.youtube` and `com.miui.securitycenter`.

---

### 18. How many receivers are actually on a normal phone?

More than you expect, and the number moves.

One snapshot of an idle Android 11 device:

| Metric | Value |
|---|---|
| `ReceiverList` registrations | 1,281 |
| `IntentFilter`s | 1,438 |
| Action strings | 2,868 |
| Distinct actions | 800 |
| Filters with **no** sender permission | 1,227 |
| Third-party registrations | 472 |

A snapshot a few minutes earlier on the *same idle device* read 1,151 / 1,306 / 2,677.

Two lessons. First, quote any such number with a timestamp — the surface is live. Second, a
receiver you failed to find may not have been registered when you looked; re-run
while exercising the target.

---

### 19. If a receiver is only registered while the app is in the foreground, is it still a risk?

Yes, but the severity changes and you must say so.

A receiver registered in `onResume` and unregistered in `onPause` is reachable only while
its Activity is visible. That makes exploitation *conditional*: the attacker must send the
broadcast while the user is on that screen. That is not hard — an app can poll — but it
does change the story from "reachable at any time" to "reachable during a window".

Two things to check before you downgrade it:

1. **Is it really unregistered?** Forgetting `unregisterReceiver` is one of the most common
   Android bugs. Hook both with `scripts/hook-broadcast.js`; the script logs
   `[unregisterReceiver]` explicitly so you can see the window close.
2. **Is the registration actually in `Application.onCreate`?** Then it lives for as long as
   the process does, which on a busy phone is a long time.

---

### 20. What is the single most useful command in this chapter?

```bash
# host
adb shell "dumpsys activity broadcasts"
```

It is the only reader of AMS's runtime registration table, it is the only record of who
sent what, and it prints broadcast extras in cleartext. Everything else in this chapter is
either a way of parsing it (`scripts/receiver-surface.py`), a way of filling the two gaps
it has — class names and export state (`scripts/hook-broadcast.js`) — or a way of deciding
which of its findings you can act on (`scripts/protected-broadcast-map.sh`).

Capture it before anything restarts. The history is a ring buffer of 50 records per queue,
and a reboot destroys the whole thing.
