# Lab 04 — Lifecycle, foreground, and the restart that did not happen

> **Objective:** measure what the platform actually does to a service — the
> `onStartCommand` return values under a real kill, the five-second foreground
> promotion deadline, and the two independent lifetime claims. Finish able to
> answer "why did my service get killed?" with evidence rather than folklore, and
> knowing one place where the textbook answer is **wrong on real hardware**.

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 90–120 minutes |
| **Needs** | `adb`; build-tools 35.0.1+; a JDK; the ability to install an APK. **No Frida, no root** (root only if your device refuses `adb install`) |
| **Measured against** | Redmi `M2101K6P`, Android 11 / API 30, arm64 — **an OEM ROM, and that matters here more than anywhere else in the chapter** |
| **Reads** | [README §3.2](../README.md), [§3.10](../README.md), [§3.12](../README.md), [§7.4](../README.md) |

---

## 0. Why this lab is not "just developer stuff"

Three reasons a tester needs this.

**You will be asked.** "Why does our service keep dying?" is the most common
question a developer puts to whoever is holding the device. Answering it with
evidence buys you enormous credibility for the findings that follow.

**Two of these behaviours are attack surface.** The five-second promotion
deadline is a one-command remote crash against an exported, startable service
([README §5.3.6](../README.md)). The `START_STICKY` null-Intent path is a latent
`NullPointerException` that fires only in the field.

**One of them will waste your afternoon if you do not know about it.** On many
OEM ROMs the restart the documentation promises does not happen, and every
lab step that depends on it silently fails.

---

## 1. Build the fixture

One service, four behaviours, switchable by an Intent extra.

```bash
# host
mkdir -p ~/ch28-lab04/src/com/example/lifecycle
cd ~/ch28-lab04
```

```bash
# host
cat > src/com/example/lifecycle/LifecycleService.java <<'EOF'
package com.example.lifecycle;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

public class LifecycleService extends Service {

    static final String TAG = "CH28LIFE";

    @Override public void onCreate() {
        super.onCreate();
        Log.i(TAG, "onCreate  pid=" + android.os.Process.myPid());
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        // NOTE the deliberate lack of a null guard on `intent` below. That is
        // the bug this lab reproduces. Do not copy this into anything real.
        String mode = (intent == null) ? "(NULL INTENT)" : intent.getStringExtra("mode");

        Log.i(TAG, "onStartCommand startId=" + startId
                 + " flags=0x" + Integer.toHexString(flags)
                 + " intent=" + intent
                 + " mode=" + mode);

        if ("fg".equals(mode)) {
            promote();
            Log.i(TAG, "promoted to foreground");
        } else if ("fg-late".equals(mode)) {
            // Deliberately do NOT promote. If this was reached via
            // startForegroundService(), the system kills the app in 5 seconds.
            Log.i(TAG, "NOT promoting -- watch the 5 second deadline");
        }

        if ("sticky".equals(mode))    return START_STICKY;
        if ("redeliver".equals(mode)) return START_REDELIVER_INTENT;
        if (intent == null)           return START_STICKY;   // keep the loop going
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) {
        Log.i(TAG, "onBind " + intent);
        return new android.os.Binder();       // a bare Binder: enough to hold a bind claim
    }

    @Override public boolean onUnbind(Intent intent) {
        Log.i(TAG, "onUnbind " + intent);
        return false;
    }

    @Override public void onTaskRemoved(Intent rootIntent) {
        Log.i(TAG, "onTaskRemoved -- android:stopWithTask decides what happens next");
        super.onTaskRemoved(rootIntent);
    }

    @Override public void onDestroy() {
        Log.i(TAG, "onDestroy");
        super.onDestroy();
    }

    private void promote() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new NotificationChannel(
                    "life", "Lifecycle", NotificationManager.IMPORTANCE_LOW));
        }
        Notification n = (Build.VERSION.SDK_INT >= 26)
                ? new Notification.Builder(this, "life")
                        .setContentTitle("Lifecycle lab")
                        .setSmallIcon(android.R.drawable.stat_notify_sync)
                        .build()
                : new Notification.Builder(this)
                        .setContentTitle("Lifecycle lab")
                        .setSmallIcon(android.R.drawable.stat_notify_sync)
                        .build();
        startForeground(4242, n);
    }
}
EOF
```

```bash
# host
cat > AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.lifecycle">
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <application android:label="LifecycleLab">
        <service
            android:name=".LifecycleService"
            android:exported="true"
            android:foregroundServiceType="dataSync"/>
    </application>
</manifest>
EOF
```

Build it exactly as in Lab 03 §1 (no AIDL step needed here), then:

```bash
# host
adb install -r lifecycle.apk
adb shell "dumpsys package com.example.lifecycle | grep userId="
```

> **Warning**
> This service is `android:exported="true"` **on purpose**, so you can drive it
> from `adb shell` and so §4 can demonstrate the promotion-deadline denial of
> service. Uninstall it when you are done; on a device you care about, an
> exported startable service is exactly the thing this chapter tells you to look
> for.

---

## 2. Step 1 — the two independent claims

```bash
# host
adb logcat -c
adb shell am start-service -n com.example.lifecycle/.LifecycleService --es mode plain
sleep 1
adb shell dumpsys activity services com.example.lifecycle | head -20
```

Look for:

```text
startRequested=true  ... callStart=true  lastStartId=1
```

Now stop it and watch `onDestroy`:

```bash
# host
adb shell am stop-service -n com.example.lifecycle/.LifecycleService
adb logcat -d -s CH28LIFE
```

```text
CH28LIFE: onCreate  pid=...
CH28LIFE: onStartCommand startId=1 flags=0x0 intent=Intent {...} mode=plain
CH28LIFE: onDestroy
```

**Q1.** Now do it again, but bind first. Predict what `am stop-service` will do.

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.example.lifecycle/com.example.lifecycle.LifecycleService'
sleep 2
adb shell am start-service -n com.example.lifecycle/.LifecycleService --es mode plain
sleep 1
adb shell am stop-service -n com.example.lifecycle/.LifecycleService
sleep 1
adb logcat -d -s CH28LIFE
```

<details>
<summary>Answer</summary>

`onDestroy` does **not** run while the prober is still bound. `stop-service`
releases the *start* claim; the *bind* claim is still outstanding. The service is
destroyed only when the prober's activity finishes six seconds later and the
binding drops — at which point you see `onUnbind` and then `onDestroy`.

This is [README §2.3](../README.md)'s state machine on real hardware, and it is
the answer to the very common developer complaint "I called `stopSelf()` and
nothing happened".
</details>

**Q2.** Check `dumpsys` while both claims are outstanding:

```bash
# host
adb shell dumpsys activity services com.example.lifecycle
```

Which fields tell you each claim exists?

<details>
<summary>Answer</summary>

`startRequested=true` is the start claim. The `Bindings:` block, with an
`IntentBindRecord` containing a non-null `binder=` and at least one
`ConnectionRecord`, is the bind claim. Both must be gone before `onDestroy`.
</details>

---

## 3. Step 2 — the background-start restriction, measured

```bash
# host -- with the app NOT in the foreground
adb shell am force-stop com.example.lifecycle
adb shell am start-service -n com.example.lifecycle/.LifecycleService --es mode plain
```

Reference output:

```text
Error: app is in background uid UidRecord{30a636 u0a310 CEM  idle change:cached procs:1 seq(0,0,0)}
```

**Q3.** Is this a security control? Have you just proved the service is
protected?

<details>
<summary>Answer</summary>

**No, and no.** This is the **API 26 background execution limit**: an app that is
not in a foreground state may not call `startService`. It is a battery measure,
not an access control, and it says nothing about whether the component is
exported or permission-guarded.

Misreading it as protection is a false negative you will not notice, because the
error message looks like a refusal. Two ways past it:

```bash
# use the foreground-service entry point instead
adb shell am start-foreground-service -n com.example.lifecycle/.LifecycleService --es mode fg

# or bind, which is not subject to this restriction
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.example.lifecycle/com.example.lifecycle.LifecycleService'
```

Note the second one: **binding sidesteps this entirely**, which is one more
reason a service test that only uses `am start-service` under-reports.
</details>

---

## 4. Step 3 — the five-second promotion deadline

```bash
# host
adb logcat -c
adb shell am start-foreground-service -n com.example.lifecycle/.LifecycleService --es mode fg
sleep 2
adb logcat -d -s CH28LIFE
adb shell dumpsys activity services com.example.lifecycle | grep -E "isForeground|foregroundId|startForegroundCount"
```

```text
CH28LIFE: onStartCommand startId=1 ... mode=fg
CH28LIFE: promoted to foreground

    startForegroundCount=1
    isForeground=true foregroundId=4242 foregroundNoti=Notification(channel=life ...)
```

Now the failure mode:

```bash
# host
adb shell am force-stop com.example.lifecycle
adb logcat -c
adb shell am start-foreground-service -n com.example.lifecycle/.LifecycleService --es mode fg-late
sleep 8
adb logcat -d | grep -iE "CH28LIFE|did not start in time|ForegroundServiceDidNotStartInTime|ANR in com.example.lifecycle"
```

Expect the app to be killed roughly five seconds after the start, with a system
log line naming the component.

**Q4.** Why is this a *finding* and not just a bug?

<details>
<summary>Answer</summary>

Because the service is `exported="true"` and startable, so **another app can
cause the crash**. One `startForegroundService` with an Intent the service does
not recognise, and the victim app dies. Repeatable, no permissions, no user
interaction.

Grade it honestly: **Low to Medium**. It is availability, not compromise, and the
app restarts. Its real value in a report is that it is provable in one command,
which establishes that the exported surface is genuinely reachable — useful
groundwork for the findings that follow.

Preconditions to state: the service must be exported and startable, and from API
31 the *attacker* must itself be allowed to start a foreground service, which
backgrounded apps generally are not. Say so.
</details>

**Q5.** Look at the `dumpsys` output for the promoted service. Can you see which
`foregroundServiceType` it declared?

<details>
<summary>Answer</summary>

**On API 30, no.** A grep of the entire `dumpsys activity services` output on the
reference device returned **zero** occurrences of `foregroundServiceType`, while
foreground services were plainly running:

```text
714:  isForeground=true foregroundId=10    foregroundNoti=Notification(channel=MiShare ...)
1547: isForeground=true foregroundId=1     foregroundNoti=Notification(channel=id_notification_center ...)
2693: isForeground=true foregroundId=20006 foregroundNoti=Notification(channel=securitycenter_... )
```

The manifest declares `android:foregroundServiceType="dataSync"` and the dump
does not show it. On newer releases the field does appear.

**Consequence for a report:** on an API 30 device you must read declared types
from the **manifest**, not from `dumpsys`. Writing "the app declares no foreground
service types" on the strength of a `dumpsys` grep would be wrong.
</details>

---

## 5. Step 4 — `START_STICKY` and the null Intent

```bash
# host
adb logcat -c
adb shell am start-foreground-service -n com.example.lifecycle/.LifecycleService --es mode sticky
sleep 2
adb shell dumpsys activity services com.example.lifecycle | grep -E "startRequested|callStart|lastStartId|restartCount"
```

Now kill the process and watch:

```bash
# host
adb shell "am kill com.example.lifecycle"
sleep 6
adb logcat -d -s CH28LIFE
adb shell dumpsys activity services com.example.lifecycle | grep -E "restartCount|nextRestartTime"
```

**The textbook answer** is that the service is recreated and `onStartCommand`
runs again with `intent=null`:

```text
CH28LIFE: onCreate  pid=<new>
CH28LIFE: onStartCommand startId=1 flags=0x0 intent=null mode=(NULL INTENT)
```

**Q6.** What did *your* device do?

<details>
<summary>Answer — and the point of this whole lab</summary>

On the reference device, **the restart did not happen**, and the reason was not
AOSP:

```text
I ActivityManager       : Process com.example.notesvault (pid 25428) has died: fg  SVC
I AutoStartManagerService: MIUILOG- Reject RestartService packageName :com.example.notesvault uid : 10310
```

`AutoStartManagerService` is a Xiaomi component with no AOSP equivalent. On this
device a `START_STICKY` service does not come back unless the app is on the
vendor's autostart allow-list.

Three things follow:

1. **Any lab step or test plan that depends on sticky restart must check the
   device first**, or it will silently produce a wrong negative.
2. **Any finding that depends on it must name the device it was measured on.**
   "The service restarts automatically and re-establishes its C2 connection" is a
   claim about a ROM, not about Android.
3. If you are testing malware persistence, the *absence* of a restart on an OEM
   ROM does not mean the malware lacks persistence — it means the malware author
   also has to deal with this, which is precisely why real families stack three
   redundant restart paths (`START_STICKY`, a `JobService`, and a boot receiver).

If your device *did* restart the service, you are on something closer to AOSP.
Record which, either way.
</details>

**Q7.** Look at the `mode=(NULL INTENT)` line (if you got one). What would have
happened had the code read `intent.getStringExtra("mode")` without the guard?

<details>
<summary>Answer</summary>

`NullPointerException` on the first line of `onStartCommand`, in the restart
path — which only ever executes after a real low-memory kill. It will not
reproduce on a developer's desk and it will fire on a two-year-old phone with
forty apps installed.

Static detection is one grep:

```bash
grep -rn -A6 "onStartCommand" out/sources/ | grep -E "intent\.(get|has)"
```

Report it as Low severity and be specific: it is a crash, in a path the developer
has never exercised.
</details>

### 5.1 `START_REDELIVER_INTENT`

```bash
# host
adb shell am force-stop com.example.lifecycle
adb logcat -c
adb shell am start-foreground-service -n com.example.lifecycle/.LifecycleService \
  --es mode redeliver --es secret "hunter2"
sleep 2
adb shell "am kill com.example.lifecycle"
sleep 6
adb logcat -d -s CH28LIFE
```

If the restart happens, the redelivered call carries the original Intent and
`flags` has `START_FLAG_REDELIVERY` (`0x1`) set.

**Q8.** `START_REDELIVER_INTENT` sounds strictly better than `START_STICKY`. What
is the security cost?

<details>
<summary>Answer</summary>

The system holds **a copy of your Intent, extras and all, inside `system_server`**
until the service finishes. If those extras contain a credential — and
`--es secret hunter2` is exactly the shape of the mistake — that credential now
lives in another process's memory for an unbounded period.

It is not exposed to other apps, so this is not a high-severity finding on its
own. It does lengthen the window in which a heap artefact exists, and it is one
more copy nobody is tracking. The remediation is trivial: pass an **index**, and
have the service look the secret up from its own storage.
</details>

---

## 6. Step 5 — why did it get killed?

Build the evidence table for your own device.

```bash
# host -- priority bands
adb shell dumpsys activity processes | grep -E "^\s+(Proc|PERS|SVC|CACHED)" | head -30
adb shell dumpsys activity processes com.example.lifecycle
```

```bash
# host -- the six candidate causes, and what each leaves behind
adb logcat -d | grep -iE "lowmemorykiller|has died|Stopping service|ANR in|AutoStart|Reject"
```

| Cause | Evidence to look for |
|---|---|
| Low memory | `lowmemorykiller` in logcat; a low `adj` in `dumpsys activity processes` |
| Task swiped away | `onTaskRemoved` ran; `android:stopWithTask` is not `false` |
| Background execution limits | `ActivityManager` log about stopping a background service |
| **OEM power management** | Often nothing. On MIUI: `AutoStartManagerService: MIUILOG- Reject RestartService` |
| It stopped itself | `onDestroy` while work is outstanding — the `stopSelf()` race |
| Crash | The stack trace |

**Q9.** Demonstrate the task-swipe path.

```bash
# host
adb shell am start-foreground-service -n com.example.lifecycle/.LifecycleService --es mode fg
# now swipe the app away from Recents on the device, by hand
adb logcat -d -s CH28LIFE
```

<details>
<summary>Answer</summary>

`onTaskRemoved` fires. Whether `onDestroy` follows depends on
`android:stopWithTask`, which defaults to true for most services. Setting it to
`false` is how "unkillable" background services are built — and its presence in a
target's manifest, on a service with no user-visible purpose, is worth a line in
a report.

a **foreground** service with a notification generally survives the
swipe regardless, which is the whole point of foreground status.
</details>

---

## 7. Step 6 — `stopSelf()` versus `stopSelf(startId)`

Add this to the fixture and rebuild:

```java
// inside onStartCommand, for mode=race
if ("race".equals(mode)) {
    final int id = startId;
    new Thread(new Runnable() { public void run() {
        try { Thread.sleep(3000); } catch (InterruptedException ignored) {}
        Log.i(TAG, "work for startId=" + id + " done; calling stopSelf()");
        stopSelf();                     // THE BUG: no startId
    }}).start();
    return START_NOT_STICKY;
}
```

```bash
# host -- send two starts, three seconds apart is too slow; send them together
adb logcat -c
adb shell "am start-foreground-service -n com.example.lifecycle/.LifecycleService --es mode race; \
           am start-service -n com.example.lifecycle/.LifecycleService --es mode race"
sleep 6
adb logcat -d -s CH28LIFE
```

**Q10.** What do you see, and what would `stopSelf(id)` have done differently?

<details>
<summary>Answer</summary>

The first job's `stopSelf()` destroys the service even though the second start is
still outstanding — `onDestroy` runs and the second job's work is lost.

`stopSelf(startId)` stops the service **only if `startId` is the most recent one
delivered**. That check is `ActiveServices.stopServiceTokenLocked`, and it is the
entire reason `startId` is a parameter of `onStartCommand` at all.

This is a correctness bug rather than a security one, but it produces
intermittent lost work that is very hard to diagnose from the outside, and
spotting it in a code review is a cheap win.
</details>

---

## 8. Success criteria

- [ ] You have shown `onDestroy` **not** running after `stop-service` because a
      bind claim was outstanding.
- [ ] You have captured `Error: app is in background` and can say why it is not
      a security control.
- [ ] You have promoted a service to the foreground and seen `isForeground=true`
      in `dumpsys`.
- [ ] You have caused the five-second promotion deadline to kill the app, and can
      state the preconditions for it being a finding.
- [ ] You have checked whether **your** device honours `START_STICKY` restart, and
      recorded the answer with the log line that proves it either way.
- [ ] You can fill in the six-row "why did it get killed" evidence table from
      your own device.
- [ ] You can state, from your own device, whether `dumpsys activity services`
      prints `foregroundServiceType`.

---

## 9. Common mistakes in this lab

| Mistake | Consequence |
|---|---|
| Reading `Error: app is in background` as protection | A false negative; it is the API 26 battery restriction |
| Assuming `START_STICKY` restarts happen | Measured refused on an OEM ROM. Check first |
| Quoting a sticky-restart result without naming the device | You are describing a ROM, not Android |
| Grepping `dumpsys` for `foregroundServiceType` on API 30 | It is not printed. Read the manifest |
| Calling the promotion-deadline crash "Critical" | It is availability, and the app restarts. Low to Medium |
| Testing lifetime with only `am start-service` | Binding is not subject to background-start limits and will reach services `start-service` cannot |
| Leaving the exported fixture installed | It is exactly the kind of component this chapter tells you to report |

---

## 10. Cleanup

```bash
# host
adb uninstall com.example.lifecycle
rm -rf ~/ch28-lab04
```

---

## Next

[Lab 05 — CTF: The Silent Door](lab-05-ctf-the-silent-door.md). Four flags, and
the fourth is awarded for something you do *not* report.
