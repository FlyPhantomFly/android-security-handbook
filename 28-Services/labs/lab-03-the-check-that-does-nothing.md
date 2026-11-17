# Lab 03 — The check that does nothing

> **Objective:** build a service whose caller check is written in `onBind`, watch
> it let an attacker straight through, and prove *why* from both sides of the UID
> boundary at once. Then move the check to the one place it works and prove that
> too. Finish able to explain the mechanism to a developer without saying "under
> the hood".

| | |
|---|---|
| **Difficulty** | Intermediate–Advanced |
| **Time** | 2–3 hours |
| **Needs** | Lab 02's prober installed; build-tools 35.0.1+; a JDK; Frida (host + `frida-server`); root to attach Frida |
| **Measured against** | Redmi `M2101K6P`, Android 11 / API 30, arm64, Frida 16.1.6 |
| **Reads** | [README §3.7](../README.md), [§3.8](../README.md), [§4.2](../README.md), [§5.3.2](../README.md) |
| **Uses** | [`../examples/`](../examples/VaultService-vulnerable.java), [`../scripts/trace-service-lifecycle.js`](../scripts/trace-service-lifecycle.js) |
| **Expected output** | [`../examples/measured-frida-trace.txt`](../examples/measured-frida-trace.txt), [`../examples/measured-bind-probe.txt`](../examples/measured-bind-probe.txt) |

---

## 0. The claim you are about to test

Here is code that looks correct:

```java
@Override
public IBinder onBind(Intent intent) {
    if (Binder.getCallingUid() != Process.myUid()) {
        return null;                  // "only our own app may bind"
    }
    return binder;
}
```

Read it aloud. "If the caller is not us, refuse." It is four words of logic, it
compiles, it passes review, and it is **completely inert**.

This lab does not ask you to believe that. It asks you to measure it, from both
processes, at the same time.

> **Mental Model**
> A Binder caller's identity exists only *while their transaction is in flight*.
> `onBind` does not run inside their transaction — it runs on your main thread,
> from a message the system posted. By then there is no caller, so the framework
> answers the only question it can: yours.

---

## 1. Build the victim

The victim is [`../examples/VaultService-vulnerable.java`](../examples/VaultService-vulnerable.java)
plus [`../examples/IVaultService.aidl`](../examples/IVaultService.aidl).

```bash
# host
mkdir -p ~/ch28-lab03/vault/src/com/example/notesvault
cd ~/ch28-lab03/vault
cp <repo>/28-Services/examples/IVaultService.aidl          src/com/example/notesvault/
cp <repo>/28-Services/examples/VaultService-vulnerable.java src/com/example/notesvault/VaultService.java
```

The manifest:

```bash
# host
cat > AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.notesvault">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <application android:label="NotesVault">
        <service android:name=".VaultService" android:exported="true">
            <intent-filter>
                <action android:name="com.example.notesvault.BIND_VAULT"/>
            </intent-filter>
        </service>
    </application>
</manifest>
EOF
```

Generate the AIDL, compile, dex, package, sign:

```bash
# host
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"; BT="$SDK/build-tools/35.0.1"
AJ="$SDK/platforms/android-35/android.jar"
mkdir -p gen classes

# LINUX / MACOS
"$BT/aidl" --lang=java -Isrc -ogen src/com/example/notesvault/IVaultService.aidl

# WINDOWS -- BACKSLASHES. Forward slashes are rejected with
#   "directory src/ is not found in any of the import paths: - src\"
# even though src/ plainly exists.
#   "$BT/aidl.exe" --lang=java "-Isrc\" -ogen "src\com\example\notesvault\IVaultService.aidl"

javac -source 8 -target 8 -bootclasspath "$AJ" -d classes \
      src/com/example/notesvault/VaultService.java \
      gen/com/example/notesvault/IVaultService.java
( cd classes && jar cf ../classes.jar . )
"$BT/d8" --lib "$AJ" --min-api 21 --output . classes.jar
"$BT/aapt2" link -I "$AJ" --manifest AndroidManifest.xml -o unsigned.apk
cp unsigned.apk withdex.apk && zip -q withdex.apk classes.dex
keytool -genkeypair -keystore ks.jks -alias k -storepass android -keypass android \
        -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=ch28vault" 2>/dev/null
"$BT/apksigner" sign --ks ks.jks --ks-pass pass:android --key-pass pass:android \
        --out vault.apk withdex.apk
```

Install (see Lab 02 §3 if `adb install` is refused):

```bash
# host
adb install -r vault.apk
# or, if the device refuses:
#   adb push vault.apk /data/local/tmp/ch28vault.apk
#   adb shell "su -c 'pm install -r -t /data/local/tmp/ch28vault.apk'"

adb shell "dumpsys package com.example.notesvault | grep userId="
```

```text
    userId=10310
```

**Write down both uids** — the vault's and the prober's from Lab 02. On the
reference device they were **10310** (victim) and **10313** (attacker).

**Q1.** Before you run anything: what will the vulnerable `onBind` compare, and
what will the answer be?

<details>
<summary>Answer</summary>

`Binder.getCallingUid()` against `Process.myUid()`. Both will be **10310**, the
service's own uid, so the condition `!=` is false and the binder is returned.
The attacker's 10313 never appears.
</details>

---

## 2. Step 1 — attack it, and read the victim's own log

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.example.notesvault/com.example.notesvault.VaultService' \
  --es tokencodes '1+3'
sleep 9
adb logcat -d -s CH28:V CH28VAULT:V
```

Reference output, both processes interleaved:

```text
CH28    : probe uid=10313 pid=21583
CH28    : BIND-RETURN com.example.notesvault/...VaultService => true

CH28VAULT: onBind intent=Intent { cmp=com.example.notesvault/.VaultService }
           callingUid=10310                                   <---- LOOK HERE

CH28    : CONNECTED ... descriptor='com.example.notesvault.IVaultService'
          alive=true ping=true local=false
CH28    :   TX code=1 ok=true replyBytes=100
            exception=java.lang.SecurityException: Binder invocation to an incorrect interface
CH28    :   TX code=2 ok=true replyBytes=100  exception=...incorrect interface
CH28    :   TX code=3 ok=true replyBytes=100  exception=...incorrect interface

CH28VAULT: getAuthToken() called by uid=10313 pid=21583        <---- AND HERE
CH28    :   TOKEN-TX code=1 ok=true replyBytes=92 exception=(none)
            string='eyJhbGciOiJIUzI1NiJ9.SECRET-SESSION-TOKEN'
CH28VAULT: isUnlocked() by uid=10313
CH28    :   TOKEN-TX code=3 ok=true replyBytes=8 exception=(none) string='null'
```

**Two lines from the same process, about the same connection, milliseconds
apart, giving different answers:**

```text
onBind        ... callingUid=10310     <- the service's OWN uid
getAuthToken()... called by uid=10313  <- the real caller
```

**Q2.** Explain the difference, mechanically, without using the word "somehow".

<details>
<summary>Answer</summary>

`onBind` is not called by the client. `ActiveServices.bindServiceLocked` sends
`scheduleBindService` to the app's `IApplicationThread`;
`ActivityThread.handleBindService` picks that message up **on the app's main
thread** and calls `onBind`. At that moment there is no client transaction in
flight, so `IPCThreadState`'s `mCallingUid` is not the client's and
`Binder.getCallingUid()` falls back to `Process.myUid()`.

`getAuthToken()` is dispatched from `Binder.execTransact` on a **Binder thread
pool thread**, inside the client's live transaction. `mCallingUid` was set from
the value the *kernel* wrote into `sender_euid` when it copied the parcel, and
that value cannot be forged — [25 §3.11](../../25-Binder/README.md) demonstrates
three separate forgery attempts failing.

Same object, two dispatch paths, two different answers to "who is calling".
[README §4.2](../README.md) traces both.
</details>

**Q3.** The blind probe at codes 1–3 produced
`SecurityException: Binder invocation to an incorrect interface`, and then code 1
succeeded. What changed between the two?

<details>
<summary>Answer</summary>

The probe wrote the **interface token** the second time. The generated
`Stub.onTransact` begins with `data.enforceInterface(DESCRIPTOR)`, which compares
the first string in the parcel against `com.example.notesvault.IVaultService`.

The attacker got that string from `getInterfaceDescriptor()` — the service handed
it over on request. It is a name tag, not a lock. Its job is to stop a client
accidentally sending code 3 to the wrong object.
</details>

---

## 3. Step 2 — watch it live, from inside the victim

logcat lines the victim was kind enough to print are not always available. Frida
gets you the same evidence against a service that logs nothing.

### 3.1 Start `frida-server`

```bash
# host
adb shell "su -c '/data/local/tmp/frida-server &'" &
sleep 2
frida-ps -U | head -3
```

### 3.2 Attach and trace

The service must already be running, because it has no launcher activity to spawn.

```bash
# host -- create the process
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.example.notesvault/com.example.notesvault.VaultService'
sleep 4
adb shell pidof com.example.notesvault
```

```bash
# host -- attach. --runtime=v8 is NOT optional; see the warning below.
frida -U -p <PID> -l <repo>/28-Services/scripts/trace-service-lifecycle.js --runtime=v8
```

> **Warning**
> **Always pass `--runtime=v8`.** On the reference setup (Frida 16.1.6, Windows
> host, Android 11 arm64) the default QuickJS runtime did not run the agent's
> timers at all: `setInterval` never fired, so the rescan for late-loaded
> `Service` subclasses and the deferred uid-to-package resolution both silently
> did nothing, and no asynchronous `console.log` output was delivered. The script
> printed its banner and appeared dead. If that happens to you, change this
> before you change anything else.

Then, from another shell, drive the attack again:

```bash
# host
adb shell "am force-stop com.pentest.ch28probe; am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.example.notesvault/com.example.notesvault.VaultService' --es tokencodes '1+2+3'"
```

Reference trace, trimmed to the interesting lines:

```text
=== trace-service-lifecycle.js ===
this process uid = 10310
any callback reporting uid=10310 is NOT telling you who called.

[+] hooking Service subclass com.example.notesvault.VaultService
[+] hooked android.os.Binder.execTransact
[+] hooked android.os.Handler$MessengerImpl.send
[+] ready. Bind or start the service now.

[BINDER]    execTransact  uid=1000  pid=0     (system)  code=39  on android.app.ActivityThread$ApplicationThread
[BINDER]    execTransact  uid=1000  pid=0     (system)  code=2   on android.app.ActivityThread$ApplicationThread
[LIFECYCLE] onCreate      uid=10310 pid=27413 (SELF -- no transaction in flight, a check here does NOTHING)
[LIFECYCLE] onBind        uid=10310 pid=27413 (SELF -- no transaction in flight, a check here does NOTHING)
            intent=Intent { cmp=com.example.notesvault/.VaultService }
            returned binder descriptor='com.example.notesvault.IVaultService'
[BINDER]    execTransact  uid=10291 pid=27858 (resolving...)  code=1598968902  on com.example.notesvault.VaultService$1
[BINDER]    execTransact  uid=10291 pid=27858 (resolving...)  code=1   on com.example.notesvault.VaultService$1
[BINDER]    execTransact  uid=10291 pid=27858 (resolving...)  code=2   on com.example.notesvault.VaultService$1
[BINDER]    execTransact  uid=10291 pid=27858 (resolving...)  code=3   on com.example.notesvault.VaultService$1
[uid]       10291 = com.pentest.ch28probe
[LIFECYCLE] onUnbind      uid=10310 pid=27413 (SELF ...)  returned false
[LIFECYCLE] onDestroy     uid=10310 pid=27413 (SELF ...)
```

**Q4.** The transactions land on `com.example.notesvault.VaultService$1`, not on
`VaultService`. Why, and what does that tell you about where to look in a
decompiled APK?

<details>
<summary>Answer</summary>

`$1` is the **anonymous inner class** — the `IVaultService.Stub` instance the
service returned from `onBind`. The `Service` subclass is a lifecycle shell; the
Binder object is a different class entirely.

In JADX, when hunting for the code that handles remote calls, look for
`extends <something>.Stub` rather than `extends Service`. It is almost always an
inner class, frequently anonymous, and frequently the only interesting class in
the file. [README §6.2](../README.md).
</details>

**Q5.** `code=1598968902` was the **first** thing the attacker sent. What is it,
and why is it always first?

<details>
<summary>Answer</summary>

`INTERFACE_TRANSACTION` — the ASCII bytes `'_NTF'`. It is
`IBinder.getInterfaceDescriptor()`, and it is first because the attacker needs
the descriptor before it can write a valid interface token for anything else. It
costs nothing, needs no APK, and every Binder object answers it.
</details>

**Q6.** `uid=1000 pid=0` appears on `ActivityThread$ApplicationThread`. What are
those, and why is the pid zero?

<details>
<summary>Answer</summary>

That is `system_server` (uid 1000) calling **into your app** on the
`IApplicationThread` interface — `scheduleCreateService`, `scheduleBindService`,
`scheduleUnbindService`, and so on. These are the calls traced in
[README §4.2](../README.md), seen from the receiving end.

`pid=0` because `Binder.getCallingPid()` is not populated for one-way
transactions. That is worth remembering generally: **a `oneway` call gives you a
uid but not a pid.**
</details>

---

## 4. Step 3 — two ways this trace failed before it worked

Both are recorded in [`../examples/measured-frida-trace.txt`](../examples/measured-frida-trace.txt)
and both are worth reproducing deliberately, because they teach more than the
success does.

### 4.1 Killing the target with a hook

The first version of the script traced `Messenger` traffic by replacing
`android.os.Handler.dispatchMessage`. Try it:

```javascript
// /tmp/killer.js -- frida -U -p <PID> -l /tmp/killer.js --runtime=v8
Java.perform(function () {
  Java.use('android.os.Handler').dispatchMessage.implementation = function (m) {
    return this.dispatchMessage(m);
  };
  console.log('[+] hooked dispatchMessage');
});
```

```bash
# host, in another shell
adb logcat -d | grep -iE "notesvault.*(SIGSEGV|has died)"
```

```text
F libc            : Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR),
                    fault addr 0x32c07000 in tid 25428 (mple.notesvault)
I ActivityManager : Process com.example.notesvault (pid 25428) has died: fg  SVC
```

**Q7.** Why did that hook kill the process when hooking `onBind` did not?

<details>
<summary>Answer</summary>

Volume. `dispatchMessage` runs for **every message on every looper** in the
process — thousands per second — and routing all of that through a JavaScript
replacement is far too much. `onBind` runs once per bind.

The right hook for `Messenger` traffic is `android.os.Handler$MessengerImpl.send`,
which is the single entry point for cross-process `Messenger` messages, fires
only when a `Messenger` is actually used, and is *also* the exact place the
framework stamps `msg.sendingUid`.

The general lesson: **choose the narrowest hook that answers the question.** A
hook on a hot path is not just slow, it is a stability problem, and a target that
SIGSEGVs mid-test destroys your evidence.
</details>

### 4.2 Deadlocking the target with a Binder call

The second failure was subtler and produced **no error at all**. The script
resolved uid → package inside the `execTransact` hook:

```javascript
// DO NOT DO THIS
var pkgs = app.getPackageManager().getPackagesForUid(uid);   // inside execTransact
```

Symptom: the trace printed its banner, the client's `onServiceConnected` never
fired, and nothing else ever appeared.

**Q8.** What went wrong?

<details>
<summary>Answer</summary>

`getPackagesForUid()` is **itself a Binder call** to `system_server`. Making it
while handling an inbound transaction, on a Binder pool thread, is exactly the
reentrancy hazard in [README §3.5.1](../README.md): the thread blocks waiting for
a reply, and the pool stops answering.

The fix in the shipped script is to print the bare number on the hot path and
resolve names on a timer running on a normal thread — which is why the trace
above shows `(resolving...)` and then a later `[uid] 10291 = com.pentest.ch28probe`
line.

**This is not a Frida quirk.** It is the same mistake a developer makes when they
call into `system_server` from inside their own AIDL method while holding a lock,
and it is the reason "AIDL is reentrant" is in the chapter at all.
</details>

---

## 5. Step 4 — fix it, and prove the fix

Swap the implementation for
[`../examples/VaultService-fixed.java`](../examples/VaultService-fixed.java):

```bash
# host
cp <repo>/28-Services/examples/VaultService-fixed.java \
   src/com/example/notesvault/VaultService.java
```

Add the permission to the manifest:

```xml
<permission android:name="com.example.notesvault.permission.VAULT"
            android:protectionLevel="signature"/>

<service android:name=".VaultService"
         android:exported="true"
         android:permission="com.example.notesvault.permission.VAULT">
    <intent-filter>
        <action android:name="com.example.notesvault.BIND_VAULT"/>
    </intent-filter>
</service>
```

Rebuild, reinstall, and attack again:

```bash
# host
adb uninstall com.example.notesvault
# ... rebuild as in section 1 ...
adb install -r vault.apk

adb logcat -c
adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
  --es targets 'com.example.notesvault/com.example.notesvault.VaultService' \
  --es tokencodes '1+3'
sleep 9
adb logcat -d -s CH28:V CH28VAULT:V
```

Expected:

```text
CH28: BIND-RETURN com.example.notesvault/...VaultService => false
      SecurityException: Not allowed to bind to service ...
```

**Q9.** The bind now fails at the manifest permission, so the per-method check
never runs. Does that make the per-method check redundant?

<details>
<summary>Answer</summary>

**No**, and this is the question that separates a good fix from a lucky one. The
manifest gate can evaporate in four ordinary ways:

1. A **manifest merge** from a library or a build variant overrides
   `android:permission` or `android:exported`.
2. A future refactor exports the service for a legitimate new client.
3. A **sibling app signed with the same key** is compromised — it holds the
   permission and the manifest gate waves it through.
4. `sharedUserId` puts another package inside your own UID.

The per-method check is the one that survives all four. The manifest gate answers
"may this uid bind"; the per-method check answers "may this uid call *this
method*". They are different questions and you want both.
</details>

### 5.1 Prove the per-method check independently

Remove the manifest permission (keep `exported="true"`), rebuild, reinstall, and
attack once more. Now the bind succeeds and the method refuses:

```text
CH28    : BIND-RETURN ... => true
CH28    : CONNECTED ... descriptor='com.example.notesvault.IVaultService'
CH28    :   TOKEN-TX code=1 ok=true replyBytes=...
            exception=java.lang.SecurityException: caller uid 10313 is not signed with our key
CH28VAULT: refused call from uid 10313
```

**That is the evidence a report needs.** Not "we added a check" — the same
attacker, the same transaction, refused, with the caller's true uid named in the
refusal.

**Q10.** You have now shown the check firing. What is the *other* half of the
proof, and why does a report need both?

<details>
<summary>Answer</summary>

You also need to show it **not** firing against an authorised caller — otherwise
you have demonstrated that the service refuses everyone, which is not the same as
demonstrating that it authorises correctly. Sign a second test app with the same
key, bind, and show `getAuthToken()` succeeding.

Negative evidence ("the hook never fired", "the call was refused") is only
meaningful next to a positive baseline. This is the same discipline as
[README §7.5](../README.md)'s note about hooking `checkSignatures` and watching
it never fire.
</details>

---

## 6. Step 5 — the three wrong places, side by side

Reproduce each with a one-line edit and confirm from the trace that the attacker
is never seen.

```java
// Variant A -- in onBind
@Override public IBinder onBind(Intent i) {
    if (Binder.getCallingUid() != Process.myUid()) return null;
    return binder;
}

// Variant B -- in onStartCommand
@Override public int onStartCommand(Intent i, int f, int id) {
    if (Binder.getCallingUid() != TRUSTED_UID) { stopSelf(); return START_NOT_STICKY; }
    ...
}

// Variant C -- on a worker thread the Stub method spawned
@Override public String getAuthToken() {
    final String[] out = new String[1];
    executor.execute(() -> {
        if (Binder.getCallingUid() != TRUSTED_UID) return;   // no transaction here
        out[0] = prefs.getString("access_token", null);
    });
    ...
}
```

**Q11.** Variant C is the interesting one. The developer knew to check
`getCallingUid()` *and* knew not to block the Binder thread. What went wrong?

<details>
<summary>Answer</summary>

They combined two correctly-learnt rules into a bug. The identity exists only on
the Binder thread, during the transaction. The moment work is handed to an
executor, the transaction is over as far as that thread is concerned and
`getCallingUid()` returns the app's own uid again.

The fix is to **capture on the Binder thread and pass it down**:

```java
@Override public String getAuthToken() {
    final int callerUid = Binder.getCallingUid();   // captured HERE
    enforce(callerUid);                             // checked HERE, synchronously
    return prefs.getString("access_token", null);   // then do the work
}
```

Variant C is worth reproducing precisely because it does not look like
carelessness. It looks like competence applied one step too late.
</details>

---

## 7. Success criteria

- [ ] Both apps built and installed; you can state both uids.
- [ ] You have captured, in one logcat, `onBind ... callingUid=<victim uid>` and
      `getAuthToken() called by uid=<attacker uid>` from the same connection.
- [ ] You have the same pair from the Frida trace, against a service that logs
      nothing itself.
- [ ] You can explain the mechanism in three sentences, naming
      `handleBindService`, `execTransact` and the Binder thread pool.
- [ ] You have reproduced at least one of the two script failure modes (the
      `dispatchMessage` SIGSEGV or the reentrancy hang) deliberately.
- [ ] You have shown the fixed service refusing the attacker **and** accepting an
      authorised caller.

---

## 8. Common mistakes in this lab

| Mistake | Consequence |
|---|---|
| Running the Frida script without `--runtime=v8` | Banner, then silence. You will assume the script is broken |
| Attaching before the service process exists | `frida: unable to find process`. Bind once first to create it |
| Attaching to the app's main pid when `android:process` is set | You hook the wrong process and see nothing |
| Re-binding with the same Intent and expecting `onBind` again | `IntentBindRecord` caches it; `onBind` runs once per filter-equal Intent while the service lives |
| Reporting "we added a check" without showing it refuse | Not evidence |
| Showing it refuse without showing it accept | Also not evidence |
| Concluding the manifest permission makes the method check redundant | Four ordinary ways the manifest gate evaporates — §5 |
| Reading the incoming `Parcel` inside an `onTransact` hook | Moves the read cursor and breaks the real dispatch. Hook the typed method instead |

---

## 9. Cleanup

```bash
# host
adb uninstall com.example.notesvault
adb uninstall com.pentest.ch28probe
adb shell "su -c 'pkill frida-server'"
rm -rf ~/ch28-lab03
```

---

## Next

[Lab 04 — Lifecycle, foreground, and the restart that did not happen](lab-04-lifecycle-and-foreground.md)
leaves identity behind and measures what the platform actually does to your
service when memory runs out — including one place where the textbook answer is
wrong on real hardware.
