# 24 — IPC · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. What actually *is* IPC? When my code calls a method, isn't that communication between things?**

It is communication, but not *inter-process* communication. A normal method call happens inside one
process: the caller and the callee share the same memory, so passing an object means passing a
pointer to memory both of them can already read.

IPC is what you need when the two parties are in **different processes**, which on Android means
different UIDs with completely separate memory. Neither can touch the other's memory, so the data has
to be copied across by the only component that can see both: the kernel.

That is the whole reason this chapter is long. Every IPC mechanism is a hole punched through the
sandbox, and every hole needs somebody checking who comes through it.

---

**2. People keep saying "it goes over Binder" like it explains something. What is Binder, physically?**

A character device — a file — at `/dev/binder`, backed by a driver in the kernel.

A process opens it, `mmap`s a buffer, and then calls `ioctl(fd, BINDER_WRITE_READ, …)` to send and
receive. The driver copies your message into the *target* process's buffer, stamps it with your UID
and PID taken from the kernel's own record of your task, and wakes a thread in the target.

You can see it:

```bash
# adb shell as root
ls -l /proc/$(pidof -s com.example.app)/fd | grep binder
```

Everything mediated — every Intent, every `ContentResolver` call, every `bindService`, every
`getSystemService` call you have ever written — travels that way. See
[25-Binder](../25-Binder/README.md).

---

**3. What does `android:exported="true"` mean, in one sentence?**

"Any other application may start or access this component."

`exported="false"` means only components running under the *same UID* may reach it. That is not the
same as "only my code", which is the subject of question 14.

---

**4. My component has no `android:exported` attribute at all. Is it exported?**

It depends on the app's `targetSdk`, which is why that is always the first thing you check.

| Situation | Effective state |
|---|---|
| Has an `<intent-filter>`, `targetSdk` ≤ 30 | **Exported** — this is the classic accidental export |
| No `<intent-filter>`, `targetSdk` ≤ 30 | Not exported |
| Any component with an `<intent-filter>`, `targetSdk` ≥ 31 | The attribute is **mandatory**; the app would not have built without it |
| `ContentProvider`, `targetSdk` ≤ 16 | **Exported by default even with no filter** |

```bash
# host
aapt2 dump badging app.apk | grep -E "targetSdkVersion|sdkVersion"
```

A low `targetSdk` on a modern app is itself worth reporting, because it opts the app out of a decade
of platform hardening.

---

**5. I ran `am start -n pkg/.Activity` from `adb shell` and it launched. Is that a finding?**

**No. Not yet.** This is the single most common reason Android IPC findings get rejected, and it is
worth internalising before anything else in this chapter.

`adb shell` runs as the Linux user `shell`, **UID 2000**, in the SELinux domain `shell`. That is not
an application. It holds capabilities and SELinux permissions no installed app has. Components you
can start from the shell may be completely unreachable by a malicious app.

What you have proved is "the mechanism works". What you need to prove is "an ordinary app can do
it". Reproduce it from something that runs as an app UID:

```bash
# host
gradle -p examples/attacker-app assembleDebug
adb install -r examples/attacker-app/build/outputs/apk/debug/attacker-app-debug.apk
adb shell am start -n com.attacker.poc/.ProbeActivity --es target com.example.target
adb logcat -s poc:I
```

Then record **both** results side by side. Something reachable from `shell` but not from the app is a
shell privilege, not an app vulnerability — and saying so is what makes your other findings
believable. Full drill: [77-UsefulCommands lab 03](../77-UsefulCommands/labs/lab-03-exported-sweep.md).

---

**6. Why bother with Drozer or a custom APK if `adb shell` can do the same commands more easily?**

Because of question 5. Drozer's agent is an ordinary installed application with an ordinary UID, so
when Drozer can do something, a malicious app can do it. That is the entire value proposition; the
convenient module syntax is a bonus.

If Drozer will not run on your Android version — which happens, the agent needs a modern build for
API 30+ — the fallback is [`examples/attacker-app/`](examples/attacker-app/README.md), which is a few
hundred lines you can read in full and hand to a client engineer.

---

**7. My probe app reports the target as "not installed", but it definitely is. What is going on?**

You are on Android 11 or later and your manifest has no `<queries>` block.

From `targetSdk` 30, **package visibility filtering** means an app cannot see every installed package
by default. The symptoms all look like absence rather than filtering, which is what makes it so
misleading: `getPackageInfo()` throws `NameNotFoundException`, `resolveActivity()` returns `null`,
`startActivity()` throws `ActivityNotFoundException`, and a provider query throws
`IllegalArgumentException: Unknown URL`.

```xml
<queries>
    <package  android:name="com.example.target" />
    <provider android:authorities="com.example.target.provider" />
</queries>
```

Providers need the `<provider>` entry as well as the `<package>` one — declaring the package alone
does not let you resolve a `content://` URI.

This is a privacy control, not a security boundary: a real attacker just declares the target. But if
*you* forget it, you will write "no exported components are reachable from a third-party app" in a
report and be wrong because of your own manifest.

---

**8. `LocalServerSocket` has "Local" in the name. Surely that means private?**

No, and this is probably the highest-value misconception in the chapter.

`android.net.LocalSocketAddress` has three namespaces — `ABSTRACT`, `RESERVED` and `FILESYSTEM` — and
the **single-argument constructor selects `ABSTRACT`**. An abstract-namespace UNIX socket is named by
a string in a kernel-global namespace, not by a filesystem path.

Read the consequence slowly:

> It has **no inode**. It has **no owner and no group**. It has **no mode bits** — there is not even
> a permission to get wrong. No directory permission protects it, because it is in no directory.

Any process in the same network namespace — on Android, every app on the device — can `connect()` to
it if it knows or guesses the name, subject only to SELinux.

```bash
# adb shell — the fastest check on any device
cat /proc/net/unix | grep '@'
```

Anything with an `@` is world-reachable. The `@` *is* the finding.

---

**9. So a filesystem UNIX socket is safe?**

It *can* be. A filesystem socket is a real file: owner, group, mode bits, SELinux label, and the
permissions of every directory on the path. A socket created inside `/data/data/<pkg>/` is genuinely
private, because no other app can traverse that directory. That is a correct design and worth saying
so in a report.

It stops being safe when it is created somewhere else, or chmod'ed to `0666` by a native helper so
that "the app can reach it" — which also lets everything else reach it. Check the mode:

```bash
# adb shell
ls -lZ /dev/socket
```

---

**10. An app is listening on `127.0.0.1`. Isn't loopback private by definition?**

No. Loopback is a *network interface*, so the ordinary network permission model applies — and the
only permission needed is `INTERNET`.

`INTERNET` is `protectionLevel="normal"`. It is granted automatically at install time, it is never
shown to the user, and essentially every app on every device holds it. So **"we only listen on
localhost" means "we listen to every app on the device"**.

Also check what it is actually bound to. `new ServerSocket(8081)` and `NanoHTTPD(8081)` both bind
**0.0.0.0** — all interfaces — by default, so the same server is often reachable from the WiFi
network too. That escalates the finding, because the attacker no longer needs to be on the device.

```bash
# adb shell
cat /proc/net/tcp | awk 'NR>1 && $4=="0A"'
# host — from your laptop on the same network
curl -s http://<device-ip>:8081/
```

---

**11. Is a "normal" protection-level permission a security control?**

No. Any app can request a `normal` permission in its manifest and the system grants it silently at
install with no user prompt. A component guarded by one is guarded by nothing.

| Level | Granted to | Real control? |
|---|---|---|
| `normal` | Anyone who asks, silently | **No** |
| `dangerous` | After a user prompt | Weak — a malicious app asks, and users tap Allow |
| `signature` | Only apps signed with the same certificate | **Yes** |

When you see `android:permission="com.example.app.permission.INTERNAL"` on an exported component,
your next command is:

```bash
# adb shell
dumpsys package permission com.example.app.permission.INTERNAL | grep -i protection
```

If it says `normal`, treat the component as unguarded.

---

**12. What is the confused deputy, in plain English?**

A program that holds authority is tricked by a less-privileged party into using that authority on the
less-privileged party's behalf.

The original 1988 example: a compiler on a shared system could write to a billing file. It also
accepted an output filename from whoever ran it. A user who could not write the billing file
asked the compiler to write its output there. The compiler was not malicious and was not
compromised. It was *confused* about whose authority it was exercising.

On Android the deputy is an exported component that does something with an Intent, a `Uri`, or a
`PendingIntent` it received from a caller. Section 3.20 works it through end to end.

---

**13. Why can a "non-exported" activity still be started?**

Because the framework's check is on the **UID making the call**, and there is a rule that says: if
the caller's UID equals the component's owning UID, allow.

That rule is what makes same-app components able to reach each other. It is also what an attacker
borrows: if any *exported* component of the app calls `startActivity()` on an Intent the attacker
supplied, that call originates inside the app's own process with the app's own UID, and the
non-exported target is reachable.

**`exported="false"` protects against other apps. It does not protect against your own app being
used as a proxy.**

---

**14. My scanner reported forty intent-redirection issues. How do I know which are real?**

By walking the reach-through, which is the part no tool does for you. For each one, enumerate what
the forwarded Intent can actually reach:

| Reached target | Severity |
|---|---|
| A URI grant on a non-exported provider holding credentials | **High–Critical** |
| An internal WebView that then loads your URL with the app's cookies | **High–Critical** |
| A non-exported activity that displays or modifies user data | **High** |
| A non-exported activity with no sensitive function | Low–Medium |
| **Only components that were already exported** | **Not a finding — say so** |

That last row is most of the forty. Reporting them costs you credibility, and credibility is the
thing that makes your genuine High findings get fixed.

---

**15. Why is `getCallingUid()` safe to authorise on but `getCallingPid()` not?**

`getCallingUid()` returns a **UID**, which is a property of the app's *installation*. It is assigned
at install time, does not change, and — this is the part that matters — the binder driver copies it
out of the calling task's kernel-held credentials, not out of the message. There is nothing in the
parcel a caller could alter to change it.

`getCallingPid()` returns a **PID**, which identifies a *running process*. It is truthful at the
instant the driver stamped it, but processes are short-lived and Linux recycles PID numbers. The
dangerous shape is not reading the PID but reading it and then **looking something up with it**:

```java
// VULNERABLE — classic PID-reuse race
int pid = Binder.getCallingPid();
String name = readAll(new File("/proc/" + pid + "/cmdline"));
if ("com.example.trusted".equals(name.trim())) { doPrivilegedThing(); }
```

Between the transaction arriving and that file being read, the caller may have exited and the number
been reused by something else. Use the PID for log lines. Never for a decision.

---

**16. Can an app spoof its UID over Binder?**

No. That is the one thing you can rely on. The value is taken from the kernel's record of the calling
task, so a caller can neither set it nor cause a different one to be reported.

Everything *else* about the caller is spoofable, including any "who am I" field the caller puts in an
Intent extra, a `Bundle`, or a socket message. If an app authenticates on
`intent.getStringExtra("caller_package")`, that is not authentication.

---

**17. I don't write system services. Do I care about `clearCallingIdentity`?**

Less than a platform engineer does, but not zero. It shows up in third-party apps that host an AIDL
service for a companion app, and it is everywhere in OEM and preinstalled APKs — which are exactly
the targets where borrowed authority is worth having.

The four patterns, and the three questions that find all of them:

1. Was the caller's identity checked **before** the clear? (If not: the check compares the service
   with itself and always passes.)
2. How much code runs inside the cleared window, and does any of it act on caller-supplied data?
3. Is the restore inside a `finally`? (If not, an exception leaks elevated identity onto a **pooled**
   binder thread, and the *next*, unrelated transaction inherits it.)

```bash
# host — read every hit, every time
grep -rn -A20 "clearCallingIdentity" out/sources/
```

Or watch it live with [`scripts/hook-binder-identity.js`](scripts/hook-binder-identity.js).

---

**18. Why is checking the caller's *package name* wrong? Package names are unique on Play.**

Unique on Play, yes. Not unique on a device that also installs from other sources, and not what you
actually want to know anyway.

What you want to know is "is this the app I trust", and the durable answer to that is the **signing
certificate**, not the name:

```java
if (getPackageManager().checkSignatures(getPackageName(), callerPkg)
        == PackageManager.SIGNATURE_MATCH) { /* same key */ }
```

Better still on API 28+, `PackageManager.hasSigningCertificate()` with a pinned digest, so a key
rotation becomes an explicit decision rather than a silent one.

---

**19. `sendBroadcast()` returned without an exception, so the receiver ran, right?**

No. `sendBroadcast()` is fire-and-forget. It returns normally even when nothing was permitted to run,
so "no exception" is not evidence of anything.

Get real evidence one of two ways. Use an ordered broadcast with a result receiver:

```java
sendOrderedBroadcast(i, null, new BroadcastReceiver() {
    @Override public void onReceive(Context c, Intent in) {
        Log.i(TAG, "result=" + getResultCode() + " data=" + getResultData());
    }
}, null, 0, null, null);
```

Or watch the **target's** own logcat:

```bash
# host
adb logcat --pid=$(adb shell pidof -s com.example.target | tr -d '\r') -v threadtime
```

---

**20. My exported service throws `SecurityException` when I bind. Does that mean it is secure?**

It means *that* attempt was refused. It does not mean the component is safe. Check, in order:

- Is the guarding permission `normal`? Then just declare it in your probe app's manifest and try
  again — you will be granted it silently.
- Is it `dangerous`? Then request it at runtime; a real malicious app would.
- Did you get the component name exactly right? A typo produces the same-looking failure.
- Is package visibility filtering hiding the target? (Question 7.)
- Is a *different* service, or a different transaction code on the same one, unguarded?

"I got an exception once" is not a conclusion.

---

**21. My app targets API 33. Am I safe from all of this?**

You are safe from a specific list of *accidents*, not from the class of problem.

`targetSdk` 31+ makes `android:exported` mandatory, so no more accidental exports. 31+ makes
`PendingIntent` mutability explicit. 33 makes runtime receiver export explicit. 34 stops implicit
intents reaching non-exported components. All genuinely valuable.

None of it touches: an exported component you exported deliberately and then trusted its input; an
abstract socket; a localhost server; a provider with SQL injection; a missing `getCallingUid()` check
in an AIDL method; or intent redirection. The platform fixed the accidents. The decisions are still
yours.

---

**22. Do I need a rooted device to test IPC?**

For the *app-level* work, no — and that is the point. Everything an attacker can do, they do from an
ordinary unrooted app: start exported components, query providers, connect to abstract sockets, hit
localhost, register broadcast receivers. Your proof-of-reachability APK needs no root at all.

Root helps for *enumeration*: reading `/proc/<pid>/fd` to attribute a socket to a process, listing
`/data/data/<pkg>` file modes, reading `/sys/kernel/debug/binder/`. Useful for finding things, never
required for proving them.

---

**23. Nothing appears in `/proc/net/unix` for my target. Does it have no sockets?**

Most likely the app has not run the code path yet. Sockets are usually opened lazily — on first
playback, first WebView load, first sync. Launch the app, use it for a minute, and look again:

```bash
# host
adb shell monkey -p com.example.target -c android.intent.category.LAUNCHER 1
sleep 8
adb shell "cat /proc/net/unix | grep '@'"
```

Also take a before/after diff around a specific feature — that is how you attribute a socket to a
feature rather than to the app in general. And remember `/proc/net/unix` does not name the owning
process; you match the **inode** column against `ls -l /proc/<pid>/fd`.

---

**24. Is the clipboard still worth testing after Android 10 restricted it?**

Yes, in both directions, though the severity changed.

**Writing:** an app that puts an OTP, a password or a recovery phrase on the clipboard has placed a
secret into a system-wide buffer. On API ≤ 28 any installed app reads it at will. On 29+ whatever app
the user focuses next reads it — which is exactly the app an attacker would like you to focus.

**Reading:** an app that reads a pasted crypto address or account number is reading data an attacker
may have planted. "Clipper" malware is a well-documented family. The defence lives on the consuming
side: show the full value and require explicit confirmation.

---

**25. Can I do all this on an emulator?**

Mostly yes, and an emulator is excellent for the mechanics: exported components, providers, sockets,
localhost, redirection. Two caveats.

First, SELinux policy and vendor customisations differ, and SELinux is precisely what decides whether
`untrusted_app` may reach a given socket. A negative result on an emulator is weaker evidence than a
negative result on the device family the client actually ships to.

Second, findings are `targetSdk`- and version-sensitive. Test on each Android version in scope and
say which one each result came from.

---

**26. What is the single highest-yield thing to do in the first ten minutes of an app assessment?**

Two commands and one script.

```bash
# host — the ground truth that decides which rules apply
aapt2 dump badging app.apk | grep -E "package|targetSdkVersion"

# adb shell — the channels no manifest tool will ever show you
cat /proc/net/unix | grep '@'
```

then

```bash
# host
./scripts/enumerate-ipc-surface.sh com.example.target
python3 scripts/ipc-surface-report.py ./ipc-surface-com.example.target/ipc-surface.txt --md report.md
```

And if you have Drozer running, `run scanner.provider.injection -a <pkg>` and
`run scanner.provider.traversal -a <pkg>` are the two highest-value commands in the entire tool.

---

**27. I found an abstract socket. It replies `{"status":"ok","version":"2.1"}` and nothing else. What severity?**

**Low**, reported as attack-surface reduction rather than as a vulnerability.

The mechanism is fascinating and the exposure is real — every app on the device can reach it with no
permission at all. But severity comes from what the channel *exposes*, and a version string exposes
nothing. Write it up honestly: state the name, state what the protocol does, state what you tried and
could not make it do.

Inflating this to Critical because the mechanism is exciting is the fastest way to have your genuine
Critical findings argued down alongside it.

---

**28. A tool told me the app "uses insecure IPC". How do I turn that into something a developer will fix?**

Give them, for that one channel: the exact code path, the exact request you sent, the observable
result, the identity you sent it from (an app UID, not the shell), the device fingerprint and
`targetSdk` it was proved on, what an attacker gains, and the fix **as code**.

The fix-as-code part is what gets things closed. "Validate untrusted input" is ignored. This is not:

```java
// Do not accept an Intent from a caller. Accept a token and build it yourself.
String dest = getIntent().getStringExtra("next");
Intent next;
switch (dest == null ? "" : dest) {
    case "gallery":  next = new Intent(this, GalleryActivity.class); break;
    case "settings": next = new Intent(this, SettingsActivity.class); break;
    default:         next = new Intent(this, HomeActivity.class);
}
startActivity(next);
```

---

**29. What is the difference between "mediated" and "direct" IPC, and why do you keep repeating it?**

Because it decides what protections exist and how you have to test.

**Mediated** IPC — Intents, providers, broadcasts, bound services — passes through `system_server`.
The framework can therefore enforce policy: it checks `exported`, it checks `android:permission`, it
checks URI grants, it can refuse. It is visible in the manifest and in `dumpsys`.

**Direct** IPC — UNIX sockets, localhost TCP, shared files, shared memory — does not involve the
framework at all. There is no `exported` attribute, no `android:permission`, no `dumpsys` entry, and
no manifest-reading tool that will ever see it. The only controls are Linux DAC and SELinux, and for
abstract sockets DAC does not apply at all.

If your methodology is "run MobSF and read the exported-components table", you miss the entire second
category — and that is where a large share of the interesting findings live.

---

**30. There is so much here. What do I have to remember if I remember nothing else?**

Five things.

1. The attacker is an ordinary app the user installed, with no permissions. Trying every door costs
   them nothing.
2. The receiving side always acts with **its own** authority. That is the confused deputy, and it is
   the root of most high-severity app findings.
3. `LocalServerSocket("name")` and `127.0.0.1` are reachable by every app on the device. Neither
   appears in any manifest.
4. Authorise on `getCallingUid()`. Log on `getCallingPid()`. Only `signature` permissions are
   controls.
5. Prove it from an app, not from `adb shell`, and rate severity by what the door leads to.
