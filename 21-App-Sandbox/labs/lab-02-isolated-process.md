# Lab 02 — Isolated Versus Non-Isolated Processes

**Difficulty:** Intermediate
**Time:** 90 minutes
**Prerequisites:** [Lab 01](lab-01-mapping-the-sandbox.md),
[Chapter 21 §3.7 and §3.12](../README.md#37-isolatedprocess--the-strongest-sandbox-available-to-a-developer),
Android Studio or a working Gradle + Android SDK install, a device or emulator running Android 10 or
later.

---

## Objective

Build **one** application that runs three services in three different ways — one in the main process,
one with `android:process`, one with `android:isolatedProcess` — and prove empirically which of the
three is a security boundary and which two are not. You will produce a side-by-side table of exactly
what each process can reach, and be able to justify every cell from first principles.

## Why this matters

`android:process` and `android:isolatedProcess` differ by one word in a manifest and by an entire
security boundary in reality. This confusion appears in real reports in both directions: a tester
writes "the parser is isolated" after seeing `android:process` (a false negative — there is no
isolation at all), or a developer adds `android:process` believing they have hardened something.

It also matters on the constructive side. `isolatedProcess` is the strongest sandbox the platform
offers to an app developer, and when you find it in a target you should recognise it and say so. The
platform relies on it for its own highest-risk code: WebView renderer processes, and — in spirit, via
`minijail` — the media extraction and software-codec stack.

> **📖 Definition — `android:isolatedProcess`**
> A `<service>` attribute. When `true`, the platform runs that service in a process assigned a
> **throwaway UID** in the 99000–99999 range (or 90000–98999 when an App Zygote is used), in the
> SELinux domain `isolated_app`, with **every permission check denied**, no network access, no data
> directory of its own, and a very small allowlist of reachable Binder services. Its entire data
> interface is the Binder connection established by `bindService()` plus whatever file descriptors the
> host explicitly passes across it.

> **🧠 Mental Model**
> `android:process` is a *memory and lifecycle* tool: it buys you a crash boundary and the ability to
> free memory by killing a process. It buys you no isolation, because the new process has the same
> UID and can open every file the main process can. `android:isolatedProcess` is a *security* tool. The
> names being one word apart is a genuine usability failure of the platform, and it costs people real
> findings.

---

## Setup

Create a new empty Android project (Kotlin, minimum SDK 29, no template activity needed) with
application ID `com.example.sandboxlab`. You will add five files.

The runnable versions of the two main sources are in [`../examples/`](../examples/):

- [`RiskyParserService.kt`](../examples/RiskyParserService.kt)
- [`IsolatedProbeActivity.kt`](../examples/IsolatedProbeActivity.kt)
- [`SandboxIdentity.kt`](../examples/SandboxIdentity.kt)

Enable AIDL in `build.gradle`:

```groovy
// host — app/build.gradle
android {
    namespace 'com.example.sandboxlab'
    compileSdk 34
    defaultConfig { applicationId "com.example.sandboxlab"; minSdk 29; targetSdk 34 }
    buildFeatures { aidl true }
}
```

Declare `INTERNET`, so that the *absence* of network in the isolated process is attributable to
isolation rather than to a missing permission. This is the control in the experiment and it is easy to
forget:

```xml
<!-- AndroidManifest.xml -->
<uses-permission android:name="android.permission.INTERNET" />
```

---

## Steps

### Step 1 — Write one probe, used by all three processes

Create the AIDL interface. All three services will implement the *same* interface, so any difference
you observe comes from the process configuration and nothing else.

```aidl
// src/main/aidl/com/example/sandboxlab/IProbe.aidl
package com.example.sandboxlab;

interface IProbe {
    /** A human-readable report of what this process can reach. */
    String probeSandbox();

    /** Count lines in a file we did not open ourselves. */
    int countLines(in ParcelFileDescriptor pfd);
}
```

Then one probe implementation, shared by all three services:

```kotlin
// src/main/java/com/example/sandboxlab/Probe.kt
package com.example.sandboxlab

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.File
import java.io.FileInputStream

object Probe {

    fun report(ctx: Context, label: String): String = buildString {
        val uid = Process.myUid()
        appendLine("--- $label ---")
        appendLine("pid            = ${Process.myPid()}")
        appendLine("uid            = $uid")
        appendLine("appId          = ${uid % 100_000}")
        appendLine("isIsolated     = ${uid in 99_000..99_999 || uid in 90_000..98_999}")
        appendLine("selinux        = " + read("/proc/self/attr/current"))
        appendLine("groups         = " + statusLine("Groups"))
        appendLine("capBnd         = " + statusLine("CapBnd"))
        appendLine("seccomp        = " + statusLine("Seccomp"))

        // 1. Our host app's private data.
        val hostData = File("/data/data/com.example.sandboxlab")
        appendLine("hostData       = exists=${hostData.exists()} read=${hostData.canRead()}")

        // 2. A data directory of our own.
        appendLine("filesDir       = " + attempt { ctx.filesDir.absolutePath })

        // 3. Network. The host app HAS android.permission.INTERNET.
        appendLine("network        = " + attempt { java.net.Socket().use { "socket created" } })

        // 4. PackageManager — a Binder service.
        appendLine("packageManager = " + attempt {
            "${ctx.packageManager.getInstalledPackages(0).size} packages"
        })

        // 5. Another Binder service entirely.
        appendLine("clipboard      = " + attempt {
            ctx.getSystemService(Context.CLIPBOARD_SERVICE)?.javaClass?.simpleName ?: "null"
        })

        // 6. Shared storage.
        val ext = File("/storage/emulated/0")
        appendLine("sharedStorage  = exists=${ext.exists()} read=${ext.canRead()}")

        // 7. /proc visibility.
        appendLine("procEntries    = " +
            (File("/proc").list { _, n -> n.all(Char::isDigit) }?.size ?: -1))
    }

    fun countLines(pfd: ParcelFileDescriptor): Int =
        FileInputStream(pfd.fileDescriptor).bufferedReader().useLines { it.count() }

    private fun read(p: String) = runCatching { File(p).readText().trim(' ', '\n') }
        .getOrElse { "DENIED: ${it.javaClass.simpleName}" }

    private fun statusLine(key: String) = runCatching {
        File("/proc/self/status").readLines().first { it.startsWith("$key:") }
            .substringAfter(':').trim()
    }.getOrElse { "unreadable" }

    private inline fun attempt(block: () -> String) =
        runCatching(block).getOrElse { "DENIED: ${it.javaClass.simpleName}: ${it.message}" }
}
```

**Question 1.** Before you run anything: predict the value of each of the seven probes for each of the
three processes. Write your predictions down now — twenty-one cells. You will score them at the end,
and the ones you get wrong are the ones you actually learn from.

### Step 2 — Three services, three configurations, identical code

```kotlin
// src/main/java/com/example/sandboxlab/Services.kt
package com.example.sandboxlab

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.ParcelFileDescriptor

private fun stub(ctx: Service, label: String) = object : IProbe.Stub() {
    override fun probeSandbox(): String = Probe.report(ctx, label)
    override fun countLines(pfd: ParcelFileDescriptor): Int = Probe.countLines(pfd)
}

/** A. Same process as the app. */
class MainProcessService : Service() {
    override fun onBind(intent: Intent): IBinder = stub(this, "A: main process")
}

/** B. Separate process, SAME UID. */
class SeparateProcessService : Service() {
    override fun onBind(intent: Intent): IBinder = stub(this, "B: android:process")
}

/** C. Separate process, THROWAWAY UID. */
class IsolatedProcessService : Service() {
    override fun onBind(intent: Intent): IBinder = stub(this, "C: android:isolatedProcess")
}
```

The manifest is where the entire experiment lives:

```xml
<!-- AndroidManifest.xml — inside <application> -->

<!-- A. Nothing special. Runs in the app's main process, as the app. -->
<service android:name=".MainProcessService" android:exported="false" />

<!-- B. A SEPARATE PROCESS with the SAME UID. This is not isolation. -->
<service
    android:name=".SeparateProcessService"
    android:process=":worker"
    android:exported="false" />

<!-- C. A separate process with a THROWAWAY UID, no permissions, no data, no network. -->
<service
    android:name=".IsolatedProcessService"
    android:isolatedProcess="true"
    android:exported="false" />
```

> **⚠️ Warning**
> An isolated service **must** be `android:exported="false"` unless you have a very specific reason
> otherwise, and it must not be given an `intent-filter`. An exported isolated service is bindable by
> any app on the device — the isolation protects *you* from the code inside it, not the other way
> round.

### Step 3 — Bind all three and collect the reports

```kotlin
// src/main/java/com/example/sandboxlab/CompareActivity.kt
package com.example.sandboxlab

import android.app.Activity
import android.content.*
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File

class CompareActivity : Activity() {

    private val conns = mutableListOf<ServiceConnection>()

    private fun bind(cls: Class<*>) {
        val c = object : ServiceConnection {
            override fun onServiceConnected(n: ComponentName, b: IBinder) {
                val probe = IProbe.Stub.asInterface(b)
                probe.probeSandbox().lines().forEach { Log.i("SANDBOXLAB", it) }

                val input = File(filesDir, "input.txt").apply {
                    if (!exists()) writeText("alpha\nbeta\ngamma\n")
                }
                ParcelFileDescriptor.open(input, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                    Log.i("SANDBOXLAB", "countLines via passed FD = ${probe.countLines(pfd)}")
                }
                Log.i("SANDBOXLAB", "")
            }
            override fun onServiceDisconnected(n: ComponentName) {}
        }
        conns += c
        bindService(Intent(this, cls), c, Context.BIND_AUTO_CREATE)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i("SANDBOXLAB", Probe.report(this, "HOST: the activity itself"))
        bind(MainProcessService::class.java)
        bind(SeparateProcessService::class.java)
        bind(IsolatedProcessService::class.java)
    }

    override fun onDestroy() {
        super.onDestroy()
        conns.forEach { runCatching { unbindService(it) } }
    }
}
```

Run it:

```bash
# host
adb logcat -c
adb shell am start -n com.example.sandboxlab/.CompareActivity
adb logcat -s SANDBOXLAB:I
```

### Step 4 — Confirm from outside, at the kernel level

Do not trust the app's self-report alone. Look at the processes from the shell.

```bash
# adb shell
ps -A -o USER,PID,NAME | grep sandboxlab
# u0_a288  12401  com.example.sandboxlab
# u0_a288  12455  com.example.sandboxlab:worker
# u0_i17   12488  com.example.sandboxlab:...

ps -A -Z | grep sandboxlab
```

**Question 2.** How many distinct **UIDs** appear across the three processes? Which two share one, and
what does that tell you immediately about whether `android:process` is a boundary?

Now read the kernel's record for each, exactly as in Lab 01:

```bash
# adb shell
for P in $(pidof com.example.sandboxlab) $(pgrep -f 'sandboxlab:'); do
  echo "=== pid $P ==="
  grep -E '^(Uid|Groups|CapBnd|Seccomp|NoNewPrivs)' /proc/$P/status
  cat /proc/$P/attr/current; echo
done
```

**Question 3.** Compare the `Groups:` line of the isolated process against that of the main process.
Which GID is missing, and what does its absence make impossible? Is the resulting network behaviour a
*permission* denial or a *kernel* denial? How would you tell them apart from the exception you get?

### Step 5 — Prove the isolated process cannot reach the host's data

The isolated process reported `hostData: read=false`. Establish *why*, and rule out the boring
explanations.

```bash
# adb shell as root
ISO=$(pgrep -f 'sandboxlab' | tail -1)
ls -ldZ /data/data/com.example.sandboxlab
cat /proc/$ISO/attr/current
```

Compare the UID that owns the directory with the UID of the isolated process, and compare the MCS
category sets on the process context and the directory label.

**Question 4.** Two independent mechanisms deny this access. Name both, and say which one would still
deny it if the other were somehow defeated. Then answer a harder question: if the developer set the
data directory to mode `0777`, would the isolated process be able to read it?

### Step 6 — Prove the descriptor still works

The isolated process reported a successful `countLines` on a file it can neither name nor open.

**Question 5.** The isolated process cannot open anything in `/data/data/com.example.sandboxlab`, yet
it successfully read a file that lives there. Explain precisely why, in terms of *when* the kernel
performs its permission check. Then state the general security lesson, and name the vulnerability class
in §3.15 that it corresponds to.

### Step 7 — What can the isolated process reach over Binder?

```bash
# adb shell as root
ls -l /proc/$ISO/fd | head -30
cat /proc/$ISO/maps | grep -c .
```

And from the report, look at the `packageManager` and `clipboard` lines.

**Question 6.** `Context.getSystemService(CLIPBOARD_SERVICE)` behaved differently from
`packageManager.getInstalledPackages()`. One threw, one may have returned an object that then failed on
use. Explain why "the service manager gave me a handle" is not the same as "I can use the service",
and what that means for how you should write a probe.

### Step 8 — Add the App Zygote and observe the UID range change

```xml
<service
    android:name=".IsolatedProcessService"
    android:isolatedProcess="true"
    android:useAppZygote="true"
    android:exported="false" />
```

Rebuild, reinstall, re-run.

```bash
# adb shell
ps -A -o USER,PID,NAME | grep sandboxlab
```

**Question 7.** The isolated process's UID moved into a different range. Which one, and why does the
platform bother distinguishing App-Zygote-spawned isolated processes from ordinary ones? What does the
App Zygote buy a developer, and what does it *not* change about the sandbox?

### Step 9 — Now break it deliberately

Change service C from `android:isolatedProcess="true"` to `android:process=":parser"`. Rebuild, re-run,
and diff the report.

**Question 8.** Produce the diff. How many of the twenty-one cells changed? Which ones? If a report
claimed "the parser runs in an isolated process" on the basis of the manifest attribute
`android:process=":parser"`, exactly what would be wrong with that claim?

### Step 10 — Fill in the table

| Probe | A: main process | B: `android:process` | C: `android:isolatedProcess` |
|---|---|---|---|
| UID | | | |
| SELinux context | | | |
| `Groups:` contains 3003 | | | |
| Host app's `/data/data` readable | | | |
| Own `filesDir` | | | |
| `new Socket()` | | | |
| `PackageManager` usable | | | |
| Clipboard service usable | | | |
| Shared storage readable | | | |
| `/proc` entries visible | | | |
| `countLines` via passed FD | | | |
| **Is it a security boundary?** | **No** | | |

**Question 9.** Score your Step 1 predictions. For every cell you got wrong, write one sentence saying
which mechanism you had misattributed.

**Question 10.** A developer comes to you with a native library that parses user-supplied PDF files and
asks where to run it. Write the three-sentence answer you would give, including what has to change in
their code (not just the manifest) and what residual risk remains after they do it.

---

## Hints

<details>
<summary>Hint 1 — the isolated service will not start</summary>

Common causes, in order of likelihood:

- The service has an `intent-filter` or `android:exported="true"`. Remove both.
- You are binding with an implicit `Intent`. Isolated services must be bound explicitly by
  `ComponentName` or class.
- You forgot `Context.BIND_AUTO_CREATE`.
- Your `Service` subclass touches something in `onCreate` that is unavailable in `isolated_app` and
  crashes before `onBind`. Check `logcat` unfiltered — the crash will not appear under your tag.

```bash
# host
adb logcat -c && adb shell am start -n com.example.sandboxlab/.CompareActivity && adb logcat -v threadtime | grep -iE 'sandboxlab|AndroidRuntime|avc'
```
</details>

<details>
<summary>Hint 2 — the isolated process crashes on <code>ctx.filesDir</code></summary>

Expected, and it is a result rather than a bug: the platform never created a data directory for this
UID. That is why every probe in `Probe.report` is wrapped in `attempt { }`. If you write a probe that
lets the first denial throw, you measure exactly one cell and lose the other twenty.

Design principle for every probe you ever write: **each check independently guarded, each result
recorded, never abort on the first denial.**
</details>

<details>
<summary>Hint 3 — the two non-isolated services report the same UID and you think you made a mistake</summary>

You did not. That *is* the finding. `android:process` creates a new process with the same UID, the same
supplementary groups, the same SELinux domain, the same MCS categories, and the same access to the same
data directory. The only things it separates are address space and lifecycle.
</details>

<details>
<summary>Hint 4 — <code>pgrep -f</code> is missing on your device</summary>

Older or minimal builds may not have it. Use:

```bash
# adb shell
ps -A -o USER,PID,NAME | grep sandboxlab
```

and read the PIDs off manually. `ps -A -Z` additionally prints the SELinux context, which is what you
actually want for step 4.
</details>

<details>
<summary>Hint 5 — <code>logcat</code> shows nothing from the isolated process</summary>

Isolated processes can normally still write to the log, but if yours cannot on your build, route the
report back to the host over the Binder call instead of logging from inside — which is what
`probeSandbox()` returning a `String` is for. The host logs it. That is deliberate design in this lab:
never depend on a channel the isolated process may not have.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** Predictions vary; the point is to have made them. The two cells most people get wrong are
(a) the isolated process's ability to read shared storage — no, and not because of a permission but
because policy and the missing storage GIDs both stop it; and (b) `countLines` via a passed
descriptor, which **succeeds**, and surprises people who have internalised "isolated means it can't
read anything".

**2.** Two distinct UIDs. A and B share the app's UID (10xxx). C has a throwaway UID in 99000–99999 (or
90000–98999 after step 8). A shared UID means a shared sandbox: `android:process` is a memory and
lifecycle boundary, not a security boundary. There is nothing B can be prevented from doing that A can
do, because the kernel cannot tell them apart.

**3.** GID **3003** (`AID_INET`) is missing from the isolated process. Its absence makes creating an
`AF_INET` or `AF_INET6` socket impossible.

It is a **kernel** denial, not a framework permission denial, and you can tell from the exception: the
failure surfaces as `SocketException: socket failed: EACCES (Permission denied)` originating in the
`socket()` syscall itself, *before* any DNS resolution or connection attempt. A framework permission
denial would be a `SecurityException` thrown by a check in `system_server` or in the app's own process,
and would name the permission. Two other things also block network here — the `isolated_app` policy
denies socket creation outright — but the missing GID alone would be sufficient.

**4.** DAC and SELinux. DAC: the directory is mode `0700` owned by UID 10xxx, and the isolated process
is UID 99xxx, so it falls in the "other" class with no bits — it cannot even traverse into the
directory. SELinux: the `isolated_app` domain has no `allow` rule to read `app_data_file` at all, and
even if it did, the MCS categories would not dominate.

Either one alone would deny the access. They run in series — DAC in the VFS, SELinux in the LSM hook —
so defeating one leaves the other standing.

The harder question: **no.** With mode `0777` the DAC check would pass, but SELinux would still refuse,
because `isolated_app` has no rule permitting it to read `app_data_file`. This is precisely the value
of MAC over DAC — the owner cannot hand out access at their discretion. It is also the reason a
mode-`0666` file inside a `0700` directory is not an app-to-app finding, and why you must name the
right mechanism when you write the result up.

**5.** Because the kernel checks permissions **at `open()` time, in the opening process** — and then
never again. The host activity, running as UID 10xxx with full access to its own data directory, called
`ParcelFileDescriptor.open()`. That `open()` succeeded on the host's authority. The resulting file
description was then transferred across the Binder transaction (ultimately via `SCM_RIGHTS` on the
underlying transport), and the isolated process received a descriptor into an already-open file. Reads
through that descriptor are not rechecked against the receiver's UID, SELinux context, or anything
else.

The general lesson: **a file descriptor is access that has already been granted, and it travels.** The
corresponding vulnerability class is §3.15 Class 5, file-descriptor leaks across the boundary — the
same mechanism that makes a `ContentProvider.openFile()` path traversal so damaging, since the
*provider* opens the file with the provider's authority and hands back a working descriptor. Here the
mechanism is used correctly and deliberately, and it is exactly what makes `isolatedProcess` usable at
all: without FD passing you could not give a parser anything to parse.

**6.** `ServiceManager` handing back a Binder handle is a *lookup*, and the isolated process is allowed
to look up a small set of services. Whether a *transaction* on that handle succeeds is decided
separately — by the service's own `Binder.getCallingUid()` checks, by the framework's permission
checks, and by SELinux rules on the `binder` class. So you can hold a `ClipboardManager` object and
still get a `SecurityException` on every method you call, and `getSystemService` returning non-null
tells you nothing.

For probe design this means: **never report reachability from object construction or service lookup.**
Perform a real operation and record what came back. This is the same discipline as the five-verdict
vocabulary in [24-IPC's probe app](../../24-IPC/examples/attacker-app/README.md) — an `ERROR` after the
door opened is a completely different result from a `DENIED` at the door.

**7.** It moves into **90000–98999** (`FIRST_APP_ZYGOTE_ISOLATED_UID`–`LAST_APP_ZYGOTE_ISOLATED_UID`).
The platform distinguishes them so that `ps` output, policy and accounting can tell an App-Zygote child
from a main-Zygote child; they have slightly different provenance and the App Zygote itself is a
process that must be tracked and torn down.

What it buys: a per-app Zygote, itself isolated, into which the app preloads shared state via
`android.app.ZygotePreload`. All that app's isolated processes then fork from it and share the
preloaded pages copy-on-write. For something like a browser or media app spawning many isolated
workers that all need the same large native library, that is a substantial memory and startup win.

What it does **not** change: the sandbox. An App-Zygote-spawned isolated process has the same absence of
permissions, network, and data directory, and the same `isolated_app` domain. It is a performance
feature, not a security one.

**8.** Typically ten to twelve cells change: the UID returns to the app's, the SELinux context becomes
`untrusted_app`, `Groups:` regains 3003, `hostData` becomes readable, `filesDir` works, the socket
succeeds, `PackageManager` and the clipboard work, shared storage becomes readable. Only `pid` and the
FD-passing result stay the same.

The claim would be wrong because `android:process=":parser"` provides **no isolation whatsoever**. The
parser process holds the app's UID, so a memory-corruption bug in it yields the app's full identity:
its data directory, its granted permissions, its network access, its signed-in session. The only thing
gained is that a crash does not take down the UI. Reporting that as isolation is a false negative that
tells the client they are protected when they are not — which is worse than reporting nothing.

**9.** Self-scored. The two systematic errors worth naming if you made them: attributing a denial to
"the permission was not granted" when it was actually SELinux or a missing GID, and attributing a
*success* to weak sandboxing when it was actually a deliberately passed file descriptor.

**10.** Something close to:

> "Run the PDF parser in a service declared with `android:isolatedProcess="true"` and
> `android:exported="false"`, and if you will spawn several of them, add `android:useAppZygote="true"`
> so they share your preloaded native library. Your code has to change too: the parser cannot open
> files, reach the network, or use any permission, so the host must open the input itself and pass a
> read-only `ParcelFileDescriptor` across the Binder interface, and the parser must return only a
> parsed result — never a path, never a handle to anything the host will then blindly trust. The
> residual risk is that an attacker who achieves code execution inside the isolated process can still
> attack *you*: they control the parsed result you get back, so treat that return value as untrusted
> input, and they can still attempt a kernel bug from `isolated_app`, which is a much narrower surface
> than `untrusted_app` but is not zero."

</details>

---

## Success criteria

- [ ] You wrote down twenty-one predictions before running anything
- [ ] All three services run the same probe code, so every difference is attributable to configuration
- [ ] You confirmed from `ps` that two of the three processes share a UID
- [ ] You read `Uid`, `Groups`, `CapBnd`, `Seccomp` and `attr/current` for all three from `/proc`
- [ ] You identified GID 3003 as absent from the isolated process and can classify the resulting network
      failure as a kernel denial rather than a framework denial
- [ ] You named **both** mechanisms that deny the isolated process access to the host's data directory,
      and can say which survives if the other is defeated
- [ ] You can explain why mode `0777` on the data directory would still not help it
- [ ] You explained the successful `countLines` in terms of when the kernel performs its check, and
      linked it to escape class 5
- [ ] You observed the UID range change when `useAppZygote` was added, and can say what it does and does
      not change
- [ ] You produced the twelve-row comparison table and scored your predictions
- [ ] You can state the difference between `android:process` and `android:isolatedProcess` in one
      sentence, and say what is wrong with a report that confuses them
- [ ] You wrote the developer-facing recommendation, including the code change and the residual risk
