# MultiProcessDemo — one app, one UID, two processes, two copies of every singleton

> A runnable app that splits itself with `android:process=":remote"` and then demonstrates the
> consequence people find hardest to believe: the two processes share a UID, share a data directory
> and share every file — but they do **not** share a singleton, a static field, or an
> `Application` object. Same sandbox, different memory.

**Belongs to:** [09 — Android App Internals](../../README.md) — see §3.18 (`android:process` and
multi-process apps) and §3.13 (Zygote)
**FAQ:** [`../../faq.md`](../../faq.md) — question 9 ("my app has three processes in `ps` but only
one UID, is that a sandbox violation?")

---

## 1. Why this exists

Two mistakes, one on each side of the fence, both caused by the same misunderstanding.

**The developer mistake:** treating a `object Session { var token: String? = null }` as app-global
state. It is process-global. Move one component into `:remote` and that component sees `null`
forever, while the main process sees a perfectly good token. The bug reproduces on some devices and
not others, because whether the second process is alive depends on memory pressure. Teams lose
weeks to this.

**The pentester mistake:** the mirror image. Seeing three processes in `ps` and writing "the app
runs multiple processes; the sandbox is fragmented" — or hooking a singleton in one process, seeing
the hook not fire, and concluding the code path is dead when it is running in the other
process. A Frida session attaches to **one PID**. `frida -U -f com.example.multiproc` gives you the
main process and nothing else.

> **Mental Model**
> One UID is one *tenant*. Processes are *rooms* that tenant rents. Every room has a key to the same
> filing cabinet in the hallway, so anything written down is shared. Nothing memorised in one room is
> known in another. `android:process` adds rooms. It does not add tenants.

The security statement, precisely: **`android:process` is a memory-management and crash-containment
tool, not a security boundary.** The exception is `android:isolatedProcess="true"`, which *is* one,
and which this demo deliberately does not use — see §7.

---

## 2. What is in this directory

The five files below ship in this directory and are the whole thing; §3 and §4 print each of them
verbatim, so you can read the demo without leaving this page. To run it, drop them into any
single-module Android project, or paste them into a new "No Activity" project in Android Studio.

| File | Role |
|---|---|
| `AndroidManifest.xml` | Declares `RemoteService` with `android:process=":remote"`. One attribute is the entire demo. |
| `DemoApplication.kt` | Logs its own process name in `onCreate()`. It will log **twice**, once per process. |
| `Counter.kt` | A Kotlin `object` — a textbook singleton — holding one mutable `Int`. |
| `MainActivity.kt` | Runs in the default process. Increments `Counter`, logs it, then starts the remote service. |
| `RemoteService.kt` | Runs in `:remote`. Logs *its* view of the same `Counter`. It will always say `0`. |

---

## 3. The manifest

```xml
<!-- examples/MultiProcessDemo/AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:name=".DemoApplication" android:label="Multi-Process Demo">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- The whole demo is this one attribute.
             A value starting with ":" is PRIVATE to this package: the real process name
             becomes com.example.multiproc:remote and no other package can ever join it.
             A value WITHOUT the colon is a global process name, which another package may
             join only if it has the same UID and the same signing certificate. -->
        <service
            android:name=".RemoteService"
            android:process=":remote"
            android:exported="false" />

    </application>
</manifest>
```

> **Warning**
> The leading colon is not cosmetic. `android:process="remote"` (no colon) declares a **global**
> process name. Combined with `sharedUserId` and a shared signing key, that is how two packages end
> up executing in one ART heap — see [`../../labs/lab-03-ctf-the-shared-uid-heist.md`](../../labs/lab-03-ctf-the-shared-uid-heist.md).
> When you are reading someone else's manifest, the presence or absence of that colon is the first
> thing to check.

---

## 4. The code

```kotlin
// examples/MultiProcessDemo/Counter.kt
package com.example.multiproc

/**
 * A textbook singleton. Exactly one instance... per PROCESS.
 * Two processes means two instances, two heaps, two values, no synchronisation between them.
 */
object Counter {
    var value: Int = 0
}
```

```kotlin
// examples/MultiProcessDemo/DemoApplication.kt
package com.example.multiproc

import android.app.Application
import android.os.Process
import android.util.Log
import java.io.File

class DemoApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        // This line appears TWICE in logcat, with two different PIDs and two different
        // process names, but the SAME uid and the SAME dataDir.
        Log.i(TAG, "APPLICATION onCreate  process=${processName()} " +
                   "pid=${Process.myPid()} uid=${Process.myUid()}")
        Log.i(TAG, "  dataDir  = ${applicationInfo.dataDir}")
        Log.i(TAG, "  Counter.value at Application start = ${Counter.value}")
    }

    companion object {
        const val TAG = "MultiProc"

        /**
         * The process's own name. Application.getProcessName() exists from API 28; reading
         * /proc/self/cmdline works everywhere and needs no version check, which is why the
         * chapter's tooling prefers it.
         */
        fun processName(): String = try {
            File("/proc/self/cmdline").readText().trim { it <= ' ' }
        } catch (e: Exception) {
            "(unknown)"
        }
    }
}
```

```kotlin
// examples/MultiProcessDemo/MainActivity.kt
package com.example.multiproc

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.widget.TextView

class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Counter.value += 1
        Log.i(DemoApplication.TAG, "MAIN     process=${DemoApplication.processName()} " +
              "pid=${Process.myPid()} uid=${Process.myUid()} Counter.value=${Counter.value}")

        // Write a file, so the NEXT section can show that the filesystem IS shared even
        // though memory is not.
        openFileOutput("shared.txt", MODE_PRIVATE).use {
            it.write("written by ${DemoApplication.processName()}\n".toByteArray())
        }

        // Starting the service forks a second process, because of one manifest attribute.
        startService(Intent(this, RemoteService::class.java))

        setContentView(TextView(this).apply {
            setPadding(48, 48, 48, 48)
            typeface = android.graphics.Typeface.MONOSPACE
            text = "main pid=${Process.myPid()} uid=${Process.myUid()}\n" +
                   "Counter.value here = ${Counter.value}\n\n" +
                   "adb logcat -d -s MultiProc -v time"
        })
    }
}
```

```kotlin
// examples/MultiProcessDemo/RemoteService.kt
package com.example.multiproc

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process
import android.util.Log
import java.io.File

class RemoteService : Service() {

    override fun onCreate() {
        super.onCreate()
        Log.i(DemoApplication.TAG, "REMOTE   process=${DemoApplication.processName()} " +
              "pid=${Process.myPid()} uid=${Process.myUid()} Counter.value=${Counter.value}")

        // Memory is NOT shared: Counter.value is 0 here no matter how many times the
        // activity incremented it.
        // Storage IS shared: the file the activity just wrote is readable, because both
        // processes run as the same UID against the same data directory.
        val f = File(filesDir, "shared.txt")
        Log.i(DemoApplication.TAG, "  filesDir      = $filesDir")
        Log.i(DemoApplication.TAG, "  shared.txt    = " +
              if (f.exists()) f.readText().trim() else "(missing)")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY

    // Not a bound service: returning null keeps this demo about processes, not about IPC.
    override fun onBind(intent: Intent?): IBinder? = null
}
```

---

## 5. Run and observe

```bash
# host
adb install -r app-debug.apk
adb logcat -c
adb shell am force-stop com.example.multiproc
adb shell am start -n com.example.multiproc/.MainActivity
adb logcat -d -s MultiProc -v time
```

### Expected output

```text
09-04 14:02:10.221 I/MultiProc: APPLICATION onCreate  process=com.example.multiproc pid=6120 uid=10234
09-04 14:02:10.222 I/MultiProc:   dataDir  = /data/user/0/com.example.multiproc
09-04 14:02:10.222 I/MultiProc:   Counter.value at Application start = 0
09-04 14:02:10.288 I/MultiProc: MAIN     process=com.example.multiproc pid=6120 uid=10234 Counter.value=1
09-04 14:02:10.402 I/MultiProc: APPLICATION onCreate  process=com.example.multiproc:remote pid=6158 uid=10234
09-04 14:02:10.403 I/MultiProc:   dataDir  = /data/user/0/com.example.multiproc
09-04 14:02:10.403 I/MultiProc:   Counter.value at Application start = 0
09-04 14:02:10.409 I/MultiProc: REMOTE   process=com.example.multiproc:remote pid=6158 uid=10234 Counter.value=0
09-04 14:02:10.410 I/MultiProc:   filesDir      = /data/user/0/com.example.multiproc/files
09-04 14:02:10.411 I/MultiProc:   shared.txt    = written by com.example.multiproc
```

Every important claim in this document is in those eleven lines.

| Observation | What it proves |
|---|---|
| `APPLICATION onCreate` appears **twice** | One `Application` object **per process**, not per app. Whatever you initialise there runs again. |
| `pid=6120` and `pid=6158` | Two real Linux processes, independently schedulable, independently killable. |
| `uid=10234` on **both** | One UID. One sandbox. The kernel cannot tell these two processes apart. |
| `dataDir` identical on both | Same private storage, same files, same permissions, same SELinux label. |
| `Counter.value=1` in main, `Counter.value=0` in remote | **Two separate singletons.** Separate class loaders, separate static state, separate ART heaps. |
| `shared.txt` readable from remote | The filesystem *is* the shared medium. Memory is not. |

Now re-launch the activity a few times without a `force-stop` and watch `Counter.value` climb in
`MAIN` while `REMOTE` reports `0` every single time. That divergence is the bug developers spend
weeks on.

---

## 6. What `ps` reveals

```bash
# adb shell
ps -A -o USER,PID,PPID,NAME | grep com.example.multiproc
```

```text
USER      PID   PPID  NAME
u0_a234   6120  1204  com.example.multiproc
u0_a234   6158  1204  com.example.multiproc:remote
```

Three things to read here.

**The `USER` column is identical.** `u0_a234` is Bionic's arithmetic rendering of UID 10234 — user
0, appId 10000 + 234 (see [`../../faq.md`](../../faq.md) question 1). Same string means same UID
means same sandbox.

**The `PPID` is identical, and it is not the main process.** PID 1204 is `zygote64`. The `:remote`
process was **not** forked from the app's main process; `ActivityManagerService` asked Zygote for it
independently. That is why the second process starts with a clean heap and re-runs
`Application.onCreate()` — it never inherited the first process's memory in the first place. See
§3.13 of the chapter.

**The name after the colon is the manifest value.** `:remote` in the manifest becomes
`com.example.multiproc:remote` on the process. This is how you read any app's manifest split from
the outside without decompiling it.

Add `-Z` to confirm the SELinux label matches too, categories and all:

```bash
# adb shell
ps -A -Z -o LABEL,USER,PID,NAME | grep com.example.multiproc
```

```text
u:r:untrusted_app:s0:c234,c256,c512,c768 u0_a234 6120 com.example.multiproc
u:r:untrusted_app:s0:c234,c256,c512,c768 u0_a234 6158 com.example.multiproc:remote
```

Identical domain, identical MLS categories — because the categories encode the appId and the userId,
and both processes have the same ones. Chapter 09 §3.2 and [`../../faq.md`](../../faq.md)
question 18 do that arithmetic. There is no SELinux boundary between these two processes either.

And the memory is genuinely separate at the kernel level:

```bash
# adb shell (root) — two distinct address spaces, two distinct heaps
cat /proc/6120/status | grep -E '^(Name|Uid|Gid|Groups|VmRSS)'
cat /proc/6158/status | grep -E '^(Name|Uid|Gid|Groups|VmRSS)'
```

`Uid` and `Groups` will match exactly. `VmRSS` will not, and neither will anything in
`/proc/<pid>/maps` beyond the shared read-only pages Zygote handed both children.

---

## 7. The security reading

**These two processes are not isolated from each other in any security-relevant way.** They hold the
same UID, therefore the same file access, the same supplementary GIDs, therefore the same
permissions, and the same SELinux context. Compromise either one and you have everything the app
has. Do not write a finding that says otherwise, and do not accept a developer's claim that
"the sensitive work is in a separate process" as a mitigation — ask which kind of separate process.

Because the correct answer is that there *is* a kind that mitigates:

| | `android:process=":remote"` | `android:isolatedProcess="true"` |
|---|---|---|
| UID | same as the app | fresh throwaway UID, 99000–99999 range |
| Access to the app's data dirs | full | **none** |
| Permissions | all the app's | none, not even `INTERNET` |
| SELinux domain | `untrusted_app` | `isolated_app` |
| Reachable Binder services | the app's full set | very few |
| Purpose | memory, crash containment, startup latency | **security boundary** |

That is how Chrome and the Android WebView sandbox their renderers. If you are auditing an app that
parses hostile input — media, archives, documents, embedded scripting — the *absence* of an isolated
process is a design observation worth writing down. If one is present, the interesting question
becomes what its `Service` interface accepts, because that binder interface is the only bridge out.
[21 — App Sandbox](../../../21-App-Sandbox/README.md) owns that analysis, and has a runnable
isolated-process lab; this chapter stops at "these two processes are the same principal".

### Consequences for your tooling

| Technique | What multi-process does to it |
|---|---|
| `frida -U -f <pkg>` | Attaches to the **main** process only. The `:remote` process spawns later and is not instrumented. Enumerate PIDs and attach to each, or hook the code path that starts the service. |
| A Frida hook that "does not fire" | Check whether the class runs in another process before concluding the path is dead. |
| `am force-stop <pkg>` | Kills **all** processes of the package. Killing a single PID leaves the others running — and the system may restart them. |
| `run-as <pkg>` | Works against the UID, so it reaches the data of every process equally. |
| Heap dumps (`am dumpheap`) | Per PID. A dump of the main process contains none of `:remote`'s objects. |
| `dumpsys meminfo <pkg>` | Reports each process separately; this is the usual way to spot a split without reading the manifest. |

### Finding the split statically

```bash
# host — every component that declares a process, in the MERGED manifest
aapt2 dump xmltree base.apk --file AndroidManifest.xml | grep -B 4 'android:process'
apktool d base.apk -o out && grep -n 'android:process' out/AndroidManifest.xml
```

```bash
# adb shell — what is actually running right now
dumpsys meminfo com.example.app | grep -i com.example.app
ps -A -o USER,PID,PPID,NAME | grep com.example.app
```

---

## 8. So how *do* the two processes share state?

They cannot share memory, so they must use IPC — and every option is a Binder transaction, a file,
or a socket:

| Mechanism | Notes |
|---|---|
| Bound `Service` + AIDL or `Messenger` | The normal answer. `onBind()` in this demo returns `null` precisely to keep the demo about processes. |
| `ContentProvider` | Providers are process-scoped too; a provider declared without `android:process` lives in the main process and both can reach it over Binder. |
| Files in the shared data directory | Works, needs your own locking, and is what `shared.txt` above demonstrates. |
| `SharedPreferences` with `MODE_MULTI_PROCESS` | **Deprecated and unreliable.** It does not synchronise; it re-reads on access. Do not build on it. |
| Broadcasts | Fine for notification, useless for state, and observable by anything holding the right permission. |

Notice what happened: the moment you split the process, ordinary field access became an IPC call —
with serialisation, a trust boundary you now have to reason about, and an interface an attacker can
enumerate. That is a real increase in attack surface even though it is not a decrease in privilege.

The mechanics of all of it belong to [24 — IPC](../../../24-IPC/README.md), and the transport
underneath every one of those options is Binder (chapter 25). Chapter 09's contribution is knowing
*why* IPC became necessary at all: one manifest attribute created a second address space.

---

## 9. What this demo does NOT show

- **Nothing about whether the split is exploitable.** It shows the two processes are one principal.
  Whether anything can reach that principal from outside is [21 — App Sandbox](../../../21-App-Sandbox/README.md).
- **No IPC.** `onBind()` returns `null` on purpose. For real cross-process communication, and for
  how to attack it, go to [24 — IPC](../../../24-IPC/README.md).
- **No isolated process.** §7 tabulates the difference but the demo does not build one; chapter 21
  has a lab that does.
- **Not a memory-savings measurement.** Splitting a process usually *costs* memory (a second ART
  heap, a second set of framework objects). The legitimate reasons are crash containment, releasing
  a heavy component's memory independently, and startup latency — not a smaller total footprint.
- **Nothing about process death ordering.** Which of the two `lmkd` kills first depends on
  `oom_score_adj`, which tracks each process's own importance independently. See §3.17 and
  [`../../faq.md`](../../faq.md) question 17.

---

## See also

- [`../../README.md`](../../README.md) — §3.13 Zygote, §3.17 process lifecycle, §3.18 `android:process`
- [`../../faq.md`](../../faq.md) — questions 9 and 19
- [`../StartupProviderPersistence/README.md`](../StartupProviderPersistence/README.md) — what runs *first* in each of these processes
- [`../AppIdentityProbe.kt`](../AppIdentityProbe.kt) — run it in both processes and diff the output
- [`../../scripts/app-identity-dump.sh`](../../scripts/app-identity-dump.sh) — its `=== processes ===` section lists exactly this split
- [`../../../21-App-Sandbox/README.md`](../../../21-App-Sandbox/README.md) — what the shared sandbox actually permits
- [`../../../24-IPC/README.md`](../../../24-IPC/README.md) — how the two processes have to talk once you split them
- [`../../../32-Manifest/README.md`](../../../32-Manifest/README.md) — the attribute itself, and manifest merging
