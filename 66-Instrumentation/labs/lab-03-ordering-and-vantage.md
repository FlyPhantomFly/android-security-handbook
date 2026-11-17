# Lab 03 — Ordering, vantage, and the two traps

> **Objective.** Measure, to sub-millisecond resolution on a real device, exactly where
> `Instrumentation.onCreate()` falls in an application's startup — and discover that the framework's
> own documentation is wrong about it. Then decide, from that measurement, which defences you can
> pre-empt and which you cannot. Finally, walk into two traps deliberately: the wait that waits for
> nothing, and the `UiAutomation` channel that silently converts an app-vantage measurement into a
> shell one.
>
> **Difficulty.** Intermediate to advanced. No new commands; a great deal of new care.
>
> **Time.** 90 minutes.

**Prerequisites:** [Lab 01](lab-01-first-instrumentation.md) and
[Lab 02](lab-02-the-gate-matrix.md) · [../README.md §3.6, §3.11, §3.12](../README.md) ·
[09 — Android App Internals](../../09-Android-App-Internals/README.md) for `ActivityThread` ·
[60 — ADB](../../60-ADB/README.md) for what the shell UID can reach

See [SECURITY.md](../../SECURITY.md) for authorised-testing scope.

---

## 0. Two questions worth an hour each

**Question one: when exactly does your code run?** Everybody knows the answer is "early". The
platform's javadoc for `Instrumentation.onCreate` says:

> *"Called when the instrumentation is starting, before any application code has been loaded."*

If that is true, you can pre-empt everything. If it is false, the parts of the app that ran first are
parts you can only observe after the fact — and those parts are, awkwardly, exactly where packers,
pinning libraries and crash reporters put themselves.

**Question two: whose eyes are you looking through?** This repository's most repeated finding is that
a probe verified from `adb shell` has not been verified: the shell sees properties, files and
`/proc` entries an app cannot. `am instrument` is a way to *leave* the shell vantage. This lab
confirms that it works — and then shows the one call that undoes it without telling you.

---

## 1. Set up

```bash
# host
cd 66-Instrumentation/examples
OUTDIR=/tmp/ch66 ./build-instrumentation-fixtures.sh --install
adb shell pm list instrumentation
```

Record the device again. Everything below was measured on `sdk_gphone16k_x86_64`, Android 15 / API 35,
`userdebug`.

### 1.1 What the fixture instruments itself with

`examples/vault-target/` logs a monotonic timestamp at four startup slots under the logcat tag
`ch66seq`:

| Tag line | Where in the target's code |
|---|---|
| `1 Application() constructor` | `VaultApp()` — no `Context` yet |
| `2 Application.attachBaseContext` | `VaultApp.attachBaseContext()` |
| `3 ContentProvider.onCreate` | `SeedProvider.onCreate()` |
| `4 Application.onCreate` | `VaultApp.onCreate()`, on **entry** |
| `5 seed complete` | `VaultApp.onCreate()`, on **exit**, after all storage is written |

and `examples/vault-probe/` logs one line under `ch66probe` at the instant its own `onCreate()` is
entered, plus a `seq.*` result block recording what it could see at that instant.

Two markers for `Application.onCreate` rather than one is not redundancy. Step 4 is about why.

---

## 2. Measure the ordering

```bash
# host -- terminal 1
adb logcat -c

# host -- terminal 1
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 | grep 'seq\.'

# host -- terminal 1
adb logcat -d -s ch66seq:I ch66probe:I
```

Measured here:

```
I ch66seq : 1 Application() constructor      t=25351020619000
I ch66seq : 2 Application.attachBaseContext  t=25351022191500
I ch66seq : 3 ContentProvider.onCreate       t=25351023364700
I ch66probe: Instrumentation.onCreate reached at t=25351027186900
I ch66seq : 4 Application.onCreate           t=25351030119400
I ch66sink: event startup=sess-7a9a3cf2bb6
I ch66seq : 5 seed complete                  t=25351038724500
```

```
INSTRUMENTATION_RESULT: seq.entryNs=25351027186900
INSTRUMENTATION_RESULT: seq.atInstrumentationOnCreate=attachBaseContext=25351022191500 \
    providerOnCreate=25351023364700 applicationOnCreate=0
INSTRUMENTATION_RESULT: seq.applicationOnCreateAfterWait=25351030119400
INSTRUMENTATION_RESULT: seq.seedCompleteAfterWait=25351038724500
```

### 2.1 Do the arithmetic

Subtract the constructor timestamp from each. From this run:

| Event | Offset | Already run at your `onCreate`? |
|---|---|---|
| `Application()` constructor | 0.000 ms | **yes** |
| `Application.attachBaseContext()` | +1.57 ms | **yes** |
| `ContentProvider.onCreate()` | +2.75 ms | **yes** |
| **`Instrumentation.onCreate()`** | **+6.57 ms** | this is you |
| `Application.onCreate()` entry | +9.50 ms | no |
| the app's own initialisation done | +18.11 ms | no |

The `seq.atInstrumentationOnCreate` line is the same fact stated a second way, and it is the stronger
form of the evidence: at the moment your code ran, `attachBaseContext` and `providerOnCreate` were
**already non-zero** and `applicationOnCreate` was still exactly **`0`**. That is not an inference
from timestamps taken on two different threads — it is a single read of three fields at one instant.

> **The javadoc is wrong, and you have now proved it.** Three pieces of application code ran before
> your `onCreate()`. If you want to see the cause rather than the effect, open the API 35 SDK's own
> copy of the framework source — `sources/android-35/android/app/ActivityThread.java` — and read
> `handleBindApplication()`. It calls `makeApplicationInner()` (which constructs the `Application`
> and calls `attachBaseContext`) and then `installContentProviders()` **above** the
> `mInstrumentation.onCreate(...)` call site, with a comment explaining that providers go first
> deliberately so the test thread does not race them.

### 2.2 Run it five more times

One measurement is an anecdote. Run the same command five more times and record the six offsets for
`Instrumentation.onCreate` relative to `attachBaseContext`. The absolute numbers move — the AVD is a
virtual machine on a busy host — but the **order** must not. If you ever see
`applicationOnCreate` non-zero in `seq.atInstrumentationOnCreate`, you have found something the
chapter did not, and you should write it down.

---

## 3. Decide what you can pre-empt

The ordering is only interesting because it maps onto where real code lives.

| Slot | What real apps put there | You are… |
|---|---|---|
| `Application()` constructor | rarely anything | behind it |
| `attachBaseContext()` | **commercial packers unpack here**; `MultiDex.install()`; some TLS-pinning bootstraps; some root checks | **behind it** |
| `ContentProvider.onCreate()` | `androidx.startup`, `FirebaseInitProvider`, crash reporters, SDK auto-initialisers, WorkManager | **behind it** |
| `Application.onCreate()` | most hand-written initialisation, most feature-flag setup, most licence gates | **ahead of it** |
| `Activity.onCreate()` and later | UI, the interesting flows | **ahead of it**, plus the framework routes it through you |

### 3.1 Prove the "ahead of it" half

The chapter's `HookFromInstrumentation.java` installs a `java.lang.reflect.Proxy` over the target's
`VaultStore.sSink` — an interface-typed static field — during `Instrumentation.onCreate()`, and the
target emits its first event during `Application.onCreate()`.

```bash
# host
cd /tmp && rm -rf ch66hook && \
  cp -r <repo>/66-Instrumentation/examples ch66hook && cd ch66hook
cp HookFromInstrumentation.java vault-probe/
sed -i 's|com.pentest.ch66.probe.VaultProbe|com.pentest.ch66.probe.HookFromInstrumentation|' \
    vault-probe/AndroidManifest.xml
OUTDIR=/tmp/ch66 ./build-instrumentation-fixtures.sh --install

# host
adb logcat -c
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.HookFromInstrumentation
adb logcat -d -s ch66hook:I ch66sink:I
```

Measured:

```
INSTRUMENTATION_RESULT: hook.call.00=event[startup, sess-7a9a3cf2bb6]
INSTRUMENTATION_RESULT: hook.callCount=1
INSTRUMENTATION_RESULT: hook.install=installed proxy over com.pentest.ch66.vault.VaultStore.sSink
INSTRUMENTATION_CODE: -1
```

```
I ch66hook: installed proxy over com.pentest.ch66.vault.VaultStore.sSink
I ch66hook: -> event[startup, sess-7a9a3cf2bb6]
I ch66sink: event startup=sess-7a9a3cf2bb6
I ch66hook: <- event = null
```

Read the last three lines in order. Your proxy saw the call, the target's real implementation still
ran (because the proxy forwards), and the return came back through you. That is a working hook, in
pure Java, with no native code, no trampoline and no ART internals — installed by an instrumentation
that arrived before the call site executed.

> **Reuse `OUTDIR`.** The build script generates its signing keys only if they are absent, so
> building into a fresh directory produces new keys and everything stops matching the installed
> target. Lab 02's hint box covers the symptom.

### 3.2 Now prove the "behind it" half

Move the emission earlier. In your copy of `examples/vault-target/VaultApp.java`, add a call inside
`attachBaseContext`, after `super.attachBaseContext(base)`:

```java
VaultStore.emit("early", "from-attachBaseContext");
```

Rebuild, reinstall, re-run the hook probe. The `early` event does **not** appear in `hook.call.*`,
and the `ch66sink` line for it appears in logcat *above* the `installed proxy` line. You were not
there yet.

That is the whole practical content of §3.6 in one experiment. **If the thing you want to intercept
runs in `attachBaseContext` or a `ContentProvider`, instrumentation cannot get in front of it.** Your
options are Frida's spawn-and-hold (`frida -U -f <pkg>`, see
[53 — Frida](../../53-Frida/README.md)) or a Zygote-level framework
([63 — LSPosed](../../63-LSPosed/README.md)). Knowing which of the three slots a defence occupies is
the cheapest way to choose a tool, and you now have a method for finding out.

---

## 4. Trap one — waiting for a flag raised at the start of the work

This is not a hypothetical. It happened while this chapter was being written, and the wrong answer it
produced was plausible.

### 4.1 Reproduce it

In your copy of `examples/vault-probe/VaultProbe.java`, change the wait loop to break on the *entry*
marker instead of the *exit* marker:

```java
// the WRONG wait -- sApplicationOnCreateAtNs is set on ENTRY to onCreate
seedDone = Probes.readStaticField(cl, TARGET_PKG + ".VaultApp", "sApplicationOnCreateAtNs");
if (!"0".equals(seedDone) && !seedDone.startsWith("ERROR")) {
    break;
}
```

Rebuild, reinstall, run. Measured, from the chapter's own first run:

```
INSTRUMENTATION_RESULT: seq.applicationOnCreateAfterWait=23172126518300
INSTRUMENTATION_RESULT: read.prefs.api_key=<absent>
INSTRUMENTATION_RESULT: read.prefs.refresh_token=<absent>
INSTRUMENTATION_RESULT: read.prefsXmlBytes=ABSENT:/data/user/0/.../shared_prefs/vault.xml: \
    open failed: ENOENT (No such file or directory)
INSTRUMENTATION_RESULT: read.file.secret=ERROR:FileNotFoundException .../files/secret.txt: \
    open failed: ENOENT (No such file or directory)
INSTRUMENTATION_CODE: -1
```

The wait *succeeded* — the marker is non-zero — and every storage read came back empty.

### 4.2 Why this is dangerous rather than merely annoying

Look at that output as if you had not written the fixture. `INSTRUMENTATION_CODE: -1`, so the run
passed. `seq.applicationOnCreateAfterWait` is non-zero, so the wait worked. Four independent storage
channels are all empty. The obvious conclusion is **"this application does not persist anything"**,
which is a finding you might well write down.

It is wrong, and nothing in the output says so. The marker is set on *entry* to
`Application.onCreate()`; the writing happens inside it. **Waiting for a flag raised before the job
starts is waiting for nothing.**

### 4.3 The fix, and the general rule

Restore the shipped version, which waits on `sSeedCompleteAtNs` — set on *exit*:

```
INSTRUMENTATION_RESULT: read.prefs.api_key=ch66-APIKEY-3f9a1c
INSTRUMENTATION_RESULT: read.file.secret=ch66-file-secret-7d41
INSTRUMENTATION_RESULT: read.prefsXmlBytes=READ:229
```

The general rule, and it applies far beyond this chapter: **a negative result from a probe that races
its target is indistinguishable from a true negative.** When you get "nothing there", the first thing
to rule out is your own timing. Practical defences:

- Wait on a marker set on *completion*, never on *entry*.
- Better: re-read on a schedule and report the whole series, not one sample.
- Better still: do not race at all. Read storage from a *separate*, later `am instrument` run against
  an app that has already been started once and has already written.
- Always report the negative *with* the wait condition attached, so a reviewer can judge it.

Against a real target you do not control, you have no marker to wait on. Use
`getTargetContext().registerComponentCallbacks`, `waitForIdleSync()`, or `startActivitySync()`
the app's launcher activity and read afterwards — by then `Application.onCreate` has certainly
completed.

---

## 5. Trap two — the vantage that changes under you

### 5.1 Establish the app vantage

The probe's `deny.*` block reads six paths as the app. Measured:

```
deny.otherAppData    ABSENT:/data/data/com.android.settings: open failed: ENOENT
deny.dataAdb         DENIED:/data/adb: open failed: EACCES
deny.systemXbinSu    DENIED:/system/xbin/su: open failed: EACCES
deny.procModules     DENIED:/proc/modules: open failed: EACCES
deny.procInit1Maps   ABSENT:/proc/1/maps: open failed: ENOENT
deny.dataLocalTmp    DENIED:/data/local/tmp: open failed: EACCES
```

Now read the same six from the shell:

```bash
# host
adb shell 'ls -ld /data/data/com.android.settings /data/adb /system/xbin/su \
                  /proc/modules /data/local/tmp 2>&1'
adb shell 'head -c 40 /proc/1/maps'
```

Measured:

```
ls: /data/data/com.android.settings: Permission denied
ls: /data/adb: Permission denied
drwxrwx--x 3 shell shell  4096 ... /data/local/tmp
-r--r--r-- 1 root  root      0 ... /proc/modules
-rwsr-x--- 1 root  shell 51224 ... /system/xbin/su
head: /proc/1/maps: Permission denied
```

Line them up:

| Path | shell (uid 2000) | app (uid 10210) |
|---|---|---|
| `/data/data/com.android.settings` | **EACCES** | **ENOENT** |
| `/data/adb` | EACCES | EACCES |
| `/system/xbin/su` | **readable, setuid root, `root:shell`** | **EACCES** |
| `/proc/modules` | **readable** | **EACCES** |
| `/proc/1/maps` | exists, EACCES | **ENOENT** |
| `/data/local/tmp` | **listable, `shell:shell`** | EACCES |

Three of the six are things the shell can do and the app cannot. Two return **different errors** for
the two vantages, and `File.exists()` maps `ENOENT` and `EACCES` to the same `false` — which is why
this repository has now measured, three times in three chapters, that a path-existence check has zero
discriminating power on the devices where it would matter. See
[63 — LSPosed](../../63-LSPosed/README.md) for the `/data/adb/lspd` version and
[37 — Root Detection](../../37-RootDetection/README.md) for the `/system/xbin/su` version.

**This is the good news.** `am instrument` bought you the app's vantage. A root-detection probe run
this way is measuring what the app measures.

### 5.2 Now break it

The probe's `ua.*` block calls `getUiAutomation()` and runs commands through it. Measured, from the
**same process**, in the **same run**:

```
ua.available             YES
ua.shell.id              uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),...
ua.shell.lsDataLocalTmp  drwxrwx--x 4 shell shell 4096 ... /data/local/tmp
ua.shell.lsSystemXbinSu  -rwsr-x--- 1 root shell 51224 ... /system/xbin/su
ua.shell.readProcModules virtio_snd 45056 0 - Live 0x000000000000
```

Every path that was `EACCES` sixty lines earlier came back. `UiAutomation.executeShellCommand()` does
not run in this process; the system runs it, as **uid 2000**.

> **This invalidates measurements silently, which is the worst kind of invalidation.**
> A detection probe written as an instrumentation that reaches for `executeShellCommand` because it
> is convenient has measured the **shell's** vantage, and nothing in its output distinguishes the two
> sources. The app you are assessing has no `UiAutomation`. It cannot list `/data/local/tmp`, cannot
> stat `/system/xbin/su`, cannot read `/proc/modules`. A root check "verified" that way will look
> like it works and will not work in production.

The rule, sharpened rather than overturned: **run the probe with the capabilities the app has.**
Inside an instrumentation that means plain `java.io` and `android.content`. Treat `getUiAutomation()`
as a *different instrument answering a different question* — it is excellent for driving the UI and
for collecting ground truth to compare against, and it is not the app.

### 5.3 A third thing about `executeShellCommand` that will waste your afternoon

```
ua.shell.echoPlain   one two
ua.shell.echoQuoted  "one two"
ua.shell.pipelineRaw
```

The quoted echo came back **with its quotes**. The pipeline produced **nothing at all**, and no error.

`executeShellCommand` splits the string on whitespace and executes it. It is not a shell: no quoting,
no pipes, no redirection, no globbing, and no diagnostic when you use them. Verify that any output
you get is non-empty, because empty is what failure looks like here.

---

## 6. Bonus — the hidden-API census

While you are in the process, one more measurement that generalises. Run the probe twice:

```bash
# host
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 | grep hidden.
adb shell am instrument -w -r --no-hidden-api-checks \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe 2>&1 | grep hidden.
```

Measured:

| Key | default | `--no-hidden-api-checks` |
|---|---|---|
| `hidden.SystemProperties.get` | `OK:35` | `OK:35` |
| `hidden.ServiceManager.getService` | `OK:...BinderProxy` | `OK:...BinderProxy` |
| `hidden.census.ActivityThread` | methods=30 fields=21 | **methods=289 fields=109** |
| `hidden.census.ActivityManager` | methods=89 fields=35 | methods=155 fields=170 |
| `hidden.census.VMRuntime` | methods=23 fields=0 has:setHiddenApiExemptions=**false** | methods=72 fields=16 has:setHiddenApiExemptions=**true** |
| `hidden.census.SystemProperties` | methods=10 fields=2 | methods=35 fields=6 |

The first two rows are the trap: both succeeded **with enforcement on**, because both members are
greylisted rather than blocklisted. A probe that tried only those two would report "hidden API is not
enforced" and be wrong.

The census rows are the honest measurement, because ART implements the restriction by *filtering*
blocked members out of `getDeclaredMethods()` and `getDeclaredFields()`. The number moves; the
boolean does not.

**Generalise it.** A single positive lookup against a filtered surface is not evidence about the
filter. Count the population. This repository has now learned the same lesson from three different
directions — a self-signature detector that agreed with 18 of 18 samples, a HIGH band where 15 of 17
were rejected on adjudication, and a three-character token that produced 16 confident false
positives.

---

## 7. Success criteria

- [ ] You produced a timestamped ordering showing `Instrumentation.onCreate()` between
      `ContentProvider.onCreate()` and `Application.onCreate()`, and confirmed it a second way with
      the `seq.atInstrumentationOnCreate` field read.
- [ ] You repeated the run at least five times and the **order** did not change.
- [ ] You can say which of your own findings the javadoc contradicts, and where in
      `ActivityThread.handleBindApplication()` the contradiction comes from.
- [ ] You installed a working `Proxy` hook from `onCreate()` and caught the app's first event.
- [ ] You moved the emission into `attachBaseContext` and demonstrated that you **could not** catch
      it.
- [ ] You reproduced the entry-marker wait and got four empty storage reads with a passing exit code.
- [ ] You can state the general rule that failure teaches, in one sentence.
- [ ] You produced the six-path vantage table with both columns from your own device.
- [ ] You demonstrated `executeShellCommand` returning `uid=2000` from a process running as an app.
- [ ] You can explain why `hidden.SystemProperties.get` succeeding proves nothing.

---

## 8. Clean up

```bash
# host
cd 66-Instrumentation/examples
./build-instrumentation-fixtures.sh --uninstall
adb shell pm list instrumentation
rm -rf /tmp/ch66hook          # if you made the copy in step 3.1
```

If you edited the fixtures in place rather than in a copy, restore them:

```bash
# host
git -C <repo> status --short 66-Instrumentation/examples
git -C <repo> checkout -- 66-Instrumentation/examples
```

---

## 9. Hints

<details>
<summary>The logcat lines come out interleaved and you cannot tell the order</summary>

`logcat` prints in timestamp order, but the timestamps have millisecond resolution and several of
these events are under a millisecond apart. Use the `t=` values in the message bodies —
`SystemClock.elapsedRealtimeNanos()` — rather than the log timestamps. That is exactly why the
fixture logs them.
</details>

<details>
<summary>seq.atInstrumentationOnCreate shows ERROR for one of the fields</summary>

The class name or field name in the probe does not match the target you installed. The probe resolves
`com.pentest.ch66.vault.VaultApp` and `com.pentest.ch66.vault.SeedProvider` by name; if you renamed
anything in your copy, update `TARGET_PKG` and the field names together.
</details>

<details>
<summary>The Proxy hook reports "implements no interface"</summary>

`java.lang.reflect.Proxy` can only manufacture an implementation of an interface. If the field's
value is a concrete class with no interfaces, this technique does not apply — and that is the
honest boundary of pure-Java interception. `HookFromInstrumentation.collectInterfaces()` walks the
superclass chain in case the interface is declared further up, but there is nothing to find if there
is no interface at all. This is where [65 — Hooking](../../65-Hooking/README.md) starts.
</details>

<details>
<summary>getUiAutomation() throws or returns null</summary>

`UiAutomation` needs the `UiAutomationConnection` the system supplies at start-up, and it also needs
the accessibility subsystem to be available. It is generally present under `am instrument`; if it is
not, the probe reports `ua.available=NO: <reason>` rather than crashing, and the rest of the lab
still works. Record the reason — it is a device fact worth knowing.
</details>

<details>
<summary>Your vantage table differs from the one above</summary>

Good — that is a measurement, not an error. `/proc` visibility, app data isolation and the presence
of `/system/xbin/su` all vary by Android version, by build type and by whether the device is rooted.
The shape that should hold on any device is that at least one path is readable by the shell and
denied to the app. If **none** is, check that your probe really ran as the app: `id.uid` should not
be 2000.
</details>

<details>
<summary>You want to know whether the app itself could reach UiAutomation</summary>

It cannot. `Instrumentation.getUiAutomation()` returns a handle built from a connection that
`ActivityManagerService` passed into `Instrumentation.init()` when it started the instrumentation.
An ordinary application never gets one. The nearest thing available to an app is an
`AccessibilityService`, which requires an explicit user grant and cannot execute shell commands.
</details>

---

## 10. What to read next

- **[Lab 04 — CTF: Before Application](lab-04-ctf-before-application.md)**, which is only solvable if
  you internalised §2 and §4 of this lab.
- **[53 — Frida](../../53-Frida/README.md)** §4, for the spawn-and-hold path that gets in front of
  `attachBaseContext`.
- **[65 — Hooking](../../65-Hooking/README.md)**, for everything the `Proxy` trick cannot reach.
- **[37 — Root Detection](../../37-RootDetection/README.md)**, whose checks you are now equipped to
  evaluate from the correct vantage.
