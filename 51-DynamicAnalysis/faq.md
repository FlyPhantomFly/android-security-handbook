# 51 — Dynamic Analysis · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct and every number
is measured. The reasoning behind each is in [README.md](README.md).

---

## 1. Where do I even start? I have a phone and an APK and no idea what to do first.

**Start with the device, not the app.** This feels wrong — the app is the target — but every claim you
make for the rest of the day is constrained by facts about the device, and they take forty seconds:

```bash
adb devices -l
adb shell "getprop ro.product.model; getprop ro.build.version.sdk; getprop ro.build.version.security_patch"
adb shell "getenforce; which su"
adb shell "ps -A -o NAME" | grep -i frida
adb shell "mount | grep cacerts"
```

Then the target, from the platform's own record rather than from the file:

```bash
adb shell "dumpsys package $PKG | grep -E 'flags=|granted=|versionName'"
adb jdwp
adb shell "run-as $PKG id"
```

Those three lines tell you whether the app is debuggable, whether you can read its private storage,
and what permissions it actually holds. **Only then** do you take a baseline and start driving it.

The reason this order matters is boring and expensive: this repository has twice produced a day of
measurements on a device whose trust store had been modified, which made every conclusion about TLS
wrong in a way that looked completely convincing. See [README §3.1.6](README.md#316-how-stage-1-fails-the-trust-store-trap-measured).

---

## 2. Do I need root?

**No**, and the assumption that you do is why a lot of published methodology is unusable on the phone
you actually have.

Without root you get: every `dumpsys` service, all logcat buffers, the live runtime receiver surface,
the real permission grant state, external storage, process state, service clients, and network
counters. That is seven of nine channels.

If the target is **debuggable** — and `adb jdwp` tells you in one command — you additionally get its
private data directory through `run-as` and a Java debugger through JDWP. That is the eighth channel
and it is the one with the interesting data in it.

What root actually adds: `strace`, another app's memory, the system CA store, and Frida without
rebuilding the APK.

This chapter's entire worked example — a validated finding on a real commercial application — was
produced on an unrooted device with no `frida-server` and **no instrumentation of any kind**.

---

## 3. Static or dynamic first?

**Static first, then dynamic, then static again.** It is a loop, not a sequence.

- **Static first** because it is cheap and it gives you two things you cannot get any other way: the
  entry-point list, which is your coverage denominator *and* your exercise plan; and a ranked lead
  queue in which most leads carry a runtime next-step.
- **Dynamic second** because it answers what static could not, and because it teaches you the
  vocabulary of the running app — including obfuscated class names you now have a reason to grep for.
- **Static again** because dynamic hands you names and addresses that make a second, targeted pass far
  more productive, and because completeness questions ("how many *other* places?") are static's alone.

If you genuinely have to pick one: pick static for an artefact you cannot run, and dynamic for a
question about behaviour. [README §6.5](README.md#65-the-finding-dynamic-can-make-that-static-was-supposed-to-own)
has the table.

---

## 4. Why did nothing happen when I hooked it?

Five causes. [53-Frida](../53-Frida/README.md) §7.4 owns the first four exhaustively:

1. **The method was inlined** by R8, so there is no function left to hook. This one is invisible and
   it is the reason [18-ARM](../18-ARM/README.md) measured a check patched to `return 1`, verified
   returning 1, with the caller still refusing — because the patched copy was called by nothing.
2. **The class is in a different classloader** and `Java.use` cannot see it.
3. **You hooked the wrong overload.** Enumerate them first.
4. **You attached instead of spawning**, and the code ran before your agent loaded.

And a fifth, which belongs to *this* chapter and is not a hooking problem at all:

5. **You never exercised the path.** A hook that does not fire is compatible with "this code is dead"
   and with "I did not reach it", and nothing about the hook distinguishes them. That is exactly why
   coverage is measured. Run `coverage-reporter.py` before you conclude anything from a silent hook.

---

## 5. How do I know I covered enough?

You do not "know". You **measure and state**, which is a different and achievable thing.

```bash
python3 -B scripts/coverage-reporter.py -p com.example.target \
        --components entrypoints.txt --logcat ./evidence/s01/09-logcat.txt
```

That turns "I clicked around for a while" into "2 of 4 components, and here are the 2 I did not
reach". Then say the *grain* out loud — **component** coverage, not code coverage — because 100% of
the former is entirely compatible with having exercised a small fraction of the code.

There is no threshold that makes a pass "enough". There is only a number, a named list of what was
missed, and a report that does not claim more than the number supports.

---

## 6. My coverage tool says 67% but my colleague's says 50% for the same session. Who is right?

**Your colleague, and this is the most useful thing in the chapter.**

The numerator is identical — you both reached two components. The *denominator* differs:

| Source | Components | Coverage |
|---|---|---|
| `dumpsys package` resolver tables | 3 | 67% |
| The APK manifest via `aapt2 dump xmltree` | 4 | 50% |

Resolver tables exist to answer *"which component would win this Intent"*, so PackageManager indexes
only components that carry an `<intent-filter>`. An Activity started by explicit Intent from inside
the app is entirely real and entirely absent from that list. On the measured app the missing one was
`MachineAccessActivty` (the typo is the app's).

**Every device-derived coverage figure is an upper bound, and always in the flattering direction.** On
a real app with dozens of internal screens the gap is much larger. Feed the static entry-point list to
`--components` and quote that number.

---

## 7. `run-as` says "package not an application". Isn't that the same as "not debuggable"?

**No, and confusing them will make you skip a real finding.** They are two different guards, checked
in this order inside `run-as`:

| Message | Cause |
|---|---|
| `unknown package: X` | Not installed |
| `package not an application: X` | It **is** debuggable — but its uid is below 10000, i.e. a system app, which `run-as` refuses by design |
| `package not debuggable: X` | `FLAG_DEBUGGABLE` is clear |

Measured on the test device: four OEM **system** apps carried `DEBUGGABLE` and all four returned
"not an application". Anyone reading that as "not debuggable" would have missed a device-posture
finding entirely. The correct rule is: **`run-as` needs `FLAG_DEBUGGABLE` *and* an application uid.**

---

## 8. Is `adb jdwp` really better than reading the manifest?

For finding debuggable *processes*, yes, and it takes one word.

`adb jdwp` streams the pid of every process with an open JDWP transport, and ART opens that transport
only when the runtime flags say the process is debuggable. So it is an exact enumerator rather than a
heuristic, it needs no APK, it needs no decompiler, and it reflects what the **platform** decided
rather than what a file claims.

For the package-level view, pair it with:

```bash
adb shell 'for p in $(pm list packages | sed s/package://); do
    f=$(dumpsys package $p 2>/dev/null | grep -m1 "flags="); case "$f" in *DEBUGGABLE*) echo "$p $f";; esac; done'
```

On the test device that returned **five packages**, four of them OEM system apps shipped debuggable on
a retail build.

---

## 9. My delta report says "no change" everywhere. Did I find nothing?

Maybe. There are five explanations and only the last is a result. Work them in this order:

1. **The exercise did not run.** By far the most common, and it is silent. Measured here: `am start`
   was absorbed by a pending permission dialog, `am start -W` reported
   `Activity: com.android.permissioncontroller/…GrantPermissionsActivity`, and all nine channels went
   quiet. Nothing had happened, and the report looked exactly like a clean negative.
2. **You watched the wrong process.** The app runs in `com.example:remote` and your `--pid` filter is
   on the main one.
3. **A channel was never captured.** `run-as` failed and channel 04 is empty because it was never
   read. `session-recorder.sh` prints `**Not captured.**` rather than "no change" for exactly this.
4. **The behaviour needs a state you did not reach.** Nothing is written until login.
5. **The app genuinely does not do it on that path.** A real, bounded, useful result.

Checks for (1): read all of `am start -W`, `dumpsys window | grep mCurrentFocus`, and `pidof`.

---

## 10. Why do I need a "control run"? It feels like ceremony.

Because a device is busy and something is always changing, so without one **everything the platform
does anyway looks like your result.**

Measured on the test device over 45 idle seconds with the app untouched: loopback moved ~4,017 bytes,
`dummy0` moved ~5,877 bytes, and **every other channel was silent**. That single run calibrated the
instrument. Afterwards, any private-filesystem, receiver, service or grant change in a real run was
attributable, and any network claim below about 4 KB per 45 seconds was not.

It costs one command and the length of your window. Scientists call it a negative control and would
not publish without one.

---

## 11. Can I just report what I saw in Burp?

No, for two independent reasons.

**A proxy is one channel of nine.** While you were reading HTTP, the app may have written a token to
`shared_prefs`, logged a bearer header, registered four receivers no manifest contains, and loaded a
DEX. None of that is in Burp.

**And a quiet proxy is ambiguous in a dangerous way.** "The app did not send the token" and "the app
refused my CA and I saw none of its traffic" produce identical proxy logs and are opposite results.
Check that you are seeing *any* of the app's traffic before you claim anything about what is absent
from it.

---

## 12. The app died the moment I attached. What now?

**Stop hooking and start triaging.** This is the boundary with
[67-BypassingProtections](../67-BypassingProtections/README.md), and it owns everything past it.

Its `bypass-triage.py` reads `dumpsys activity exit-info` plus the tombstone and classifies the death.
Its measured signature table is what makes the triage fast:

| Mechanism | reason | status | Lifecycle events |
|---|---|---|---|
| `abort()` in `JNI_OnLoad` | 5 (CRASH_NATIVE) | 6 (SIGABRT) | **none at all** |
| Java `abortNow()` | 5 | 6 | create → start → resume |
| `System.exit(42)` | 1 (EXIT_SELF) | **42** | — |
| `killProcess(myPid())` | 2 (SIGNALED) | 9 | — |
| Silent degradation | — | — | *no record at all* |

That "none at all" row is the useful one: it means the check ran before any Java, in `.init_array` or
`JNI_OnLoad`, so attaching was already too late and you need spawn-and-suspend.

**Note the same field means the exit code for reason 1 and the signal number for reasons 2 and 5.**

---

## 13. Is a bypass a finding?

**No.** 67 states the rule and it is worth carrying into every report: *"A bypassed control is not a
finding. The finding is what the control was protecting and whether the server re-verifies it."*

Two corollaries that catch people in both directions:

- **"The app has no root detection"** is not a vulnerability either. It is an observation about
  hardening, and most bounty programmes say so in their policy.
- **"I bypassed the PIN with Frida"** is a tool anecdote. *"The PIN is validated client-side in
  `com.example.auth.PinValidator.check(String)` and the server accepts a session established without
  it"* is a finding.

---

## 14. Can I use `adb shell am start` to prove a component is reachable?

**No.** The shell is uid 2000, and [60-ADB](../60-ADB/README.md) measured precisely how privileged
that is: the `com.android.shell` package requests **200 permissions**, 183 granted at install and
**16 runtime permissions pre-granted `SYSTEM_FIXED`** — including `CAMERA`, `RECORD_AUDIO`,
`READ_SMS` and background location.

An `am start` that succeeds from the shell tells you the component exists and is startable *by the
shell*. To claim reachability you build a fifteen-line unprivileged app and show the call succeeding
from it — or you write the honest sentence:

> "The component started successfully when invoked from `adb shell` (uid 2000); reachability from an
> unprivileged application was not established."

That sentence is worth more than the confident one, because a reviewer can act on it.

---

## 15. Why does `TracerPid` not detect my debugger?

Because `TracerPid` detects **`ptrace`-based attachment**, and a Java debugger does not use `ptrace`.
JDWP is a protocol spoken over a socket to a transport ART opens when the process is debuggable.

[38-TamperDetection](../38-TamperDetection/README.md) attached `jdb`, enumerated threads, and read
`TracerPid: 0` throughout. Many published anti-debug tables list `TracerPid` as *the* debugger check.
An app relying on it alone is not detecting the debugger most testers actually use — which is good
news for you, because the JDWP path is frequently available on apps that believe they have anti-debug.

---

## 16. I searched the database and the credentials were gone after logout. Are they?

**Check the files, not the database.** [33-Storage](../33-Storage/README.md) measured a `logout` that
deleted 2 rows and left **all four secrets readable in a 61,832-byte `-wal` file** while SQL reported
them gone.

```bash
adb shell "run-as $PKG grep -c -- '$VALUE' /data/data/$PKG/databases/app.db-wal"
adb shell "run-as $PKG ls -la /data/data/$PKG/databases/"
```

Sweep `*.db`, `*.db-wal` and `*.db-shm`. "The app deletes credentials on logout" is precisely the
claim a `SELECT` will get wrong.

---

## 17. Where does the "69% of receivers are invisible" number come from, and does it hold up?

[29-BroadcastReceivers](../29-BroadcastReceivers/README.md) parsed ActivityManagerService's live
registration table and subtracted `cmd package query-receivers`: **299 of 431 distinct actions (69%)**
registered by third-party processes had **no** manifest-declared receiver anywhere on the device.

This chapter re-ran the same script on a **different device at a different API level** (i9000S,
Android 13 / API 33 versus the Redmi's Android 11 / API 30):

```
214 of 321 distinct actions have live runtime registrations and NO
manifest-declared receiver anywhere on this device.
```

**67%.** Two independent measurements, two devices, two API levels, both approximately two thirds.

One caveat worth repeating: the counts are **timestamped, not stable**. Three snapshots of the same
idle device gave 1,151 / 1,281 / 1,290 registrations. Quote the ratio, not the absolute number, and
say when you took it.

---

## 18. Is an unguarded runtime receiver a finding?

**No — it is a precondition.** Chapter 29's own tooling prints that sentence in its output.

Measured on the test device: 263 of 308 runtime filters had no sender permission, and 245
registrations belonged to third-party apps with at least one unguarded filter. If every one of those
were a finding, the report would be useless.

The severity comes from what `onReceive` *does* with the Intent, and you have to show it. Three
measured facts that bear on this:

- `INSTALL_REFERRER`, `c2dm.intent.RECEIVE` and `PROVIDER_CHANGED` **are forgeable** by an ordinary
  app, despite being widely trusted.
- `am broadcast` sends **`ordered=true`**, so a receiver may behave differently under your test than
  in production.
- **`dumpsys` records broadcast extras in cleartext** — a test broadcast carrying
  `token=SUPERSECRET123` was readable afterwards by anything that can read `dumpsys`. Be careful what
  you send while testing.

---

## 19. Do I have to run `strace`? It is in every methodology I have read.

Only if you have root, and on many devices you cannot at all. Measured on the test device:

```
$ adb shell "which strace; ls -la /system/bin/strace"
ls: /system/bin/strace: No such file or directory
```

There is no `strace` present, and `ptrace`-attaching to another app's process is exactly what the
sandbox prevents anyway.

`strace` earns its reputation for one specific job: finding a **native** root or integrity check that
Java-level hooking missed, by showing the `openat("/system/xbin/su")` no Java hook ever saw.
[67](../67-BypassingProtections/README.md) §7.8 owns that technique.

The substitutes, in order of preference: `frida-trace -i 'libc.so!open*'` if you have Frida;
`simpleperf` (present on the test device, no injection, tells you which functions run);
Perfetto/`atrace` for system-wide including Binder; and if none of those, read the `.so` in
[57-Ghidra](../57-Ghidra/README.md) after narrowing it with a `RegisterNatives` hook. `ltrace` is
broken on bionic generally — do not spend time on it.

---

## 20. How do I find the private storage of an app that is not debuggable, without root?

**You do not.** That row of the capability matrix is closed, and the honest response is to record it
as a gap rather than to report an absence of findings.

Write: *"Private storage was **not captured**: the package is not debuggable and the device is not
rooted."* — not *"no sensitive data was found in private storage"*, which claims a search you did not
perform.

What you can still do without that channel: external storage (needs nothing), logcat (needs nothing),
the runtime receiver surface, the real grant state, service clients, process state, and network
content through a proxy. That is enough for a substantial platform-and-network assessment, and the
report says which parts of a storage assessment were not possible.

If you are *permitted* to modify the app, a debuggable rebuild opens the channel — but the resulting
artefact is not the shipped one, its signing certificate has changed, and every finding from it
carries that caveat.

---

## 21. Why does this chapter keep telling me to go and read another chapter?

Because the repository is arranged so that each technique is explained once, properly, by the chapter
that owns it — and duplicating it here would produce a worse copy that drifts out of date.

Concretely: [53-Frida](../53-Frida/README.md) owns the instrumentation engine, so this chapter decides
*whether and where* to hook and 53 explains *how*. [67](../67-BypassingProtections/README.md) owns
what happens when the app fights back. [77](../77-UsefulCommands/README.md) owns the commands
themselves — its own references table calls this chapter *"the methodology these commands serve"*.
[80-Appendix](../80-Appendix/README.md) owns the report template and the severity rubric.
[52-StaticAnalysis](../52-StaticAnalysis/README.md) owns the other half of the loop.

What this chapter owns and nobody else does: the pipeline, channel selection, **correlation**,
**coverage**, and honest severity for a behavioural observation.
