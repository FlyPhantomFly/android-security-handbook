# 37 — Root Detection · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. What actually *is* root? I keep hearing "root access" and nodding.**

Root is the user account with UID (user identifier) 0 on any Linux-based system, and Android is
Linux-based. The kernel special-cases UID 0: a process running as UID 0 skips the ordinary file
permission checks and is allowed to make privileged system calls.

"Rooting a phone" does not mean discovering a secret password. It means **installing a mechanism**
that did not previously exist — normally a `su` binary plus a daemon — by which a chosen process can
obtain UID 0 on demand. A retail Android device ships with no such mechanism anywhere, which is why
the mere presence of a `su` binary is evidence of modification.

One correction people need early: root is **not** unlimited power on Android. SELinux applies
mandatory access control on top of UID checks, and even UID 0 is confined to its SELinux domain. "I
have root and still get permission denied" is a normal experience, not a bug. See
[22-SELinux](../22-SELinux/README.md).

---

**2. Why does an app care whether my phone is rooted? It is my phone.**

Because a small category of apps is enforcing a rule *against* the person holding the device rather
than protecting them from someone else. A bank limiting a transfer, a streaming client refusing to
hand over a decrypted film, a game stopping you giving yourself infinite gold, an MDM agent asserting
to your employer that this device is compliant — in all of those, you are the adversary in the threat
model.

That is a legitimate business problem. It is also a problem the Android security model was never
designed to solve, because that model assumes the operating system is a trusted referee between
mutually distrusting apps. Root removes the referee.

Your instinct that "it is my phone" is correct, and it is exactly why client-side root detection
cannot work: on your phone, you win. That is why the real control lives on the server.

---

**3. If it cannot work, why does anyone implement it?**

Because "cannot work against a motivated attacker" and "worthless" are different claims.

A cheap root check removes the entire population of casual, unmotivated, script-following attackers,
and it costs a few hundred lines. It also produces a useful *risk signal* for a fraud model even when
it is trivially defeatable, because the population that bothers to defeat it is itself interesting.

What it never does is produce an *authorisation decision* you can trust. The failure mode to avoid is
not implementing the check — it is **believing** the check. See §1.4 of the
[README](README.md#14-the-honest-framing-this-cannot-be-won-on-the-client).

---

**4. I hooked `java.io.File.exists()` and the app still detects root. What did I do wrong?**

Probably nothing wrong; you just hooked one branch of four possible ones. In rough order of
likelihood:

1. **The check is in native code.** A C function calling `access("/system/xbin/su", F_OK)` never
   enters the ART runtime, so no `Java.perform` hook can ever see it. This is the single most common
   cause. Use [`scripts/native-root-bypass.js`](scripts/native-root-bypass.js).
2. **The check uses a different Java API.** `Os.access`, `FileInputStream`, `Files.exists`,
   `RandomAccessFile` — none of which route through `File.exists()`.
3. **The check is not filesystem-based at all.** Properties, mount table, packages, subprocess.
4. **You attached instead of spawning.** `frida -U -n com.app` misses everything in
   `Application.onCreate`, which is where most checks live. Always `-f`.

The correct next step is not to guess. Run
[`scripts/root-check-tracer.js`](scripts/root-check-tracer.js) and find out empirically.

---

**5. What is the difference between hooking `File.exists` and hooking `libc.so!access`?**

Position in the stack. A Java `File.exists()` call goes: `File.exists` → libcore's
`UnixFileSystem`/`BlockGuardOs` → JNI in `libjavacore.so` → bionic `libc access()` → the
`faccessat` syscall. A native check jumps straight into bionic.

So hooking `File.exists` covers only Java callers using that specific API, while hooking
`libc.so!access` covers **both** the Java path and the native path, because everything above
eventually calls libc.

Hooking lower catches more. It also affects unrelated code, so you must be more careful about which
paths you lie about — a blanket denial at the libc layer will break the app in ways that look exactly
like the root check firing, and you will spend an hour debugging your own script.

---

**6. Why do people say "spawn, never attach"? Frida attaches fine.**

It attaches fine and it is too late. Most root checks run during `Application.onCreate()` or even
`Application.attachBaseContext()`, which complete within milliseconds of process start. By the time
your `frida -U -n` finds the process, enumerates the runtime and installs a hook, the check has
already run and its result is already stored.

`frida -U -f com.target.app -l script.js --no-pause` starts the process suspended, loads your script,
then resumes. Your hooks are in place before a single line of app code executes.

---

**7. I did `Java.use("android.content.pm.PackageManager")` and my hook never fired. Is Frida broken?**

No — you hooked an abstract class. `Context.getPackageManager()` returns an instance of
`android.app.ApplicationPackageManager`, which is the concrete implementation that marshals a Binder
call to `PackageManagerService`. Hook that class name instead.

This one mistake wastes more beginner hours in Android Frida work than any other. The same trap
exists elsewhere: hook the class the runtime actually instantiates, not the type the API is declared
as.

---

**8. Magisk DenyList sometimes defeats a check with no hooking at all. How?**

Because Magisk's root is *systemless*: it does not modify the real `/system` partition, it constructs
a modified view using bind mounts inside a mount namespace. DenyList makes Magisk's daemon revert the
target process's mount namespace to a clean state before the app's code runs.

The consequence is subtle and worth stating carefully: the check is **not fooled**. It is correct.
There genuinely is no `su` in that process's view of the filesystem, and the mount table it reads
genuinely is clean. You did not lie to the app; you changed reality inside the app's namespace.

That is why it is the first thing to try. It costs sixty seconds and it defeats a surprising number
of apps outright.

---

**9. An app checks for `com.topjohnwu.magisk` and it never fires, even though Magisk Manager is
installed. Why?**

Package visibility filtering, introduced in Android 11 (API 30). An app targeting API 30+ can only see
packages it declares in its `<queries>` manifest element, plus a small always-visible set. Without the
declaration, `PackageManagerService` filters the package out and the client throws
`NameNotFoundException` exactly as though it were not installed.

The check is dead code. That is a **finding worth reporting**, because the developer believes they
have a control they have never actually had. Conversely, an app that *does* declare a long `<queries>`
list has handed you, in its manifest, the exact list of packages it hunts for.

---

**10. Half the checks I find seem to be broken. Am I misreading them?**

Probably not. Broken root checks are extremely common, and spotting them is half the value you
deliver. The recurring ones:

| Bug | Why it silently never fires |
|---|---|
| `System.getProperty("ro.build.tags")` | Reads the JVM properties table, not Android's. Always returns `null` |
| `Runtime.exec("/system/xbin/which", "su")` | `which` lives in `/system/bin` (toybox) on modern devices; `IOException` → `catch` → `return false` |
| `getPackageInfo` without `<queries>` on API 30+ | Filtered out, throws `NameNotFoundException` |
| `new File("/data/local/tmp").listFiles()` | Directory is `0771 shell:shell`; an app UID gets `null` |
| `stat("/data/adb/magisk")` | `/data/adb` is `0700 root:root`; app UID gets `EACCES`, which most checkers treat as "absent" |

Report these. A developer paying for check number twenty-seven while check number three has never run
is a finding with a clear remediation.

---

**11. Which single local check is actually worth anything?**

`ro.boot.verifiedbootstate`. Its value originates in the **bootloader**, is passed to the kernel on
the command line, and is imported by `init` — all of which happens before any of the attacker's user
space exists. `green` means verified boot succeeded; `orange` means the bootloader is unlocked.

It is still spoofable locally by an attacker with root (`setprop`, or a hook on the read path), so it
is not a gate. Its value is as **corroborating evidence sent to a server**: a request that reports
`verifiedbootstate=green` alongside a Play Integrity token that says the device does not meet device
integrity contains a contradiction, and that contradiction is a much stronger signal than either
value alone.

---

**12. What is the difference between MagiskHide, DenyList, and Zygisk? People use them interchangeably.**

They are three different things and the confusion causes real wasted time.

- **MagiskHide** (historical, removed in Magisk v24) actively unmounted Magisk's modifications from
  listed processes *and* went further, hiding daemon traces from them.
- **DenyList** (current) is narrower: for each listed process, Magisk reverts the mount namespace to a
  clean state before the app runs. It does not actively fight detection beyond that.
- **Zygisk** is the injection mechanism — Magisk's code running inside the Zygote process, so every
  forked app process starts with Magisk's infrastructure available. It enables modules to run inside
  app processes, and it lets DenyList do its unmounting at process specialisation, the earliest
  possible moment.

Third-party "hiding" modules build on Zygisk and go further. Their capabilities change fast enough
that naming specific behaviour in writing is a mistake; test on the device in front of you.

---

**13. The app detects root even after I hook `access`, `stat`, `open`, `openat`, `fopen`, `popen`,
`system` and `syscall`. What is left?**

Inline syscall assembly. Truly hostile code emits the `svc #0` instruction directly rather than
calling any libc symbol, at which point there is nothing for `Interceptor.attach` to attach to.

Stop hooking. Switch to `strace`, which observes the kernel boundary and therefore cannot be lied to
by a hook you did not install:

```bash
# adb shell as root
strace -f -p $(pidof -s com.target.app) -e trace=openat,faccessat,newfstatat,execve -s 200
```

That tells you which paths are actually being probed. Then find the call site in Ghidra by
cross-referencing, note the offset of the **comparison or the return** — not the check — and patch it,
either at runtime with `Memory.patchCode` or on disk in the `.so`.

---

**14. Why patch the return rather than fix the check?**

Because a check can be five hundred instructions and a return is one. Every root check, however
sophisticated — native, obfuscated, timing-hardened, whitebox-crypto-protected — ends by handing a
value back to a caller who branches on it. That branch is a single instruction in DEX bytecode or a
single comparison in ARM64.

This is the structural reason client-side detection cannot win, stated as a practical technique. The
sophistication of the check does not raise the cost of flipping its result.

---

**15. The app does not show a "rooted device" message. It just says "cannot connect". Is there no root
check?**

There is very likely a root check, and you have met the best anti-tamper design pattern in the whole
chapter: **decoupling detection from consequence**.

Instead of `if (rooted) showDialog()`, the app lets the root state perturb a *value* — a key
derivation salt, a checksum, an index — that is consumed much later and somewhere else. Ten screens
away, a decryption fails and the app reports a generic error. Nothing in the failing code has
anything to do with root.

Recognising this is a skill. The signs: the failure is generic and delayed; the failing code path
looks innocent; the same build works on an unrooted device; and `strace` shows a filesystem probe for
`su` that no visible code accounts for. [Lab 04](labs/lab-04-ctf-decoupled.md) exists specifically to
teach it. Almost nobody implements it, which is a shame, because it is the one client-side pattern
that genuinely costs an attacker hours.

---

**16. Should I run the tracer before or after trying a bypass?**

Before. This is the single biggest efficiency difference between junior and senior work in this area.

The tracer does not bypass anything. It reports which functions were called, with what arguments,
from where, at which layer. Two seconds of its output tells you whether the checks are Java or native,
which class implements them, and which `.so` to open in Ghidra. That converts an open-ended fight into
a specific, small task.

Skipping it means writing hooks by guesswork, and guesswork in this area routinely costs an afternoon.

---

**17. Is Objection's `android root disable` enough?**

Sometimes, for thirty seconds' investment, which makes it a reasonable first move — but it is a
convenience wrapper over roughly the Java-layer hooks in
[`scripts/java-root-bypass.js`](scripts/java-root-bypass.js). It does not touch native checks, it does
not know about your target's custom checker class, and it will not tell you *why* it failed when it
fails.

Use it as a thirty-second probe. If it works,the app's protection is Java-only and move on.
If it does not, run the tracer.

---

**18. Why does everyone recommend hooking `finish()` and `System.exit()`?**

Because they are the *consequence*, and the consequence is usually one method call regardless of how
elaborate the detection is. An app with twenty checks and one `finish()` call is defeated by one hook.

```javascript
Java.perform(function () {
    Java.use("android.app.Activity").finish.implementation = function () {};
    Java.use("java.lang.System").exit.implementation = function (c) {};
    Java.use("android.os.Process").killProcess.implementation = function (p) {};
});
```

Two caveats. First, this is diagnosis, not a finished bypass: an app that has decided it is on a
rooted device may also have set an internal flag that degrades behaviour later. Second, it tells you
nothing about *which* check fired, so you still need the tracer to produce a report the developer can
act on.

---

**19. RootBeer keeps coming up. What is it and how do I handle it?**

`com.scottyab.rootbeer` is by a wide margin the most common third-party root-detection library in the
Android ecosystem. It bundles most of the catalogue in §3 behind methods with obvious names
(`isRooted`, `checkForSuBinary`, `detectTestKeys`, `checkForRootNative`, …) plus a native component in
`librootbeer.so`.

Two things make it easy. The filename `librootbeer.so` survives everything, and so does the JNI symbol
`Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot` — JNI symbols are resolved by name at
runtime, so R8 cannot rename them. Even if the Java class has been shaded, that symbol is a reliable
anchor.

RootBeer's own documentation is admirably honest that it will not stop a determined attacker. The
problem is not the library; it is developers treating its boolean as truth.

---

**20. Is Play Integrity actually unbeatable, then?**

No, and claiming so would be as wrong as claiming a `File.exists` check works. What is true is that
the *economics are completely different*, because the evidence is produced by the TEE — a separate
secure processor context that Magisk cannot reach — and verified by your server against Google's
signature.

Where it still fails: unpatched devices and some vendor implementations produce weaker verdicts than a
defender would like; tokens can be farmed from clean devices if the binding is weak; and cloud-device
farms exist.

Where it fails much more often, and what you should actually test:

1. The app decodes the JWS itself and branches on the result → hook the branch, done.
2. No server-issued nonce or `requestHash` binding → capture one token from a clean device, replay it
   indefinitely from a rooted one.
3. Fail-open when Google's endpoint is unreachable → block the network path and proceed.

Those three tests take fifteen minutes and find real bugs. Trying to defeat the attestation itself
takes days and finds none.

---

**21. My client asked me to "bypass root detection". What should I actually deliver?**

Not "root detection bypassed". That sentence is a step in your methodology, not a finding.

Deliver:

- **What the bypass gave you access to.** Which flows, which data, which API calls became reachable.
- **Whether the server independently validated anything.** Replay the sensitive API call from a plain
  HTTP client with no app at all. If it succeeds, the root check was the *only* control and that is
  the finding.
- **Which checks fired and which silently never ran.** The dead ones are free value to the developer.
- **Where the budget should go.** Server-side enforcement and correct attestation binding, not check
  number twenty-eight.

---

**22. Do I need a rooted device to test root detection?**

To test whether the detection works, yes — you need the condition it detects. But two adjacent
approaches are worth knowing.

First, you can often analyse the *implementation* statically on any machine and report broken checks
(question 10) without a device at all.

Second, and more important: the highest-value tests in this chapter — attestation replay, token
removal, server-side enforcement — need a *proxy and an HTTP client*, not root. You can find the
serious bugs from an unrooted device.

Be careful with emulators. An app may disable a feature entirely because it detected the emulator, and
you will report that a control does not exist when it does. See
[39-EmulatorDetection](../39-EmulatorDetection/README.md).

---

**23. I changed device state to get a bypass working. Does that matter for the report?**

Yes, and forgetting is a classic mistake. `setenforce 0`, a DenyList entry, a hiding module, a
property override — each changes what the app sees, and behaviour you observed under those conditions
may not reproduce on a normal device.

Record every state change you made, and re-verify your key findings with the device returned to a
baseline you can describe. A finding that does not reproduce is worse than no finding, because it
costs the client's engineers a day and costs you credibility.

---

**24. As a developer, what should I actually build?**

In this order, and stop when the budget runs out:

1. **A correct Play Integrity integration.** Server-issued nonce, `requestHash` bound to the specific
   request, token opaque to the app, decoded and evaluated **on the server**, fail closed.
2. **Server-side enforcement of every sensitive capability.** If a rooted client can call your
   transfer endpoint directly and it works, nothing else on this list matters.
3. **Graduated responses.** Block *operations*, not *users*. Read-only mode, step-up authentication,
   fraud review — not `finish()`.
4. **A small native local-signal collector**, sending signals to the server as evidence rather than
   acting on them. Cheap, feeds the fraud model, and the inconsistency between local signals and the
   attested verdict is itself a strong signal.
5. **Nothing else.** Checks fifteen through thirty have approximately zero marginal value and each one
   adds false positives and support cost.

And do not log the detection result. `RootChecker: su found at /system/xbin/su` in logcat hands the
attacker a map of your controls.

---

**25. What is the fastest realistic path from "app closes on launch" to "app runs"?**

```bash
# host — 1. Read the logs first. Developers log. This works more often than it should.
adb logcat -c && adb shell am force-stop com.target.app
adb shell monkey -p com.target.app -c android.intent.category.LAUNCHER 1
adb logcat -v threadtime | grep -iE "root|magisk|su |integrity|tamper"

# 2. Magisk DenyList + Zygisk, force-stop, relaunch.   (60 seconds)

# 3. Find out what actually fires.
frida -U -f com.target.app -l scripts/root-check-tracer.js --no-pause

# 4. Apply the layer the tracer pointed at.
frida -U -f com.target.app -l scripts/java-root-bypass.js -l scripts/native-root-bypass.js --no-pause

# 5. Exercise the SENSITIVE flows, not just the login screen.
```

Step 5 is what separates a finished job from an embarrassing one. Apps very frequently re-check
immediately before the interesting action rather than at startup.

---

## Related reading

- [38-TamperDetection](../38-TamperDetection/README.md) — signature verification, anti-debug, anti-Frida
- [39-EmulatorDetection](../39-EmulatorDetection/README.md) — the sibling control
- [40-Obfuscation](../40-Obfuscation/README.md) — what survives R8, and how to recover encrypted strings
- [62-Magisk](../62-Magisk/README.md) — the other side of the arms race
- [53-Frida](../53-Frida/README.md) — how these hooks work internally
