# 67 — Bypassing Protections — FAQ

Real questions, including the ones people are embarrassed to ask. Answered directly.
Everything here assumes an application you own or are contracted to test — see
[README §1.3](README.md#13-scope-and-ethics-stated-once-and-precisely).

---

### 1. Why does the app close the moment I attach?

Because something ran before you did.

The overwhelmingly likely cause is a check in native code that executed at **library load time** —
either an `.init_array` constructor (which runs *inside* `dlopen`) or `JNI_OnLoad` (which runs
immediately after, inside `System.loadLibrary`). Both happen before any of the app's own Java code,
and both happen before you can possibly have attached to a process that was already running.

Do this, in this order:

```bash
# host — 1. what killed it, and when?
python3 -B scripts/bypass-triage.py -p <pkg> --postmortem
```

If you see `reason=5 (CRASH_NATIVE) status=6` and **no Activity lifecycle events**, that is the
load-time case, confirmed. The tombstone's first app-owned frame names the library and symbol that
did it.

```bash
# host — 2. stop attaching. Spawn.
frida -U -f <pkg> -l scripts/early-instrument.js --no-pause
```

If it *still* dies when you spawn, the check is running before your script can install hooks —
usually a packer, or `PTRACE_TRACEME` in a constructor. See question 4.

**The other possibility, and check it before the exotic ones:** the app crashed for an ordinary
reason and you are attributing it to a protection. `reason=4 CRASH` at launch is far more often a
bug than a control. Read the stack.

---

### 2. I hooked the check and nothing changed. Why?

Six causes, in the order you should eliminate them:

1. **The hook never installed.** Confirm it fired at all — put a `console.log` at the top of the
   implementation, not just in the branch you care about. A `Java.use` on a class that has not been
   loaded yet silently throws inside `Java.perform` and your script continues.
2. **There is a second tier you did not hook.** You hooked `java.io.File.exists()` and the real check
   is `stat()` in a `.so`. Your log fills with intercepted calls and the app still refuses. Hook
   libc; it catches both, because libcore calls libc too.
3. **Wrong overload.** `SystemProperties.get` has two overloads, and hooking one leaves the other
   live. Iterate `.overloads` rather than picking one.
4. **Wrong class loader.** A packed or multi-DEX app loads classes from a loader `Java.use` does not
   search by default. Use `Java.enumerateClassLoaders` and `Java.classFactory.loader`.
5. **The check already ran.** You hooked `evaluate()` but the verdict was computed in
   `Application.onCreate`, before your `Java.perform` body executed. Spawn.
6. **There is a second copy of the check.** A competent app computes the verdict in two places, in
   two languages, and compares. You changed one. This is deliberate anti-tamper and it is the point
   at which you should stop attacking the verdict and attack the read instead.

---

### 3. Is spawn or attach better?

**Spawn, unless you have a specific reason not to.**

| | Spawn (`-f`) | Attach (`-F` / `-n`) |
|---|---|---|
| Before `.init_array` | Yes | No |
| Before `JNI_OnLoad` | Yes | No |
| Before `Application.onCreate` | Yes | No |
| Preserves app state (logged in, mid-flow) | **No — you lose it** | **Yes** |
| Works when the app is already misbehaving | No | Yes |

The one genuine reason to attach is that you need the process's *current* state — a live session,
a decrypted buffer, a token that took a login to obtain. Attaching is a deliberate trade, not a
default.

There is a third option people forget: **spawn, then reproduce the state**. It is slower once and
faster every time afterwards, and it is what you want if you are going to run this more than twice.

---

### 4. It dies even when I spawn. Now what?

Then something runs before Frida's agent finishes installing. Three causes:

1. **`PTRACE_TRACEME` in a constructor.** The app traces itself, occupying the only tracer slot, so
   Frida's injection fails. Defeat it by hooking `ptrace` before the app's libraries load —
   `scripts/early-instrument.js` is built for this, and the hook itself is four lines.
2. **A packer.** The real code is decrypted at runtime by a loader whose own constructor runs first.
   [40-Obfuscation](../40-Obfuscation/README.md) owns this; dump the DEX before doing anything else.
3. **Frida-server itself is being detected before your script runs.** Move it:
   `frida-server -l 127.0.0.1:1337 --directory /data/local/tmp/.x`. This costs nothing and defeats a
   surprising fraction of anti-Frida in the wild.

If none of the three works, consider **frida-gadget** instead of frida-server: embedded in the APK,
the gadget loads earlier than anything else in the process, because the loader itself is what maps
it. That requires repackaging, which trips signature checks — which is chapter 38's problem, and now
you are on the ladder.

---

### 5. Can the app tell that I bypassed it?

It depends entirely on which seam you used, and this is the practical reason the seam taxonomy
matters rather than being an abstraction.

| Seam | Can the app tell? | How it would |
|---|---|---|
| S1 — input | **Almost never.** The app reads a world that genuinely says what it says | Only by asking a source you forgot to change |
| S2 — read | Only with counter-instrumentation | Inline-hook checksums; timing; re-reading via a path you did not hook |
| S3 — verdict | **Easily** | Compute it twice and compare; checksum the function; time it |
| S4 — branch | **Easily** | Same, plus a signature check catches a static patch |
| S5 — gated code | **No.** No control was touched | It cannot — but it can be *designed* so that calling directly produces garbage |

The general principle: the closer you act to the decision, the more of the app's own state
contradicts its behaviour, and internal contradiction is exactly what a second layer looks for.

---

### 6. When should I give up hooking and just read the code?

When any of these is true — and this is a decision, not a defeat:

- The check issues **inline syscalls** (`svc #0`) and never touches a libc symbol. Nothing that
  resolves symbols can help you.
- The function **checksums its own bytes**. Your hook is the modification being detected.
- You are three rounds into the escalation and **each round costs more than the last**. You are on
  the wrong side of an exponential; the code, by contrast, is finite.
- What you want is an **algorithm**, not a decision. A hook gives you the answer this session; a
  reimplementation gives it to you forever, and to whoever reads your report next year.

**Keep hooking** when you need runtime *values* — a decrypted buffer, a derived key, a session token.
Static analysis gives you the algorithm; only the running process has the data.

> Hooking rents the answer. Static analysis buys it. Rent while you are still deciding what you
> want.

And remember the third option: **go around**. If the app is hard and the server is soft, stop
attacking the app.

---

### 7. Why is hooking the "isRooted" function considered bad practice if it works?

It is not bad practice; it is the wrong *default*. It is excellent for triage — thirty seconds to
learn whether the thing behind the check is worth pursuing.

The problems appear when you rely on it:

- It **breaks on the next release**, because R8 renames the method.
- It is **easy to detect** — the app can compute the verdict twice, or checksum the function whose
  prologue your hook just overwrote.
- It **teaches you nothing**. The content of your report is *which signals the app weighs* and,
  more interestingly, which it does not. A verdict hook hides all of that.

Run it to decide whether to continue. Then throw it away and hook the reads.

---

### 8. What is the difference between `TracerPid` and `Debug.isDebuggerConnected()`?

They are unrelated, and confusing them is common on both sides.

- **`TracerPid`** is written by the **kernel** into `/proc/<pid>/status`. It is non-zero when a
  process is `ptrace`-attached. It catches `gdb`, `lldb`, `strace`, and a Frida injection *while it
  is happening*.
- **`Debug.isDebuggerConnected()`** asks **ART** whether a **JDWP** debugger is attached. JDWP is not
  ptrace and does not set `TracerPid`.

You can be JDWP-debugged with `TracerPid` at 0, and `ptrace`d with `isDebuggerConnected()` returning
false. An app that checks one and believes it covered the other has a gap; a tester who defeats one
and assumes the other is handled has a bad afternoon coming.

---

### 9. Frida detaches after injecting, so `TracerPid` is 0. Why do apps still check it?

Three reasons, and only the first is good:

1. It genuinely catches `gdb`/`lldb`/`strace`, which are real analysis tools.
2. It catches the *window* during injection, if the app polls frequently.
3. It is in every tutorial, so it is in every app, regardless of whether it works.

Treat a `TracerPid` check as an **anti-debugger** control, not an anti-Frida one. If an app has only
that, its author was following a checklist.

---

### 10. Is running frida-server on a different port really a "bypass"?

Yes, and it is the best kind — a seam-1 attack.

The check asks "is anything listening on 27042?" You do not lie about the answer. You make the
answer honestly "no". There is no hook to be detected, nothing to maintain across releases, and
nothing that a self-checksum or a timing measurement can see.

```bash
adb shell "/data/local/tmp/frida-server -l 127.0.0.1:1337 --directory /data/local/tmp/.x &"
frida -H 127.0.0.1:1337 -f <pkg> -l agent.js --no-pause
```

That one change defeats the port check, the handshake check, the `re.frida.server` directory check
and the `linjector` pipe check. Four of the eleven common anti-Frida techniques, for one flag.

---

### 11. The app runs fine but gives me the wrong data. Is it broken?

Probably not. That is very likely **silent degradation** — the app detected you, decided not to
crash, and is quietly producing wrong results. It is the response that costs an attacker the most
time, precisely because nothing looks wrong.

The demo app in this chapter implements it as `Guard.Response.POISON`. Measured: the vault opened
and returned `ch[CLNTSDBLANSNTALCK]` instead of `CH67{cl13nt_s1d3_b00l3an_1s_n0t_a_l0ck}`. Nothing
crashed. Nothing logged an error. There is **no exit record**, because nothing exited.

**How to catch it:** differential testing. Run the same flow clean, record the output, then run it
instrumented and diff. Compare *outputs*, not exit codes. The triage script explicitly tells you it
cannot detect this case, because a tool that quietly misses something is worse than one that says so.

---

### 12. Do I need root?

For most of this chapter, yes — frida-server needs root to inject, and seam 1 needs root for
anything that changes the device.

What you can do **without** root, all of which this chapter demonstrates on an unrooted phone:

- Full triage: `dumpsys activity exit-info`, `logcat`, the events buffer, tombstone frames.
- The complete static pass, including native-library string and symbol analysis.
- Build and install your own targets.
- Make two controls fire honestly: an anti-Frida port check (`adb reverse tcp:27042 tcp:27042`
  creates a real device-side listener) and a `FLAG_DEBUGGABLE` check (build the same sources twice).
- Instrument your own app with **frida-gadget** embedded in the APK — no root at all, and it loads
  earlier than frida-server can attach.

That last one is the serious no-root answer for an app you own. For an app you do not own,
repackaging to embed the gadget is a modification you probably are not authorised to make.

---

### 13. What is the difference between this chapter and 37-RootDetection?

37 owns **root**: what it is, how it is detected, and how that specific detection is defeated. It
ships the reference libc-interposition script and the tracer.

67 owns the **method** that 37 is an instance of. Root detection, pinning, tamper checks and
anti-debug all have the same five seams, and the choice between them follows the same rules. If you
only ever needed to defeat root, 37 alone is enough. The moment you meet a control 37 does not cover,
you need the shape rather than the script.

Practically: read 37 for the artefact tables and the scripts, read 67 for the decision about where
to attack and whether it was worth reporting.

---

### 14. Can I just patch the APK instead of hooking?

Often, yes — and for anything you need to reproduce later, it is the better answer. The trade-offs:

| | Hooking | Patching |
|---|---|---|
| Setup | Seconds | 15–60 min per build |
| Survives an app update | Usually (at low seams) | No — redo it |
| Detectable | Only by counter-instrumentation | **By any signature check** |
| Reproducible by someone else | No | Yes — you have an artefact |
| Works against inline-hook checksums | No | Yes |
| Works against a self-checksum | No | Only if you patch that too |

The killer is the signature check: a repackaged APK has a different signing certificate, and any app
that verifies its own signature — or, far worse for you, whose **server** verifies it — notices
immediately. That is chapter 38's subject, and it is where the ladder usually turns.

---

### 15. Is a bypassed control a vulnerability?

**No, not by itself.** This is the most important professional point in the chapter.

Ask three questions, in this order:

1. **What was the control protecting?** If it gated a screen the user could reach anyway, the finding
   is INFO no matter how clever the bypass.
2. **Does the server re-verify?** If flipping the client's decision changes only the client's
   behaviour, you have a **resilience** weakness, not an authorisation flaw. Say that sentence
   explicitly; a reader who does not see it will assume the worst.
3. **What could you do once inside?** *That* is the finding — the extracted key, the forged request
   the server accepted, the other user's data.

Report the resilience weakness separately and lower. Two findings, honestly rated, are worth more
than one inflated one.

---

### 16. Everyone says client-side controls are useless. Are they?

No — they are **badly described**, which is different.

They do not prevent a determined attacker. They cannot; the trust model forbids it. What they do is
**raise cost**, and cost is exactly the right currency against unattended, scaled fraud, which needs
to work across thousands of devices without a human. A control that takes two hours to defeat and
must be re-defeated every release is a genuine operational problem for that adversary and no problem
at all for a researcher with a weekend.

Where they become actively harmful: when they are used **instead of** a server-side control rather
than alongside one; when they respond by hard-blocking, which pushes legitimate rooted users toward
cracked builds; and when a false positive silently corrupts real data.

The defensible position is a small, cheap client-side layer wired into server-side telemetry and risk
scoring, and everything else spent on the server.

---

### 17. Why does my hook work in the REPL but not from `-l script.js`?

Almost always timing. From the REPL you type the command after the app has loaded the class you are
hooking; from `-l` the script runs at spawn, before it exists.

```javascript
// Wrong when the class is loaded later.
Java.perform(function () { Java.use('com.x.Guard'); });   // ClassNotFoundException

// Right: wait for the class loader that has it.
Java.perform(function () {
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                loader.loadClass('com.x.Guard');
                Java.classFactory.loader = loader;
                // ... install the hook here ...
            } catch (e) { /* not this one */ }
        },
        onComplete: function () { }
    });
});
```

---

### 18. What is the very first thing I should run against a new target?

Before any hook:

```bash
# host — 1. identify the device and record it in your notes
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk

# host — 2. what does "working" look like? You cannot detect degradation without this.
python3 -B scripts/bypass-triage.py -p <pkg> -a .MainActivity --json baseline.json

# host — 3. what controls EXIST, in how many tiers?
python3 -B scripts/bypass-triage.py -p <pkg> --apk target.apk --postmortem
```

Step 3 is the one that saves the most time. If the same detection strings appear in **both**
`classes.dex` and a `.so`, there are two tiers, and a Java-only bypass will not be enough — which you
now know before writing it rather than after.

---

### 19. Why does the chapter keep saying "the lowest altitude that works"?

Because three independent things all improve as you move lower, and only one thing gets worse.

Better as you go lower: **robustness** (a libc symbol does not get renamed by R8), **invisibility**
(the app reads a world that genuinely says what it says), and **information** (you learn which
signals matter, which is your actual finding).

Worse as you go lower: **blast radius**. A seam-1 change affects every process on the device,
including whatever you measured your baseline with, and on a client's loaned device that may be
unacceptable.

So the rule is not "always go as low as possible". It is: go as low as your constraints allow, and
when you cannot, write down *why* — because the reason is itself a finding about the app.

---

### 20. I defeated everything and the server still says no. Did I fail?

You succeeded, and you have found the one thing in this chapter worth reporting positively.

A server that independently re-verifies is the control that actually holds. Every technique here
works against the client and none of them changes what the server does. Write that down explicitly:
*"client-side authorisation can be flipped, and the server rejected the resulting request"* is a
sentence that tells your client their architecture is right, and it is worth more to them than a
list of bypasses.

Then go and test the server properly, because that is now where the interesting questions are: is
the nonce single-use, does the endpoint authenticate, does it send a **capability** or a
**permission**? [`examples/server-app/`](examples/server-app/) exists so you can practise exactly
that transition.
