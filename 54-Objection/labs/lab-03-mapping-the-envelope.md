# Lab 03 — Mapping the envelope: turning "it depends" into a capability statement

**Difficulty:** Advanced
**Time:** 3–4 hours
**Prerequisites:** [lab-01](lab-01-first-session.md) and
[lab-02](lab-02-objection-versus-a-script.md) completed. You can write a Frida hook without
looking it up. [37-RootDetection §2.2](../../37-RootDetection/README.md) and
[36-CertificatePinning §3](../../36-CertificatePinning/README.md) read.

---

## Objective

Stop treating "Objection's coverage" as folklore. By the end of this lab you will have produced,
by experiment, a **capability statement** for two canned commands on **your** version — a table
you could hand to a colleague that says exactly what each command can and cannot influence, with
the evidence attached.

You will be able to:

1. Design a measuring instrument for a canned bypass, rather than testing it against whatever
   app is to hand.
2. Distinguish **four** outcomes that every tool reports identically: covered-and-flipped,
   covered-but-did-not-flip, not-covered, and nothing-to-cover.
3. Produce the same statement for `android sslpinning disable`.
4. Write the result as a reusable artefact rather than a session memory.

> Everything here runs against applications you build. See [SECURITY.md](../../SECURITY.md) for
> authorised-testing scope.

---

## Why this lab exists

Ask five testers what `android root disable` covers and you will get five answers, all of them
vague, none of them wrong enough to argue with. "It handles the common checks." "It's Java-only."
"It works on simple apps."

None of that is a capability statement. A capability statement looks like this:

> On objection 1.11.0, `android root disable` installs three hooks. It can influence a root
> check if and only if the check reaches `java.io.File.exists()` with an absolute path exactly
> equal to one of thirteen strings, **or** `java.lang.Runtime.exec(String)` with a command
> ending in `su`, **or** `java.lang.String.contains("test-keys")`. It cannot influence any other
> path, the `exec(String[])` or `ProcessBuilder` routes, `PackageManager` queries, procfs reads,
> SELinux state, `Settings.Global`, or any native check. Measured coverage against a five-check
> instrument: one of five.

That is falsifiable, version-scoped, and useful. This lab produces one.

---

## Part A — Design the instrument (45 min)

### The principle

You cannot measure a canned bypass against a real app, because a real app's checks are not
under your control and you cannot tell a check that did not fire from a check that was
suppressed. You need a **target you designed**, where each check is:

- **isolated** — one probe per method, so a result is attributable;
- **non-short-circuiting** — every check runs every time, so one result never hides another;
- **individually logged** — with a distinct tag, so `logcat` gives per-check output;
- **positioned deliberately** — some inside the expected envelope, some outside it.

[`../examples/target-app/SecurityGate.java`](../examples/target-app/SecurityGate.java) is one
such instrument. Read it before you extend it.

### Task A.1 — derive the envelope from source, not from documentation

```bash
# host
python3 -B ../scripts/split-agent.py --out /tmp/agent-modules
sed -n '1,140p' /tmp/agent-modules/*android_root*.js
```

Produce a table with one row per hook: the hooked method, the exact condition, and the
substituted behaviour. **Use your version, not this chapter's.**

### Task A.2 — extend the instrument to cover the families it misses

The shipped target has five checks. Add at least four more, one per family from
[37 §2.2](../../37-RootDetection/README.md) that the canned command cannot reach:

```java
// examples/target-app/SecurityGate.java -- additions for lab 03

// Family: PackageManager queries. objection hooks nothing here.
public static boolean checkF_rootManagerPackage(Context ctx) {
    boolean found = false;
    String[] pkgs = {"com.topjohnwu.magisk", "eu.chainfire.supersu",
                     "com.koushikdutta.superuser"};
    for (String p : pkgs) {
        try { ctx.getPackageManager().getPackageInfo(p, 0); found = true; }
        catch (Exception ignored) { }
    }
    Log.i(TAG, "F pm-root-packages     rooted=" + found);
    return found;
}

// Family: procfs. objection hooks nothing here either.
public static boolean checkG_mounts() {
    boolean found = false;
    try {
        BufferedReader r = new BufferedReader(new FileReader("/proc/self/mounts"));
        String line;
        while ((line = r.readLine()) != null) {
            if (line.contains("magisk") || line.contains("/su/")) { found = true; break; }
        }
        r.close();
    } catch (Exception ignored) { }
    Log.i(TAG, "G proc-mounts          rooted=" + found);
    return found;
}

// Family: system properties, read the way real apps read them (not via String.contains).
public static boolean checkH_propViaExec() {
    boolean found = false;
    try {
        Process p = new ProcessBuilder("/system/bin/getprop", "ro.build.tags").start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String out = r.readLine();
        r.close();
        found = out != null && out.indexOf("test-keys") >= 0;
    } catch (Exception ignored) { }
    Log.i(TAG, "H getprop-tags         rooted=" + found);
    return found;
}

// Control: a check INSIDE the envelope that uses a DIFFERENT covered path,
// to confirm the list is matched exactly rather than by prefix.
public static boolean checkI_busybox() {
    boolean found = new File("/system/xbin/busybox").exists();
    Log.i(TAG, "I busybox-known-path   rooted=" + found);
    return found;
}
```

Wire them into `evaluate()` and rebuild:

```bash
# host
cd ../examples && ./build.sh --install
```

### Question A.1

Check H reads `ro.build.tags` through `getprop`. Objection hooks `String.contains("test-keys")`.
Will check H be covered? Reason it out **before** you test.

<details>
<summary>Answer</summary>

**No** — and for two independent reasons, either of which is sufficient.

First, the value arrives through `ProcessBuilder`, not `Runtime.exec(String)`, so hook 2 never
sees it. Second, the comparison uses `String.indexOf`, not `String.contains`, so hook 1 never
fires either.

That second reason is the more interesting one, because it shows the envelope is defined by the
**method the app happens to call**, not by what the app is trying to learn. Two apps asking the
identical question — "do the build tags say test-keys?" — land inside or outside the envelope
purely on the basis of which `String` method the developer typed.
</details>

---

## Part B — Measure the root envelope (60 min)

### The experimental design

Four runs, in this order. The order matters.

| # | Run | Purpose |
|---|---|---|
| 1 | No instrumentation | **Control.** What does the app say when nobody is touching it? |
| 2 | `android root disable` | The claim under test, in the suppressing direction |
| 3 | `android root simulate` | The same hooks in the asserting direction — **this is the one that maps the envelope** |
| 4 | `root-disable-equivalent.js` | The same hooks with full reporting — the ground truth |

### Task B.1 — the control

```bash
# host
adb shell am force-stop com.pentest.ch54.target
adb logcat -c
adb shell am start -n com.pentest.ch54.target/.MainActivity
sleep 4
adb logcat -d -s CH54 > run1-control.txt
```

### Task B.2 — `root disable`

```bash
# host
adb shell am force-stop com.pentest.ch54.target
adb logcat -c
objection -S <serial> -g com.pentest.ch54.target explore
```
```
# objection REPL
android root disable
android intent launch_activity com.pentest.ch54.target.GateActivity
```
```bash
# host
adb logcat -d -s CH54 > run2-disable.txt
diff run1-control.txt run2-disable.txt
```

### Question B.1

On the reference device the diff is empty apart from timestamps. Does that mean the command
failed?

<details>
<summary>Answer</summary>

**Unknown, and that is the finding.** Every check already reported `false` in the control, so a
command that forces checks to report `false` cannot produce an observable change.

"It worked perfectly" and "it did nothing" are indistinguishable here. This is why run 3 exists:
you cannot map an envelope by pushing in the direction the system is already sitting in.
</details>

### Task B.3 — `root simulate`, the run that actually maps the envelope

```bash
# host
adb shell am force-stop com.pentest.ch54.target
adb logcat -c
objection -S <serial> -g com.pentest.ch54.target explore
```
```
# objection REPL
android root simulate
android intent launch_activity com.pentest.ch54.target.GateActivity
```
```bash
# host
adb logcat -d -s CH54 > run3-simulate.txt
diff run1-control.txt run3-simulate.txt
```

Every check that **changed** is inside the envelope. Every check that did not is either outside
it, or inside it and not firing — and you cannot yet tell which.

Reference result on the shipped five-check instrument: `score` went 0/5 → 1/5. Check A flipped.
B, C, D and E did not.

### Task B.4 — the ground truth run

```bash
# host
adb shell am force-stop com.pentest.ch54.target
frida -U -f com.pentest.ch54.target -l ../scripts/root-disable-equivalent.js > run4-truth.txt
```

This run tells you which JDK methods the app actually called, which of them matched the canned
conditions, and which sat outside. It is what lets you separate the two cases run 3 conflated.

### Task B.5 — build the four-outcome table

For each check, classify it into exactly one of four outcomes:

| Outcome | Evidence needed |
|---|---|
| **Covered, and flipped** | changed in run 3 |
| **Covered, did not flip** | unchanged in run 3, but run 4 shows the hook matched |
| **Not covered** | unchanged in run 3, and run 4 shows the call sits outside the conditions |
| **Nothing to cover** | the check never ran at all in run 4 |

| Check | Run 1 | Run 3 | Run 4 evidence | Outcome |
|---|---|---|---|---|
| A `/system/xbin/su` | false | **true** | on the 13-path list | Covered, flipped |
| B `/sbin/magisk` | false | false | | |
| C `exec("/system/bin/su")` | false | false | | |
| D `exec(String[])` | false | false | | |
| E `Build.TAGS.contains` | false | false | | |
| F PackageManager | | | | |
| G `/proc/self/mounts` | | | | |
| H `getprop` via ProcessBuilder | | | | |
| I `/system/xbin/busybox` | | | | |

### Question B.2

Check C is hooked — run 4 shows the agent matched it — yet it did not flip in run 3. Read the
exception message in run 3's logcat. What happened?

<details>
<summary>Answer</summary>

On the reference device the exception changed from
`Cannot run program "/system/bin/su": error=2, No such file or directory`
to
`Attempt to invoke virtual method 'void java.lang.Process.destroy()' on a null object reference`.

The canned hook's "allow" branch does `return this.apply(this, arguments)`. `this` is a Frida
Java **instance wrapper**, not a function, so `.apply()` does not re-enter the original method
and the app receives something that is not a `Process`.

This is a bug in the canned script. It is also the fourth outcome that no tool distinguishes:
the hook fired, announced success, and produced a **different failure** than the one it
replaced. If your detector was grepping for "No such file", it just went quiet for the wrong
reason.
</details>

### Question B.3

Check I probes `/system/xbin/busybox`, which **is** on the thirteen-path list. Did it flip? What
does the answer tell you about how the list is matched?

<details>
<summary>Answer</summary>

It should flip under `simulate`, because the hook compares with `indexOf(path) >= 0` — exact
string equality against the full absolute path.

The instructive comparison is with check B: `/sbin/magisk` does not flip, and
`/data/adb/magisk` does not flip, even though both are plainly root artefacts. The list is
**not** a pattern, a prefix set, or a heuristic. It is thirteen literal strings, and a path that
differs by one character falls straight through.
</details>

---

## Part C — Map the pinning envelope (45 min)

### Task C.1 — read your pinning module

```bash
# host
grep -oE 'Java\.use\("[^"]+"\)' /tmp/agent-modules/*pinning*.js | sort -u
grep -n 'overload(' /tmp/agent-modules/*pinning*.js
```

### Question C.1

One overload signature in that output contains a type name that is not a real Java type. Find
it. What is it, and why is it a serious defect?

<details>
<summary>Answer</summary>

`certificatePinner.check$okhttp.overload("java.lang.String", "u15")`.

`u15` is an **R8-obfuscated class name** from one particular build of one particular
application, hard-coded into the agent. On any app whose OkHttp was minified with a different
seed — which is nearly every app — the class is named something else, the overload lookup
throws, and that hook silently does not install.

It is the clearest example in the whole agent of the general problem with pre-written scripts:
they encode assumptions about the specific app they were written against.
</details>

### Task C.2 — the null-app experiment

Run `android sslpinning disable` against the target app, which has **no networking at all**.

```bash
# host
adb shell am force-stop com.pentest.ch54.target
objection -S <serial> -g com.pentest.ch54.target explore
```
```
# objection REPL
android sslpinning disable
```

Reference output:

```
(agent) Custom TrustManager ready, overriding SSLContext.init()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.verifyChain()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.checkTrustedRecursive()
(agent) Registering job 255269. Type: android-sslpinning-disable
```

### Question C.2

Three hooks reported success against an app that cannot open a socket. Write the one-sentence
rule this establishes for reading pinning output.

<details>
<summary>Answer</summary>

A `Found ... overriding ...` line naming a **platform** class (`SSLContext`,
`com.android.org.conscrypt.TrustManagerImpl`) proves only that you are attached to an Android
process; the only lines that carry information about the app are those naming **third-party**
classes, and the only lines that prove a code path ran are the `Called ...` lines — which
`--quiet` suppresses.
</details>

### Task C.3 — build a positive control

The null-app experiment shows what a *false* positive looks like. Now build the true positive.

Extend the target app with an HTTPS request and a `network_security_config` `<pin-set>` pinned
to a wrong hash, so the connection genuinely fails. Then:

1. Run `android sslpinning disable` and re-attempt the request.
2. Record whether the connection succeeds.

### Question C.3

`network_security_config` pinning is not defeated by any of the seven hooks. Which chapter owns
that, and what does the failure tell a client?

<details>
<summary>Answer</summary>

[44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) owns declarative pinning;
[36 §3](../../36-CertificatePinning/README.md) places it in the layer stack.

What it tells a client is a **capability statement about your tooling, not a finding about their
app**: stock instrumentation does not address declarative pinning, so its survival is not
evidence that the control is strong. Reporting "we could not bypass pinning" when you only tried
one layer is exactly the error [36 §1.6](../../36-CertificatePinning/README.md) warns about —
a partial bypass looks identical to a failed one.
</details>

---

## Part D — Write the capability statement (30 min)

### Deliverable

Produce a one-page document containing:

**1. Scope.** Tool and version, frida versions, device model, Android version, ABI, root method.
Without these the statement is not falsifiable.

**2. The root envelope.** One table: hooked method, exact condition, substituted behaviour.

**3. Measured coverage.** Your four-outcome table from B.5, with the counts.

**4. The pinning envelope.** Classes hooked, plus an explicit "not covered" list: native TLS,
`network_security_config`, WebView, CT, TrustKit, bundled Conscrypt.

**5. Known defects.** At least the `this.apply` bug and the `u15` hard-coded type.

**6. The decision rule.** Two or three sentences telling a colleague when to reach for the
canned command and when not to.

### Task D.1 — validate it

Hand your statement to someone who has not done the lab, with the target app, and ask them to
predict the outcome of three checks they have not seen. If they can, the statement works. If
they cannot, it is prose rather than a specification.

---

## Success criteria

- [ ] You derived the envelope from **your** `agent.js`, not from this chapter.
- [ ] You extended the instrument with at least four checks in uncovered families.
- [ ] You ran all four runs, in order, and kept the outputs as files.
- [ ] You can explain why run 2 alone cannot map an envelope.
- [ ] Every check is classified into exactly one of the four outcomes, with evidence.
- [ ] You found and explained the `this.apply` bug from your own output.
- [ ] You found the hard-coded obfuscated type name in the pinning module.
- [ ] You ran the null-app pinning experiment and can state the reading rule it establishes.
- [ ] Your capability statement lets someone else predict an outcome they have not seen.
- [ ] The app is uninstalled and the device is as you found it.

---

## Clean-up

```bash
# host
cd ../examples && ./build.sh --uninstall
```

---

## Extension work

1. **Version-diff the envelope.** Install objection 1.12.x in a virtualenv, split its agent, and
   diff the root and pinning modules against 1.11.0's. What changed, and what does that tell you
   about how long a capability statement stays true?
2. **Automate it.** Turn Part B into a script: build, install, run all four, diff, and emit the
   four-outcome table as JSON. That is a regression test for a tool's coverage.
3. **Do the same for a family Objection has no commands for at all** — `Settings.Global`
   `adb_enabled`, or SELinux state. Confirm by absence rather than by experiment, and say how
   you know.

---

## What comes next

[lab-04](lab-04-ctf-the-confident-tool.md) is the CTF: an application where every Objection
command reports success and nothing works. Everything you built here is what gets you through it.
