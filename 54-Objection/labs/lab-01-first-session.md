# Lab 01 — Your first session, and the four ways it goes wrong

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) read;
[53-Frida lab-01](../../53-Frida/labs/lab-01-first-contact.md) completed, or at least a working
`frida-server`; [60-ADB](../../60-ADB/README.md) for device basics.

---

## Objective

By the end of this lab you will be able to:

1. Get an Objection session against an application **you built**, and state precisely what
   `Agent injected and responds ok!` does and does not prove.
2. Produce each of the **four failure modes** deliberately, recognise each one blind, and
   diagnose it from the symptom alone.
3. Explain, without looking it up, why `adb shell am force-stop` before connecting changes
   your results.
4. Read your own `agent.js` and state how many hooks `android root disable` installs on
   **your** version.

That last one is the point of the lab. Everything else is scaffolding for it.

> **⚠️ Authorised testing only.** Every step uses `examples/target-app/`, an application built
> for this chapter. Do not point any of this at software you do not own.

---

## Setup

### S1. Identify your device before you trust anything

Devices get swapped. This repository's own build log records it happening mid-session more than
once.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abi
adb shell "su -c id"     # uid=0(root) -> you can use frida-server
```

Write the four values down. If `su` returns "inaccessible or not found", you are on the
unrooted path and step S3 will fail — that is expected, and Exercise 5 is written for you.

### S2. Establish the version triple

```bash
# host
python3 -B ../scripts/objection-doctor.py --serial <your-serial>
```

Read the whole report. The reference environment for this chapter was:

```
objection              1.11.0
frida (python)         16.1.6
frida-tools            12.3.0
agent.js size          1045437

model                  M2101K6P
api level              30
device abi             arm64-v8a
rooted                 True
frida-server version   16.1.6
```

**Success criterion for S2:** the doctor prints `RESULT: consistent.` If it does not, fix that
before continuing. Nothing later in this lab will make sense against a mismatched pair.

### S3. Start frida-server

```bash
# adb shell as root
adb shell "su -c '/data/local/tmp/frida-server -D'"

# host -- the wire test
frida-ps -U | head
```

If `frida-ps -U` prints a process list, injection is possible.

### S4. Build and install the target

```bash
# host
export ANDROID_HOME=/path/to/Android/Sdk
cd ../examples
./build.sh --install
```

On an OEM device that refuses `adb install` with `INSTALL_FAILED_USER_RESTRICTED`, the script
detects that exact failure and retries through root automatically. That is not a workaround for
a broken APK; it is an OEM policy, and the script says so.

Confirm the app runs and produces its log:

```bash
# host
adb logcat -c
adb shell am start -n com.pentest.ch54.target/.MainActivity
sleep 3
adb logcat -d -s CH54
```

You should see five checks and a verdict.

---

## Part 1 — The baseline (15 min)

**Do this before you touch Objection.** It is the habit the whole chapter is trying to install.

### Task 1.1

Capture the app's behaviour with nothing instrumenting it:

```bash
# host
adb shell am force-stop com.pentest.ch54.target
adb logcat -c
adb shell am start -n com.pentest.ch54.target/.MainActivity
sleep 3
adb logcat -d -s CH54 > baseline.txt
cat baseline.txt
```

**Record the verdict line.** On the reference device it read:

```
I CH54: VERDICT score=0/5 rooted=false
```

### Question 1.1

Your device is rooted — you proved it in S1 with `su -c id`. The app says it is not. Both
statements are true. Explain how, in one sentence.

<details>
<summary>Answer</summary>

Magisk's DenyList hides root artefacts from the app's view: the `su` binary is not at any path
the app probes, and `ro.build.tags` reads `release-keys`. The app is reporting honestly about
what it can see, which is not the same as what is true. See
[37 §3.14](../../37-RootDetection/README.md).

If your device roots differently — a system-image `su`, or an emulator — you may see a non-zero
score. That is fine and it makes Part 3 easier to read.
</details>

### Question 1.2

Why does this baseline matter more than any command you are about to run?

<details>
<summary>Answer</summary>

Because a bypass command that changes nothing and a bypass command that had nothing to change
produce **identical** output. Without the control run you cannot distinguish them, and you will
report a defeated check that never fired. [51 §3.2](../../51-DynamicAnalysis/README.md) makes
the control run a required stage for exactly this reason.
</details>

---

## Part 2 — Connecting (15 min)

### Task 2.1

```bash
# host
adb shell am force-stop com.pentest.ch54.target
objection -S <serial> -g com.pentest.ch54.target explore
```

Expected:

```
Using USB device `M2101K6P`
Agent injected and responds ok!
```

> **If `explore` aborts with a `prompt_toolkit` traceback**, your shell has no console — this
> happens on Windows with redirected input, and in CI. Use API mode instead; the whole lab
> works through it:
> ```bash
> objection -S <serial> -g com.pentest.ch54.target api &
> curl -s http://127.0.0.1:8888/rpc/invoke/envFrida
> ```
> Endpoint names are RPC exports, not commands. The chapter cheatsheet §10 has the mapping.

### Task 2.2

```
# objection REPL
env
frida
ping
jobs list
```

Record `heap` from the `frida` output.

### Question 2.1

`Agent injected and responds ok!` printed. Which of these does it prove?

- (a) frida-server is running and reachable
- (b) The agent loaded and answered an RPC call
- (c) Your objection, frida and frida-server versions are compatible
- (d) Hooking commands will work

<details>
<summary>Answer</summary>

**(a) and (b) only.**

Objection calls `rpc.exports.ping()` and requires a truthy answer before printing that line, so
the socket and the agent are both alive.

It does **not** prove (c). Three version relationships must hold, and `ping()` exercises only
the wire. An `agent.js` built against a different Frida major will connect happily and then
throw on the first command that touches the Java bridge. It therefore does not prove (d)
either.
</details>

### Question 2.2

Your `heap` value is roughly 7.6 MB on the reference device. The application's own code is
three classes. Where did 7.6 MB come from, and what does it cost you operationally?

<details>
<summary>Answer</summary>

It is Objection's `agent.js` — about a megabyte of compiled JavaScript, 125 modules, including
a full iOS implementation that will never run — parsed and resident in the target process's
QuickJS heap.

Operationally it is footprint. Anti-instrumentation heuristics scale with footprint, so an app
that tolerates a 200 KB hand-written script may kill an Objection session. If that happens, the
fix is a smaller tool, not a hunt for "anti-Objection" code.
</details>

---

## Part 3 — Reconnaissance, which is what the tool is for (20 min)

### Task 3.1

```
# objection REPL
android hooking list classes
```

Count them. On the reference device: **16,087**.

### Task 3.2

Now filter:

```
# objection REPL
android hooking search classes com.pentest.ch54
```

Three results. One is called `SecurityGate`.

### Task 3.3

Get exact signatures:

```
# objection REPL
android hooking list class_methods com.pentest.ch54.target.SecurityGate
android hooking list class_methods com.pentest.ch54.target.MainActivity$AuthGate
```

### Question 3.1

16,087 classes for an app with three of its own. What is everything else, and what does the
ratio tell you about how to use this command?

<details>
<summary>Answer</summary>

Framework and support-library classes the process has loaded. The command reads the runtime's
loaded-class table, not the APK.

The ratio tells you `list classes` is never the command you want on its own — always
`search classes <your.target.package>`. It also tells you the table is a *runtime* artefact,
which is why it survives R8 renaming (the runtime still has to register every class) and why it
misses classes the app has not touched yet.
</details>

### Question 3.2

`AuthGate` shows **two** `checkPin` entries. Why does that matter before you hook it?

<details>
<summary>Answer</summary>

They are overloads — `checkPin(int)` and `checkPin(java.lang.String)`. A Frida hook is
per-signature, exactly as Java dispatch is. If you supply no overload filter, Objection hooks
**both**, which is usually right during reconnaissance and wrong when measuring, because a
delegating pair double-reports every call.

This is also, precisely, the bug in Objection's own root hook: it hooks
`Runtime.exec(String)` and leaves `exec(String[])` untouched.
</details>

---

## Part 4 — The four failure modes, produced deliberately (30 min)

This is the core of the lab. You will cause each failure on purpose, so that you recognise it
when it happens by accident.

### Failure 3 first — the hook that landed too late

Failure 3 is the most common and the easiest to stage.

```bash
# host -- START the app and LEAVE IT RUNNING
adb shell am force-stop com.pentest.ch54.target
adb shell am start -n com.pentest.ch54.target/.MainActivity
sleep 3
# now connect while it is running -- objection will ATTACH
objection -S <serial> -g com.pentest.ch54.target explore
```

```
# objection REPL
android hooking watch class_method com.pentest.ch54.target.SecurityGate.checkA_suBinaryKnownPath --dump-return
```

Nothing happens. The check ran during `onCreate`, before you connected.

Now fix it:

```
# objection REPL
android intent launch_activity com.pentest.ch54.target.GateActivity
```

The watch fires.

### Task 4.1

Repeat the whole thing with a `force-stop` **before** connecting, so Objection spawns instead.
Note the difference in what you had to do to see output.

### Question 4.1

State, in one sentence, the rule that this exercise establishes.

<details>
<summary>Answer</summary>

Objection attaches to a running process and spawns a stopped one, silently and with no flag to
force either, so `adb shell am force-stop <pkg>` before connecting is what turns an ambiguous
default into a known starting state.
</details>

### Failure 2 — the class that is not there

```
# objection REPL
android hooking list class_methods com.pentest.ch54.target.NoSuchClass
```

You get an error rather than a list. Now the subtler version:

```
# objection REPL
android sslpinning disable
```

Watch which lines appear. On the reference run:

```
(agent) Custom TrustManager ready, overriding SSLContext.init()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.verifyChain()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.checkTrustedRecursive()
```

### Question 4.2

The target app has **no networking at all** — no `INTERNET` permission, no HTTP client, no TLS.
Three hooks reported success. Explain, and say which four of the seven hooks are missing from
that output and why.

<details>
<summary>Answer</summary>

The three that reported are `SSLContext.init` and the two `TrustManagerImpl` methods. All three
are **platform** classes, loaded into every Android process regardless of what the app does. The
hooks genuinely installed; that fact says nothing about the app.

The four missing ones target `okhttp3.CertificatePinner` (twice),
`appcelerator.https.PinningTrustManager` and `nl.xservices.plugins.SSLCertificateChecker` —
third-party classes that are not in this app, so `Java.use` threw `ClassNotFoundException` and
the agent swallowed it silently.

**The informative lines are the ones naming third-party classes**, and the *most* informative
are the `Called ...` lines printed when a hook actually fires. `--quiet` suppresses exactly
those.
</details>

### Failure 4 — outside the envelope

```bash
# host
adb shell am force-stop com.pentest.ch54.target
objection -S <serial> -g com.pentest.ch54.target explore
```

```
# objection REPL
android root simulate
android intent launch_activity com.pentest.ch54.target.GateActivity
```

```bash
# host
adb logcat -d -s CH54 | grep -A8 "GateActivity re-running"
```

On the reference device: `score=1/5`. Check A flipped; B, C, D and E did not.

### Task 4.2

For each of the five checks, say whether it is inside or outside the canned envelope, and why.
Use [`../examples/target-app/SecurityGate.java`](../examples/target-app/SecurityGate.java) and
your own `agent.js` — not this chapter's tables.

### Failure 1 — injection never happened

If you have an unrooted device, use it. Otherwise stop `frida-server`:

```bash
# adb shell as root
adb shell "su -c 'pkill frida-server'"
```

```bash
# host
objection -g com.pentest.ch54.target explore
```

### Question 4.3

Objection prints `Unable to connect to the frida server: <something>`. Why is the headline
unreliable, and what should you read instead?

<details>
<summary>Answer</summary>

Objection prints that one sentence for **three** different exception types —
`ServerNotRunningError`, `NotSupportedError` and `ProtocolError` — so the headline is a guess
and the text after the colon is the actual diagnosis.

Measured on an unrooted Android 13 device, the same headline carried:
`need Gadget to attach on jailed Android; its default location is: ...gadget-android-arm64.so`
— which is not a server problem at all.

**In Objection, the diagnosis is always after the colon.**
</details>

---

## Part 5 — Read your own agent (20 min)

The most valuable twenty minutes in the chapter.

### Task 5.1

```bash
# host
python3 -B ../scripts/split-agent.py --out /tmp/agent-modules
python3 -B ../scripts/split-agent.py --list --filter android
```

### Task 5.2

```bash
# host
grep -n '"/' /tmp/agent-modules/*android_root*.js
```

Count the paths. Count the hooks.

### Task 5.3

```bash
# host
grep -oE 'Java\.use\("[^"]+"\)' /tmp/agent-modules/*pinning*.js | sort -u
```

### Deliverable

Write four sentences, in your own words:

1. How many hooks does `android root disable` install on **your** version, and what are they?
2. How many hard-coded paths, and how are they matched — exactly, by prefix, or by pattern?
3. Which classes does **your** pinning bypass know about?
4. Name one root-detection technique from [37 §2.2](../../37-RootDetection/README.md) that your
   version cannot touch, and say why not.

---

## Success criteria

You have finished this lab when all of the following are true:

- [ ] `objection-doctor.py` reports `RESULT: consistent.`
- [ ] You captured a **baseline** before running any Objection command, and can say why.
- [ ] You produced all four failure modes deliberately and can describe each symptom.
- [ ] You can explain why failures 3 and 4 look identical, and name the one-minute experiment
      that separates them.
- [ ] You can state what `Agent injected and responds ok!` does **not** prove.
- [ ] You have read your own `agent.js` and know the hook count and path count for your version.
- [ ] You uninstalled the target app and left the device as you found it.

---

## Clean-up

```bash
# host
cd ../examples && ./build.sh --uninstall
adb shell "su -c 'pkill frida-server'"    # only if YOU started it
```

---

## Hints

<details>
<summary>Objection connects but every command errors</summary>

Version skew of the third kind: your `agent.js` was built against a different Frida JavaScript
API than the `frida-server` you are talking to. `env` and `ping` work because they do not touch
the Java bridge. Align objection, the frida Python package and frida-server. See chapter §3.11.
</details>

<details>
<summary>`android hooking search classes` returns nothing for my package</summary>

The classes are not loaded yet. Drive the app to a screen that uses them first, then retry. The
command reads the runtime's table, not the APK.
</details>

<details>
<summary>`build.sh` fails with "failed to load XML file"</summary>

You are on Git Bash and the SDK tools are Windows binaries that do not understand `/c/Users/...`
paths. The script already handles this with `cygpath`; check that `cygpath` is on your PATH. Also
note that XML comments must not contain two consecutive hyphens — `aapt2` rejects the file with
a confusing "not well-formed" error if they do.
</details>

<details>
<summary>My verdict is not 0/5</summary>

Good — your device exposes root artefacts the reference device hides. The lab still works; your
numbers will differ, and Part 4's `root disable` will produce a *visible* change, which makes it
easier to read, not harder. Record your own numbers.
</details>

---

## What comes next

[lab-02](lab-02-objection-versus-a-script.md) takes one task and solves it twice — once with
Objection, once with a hand-written script — so you can feel the trade rather than read about it.
