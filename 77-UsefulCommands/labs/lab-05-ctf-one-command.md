# Lab 05 — CTF: One Command, One Flag

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** Labs [01](lab-01-device-recon.md)–[04](lab-04-storage-diff.md), and the whole of
[Chapter 77](../README.md)

---

## The challenge

Twelve questions. Each is answerable with **a single command** — one line, one invocation, no scripts,
no chaining a dozen tools together.

Some are easy if you know the right command and infuriating if you do not. That is the point: this lab
tests whether the command surface has become reflex, which is the difference between a tester who
takes ten minutes to answer a question and one who takes ten seconds.

**Rules:**

- One command per question. A pipeline (`cmd | grep`) counts as one. A `for` loop does not.
- No writing files. No Frida. No decompilers.
- You may use `adb shell` and anything on the device or in the SDK.
- If you need two commands, you have not found the right one — keep looking.

Score yourself honestly. Eight or more without hints is a good result.

---

## Setup

Any device with a few third-party apps installed. A deliberately vulnerable app from
[80-Appendix](../../80-Appendix/README.md) makes several questions more interesting.

```bash
# host
adb devices -l
adb shell pm list packages -3 | head
```

Pick one third-party package as `$PKG` for the questions that need a target.

---

## The questions

### Q1 — Which screen am I looking at?

The device is showing some app. Name the exact Activity class currently in focus.

<details><summary>Answer</summary>

```bash
adb shell dumpsys window | grep mCurrentFocus
```

Output looks like `mCurrentFocus=Window{... u0 com.example/com.example.MainActivity}`.

**Why it matters:** this replaces clicking through JADX guessing which layout corresponds to the screen
in front of you. It is probably the single most-used command in the whole chapter.
</details>

---

### Q2 — Where is this app's APK?

Given a package name, print the full path(s) of its APK file(s) on disk.

<details><summary>Answer</summary>

```bash
adb shell pm path com.example.target
```

**The trap:** on a split-APK install this prints **several** paths. Pull all of them. Analysing only
`base.apk` is how people conclude an app has no native code when its `.so` files are in a config split.
</details>

---

### Q3 — Is this app debuggable?

Determine whether an installed app has the debuggable flag, without pulling or decoding the APK.

<details><summary>Answer</summary>

```bash
adb shell dumpsys package com.example.target | grep -i "flags="
```

Look for `DEBUGGABLE` in the flags list. Also acceptable:

```bash
adb shell run-as com.example.target id
```

If that returns a UID rather than an error, the app is debuggable — you just proved it by using the
capability rather than reading a flag.
</details>

---

### Q4 — What is this app's UID?

Print the Linux UID assigned to a package.

<details><summary>Answer</summary>

```bash
adb shell dumpsys package com.example.target | grep userId=
```

**Why it matters:** you need it to correlate the app with `ps` output, per-UID network statistics, and
`logcat` filtering. It is also how you confirm two packages share a `sharedUserId`.
</details>

---

### Q5 — Show me only this app's log output

Filter logcat to a single running app, without knowing its PID in advance.

<details><summary>Answer</summary>

```bash
adb logcat --pid=$(adb shell pidof -s com.example.target)
```

**The trap:** if the app uses `android:process` it has several PIDs and `pidof -s` returns only one.
Drop `-s` and filter, or use `adb logcat | grep <process-name>`.
</details>

---

### Q6 — Which apps on this device can talk to the internet?

List every third-party package holding the `INTERNET` permission.

<details><summary>Answer</summary>

```bash
adb shell 'for p in $(pm list packages -3 | sed s/package://); do dumpsys package $p | grep -q "android.permission.INTERNET" && echo $p; done'
```

That is a loop, so if you are being strict it fails the rules. The single-command version:

```bash
adb shell dumpsys package | grep -B40 "android.permission.INTERNET: granted=true" | grep "^Package \[" | sort -u
```

**Bonus insight:** `INTERNET` is a Linux group (GID 3003), not a runtime check — see
[06-Android-Architecture](../../06-Android-Architecture/README.md). So this also works:

```bash
adb shell 'cat /proc/net/xt_qtaguid/stats 2>/dev/null | head'
```
</details>

---

### Q7 — Is there anything listening on localhost?

Find TCP services bound to the loopback interface. These are reachable by **any** app holding
`INTERNET` and are a recurring real-world finding.

<details><summary>Answer</summary>

```bash
adb shell netstat -tlnp 2>/dev/null | grep -E '127\.0\.0\.1|::1'
```

Or, when `netstat` is unavailable or lacks `-p`:

```bash
adb shell cat /proc/net/tcp
```

…and decode the hex addresses. `0100007F` is `127.0.0.1` in little-endian.

**Why it matters:** an app listening on localhost has created an IPC endpoint outside the framework
permission model entirely. See [24-IPC](../../24-IPC/README.md).
</details>

---

### Q8 — What did this app write when I logged in?

Without decompiling, show every file in the app's private storage modified in the last two minutes.

<details><summary>Answer</summary>

```bash
adb shell "su -c 'find /data/data/com.example.target -type f -mmin -2 -exec ls -la {} \;'"
```

Or on a debuggable app with no root:

```bash
adb shell run-as com.example.target find . -type f -mmin -2
```

**Why it matters:** this is the fast version of [Lab 04](lab-04-storage-diff.md). When you only need to
know *what* changed rather than *how*, `-mmin` beats a full snapshot diff.
</details>

---

### Q9 — Prove this device's boot chain is intact

In one command, print every property that establishes whether Verified Boot and dm-verity are enforcing.

<details><summary>Answer</summary>

```bash
adb shell getprop | grep -E 'verifiedboot|flash.locked|veritymode|build.tags|debuggable|secure'
```

**What you are looking for:** `verifiedbootstate=green`, `flash.locked=1`, `veritymode=enforcing`,
`build.tags=release-keys`, `debuggable=0`, `secure=1`. Any deviation is covered in
[06-Android-Architecture §5.3](../../06-Android-Architecture/README.md).

**The trap:** `ro.build.tags=test-keys` is the critical one and the easiest to skim past. It means the
image was signed with the **public** AOSP test keys, so anyone can sign a platform-privileged APK.
</details>

---

### Q10 — Read a content provider you were not meant to read

Given an app with an exported provider at authority `com.example.target.provider`, dump the contents of
its `users` table.

<details><summary>Answer</summary>

```bash
adb shell content query --uri content://com.example.target.provider/users
```

**The follow-up that catches people out:** the injection points are `--projection`, `--where` **and**
`--sort`. Automated scanners usually fuzz only `--where`:

```bash
adb shell content query --uri content://com.example.target.provider/users --sort "1=(SELECT 1)"
```

**And the discipline:** this proves reachability from `shell` (UID 2000), *not* from an app. See
[Lab 03](lab-03-exported-sweep.md).
</details>

---

### Q11 — Which certificate signed this app?

Print the signing certificate's SHA-256 digest for an installed package, without pulling the APK.

<details><summary>Answer</summary>

```bash
adb shell dumpsys package com.example.target | grep -A3 "signing details\|signatures"
```

From the APK, if you have it:

```bash
apksigner verify -v --print-certs target.apk
```

**Why it matters:** compare it against any hardcoded digest you find in the app's own tamper-detection
code. And check for `CN=Android Debug` — a release app signed with the public debug key means *anyone*
can sign updates for it.
</details>

---

### Q12 — Make every method in this app interpreted

Put an app into the state where Frida hooks land reliably at every call site.

<details><summary>Answer</summary>

```bash
adb shell cmd package compile -m verify -f com.example.target
```

Then `am force-stop` it so the change takes effect on next launch. (Two commands — take the point if
you named the first.)

**Why it matters:** this is the single highest-value command in Android dynamic analysis. It forces
every method into the interpreter, which defeats the inlining that silently breaks hooks. If a hook
fires after this and did not before, compilation was the cause. Full explanation in
[13-ART §3.10](../../13-ART/README.md) and [Lab 02 of chapter 13](../../13-ART/labs/lab-02-compiler-filters-and-hooks.md).
</details>

---

## Scoring

| Score | Assessment |
|---|---|
| 11–12 | The command surface is reflex. You will not lose time to tooling. |
| 8–10 | Solid. Note which you missed and drill those. |
| 5–7 | Working knowledge with real gaps. Re-read [§3 of the chapter](../README.md). |
| Under 5 | Work through Labs 01–04 first; this one is premature. |

---

## Part 2 — Build your own

The real exercise. Write **five** new questions of the same shape, each answerable in one command, each
teaching something the twelve above do not.

Constraints:

- No two may use the same primary tool
- At least one must use `service call` or raw Binder
- At least one must be about the *device*, not an app
- At least one must have a trap — an obvious wrong answer that looks right

Write them with answers and hand them to someone else.

**Q13.** Which was harder: answering the twelve, or writing five good ones? Why?

---

## Debrief

Answer in writing:

1. For each question you missed, what was the underlying gap — a command you did not know, or a
   *subsystem* you did not know existed?
2. Three questions have traps (Q2 splits, Q5 multi-process, Q10 shell-vs-app). Did you hit any? What
   would each have cost you in a real engagement?
3. Q12's answer is arguably two commands. Does that matter? What does the ambiguity tell you about how
   the compiler filter actually takes effect?
4. Which of the twelve would you run **first** on an unfamiliar device, and why that one?

---

## Success criteria

- [ ] You attempted all twelve before opening any answer
- [ ] You scored 8 or above unaided
- [ ] For every miss, you identified whether the gap was a command or a subsystem
- [ ] You hit — and can explain — the split-APK, multi-process and shell-vs-app traps
- [ ] You wrote five original questions meeting all four constraints
- [ ] You handed them to someone else and they were solvable
- [ ] You answered all four debrief questions in writing
- [ ] `dumpsys window | grep mCurrentFocus` and `cmd package compile -m verify -f` are now muscle memory
