# Lab 02 — One task, two tools: feeling the trade

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [lab-01](lab-01-first-session.md) completed. Working `frida-server` matching
your host. [53-Frida §3.9](../../53-Frida/README.md) skimmed — you will write a hook, and this
lab does not re-teach the Java bridge.

> **This is the most important lab in the chapter.** If you do only one, do this one. It is the
> chapter's thesis converted into an exercise: the same task, solved twice, and a written
> comparison of what each approach told you.

---

## Objective

By the end you will be able to:

1. Solve one concrete task with a canned Objection command and state exactly what you learned.
2. Solve the **same** task with a hand-written Frida script installing the **same** hooks, and
   state exactly what you learned.
3. Quantify the difference — not as an opinion, but as a list of questions each approach can
   and cannot answer.
4. Articulate the rule for choosing between them, and defend it to a sceptical colleague.

> Uses `examples/target-app/`, built for this chapter. See [SECURITY.md](../../SECURITY.md) for
> authorised-testing scope.

---

## The task

You are handed this, verbatim, by a client:

> *"Our app refuses to run on some customers' phones and says the device is not secure. We
> inherited this code. Tell us exactly which check is refusing, so we can decide whether to
> keep it."*

Read it twice. Notice what it does **not** ask. It does not ask you to make the app run. It
asks you to **name the mechanism**, because the deliverable is a decision the client has to
make, and nobody can make a decision from "a tool got past it".

That distinction is the whole lab.

---

## Setup

```bash
# host
export ANDROID_HOME=/path/to/Android/Sdk
cd ../examples && ./build.sh --install

# host -- verify the versions before you measure anything
python3 -B ../scripts/objection-doctor.py --serial <serial>
```

### The mandatory baseline

```bash
# host
adb shell am force-stop com.pentest.ch54.target
adb logcat -c
adb shell am start -n com.pentest.ch54.target/.MainActivity
sleep 3
adb logcat -d -s CH54 | tee baseline.txt
```

Reference device:

```
I CH54: A su-known-path        rooted=false
I CH54: B magisk-unknown-path  rooted=false
I CH54: C exec-string threw: Cannot run program "/system/bin/su": error=2, No such file or directory
I CH54: C exec-su-String       rooted=false
I CH54: D which-su-String[]    rooted=false
I CH54: E build-tags           rooted=false (TAGS=release-keys)
I CH54: VERDICT score=0/5 rooted=false
```

Keep `baseline.txt`. You will compare against it twice.

---

## Part A — Solve it with Objection (25 min)

### Task A.1

```bash
# host
adb shell am force-stop com.pentest.ch54.target
objection -S <serial> -g com.pentest.ch54.target explore
```

```
# objection REPL
android root disable
```

```
(agent) Registering job 370560. Type: root-detection-disable
```

### Task A.2

Re-trigger the gate and read the **app's** log:

```bash
# host
adb shell am start -n com.pentest.ch54.target/.GateActivity
sleep 3
adb logcat -d -s CH54 | tail -8 > objection-result.txt
cat objection-result.txt
```

### Task A.3 — answer the client, using only what you have

Write out the answer to *"which check is refusing?"* using **only** the output of A.1 and A.2.
Do not use anything you know from the chapter or from reading the source. Genuinely try.

### Question A.1

What is the complete list of things Objection told you?

<details>
<summary>Answer</summary>

One job identifier: `370560`, type `root-detection-disable`. That is the entire output.

The verdict was 0/5 before and 0/5 after — which you only know because you took a baseline. A
tester who skipped it would see 0/5 and report "root detection bypassed".
</details>

### Question A.2

Which of these can you now answer? Mark each yes or no.

1. How many root checks does the app perform?
2. Which check refused?
3. Did the command suppress anything, or was there nothing to suppress?
4. Which checks did the command hook?
5. Which did it hook and fail to affect?
6. What did the app probe that the command never looked at?

<details>
<summary>Answer</summary>

**No to all six.**

Not because the tool malfunctioned — it did exactly what it documents — but because the command
is built to produce an *effect* and the client asked for an *explanation*. No amount of
re-running converts one into the other.

This is the trade arriving. It is not a bug, and noticing it quickly is the skill.
</details>

### Task A.4

Try to squeeze more out of Objection before you give up. Legitimate attempts:

```
# objection REPL
android hooking search classes com.pentest.ch54
android hooking list class_methods com.pentest.ch54.target.SecurityGate
android hooking watch class com.pentest.ch54.target.SecurityGate --dump-return
android intent launch_activity com.pentest.ch54.target.GateActivity
```

### Question A.3

`watch class ... --dump-return` gets you closer. What does it now tell you, and what is still
missing?

<details>
<summary>Answer</summary>

**It tells you** which of the app's own five methods ran and what each returned. That is real
progress and it is Objection being used well — as reconnaissance rather than as a bypass.

**Still missing:** the mapping from those methods to the *canned envelope*. You can see check B
returned `false`; you cannot see that `/sbin/magisk` is absent from Objection's thirteen paths,
because Objection never tells you what its paths are. You also cannot see which JDK methods the
app called, only which of its own it called — so `exec(String)` versus `exec(String[])` is
invisible.

Note what this implies: **Objection's reconnaissance commands can answer the question; its
bypass command cannot.** The client's question was never a bypass question.
</details>

---

## Part B — Solve it with a script (60 min)

### Task B.1 — read the canned script first

```bash
# host
python3 -B ../scripts/split-agent.py --out /tmp/agent-modules
grep -n '"/' /tmp/agent-modules/*android_root*.js
sed -n '1,120p' /tmp/agent-modules/*android_root*.js
```

Write down: the number of hooks, the number of paths, and the exact condition on each hook.

### Task B.2 — write it yourself

Now write a Frida script that installs the **same three hooks** and reports every call.

**Do not read [`../scripts/root-disable-equivalent.js`](../scripts/root-disable-equivalent.js)
yet.** Write your own first, even if it is worse. The comparison at the end is only meaningful
if you have felt the work.

A skeleton to start from:

```javascript
// my-root-report.js
Java.perform(function () {
    var PATHS = [ /* the thirteen, from Task B.1 */ ];

    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        var real = this.exists();
        var covered = PATHS.indexOf(p) >= 0;
        console.log('[File.exists] ' + p + ' real=' + real +
                    (covered ? '  (COVERED)' : '  (not on the list)'));
        return covered ? false : real;
    };

    // TODO: Runtime.exec(String)   -- throw IOException when the command ends in "su"
    // TODO: String.contains(String) -- force false when the argument is "test-keys"
});
```

```bash
# host
adb shell am force-stop com.pentest.ch54.target
frida -U -f com.pentest.ch54.target -l my-root-report.js
```

### Task B.3 — add the observers

Your script now reports what Objection *does*. Add what Objection **cannot** do: hook
`Runtime.exec(String[])` and `ProcessBuilder.start()` **without changing their behaviour**, and
count the calls.

```javascript
var Runtime = Java.use('java.lang.Runtime');
var arrayExec = Runtime.exec.overload('[Ljava.lang.String;');
arrayExec.implementation = function (argv) {
    console.log('[exec(String[])] ' + Java.array('java.lang.String', argv).join(' ') +
                '  *** OUTSIDE THE CANNED ENVELOPE ***');
    return arrayExec.call(this, argv);   // change nothing
};
```

### Task B.4 — compare with the shipped version

Now read [`../scripts/root-disable-equivalent.js`](../scripts/root-disable-equivalent.js) and
run it:

```bash
# host
adb shell am force-stop com.pentest.ch54.target
frida -U -f com.pentest.ch54.target -l ../scripts/root-disable-equivalent.js
```

Measured output on the reference device, abridged:

```
[File.exists    ] /system/xbin/su       -> FORCED false  (was false)  (COVERED)
[File.exists    ] /sbin/magisk          -> real: false   *** NOT IN OBJECTION'S 13-PATH LIST ***
[File.exists    ] /data/adb/magisk      -> real: false   *** NOT IN OBJECTION'S 13-PATH LIST ***
[Runtime.exec   ] "/system/bin/su"      -> IOException forced   (objection envelope: COVERED)
[exec(String[]) ] "/system/bin/which su"  *** OUTSIDE OBJECTION'S ENVELOPE -- not hooked ***
[String.contains ] "test-keys" tested against "release-keys" -> FORCED false   (was false)

 INSIDE the canned envelope:
   File.exists()      calls seen : 12
     on objection's 13-path list : 1
   Runtime.exec(String) calls    : 1   (ending in "su": 1)
   String.contains("test-keys")  : 1
 OUTSIDE the canned envelope:
   File.exists() on known-uncovered root paths : 2
   Runtime.exec(String[]) calls                : 1   (su-like: 1)
   ProcessBuilder.start() calls                : 1   (su-like: 0)
```

### Question B.1

Your script and Objection install the same three hooks with the same semantics. Does the **app**
behave differently under one than the other?

<details>
<summary>Answer</summary>

No. That is the point. To the application they are indistinguishable — same hooks, same paths,
same conditions. The entire difference is in what *you* are told.
</details>

### Question B.2

Now answer the client's question, in one paragraph, from the script's output.

<details>
<summary>Answer</summary>

> The application performs six root probes across four families, all in the Java layer:
> `File.exists()` on `/system/xbin/su`, `/sbin/magisk` and `/data/adb/magisk`;
> `Runtime.exec("/system/bin/su")`; `Runtime.exec(String[]{"/system/bin/which","su"})`; and
> `Build.TAGS.contains("test-keys")`. Stock instrumentation tooling can influence three of the
> six — the two `/system/xbin/su` and `su`-suffixed `exec` probes and the build-tags check —
> because its canned bypass hard-codes thirteen paths and hooks only the single-String `exec`
> overload. The Magisk-specific path probes and the array-overload `exec` are outside that
> envelope entirely.

Every clause is backed by a line of output. That is a finding.
</details>

---

## Part C — The two results only the script produced (25 min)

### Task C.1 — the phantom `ProcessBuilder` call

Look at the counts: one `exec(String[])` call and one `ProcessBuilder.start()`. Grep the app's
source: it never mentions `ProcessBuilder`.

### Question C.1

Where did the `ProcessBuilder.start()` call come from, and what does it prove about hooking
`Runtime.exec(String)`?

<details>
<summary>Answer</summary>

From the JDK's own delegation chain:

```
Runtime.exec(String) -> Runtime.exec(String[], String[], File) -> ProcessBuilder.start()
       ^ objection hooks HERE                                          ^ naked
```

It proves that hooking `Runtime.exec(String)` catches **only callers who enter at the top of the
chain**. A developer who writes `exec(new String[]{...})` skips the hooked frame; one who uses
`ProcessBuilder` directly skips two. That is a structural limit, not a configuration one, and no
setting of `android root disable` can change it.
</details>

### Task C.2 — the hook that fires in one ordering and not the other

Compare two runs of the *same* `String.contains` hook.

**Run 1 — Objection, app already running:**

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

The agent's `test-keys` message does **not** appear.

**Run 2 — `frida -f`, app spawned suspended:**

```bash
# host
adb shell am force-stop com.pentest.ch54.target
frida -U -f com.pentest.ch54.target -l ../scripts/root-disable-equivalent.js
```

```
[String.contains ] "test-keys" tested against "release-keys" -> FORCED false   (was false)
```

It fires.

### Question C.2

Same hook, same method, same device. Why does one fire and the other not?

<details>
<summary>Answer</summary>

**Ordering.** `frida -U -f` spawns the process suspended and installs the hook before a single
line of app code runs. In the Objection run, the process had already executed
`checkE_buildTags` once before the command was issued.

`java.lang.String.contains` is a core-library method that ART may intrinsify and inline into a
caller it has already compiled. A hook installed afterwards may never be reached — the code that
would have called it no longer exists as a call.

This is Objection's silent attach-versus-spawn choice (chapter §2.4) producing a visible,
reproducible difference in result. It is the strongest single argument for `am force-stop`
before you connect.
</details>

---

## Part D — The written comparison (30 min)

This is the deliverable.

### Task D.1

Complete this table from your own runs, not from the chapter:

| Question | Objection | Your script |
|---|---|---|
| Time to first result | | |
| Time on the *second* engagement | | |
| Effect on the app | | |
| How many checks does the app perform? | | |
| Which checks are inside the canned envelope? | | |
| Which are outside it? | | |
| Did it suppress anything, or was there nothing to suppress? | | |
| Did a hook install but never fire? | | |
| Is the result a reproducible artefact? | | |
| Process footprint | | |
| Can you answer the client's question? | | |

### Task D.2 — argue the other side

Write a paragraph defending **Objection** against someone who has just done this lab and
concluded the tool is useless.

<details>
<summary>A model answer</summary>

The comparison is rigged, and deliberately so: the client asked an explanation question, and
Objection is built for a decision question. Change the request to *"is this app's root detection
worth a day of my time?"* and the four-second answer is correct, sufficient, and the right
professional call — the script would be twenty minutes wasted.

More than that, Objection did most of the work in Part B. `android hooking search classes`
found `SecurityGate`; `android hooking list class_methods` produced the exact overload
signatures the script needed; `android hooking generate simple` would have printed a scaffold.
The script was cheap to write **because Objection did the reconnaissance**.

The correct conclusion is not that one tool is better. It is that they answer different
questions, they are used in that order, and the skill is noticing quickly which question you
have been asked.
</details>

### Task D.3 — write the rule

In one sentence, state when you stop using Objection. Then check it against chapter §7.4.

---

## Success criteria

- [ ] You took a baseline before either approach.
- [ ] You attempted to answer the client's question from Objection's output alone, and can
      explain precisely why it is impossible.
- [ ] You wrote your own script installing the three hooks, before reading the shipped one.
- [ ] Your script reports at least one call **outside** the canned envelope.
- [ ] You can explain the phantom `ProcessBuilder.start()` call.
- [ ] You reproduced the `String.contains` ordering difference and can explain it.
- [ ] You completed the comparison table with your own numbers.
- [ ] You wrote the defence of Objection, and it is not sarcastic.
- [ ] You uninstalled the app and left the device as you found it.

---

## Clean-up

```bash
# host
cd ../examples && ./build.sh --uninstall
```

---

## Extension work

1. **Extend the script to a family Objection ignores.** Hook `PackageManager.getPackageInfo` and
   report queries for root-manager package names. That is family 4 of
   [37 §2.2](../../37-RootDetection/README.md), and no version of `android root disable` touches it.
2. **Make it an agent, not a script.** Expose `summary()` over `rpc.exports` and drive it from a
   Python harness — [53 §3.12](../../53-Frida/README.md).
3. **Do the same exercise for pinning.** Read your pinning module's `Java.use` list, then compare
   against [53's `ssl-pinning-bypass.js`](../../53-Frida/scripts/ssl-pinning-bypass.js), which
   addresses six layers. Write the coverage table.
4. **Measure the footprint difference.** Compare `heap` under Objection against a session with
   only your script loaded. The chapter measured 7.6 MB for Objection; what does yours cost?

---

## What comes next

[lab-03](lab-03-mapping-the-envelope.md) turns this from a demonstration into a method: you will
determine the exact coverage boundary of two canned commands empirically, and write it up as a
capability statement you could hand to a team.
