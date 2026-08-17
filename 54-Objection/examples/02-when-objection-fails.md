# Example 02 — Where Objection loses, and the hand-written equivalent wins

One task. Two tools. The same three hooks. Completely different outcomes.

**The task:** *"This application refuses to run. Tell the developer exactly which check
refused, so they can decide whether to keep it."*

That is a normal engagement request, and it is worth noticing what it asks for. It does not
ask you to make the app run. It asks you to **name the mechanism** — because the deliverable
is a decision the developer has to make, and they cannot make it from "a tool got past it".

All output below was produced on a real device against [`target-app/`](target-app/), an
application built for this chapter. Environment as in
[`01-annotated-session.md`](01-annotated-session.md): Redmi `M2101K6P`, Android 11 / API 30,
arm64, Magisk-rooted, frida-server 16.1.6, objection 1.11.0, frida 16.1.6.

---

## Attempt 1 — Objection

```bash
# host
adb shell am force-stop com.pentest.ch54.target
objection -g com.pentest.ch54.target explore
```

```
# objection REPL
android root disable
```

```
(agent) Registering job 370560. Type: root-detection-disable
```

Re-trigger the gate:

```bash
# host
adb shell am start -n com.pentest.ch54.target/.GateActivity
adb logcat -d -s CH54 | tail -8
```

```
I CH54: VERDICT score=0/5 rooted=false
```

### What you have

A job identifier. That is the complete output of the command.

You know the verdict is 0/5. You knew that before you started, because you took a baseline.
You do **not** know:

- how many checks the app performs (five, as it happens),
- which of them the command hooked (three of five sit inside its envelope),
- which of them actually fired (one of the three),
- whether any check was suppressed or whether there was simply nothing to suppress,
- what the app probed that the tool never looked at.

**You cannot answer the question.** Not because the tool malfunctioned — it did exactly what
it is documented to do — but because the command is designed to produce an *effect* and the
question asks for an *explanation*. No amount of re-running it will convert one into the other.

The failure here is not a bug. It is the trade, arriving.

---

## Attempt 2 — the hand-written equivalent

[`../scripts/root-disable-equivalent.js`](../scripts/root-disable-equivalent.js) installs the
**same three hooks**, using the **same thirteen hard-coded paths**, with the **same
semantics** — transcribed from Objection's own `agent.js` module 90. To the application the
two are indistinguishable.

The difference is entirely in what it tells *you*.

```bash
# host
adb shell am force-stop com.pentest.ch54.target
frida -U -f com.pentest.ch54.target -l scripts/root-disable-equivalent.js
```

Measured output, abridged only by dropping eight uninteresting `File.exists()` lines from the
app's ordinary startup:

```
root-disable-equivalent.js  --  chapter 54
reproducing `objection android root disable`, with the reporting it lacks
mode: ACTIVE

[+] hook 1/3 installed: java.lang.String.contains(String)
[+] hook 2/3 installed: java.lang.Runtime.exec(java.lang.String)
[+] hook 3/3 installed: java.io.File.exists()
[+] observer installed: java.lang.Runtime.exec(String[])  (reports only)
[+] observer installed: java.lang.ProcessBuilder.start()  (reports only)

[File.exists    ] /data/user/0/com.pentest.ch54.target       -> real: true    (not a root path)
[File.exists    ] /data/user_de/0/com.pentest.ch54.target    -> real: true    (not a root path)
[File.exists    ] /system/xbin/su                            -> FORCED false  (was false)  (COVERED)
[File.exists    ] /sbin/magisk         -> real: false   *** NOT IN OBJECTION'S 13-PATH LIST ***
[File.exists    ] /data/adb/magisk     -> real: false   *** NOT IN OBJECTION'S 13-PATH LIST ***
[Runtime.exec   ] "/system/bin/su"  -> IOException forced   (objection envelope: COVERED)
[exec(String[]) ] "/system/bin/which su"  *** OUTSIDE OBJECTION'S ENVELOPE -- not hooked ***
[String.contains ] "test-keys" tested against "release-keys" -> FORCED false   (was false)

==============================================================
 COVERAGE SUMMARY -- objection android root disable equivalent
 mode: ACTIVE (behaves as objection does)
 window: 15s
==============================================================

 INSIDE the canned envelope -- these three hooks ARE what
 `android root disable` installs:
   File.exists()      calls seen : 12
     on objection's 13-path list : 1
   Runtime.exec(String) calls    : 1   (ending in "su": 1)
   String.contains("test-keys")  : 1

   paths matched from the list:
     /system/xbin/su                              x1

 OUTSIDE the canned envelope -- no configuration of
 `android root disable` can influence any of these:
   File.exists() on known-uncovered root paths : 2
   Runtime.exec(String[]) calls                : 1   (su-like: 1)
   ProcessBuilder.start() calls                : 1   (su-like: 0)

   uncovered paths the app actually probed:
     /sbin/magisk                                 x1
     /data/adb/magisk                             x1

 HOOK STATUS
   [installed] String.contains
   [installed] Runtime.exec(String)
   [installed] File.exists
   [installed] Runtime.exec(String[]) [OBSERVER]
   [installed] ProcessBuilder.start() [OBSERVER]

 READ THIS BEFORE CONCLUDING ANYTHING
   This app probes root artefacts that `android root disable`
   structurally cannot reach. If the canned command "worked",
   it worked by coincidence. Write the specific hook.
==============================================================
```

### What you have now

The question is answered, in full:

| The app performs | Inside the canned envelope? |
|---|---|
| `File.exists("/system/xbin/su")` | **Yes** — one of the thirteen strings |
| `File.exists("/sbin/magisk")` | **No** — not on the list |
| `File.exists("/data/adb/magisk")` | **No** — not on the list |
| `Runtime.exec("/system/bin/su")` | **Yes** — the hooked `String` overload |
| `Runtime.exec(String[]{"/system/bin/which","su"})` | **No** — the array overload is not hooked |
| `Build.TAGS.contains("test-keys")` | **Yes** |

Six probes, four families, and a precise statement of which three the stock tooling can touch.
That is a finding. You can hand the table to a developer and they can act on it.

---

## The two results that only the script produced

### 1. `ProcessBuilder.start()` fired once, and nothing called it directly

Read the counts again: one `exec(String[])` call, and one `ProcessBuilder.start()`. The app
makes exactly one `exec(String[])` call and never touches `ProcessBuilder` in its source.

That is the JDK's delegation chain, caught in the act:

```
Runtime.exec(String)  ->  Runtime.exec(String[], String[], File)  ->  ProcessBuilder.start()
       ^ objection hooks HERE                                              ^ and everything
                                                                             below is naked
```

This is why hooking `Runtime.exec(String)` covers so little: it is the *top* of a chain, and
only callers who enter at the top are caught. A developer who writes `exec(new String[]{...})`
skips the hooked frame; one who uses `ProcessBuilder` directly skips two. The script proved
this on a live device in fifteen seconds; the canned command cannot express the question.

### 2. The same hook fired here and did not fire under Objection

`String.contains("test-keys")` was hooked by **both** tools. Under Objection's
`android root simulate` it never fired — the agent's message for that hook never appeared.
Under `frida -f` with this script it fired immediately.

Same method. Same device. Same hook. Opposite results.

The variable is **ordering**. `frida -U -f` spawned the process suspended and installed the
hook before a single line of app code ran. In the Objection session the process was already
running and had executed that check once already; ART is free to intrinsify and inline a
core-library method like `String.contains` into a caller it has compiled, and a hook installed
afterwards may never be reached.

That is not a defect in Objection's hook — it is the same hook. It is a consequence of
Objection **choosing attach or spawn silently** based on whether the app happened to be
running (chapter README §2.4). The script did not fix it; running under `-f` did. The lesson
is `am force-stop` before you connect, every time.

---

## The honest scoreboard

Objection is not the loser here in any general sense. Be precise about what each tool cost and
bought:

| | Objection | Hand-written script |
|---|---|---|
| Time to first result | **~4 seconds** | ~20 minutes to write, once |
| Time on the second engagement | ~4 seconds | **~4 seconds** |
| Effect on the app | identical | identical |
| Tells you *what the app checked* | no | **yes** |
| Tells you what it **cannot** reach | no | **yes** |
| Distinguishes "suppressed" from "nothing to suppress" | no | **yes** |
| Distinguishes "installed" from "fired" | no | **yes** |
| Reproducible artefact | a scrollback | **a file** |
| Process footprint | ~1 MB agent, ~7.6 MB heap | a few hundred lines |
| Answers "is this worth my afternoon?" | **yes, better than anything else** | overkill |

**Objection won the question it was designed for and lost the one that was asked.** If the
request had been *"is this app's root detection worth a day of my time?"*, the four-second
answer would have been correct, sufficient, and the right professional call. The script would
have been a waste.

That is the trade in the chapter's opening sentence, arriving in practice: **speed bought with
knowledge.** The skill is not preferring one tool. It is noticing, quickly, which of the two
questions you are actually being paid to answer.

---

## The rule this example exists to establish

> Run Objection first. It costs seconds and a false negative is cheap.
> The moment the deliverable changes from an **effect** to an **explanation**, stop, and write
> the hook.

You do not need a new skill to make the switch. You need the overload signatures, and
Objection just gave them to you with `android hooking list class_methods`. Then
`android hooking generate simple <class>` prints a scaffold. Objection's most valuable
contribution is often helping you stop using it.

---

## Related

- [`01-annotated-session.md`](01-annotated-session.md) — the full session, annotated
- [`../scripts/root-disable-equivalent.js`](../scripts/root-disable-equivalent.js) — the script used here
- [`../scripts/split-agent.py`](../scripts/split-agent.py) — how the three hooks were recovered
- [`../labs/lab-02-objection-versus-a-script.md`](../labs/lab-02-objection-versus-a-script.md) — do it yourself
- Chapter README [§7.4](../README.md) — the exit criteria, as rules
- [37-RootDetection §7.3](../../37-RootDetection/README.md) — the tracer, when even this is not enough
- [53-Frida §7.3](../../53-Frida/README.md) — building an agent library so the handoff gets cheaper
