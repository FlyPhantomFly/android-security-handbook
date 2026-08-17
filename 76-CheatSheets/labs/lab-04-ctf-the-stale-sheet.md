# Lab 04 — CTF: The stale sheet

> **Difficulty:** Advanced
> **Time:** 2 hours for the audit, 45 minutes for the write-up.
> **Prerequisites:** Labs [01](lab-01-sixty-minute-triage.md), [02](lab-02-the-sheet-lies.md) and
> [03](lab-03-build-your-own-sheet.md). An Android device or emulator with `adb`. Root and a
> debuggable package make three rows sharper but are not required for any of the five flag rounds.
> **Constraint:** every verdict you record must be backed by a command you ran and its output. A
> verdict you reasoned to is not a verdict.

---

## 1. The scenario

A colleague hands you the file below. It is their team's Android cheat sheet. It was written in 2019
against a Nexus 5X, it has been copied between four laptops since, and nobody has run a line of it in
three years.

It is now being used to train juniors.

Your job is to audit it. Ten rows. Some are still correct. Some were **always** wrong and nobody
noticed because they fail quietly. Some were correct in 2019 and are wrong now, for reasons that are
not visible from the text.

Five of the rows conceal the flag.

```
Flag format:  CTF{TOKEN1-TOKEN2-TOKEN3-TOKEN4-TOKEN5}
              37 characters including the braces
              every token is a single upper-case word or acronym
```

**Verify without spoiling.** When you think you have it:

```bash
# host — Git Bash / Linux / macOS
printf '%s' 'CTF{...your...guess...}' | sha256sum
```

```powershell
# host — PowerShell
$g = 'CTF{...your...guess...}'
$s = [System.Security.Cryptography.SHA256]::Create()
-join ($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($g)) | ForEach-Object { $_.ToString('x2') })
```

**Target digest:**

```
fe9aff2a0c4f46b5ad68dc52d5ad0e855fc11954cba0f90f0a342351312de5ce
```

Per-token digests, truncated to 16 hex characters, so you can confirm one round at a time without
seeing the others. Hash the bare upper-case token — no braces, no hyphens, no trailing newline:

| Round | First 16 hex of `sha256(TOKEN)` |
|---:|---|
| 1 | `f92fc83b9b091613` |
| 2 | `e366e0adc6149908` |
| 3 | `8cfe2945583e33f5` |
| 4 | `3755c6577af15a38` |
| 5 | `72d0059de79249c0` |

```bash
# host — confirm one token
printf '%s' 'YOURGUESS' | sha256sum | cut -c1-16
```

> **Note on `printf`.** Use `printf '%s'`, not `echo`. `echo` appends a newline and you will hash the
> wrong bytes. On Git Bash, `sha256sum` reading from a pipe prints a trailing ` *-`; ignore it.

---

## 2. The stale sheet

Audit these ten rows. Row numbers are referenced by the rounds below.

<!-- lint:allow -- the stale sheet is the SUBJECT of this CTF; every broken row is deliberate -->
```markdown
# Android pentest quick reference (team wiki, last edited 2019)

| # | Command | What it tells you |
|---|---|---|
| 1 | `adb shell su -c id` | Whether the device is rooted. `uid=0` means yes |
| 2 | `adb shell ls /system/xbin/su` | Whether the su binary is present |
| 3 | `adb shell ls /dev/qemu_pipe` | Whether this is an emulator |
| 4 | `set -o pipefail; adb shell pm list packages \| grep -q "$P" \|\| echo "not installed"` | Whether a package is installed |
| 5 | `frida-ps -U` | Whether Frida is working on this device |
| 6 | `adb shell dumpsys package $P` | What PackageManager parsed |
| 7 | `adb shell am start -n $P/.MainActivity --es url "$U"` | Launch with a URL extra |
| 8 | `grep -rn FLAG_SECURE out/sources/` | Whether the app blocks screenshots |
| 9 | `ls -l app-release.apk` | Whether R8 shrinking worked |
| 10 | `adb shell run-as $P ls` | Read the app's private data |
```

Nine of these ten appear, in almost this form, in cheat sheets published today.

---

## 3. Method

Work row by row. For each, produce:

```
ROW n
  claim            : (what the sheet says it tells you)
  what it really answers :
  command I ran    :
  output           :
  verdict          : STILL TRUE / ALWAYS WRONG / VANTAGE-DEPENDENT / DEVICE-DEPENDENT
  the fixed row    :
```

Four verdicts, and the distinction between the last three is the whole exercise:

| Verdict | Meaning |
|---|---|
| **STILL TRUE** | Correct today, on any device, from any vantage a reader is likely to have |
| **ALWAYS WRONG** | It never answered the question it claims to answer, on any device, ever |
| **VANTAGE-DEPENDENT** | Correct from one uid and wrong from another, with no error either way |
| **DEVICE-DEPENDENT** | Correct on the device class it was written for, wrong on yours |

> **⚠️ Warning — the trap in the verdicts themselves.** A row can be more than one. Row 1 is both
> DEVICE-DEPENDENT *and* carries a second defect that fires everywhere. If you stop at the first
> explanation you find, you will miss the second — which is exactly how the row survived three years
> of use.

Start with the preflight so every claim you make names a device:

```bash
# host — from 76-CheatSheets/
bash examples/03-session-preflight.sh --pkg <a debuggable package>
```

---

## 4. The five rounds

Each round names a row and asks one question with a one-word answer. Confirm each token against its
digest before moving on.

### Round 1 — Row 1

The sheet says `adb shell su -c id` <!-- lint:allow --> tells you whether the device is rooted.

Run it on your device. Then establish, by at least two independent means that do **not** use that
command, whether the device actually has root.

> **Question.** This chapter's row format carries exactly two precondition columns. Name, in one
> upper-case word, **the column whose absence let this row survive** — the one which, had it been
> filled in, would have told a 2019 reader that this command's behaviour is not universal.

Token 1 digest: `f92fc83b9b091613`

---

### Round 2 — Row 2

The sheet says `adb shell ls /system/xbin/su` <!-- lint:allow --> tells you whether the `su`
binary is present.

Run it from `adb shell`. Then run the equivalent from an application uid:

```bash
# host — from 76-CheatSheets/
bash scripts/vantage.sh --file /system/xbin/su --pkg <a debuggable package>
```

Compare the two answers carefully. Then work out what `new File("/system/xbin/su").exists()` would
return from inside an app on this device, and whether that matches what the app is trying to learn.

> **Question.** In one upper-case word, name **this chapter's term** for the property that differs
> between the two readings.

Token 2 digest: `e366e0adc6149908`

---

### Round 3 — Row 3

The sheet says `adb shell ls /dev/qemu_pipe` <!-- lint:allow --> tells you whether this is an
emulator.

Run it. Then determine whether the *mechanism* the row depends on is gone, or merely somewhere else.

```bash
# host — start here, then widen
adb shell 'ls /dev/' | grep -i -E 'qemu|goldfish|ranchu'
```

> **Question.** In one upper-case word (past tense), what happened to the thing this row was looking
> for?

Token 3 digest: `8cfe2945583e33f5`

---

### Round 4 — Row 4

The sheet's row 4 is a shell pipeline, and it is the only row that does not need a device to break.

<!-- lint:allow -- the failing pipelines are the subject of Round 4 -->
```bash
# host — reproduce the mechanism directly, with a producer large enough to matter
bash -c 'set -o pipefail; yes | head -3 >/dev/null; echo $?'
bash -c 'set -o pipefail; seq 1 100000 | grep -q 5; echo $?'
bash -c 'set -o pipefail; seq 1 100000 | grep -c 5 >/dev/null; echo $?'
bash -c 'set -o pipefail; seq 1 10000  | head -3 >/dev/null; echo $?'
```

Four commands. Two produce the same non-zero status on **success**. One is the fix. And one of them
produces `0` for a reason that explains why nobody caught this for three years — work out which, and
why.

> **Question.** In one upper-case word, name the signal whose delivery produces that status.

Token 4 digest: `3755c6577af15a38`

---

### Round 5 — Row 5

The sheet says `frida-ps -U` tells you whether Frida is working on this device.

Run it. Then determine, independently, whether you can actually instrument anything:

```bash
# host
adb shell 'ps -A' | grep -i frida ; echo "grep exit=$?"
frida -U -n <any process from the list> -e 'console.log("ok")' -q ; echo "frida exit=$?"
```

If `frida-ps` gave you a list and the attach failed, you have found it. If both worked, temporarily
stop `frida-server` (or use a device that has none) and run `frida-ps -U` again — the point is what
it prints when there is **no server at all**.

> **Question.** `frida-ps -U` succeeded. In one upper-case acronym, name the thing it actually proved
> was working.

Token 5 digest: `72d0059de79249c0`

---

## 5. The other five rows

Not part of the flag, and worth more than it. Audit them too and record a verdict for each.

### Row 6 — `adb shell dumpsys package $P`

Probably your only STILL TRUE row, and it is worth knowing *why* it is durable. It reads what
`PackageManager` actually parsed, rather than what a file says. When `apktool`, `aapt2` and `dumpsys`
disagree, this one is the authority — and the disagreement is itself a finding, because crafted
binary XML can make the offline tools display something the platform did not parse.

Even here, add a `Needs` and `Device`: it works at uid 2000 on any device, and its **output format is
not stable across releases**, so a script that parses it needs to tolerate that.

### Row 7 — `am start -n $P/.MainActivity --es url "$U"`

Run it twice with different values of `$U` and watch what happens.

<details>
<summary>What you should see</summary>

The second invocation prints:

```
Warning: Activity not started, intent has been delivered to currently running top-most instance
```

`am start` compares intents with `Intent.filterEquals()`, which **ignores extras**. Your second
payload never reaches a fresh instance. A tester iterating payloads sees the app not change and
concludes the parameter is not used.

The fix is one character: `am start -S`. Every measurement in this repository's fragment-injection
work uses it for exactly this reason.

There is a second, quieter failure on the same row. On some OEM builds, while the keyguard is up,
every activity start that **originates from an app** is refused and logged at debug level, while
`adb shell am start` still works. Half your commands succeed, half fail, and the pattern looks
random. Check first:

```bash
# host
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
```
</details>

### Row 8 — `grep -rn FLAG_SECURE out/sources/`

Try it against decompiled **release** output.

<details>
<summary>Why it finds nothing</summary>

`FLAG_SECURE` is a compile-time constant. Verified against `android-35`'s `android.jar`:

```
$ javap -p -constants android/view/WindowManager\$LayoutParams.class | grep FLAG_SECURE
  public static final int FLAG_SECURE = 8192;
```

`javac` folds `public static final` primitives at the call site, so the **name never reaches the
DEX** — only the literal `0x2000` does. Grepping decompiled output for the identifier searches for
something the compiler deleted.

Search for the constant instead, or hook `Window.setFlags` at runtime and observe what is actually
passed. The generalisation is worth more than the flag: **a `static final` primitive has no identity
in compiled output**, so no identifier-based search will ever find one.
</details>

### Row 9 — `ls -l app-release.apk`

<details>
<summary>Why size tells you nothing</summary>

Three builds of one app — unminified, minified, and minified-with-different-rules — came out
**byte-identical in size at 12,757 bytes**, while their DEX sizes were 7,384 / 2,920 / 7,180.

`apksigner` pads the signing block to a 4 KiB boundary. Below that granularity, APK size is
quantised and carries no information about what is inside.

Compare the DEX:

```bash
# host
unzip -l app-release.apk | grep -E 'classes.*\.dex'
```
</details>

### Row 10 — `adb shell run-as $P ls`

<details>
<summary>The two refusals, and why the folklore rule is half wrong</summary>

`run-as` requires `FLAG_DEBUGGABLE` **and** an application uid. It refuses in two distinct ways:

| Message | Condition |
|---|---|
| `run-as: package not debuggable` | Exactly what it says |
| `run-as: package not an application` | A **debuggable system app** — a different condition entirely |

Reading the second as the first loses a genuine finding: you have just been told the target is
debuggable *and* privileged.

The row is also missing its `Needs` column: `dbg`, not `any`. A junior running it against a release
build sees a refusal and concludes the data is inaccessible, when the actual conclusion is "not by
this route".
</details>

---

## 6. The write-up

Produce a short audit memo. This is the deliverable your colleague actually needs.

```markdown
# Audit of <team> Android quick reference, <date>

**Audited against:** <device>, Android <rel> / API <sdk>, <build type>, root: <yes/no + how>
**Method:** every row executed in the form written; vantage-sensitive rows re-run from an app uid
            with scripts/vantage.sh.

## Summary

| Verdict | Rows |
|---|---|
| Still true | |
| Always wrong | |
| Vantage-dependent | |
| Device-dependent | |

## The pattern

<one paragraph — not ten findings>

## Replacement rows

<the ten rows, rewritten to the four-property standard>

## What I could not check

<honestly>
```

The **pattern** paragraph is the part that makes this a service rather than a list. Ten corrected
rows fix ten commands; naming the pattern stops the eleventh bad row being written next month.

<details>
<summary>The pattern, if you want to check yours against it</summary>

Every broken row **answers a narrower question than the one it claims to answer**, and reports the
answer in the vocabulary of the wider one.

| The row claims to answer | It actually answers |
|---|---|
| Is this device rooted? | Does this `su` accept a `-c` flag? |
| Is the `su` binary present? | Can *this uid* see that path? |
| Is this an emulator? | Does one specific 2014-era device node exist? |
| Did the pipeline succeed? | What status did the *writer* exit with? |
| Can Frida instrument this device? | Can adb enumerate processes? |
| Does the app block screenshots? | Does an identifier the compiler deleted appear in the output? |
| Did shrinking work? | How large is the padded file? |
| Can I read the app's data? | Can I read it *by this one route*? |

The general form: **a detector's blind spot is invisible in its output.** It is the same defect this
repository found in its own link checker — a check reporting "no broken links" that meant "no broken
links outside an excused category nobody had audited", which hid 1,512 of them. And in its own
`su -c` detector, whose published pattern found 79 of 376 occurrences because it could not see the
double-quoted form.

The defence is not vigilance. It is **closing the arithmetic**: explain every hit, and go looking for
the ones you did not get.
</details>

---

## 7. Success criteria

- [ ] Flag recovered and confirmed against the target digest.
- [ ] All ten rows have a verdict, each backed by a command and its output.
- [ ] At least one row carries **two** verdicts, with both mechanisms named.
- [ ] Ten replacement rows written to the four-property standard.
- [ ] Replacement rows pass `python3 -B scripts/lint-commands.py`, or every finding is a marked
      counter-example.
- [ ] The pattern paragraph written **before** you opened the reveal in §6.
- [ ] A "what I could not check" section that names something real.

---

## 8. Hints

<details>
<summary>Round 1 — I have the mechanism but not the word.</summary>

The mechanism is that AOSP's `su` takes `su <uid> <cmd>` and rejects `-c`, while Magisk's `su` on a
phone accepts it. So the row is correct on one class of hardware and fails on another.

The chapter's row format has exactly two precondition columns. One is about *privilege*. The other is
about *what you are running on*. The token is the second one — the column heading itself, upper-cased.

Read [`../README.md`](../README.md) §2, "The entry format".
</details>

<details>
<summary>Round 1 — the second defect.</summary>

Even where `su -c` is accepted, `adb shell` does not preserve quoting. The whole line arrives as
separate argv words, so `su -c magisk -v` hands `-v` to **`su`**, not to `magisk`. The row prints
`su`'s version under a heading that says Magisk.

That one is not device-dependent. It fires everywhere. Record both.
</details>

<details>
<summary>Round 2 — I ran it and got the same answer twice.</summary>

Then you ran it from the same uid twice. `adb shell run-as <pkg> …` is not the same identity as
`adb shell …`. Check with `id` on both sides before comparing anything else:

```bash
# host
adb shell id
adb shell "run-as <pkg> id"
```

If `run-as` refuses, the package is not debuggable — install a debuggable "hello world" with
`adb install -t`. Without a second uid this round cannot be measured, only read about.
</details>

<details>
<summary>Round 3 — nothing in /dev looks relevant.</summary>

Widen the grep. The node was renamed, not removed, and the new name contains an abbreviation of
"deprecated". Compare the two names and you have the token.

While you are there, check the other three artefacts from the same era —
`/dev/socket/qemud`, `/system/bin/qemu-props`, `libc_malloc_debug_qemu.so` — and note that *those*
are genuinely gone. "Renamed" and "removed" are different verdicts and the row deserves the accurate
one.
</details>

<details>
<summary>Round 4 — all four of my commands print 0.</summary>

Your producer finished before the consumer closed the pipe. That is the whole reason this defect
survives in the wild: with a *small* input it does not reproduce.

Use `yes` — an infinite producer — and it fires every time:

<!-- lint:allow -- the failing pipeline is the point of the hint -->
```bash
# host
bash -c 'set -o pipefail; yes | head -3 >/dev/null; echo $?'
```

Then read the number. It is 128 + n. Work out what n is, and look up signal n.
</details>

<details>
<summary>Round 5 — frida-ps fails on my device too, so I cannot see the effect.</summary>

Then you have the *right* answer from the wrong direction, and you still need to see the failure mode
to name it. The point of the round is that `frida-ps -U` can **succeed with no server at all**,
because Frida's Android backend enumerates processes over the debug bridge rather than through an
injected agent.

Ask what channel is left when there is no agent, no gadget and no server. It is the same channel that
made your `adb shell` commands work all lab. Three letters.
</details>

<details>
<summary>I have five words but the full-flag digest does not match.</summary>

Three usual causes:

1. **Wrong order.** Tokens go in round order, 1 to 5.
2. **A trailing newline.** Use `printf '%s'`, never `echo`. `echo 'CTF{…}' | sha256sum` hashes an
   extra `0x0a` byte.
3. **Case or separator.** Upper-case tokens, single hyphens, `CTF{` and `}` with no spaces. The whole
   string is 37 characters.

Confirm each token individually against its 16-hex prefix before assembling.
</details>

---

## 9. Extension — audit a sheet you actually use

The stale sheet above is a construction. The one on your team wiki is not.

Take any Android cheat sheet you rely on — this repository's own included — and run the same audit
against ten of its rows. Then:

```bash
# host — from 76-CheatSheets/
python3 -B scripts/lint-commands.py --path /path/to/that/sheet.md --no-fail
```

Two things to expect, both of which happened while this chapter was being written.

**You will find defects in sheets you trusted.** This repository's own sheets carry **56 ERROR-tier
and 60 WARN-tier** findings across the 78 of them, and the largest single class is a command form
documented as broken in four separate chapters and used throughout the prose of the same repository.

**You will find defects in the linter.** Two of its rules were withdrawn or downgraded after
adjudicating the top band by hand: one flagged 130 lines of `adb shell am start … && adb logcat` as
errors when that is correct, intentional host-side chaining. If your sheet trips a rule and you are
confident the row is right, run the command — that settles it, and it settles it better than an
argument.

Either outcome is a result. Write it up the same way.

---

## See also

- [`lab-01-sixty-minute-triage.md`](lab-01-sixty-minute-triage.md) — the sheets under time pressure
- [`lab-02-the-sheet-lies.md`](lab-02-the-sheet-lies.md) — the same six mechanisms, guided
- [`lab-03-build-your-own-sheet.md`](lab-03-build-your-own-sheet.md) — writing rows that survive audit
- [`../README.md`](../README.md) §6 — thirty-three rows where the obvious command lies
- [`../README.md`](../README.md) §7 — how this chapter itself gets misused
- [`../examples/01-anatomy-of-a-sheet-row.md`](../examples/01-anatomy-of-a-sheet-row.md) — the standard
  your replacement rows are held to
- [`../scripts/lint-commands.py`](../scripts/lint-commands.py) — the mechanical half of this audit
