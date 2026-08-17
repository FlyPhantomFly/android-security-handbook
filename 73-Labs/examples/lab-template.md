# Lab NN — Title in sentence case

<!--
    73-Labs/examples/lab-template.md

    The skeleton every lab in this repository follows. Copy it into the chapter
    the lab belongs to and delete the guidance comments as you fill each section.

        cp 73-Labs/examples/lab-template.md 27-ContentProviders/labs/lab-06-my-lab.md

    This is not an invented house style. It is what the corpus already does,
    extracted from the labs by 73-Labs/scripts/build-lab-index.py -- which also
    parses this header, so a lab that follows it is indexable for free.

    Used by 73-Labs/labs/lab-03-write-a-lab-that-survives.md, which is the
    lab about writing labs and explains WHY each section is here.

    Write the sections in this order, which is not the reading order:
        1. Success criteria    2. Measured output    3. Steps
        4. Setup               5. Why this matters   6. If it did not work
-->

> **Objective.** One paragraph, present tense, describing what the reader will have **done** — not
> what they will have read about. If you cannot finish the sentence "by the end you will have…" with
> a verb, you do not have a lab yet.

**Difficulty:** Beginner | Intermediate | Advanced | CTF
**Time:** 60–90 minutes
**Prerequisites:** [Chapter NN §x](../README.md#1-introduction), prior labs, and anything the reader
must already be able to do
**Requires:** the honest list. Device? Root? Frida? An NDK? Nothing at all? Mark anything optional
as optional, and say which section uses it
**Device used to verify this lab:** model, Android version, API level, ABI, build type, root status,
and the working `su` form

---

<!--
    HEADER NOTES

    Difficulty is the level you need to FINISH, not to start. A lab written
    "Beginner to Intermediate" is an Intermediate lab. CTF is a band, not a
    modifier, and by convention the CTF is the LAST lab in a chapter.

    "Device used to verify" is the field people omit and the one reviewers read
    first. A measured output with no device attached to it cannot be
    reproduced, cannot be diverged from, and cannot be corrected.

    Mark optional requirements. The index derives requirements from your text
    and cannot see the word "optional" in a section heading, so a lab that uses
    root in one late section will be tagged `root`. Fix that in the header
    prose, not by removing the section.
-->

## 1. Why this matters

Two or three paragraphs, before the first command. What breaks without this knowledge; what a person
who skips it gets wrong. Write this section **last**, when you know what the lab turned out to be
about, and then move it here.

> **🧠 Mental Model.** An analogy that survives being pushed on. If the analogy breaks under the
> first follow-up question, cut it — a broken analogy is worse than none, because the reader keeps
> using it.

---

## 2. Setup

Every precondition, explicitly, including the ones you think are obvious. The reader's machine is
not yours.

```bash
# host
# Label every code block with where it runs: host, adb shell, device root,
# Frida REPL. An unlabelled command is a command run in the wrong place.
```

State how to check the setup worked before the lab depends on it:

```bash
# host
adb devices -l
adb shell getprop ro.build.version.sdk
```

> **⚠️ Warning.** If your lab installs anything, builds anything, or writes to the device, say so
> here and give the cleanup in the last section. Build **out of tree**: everything your script
> produces goes under `$OUTDIR`, outside the repository. The pattern to copy is
> [`43-WebView/examples/build.sh`](../../43-WebView/examples/build.sh).

---

## 3. Part 1 — <what the reader does first>

Number the parts. Give each one a goal in its first sentence.

```bash
# host
<the command>
```

Measured:

```
<the output you actually observed, pasted, warnings and all>
```

<!--
    Paste output you OBSERVED, never output you composed. Real output has
    warnings in it. If you had to run the command three times to get this, say
    so in the step rather than presenting the third run as the first.
-->

Then explain what the reader is looking at. Never leave output to speak for itself.

---

## 4. Part 2 — <the part where something is surprising>

The best labs have a moment where the obvious expectation is wrong. Set the expectation explicitly
first, so the reader can be wrong about it, then show the result.

> **🔍 Pentester's Note.** Use this callout for the thing that transfers to real work.

---

## 5. Hints

Progressive and spoiler-ordered: the first hint should be almost useless, the last almost the
answer. A CTF lab needs these; a guided lab usually does not.

<details>
<summary>Hint 1 — where to look</summary>

...
</details>

<details>
<summary>Hint 2 — what to look for</summary>

...
</details>

---

## 6. What this lab does **not** establish

<!--
    Every lab should have one of these. A lab with no stated limits is claiming
    completeness, and completeness is never true. Real examples:
      - 73-Labs lab 01 section 4.6 lists four things its survey does not check
      - 73-Labs lab 02 section 7.3 states no finding was established from an
        unprivileged third-party app
-->

- <a vantage you did not test from>
- <a device class you could not check>
- <a claim that holds only on the API level in your header>

---

## 7. Success criteria

Falsifiable checkboxes. "Understand X" is not a criterion; "can state X without looking it up" is.

- [ ] <a thing the reader can now do>
- [ ] <an output the reader has personally produced>
- [ ] <a question the reader can answer from memory of having measured it>
- [ ] <one thing the reader can say they did not establish>

---

## 8. If it did not work

Build this table from failures **you actually hit while writing the lab**. It writes itself if you
keep notes and cannot be fabricated if you do not.

| Symptom | Most likely cause | Check |
|---|---|---|
| | | |
| | | |

If the lab still does not reproduce, that is a divergence, not a defect in the reader. The procedure
is in [`73-Labs` lab 03 §7](../labs/lab-03-write-a-lab-that-survives.md), and the short report form
is [`divergence-report.md`](divergence-report.md).

---

## 9. Cleanup

Name every file and package **you** created. Nothing else.

```bash
# host
adb uninstall com.example.yourlab
rm -rf "$OUTDIR"
```

```bash
# host — verify
adb shell "pm list packages | grep yourlab"   # expect no output
git status --short                             # expect no output
```

> **⚠️ Warning.** If you find files on the device that are not yours, **leave them**. A live
> workspace and abandoned residue look identical from outside, and only the agent that created them
> can tell the difference.

---

## 10. Where this goes next

<!--
    The two targets below are LITERAL PLACEHOLDERS and are deliberately not
    links. `lab-NN.md` and `../../NN-Chapter/README.md` do not exist and never
    will; written as markdown links they would be reported as broken by every
    link checker in this repository, forever, in a file whose whole job is to be
    copied. Replace the backticks with real links when you fill them in.

    DO NOT "fix" these by pointing them at real files. They are the shape you
    are meant to copy, not references you are meant to follow.
-->

| Next | Why |
|---|---|
| `[<the next lab>](lab-NN.md)` | |
| `[<a related chapter>](../../NN-Chapter/README.md)` | |

<!--
    LINK DEPTH. This file lives in a subdirectory of a chapter, which is TWO
    levels below the repository root. A link to another chapter is therefore
        ../../NN-Chapter/README.md
    The one-level form resolves inside your own chapter and is silently wrong.
    That mistake produced 1,495 broken links in this repository once. Verify by
    RESOLVING links, not by reading them:
        python3 -B 73-Labs/scripts/build-lab-index.py --verify-links
-->

<!--
    BEFORE YOU CALL IT FINISHED

    python3 -B scripts/build-lab-index.py --why <your lab>   # header vs derived
    python3 -B scripts/build-lab-index.py --verify-links     # every promised path
    python3 -B scripts/lab-env-probe.py --match --chapter NN # can a reader run it?

    Plus, from 73-Labs/labs/lab-03 section 5.4: zero raw C0 control bytes, no
    BOM (a BOM is valid UTF-8 and passes a naive decode check), LF endings, and
    no build artefacts anywhere in the chapter.
-->
