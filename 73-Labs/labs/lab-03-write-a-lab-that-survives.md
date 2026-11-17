# Lab 03 — Write a lab that survives someone else running it

> **Objective.** Write a complete, original lab to this repository's conventions, and then **validate
> it mechanically** — not by reading it back, which never works, but by running the index generator
> against it and checking that the machine's derived requirements match the ones you declared. You
> will also learn the failure mode that makes most self-written labs worthless: they are reproducible
> only by their author, and the author cannot tell.

**Difficulty:** Intermediate
**Time:** 3–4 hours for a first lab. The writing is an hour; the validation is the rest, and the
proportion is the lesson.
**Prerequisites:** [Lab 01](lab-01-the-capability-survey.md) and
[Lab 02](lab-02-the-chain-no-chapter-can-host.md). You must have *consumed* a lab critically before
writing one. [STYLE-GUIDE.md](../../STYLE-GUIDE.md) §4 and §5.
**Requires:** Python 3 and this repository. **No device needed for the validation half**; your lab
may require whatever you like.
**Verified:** the validation loop in §5 and §6 was run against this repository on 2026-08-16,
CPython 3.13.3, and the defects it found in this chapter's own labs are recorded in §6.4.

---

## 1. Why this lab exists

There are three reasons to write a lab, and only one of them is about other people.

**To learn.** Writing a lab forces you to establish every claim, because a claim you cannot
reproduce becomes a step that does not work. This is the same mechanism that makes teaching the
fastest way to find the holes in your own understanding, and it is available to you privately.

**To extend.** This repository has 327 labs and they do not cover everything. When you find the gap,
the useful response is a lab, not a note.

**To be run by somebody else.** This is the hard one, and it is the only one with an external
success criterion. A lab that works on your machine and nowhere else is not a lab; it is a diary
entry with commands in it.

> **Mental Model.** A lab is a **promise made to a stranger about their machine.** Every sentence
> is a claim about what will happen when someone you will never meet types something into a shell
> you have never seen. Most of the craft is in noticing which of your claims are actually about
> *your* shell.

### 1.1 What breaks without this

The failure is always the same shape and it is always invisible to the author:

<!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches -->
- You write `adb shell su -c 'id'` because it works on your phone. It is **broken everywhere** — the
  outer shell strips the quotes before `su` sees them. It happened to work for you because your
  particular `su` tolerated the mangling. This repository accumulated the same line until a
  repo-wide sweep found **196 occurrences**; **134 were repaired** and the remainder were adjudicated
  as deliberate counter-examples and marked as such. Nobody wrote them carelessly. They each worked
  on the machine of the person who wrote them.
- You write `unzip -l app.apk` because `unzip` is on your PATH. It is not on a default Windows +
  Git Bash machine, and your reader's first command fails.
- You declare `**Difficulty:** Beginner` and then require an NDK, a rooted device and a working
  `frida-server` in step four.
- You write "the output will look like this" and paste output from a device three Android versions
  older than the one you told the reader to use.

None of these are carelessness. They are all the same cognitive error: **you cannot see your own
environment, because it is the background against which you see everything else.** The only cure is
a tool that does not share it.

---

## 2. The contract, extracted from 327 labs

These are not house rules invented for this lab. They are what the corpus already does, measured:

```bash
# host — from 73-Labs
python3 -B scripts/build-lab-index.py --stats | tail -30
```

### 2.1 The header block

Every lab opens with a header the index can parse. Four formats occur in the corpus and all four are
accepted, but **write the first one** — it is what 222 of the labs use:

```markdown
# Lab NN — Title in sentence case

> **Objective.** One paragraph. What the reader will have DONE, not what they will have read.

**Difficulty:** Beginner | Intermediate | Advanced | CTF
**Time:** 60–90 minutes
**Prerequisites:** [Chapter NN §x](../README.md#...), and any prior labs
**Requires:** the honest list — device? root? Frida? NDK? nothing?
**Device used to verify this lab:** model, Android version, API level, ABI, build type, root status
```

The last line is the one people omit and it is the most valuable. A measured output with no device
attached to it cannot be reproduced, cannot be diverged from, and cannot be corrected.

> **Definition — difficulty band, in this repository.** Four values, and the band is *the level
> you need to finish, not to start.* A lab written "Beginner to Intermediate" is an Intermediate
> lab. `CTF` is a band, not a modifier: it means the lab withholds the method and gives you a goal.
> By convention the CTF is the **last** lab in a chapter.

### 2.2 The body

| Section | Rule | Why |
|---|---|---|
| Objective | States a capability, not a topic | "You will be able to X" is testable; "you will learn about X" is not |
| Why this matters | Before the first command | A reader who does not know why will not debug your step 7 |
| Setup | Every precondition, explicitly | Including the ones you think are obvious |
| Steps | Each with expected output | An unstated expectation cannot be compared against |
| Hints | Progressive, spoiler-ordered | Not the answer, and not nothing |
| Success criteria | Falsifiable checkboxes | "Understand X" is not a criterion |
| If it did not work | A real table, not "check your setup" | This is where most readers actually are |
| Cleanup | Named files and packages | Yours to remove, nobody else's |

### 2.3 The rules that come from the repository, not from you

- **Sources, never binaries.** No `.apk`, `.dex`, `.class`, `.o`, `.so`, `.jar`, `.pyc` may be
  committed. Ship the source and a build script.
- **Build out of tree.** Everything your build script produces goes under `$OUTDIR`, outside the
  repository. The pattern to copy is
  [`43-WebView/examples/build.sh`](../../43-WebView/examples/build.sh) — read its header before you
  write your own — or this chapter's
  [`build-chain-target.sh`](../examples/build-chain-target.sh).
- **A path in a code fence is a promise.** If you write `../scripts/foo.py`, that file must exist.
  The repository's checker resolves these, including the ones inside shell commands.
- **BOM-less UTF-8, LF endings, no raw C0 control bytes.**
- **Authorised-testing framing.** Never name a real vendor or application as vulnerable. The
  convention is "a 17 MB commercial app".
- **Never invent a CVE identifier, an AOSP line number, or a bug-bounty URL.** File paths in AOSP
  are stable and fine to cite; line numbers are not.

> **Warning — the `su -c` trap, stated precisely because you will hit it.**
> <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this warning teaches -->
> `adb shell su -c 'whoami'` is broken. The `adb shell` argument is re-parsed by the device's shell,
> which strips your quotes, so `su` receives `-c` and `whoami` as separate words. Two forms work:
> `adb shell "su -c 'whoami'"` on a Magisk-style `su`, and `su 0 whoami` on the AOSP `su` that the
> API 35 emulator ships — where `su -c` fails outright with `su: invalid uid/gid '-c'`.
> **Test on the device you name in your header, and write the form that device accepts.**

---

## 3. Part 1 — Choose something worth writing

Spend twenty minutes here. It determines whether the next three hours produce anything.

### 3.1 Find a genuine gap

```bash
# host — is your topic already covered?
python3 -B scripts/build-lab-index.py --by chapter --out - | grep -i "your topic"

# host — what does the chapter you would extend already have?
python3 -B scripts/lab-env-probe.py --match --chapter 27
```

A good lab candidate has all four of these properties:

1. **It has a falsifiable outcome.** Something either happens or does not.
2. **It is reproducible on hardware a reader plausibly has.** If it needs a specific handset, say so
   in the header and expect most readers to skip it.
3. **It teaches a mechanism, not a tool invocation.** "How to run `jadx`" is documentation. "Why
   `jadx` and `dexdump` disagree about this method" is a lab.
4. **You do not already know the answer.** If you do, you will write the steps that lead to it and
   omit the ones that made you doubt it, and the doubt was the valuable part.

### 3.2 Three shapes that work

| Shape | Example from the corpus | Why it works |
|---|---|---|
| **Predict, then measure** | Lab 02 §3.4 of this chapter | The gap between prediction and result is the teaching |
| **Two tools, one question** | Comparing a decompiler against a disassembler | Disagreement is a fact you can hold |
| **Build the thing, then break it** | The escalation ladder in [67](../../67-BypassingProtections/README.md) | Nobody argues with a defence they wrote themselves |

### 3.3 One shape that does not

A lab that is a list of commands with their outputs. That is a cheatsheet, and this repository has
[`76-CheatSheets`](../../76-CheatSheets/README.md) for it. The distinguishing question: **is the
reader ever uncertain?** If not, you have written a transcript.

---

## 4. Part 2 — Write it

Start from the template rather than a blank file:

```bash
# host — write your lab into the chapter it belongs to
cp 73-Labs/examples/lab-template.md 27-ContentProviders/labs/lab-06-my-lab.md
```

Write in this order. It is not the order the reader reads, and that is deliberate:

1. **The success criteria.** First, before anything. If you cannot write falsifiable criteria, you
   do not have a lab yet.
2. **The measured output blocks.** Run everything, capture real output, paste it. Never write the
   output you expect.
3. **The steps that produce those outputs**, backwards from the results you have.
4. **Setup**, once you know what the steps actually needed — which is never what you assumed.
5. **"Why this matters"**, last, when you know what the lab turned out to be about.
6. **"If it did not work"**, from the failures you personally hit while writing it. This section
   writes itself if you keep notes and is impossible to fabricate if you do not.

> **Pentester's Note.** Step 2 is the one that separates a lab from an essay. Paste output you
> **observed**, not output you composed, and if you had to run the command three times to get it,
> say so in the step. This chapter's Lab 02 §5.2 documents a command that printed a success message
> and did nothing; writing that down took one paragraph and is worth more than the six steps around
> it.

### 4.1 Mark what you did not establish

Every lab should contain at least one honest limit. Real examples from this chapter:

- Lab 01 §4.6 lists four things the capability survey does not check.
- Lab 02 §7.3 states that no finding was established from an unprivileged third-party app.

A lab with no stated limits is claiming completeness, and completeness is never true.

---

## 5. Part 3 — Validate it mechanically

**This is the part that matters, and it is why this lab is in this chapter rather than in a style
guide.** You cannot proofread your own environment out of your own document. So ask a program that
does not have your environment.

### 5.1 Does the machine agree with your header?

```bash
# host — from 73-Labs
python3 -B scripts/build-lab-index.py --why 27-ContentProviders/labs/lab-06-my-lab.md
```

The generator re-derives your lab's requirements **from its text**, independently of what you
declared, and shows the evidence line for each. Compare the two lists. There are exactly four
outcomes:

| Outcome | Meaning | What to do |
|---|---|---|
| Agreement | Your header matches your content | Nothing. This is rarer than you expect on a first draft |
| **You declared a requirement the machine did not derive** | Your header promises a constraint your steps never impose | Either the header is over-cautious, or a step is missing. Usually the second |
| **The machine derived a requirement you did not declare** | Your lab silently needs something | **The most common result, and always a defect.** Fix the header |
| The machine derived something absurd | The detector is wrong | Read §6.3 before assuming this |

### 5.2 The check that costs nothing and catches the most

```bash
# host — every path you promised, resolved
python3 -B scripts/build-lab-index.py --verify-links
```

Measured on this chapter mid-write:

```
BROKEN: from 73-Labs/references/ -> ../scripts/lab-doctor.sh   (resolved: ...\73-Labs\scripts\lab-doctor.sh)
BROKEN: from 73-Labs/references/ -> ../scripts/lab-env-probe.py
BROKEN: from 73-Labs/references/ -> ../README.md
links=395 broken=3
```

All three were files promised before they were written. That is the normal state of a lab mid-write,
and the check is how you find the ones you *forgot* to write rather than deferred.

> **Warning — relative depth, the defect this repository paid the most for.**
> A file in `labs/` or `references/` is **two** levels below the repository root. A link from there
> to another chapter is `../../NN-Chapter/README.md`. The one-level form, `../NN-Chapter/README.md`,
> resolves *inside your own chapter directory* and is silently wrong.
> `75-InterviewQuestions` emitted the one-level form from a generator and produced **1,495 broken
> links**, which a "forward reference" exemption in the checking script hid for months. Verify by
> **resolving** links, never by reading them.

### 5.3 Can your reader actually run it?

```bash
# host
python3 -B scripts/lab-env-probe.py --match --chapter 27
```

If your new lab appears under `blocked` for a capability you did not expect, your header is lying to
someone. If it appears under `runnable` and you know it is not, the tags are too weak — usually
because a requirement appears only in prose and never in a command, which the derivation
deliberately does not count.

### 5.4 The repository-wide checks

Run these before you consider the lab finished. They are the lab-sized subset of the sweep described
in [README §8.2](../README.md#82-the-checks-this-repository-runs-on-itself) — artefacts, mojibake,
relative links, control bytes, byte-order marks and command shapes.

```powershell
# host, PowerShell — raw C0 control bytes. Must be zero.
Get-ChildItem -LiteralPath "27-ContentProviders\labs" -Recurse -File | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    $n = @($b | Where-Object { ($_ -lt 0x20 -and $_ -notin 9,10,13) -or $_ -eq 0x7F }).Count
    if ($n) { "$($_.Name) $n" }
}
```

```powershell
# host, PowerShell — byte-order marks. A BOM is VALID UTF-8, so a decoder will not catch it.
Get-ChildItem -LiteralPath "27-ContentProviders\labs" -Recurse -File -Filter *.md | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) {
        "BOM: $($_.Name)"
    }
}
```

```bash
# host — build artefacts anywhere in your chapter
find 27-ContentProviders -name '__pycache__' -o -name '*.pyc' -o -name '*.class' \
     -o -name '*.apk' -o -name '*.dex' -o -name '*.so' -o -name '*.o'
```

> **Warning — two PowerShell traps that will cost you an afternoon.**
> **Never** pair `Get-Content -Raw` with `Set-Content -Encoding UTF8`: `-Raw` reads a BOM-less UTF-8
> file using the ANSI codepage, so every multi-byte character decodes wrongly and writing it back
> makes the damage permanent. It corrupted 11 files in this repository. Use a `.NET`
> `UTF8Encoding($false, $true)` for both directions. Separately, **`-Include` is silently ignored
> when combined with `-LiteralPath`** — use `Where-Object` for extension filtering, or every file
> reports as a hit.

---

## 6. Part 4 — The four defects to look for, with real examples

### 6.1 The declared/derived mismatch

Run `--why` on any lab and compare against its header. This chapter's own Lab 02 failed this check
twice, in two different ways, and both are worth walking through because they are the two shapes you
will hit.

```bash
# host
python3 -B scripts/build-lab-index.py --why 73-Labs/labs/lab-02-the-chain-no-chapter-can-host.md
```

**The first draft produced this**, against a header that said *"No root, no Frida, no proxy"*:

```
    frida        <- **Requires:** a device or emulator, a JDK and the SDK build-tools. **No root, no Frida, no proxy.**
```

Read the evidence line. **The sentence denying Frida is what raised the Frida tag.** That is a
detector defect, not an authoring one, and it is the cleanest possible example of why the evidence
column exists: the tag alone would have sent the author off to rewrite a correct header.

The fix was in the generator — a header-scoped negation set, so a lab denying a tool in its own
contract suppresses the tag rather than raising it. After the fix:

```
    no-frida     <- **Requires:** ... **No root, no Frida, no proxy.**
    no-proxy     <- **Requires:** ... **No root, no Frida, no proxy.**
    root         <- # host — this AVD's su takes `su 0 <cmd>`; see Lab 01 §3.2
    apktool      <- apktool d -f -o /tmp/ch73-apktool chain-target.apk
```

**Two mismatches survive the fix, and they are the author's to resolve, not the tool's.**

`root` is raised because §6.2 really does run `su 0 am broadcast`. The lab is completable without
root; one optional section uses it. The derivation cannot see the word "optional" in a section
heading. `apktool` is raised because §3.2 offers an `apktool` route alongside the SDK-only one.

The honest fix for both is **in the header**, and Lab 02's header now reads: *"Root is optional and
used in §6.2 only... `apktool` and `jadx` are convenient and neither is required."*

> **Mental Model.** A tag that over-reports a requirement turns readers away from a lab they
> could have done. A header that under-reports one strands them at step 40. Given a choice, make the
> **header** more precise rather than the detector more permissive — the header is read by humans
> who can understand "optional", and the detector is not.

### 6.2 Output that was never observed

The tell is output that is too clean. Real output has warnings in it. This repository's `apksigner`
prints four lines about restricted methods in `java.lang.System` before it prints anything you
wanted. If your pasted output has none of that, ask yourself where you got it.

### 6.3 Blaming the detector

When the derivation disagrees with you, the repository's own rule applies: **a detector that
disagrees with one sample out of many is more likely to be wrong than the sample; a detector that
disagrees with a dozen is definitely wrong.**

Both directions have happened here and both are recorded:

- The interview-question generator in `75-InterviewQuestions` initially reported `25-Binder` as
  having no questions. The detector was wrong: that chapter writes questions without a `Q.` prefix.
- This chapter's index generator initially reported **17** labs with no declared difficulty. Twelve
  of them did declare one, in two header formats the parser did not know
  (`> **Difficulty.** Beginner.` and `> **Level:** Beginner · **Time:** ...`). The parser was wrong.
  After the fix, **6** labs genuinely declare nothing — and those are reported as `unstated` rather
  than assigned a guess.

The discipline is to check a handful of the disagreements by hand before touching either side.

### 6.4 Defects this chapter's own labs had, found by this loop

Recorded because a validation section that only shows the tool passing is not evidence that it works.

| Defect | Found by | Fix |
|---|---|---|
| The environment probe reported `apktool` as present with the detail "not on PATH" | Reading its own output | Presence now decided by whether the process executed, not by `shutil.which` |
| The probe reported "no frida-server in /data/local/tmp" on a device where it was present | Comparing against a hand-run `ls` | It reduced every command's output to one line before inspecting it |
| `--no-device --match` reported 108 labs runnable with no device attached | Running the flag the feature exists for | `device` had been excused as a non-gating tag |
| Lab 01 quoted a `--why` output block that had never been run | Running it | Replaced with the real output, which had different tags, a different line count and weaker evidence |
| The sentence "No root, no Frida, no proxy" raised the `frida` tag | `--why` on Lab 02 | Header-scoped negations added (§6.1) |
| A tool named as "if you have apktool" counted as a requirement | Reading the evidence line | Matches on optional-phrasing lines are skipped and the search continues |
| `--why` crashed with `UnicodeEncodeError` on a title containing an arrow | Running it on this chapter's own Lab 02 | Both scripts now force UTF-8 on their text streams |

The fourth is the one to dwell on. It was **fabricated plausibly** — right format, believable
content — and only running the command exposed it. That is the specific failure this whole part is
designed to catch, and it caught its own author.

---

## 7. When your own lab does not reproduce

You will hand your lab to someone and they will report that step 6 does not work. Here is the
procedure, in the order that resolves the most cases soonest.

### 7.1 Establish that you are talking about the same thing

Before debugging anything, get these from the reader. Most divergences resolve here:

```bash
# reader's host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.type
adb shell getenforce
adb shell "su 0 id"; adb shell "su -c id"
```

```bash
# reader's host — from 73-Labs
python3 -B scripts/lab-doctor.sh --lab <path-to-your-lab>
```

### 7.2 The ranked causes

From this repository's own divergence record, in descending order of frequency:

| Rank | Cause | How to rule it out |
|---|---|---|
| 1 | **Vantage.** They ran as an app, you ran as `shell`, or the reverse | Ask which identity. This is the most common cause by a wide margin |
| 2 | **Device or version difference** | Compare the six properties above |
| 3 | **`su` form** | `su 0` versus `su -c`. Reads exactly like "not rooted" |
| 4 | **Tool version** | Especially Frida host/server, and build-tools |
| 5 | **A command that succeeded and did nothing** | The Lab 02 §5.2 class. Ask for the *effect*, not the exit status |
| 6 | **The lab is wrong** | Genuinely last, but it does happen — see §6.4 |

### 7.3 What to write down

If you cannot resolve it, the verdict is **`DIVERGED, cause not established`**, and that is a
complete and respectable outcome. Record:

- what was claimed, and where;
- what was observed instead, verbatim;
- both environments, in full;
- which of the six causes above you ruled out, and how.

Then **change nothing** until you know why. The failure mode here is picking whichever explanation
flatters you and editing the lab to match, which converts an open question into a confident error
that every future reader inherits.

The reference implementation is
[74-CaseStudies/examples/reproduction-log.md](../../74-CaseStudies/examples/reproduction-log.md).
The short form for a single claim is
[`../examples/divergence-report.md`](../examples/divergence-report.md).

> **Under the Hood.** Why is `DIVERGED, cause not established` an acceptable end state? Because
> the alternative is not knowledge, it is a guess wearing knowledge's clothes. A recorded divergence
> is a question the next person can answer with one more device. A resolved-by-assertion divergence
> is a claim nobody will re-examine, because it looks settled.

---

## 8. Success criteria

- [ ] Your lab exists, in the `labs/` directory of the chapter it belongs to, named
      `lab-NN-short-name.md`.
- [ ] Its header declares difficulty, time, prerequisites, requirements and **the device it was
      verified on**.
- [ ] Every output block in it was observed by you, on that device, and you can say which command
      produced it.
- [ ] `build-lab-index.py --why <your lab>` derives the requirements you declared — or you have
      written down, in the lab, why the two differ.
- [ ] `build-lab-index.py --verify-links` reports zero broken links attributable to your lab, and
      every path you named in a code fence exists.
- [ ] The control-byte and BOM checks in §5.4 return nothing for your file.
- [ ] Your lab contains at least one **stated limit** — something it does not establish.
- [ ] Your lab has an "If it did not work" table built from failures **you actually hit**.
- [ ] Someone else has run it, on a different machine, and either it worked or you have a
      divergence record.

The last one is the only criterion that cannot be self-assessed, which is exactly why it is the one
that matters.

---

## 9. Extensions

1. **Write the CTF variant.** Take your lab and remove the method, leaving only the goal and a
   verifiable flag. Notice how much of your original was scaffolding.
2. **Extend the index generator.** Add a requirement tag it does not have — a specific Android
   version floor, say — and validate it against the corpus with `--stats`. If your new tag fires on
   200 labs, it is measuring the wrong thing.
3. **Write a lab you cannot complete**, and mark every step you could not verify. Then get someone
   with the right hardware to fill them in. This is how the physical-device labs in this repository
   should be extended, and it is more honest than simulating.
4. **Audit an existing lab** with §6's four defects. Do not edit another chapter's lab; record what
   you found and take it to the owner.

---

## 10. Where this goes next

| Next | Why |
|---|---|
| [Lab 04 — CTF: the gauntlet](lab-04-ctf-the-gauntlet.md) | The chapter's capstone. Everything above is in play |
| [`../examples/lab-template.md`](../examples/lab-template.md) | The skeleton, ready to copy |
| [STYLE-GUIDE.md](../../STYLE-GUIDE.md) | The binding contract for the rest of a chapter |
| [74-CaseStudies](../../74-CaseStudies/README.md) | How a divergence is written up properly |
