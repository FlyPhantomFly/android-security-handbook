# The replay journal — re-running other people's case studies, dead ends included

This is the session log from writing [chapter 74](../README.md). Its subject is unusual: not an
application, but **six case studies already published in this repository**, re-executed to find out
whether they still reproduce.

[68's worked journal](../../68-ReverseEngineering/examples/worked-journal.md) is the reference for
this form — eighteen entries, nine of them failures, in the `H`/`P`/`R`/`E`/`O`/`V` notation this
file also uses. **68 records an investigation; this file records a replication.** They fail
differently, and the difference is the reason this exists as a separate artefact:

| | Investigating | Replicating |
|---|---|---|
| The thing that goes wrong | You believe your first hypothesis | You believe the *published* hypothesis |
| The pull, when evidence disagrees | Explain the evidence away | Assume the world changed since |
| The cheap escape | "It's probably fine" | "Close enough" |
| What saves you | A refutation criterion written first | **Arithmetic**, because "close enough" is checkable |

**Four of the nine hypotheses below were refuted, and two of the four produced findings the original
chapters do not contain.** One produced an entirely new case study.

**Session facts, recorded first, because every claim below is a claim about them:**

| | |
|---|---|
| Devices attached | **One.** `emulator-5554` — AVD `sdk_gphone16k_x86_64`, Android 15 / API 35, x86_64, 16 KiB pages |
| Root | Magisk 30.7, `su 0 <cmd>` form, **not** `su -c` |
| App vantage | `run-as com.devuser.helloworld`, uid 10207, domain **`runas_app`** |
| Not attached | The Redmi `M2101K6P` (API 30) and the `i9000S` (API 33). **Nothing attributed to them was re-run.** |
| Host | Windows 11, Git Bash, NDK 25.2.9519653, Python 3 |
| Date | 2026-08-16 |

Raw output for everything below: [`reproduction-log.md`](reproduction-log.md).

---

## Q1 — What am I actually talking to?

Asked first, before any case, because every downstream verdict is correlated against the answer. This
is not a question about any target.

```
H1  the devices this chapter's cases were measured on are available
P   adb devices -l lists a phone and an emulator
R   it lists something else
E   adb devices -l
O   emulator-5554  device  product:sdk_gphone16k_x86_64  device:emu64xa16k
    -- one device, and it is the AVD
V   REFUTED
```

**Consequence, immediately, and it shaped the whole chapter.** Cases A (the Redmi legs), B and F were
measured on hardware that is not here. Three options existed:

1. Re-run what can be re-run, transcribe the rest, and label which is which.
2. Re-run everything on the AVD and present it as reproduction.
3. Skip the un-runnable cases.

Option 2 is the tempting one and it is the error 68 §7.5 warns about — correlating an API 35 runtime
against measurements from an API 30 phone. Option 3 throws away the two best cases. **Option 1 was
taken**, and every case in the chapter carries a provenance box saying "transcribed" or "re-run".

`Q1 -> answered`. Recording a device you *did not* use is as valuable as recording one you did.

---

## Q2 — Does the boot-state property still read empty?

The easiest case to replicate, deliberately taken first to shake out the tooling.

```
H2  ro.boot.verifiedbootstate is still the empty string on this AVD
P   getprop prints nothing
R   it prints one of green/yellow/orange/red
E   adb -s emulator-5554 shell "getprop ro.boot.verifiedbootstate" | cat -A
O   ^M$
V   SUPPORTED -- REPRODUCED
```

The `| cat -A` was not in the original plan and is worth keeping. **Without it, "the property is
empty" and "the command failed and printed nothing" are indistinguishable on a terminal.** A blank
line is not an observation; `^M$` is.

---

## Q2a — Why is it empty? And can the app find out?

The original chapter traced the cause to absent `androidboot.*` keys. Re-running that was meant to be
confirmation and turned into two additions.

```
H3  /proc/bootconfig lacks androidboot.verifiedbootstate
P   grep finds it absent and finds veritymode present
R   it is present, or the file cannot be read
E   adb -s emulator-5554 shell "cat /proc/bootconfig"
O   cat: /proc/bootconfig: Permission denied
V   INCONCLUSIVE -- this is not a result about the device, it is a result about me
```

**Dead end 1, and the most useful of the session.** The natural next move is `su 0` and carry on,
which is what I did — but stopping to ask *why* the shell was refused is what produced the finding.

```
E   adb -s emulator-5554 shell "su 0 cat /proc/bootconfig"
O   androidboot.veritymode = "enforcing"
    androidboot.vbmeta.digest = "2c9cddc57820...ceea"
    ... and NO androidboot.verifiedbootstate, .flash.locked,
        .vbmeta.device_state or .slot_suffix
V   H3 SUPPORTED -- REPRODUCED
```

Two things fall out that the original write-up does not have.

**First, the derivation is now proven in both directions.** The digest in bootconfig and the digest in
the property are byte-identical, so the positive half of *`androidboot.X` becomes `ro.boot.X`* is
demonstrated, not just the negative half. That took no extra work — the value was already on screen —
and it upgrades the argument from "the property is empty and here is a plausible reason" to a closed
causal loop.

**Second, and larger: the cross-check is root-only.** `/proc/bootconfig` and `/proc/cmdline` both
refuse uid 2000. The comparison that catches a forged property **cannot be performed by the process
doing the checking.** That converts "client-side verified-boot checking is badly implemented" into
"it is structurally unsound", which is a different finding with a different remediation.

The dead end *was* the finding. A permission error is data about the boundary you just hit.

---

## Q3 — Does the three-vantage detection result still hold?

```
H4  /data/adb/lspd is ENOENT to root and EACCES to both unprivileged vantages
P   the three-vantage table reproduces row for row
R   any row differs
E   ls -ld from su 0, from adb shell, and via run-as, over six paths
O   /data/adb            root drwx------  | shell EACCES | app EACCES
    /data/adb/lspd       root ENOENT      | shell EACCES | app EACCES
    /data/adb/modules    root PRESENT     | shell EACCES | app EACCES
    /system/xbin/su      root -rwsr-x---  | shell VISIBLE| app EACCES
    /debug_ramdisk       root 0711        | shell stat OK| app stat OK
    /debug_ramdisk/magisk 428416 bytes    | shell OK     | app READ OK
V   SUPPORTED -- REPRODUCED, six rows for six
```

Clean reproduction, months after the original, on a device that has been rebooted many times since.
That is the outcome replication is supposed to have and it is worth saying plainly: **most of what
this repository has measured, reproduces.** The interesting entries below are the minority.

---

## Q3a — Is the mountinfo count right?

Asked only because the chapter's cheatsheet states a specific number, and quoting a number obliges
you to check it.

```
H5  three lines in /proc/self/mountinfo have a mount source of "magisk"
P   grep -c ' magisk ' returns 3
R   it returns something else
E   grep -c ' magisk ' vs grep -c magisk, from all three vantages
O   ' magisk ' -> 2     magisk -> 3     (identical from root, shell and app)
V   REFUTED
```

**Dead end 2 — mine, for about ten minutes.** My first reaction was that my delimiters were wrong,
because the published number was 3 and I was getting 2. I widened the pattern, got 3, and nearly
recorded "reproduced".

What stopped it was reading the third line instead of counting it:

```
58 56 0:27 / /debug_ramdisk/.magisk/pts ... - devpts devpts rw,seclabel,...
```

Its mount source is **`devpts`**. The token `magisk` occurs only in the mount *point path*. So there
are two `magisk`-sourced mounts and three lines mentioning `magisk`, and the published sentence
picked the wrong one of those two facts.

**This is case F in miniature, committed by a chapter that documents case F's neighbours.** A
substring matched something other than what the sentence claimed it matched. The conclusion is
untouched — the signal is real, needs no privilege, and proves Magisk — but the count wants
rephrasing to *"two `magisk`-sourced mounts, three lines mentioning `magisk`"*, which is unambiguous
and no longer.

Recorded as DIVERGED, chapter 63 left unedited.

---

## Q4 — Can I quote chapter 39's property figures accurately?

This was clerical. It was going to be one command, a number, and a citation.

```
H6  the documented command reproduces the documented figures (shell 1053, app 634)
P   both land within a few of the published values
R   either differs materially
E   adb shell "getprop | wc -l"  and the same under run-as
O   shell = 673      app = 633
V   REFUTED for shell; the app figure reproduces within 1
```

**Dead end 3, and the one I was most likely to get wrong.** The available explanation was right
there: *properties come and go, the device has been updated, close enough.* I nearly took it.

What made it untakeable was arithmetic rather than judgement. **One number in a pair moving by 380
while the other moves by 1 is not drift.** Drift moves both. Something structural differed, and the
"close enough" escape is checkable in a way that "it feels fine" is not.

```
H7  I caught an unstable sample
P   repeated runs vary
R   they are identical
E   the same commands, three times
O   run 1: shell=673 app=633 root=1055
    run 2: shell=673 app=633 root=1055
    run 3: shell=673 app=633 root=1055
V   REFUTED -- and look at the third column
```

The root measurement was added out of habit, not design. **`root = 1055`; the published "shell"
figure is 1053.**

The published shell figure reproduces as the root figure to within two; the published app figure
reproduces to within one. The economical reading is that the shell leg was taken through `su` and
labelled `shell`.

> **What I did not do.** I did not write that as the finding, and I did not edit chapter 39. One
> device, one session, one suggestive coincidence. The alternative — that this AVD's shell-visible
> property set shrank by 380 while its app-visible set moved by one — is unlikely, not impossible.
> **The verdict is `DIVERGED, cause not established`**, and inventing a resolution would have cost
> more than the ambiguity does. A published divergence with its evidence attached is a claim someone
> with the original hardware can settle. A silent rewrite destroys the record of the disagreement.

---

## Q4a — What is the count standing in for?

Asked because a count is nearly always the weak form of a question, and this one had survived
unchecked precisely because nothing could be compared against it.

```
H8  the shell/app difference is spread evenly across the namespace
P   the 37 differing names look like an arbitrary sample
R   they cluster on something meaningful
E   comm -23 / comm -13 over the sorted NAME sets
O   37 shell-only, 0 app-only.
    Among the 37: ro.debuggable, ro.secure, partition.system.verified,
                  ro.serialno, qemu.sf.lcd_density
V   REFUTED -- three of them are standard integrity checks
```

**This is the finding, and it is bigger than the count that led to it.** `ro.debuggable`, `ro.secure`
and `partition.system.verified` are recommended in published root- and tamper-detection checklists,
and **an application cannot read any of them on this device.** `ro.debuggable` is genuinely `1` here;
the app sees the empty string; the usual `"1".equals(...)` therefore concludes the device is fine.
The check fails open, silently, on the only vantage that matters.

The zero in `0 app-only` is not decoration. It confirms the app's view is a strict subset of the
shell's, which is what the SELinux property-type model predicts, and it was a free control on whether
the measurement itself was sound. A non-zero there would have meant my method was broken.

And a second divergence fell out of the same table. Chapter 39 describes `ro.boottime.qemu-props` and
its two siblings as *"a goldmine from `adb shell`, unreachable from the app being assessed."*
Measured: empty to `shell`, empty to the app, populated only under root. **A goldmine from root** —
and root is not a vantage any assessment target occupies. The direction of the conclusion is right;
the vantage is one rung off.

`Q4 -> answered, and it grew a case study.` It started as a citation check.

---

## Q5 — Does the compiler still delete the obfuscation?

```
H9  noinline on the decoder prevents the constant folding
P   the -O2 build hides the plaintext, like the -O0 build
R   the -O2 build leaks it
E   write a fresh 12-line fixture WITH noinline; build -O0 and -O2; llvm-strings
O   -O0 : (nothing)
    -O2 : /system/xbin/su
V   REFUTED
```

The fixture was written from scratch rather than reusing 59's, so that a reproduction would be
independent evidence rather than a re-execution of the same file. It carries
`__attribute__((noinline))` from the first line, because that is the fix
[58-IDA §11.4](../../58-IDA/README.md) records applying.

The original result reproduced. The fix did not work. So the question became *what actually
happened*, which meant going one rung down from `strings` to the section it summarises:

```
E   llvm-objdump -s -j .rodata on both builds
O   -O0 : 88d4ded4 d3c2ca88 dfc5cec9 88d4d2...   the ciphertext
    -O2 : 2f737973 74656d2f 7862696e 2f737500   /system/xbin/su -- and NO ciphertext
V   the array was not decoded, it was DELETED
```

```
E   llvm-objdump -d --disassemble-symbols=decode on both
O   -O0 : 31 instructions
    -O2 :  4 instructions -- adrp / ldr q0 / str q0 / ret
    and main sets ONE argument register before calling a 4-argument function
V   noinline was OBEYED. The function exists and is called.
    Its BODY was specialised against compile-time constant arguments.
```

**`noinline` constrains the inliner. Nothing above is the inliner.** Interprocedural constant
propagation and function specialisation are separate passes and do not read the attribute.

> Recorded as: original REPRODUCED; **the fix REFUTED as a general remedy.** It worked on 58's
> fixture and does not work here, which makes it a fixture-specific repair rather than a rule. The
> remedy that does work is 59's — `static volatile` on the key, so the optimiser cannot prove the
> value.

---

## Q6 — Does my own fixture compile?

Asked last, and only because the chapter was about to ship a file telling readers to build it.

```
H10 examples/fold.c compiles as shipped
P   clang -Wall -Wextra produces a .so at both -O0 and -O2
R   it does not compile
E   build the file from its path in the repository, not from my scratch copy
O   fold.c:23:72: error: unknown type name 'bin'
     *   NDK=.../toolchains/llvm/prebuilt/*/bin
V   REFUTED -- the shipped file did not build
```

**Dead end 4, and the most embarrassing, because it is a class this repository has already recorded.**
The header comment contained a glob whose two closing characters also close a C block comment. The
comment terminated in the middle of a path and the rest of the header was parsed as code.
`37-RootDetection` shipped exactly this bug once, with `/proc/<star>/mounts` inside a block comment.

It was caught for one reason: **the file was built from its path in the repository rather than from
the scratch copy I had been iterating on.** Those were different files, and only one of them had the
header. A verification that runs against your working copy verifies your working copy.

Fixed by spelling the host tag out, with a comment explaining why it is not a glob.

---

## Q7 — Does my own auditor detect what it claims to?

Asked last, and only because the chapter was about to tell readers to run it on their work. This is
68's Q6 — *turn your own tooling on your own claims last* — and it found the same kind of thing.

`claim-ledger.py` looks for four defects, one of which is **the unlabelled composite**: a case study
that reads as one session but was assembled from several. Its test is "more than one device named,
and no provenance statement anywhere."

```
H11 the four detectors fire on fixtures built to trip each one
P   --self-test reports all passed
R   any detector misses its own fixture
E   python3 -B claim-ledger.py --self-test
O   clean case study        expect=(none)     got=(none)     OK
    tidy narrative          expect=TIDY       got=TIDY       OK
    counts, no denominator  expect=NO-DENOM   got=NO-DENOM   OK
    unlabelled composite    expect=COMPOSITE  got=(none)     FAIL
V   REFUTED
```

**Dead end 5, and by some distance the most instructive, because the tool committed the exact error
the chapter is about.**

The fixture names two devices and carries no provenance statement, so the detector should have fired.
It did not. The provenance test was a regex over disclosure keywords — `composed`, `transcribed`,
`provenance` — and the fixture's heading read:

```
# Two devices, no provenance
```

**It matched the word `provenance` inside a sentence stating that there was none, and reported the
document clean.**

That is case F in one line, committed by the tool written to catch case F. A substring matched
something other than what the sentence claimed it matched. It is also
[48-Biometrics'](../../48-Biometrics/README.md) grader reading its own files' explanatory comments and
scoring them backwards — a static matcher cannot tell an assertion from a denial of that assertion,
and the failure went in the direction that **looks clean**, which is the dangerous one.

Fixed with a negation lookbehind, so `no provenance`, `not transcribed` and `never re-run` no longer
count as disclosure. The comment above the regex explains why it is there, because a future reader
would otherwise simplify it back.

Two things worth extracting:

1. **A detector that has never failed a fixture has never been tested.** The self-test existed only
   because the three passing rows made the fourth row's failure visible. Had I written three fixtures
   instead of four, the tool would have shipped broken and confident.
2. **The trap does not care whether you know about it.** This chapter's §3.6 is *about* substring
   false positives. I wrote that section, then wrote this bug, in the same session. Knowing about a
   trap is a fact about knowledge; falling into it is a fact about attention, and they are almost
   unrelated. Q4's finding says the same thing about chapter 39.

---

## The ledger

| | |
|---|---|
| Questions asked | 7 (plus three sub-questions) |
| Hypotheses | 11 |
| **Refuted** | **7** |
| Reproduced as published | 3 cases (boot state, three-vantage probe, compiler leak) |
| **Diverged** | **3** (mountinfo count; property counts; `ro.boottime` vantage) |
| Not re-run, transcribed | 4 cases, on devices not attached |
| Findings the originals do not contain | **4** |
| New case studies produced | **1** (case E) |
| Dead ends that were mine, not the material's | **3 of 5** |
| Bugs found in this chapter's own shipped files | **2** (`fold.c` did not compile; `claim-ledger.py` read a denial as a confirmation) |

**The residue, written before the chapter was called finished:**

*Chosen.* One device, one session. The app vantage is `run-as`, so the domain is `runas_app` and not
`untrusted_app` — every *refusal* generalises to a real application, every *success* needs a probe
APK before publication. Cases B and F were not re-run for budget reasons rather than technical ones.
The two divergences against chapter 39 have a leading explanation that was deliberately not asserted.

*Structural.* No physical device was attached, so nothing on API 30 or API 33 was checked, and three
of the six cases have legs that only exist on hardware. The compiler case is host-side and says
nothing about what any real application ships. The 237-APK corpus behind case F was not re-pulled, so
that case rests entirely on its original chapter.

---

## What to copy from this

1. **Ask what you are talking to before you ask anything else.** Q1 changed the structure of the
   whole chapter and was not about any case study.
2. **A permission error is data.** Q2a's `Permission denied` was the best finding of the session.
   The reflex is to re-run with `su` and move on; the value is in asking why the first attempt was
   refused.
3. **"Close enough" is checkable.** Q4's escape hatch failed on arithmetic, not on judgement. One
   number moving by 380 while its partner moves by 1 is not drift.
4. **Add the control you do not need.** The root column in Q4 was habit. It is the entire case.
5. **Prefer sets to counts.** "How many?" survived unchecked for months. "Which ones?" produced a
   finding in ten minutes.
6. **Read the line, do not count the lines.** Q3a was saved by looking at the third match instead of
   tallying it.
7. **Publish the divergence, do not resolve it by assertion.** `DIVERGED, cause not established` is a
   real verdict and a more useful artefact than a confident guess.
8. **Verify the shipped file, not your working copy.** Q6 found a file that did not compile, from a
   path the chapter tells readers to use.
9. **Turn your own tooling on your own claims last, and give it a fixture it should fail.** Q7's
   detector was broken in exactly the way the chapter warns about, and only a deliberately-failing
   test case exposed it.

The enforcement tooling for the parts that are easy to skip:
[`scripts/claim-ledger.py`](../scripts/claim-ledger.py) refuses a claim with no device, no command or
no verdict, and reports the refuted-to-supported ratio for the document as a whole. **A case study
with no refutations has either been edited into a report, or was not an investigation.**
