# 73 — Labs · FAQ

Real questions, including the ones people feel stupid asking. Answers are direct; the reasoning is in
[README.md](README.md).

---

### 1. There are 327 labs. Where do I actually start?

Not at lab 1 of chapter 00. Start by finding out what your machine can run:

```bash
# host — from 73-Labs
python3 -B scripts/lab-env-probe.py --match
```

Then pick a route from [`references/learning-paths.md`](references/learning-paths.md) that matches
your goal. Reading order is a dependency order for *concepts*; it is not a learning order for
*skills*, and the difference is why people stall around chapter 20.

### 2. Do I have to do all of them?

No, and nobody has. 327 labs at a conservative two hours each is over eighty full working days. The
paths exist because the useful question is not "which labs are good" but "which fourteen labs get me
to a stated goal". Pick a goal first.

### 3. I do not have an Android phone. Is this repository useless to me?

No. **58 labs contain no `adb` invocation at all**, and they include much of chapters 10, 12, 32, 41,
42 and 56 — which is to say much of static analysis. Beyond those, an emulator covers most of the
rest: on the setup this chapter measured, an AVD blocked only **8** labs for being an emulator, out
of 187 blocked in total. Almost everything else was blocked by missing *host* tools — and a later
audit showed that figure was itself too pessimistic, because the probe resolved tools by command
name and missed two that were installed off `PATH`. Re-measured, the block count is **154**.

### 4. What is a "capability tag" and where does it come from?

A short identifier such as `root`, `frida` or `no-device`, derived from the lab's own text by
[`scripts/build-lab-index.py`](scripts/build-lab-index.py). It means **this lab issues a command
using this thing, or names it in its own prerequisites block** — not that the word appears somewhere.
Ask why any single tag was assigned:

```bash
# host
python3 -B scripts/build-lab-index.py --why 53-Frida/labs/lab-01-first-contact.md
```

### 5. Why generate the index instead of just writing it?

Because a written index is wrong the moment a chapter changes and nothing tells you. A generated one
is wrong only until somebody re-runs it, and the command is printed in the file's own banner. This is
not a labour-saving argument; it is a correctness argument.

### 6. The numbers in the chapter do not match what I get. Is something broken?

Almost certainly not. The denominator counts a repository that changes. This chapter's own Lab 01
first captured `131 / 315` and now reads `140 / 327`, because two chapters landed in between. **A
generated number is a measurement with a timestamp.** Compare the *shape* — which capability blocks
the most — rather than the digits.

### 7. `su` does not work on my device but I definitely rooted it. What is wrong?

You are probably using the wrong form. Run both:

```bash
# host
adb shell "su 0 id"
adb shell "su -c id"
```

The API 35 emulator ships AOSP's `su`, whose first positional argument is a **uid**, so `su -c` fails
with `su: invalid uid/gid '-c'` — which reads exactly like "not rooted". Magisk's `su` is a different
program and accepts `-c`. This is the single most misread signal in the repository.

<!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as the counter-example this answer teaches -->
### 8. Why is `adb shell su -c 'cmd'` wrong when it works for me?

Because the `adb shell` argument is re-parsed by the device's shell, which strips your quotes. `su`
then receives `-c` and `cmd` as separate words. Depending on which `su` you have, it runs only the
first word or rejects the flag. It "works" for you when your particular `su` tolerates the mangling
and your command happens to be a single word. Write `adb shell "su -c 'cmd'"` or `su 0 cmd`.

A repository-wide sweep found **196 occurrences** of the broken form here; 134 were repaired and the
rest were adjudicated as deliberate counter-examples and marked. Nobody wrote them carelessly.

### 9. `frida --version` prints a version. Why does the probe say I do not have Frida?

Because Frida is a capability that spans two machines. The host client and the device server are
separate programs, and yours may not run:

```bash
# host
adb shell "su 0 /data/local/tmp/frida-server --version"
```

On the device this chapter was written against, that prints `CANNOT LINK EXECUTABLE … empty/missing
DT_HASH/DT_GNU_HASH` — the binary was built with a toolchain newer than the image's dynamic linker
understands. Worse, `frida-ps -U` **still lists processes**, so the failure only appears on attach.
Test a capability with the operation you need it for.

### 10. `adb install` says "Install canceled by user" but I did not cancel anything. What?

You did not, and the message is untrue. `INSTALL_FAILED_USER_RESTRICTED` is an OEM policy — typically
"Install via USB" being disabled — and the working route is usually `adb push` followed by a root
`pm install` from the device shell. It is a completely different problem from
`INSTALL_FAILED_DEPRECATED_SDK_VERSION` (the platform's `targetSdk` floor, lifted with
`--bypass-low-target-sdk-block`) and from `INSTALL_FAILED_UPDATE_INCOMPATIBLE` (a signing-key
mismatch, needing an uninstall first). **Read the string; the three have unrelated fixes.**

### 11. Why does this repository never ship a prebuilt APK?

Three reasons. Build artefacts are unreviewable — you cannot diff a DEX meaningfully. A downloaded
"vulnerable app" binary is an unsigned-by-you executable of unknown provenance that you are about to
install on a device with developer options enabled, and that category has been abused. And sources
plus a build script stay correct as toolchains change, where a binary silently rots.

### 12. What does "build out of tree" mean and why does it matter?

Everything your build script produces goes under `$OUTDIR`, outside the repository, so no `.apk`,
`.dex`, `.class` or key is ever committed. It matters because those extensions are on the artefact
blocklist and the repository's checks fail on them — and because a committed build artefact is a
thing nobody can review and everybody trusts.

### 13. Is it normal that my static findings mostly do not survive the dynamic stage?

Yes, and it is the point. In this chapter's own chain lab, **three of four static severity
predictions were wrong**, and the one that looked worst on paper — an exported receiver performing a
destructive action — turned out to be unreachable by any caller that could actually be constructed.
Static analysis systematically over-rates reachability and under-rates data exposure: it sees the
door and not the room.

### 14. What is a "vantage" and why does everyone here keep saying it?

The security identity a command ran as: a third-party app, `shell` (uid 2000, over `adb`), root, or
the app itself. They hold different permissions and sit in different SELinux domains, and they answer
the same question differently. It comes up constantly because **a result measured from one and
reported as though from another is wrong even when every command succeeded**, and it is the most
repeated methodology error in this repository.

`adb shell` in particular is neither an app nor root, and it is where most people measure from.

### 15. The command printed "Broadcast completed: result=0". Did it work?

Unknown. That line prints whether or not any receiver ran — the number is the ordered-broadcast
result, not a delivery count. Measured in Lab 02: the same command produced byte-identical output in
a case where the receiver ran and a case where it did not, and only the application's own log
distinguished them. **If your evidence is the tool's own success message, you have no evidence.**

### 16. A lab does not reproduce for me. Am I doing it wrong?

Maybe, but that is the sixth thing to check, not the first. Run the triage:

```bash
# host
bash scripts/lab-doctor.sh --lab <path to the lab>
```

The ranked causes are: vantage, device or version difference, `su` form, tool version, a command that
succeeded and did nothing, and only then the lab being wrong. Most divergences resolve in the first
three.

### 17. I worked through it and still cannot explain the difference. What do I write?

**`DIVERGED, cause not established`**, and you change nothing. That is a complete and respectable
outcome. Record what was claimed and where, what you observed verbatim, both environments in full,
and which causes you ruled out and how. The template is
[`examples/divergence-report.md`](examples/divergence-report.md).

Resolving a divergence by assertion — picking whichever explanation flatters you and editing to match
— converts an open question into a confident error that every future reader inherits.

### 18. Can I fix a lab in another chapter if I find it wrong?

File the report; do not edit it. Another chapter's lab has an owner who knows things you do not,
including which device it was measured on and whether the oddity is deliberate. The same rule applies
to files you find on a shared test device: **residue and a live workspace look identical from
outside**, and only the person who created them can tell you which it is.

### 19. Why do some labs say "Difficulty: unstated"?

Because six labs genuinely declare no difficulty, and the index reports that rather than guessing.
One writes `**Level:** Core`, which is meaningful to a reader and is not one of the four bands.
Recording an honest absence is better than manufacturing a value that looks like a measurement.

Note the history: the parser's first version reported **17** unstated, and twelve of those did
declare a difficulty in formats it did not recognise. The parser was wrong, not the labs.

### 20. I want to write my own lab. What is the minimum bar?

[Lab 03](labs/lab-03-write-a-lab-that-survives.md) is the full answer;
[`examples/lab-template.md`](examples/lab-template.md) is the skeleton. The minimum bar is four
things: a header declaring difficulty, time, requirements and **the device you verified on**; output
blocks you personally observed on that device; falsifiable success criteria; and an "if it did not
work" table built from failures you actually hit. Then validate mechanically — you cannot proofread
your own environment out of your own document.

### 21. Do I need to run Python with `-B` every time? What does it do?

Yes, and it suppresses `__pycache__`. `.pyc` files are on the repository's artefact blocklist, so a
single forgotten `-B` leaves a directory the checks reject. It costs two characters and saves a
cleanup.

### 22. Something in `/data/local/tmp` is not mine. Should I delete it?

No. It may be another session's live workspace, and there is no way to tell from outside. Clean up
only what you created. This rule exists because a chapter here once found unfamiliar files, left them
alone, and they turned out to belong to a chapter being written in parallel — which had cleaned them
up itself by the end.

### 23. Why does this chapter have its own labs at all? Is it not just an index?

Because four things genuinely cannot live in any other chapter: a survey of your machine against the
whole corpus; a chain that carries one finding from static analysis through dynamic confirmation into
a report, crossing eight chapters; a lab about writing labs; and a CTF spanning five chapters'
techniques. Each of those is a property of the set, and a member of the set cannot hold it.
