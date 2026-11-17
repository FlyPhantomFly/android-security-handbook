# Contributing

This repository has unusually strong conventions. They are not stylistic preferences — nearly every
one of them exists because something went wrong here first, was measured, and was written down so it
would not happen again.

**Read [`STYLE-GUIDE.md`](STYLE-GUIDE.md) before you write anything.** It is the contract for how
chapters are written. This file covers everything around it: what a change has to satisfy, and the
commands that prove it does.

Two documents govern the rest:

- [`SECURITY.md`](SECURITY.md) — authorised-testing scope, the anonymisation policy, and how to
  report a problem in this material.
- [`LICENSE`](LICENSE) — CC BY 4.0 for content, MIT for code. By contributing you agree your
  contribution is licensed the same way.

---

## 1. The rules that get changes rejected

These are absolute. Everything else is negotiable.

### 1.1 Measure, do not recite

**A claim carries the command that produced it.** Not "Frida usually fails on this" — the command,
the device, and the output. If you cannot produce a claim's evidence, the claim does not go in.

This is the repository's founding standard, and it earns its keep. Roughly thirty recorded findings
here contradict what the field repeats to itself, and every one was found by running the thing
instead of quoting it:

| What everyone says | What measurement showed |
|---|---|
| `Build.FINGERPRINT.startsWith("generic")` detects an emulator | **False on a stock current AVD.** The most-copied `isEmulator()` on the internet returns `false`. |
| `/dev/qemu_pipe` is *the* emulator check | **`ENOENT` on API 35.** The node was renamed. |
| Scudo keeps freed blocks in a quarantine | **No quarantine on Android** — the freed block came straight back at the same address. |
| Use `explicit_bzero` to scrub secrets | **Absent from the NDK r25c sysroot entirely.** The standard advice fails at link time. |
| Patching a check function defeats the check | **Not when the compiler inlined it.** The patch provably worked; the patched copy was called by nothing. |

Each row is recorded with its command, its device and its API level in the chapter that measured it,
precisely because they are the kind of thing an editor working from memory will "correct" back to the
wrong answer. The largest collections are
[`76-CheatSheets`](76-CheatSheets/README.md) §6 — 33 commands that do not do what they are widely
believed to do, each with the measurement that refutes it — and the honesty conventions in
[`58-IDA`](58-IDA/README.md) and [`59-radare2`](59-radare2/README.md), which state what a tool was
*not* able to establish alongside what it was. **A correction you cannot reproduce is not a
correction**; if you want to change one of these rows, bring the new transcript.

Two corollaries:

- **State the environment.** Device or emulator, Android version and API level, architecture, root
  method, host OS and shell. A measurement without its environment is an anecdote.
- **When you are wrong, record it.** Corrections here keep the old claim and the reason it was
  wrong. That is how the contradictions table above came to exist.

### 1.2 Never name a real vendor or application as vulnerable

**Describe the class, quantify the population, anonymise the instance.**

"Twelve of fourteen apps present a pinning surface and four pin" is publishable and useful. The same
sentence with product names attached is, at best, a disclosure you were not authorised to make and,
at worst, defamatory if your adjudication was wrong.

Every commercial app measured here appears as `com.vendor.<category>`, with **the same pseudonym in
every chapter**. If you add a measurement, use the existing pseudonym or add a new row to the table
in [`72-RealWorldFindings/references/README.md` §4](72-RealWorldFindings/references/README.md#4-corpus-pseudonyms),
which is the authoritative text and which you must read first. In particular:

- **Partial anonymisation is not anonymisation.** One chapter here anonymised carefully and four
  others then named the same app outright, making the first chapter's work fully reversible.
- **An inventory is a fingerprint.** A size, a `targetSdk`, an SDK list and a per-package class count
  identify a vendor as reliably as the package name.
- **Anonymise the identity, never the measurement.** If a substitution would cost a number, the
  number wins and the prose is rewritten around it.

### 1.3 Never fabricate an identifier

No invented CVE IDs. No invented bug bounty report URLs. No invented AOSP line numbers.

Where you are not certain, **describe the class instead of inventing the identifier**. "This is the
exported-provider class of issue" is correct and useful; a plausible-looking `CVE-2021-XXXXX` that
does not exist destroys the credibility of everything around it. AOSP file paths are expected and
encouraged; line numbers are not, because they move.

### 1.4 Sources, never binaries — build out of tree

The repository ships the source of every target plus the script that builds it, and never the built
binary. `.pyc`, `__pycache__`, `.class`, `.o`, `.so`, `.jar`, `.apk`, `.dex`, `.iml` and `.DS_Store`
are a hard blocklist: a match is a failure, not a warning.

- Build scripts write to `$OUTDIR`, defaulting to `$TMPDIR`, **outside the tree**.
  [`43-WebView/examples/build.sh`](43-WebView/examples/build.sh) is the reference implementation.
- Signing keys are **generated at build time** into the output directory. No key, keystore or
  certificate is ever committed.
- Run every Python script with **`python3 -B`** so no `__pycache__` is created.
- [`.gitignore`](.gitignore) enforces this and explains the reasoning. Note what it deliberately does
  **not** ignore: `*.log` (two SELinux logs are measured evidence) and `.gitkeep` (406 of them hold
  open required chapter directories).

### 1.5 A path in a code fence is a promise

If you write a path, **the file must exist at that path**. This applies to prose links, fenced
commands, and script headers alike. Check before you submit; §3 gives the command.

### 1.6 Encoding: BOM-less UTF-8, no raw C0 control bytes

Both of these have drawn blood here.

**No byte-order mark.** A BOM is *valid* UTF-8 — `EF BB BF` decodes cleanly to U+FEFF — so a decoder
will never catch one. Ten files here carried a BOM and passed every UTF-8 decode. **A validity check
is not a conformance check.** Check the bytes.

**No raw C0 control bytes** (anything below `0x20` except tab, LF and CR, plus `0x7F`). Seventeen of
them were found across nine files. Write the escape, never the byte: the six ASCII characters
`\`, `u`, `0`, `0`, `0`, `0` — not a literal NUL.

> **This trap has fired four times out of four, and every single time on someone writing a warning
> about it.** One chapter did it twice in one session: once in the prose warning, and again *in the
> edit that was supposed to fix it*. This is a property of the tooling, not carelessness — typing an
> escape sequence into a tool call can be interpreted *before* it reaches disk, so the "fix" writes
> the same raw byte again and the file looks correct in every editor. Assume you have done it, and
> check the bytes.

**Never pair `Get-Content -Raw` with `Set-Content -Encoding UTF8`** in Windows PowerShell 5.1.
`-Raw` reads a BOM-less UTF-8 file using the ANSI codepage, so every multi-byte character decodes
wrongly, and writing it back makes the damage permanent. It silently corrupted 11 files here. Use
`[System.IO.File]::ReadAllText`/`WriteAllText` with an explicit encoding, or Python with
`encoding="utf-8"`.

**`-Include` is silently ignored when combined with `-LiteralPath`.** Use `Where-Object`. A check
that reports zero because it examined nothing is worse than no check.

### 1.7 Keep the lint gate at ERROR 0

[`76-CheatSheets/scripts/lint-commands.py`](76-CheatSheets/scripts/lint-commands.py) detects command
forms this repository has **measured** to be broken. Every rule corresponds to a recorded failure;
none is speculative, and none is style. The gate is **`ERROR 0`** and must stay there.

The rule you are most likely to hit is an **unquoted `su -c` following `adb shell`**. `adb shell`
does not preserve quoting, so your local shell strips the quotes and the command arrives at the
device as separate argv words: only the first statement of a compound command runs, and any flags
after it are eaten by `su` itself. Quote the whole thing instead:

```bash
# host — quoted so the device shell sees one command
adb shell "su -c 'a; b'"
```

**Suppressions must name the rules they suppress.** Roughly six occurrences here are deliberate
counter-examples that teach the trap. Mark them, and name the rule:

```bash
# host — a deliberate counter-example, not a defect
adb shell su -c 'id'          # lint:allow SU-DASH-C -- counter-example
```

> **A bare `lint:allow` suppresses *every* rule on that line.** One did exactly that here and
> silenced nine unrelated live warnings. Always name the rule ids. `--show-suppressed` lists
> suppressions anyway, so a marker cannot hide a defect from an audit.

---

## 2. Chapter structure

### 2.1 Teaching chapters — the 14-section template

Every numbered chapter's `README.md` uses these exact H2 headings, in this order. The full
description of what belongs in each is in [`STYLE-GUIDE.md` §3](STYLE-GUIDE.md).

```markdown
# NN — Chapter Title

> One-line statement of what the reader will be able to do after this chapter.

**Prerequisites:** links to prior chapters
**Applies to:** API levels / Android versions

## Table of Contents

## 1. Introduction
## 2. High-Level Architecture
## 3. Deep Internal Working
## 4. Source Code Walkthrough (AOSP)
## 5. Security Perspective
## 6. Reverse Engineering Perspective
## 7. Dynamic Analysis
## 8. Static Analysis
## 9. Examples
## 10. Common Interview Questions
## 11. Common Mistakes
## 12. Hands-on Labs
## 13. Summary
## 14. References
```

Plus the supporting files every chapter folder carries: `cheatsheet.md`, `mindmap.md`, `faq.md`,
`labs/`, `examples/`, `scripts/`, `references/`, `images/`.

### 2.2 Reference chapters — the one permitted alternative

**`76-CheatSheets`, `78-Diagrams`, `79-Glossary` and `80-Appendix` only.** Nothing else.
`75-InterviewQuestions` is **not** one of these — it has genuine labs and analysis, and keeps the
standard template.

These four are lookup artefacts, read non-linearly. Forcing the 14-section template onto them
produces filler — a "Hands-on Labs" section in a glossary — and filler in a reference is worse than
an honest omission because it buries the useful part. They follow the contract in
[`STYLE-GUIDE.md` §4a](STYLE-GUIDE.md) instead:

| Section | Why it is required |
|---|---|
| **Introduction** | What this is, and when you would reach for it *instead of* the chapter |
| **How to use it** | The entry format, the sort order, what the cross-references mean |
| **The body** | Whatever form fits — A–Z terms, a version matrix, templates, checklists |
| **Confusions and misuse** | The analogue of "Common Mistakes", and **the highest-value section in any reference** |
| **Summary** | Including quick revision and, where it helps, an inline Mermaid map |
| **References** | Annotated, ending with a Related-chapters table |

> **This is a different standard, not a lower one.** The exemption from `labs/`, `examples/`,
> `scripts/`, `cheatsheet.md`, `mindmap.md` and `faq.md` is **conditional on the equivalent material
> being present inline**. A reference chapter with no confusions section and no inline mind map does
> not qualify for the exemption — it is unfinished.

### 2.3 Writing rules, in brief

Complete sentences in prose (no arrow-chains — that is what diagrams are for). Tables for anything
enumerable. Jargon defined on first use. No filler openers. Cross-links relative
(`[Binder](25-Binder/README.md)`). Code fences labelled on the first line with **where the command
runs** — host, `adb shell`, device root, or Frida REPL. The five callout types are
`> **Definition**`, `> **Warning**`, `> **Pentester's Note**`, `> **Mental Model**` and
`> **Under the Hood**`.

---

## 3. Verification — run these before you submit

Run every command from the **repository root**. All of them must pass.

**1. The lint gate. Must report `ERROR 0`.**

```bash
# host — the whole repository
python3 -B 76-CheatSheets/scripts/lint-commands.py
```

```bash
# host — prove the detector before trusting its verdict
python3 -B 76-CheatSheets/scripts/lint-commands.py --self-test
```

```bash
# host — just your chapter, one rule
python3 -B 76-CheatSheets/scripts/lint-commands.py --path ./NN-Your-Chapter
```

**2. Build artefacts. Must print nothing.**

```bash
# host — the artefact blocklist
find . \( -name '__pycache__' -o -name '*.pyc' -o -name '*.class' -o -name '*.apk' \
     -o -name '*.dex' -o -name '*.so' -o -name '*.o' -o -name '*.jar' \
     -o -name '*.iml' -o -name '.DS_Store' \)
```

**3. Raw C0 control bytes. Must print nothing.**

```powershell
# host, PowerShell — note Where-Object, because -Include is ignored with -LiteralPath
Get-ChildItem -LiteralPath "." -Recurse -File | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    $n = @($b | Where-Object { ($_ -lt 0x20 -and $_ -notin 9,10,13) -or $_ -eq 0x7F }).Count
    if ($n) { "$($_.FullName) $n" }
}
```

**4. Byte-order marks. Must print nothing.**

```powershell
# host, PowerShell — a BOM is VALID UTF-8, so no decoder will catch it
Get-ChildItem -LiteralPath "." -Recurse -File -Filter *.md | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { "BOM: $($_.FullName)" }
}
```

If you are not on Windows, or you want checks 3 and 4 in one pass:

```bash
# host — control bytes and BOMs together, portable
python3 -B -c "
import os
for r, d, fs in os.walk('.'):
    if '.git' in r.split(os.sep): continue
    for f in fs:
        p = os.path.join(r, f)
        b = open(p, 'rb').read()
        if b[:3] == b'\xef\xbb\xbf': print('BOM:', p)
        n = sum(1 for x in b if (x < 0x20 and x not in (9, 10, 13)) or x == 0x7f)
        if n: print('CTRL:', p, n)
"
```

**5. Every path in a fence or link resolves.**

```bash
# host — relative markdown links that point at nothing
python3 -B -c "
import os, re
bad = 0
for r, d, fs in os.walk('.'):
    if '.git' in r.split(os.sep): continue
    for f in fs:
        if not f.endswith('.md'): continue
        p = os.path.join(r, f)
        for m in re.finditer(r']\((?!https?:|mailto:|#)([^)#]+)', open(p, encoding='utf-8').read()):
            t = os.path.normpath(os.path.join(r, m.group(1).strip()))
            if not os.path.exists(t):
                print('MISSING', p, '->', m.group(1)); bad += 1
print('broken links:', bad)
"
```

**6. If you touched a build script**, run it and confirm it wrote nothing into the tree:

```bash
# host — build, then prove the tree is unchanged
./NN-Chapter/examples/build.sh
find . -newer ./NN-Chapter/examples/build.sh -type f
```

---

## 4. Submitting

1. **One topic per change.** A chapter rewrite and a lint fix are two changes.
2. **Say what you measured, and on what.** Include the device, API level, and the command output.
   A change to a measured claim without a new measurement will be rejected on principle, however
   right it looks.
3. **Run every check in §3** and say so.
4. **Note any new third-party material** so it can be added to [`LICENSE`](LICENSE) §3. Device
   captures and vendor policy files are third-party material even when they look like plain text.

### What gets a change sent back

- A claim with no command behind it.
- A named vendor attached to a finding, or a de-anonymising detail.
- An invented CVE, bounty URL or AOSP line number.
- A committed binary, keystore, or `__pycache__`.
- A path in a fence that does not exist.
- A bare `lint:allow`, or any `ERROR`-tier lint finding.
- A BOM, or a raw control byte — including in the paragraph warning about them. *Especially* there.

---

## 5. Reporting rather than contributing

If you found a problem but do not want to write the fix, that is welcome too — an unsafe lab or a
destructive command is worth more reported than left alone. [`SECURITY.md` §4](SECURITY.md) covers
what is in scope and how to report it, including what must be reported **privately** rather than in
a public issue.
