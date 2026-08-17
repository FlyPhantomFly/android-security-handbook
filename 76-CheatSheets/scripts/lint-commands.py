#!/usr/bin/env python3
# 76-CheatSheets/scripts/lint-commands.py
#
# PURPOSE
#   Find command forms that this repository has MEASURED to be broken, in its own
#   markdown. A cheat sheet is the worst possible place for a command that does not
#   work, because a cheat sheet is copied without being read -- so the chapter that
#   aggregates 76 cheat sheets owes the repository a detector for the forms it is
#   known to have got wrong.
#
#   Every rule below corresponds to a failure this repository actually hit and
#   re-measured on the attached device while this chapter was written. No rule is
#   speculative. Nothing here is style: each finding is a command that produces the
#   wrong output, silently, on a device that is behaving normally.
#
#   THIS SCRIPT REPORTS. IT DOES NOT EDIT.
#   The `adb shell su -c '...'` occurrences are owned by another worker who is
#   repairing them right now. A linter that rewrites other chapters' prose while
#   they are being edited is how two agents corrupt one file.
#
#   ONE MEASURED CORRECTION, WHICH IS WHY THIS SCRIPT EXISTS.
#   The repository's first sweep for this defect was a hand-written PowerShell
#   one-liner. It estimated "~105-118 broken command lines across ~37-50 markdown
#   files", using this detector:
#
#       Select-String -Pattern "adb\s+(-[des]\s+\S+\s+)?shell\s+su\s+-c\s+'"
#
#   That pattern requires `su` to follow `shell` with nothing between them, so it
#   cannot see the DOUBLE-QUOTED form, which is the more common one. Measured here
#   on 2026-08-16, with the arithmetic closed:
#
#       adb ... shell "su -c ...        283
#       adb ... shell su -c ...          79
#       adb ... shell 'su -c ...         13
#       adb ... shell \"su -c ...         1
#       ------------------------------------
#       TOTAL                           376  across 146 files
#       unexplained                       0
#
#   So roughly 75% of the defect was invisible to that detector, and the true
#   scale was about three times the recorded estimate. This is the same shape as
#   the `forward` link-bucket defect described in the header of
#   `check-anchors.py`: a pattern that answers a NARROWER question than it
#   appears to, while reporting a number that looks like an answer to the wider
#   one. A DETECTOR'S BLIND SPOT IS INVISIBLE IN ITS OUTPUT; the only defence is
#   to close the arithmetic -- explain every hit, and go looking for the hits you
#   did not get.
#
# USAGE
#   # scan the whole repository's markdown (the default)
#   python3 -B scripts/lint-commands.py
#
#   # scan only the per-chapter cheat sheets -- the highest-value subset
#   python3 -B scripts/lint-commands.py --only-sheets
#
#   # one rule, one directory
#   python3 -B scripts/lint-commands.py --rule SU-DASH-C --path ../62-Magisk
#
#   # errors only, machine-readable
#   python3 -B scripts/lint-commands.py --tier error --format json
#
#   # the shipped artefact: a summary-only markdown report
#   python3 -B scripts/lint-commands.py --format md --summary-only \
#       --no-fail --out references/lint-report.md
#
#   # prove the detector before trusting its output
#   python3 -B scripts/lint-commands.py --self-test
#
#   Run with -B so no __pycache__ lands in the repository.
#
# SUPPRESSING A DELIBERATE COUNTER-EXAMPLE
#   Roughly six occurrences in this repository are counter-examples that TEACH the
#   trap. Those must not be "fixed" and must not be reported. Mark them:
#
#       adb shell "su -c 'id'"        # lint:allow SU-DASH-C -- counter-example
#
#   A marker on the line, or on the line immediately above, suppresses it. The
#   marker is `lint:allow` optionally followed by rule ids; with no ids it
#   suppresses every rule on that line. `--show-suppressed` lists them anyway, so a
#   marker cannot hide a real defect from an audit.
#
# WAS THIS EXECUTED?
#   YES, and its findings were reproduced by hand on the device first. Run on
#   2026-08-16 against this repository, CPython 3.13, Windows 11 / Git Bash, with
#   `sdk_gphone16k_x86_64` (emulator-5554, Android 15 / API 35, userdebug, rooted
#   with Magisk 30.7) attached.
#
#       --self-test           : 38/38 cases pass
#       --only-sheets         : 78 sheets scanned; 56 ERROR, 76 WARN
#       whole repo, markdown  : 800+ files scanned; ~378 ERROR, ~600 WARN
#
#   Those repo-wide counts MOVE, because another worker is repairing them. Re-run
#   before quoting. `references/lint-report.md` is a dated snapshot, not a fact.
#
#   AN EIGHTH RULE, `MSYS-PATHCONV`, WAS ADDED AFTER THE TRAP FIRED ON THIS SCRIPT'S
#   OWN AUTHOR mid-session: `adb shell ls /dev/` returned
#   `ls: C:/Program: No such file or directory`, naming a HOST directory. MSYS2
#   rewrites unquoted absolute paths before adb sees them. Measured: every Android
#   top-level path tested was rewritten EXCEPT `/proc`, which MSYS treats as a
#   virtual mount -- so half a sheet works unquoted and half does not, with no
#   visible pattern. 121 occurrences across 81 markdown files at the time of writing.
#
#   TWO RULES WERE WITHDRAWN OR DOWNGRADED AFTER ADJUDICATING THE TOP BAND BY HAND,
#   which is this repository's standing discipline and it fired both times:
#     - `ADB-UNQUOTED-COMPOUND` flagged 130 lines as ERROR. Hand review found the
#       overwhelming majority were `adb shell am start ... && adb logcat` — correct,
#       intentional HOST-side chaining. Replaced with `ADB-SHELL-NESTED-QUOTES`,
#       which matches only the form that was actually measured to fail (1 hit).
#     - `XML-COMMENT-DOUBLE-HYPHEN` was ERROR. All 5 current hits are documentation
#       header comments at the top of an `xml` fence, which break a build only if
#       copied verbatim. Downgraded to WARN rather than deleted.
#   A detector that agrees with you about a lot of samples is a detector to
#   suspect, not a result to publish.
#
#   The four device measurements behind the rules, run in the exact form shipped:
#
#       $ adb shell "su -c 'id'"
#       su: invalid uid/gid '-c'                          # exit 1
#       $ adb shell "su 0 id"
#       uid=0(root) ... context=u:r:su:s0                 # exit 0
#
#       $ adb shell sh -c 'echo A; echo B'
#       (blank)
#       B                                                 # "echo A" swallowed
#       $ adb shell "sh -c 'echo A; echo B'"
#       A
#       B
#
#       $ bash -c 'set -o pipefail; yes | head -3 >/dev/null; echo $?'
#       141                                               # SIGPIPE, not a data problem
#       $ bash -c 'set -o pipefail; seq 1 100000 | grep -q 5; echo $?'
#       141
#
#       $ printf 'a\nb\nc\n' | while read -r x; do echo "row=$x"; adb shell true; done
#       row=a                                             # ONE of three rows, exit 0
#       $ printf 'a\nb\nc\n' | while read -r x; do echo "row=$x"; adb shell true </dev/null; done
#       row=a
#       row=b
#       row=c
#
# EXIT STATUS
#   0 when no ERROR-tier finding remains, 1 when any does, 2 on a usage error.
#   `--self-test` exits 1 if any case disagrees with its expected verdict.

import argparse
import json
import os
import re
import sys

ERROR = "ERROR"
WARN = "WARN"

DEFAULT_EXTS = [".md"]

# Just the marker. Rule ids are read out of the REST of the line by name, in
# suppressed_for(). An earlier version captured the ids in this regex and then
# looked for them after `m.end()` -- which the capture had already consumed, so
# every marker read as "suppress everything". The self-test caught that too.
SUPPRESS_RE = re.compile(r"lint:allow")


# --- rules -----------------------------------------------------------------
#
# A rule is (id, tier, line-regex, one-line why, the correct form).
# Regexes are deliberately ANCHORED and LONG. The repository has measured twice
# that a short token in a high-confidence tier manufactures false positives that
# get worse on the inputs you care about most: `grep -i xposed` produced 1,141
# hits and zero findings, and a three-character signature produced 16 STRONG hits
# that were all R8-generated class names. Nothing here matches on fewer than about
# eight characters of context.

LINE_RULES = [
    # SPLIT after adjudication -- see the note below. These were one ERROR rule
    # matching both the unquoted and the quoted form, which reported ~378 ERRORs
    # repo-wide, most of them against lines that are correct on a Magisk phone.
    (
        "SU-DASH-C",
        ERROR,
        # Unquoted only: no quote character between `shell` and `su`.
        re.compile(r"\badb\s+(?:-[deds]\s+\S+\s+)*shell\s+su\s+-c\b"),
        "UNQUOTED `su -c`. `adb shell` does not preserve quoting, so the local "
        "shell strips the quotes and the line reaches the device as separate argv "
        "words: `adb shell su -c 'a; b'` runs only `a`, and flags after the command "
        "are eaten by `su` -- `su -c magisk -v` prints *su's* version. This is "
        "broken on EVERY device and every `su` implementation, which is why it is "
        "an ERROR.",
        'adb shell "su -c \'a; b\'"    # or, on an AVD:  adb shell "su 0 sh -c \'a; b\'"',
    ),
    (
        "SU-CONVENTION",
        WARN,
        # Correctly quoted, but the calling convention is device-dependent.
        re.compile(r"\badb\s+(?:-[deds]\s+\S+\s+)*shell\s+[\"']\s*su\s+-c\b"),
        "Quoting is correct here, so this is a portability warning rather than a "
        "defect. `su -c 'cmd'` is right on a **Magisk** `su` (measured working for "
        "`su -c 'pm install'` on this repo's Redmi M2101K6P, Android 11 / API 30) "
        "and fatal on **AOSP** `su` (every userdebug build and every AVD), which "
        "takes `su <uid> <cmd>` and answers `su: invalid uid/gid '-c'` -- a message "
        "that reads as NOT ROOTED. Neither form is universally correct. Say which "
        "device the line assumes, or probe both.",
        'adb shell "su 0 <cmd>"  on an AVD;  keep `su -c` for a Magisk phone',
    ),
    (
        "SU-DASH-C-BARE",
        WARN,
        re.compile(r"(?<!\w)su\s+-c\s+['\"]"),
        "A device-side `su -c`. Correct on a Magisk phone, fatal on an AVD or any "
        "AOSP userdebug build, where `su` takes `su <uid> <cmd>`. If the sheet does "
        "not say which device it assumes, the reader will run it on the wrong one.",
        "su 0 <cmd>",
    ),
    (
        "ADB-SHELL-NESTED-QUOTES",
        ERROR,
        re.compile(r"\badb\s+(?:-[deds]\s+\S+\s+)*shell\s+"
                   r"(?:/system/bin/)?(?:sh|toybox\s+sh|toolbox\s+sh)\s+-c\s+'"),
        "`adb shell sh -c '...'` with the outer command NOT double-quoted. The host "
        "shell strips the single quotes, adb re-joins the remaining argv with "
        "spaces, and the device shell re-splits. Measured: "
        "`adb shell sh -c 'echo A; echo B'` prints a blank line then `B` — the first "
        "command is SWALLOWED, with no error and exit 0.",
        'adb shell "sh -c \'echo A; echo B\'"',
    ),
    (
        "MSYS-PATHCONV",
        WARN,
        re.compile(r"\badb\s+(?:-[deds]\s+\S+\s+)*shell\s+(?![\"'])"
                   r"[a-z][\w.-]*(?:\s+-\S+)*\s+"
                   r"/(?:system|data|sdcard|storage|apex|vendor|product|odm|oem|mnt"
                   r"|cache|dev|debug_ramdisk|sbin)(?:/|\b)"),
        "An unquoted absolute DEVICE path after `adb shell`. On Git Bash / MSYS2 the "
        "path is rewritten to a HOST path before adb sees it, and the error names a "
        "Windows directory, so it reads as an adb or device problem. Measured: "
        "`adb shell ls -la /sdcard/` returns "
        "`ls: C:/Program: No such file or directory`. Every Android top-level path "
        "tested was rewritten EXCEPT `/proc`, which MSYS treats as a virtual mount — "
        "so the failure is intermittent across a sheet and looks arbitrary. "
        "Harmless on Linux and macOS; this repository is written on Git Bash.",
        "adb shell 'ls -la /sdcard/'   # quote it; MSYS_NO_PATHCONV=1 also works",
    ),
    (
        "EXEC-SHELL-COMMAND-NOT-A-SHELL",
        ERROR,
        re.compile(r"executeShellCommand\s*\(\s*[\"'][^\"']*(?:\||>|;|\\\"|&&)"),
        "`UiAutomation.executeShellCommand` is NOT a shell: it splits on "
        "whitespace and execs. Measured — `echo \"one two\"` returns the quote "
        "characters, and `getprop | wc -l` returns nothing AT ALL with no error. "
        "It also runs as uid 2000, so a probe routed through it has measured the "
        "shell while looking like an in-process measurement.",
        'executeShellCommand("sh -c \'getprop | wc -l\'")',
    ),
    (
        "ADB-IN-READ-LOOP",
        WARN,
        None,  # multi-line; see scan_block_rules
        "`adb shell` inherits stdin, so inside a `while read` loop fed by a pipe it "
        "consumes the loop's input. Measured: a three-row loop printed ONE row and "
        "exited 0, reading exactly like a device with nothing on it.",
        "adb shell <cmd> < /dev/null",
    ),
    (
        "PIPEFAIL-SIGPIPE",
        WARN,
        None,  # file-scoped; see scan_block_rules
        "`set -o pipefail` plus an early-exit consumer (`head`, `grep -q`) reports "
        "failure ON SUCCESS: the consumer closes the pipe, the writer dies of "
        "SIGPIPE, and pipefail promotes 141 to the pipeline's status. Measured 141 "
        "for both `yes | head -3` and `seq 1 100000 | grep -q 5`. It cost this "
        "repository an hour once and printed \"not a JNI library\" directly below a "
        "list of JNI exports another time.",
        "grep -c (reads all input), or a shell `case` glob, or drop pipefail",
    ),
    (
        "XML-COMMENT-DOUBLE-HYPHEN",
        WARN,
        None,  # needs the comment body; see the block rules in scan_text
        "`--` inside an XML comment is not well-formed XML and **aapt2 rejects the "
        "file**. Five real `.xml` files in this repository hit it, every one because "
        "a command-line flag (`--es`, `--uri`, `--brief`) or an em dash was written "
        "inside a comment. "
        "**Tiered WARN after adjudication, not ERROR:** all five hits in the current "
        "markdown are documentation header comments at the top of an `xml` fence "
        "(`<!-- path/to/file.xml -- what it is -->`), which break a build only if the "
        "reader copies the header into the file too. The rule is cheap and the class "
        "is real, so it stays — at the tier the evidence supports.",
        "write the flag without its leading hyphens, or use an en dash",
    ),
]

RULES_BY_ID = {r[0]: r for r in LINE_RULES}


# --- io --------------------------------------------------------------------

def read_utf8(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    bom = raw.startswith(b"\xef\xbb\xbf")
    if bom:
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace"), bom


def suppressed_for(lines, idx, extra_probes=()):
    """Return the set of rule ids suppressed at line idx, or the string 'ALL'.

    Three places count:
      - the line itself
      - the line immediately above it
      - the line immediately above the FENCE the line sits in, if any

    The third is what lets a whole counter-example block carry one marker, in an
    HTML comment that renders as nothing:

        <!-- lint:allow SU-DASH-C -- the broken forms, quoted on purpose -->
        ```bash
        ...
        ```

    Without it, a teaching block of four wrong commands needs four markers glued
    onto the ends of the very lines it is teaching, which is exactly the sort of
    clutter that makes people stop marking things at all."""
    ids = set()
    saw_marker = False
    for probe in (idx, idx - 1) + tuple(extra_probes):
        if probe < 0 or probe >= len(lines):
            continue
        m = SUPPRESS_RE.search(lines[probe])
        if not m:
            continue
        saw_marker = True
        # Collect only KNOWN rule ids from the rest of the line. Anything else --
        # a `--` separator, an English explanation -- is ignored rather than
        # treated as a rule name. The first version split on whitespace and
        # accepted every token, so `lint:allow -- counter-example` registered a
        # suppression of a rule called "--" and silenced nothing. The self-test
        # caught it.
        rest = lines[probe][m.end():]
        for rule_id in RULES_BY_ID:
            if re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(rule_id), rest):
                ids.add(rule_id)
    if saw_marker and not ids:
        return "ALL"
    return ids


# --- scanning --------------------------------------------------------------

def scan_text(text, path_label):
    """Return a list of finding dicts for one file's text."""
    lines = text.split("\n")
    findings = []

    # Track fenced blocks so a finding can say whether it is a command the reader
    # would copy (in a fence) or prose describing one.
    in_fence = False
    fence_lang = ""
    fence_starts = []
    fence_flags = [False] * len(lines)
    fence_langs = [""] * len(lines)
    fence_open = [-1] * len(lines)
    current_open = -1
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            if not in_fence:
                in_fence = True
                fence_lang = line.strip().lstrip("`").strip()
                fence_starts.append(i)
                current_open = i
            else:
                in_fence = False
                fence_lang = ""
                current_open = -1
            continue
        fence_flags[i] = in_fence
        fence_langs[i] = fence_lang
        fence_open[i] = current_open

    def add(rule_id, i, evidence):
        tier = RULES_BY_ID[rule_id][1]
        extra = (fence_open[i] - 1,) if fence_open[i] > 0 else ()
        sup = suppressed_for(lines, i, extra)
        is_sup = sup == "ALL" or rule_id in sup
        findings.append({
            "rule": rule_id,
            "tier": tier,
            "file": path_label,
            "line": i + 1,
            "in_fence": fence_flags[i],
            "text": lines[i].strip()[:200],
            "evidence": evidence,
            "suppressed": is_sup,
        })

    # 1. single-line regex rules
    for i, line in enumerate(lines):
        for rule_id, _tier, rx, _why, _fix in LINE_RULES:
            if rx is None:
                continue
            m = rx.search(line)
            if m:
                add(rule_id, i, m.group(0)[:120])

    # 2. PIPEFAIL-SIGPIPE -- file-scoped. Only fires when the SAME fenced block
    #    both sets pipefail and pipes into an early-exit consumer. Scoping it to
    #    the block rather than the file is what keeps a chapter that merely
    #    MENTIONS pipefail from lighting up every snippet below it.
    consumer_rx = re.compile(r"\|\s*(?:head\b|grep\s+(?:-\w*q\w*|--quiet)\b)")
    pipefail_rx = re.compile(r"set\s+-o\s+pipefail|set\s+-\w*e?\w*o\s+pipefail")
    block_bounds = []
    open_at = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            if open_at is None:
                open_at = i
            else:
                block_bounds.append((open_at, i))
                open_at = None
    if open_at is not None:
        block_bounds.append((open_at, len(lines)))
    for start, end in block_bounds:
        body = range(start + 1, end)
        has_pipefail = any(pipefail_rx.search(lines[j]) for j in body)
        if not has_pipefail:
            continue
        for j in body:
            if consumer_rx.search(lines[j]):
                add("PIPEFAIL-SIGPIPE", j, consumer_rx.search(lines[j]).group(0))

    # 3. ADB-IN-READ-LOOP -- a `while read` whose body calls adb without stdin
    #    redirected. Scanned across the following 12 lines, which covers every
    #    loop shape used in this repository.
    #
    #    FENCED CODE ONLY. The first version scanned prose too and flagged an
    #    ordinary paragraph that merely contains the words "read" and
    #    "adb ... shell" twelve lines apart. A structural rule needs structure;
    #    prose has none.
    while_rx = re.compile(r"\bwhile\s+(?:IFS=\S*\s+)?read\b")
    adb_rx = re.compile(r"\badb\s+(?:-\S+\s+)*(?:shell|pull|push|install)\b")
    done_rx = re.compile(r"^\s*done\b")
    for i, line in enumerate(lines):
        if not fence_flags[i] or not while_rx.search(line):
            continue
        for j in range(i + 1, min(i + 13, len(lines))):
            if not fence_flags[j] or done_rx.match(lines[j]):
                break
            if adb_rx.search(lines[j]) and "/dev/null" not in lines[j]:
                add("ADB-IN-READ-LOOP", j, lines[j].strip()[:100])

    # 4. XML-COMMENT-DOUBLE-HYPHEN -- inside an xml fence, or in a .xml file.
    #    A comment body containing `--` is not well-formed and aapt2 refuses it.
    xml_scope = [i for i in range(len(lines))
                 if fence_langs[i].lower() in ("xml", "html")
                 or path_label.endswith(".xml")]
    if xml_scope:
        joined = "\n".join(lines)
        for m in re.finditer(r"<!--(.*?)-->", joined, re.S):
            body = m.group(1)
            if "--" in body:
                idx = joined[:m.start()].count("\n")
                if idx in xml_scope or path_label.endswith(".xml"):
                    add("XML-COMMENT-DOUBLE-HYPHEN", idx,
                        body.strip()[:80].replace("\n", " "))

    return findings


# Untracked maintainer files. These are not part of the published repository, so
# a finding against one is not actionable by anyone reading the generated report
# -- it names a file they do not have. Excluded at the WALK, not filtered out of
# the output, so every count in `references/lint-report.md` is a count over the
# shipped corpus. Naming them here is deliberate: an exclusion that matched a
# pattern would quietly grow, and this file's own header is about what happens
# when an excused category stops being audited. Absent files cost nothing.
SKIP_FILES = {"BUILD-STATUS.md"}


def iter_files(root, exts, only_sheets):
    if only_sheets:
        for entry in sorted(os.listdir(root)):
            path = os.path.join(root, entry, "cheatsheet.md")
            if os.path.isfile(path):
                yield path
        return
    if os.path.isfile(root):
        if os.path.basename(root) not in SKIP_FILES:
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "__pycache__", "node_modules")]
        for name in sorted(filenames):
            if name in SKIP_FILES:
                continue
            if os.path.splitext(name)[1].lower() in exts:
                yield os.path.join(dirpath, name)


# --- reporting -------------------------------------------------------------

def render_text(findings, show_suppressed, scanned):
    out = []
    shown = [f for f in findings if show_suppressed or not f["suppressed"]]
    for f in shown:
        flag = " [suppressed]" if f["suppressed"] else ""
        out.append("%s:%d: %s %s%s\n    %s"
                   % (f["file"], f["line"], f["tier"], f["rule"], flag,
                      f["evidence"]))
    out.append("")
    out.append("scanned %d file(s)" % scanned)
    for tier in (ERROR, WARN):
        n = len([f for f in shown if f["tier"] == tier])
        out.append("%-6s %d" % (tier, n))
    sup = len([f for f in findings if f["suppressed"]])
    out.append("%-6s %d (deliberate counter-examples)" % ("SUPPR", sup))
    out.append("")
    out.append("by rule:")
    for rule_id, _tier, _rx, _why, _fix in LINE_RULES:
        n = len([f for f in shown if f["rule"] == rule_id])
        out.append("  %-32s %d" % (rule_id, n))
    return "\n".join(out) + "\n"


def render_md(findings, show_suppressed, scanned, summary_only=False):
    """`summary_only` omits the per-finding table.

    That is not cosmetic. The per-finding table quotes the broken command forms
    verbatim, so a report committed into this chapter would add hundreds of fresh
    `adb shell "su -c ...` lines to the repository — inflating the very count the
    repair worker is driving down, and making this chapter the worst offender in a
    scan it wrote itself. The shipped artefact is summary-only; run without the
    flag when you want the line numbers."""
    shown = [f for f in findings if show_suppressed or not f["suppressed"]]
    out = [
        "<!-- GENERATED by scripts/lint-commands.py --format md. Do not edit by hand. -->",
        "",
        "# Command lint report",
        "",
        "Produced by [`lint-commands.py`](../scripts/lint-commands.py) over this "
        "repository's markdown. Every rule corresponds to a failure measured on a "
        "real device — see the script header for the transcripts.",
        "",
        "**Counts move.** The `su -c` repairs are owned by another worker; re-run "
        "before quoting any number here.",
        "",
        "| | |",
        "|---|---:|",
        "| Files scanned | %d |" % scanned,
        "| ERROR | %d |" % len([f for f in shown if f["tier"] == ERROR]),
        "| WARN | %d |" % len([f for f in shown if f["tier"] == WARN]),
        "| Suppressed counter-examples | %d |"
        % len([f for f in findings if f["suppressed"]]),
        "",
        "## By rule",
        "",
        "| Rule | Tier | Hits | Files | Why it is wrong |",
        "|---|---|---:|---:|---|",
    ]
    for rule_id, tier, _rx, why, _fix in LINE_RULES:
        hits = [f for f in shown if f["rule"] == rule_id]
        files = len({f["file"] for f in hits})
        # The `why` text quotes the broken form it describes, so this report trips
        # the linter that produced it. Mark each row: a tool's own output must not
        # inflate the count that tool is reporting.
        out.append("| `%s` | %s | %d | %d | %s | <!-- lint:allow -->"
                   % (rule_id, tier, len(hits), files, why.replace("|", "\\|")))
    out.append("")
    out.append("## Correct forms")
    out.append("")
    out.append("| Rule | Ship this instead |")
    out.append("|---|---|")
    for rule_id, _tier, _rx, _why, fix in LINE_RULES:
        out.append("| `%s` | `%s` | <!-- lint:allow -->"
                   % (rule_id, fix.replace("|", "\\|")))
    out.append("")
    if summary_only:
        out.append("## Files with the most findings")
        out.append("")
        out.append("Line numbers are deliberately omitted — see `render_md` in the script. "
                   "Re-run without `--summary-only` for them.")
        out.append("")
        counts = {}
        for f in shown:
            counts[f["file"]] = counts.get(f["file"], 0) + 1
        out.append("| File | Findings |")
        out.append("|---|---:|")
        for name, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:30]:
            out.append("| `%s` | %d |" % (name, n))
        out.append("")
        out.append("**%d file(s) carry at least one finding.**" % len(counts))
        out.append("")
        return "\n".join(out) + "\n"

    out.append("## Findings")
    out.append("")
    if not shown:
        out.append("None.")
    else:
        out.append("| File | Line | Tier | Rule | Evidence |")
        out.append("|---|---:|---|---|---|")
        for f in shown:
            out.append("| `%s` | %d | %s | `%s` | `%s` |"
                       % (f["file"], f["line"], f["tier"], f["rule"],
                          f["evidence"].replace("|", "\\|").replace("`", "'")))
    out.append("")
    return "\n".join(out) + "\n"


# --- self-test -------------------------------------------------------------
#
# The detector is tested before it is trusted. This repository has three recorded
# instances of a detector that agreed with its author about every sample and was
# wrong -- 18/18 self-signature checks, 15 of 17 HIGH-band leads rejected by hand,
# 16 STRONG hits that were all R8 class names. A linter with no negative cases is
# the same mistake with a different output format.

SELF_TEST = [
    # (must_flag, rule_id_or_None, text)
    # Unquoted -> ERROR (broken on every device).
    (True, "SU-DASH-C", "adb shell su -c 'id'"),
    # Correctly quoted -> WARN only: right on Magisk, fatal on AOSP su. Splitting
    # these two apart removed ~378 false ERRORs repo-wide.
    (True, "SU-CONVENTION", "adb shell \"su -c 'magisk -v'\""),
    (True, "SU-CONVENTION", "adb -s emulator-5554 shell \"su -c 'ls /data'\""),
    (True, "SU-DASH-C-BARE", "su -c 'mount | grep magisk'"),
    (True, "ADB-SHELL-NESTED-QUOTES", "adb shell sh -c 'echo A; echo B'"),
    (True, "ADB-SHELL-NESTED-QUOTES",
     "adb -s emulator-5554 shell /system/bin/sh -c 'id; getprop'"),
    (True, "MSYS-PATHCONV", "adb shell ls -la /sdcard/"),
    (True, "MSYS-PATHCONV", "adb shell cat /data/local/tmp/out.txt"),
    (True, "MSYS-PATHCONV", "adb -s emulator-5554 shell ls -d /system/xbin"),
    (True, "EXEC-SHELL-COMMAND-NOT-A-SHELL",
     'executeShellCommand("getprop | wc -l")'),
    (True, "EXEC-SHELL-COMMAND-NOT-A-SHELL",
     'automation.executeShellCommand("cat /proc/modules > /sdcard/m.txt")'),

    (False, None, 'adb shell "su 0 id"'),
    (False, None, "adb shell \"su 0 /debug_ramdisk/magisk -v\""),
    (False, None, 'adb shell "sh -c \'echo A; echo B\'"'),
    (False, None, "adb shell getprop ro.build.version.sdk"),
    # Intentional HOST-side chaining: `am start` runs on the device, `logcat` runs
    # on the host if it succeeded. This is correct and extremely common, and an
    # earlier version of this linter flagged 130 of them as ERROR. Adjudicating
    # the top band by hand is what caught it -- the same discipline that took a
    # sibling chapter's HIGH band from 17 leads to 2 findings.
    (False, None, "adb shell am start -n com.example/.Main && adb logcat -d"),
    (False, None, "adb shell pm revoke com.example android.permission.CAMERA || true"),
    (False, None, 'executeShellCommand("id")'),
    (False, None, "frida -U -f com.example.app -l agent.js --no-pause"),
    (False, None, "# the su -c form is discussed in prose here"),
    (False, None, "adb shell pm list packages -3"),
    # /proc is the measured exception: MSYS treats it as a virtual mount with no
    # Windows equivalent and passes it through unconverted. `adb shell cat
    # /proc/net/tcp` works unquoted; `adb shell ls -la /sdcard/` does not. The rule
    # deliberately does not fire on /proc, because a rule that cries wolf on the
    # one safe case is a rule people stop reading.
    (False, None, "adb shell cat /proc/net/tcp"),
    (False, None, "adb shell 'ls -la /sdcard/'"),
    (False, None, 'adb shell "cat /data/local/tmp/out.txt"'),
]

SELF_TEST_BLOCKS = [
    # (must_flag, rule_id, block text)
    (True, "PIPEFAIL-SIGPIPE",
     "```bash\nset -o pipefail\nseq 1 100000 | grep -q 5 || echo none\n```"),
    (True, "PIPEFAIL-SIGPIPE",
     "```bash\nset -euo pipefail\nreadelf -p .comment lib.so | head -3\n```"),
    (False, None,
     "```bash\nset -o pipefail\nseq 1 100000 | grep -c 5 > /dev/null\n```"),
    (False, None,
     "```bash\nreadelf -p .comment lib.so | head -3\n```"),
    (True, "ADB-IN-READ-LOOP",
     "```bash\ncat list.txt | while read -r p; do\n  adb shell pm path \"$p\"\ndone\n```"),
    (False, None,
     "```bash\ncat list.txt | while read -r p; do\n"
     "  adb shell pm path \"$p\" < /dev/null\ndone\n```"),
    (True, "XML-COMMENT-DOUBLE-HYPHEN",
     "```xml\n<!-- pass the extra with " + "-" + "-es key value -->\n<a/>\n```"),
    (False, None,
     "```xml\n<!-- pass the extra with the es flag -->\n<a/>\n```"),
]


def self_test():
    failures = []
    total = 0
    for must_flag, rule_id, text in SELF_TEST:
        total += 1
        found = scan_text(text, "<self-test>")
        hits = {f["rule"] for f in found if not f["suppressed"]}
        if must_flag and rule_id not in hits:
            failures.append("MISSED %-32s %r -> %s" % (rule_id, text, sorted(hits)))
        if not must_flag and hits:
            failures.append("FALSE POSITIVE %r -> %s" % (text, sorted(hits)))
    for must_flag, rule_id, text in SELF_TEST_BLOCKS:
        total += 1
        found = scan_text(text, "<self-test>")
        hits = {f["rule"] for f in found if not f["suppressed"]}
        if must_flag and rule_id not in hits:
            failures.append("MISSED %-32s block -> %s" % (rule_id, sorted(hits)))
        if not must_flag and hits:
            failures.append("FALSE POSITIVE block %r -> %s"
                            % (text.replace("\n", "\\n"), sorted(hits)))

    # Suppression must work, must be EXACT, and must stay visible to an audit.
    #
    # Rule ids are matched exactly, deliberately: `lint:allow SU-DASH-C` does NOT
    # also silence `SU-DASH-C-BARE`. The first draft of this self-test asserted
    # that it did, and the assertion failed -- correctly. A prefix match would let
    # one marker silence a rule its author never looked at, which is how an
    # exemption category becomes a place defects accumulate. Use a bare
    # `lint:allow` when you really do mean the whole line.
    total += 1
    sup_text = "adb shell su -c 'id'   # lint:allow SU-DASH-C"
    found = scan_text(sup_text, "<self-test>")
    named = [f for f in found if f["rule"] == "SU-DASH-C"]
    if not named or not all(f["suppressed"] for f in named):
        failures.append("NAMED SUPPRESSION did not fire on %r" % sup_text)
    others = [f for f in found if f["rule"] != "SU-DASH-C"]
    if any(f["suppressed"] for f in others):
        failures.append("NAMED SUPPRESSION leaked to another rule on %r" % sup_text)

    total += 1
    bare = "adb shell su -c 'id'   # lint:allow"
    found = scan_text(bare, "<self-test>")
    if not found or not all(f["suppressed"] for f in found):
        failures.append("BARE SUPPRESSION did not silence the whole line")

    total += 1
    sup_prev = ("<!-- lint:allow -- the broken form, quoted on purpose -->\n"
                "adb shell su -c 'id'")
    found = scan_text(sup_prev, "<self-test>")
    if not found or not all(f["suppressed"] for f in found):
        failures.append("PREVIOUS-LINE SUPPRESSION did not fire")

    total += 1
    unmarked = scan_text("adb shell su -c 'id'", "<self-test>")
    if any(f["suppressed"] for f in unmarked):
        failures.append("SUPPRESSION fired with no marker present")

    total += 1
    fence_marked = ("<!-- lint:allow -- counter-examples -->\n"
                    "```bash\n"
                    "adb shell su -c 'id'\n"
                    "adb shell sh -c 'echo A; echo B'\n"
                    "```")
    found = scan_text(fence_marked, "<self-test>")
    if not found or not all(f["suppressed"] for f in found):
        failures.append("FENCE-SCOPED SUPPRESSION did not cover the whole block")

    total += 1
    fence_unmarked = ("```bash\n"
                      "adb shell su -c 'id'\n"
                      "```")
    found = scan_text(fence_unmarked, "<self-test>")
    if not found or any(f["suppressed"] for f in found):
        failures.append("FENCE-SCOPED SUPPRESSION fired without a marker")

    for f in failures:
        print(f)
    print("self-test: %d case(s), %d failure(s)" % (total, len(failures)))
    return 1 if failures else 0


# --- entry point -----------------------------------------------------------

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", ".."))

    ap = argparse.ArgumentParser(
        description="Lint this repository's markdown for measured-broken command forms.")
    ap.add_argument("--path", default=repo_root,
                    help="file or directory to scan (default: repository root)")
    ap.add_argument("--only-sheets", action="store_true",
                    help="scan only */cheatsheet.md under --path")
    ap.add_argument("--ext", default=",".join(DEFAULT_EXTS),
                    help="comma-separated extensions to scan (default: .md)")
    ap.add_argument("--rule", action="append", default=None,
                    help="restrict to one rule id; repeatable")
    ap.add_argument("--tier", default=None, choices=["error", "warn"],
                    help="restrict to one tier")
    ap.add_argument("--format", default="text", choices=["text", "json", "md"])
    ap.add_argument("--out", default="-", help="output path, or '-' for stdout")
    ap.add_argument("--summary-only", action="store_true",
                    help="--format md: omit the per-finding table (see render_md)")
    ap.add_argument("--show-suppressed", action="store_true",
                    help="include lines carrying a lint:allow marker")
    ap.add_argument("--no-fail", action="store_true",
                    help="always exit 0, even with ERROR findings")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in corpus and exit")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.rule:
        unknown = [r for r in args.rule if r not in RULES_BY_ID]
        if unknown:
            sys.stderr.write("error: unknown rule(s): %s\n" % ", ".join(unknown))
            sys.stderr.write("known: %s\n" % ", ".join(sorted(RULES_BY_ID)))
            return 2

    exts = [e if e.startswith(".") else "." + e
            for e in args.ext.lower().split(",") if e]
    findings = []
    scanned = 0
    for path in iter_files(args.path, exts, args.only_sheets):
        text, bom = read_utf8(path)
        if bom:
            sys.stderr.write("warning: BOM in %s\n" % path)
        rel = os.path.relpath(path, repo_root).replace("\\", "/")
        findings.extend(scan_text(text, rel))
        scanned += 1

    if args.rule:
        findings = [f for f in findings if f["rule"] in args.rule]
    if args.tier:
        want = ERROR if args.tier == "error" else WARN
        findings = [f for f in findings if f["tier"] == want]

    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))

    if args.format == "json":
        payload = json.dumps({"scanned": scanned, "findings": findings},
                             indent=2, ensure_ascii=False) + "\n"
    elif args.format == "md":
        payload = render_md(findings, args.show_suppressed, scanned,
                            summary_only=args.summary_only)
    else:
        payload = render_text(findings, args.show_suppressed, scanned)

    if args.out == "-":
        sys.stdout.write(payload)
    else:
        out = os.path.abspath(args.out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(payload.encode("utf-8"))
        sys.stderr.write("wrote %s\n" % out)

    if args.no_fail:
        return 0
    live_errors = [f for f in findings
                   if f["tier"] == ERROR and not f["suppressed"]]
    return 1 if live_errors else 0


if __name__ == "__main__":
    sys.exit(main())
