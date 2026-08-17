#!/usr/bin/env python3
# 73-Labs/scripts/build-lab-index.py
#
# PURPOSE
#   Build the repository-wide lab index MECHANICALLY, by parsing every
#   `NN-Chapter/labs/*.md` file in this repository. Nothing in the generated
#   output is transcribed by hand, so the index cannot drift: re-run it after any
#   chapter changes and the output is correct again.
#
#   Chapter 73's whole reason to exist is that concatenating ~315 labs would be
#   enormous and worthless. This script does the one part of aggregation that IS
#   worth doing -- navigation and capability matching -- and leaves the teaching
#   to the chapters that own each lab.
#
#   Three things are derived, never guessed:
#     * difficulty  -- read from the lab's own header, in the four formats the
#                      repository actually uses (see FORMATS below)
#     * time        -- read from the lab's own header
#     * requirements-- derived from the lab TEXT by the rules in REQUIREMENTS
#                      below, and every derived tag carries the line that
#                      produced it, so any claim in the index can be audited
#                      back to the sentence in the lab that justifies it.
#
# USAGE
#   # write all four generated artefacts under ../references/
#   python3 -B scripts/build-lab-index.py
#
#   # one grouping to stdout
#   python3 -B scripts/build-lab-index.py --by chapter     --out -
#   python3 -B scripts/build-lab-index.py --by difficulty  --out -
#   python3 -B scripts/build-lab-index.py --by requirement --out -
#   python3 -B scripts/build-lab-index.py --by path        --out -
#
#   # machine-readable; lab-env-probe.py consumes exactly this
#   python3 -B scripts/build-lab-index.py --format json --out ../scratch/labs.json
#
#   # counts only, nothing written
#   python3 -B scripts/build-lab-index.py --stats
#
#   # show WHY a lab carries a tag -- prints the evidence line for each
#   python3 -B scripts/build-lab-index.py --why 53-Frida/labs/lab-01-first-contact.md
#
#   # resolve every link this script emits against the filesystem.
#   # THIS IS THE DEPTH CHECK. Run it after every change to an emit site.
#   python3 -B scripts/build-lab-index.py --verify-links
#
#   Always run with -B so no __pycache__ is written into the repository.
#
# LINK DEPTH -- READ THIS BEFORE EDITING ANY EMIT SITE
#   Output lands in 73-Labs/references/, which is TWO levels below the repo root.
#   A link to another chapter is therefore `../../NN-Chapter/labs/x.md`, not
#   `../NN-Chapter/labs/x.md`. The one-level form resolves inside 73-Labs/ and is
#   silently wrong. The identical mistake in 75-InterviewQuestions produced 1,495
#   broken links that a checker exemption hid for months. Every emit site here
#   goes through link_to_repo() or link_to_chapter73(), which are the only two
#   functions that know the depth, and --verify-links resolves all of them.
#
# FORMATS -- how the 315 labs actually write their headers, measured not assumed
#   **Difficulty:** Intermediate          222 files
#   > **Difficulty:** Intermediate         65 files
#   | **Difficulty** | Intermediate |      22 files
#   > **Difficulty.** Beginner. ...         4 files (period inside the bold run)
#   > **Level:** Beginner - **Time:** ...   4 files ("Level", fields separated
#                                           by a middle dot on one line)
#   ...Difficulty: intermediate...          3 files (prose, chapter 04)
#   no marker of any kind                  the remainder -- reported as
#                                          "unstated", NEVER invented
#
#   The first version of this parser reported 17 labs with no difficulty. Twelve
#   of those did declare one, in the two formats above that it did not know. The
#   repository's own rule applied: a detector that disagrees with a dozen samples
#   is more likely to be wrong than the samples are.
#
# REQUIREMENTS -- the derivation rules, and what a tag actually claims
#   A tag means: **this lab issues a command that uses this tool, or names it in
#   its own prerequisites block.** It does NOT mean "the word appears somewhere".
#   That distinction is the whole difference between a useful index and a word
#   count: the first version of this script tagged 186 labs as needing Frida,
#   and one of them was 66-Instrumentation lab 01, whose only mention of Frida is
#   the sentence "without root, without Frida". Tool detection is therefore
#   scoped to the HEADER BLOCK plus the contents of FENCED CODE BLOCKS, and the
#   count fell to a number that survives inspection.
#
#   Negations are checked first and win outright, because a lab that says "No
#   root required for any step" also contains `su` in a counter-example.
#
#   Every tag stores the matched line as evidence, so any claim in the generated
#   index can be traced back to the sentence in the lab that justifies it:
#       python3 -B scripts/build-lab-index.py --why <chapter>/labs/<file>.md
#
# WAS THIS EXECUTED?
#   YES, repeatedly, and the numbers below are the final run. Run against this
#   repository on 2026-08-16 with CPython 3.13.3 on Windows 11, Git Bash:
#
#       chapters with a labs/ directory        : 79
#       lab markdown files indexed             : 327
#       CTF labs                               : 74
#       Beginner / Intermediate / Advanced     : 61 / 120 / 66
#       difficulty not declared by the lab     : 6   (reported, never guessed)
#       labs with no adb invocation at all     : 58
#       labs stating root is NOT needed        : 69
#       labs needing root                      : 82
#       labs needing Frida                     : 128
#       labs needing an NDK                    : 50
#       labs needing a physical device         : 8
#       distinct links emitted                 : 410
#       links that failed to resolve           : 0
#
#   `--verify-links` resolves every emitted link against the filesystem and
#   returned `links=410 broken=0`. Re-run it; do not trust this comment.
#
#   Four defects were found in THIS script by running it, not by reading it:
#     * 17 labs reported as having no difficulty; 12 of them did declare one, in
#       two header formats the parser did not know. The parser was wrong.
#     * 186 labs reported as needing Frida, including one whose only mention is
#       "without root, without Frida". Tool detection is now scoped to the
#       header block plus fenced code blocks.
#     * A lab header reading "No root, no Frida, no proxy" RAISED the frida tag.
#       Header-scoped negations added.
#     * `--why` crashed with UnicodeEncodeError on a title containing an arrow,
#       because a Windows console is cp1252. Both scripts now force UTF-8.
#
# EXIT STATUS
#   0 normally. 1 from --verify-links if any emitted link fails to resolve.
#   2 if no chapter directories were found under --root.

import argparse
import json
import os
import re
import sys

# Lab titles in this repository contain em-dashes and arrows, and a Windows
# console defaults to cp1252, where `print()` raises UnicodeEncodeError on both.
# That is how `--why` first failed on a lab whose title contained a right-arrow.
# Force UTF-8 on the text streams; fall back silently on Python builds that do
# not support reconfigure().
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CHAPTER_DIR_RE = re.compile(r"^(\d{2})-")

# This chapter. Its own labs are indexed like any other, but they are marked so
# a reader can tell the aggregator's labs from the chapters' labs.
SELF = "73-Labs"

# Canonical difficulty bands, in escalation order. Everything normalises here.
BANDS = ["Beginner", "Intermediate", "Advanced", "CTF"]

# Ordered: the FIRST pattern that matches decides the band, so CTF outranks
# Advanced outranks Intermediate outranks Beginner. A lab written
# "Beginner -> Intermediate" lands in Intermediate, which is the honest read:
# it is the level you need to finish, not the level you need to start.
BAND_PATTERNS = [
    (re.compile(r"\bctf\b", re.I), "CTF"),
    (re.compile(r"advanc|expert|\bhard\b|capstone|★{4}", re.I), "Advanced"),
    (re.compile(r"intermediate|★{3}", re.I), "Intermediate"),
    (re.compile(r"beginner|introductory|warm.?up|★{1,2}", re.I), "Beginner"),
]

# The header formats, tried in order. `FIELD_SEP` is what ends a field when a
# lab puts several on one line: a middle dot, a pipe, or end of line.
FIELD_SEP = r"(?:\s*[·|]|$)"

DIFF_RES = [
    # | **Difficulty** | Intermediate |
    re.compile(r"^\s*\|\s*\*\*(?:Difficulty|Level)\*\*\s*\|\s*(.+?)\s*\|\s*$", re.I | re.M),
    # **Difficulty:** X   /   > **Difficulty.** X   /   **Level:** X
    re.compile(r"^\s*>?\s*\*\*(?:Difficulty|Level)\s*[:.]?\s*\*\*\s*[:.]?\s*(.+?)"
               + FIELD_SEP, re.I | re.M),
    # prose: "Difficulty: intermediate."
    re.compile(r"Difficulty:\s*([^.<|\n]+)", re.I),
]

TIME_RES = [
    re.compile(r"^\s*\|\s*\*\*(?:Time|Duration)\*\*\s*\|\s*(.+?)\s*\|\s*$", re.I | re.M),
    re.compile(r"^\s*>?\s*\*\*(?:Time|Duration|Estimated time)\s*[:.]?\s*\*\*\s*[:.]?\s*(.+?)"
               + FIELD_SEP, re.I | re.M),
]

# Fenced code blocks. Tool requirements are read from these plus the header
# block, never from running prose. See REQUIREMENTS in the header comment.
FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.M | re.S)

TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.M)
OBJECTIVE_RE = re.compile(
    r"^(?:##+\s*(?:\d+\.\s*)?Objective\s*$|>\s*\*\*Objective\.?\*\*)", re.I | re.M)

# --------------------------------------------------------------------------- #
# Requirement derivation
#
# Each rule has:
#   tag       short identifier used in the index
#   label     one-line human meaning
#   negate    regex that, if it matches the whole file, suppresses the tag
#   positive  regex that raises the tag
#   also_any  optional second regex evaluated against the WHOLE file, for claims
#             a lab makes in prose rather than demonstrates in a command
#
# Positive matching is scoped to header + fenced code blocks. See REQUIREMENTS.
# --------------------------------------------------------------------------- #

RULES = [
    dict(
        tag="root",
        label="root on the device",
        negate=re.compile(
            r"no\s+root\s+(?:is\s+)?(?:required|needed)"
            r"|root\s+is\s+not\s+(?:required|needed)"
            r"|without\s+root|no-root|unrooted\b|not\s+rooted\b",
            re.I),
        positive=re.compile(
            r"rooted\s+(?:device|phone|emulator|avd)"
            r"|requires?\s+root|root\s+(?:is\s+)?required|needs?\s+root"
            r"|\bsu\s+0\s|\badb\s+root\b|\bmagisk\b|\bsu\s+-c\b",
            re.I),
    ),
    dict(
        tag="frida",
        label="Frida (host tool and a working frida-server)",
        negate=None,
        positive=re.compile(r"\bfrida\b|frida-server|frida-trace|frida-ps", re.I),
    ),
    dict(
        tag="objection",
        label="Objection",
        negate=None,
        positive=re.compile(r"\bobjection\b", re.I),
    ),
    dict(
        tag="ndk",
        label="Android NDK (native toolchain)",
        negate=None,
        positive=re.compile(
            r"ANDROID_NDK|ndk-build|\bNDK\b|aarch64-linux-android\d*-clang"
            r"|x86_64-linux-android\d*-clang|llvm-objdump|CMakeLists",
            re.I),
    ),
    dict(
        tag="jdk",
        label="JDK plus SDK build-tools (javac / kotlinc / d8 / aapt2)",
        negate=None,
        positive=re.compile(
            r"\bjavac\b|\bkotlinc\b|\bd8\b|\baapt2\b|\bapksigner\b|\bzipalign\b"
            r"|\bkeytool\b|\bdx\b\s", re.I),
    ),
    dict(
        tag="jadx",
        label="jadx",
        negate=None,
        positive=re.compile(r"\bjadx(?:-gui)?\b", re.I),
    ),
    dict(
        tag="apktool",
        label="apktool",
        negate=None,
        positive=re.compile(r"\bapktool\b", re.I),
    ),
    dict(
        tag="ghidra",
        label="Ghidra",
        negate=None,
        positive=re.compile(r"\bghidra\b|analyzeHeadless", re.I),
    ),
    dict(
        tag="radare2",
        label="radare2",
        negate=None,
        positive=re.compile(r"\bradare2\b|\br2\b|\brabin2\b|\br2pipe\b"),
    ),
    dict(
        tag="ida",
        label="IDA Pro or IDA Free",
        negate=None,
        # IDA's own command surface, not the two letters: the headless drivers,
        # the Python API, and the FLIRT/type-library tools that ship with it.
        positive=re.compile(
            r"\bIDA\s+(?:Pro|Free|View)\b|\bidapython\b|\bidaapi\b|\bidautils\b"
            r"|\bidat?6?4?\s+-[A-Za-z]|\bsigmake\b|\bpelf\b|\btilib\b"
            r"|Hex-Rays|\.i64\b", re.I),
    ),
    dict(
        tag="mobsf",
        label="MobSF",
        negate=None,
        positive=re.compile(r"\bmobsf\b", re.I),
    ),
    dict(
        tag="proxy",
        label="an intercepting proxy (Burp, mitmproxy, ZAP)",
        negate=None,
        positive=re.compile(r"\bburp\b|\bmitmproxy\b|\bmitmdump\b|\bOWASP ZAP\b", re.I),
    ),
    dict(
        tag="xposed",
        label="Xposed or LSPosed",
        negate=None,
        positive=re.compile(r"\bxposed\b|\blsposed\b|\bedxposed\b|XposedBridge", re.I),
    ),
    dict(
        tag="drozer",
        label="drozer",
        negate=None,
        positive=re.compile(r"\bdrozer\b", re.I),
    ),
    dict(
        tag="aosp",
        label="a local AOSP checkout or AOSP source browsing",
        negate=None,
        positive=re.compile(
            r"\brepo\s+init\b|\brepo\s+sync\b|\bcs\.android\.com\b|\blunch\b\s"
            r"|\bsource\s+build/envsetup\.sh\b", re.I),
    ),
    dict(
        tag="python",
        label="Python 3 on the host",
        negate=None,
        positive=re.compile(r"\bpython3?\b\s+-?\w|\bpip3?\s+install\b", re.I),
    ),
    dict(
        tag="docker",
        label="Docker",
        negate=None,
        positive=re.compile(r"\bdocker\s+(?:run|build|compose|pull)\b", re.I),
    ),
    dict(
        tag="physical",
        label="a physical device (an emulator cannot answer this honestly)",
        negate=None,
        # In a command: flashing, or a TEE/StrongBox API an AVD emulates in
        # software and therefore answers wrongly.
        positive=re.compile(
            r"\bfastboot\s+(?:flash|oem|unlock|erase)\b|StrongBox"
            r"|isInsideSecureHardware|SECURITY_LEVEL_STRONGBOX"
            r"|SECURITY_LEVEL_TRUSTED_ENVIRONMENT", re.I),
        # In prose: the lab saying so itself. Scoped tightly -- "on a real
        # device" as a passing aside is not a requirement.
        also_any=re.compile(
            r"(?:requires?|needs?|must\s+(?:use|be))\s+a?\s*(?:real|physical)\s+"
            r"(?:device|phone|handset)"
            r"|(?:will\s+not|cannot|can't|does\s+not)\s+work\s+on\s+an?\s+emulator"
            r"|not\s+(?:possible|available|meaningful)\s+on\s+an?\s+emulator"
            r"|an?\s+emulator\s+cannot\s+answer", re.I),
    ),
]

# Curated, and the second of only two hand-written data blocks in this file.
#
# A chapter about a tool does not always print that tool's command line -- three
# of 58-IDA's four labs drive IDA through its GUI and never type `idat`, so
# derivation alone reported 2 of 4. Refusing to fix that would be dishonest in
# the other direction: a reader filtering on `ida` would be told those labs do
# not need IDA, which is false. So a lab inherits its chapter's tool, with the
# evidence line saying exactly that, and the derivation is still shown when it
# fires independently.
#
# Keyed by chapter NUMBER, so renaming a directory cannot break it.
CHAPTER_IMPLIED_TOOLS = {
    "53": ["frida"],
    "54": ["objection", "frida"],
    "55": ["mobsf"],
    "56": ["jadx"],
    "57": ["ghidra"],
    "58": ["ida"],
    "59": ["radare2"],
    "62": ["root"],
    "63": ["xposed", "root"],
    "64": ["xposed", "root"],
}

# A tool named in a line like "if you have apktool" or "optional: Ghidra" is not
# a requirement. Matches on such lines are SKIPPED and the search continues, so
# a lab that uses a tool optionally in one place and necessarily in another is
# still tagged. Found because Lab 02 of this chapter was tagged `apktool` on the
# strength of the line "if you have apktool, which decodes resources as well".
OPTIONAL_LINE_RE = re.compile(
    r"\bif\s+you\s+have\b|\boptional(?:ly)?\b|\bif\s+available\b"
    r"|\bnot\s+required\b|\bnot\s+needed\b|\bwhere\s+available\b", re.I)

# A lab that says "No root, no Frida, no proxy" in its own header is stating a
# contract, and the header outranks any later mention. Without this, the header
# sentence ITSELF matched the positive pattern and raised the very tag it was
# denying -- which is what happened to Lab 02 of this chapter.
NEGATE_HEAD = {
    "frida": re.compile(r"no\s+frida|without\s+frida|frida\s+(?:is\s+)?not\s+"
                        r"(?:required|needed|used)", re.I),
    "proxy": re.compile(r"no\s+proxy|without\s+(?:a\s+)?(?:proxy|burp)"
                        r"|no\s+burp", re.I),
    "objection": re.compile(r"no\s+objection|without\s+objection", re.I),
    "ndk": re.compile(r"no\s+ndk|without\s+(?:an?\s+)?ndk", re.I),
    "xposed": re.compile(r"no\s+(?:xposed|lsposed)|without\s+(?:xposed|lsposed)", re.I),
}

# `device` and `no-device` are not rules; they are computed from whether the lab
# ever speaks to a device at all. See derive().
ADB_RE = re.compile(r"^\s*(?:#\s*)?(?:\$\s*)?adb\b|`adb\b|\badb\s+(?:shell|push|pull|install|logcat|devices|forward|reverse|root)\b")

# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


def read_utf8(path):
    """Strict UTF-8. Raises on invalid bytes rather than replacing them, so an
    encoding accident is loud instead of silent. A BOM is reported, not
    tolerated silently -- the repository standard is BOM-less."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        sys.stderr.write("warning: BOM in %s\n" % path)
        raw = raw[3:]
    return raw.decode("utf-8")


def header_block(text):
    """The lab's self-declared contract: everything before the first horizontal
    rule, capped at 60 lines. Every lab in the repository puts its difficulty,
    time and prerequisites here."""
    lines = text.split("\n")
    for i, line in enumerate(lines[:60]):
        if i > 2 and re.match(r"^\s*---\s*$", line):
            return "\n".join(lines[:i])
    return "\n".join(lines[:60])


def first_match(regexes, text):
    for rx in regexes:
        m = rx.search(text)
        if m:
            return m.group(1).strip()
    return None


def band_of(raw, filename, title):
    """Normalise a free-text difficulty into one of the four bands. The filename
    and title are consulted too, because seven labs name themselves `ctf-...`
    without writing CTF in the difficulty line."""
    haystack = " ".join(x for x in (raw or "", filename, title or "") if x)
    for rx, band in BAND_PATTERNS:
        if rx.search(haystack):
            return band
    return None


def evidence_line(text, match):
    """The single source line a regex matched, trimmed. This is what makes a tag
    auditable: the index can be asked WHY, and answers with the sentence."""
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    if end < 0:
        end = len(text)
    line = text[start:end].strip()
    return (line[:157] + "...") if len(line) > 160 else line


def code_text(text):
    """Everything inside fenced code blocks, concatenated. This is where a lab
    demonstrates what it needs, as opposed to where it discusses it."""
    return "\n".join(m.group(1) for m in FENCE_RE.finditer(text))


def _first_real_match(rx, src):
    """First match whose own line is not an optional/negated mention.

    Iterating rather than taking `.search()` matters: a lab may name a tool
    optionally in one place and necessarily in another, and only the second is
    a requirement. Returns None if every match sits on a skippable line.
    """
    for m in rx.finditer(src):
        if not OPTIONAL_LINE_RE.search(evidence_line(src, m)):
            return m
    return None


def _search_scoped(rx, head, code, text):
    """Header first, then commands. Returns (match, source_text) or (None, None).
    Header wins because that is where a lab states its own contract."""
    m = _first_real_match(rx, head)
    if m:
        return m, head
    m = _first_real_match(rx, code)
    if m:
        return m, code
    return None, None


def derive(text, head, code):
    """Return {tag: evidence_line}. Negations win outright. Positives are scoped
    to the header block and fenced code blocks, so a tool merely discussed in
    prose does not become a requirement."""
    tags = {}

    for rule in RULES:
        # A denial in the header block is a contract and outranks everything.
        head_neg = NEGATE_HEAD.get(rule["tag"])
        if head_neg is not None:
            m = head_neg.search(head)
            if m:
                tags["no-" + rule["tag"]] = evidence_line(head, m)
                continue

        neg = rule.get("negate")
        if neg is not None:
            m = neg.search(head)
            src = head
            if not m:
                m = neg.search(text)
                src = text
            if m:
                tags["no-" + rule["tag"]] = evidence_line(src, m)
                continue

        m, src = _search_scoped(rule["positive"], head, code, text)
        if m is None and rule.get("also_any") is not None:
            m = rule["also_any"].search(text)
            src = text if m else None
        if m is not None:
            tags[rule["tag"]] = evidence_line(src, m)

    m = ADB_RE.search(text)
    if m:
        tags["device"] = evidence_line(text, m)
    else:
        tags["no-device"] = "no adb invocation anywhere in the file"
    return tags


def parse_lab(repo_root, chapter_dir, filename):
    path = os.path.join(repo_root, chapter_dir, "labs", filename)
    text = read_utf8(path)
    head = header_block(text)

    title_m = TITLE_RE.search(text)
    title = title_m.group(1).strip() if title_m else filename
    title = re.sub(r"\s+", " ", title)

    raw_diff = first_match(DIFF_RES, head) or first_match(DIFF_RES, text)
    if raw_diff:
        raw_diff = re.sub(r"\s+", " ", raw_diff).strip(" .*|")
    raw_time = first_match(TIME_RES, head) or first_match(TIME_RES, text)
    if raw_time:
        raw_time = re.sub(r"\s+", " ", raw_time).strip(" .*|")

    band = band_of(raw_diff, filename, title)
    tags = derive(text, head, code_text(text))

    number = CHAPTER_DIR_RE.match(chapter_dir).group(1)
    for tag in CHAPTER_IMPLIED_TOOLS.get(number, []):
        if tag not in tags and ("no-" + tag) not in tags:
            tags[tag] = "implied by chapter %s; the lab does not print the command" % number

    return {
        "chapter": chapter_dir,
        "chapter_number": CHAPTER_DIR_RE.match(chapter_dir).group(1),
        "chapter_title": chapter_dir.split("-", 1)[1].replace("-", " "),
        "file": filename,
        "relpath": "%s/labs/%s" % (chapter_dir, filename),
        "title": title,
        "difficulty_raw": raw_diff,
        "difficulty": band,
        "time": raw_time,
        "lines": text.count("\n") + 1,
        "has_objective": bool(OBJECTIVE_RE.search(text)),
        "is_ctf": band == "CTF" or "ctf" in filename.lower(),
        "is_self": chapter_dir == SELF,
        "tags": tags,
    }


def collect(repo_root):
    labs = []
    for entry in sorted(os.listdir(repo_root)):
        if not CHAPTER_DIR_RE.match(entry):
            continue
        labs_dir = os.path.join(repo_root, entry, "labs")
        if not os.path.isdir(labs_dir):
            continue
        for name in sorted(os.listdir(labs_dir)):
            if not name.lower().endswith(".md"):
                continue
            labs.append(parse_lab(repo_root, entry, name))
    return labs


# --------------------------------------------------------------------------- #
# Link emission -- the ONLY two functions that know the output depth
# --------------------------------------------------------------------------- #

# Generated files land in 73-Labs/references/. From there:
#   repo root        is  ../../
#   this chapter     is  ../
DEPTH_TO_ROOT = "../../"
DEPTH_TO_SELF = "../"


def link_to_repo(relpath):
    """A path relative to the REPOSITORY ROOT, e.g. '53-Frida/labs/lab-01.md'."""
    return DEPTH_TO_ROOT + relpath


def link_to_chapter73(relpath):
    """A path relative to 73-Labs, e.g. 'scripts/build-lab-index.py'."""
    return DEPTH_TO_SELF + relpath


def emitted_links(labs):
    """Every link this generator can emit, as (repo-root-relative) targets. Used
    by --verify-links. If you add an emit site, add it here too."""
    out = set()
    for lab in labs:
        out.add(("repo", lab["relpath"]))
        out.add(("repo", "%s/README.md" % lab["chapter"]))
    out.add(("self", "scripts/build-lab-index.py"))
    out.add(("self", "scripts/lab-env-probe.py"))
    out.add(("self", "scripts/lab-doctor.sh"))
    out.add(("self", "README.md"))
    for spec in PATHS.values():
        for step in spec["steps"]:
            out.add(("repo", "%s/README.md" % step["chapter"]))
    return sorted(out)


# --------------------------------------------------------------------------- #
# Curation -- the only hand-written data in this file
#
# Learning paths. Keyed by chapter NUMBER so renaming a directory cannot break
# them. Each step names a chapter and says what the reader is there to get; the
# labs themselves are filled in mechanically from the index, so a path never
# names a lab that has been renamed or deleted.
# --------------------------------------------------------------------------- #

PATHS = {
    "two-weeks-no-android": {
        "goal": "Two weeks, no Android background, no prior security work.",
        "budget": "10 working days, 3-4 hours a day.",
        "rule": "Do not skip a step because the topic sounds familiar. Every step "
                "is a prerequisite of the next, and the first four exist to make "
                "the vocabulary of the rest survivable.",
        "bands": ["Beginner", "Intermediate"],
        "steps": [
            {"chapter": "00-Introduction", "for": "The workstation, and what the job is"},
            {"chapter": "02-Linux-Basics", "for": "Processes, users, permissions, a shell"},
            {"chapter": "06-Android-Architecture", "for": "What the layers are"},
            {"chapter": "10-APK-Internals", "for": "What is actually inside the file"},
            {"chapter": "32-Manifest", "for": "The attack surface declaration"},
            {"chapter": "21-App-Sandbox", "for": "Why one app cannot read another"},
            {"chapter": "23-Permissions", "for": "The model everything else references"},
            {"chapter": "26-Intent", "for": "The first exploitable primitive"},
            {"chapter": "27-ContentProviders", "for": "The second, and the easiest to find"},
            {"chapter": "33-Storage", "for": "Where the data actually is"},
            {"chapter": "60-ADB", "for": "The only channel to the device"},
            {"chapter": "52-StaticAnalysis", "for": "Reading before running"},
            {"chapter": "51-DynamicAnalysis", "for": "Running before concluding"},
            {"chapter": "71-OWASP-Mobile", "for": "The vocabulary a report is written in"},
        ],
    },
    "interview-ready": {
        "goal": "Interview-ready in the shortest defensible time.",
        "budget": "3 weeks, evenings.",
        "rule": "Depth beats breadth here. One mechanism you can trace to AOSP "
                "outranks nine you can name. Pair every lab with the matching "
                "chapter's section 10, and read 75-InterviewQuestions first, not last.",
        "bands": ["Intermediate", "Advanced"],
        "steps": [
            {"chapter": "75-InterviewQuestions", "for": "What each round measures"},
            {"chapter": "10-APK-Internals", "for": "Asked in every screen"},
            {"chapter": "12-DEX-Internals", "for": "The follow-up to the above"},
            {"chapter": "21-App-Sandbox", "for": "The uid story, told correctly"},
            {"chapter": "25-Binder", "for": "The one mechanism seniors are pushed on"},
            {"chapter": "26-Intent", "for": "The confused-deputy question"},
            {"chapter": "27-ContentProviders", "for": "The path-traversal question"},
            {"chapter": "34-Cryptography", "for": "The 'ECB is fine here' trap"},
            {"chapter": "36-CertificatePinning", "for": "Bypass without hand-waving"},
            {"chapter": "37-RootDetection", "for": "The classic probe question"},
            {"chapter": "49-KeyStore", "for": "Where a staff answer separates"},
            {"chapter": "53-Frida", "for": "The live exercise tool"},
            {"chapter": "67-BypassingProtections", "for": "Composing the above"},
            {"chapter": "72-RealWorldFindings", "for": "Severity under pushback"},
        ],
    },
    "emulator-only": {
        "goal": "An emulator and nothing else. No phone, no bootloader, no TEE.",
        "budget": "Open-ended.",
        "rule": "The index tag `physical` marks labs an emulator genuinely cannot "
                "answer -- hardware-backed key attestation, bootloader state, TEE "
                "behaviour. Those are not 'harder on an emulator', they are "
                "unanswerable there, and attempting them teaches the wrong answer. "
                "Read the chapter and skip the lab.",
        "bands": ["Beginner", "Intermediate", "Advanced"],
        "steps": [
            {"chapter": "06-Android-Architecture", "for": "Orientation"},
            {"chapter": "60-ADB", "for": "Everything else runs through this"},
            {"chapter": "10-APK-Internals", "for": "Host-side, no device needed"},
            {"chapter": "32-Manifest", "for": "Host-side"},
            {"chapter": "26-Intent", "for": "Fully reproducible on an AVD"},
            {"chapter": "27-ContentProviders", "for": "Fully reproducible on an AVD"},
            {"chapter": "29-BroadcastReceivers", "for": "Fully reproducible on an AVD"},
            {"chapter": "30-Activities", "for": "Fully reproducible on an AVD"},
            {"chapter": "22-SELinux", "for": "The AVD is Enforcing; this is honest here"},
            {"chapter": "39-EmulatorDetection", "for": "The one chapter the AVD is the ideal target for"},
            {"chapter": "52-StaticAnalysis", "for": "Host-side"},
            {"chapter": "56-JADX", "for": "Host-side"},
        ],
    },
    "native-re": {
        "goal": "The native / reverse-engineering track.",
        "budget": "4-6 weeks. This is the longest path in the repository.",
        "rule": "Do not start at Ghidra. The tool chapters are worthless until "
                "you can read what they are showing you, which is what 15, 16, 18 "
                "and 19 are for. An NDK is required from step three onward.",
        "bands": ["Intermediate", "Advanced", "CTF"],
        "steps": [
            {"chapter": "01-Computer-Science-Basics", "for": "Bytes, endianness, pointers"},
            {"chapter": "15-Native-Code", "for": "What a .so is and how it is loaded"},
            {"chapter": "16-JNI", "for": "The boundary every hook crosses"},
            {"chapter": "18-ARM", "for": "Reading the instructions"},
            {"chapter": "19-Memory", "for": "Layout, mappings, protections"},
            {"chapter": "12-DEX-Internals", "for": "The managed side, for contrast"},
            {"chapter": "17-Libraries", "for": "What ships in a real app"},
            {"chapter": "57-Ghidra", "for": "First decompiler"},
            {"chapter": "59-radare2", "for": "Scriptable second opinion"},
            {"chapter": "58-IDA", "for": "Third opinion, where available"},
            {"chapter": "40-Obfuscation", "for": "What was done to the code"},
            {"chapter": "65-Hooking", "for": "Changing native behaviour"},
            {"chapter": "68-ReverseEngineering", "for": "Method, not tools"},
            {"chapter": "70-VulnerabilityResearch", "for": "Where it leads"},
        ],
    },
    "no-device-at-all": {
        "goal": "No device, no emulator. A laptop on a train.",
        "budget": "A week of commutes.",
        "rule": "The index computes this set rather than guessing it: a lab is "
                "here only if it contains no adb invocation anywhere in the file. "
                "That is a strict test and it under-counts slightly -- a few labs "
                "have an optional device section -- but it never over-promises.",
        "bands": ["Beginner", "Intermediate", "Advanced"],
        "steps": [
            {"chapter": "01-Computer-Science-Basics", "for": "Pure host work"},
            {"chapter": "03-Programming-Fundamentals", "for": "Pure host work"},
            {"chapter": "04-Java", "for": "Compiles locally"},
            {"chapter": "05-Kotlin", "for": "Compiles locally"},
            {"chapter": "10-APK-Internals", "for": "An APK is a file"},
            {"chapter": "12-DEX-Internals", "for": "A DEX is a file"},
            {"chapter": "32-Manifest", "for": "XML is a file"},
            {"chapter": "41-ProGuard", "for": "Build-time only"},
            {"chapter": "42-R8", "for": "Build-time only"},
            {"chapter": "56-JADX", "for": "Host decompiler"},
            {"chapter": "71-OWASP-Mobile", "for": "Reading and writing"},
            {"chapter": "75-InterviewQuestions", "for": "Reading and writing"},
        ],
    },
}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

BANNER = """<!-- GENERATED FILE. Do not edit by hand.
     Rebuild with:  python3 -B scripts/build-lab-index.py
     Source: every NN-Chapter/labs/*.md in this repository.
     Link depth: this file lives two levels below the repo root, so chapter
     links are ../../NN-Chapter/... -- see the script header. -->
"""


def esc(text):
    """A markdown table cell cannot contain an unescaped pipe."""
    return (text or "").replace("|", "\\|")


def esc_evidence(text):
    """Render an evidence line inertly.

    An evidence line is a verbatim line lifted out of ANOTHER lab, and it
    frequently contains markdown of its own -- backticks, and worse, links that
    are relative to THAT lab's directory. Pasted into a file in references/,
    such a link resolves against the wrong directory and becomes a broken link
    this chapter did not write and cannot fix.

    A repository-wide link resolution caught 21 of these. It is the same defect
    class as the relative-depth bug this whole generator is careful about,
    arriving through a different door: **content copied from one directory into
    another carries that directory's assumptions with it.**

    So backticks become apostrophes -- a stray backtick otherwise closes the
    surrounding code span early and exposes the rest of the line as live
    markdown -- and the link syntax `](` is broken apart so nothing is a link.
    """
    return ((text or "")
            .replace("`", "'")
            .replace("](", "] (")
            .replace("|", "\\|"))


# Command shapes that the repository's linter flags as errors. An evidence line
# quoting one of them is quoting ANOTHER chapter's prose verbatim, which this
# chapter must not silently rewrite and cannot fix at source. The row therefore
# carries a NAMED suppression marker, rendered as an HTML comment so a reader
# never sees it.
#
# Named, never bare: a bare `lint:allow` suppresses every rule on the line,
# including ones nobody adjudicated. That is the same "excused category" failure
# that let a forward-reference bucket hide 1,512 broken links in this repository.
LINT_TRIGGERS = re.compile(r"adb\s+(?:-[des]\s+\S+\s+)?shell\s+su\s+-c\b")
LINT_MARKER = ("<!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- verbatim evidence "
               "quoted from another chapter's lab; not a command this file runs -->")


def lint_marker_for(evidence):
    """Return a suppression marker if this evidence line would trip the linter."""
    return (" " + LINT_MARKER) if LINT_TRIGGERS.search(evidence or "") else ""


def tagline(lab, interesting=None):
    """Render a lab's derived tags as a short, sorted, human string."""
    interesting = interesting or (
        "root", "no-root", "no-device", "frida", "ndk", "jdk", "proxy",
        "physical", "jadx", "ghidra", "radare2", "ida", "mobsf", "objection",
        "apktool", "xposed", "drozer", "aosp", "docker")
    present = [t for t in interesting if t in lab["tags"]]
    return ", ".join("`%s`" % t for t in present) if present else "-"


def render_by_chapter(labs):
    out = [BANNER, "# Lab index — by chapter", ""]
    out.append(_preamble(labs))
    out.append("")
    current = None
    for lab in labs:
        if lab["chapter"] != current:
            current = lab["chapter"]
            out.append("## %s — %s" % (lab["chapter_number"], lab["chapter_title"]))
            out.append("")
            out.append("Chapter: [%s](%s)"
                       % (lab["chapter"], link_to_repo("%s/README.md" % lab["chapter"])))
            out.append("")
            out.append("| Lab | Band | Time | Lines | Requires |")
            out.append("|---|---|---|---:|---|")
        out.append("| [%s](%s) | %s | %s | %d | %s |" % (
            esc(lab["title"]), link_to_repo(lab["relpath"]),
            lab["difficulty"] or "unstated",
            esc(lab["time"] or "-"), lab["lines"], tagline(lab)))
        if lab is labs[-1] or labs[labs.index(lab) + 1]["chapter"] != current:
            out.append("")
    return "\n".join(out) + "\n"


def render_by_difficulty(labs):
    out = [BANNER, "# Lab index — by difficulty band", ""]
    out.append(_preamble(labs))
    out.append("")
    out.append("Bands are normalised from the lab's own header by the rules in "
               "[`build-lab-index.py`](%s). A lab written "
               "\"Beginner to Intermediate\" lands in **Intermediate**: the band "
               "is the level you need to *finish*, not to start."
               % link_to_chapter73("scripts/build-lab-index.py"))
    out.append("")
    for band in BANDS + [None]:
        rows = [l for l in labs if l["difficulty"] == band]
        if not rows:
            continue
        name = band or "Unstated (the lab does not declare a difficulty)"
        out.append("## %s (%d)" % (name, len(rows)))
        out.append("")
        out.append("| Ch | Lab | Declared as | Time | Requires |")
        out.append("|---|---|---|---|---|")
        for lab in rows:
            out.append("| %s | [%s](%s) | %s | %s | %s |" % (
                lab["chapter_number"], esc(lab["title"]),
                link_to_repo(lab["relpath"]),
                esc(lab["difficulty_raw"] or "-"), esc(lab["time"] or "-"),
                tagline(lab)))
        out.append("")
    return "\n".join(out) + "\n"


def render_by_requirement(labs):
    out = [BANNER, "# Lab index — by what your setup must have", ""]
    out.append(_preamble(labs))
    out.append("")
    out.append("Every tag below is **derived from the lab text**, not assigned by "
               "hand. Ask the generator why any single lab carries a tag:")
    out.append("")
    out.append("```bash")
    out.append("# host, from 73-Labs/")
    out.append("python3 -B scripts/build-lab-index.py --why 53-Frida/labs/lab-01-first-contact.md")
    out.append("```")
    out.append("")
    out.append("`no-root` means the lab **states in its own header** that root is "
               "not needed. Absence of both `root` and `no-root` means the lab "
               "never says — treat that as unknown, not as \"no root needed\".")
    out.append("")

    order = ["no-device", "no-root", "root", "physical", "frida", "objection",
             "ndk", "jdk", "jadx", "apktool", "ghidra", "radare2", "ida",
             "mobsf", "proxy", "xposed", "drozer", "aosp", "docker", "python",
             "device"]
    labels = {r["tag"]: r["label"] for r in RULES}
    labels.update({
        "device": "any Android device or emulator reachable over adb",
        "no-device": "nothing but a laptop",
        "no-root": "explicitly states root is NOT needed",
    })

    out.append("| Tag | Meaning | Labs |")
    out.append("|---|---|---:|")
    for tag in order:
        n = len([l for l in labs if tag in l["tags"]])
        out.append("| `%s` | %s | %d |" % (tag, labels.get(tag, tag), n))
    out.append("")

    for tag in order:
        rows = [l for l in labs if tag in l["tags"]]
        if not rows:
            continue
        out.append("## `%s` — %s (%d)" % (tag, labels.get(tag, tag), len(rows)))
        out.append("")
        out.append("| Ch | Lab | Band | Evidence in the lab |")
        out.append("|---|---|---|---|")
        for lab in rows:
            evidence = lab["tags"][tag]
            out.append("| %s | [%s](%s) | %s | `%s`%s |" % (
                lab["chapter_number"], esc(lab["title"]),
                link_to_repo(lab["relpath"]), lab["difficulty"] or "unstated",
                esc_evidence(evidence)[:120], lint_marker_for(evidence)))
        out.append("")
    return "\n".join(out) + "\n"


def render_paths(labs):
    by_chapter = {}
    for lab in labs:
        by_chapter.setdefault(lab["chapter"], []).append(lab)

    out = [BANNER, "# Learning paths — ordered routes through the repository's labs", ""]
    out.append(_preamble(labs))
    out.append("")
    out.append("The repository has more labs than anyone will do, in reading "
               "order rather than in learning order. Each path below is an "
               "**ordered** route with a stated goal. The chapter sequence is "
               "curated; the lab list under each step is generated, so a path "
               "can never name a lab that has been renamed or deleted.")
    out.append("")
    out.append("| Path | Goal | Budget | Labs in scope |")
    out.append("|---|---|---|---:|")
    for key, spec in PATHS.items():
        n = 0
        for step in spec["steps"]:
            n += len([l for l in by_chapter.get(step["chapter"], [])
                      if l["difficulty"] in spec["bands"] or l["difficulty"] is None])
        out.append("| [`%s`](#%s) | %s | %s | %d |"
                   % (key, key, esc(spec["goal"]), esc(spec["budget"]), n))
    out.append("")

    for key, spec in PATHS.items():
        out.append("## %s" % key)
        out.append("")
        out.append("**Goal.** %s" % spec["goal"])
        out.append("")
        out.append("**Budget.** %s" % spec["budget"])
        out.append("")
        out.append("**Rule for this path.** %s" % spec["rule"])
        out.append("")
        out.append("**Bands in scope:** %s." % ", ".join(spec["bands"]))
        out.append("")
        for i, step in enumerate(spec["steps"], 1):
            chapter = step["chapter"]
            rows = [l for l in by_chapter.get(chapter, [])
                    if l["difficulty"] in spec["bands"] or l["difficulty"] is None]
            out.append("### Step %d — [%s](%s)"
                       % (i, chapter, link_to_repo("%s/README.md" % chapter)))
            out.append("")
            out.append("*You are here for:* %s" % step["for"])
            out.append("")
            if not rows:
                out.append("No lab in this chapter falls in this path's bands. "
                           "Read the chapter; do its labs later.")
                out.append("")
                continue
            out.append("| Lab | Band | Time | Requires |")
            out.append("|---|---|---|---|")
            for lab in rows:
                out.append("| [%s](%s) | %s | %s | %s |" % (
                    esc(lab["title"]), link_to_repo(lab["relpath"]),
                    lab["difficulty"] or "unstated", esc(lab["time"] or "-"),
                    tagline(lab)))
            out.append("")
    return "\n".join(out) + "\n"


def _preamble(labs):
    ctf = len([l for l in labs if l["is_ctf"]])
    chapters = len(set(l["chapter"] for l in labs))
    return ("**%d labs across %d chapters, %d of them CTFs.** Built mechanically by "
            "[`scripts/build-lab-index.py`](%s); do not edit this file."
            % (len(labs), chapters, ctf,
               link_to_chapter73("scripts/build-lab-index.py")))


RENDERERS = {
    "chapter": render_by_chapter,
    "difficulty": render_by_difficulty,
    "requirement": render_by_requirement,
    "path": render_paths,
}

DEFAULT_OUT = {
    "chapter": "lab-index-by-chapter.md",
    "difficulty": "lab-index-by-difficulty.md",
    "requirement": "lab-index-by-requirement.md",
    "path": "learning-paths.md",
}


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def write(path, text):
    if path == "-":
        # Write BYTES, not text. A Windows console defaults to cp1252 and
        # sys.stdout.write() raises UnicodeEncodeError on the em-dashes in these
        # lab titles -- which is how `--format json --out -` failed the first
        # time it was piped into another program.
        sys.stdout.flush()
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.flush()
        return
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # BOM-less UTF-8, LF endings: the repository standard.
    with open(path, "wb") as fh:
        fh.write(text.encode("utf-8"))
    sys.stderr.write("wrote %s (%d bytes)\n" % (path, len(text.encode("utf-8"))))


def verify_links(repo_root, chapter_root, labs):
    """Resolve every link the generator can emit. This is the depth check, and
    it is the reason the 75-InterviewQuestions defect cannot recur here: it
    resolves paths against the filesystem instead of trusting the author's eye."""
    refs_dir = os.path.join(chapter_root, "references")
    bad = 0
    total = 0
    for kind, rel in emitted_links(labs):
        link = link_to_repo(rel) if kind == "repo" else link_to_chapter73(rel)
        resolved = os.path.normpath(os.path.join(refs_dir, link))
        total += 1
        if not os.path.exists(resolved):
            bad += 1
            print("BROKEN: from 73-Labs/references/ -> %s   (resolved: %s)"
                  % (link, resolved))
    print("links=%d broken=%d" % (total, bad))
    return 1 if bad else 0


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    chapter_root = os.path.abspath(os.path.join(here, ".."))
    default_root = os.path.abspath(os.path.join(here, "..", ".."))

    ap = argparse.ArgumentParser(
        description="Build the repository-wide lab index from every chapter's labs/.")
    ap.add_argument("--root", default=default_root,
                    help="repository root (default: two levels above this script)")
    ap.add_argument("--by", default=None,
                    choices=sorted(RENDERERS),
                    help="which grouping to render (default: all four, to files)")
    ap.add_argument("--format", default="md", choices=["md", "json", "csv"])
    ap.add_argument("--out", default=None, help="output path, or '-' for stdout")
    ap.add_argument("--stats", action="store_true",
                    help="print counts and write nothing")
    ap.add_argument("--why", metavar="RELPATH",
                    help="explain one lab's derived tags, with evidence lines")
    ap.add_argument("--verify-links", action="store_true",
                    help="resolve every emitted link against the filesystem")
    args = ap.parse_args()

    labs = collect(args.root)
    if not labs:
        sys.stderr.write("error: no chapter labs/ directories found under %s\n"
                         % args.root)
        return 2

    if args.why:
        rel = args.why.replace("\\", "/")
        hit = [l for l in labs if l["relpath"] == rel or l["file"] == rel]
        if not hit:
            sys.stderr.write("error: no indexed lab matching %s\n" % rel)
            return 2
        for lab in hit:
            print("%s" % lab["relpath"])
            print("  title      : %s" % lab["title"])
            print("  difficulty : %s   (declared: %s)"
                  % (lab["difficulty"] or "unstated", lab["difficulty_raw"] or "-"))
            print("  time       : %s" % (lab["time"] or "-"))
            print("  lines      : %d" % lab["lines"])
            print("  tags:")
            for tag in sorted(lab["tags"]):
                print("    %-12s <- %s" % (tag, lab["tags"][tag]))
        return 0

    if args.verify_links:
        return verify_links(args.root, chapter_root, labs)

    if args.stats:
        print("%-34s %5s  %s" % ("chapter", "labs", "bands"))
        by_chapter = {}
        for lab in labs:
            by_chapter.setdefault(lab["chapter"], []).append(lab)
        for chapter in sorted(by_chapter):
            rows = by_chapter[chapter]
            bands = [b for b in BANDS
                     if any(l["difficulty"] == b for l in rows)]
            print("%-34s %5d  %s" % (chapter, len(rows), ", ".join(bands)))
        print("-" * 60)
        for band in BANDS:
            print("%-34s %5d" % (band, len([l for l in labs if l["difficulty"] == band])))
        print("%-34s %5d" % ("unstated",
                             len([l for l in labs if l["difficulty"] is None])))
        print("-" * 60)
        print("%-34s %5d" % ("TOTAL labs", len(labs)))
        print("%-34s %5d" % ("chapters with labs", len(by_chapter)))
        print("%-34s %5d" % ("CTF labs", len([l for l in labs if l["is_ctf"]])))
        print("-" * 60)
        for tag in ["no-device", "device", "root", "no-root", "physical",
                    "frida", "ndk", "jdk", "proxy", "jadx", "ghidra",
                    "radare2", "ida", "mobsf", "objection", "apktool",
                    "xposed", "drozer", "aosp", "docker"]:
            print("%-34s %5d" % (tag, len([l for l in labs if tag in l["tags"]])))
        return 0

    if args.format == "json":
        write(args.out or "-", json.dumps(labs, indent=2, ensure_ascii=False) + "\n")
        return 0

    if args.format == "csv":
        rows = ["chapter,file,difficulty,time,lines,ctf,tags"]
        for lab in labs:
            rows.append('%s,"%s","%s","%s",%d,%s,"%s"' % (
                lab["chapter"], lab["file"], lab["difficulty"] or "",
                (lab["time"] or "").replace('"', '""'), lab["lines"],
                "yes" if lab["is_ctf"] else "no",
                " ".join(sorted(lab["tags"]))))
        write(args.out or "-", "\n".join(rows) + "\n")
        return 0

    groupings = [args.by] if args.by else sorted(RENDERERS)
    for grouping in groupings:
        text = RENDERERS[grouping](labs)
        if args.out:
            write(args.out, text)
        else:
            write(os.path.join(chapter_root, "references", DEFAULT_OUT[grouping]), text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
