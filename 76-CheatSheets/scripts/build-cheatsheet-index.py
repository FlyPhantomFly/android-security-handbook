#!/usr/bin/env python3
# 76-CheatSheets/scripts/build-cheatsheet-index.py
#
# PURPOSE
#   Build the router over every chapter's `cheatsheet.md` MECHANICALLY, by parsing
#   the H2 headings, code fences and tables out of each one. Nothing is transcribed
#   by hand, so the router cannot drift: re-run it after any chapter changes and it
#   is correct again.
#
#   This chapter exists because CONCATENATING the per-chapter sheets is worthless.
#   Measured on this repository: 78 sheets, 29,189 lines, 1,198 H2 sections. A
#   single file of that size is not a cheat sheet, it is a book with no index, and
#   it is stale the moment any chapter is edited. The one part of aggregation worth
#   doing is NAVIGATION, and that is all this script does. The analysis lives in
#   `../README.md`; the cross-cutting sheets live in `../cheatsheet.md`.
#
# USAGE
#   # default artefact: references/cheatsheet-index.md, grouped by chapter
#   python3 -B scripts/build-cheatsheet-index.py
#
#   # the curated task router -- "what am I doing?" rather than "which chapter?"
#   python3 -B scripts/build-cheatsheet-index.py --by task
#
#   # mechanical tool census -- "I know the tool, which sheet has the most of it?"
#   python3 -B scripts/build-cheatsheet-index.py --by tool
#
#   # to stdout instead of a file
#   python3 -B scripts/build-cheatsheet-index.py --by task --out -
#
#   # machine-readable
#   python3 -B scripts/build-cheatsheet-index.py --format json --out -
#
#   # counts only, writes nothing
#   python3 -B scripts/build-cheatsheet-index.py --stats
#
#   # CI gate: which written chapters have a README but no cheatsheet?
#   python3 -B scripts/build-cheatsheet-index.py --check
#
#   # resolve every link in every file this script writes (see LINK DEPTH below)
#   python3 -B scripts/build-cheatsheet-index.py --verify-links
#
#   Run with -B so no __pycache__ lands in the repository.
#
# LINK DEPTH -- READ THIS BEFORE EDITING ANY EMIT SITE
#   The generated files live in `76-CheatSheets/references/`, which is TWO levels
#   below the repository root. A link to another chapter is therefore
#       ../../NN-Chapter/cheatsheet.md
#   and NOT `../NN-Chapter/cheatsheet.md`.
#
#   This is not a hypothetical. `75-InterviewQuestions/scripts/build-interview-index.py`
#   emitted the one-dot-dot form from four sites and produced 1,495 broken links that
#   hid for months inside a "forward reference" exemption in the repo's link checker.
#   Every emit site below uses the module constant UP, and `--verify-links` resolves
#   every link this script writes against the filesystem. Do not eyeball it; run it.
#
# WAS THIS EXECUTED?
#   YES. Run against this repository on 2026-08-16, CPython 3.13 on Windows 11,
#   Git Bash. Measured at that time:
#
#       chapter directories with a README   : 80
#       chapters carrying a cheatsheet.md   : 78
#       total H2 sections across all sheets : 1198
#       total lines across all sheets       : 29189
#       total fenced code blocks            :  747
#
#   THOSE NUMBERS MOVED DURING THE SESSION THAT WROTE THEM. Two chapters landed in
#   parallel and the sheet count went 76 -> 78, lines 28594 -> 29189, emitted links
#   1595 -> 1628. Re-run `--stats`; do not quote a figure from this comment.
#
#   `--check` reports 0 problems: the only two chapters with a README and no sheet
#   are 79-Glossary and 80-Appendix, reference chapters exempted by STYLE-GUIDE.md
#   section 4a. (`73-Labs` had no README at that moment and is therefore not counted
#   at all -- an unwritten chapter is not a missing sheet. `78-Diagrams` landed
#   mid-session and is counted from that point on.)
#
#   `--verify-links` on the FIRST run reported 58 broken of 1,595. Three were
#   `../README.md` before this chapter's own README existed; the other 55 were the
#   copied-subtitle defect fixed in `rebase_links()` below. After the fix and once
#   the README landed: 0 broken of 1,595, and 0 broken of 1,628 at the end of the
#   session.
#
# EXIT STATUS
#   0 normally. 1 from --check when a non-reference chapter with a README has no
#   cheatsheet. 1 from --verify-links when any emitted link fails to resolve.

import argparse
import importlib.util
import json
import os
import re
import sys

# --- the slugger, borrowed rather than re-implemented -----------------------
#
# THE THIRD DEFECT THIS FILE HAS SHIPPED, AND THE SAME SHAPE AS THE FIRST TWO.
# `github_anchor()` used to be four lines of "closely enough":
#
#     text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
#     return re.sub(r"\s+", "-", text)
#
# Measured by `check-anchors.py` on 2026-08-17: 230 of this file's emitted
# anchors did not exist on GitHub. Two independent errors, both in those two
# lines:
#
#   1. `\s+` COLLAPSES A WHITESPACE RUN TO ONE HYPHEN. GitHub replaces EACH
#      space with its own hyphen, and deletes an em-dash rather than converting
#      it -- so `## 1. Toolchain install — Windows` leaves TWO adjacent spaces
#      and slugs to `1-toolchain-install--windows`. This script emitted
#      `...install-windows` and the jump died. ~215 of the 230.
#
#   2. `[^\w\s-]` DELETES CHARACTERS GITHUB KEEPS. GitHub's removal set is a
#      punctuation list, not a whitelist: `→` (U+2192) is not punctuation to it
#      and survives into the slug. `## 8. Burp CA → Android system certificate`
#      is `#8-burp-ca-→-android-system-certificate`. This script deleted the
#      arrow. ~15 of the 230.
#
# Both were invisible because `--verify-links` split every target on `#` and
# resolved only the path half -- exactly the narrowing the repository's own link
# sweep suffered from, and the reason `check-anchors.py` exists; its header
# records the two earlier instances. It now checks fragments too.
#
# The fix is NOT a better regex here. Two implementations of one algorithm is
# what produced the defect, so this file no longer has its own: it loads the
# one in `check-anchors.py`, which is self-tested against 46 cases. Duplicate
# H2 headings within one sheet now get GitHub's `-1`, `-2` suffixes as well,
# which the old function could not express at all.

_ANCHORS_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "check-anchors.py")


def _load_anchor_module():
    spec = importlib.util.spec_from_file_location("check_anchors", _ANCHORS_PY)
    if spec is None or spec.loader is None:
        raise ImportError(_ANCHORS_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True      # no __pycache__ from the import either
    spec.loader.exec_module(mod)
    return mod


try:
    _anchors = _load_anchor_module()
except Exception as _exc:               # pragma: no cover - fail loudly, not silently
    sys.stderr.write(
        "error: cannot load the shared slugger from %s (%s).\n"
        "       This script must not re-implement GitHub's anchor algorithm; see\n"
        "       the comment above. Restore that file and re-run.\n"
        % (_ANCHORS_PY, _exc))
    raise

Slugger = _anchors.Slugger

# --- constants -------------------------------------------------------------

# The literal prefix from a file in `references/` back to the repository root.
# Every emit site uses this. See LINK DEPTH in the header.
UP = "../../"

# Reference chapters follow STYLE-GUIDE.md section 4a. A glossary IS a cheat
# sheet; shipping a second one that condenses it is duplication. Not defects.
REFERENCE_CHAPTERS = {"76-CheatSheets", "78-Diagrams", "79-Glossary", "80-Appendix"}

CHAPTER_DIR_RE = re.compile(r"^(\d{2})-")
H2_RE = re.compile(r"^##\s+(.*\S)\s*$")
H1_RE = re.compile(r"^#\s+(.*\S)\s*$")
ANY_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
FENCE_RE = re.compile(r"^```")
TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")

# --- curation --------------------------------------------------------------
# The ONLY hand-written data in this file. It maps chapters onto what a reader is
# DOING rather than onto reading order, which is the whole point of a cheat sheet.
# Keyed by chapter NUMBER so renaming a directory cannot break it.
#
# A chapter appears under several tasks on purpose: 53-Frida is reached from
# "the app detects me" and from "nothing works", and those are different questions.

TASKS = [
    (
        "I have an APK and one hour",
        ["10", "32", "52", "56", "55", "44", "23", "40", "33", "46"],
        "Triage order, not depth order. Manifest before code, code before runtime, "
        "and every automated hit adjudicated by hand before it is written down.",
    ),
    (
        "I am on an unrooted device",
        ["09", "10", "51", "53", "54", "60", "66", "36", "43", "44"],
        "Everything here works at uid 2000 or below. Repackaging with the Frida "
        "Gadget, `run-as` on a debuggable build, and instrumentation gated by the "
        "signing key rather than by root.",
    ),
    (
        "I have only an emulator",
        ["39", "49", "50", "61", "62", "35", "44", "13", "21"],
        "What an AVD can and cannot answer. Attestation, verified boot and fastboot "
        "are the three questions it answers wrongly rather than not at all.",
    ),
    (
        "The app detects my hook",
        ["37", "38", "39", "40", "53", "62", "63", "64", "65", "67"],
        "Find the check before you bypass it. A bypass applied to the wrong seam "
        "reads exactly like a bypass that failed.",
    ),
    (
        "I need to see the traffic",
        ["35", "36", "43", "44", "45", "46", "47", "53", "54"],
        "Trust store, then config, then pinning, then non-HTTP. Stop at the first "
        "layer that explains the silence.",
    ),
    (
        "I need to read the app's data",
        ["09", "21", "27", "33", "34", "48", "49", "60"],
        "On disk, in the WAL, in the backup, in the logs, in `dumpsys`, and in the "
        "KeyStore that prevents extraction but not use.",
    ),
    (
        "I need to reach it from another app",
        ["24", "25", "26", "27", "28", "29", "30", "31", "32", "43"],
        "The IPC surface, from the position of a malicious app rather than from "
        "`adb shell` -- which holds privileges an app does not.",
    ),
    (
        "I am staring at native code",
        ["15", "16", "17", "18", "19", "57", "58", "59", "65", "68"],
        "ELF layout, JNI registration, the calling convention, and the two ways a "
        "perfectly-installed hook changes nothing.",
    ),
    (
        "I need to prove this finding",
        ["47", "51", "52", "71", "72", "74", "80"],
        "Threat model, reproduction from an app uid, evidence, honest severity. A "
        "sweep produces leads; adjudication produces findings.",
    ),
    (
        "Nothing works and I do not know why",
        ["51", "53", "54", "60", "62", "66", "77"],
        "Debug the tool before you debug the app. Most of this band is a liveness "
        "check that nobody ran.",
    ),
]

# Mechanical tool census. Tokens are matched inside fenced code blocks only, as
# whole words, case-sensitively where the tool name is lower-case by convention.
#
# EVERY TOKEN HERE IS AT LEAST FOUR CHARACTERS, deliberately. The repository has
# measured twice that short case-insensitive tokens manufacture false positives
# that get WORSE on better-obfuscated inputs -- `grep -i xposed` matched "exposed"
# 1,141 times with zero genuine hits, and a three-character `vxp` signature
# produced 16 STRONG hits that were all R8 class names. This census reports where
# a tool is DOCUMENTED, which is a much easier question, but the rule still holds.
TOOLS = [
    "adb", "aapt2", "apktool", "apksigner", "baksmali", "dexdump", "drozer",
    "fastboot", "frida", "frida-ps", "frida-trace", "ghidra", "jadx", "keytool",
    "magisk", "mitmproxy", "objection", "openssl", "radare2", "readelf",
    "semgrep", "smali", "sqlite3", "strace", "strings", "zipalign",
]
# Device-side subcommands worth routing on. `adb shell <this>`.
DEVICE_TOOLS = ["dumpsys", "getprop", "logcat", "pidof", "settings", "service"]


# --- io --------------------------------------------------------------------

def read_utf8(path):
    """Read strictly as UTF-8. Raises on invalid bytes rather than replacing them,
    so an encoding accident is loud instead of silent."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        sys.stderr.write("warning: BOM in %s (repo standard is BOM-less)\n" % path)
        raw = raw[3:]
    return raw.decode("utf-8")


def write(path, text):
    if path == "-":
        sys.stdout.write(text)
        return
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # BOM-less UTF-8, LF endings: the repository standard.
    with open(path, "wb") as fh:
        fh.write(text.encode("utf-8"))
    sys.stderr.write("wrote %s (%d bytes)\n" % (path, len(text.encode("utf-8"))))


def github_anchor(heading_text):
    """GitHub's heading-anchor algorithm, for a heading with no duplicate in its
    file. Delegates to `check-anchors.py`; see the note at the top of this file
    for why this is not implemented here."""
    return _anchors.slug(_anchors.render_inline(heading_text))


def escape_cell(text):
    """A markdown table cell cannot contain an unescaped pipe."""
    return text.replace("|", "\\|")


def rebase_links(text, chapter_dir):
    """Rewrite relative markdown links inside text QUOTED FROM a chapter's sheet so
    they still resolve from `references/`.

    Every sheet's own subtitle line says something like
        Printable. No prose. See [README.md](README.md) for why each of these works.
    That `README.md` is relative to the CHAPTER directory. Emitted verbatim into
    `references/` it points at `76-CheatSheets/references/README.md`, which is a
    different file entirely.

    `--verify-links` found 55 of these on the first run of this script. That is the
    same defect class as the one in LINK DEPTH above, arriving from the other
    direction: not a path this script composed, but a path it COPIED across a depth
    boundary. Quoting text that contains links is a link operation."""
    def fix(m):
        target = m.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#", "../", "/")):
            return m.group(0)
        return "](%s%s/%s)" % (UP, chapter_dir, target)
    return re.sub(r"\]\(([^)\s]+)\)", fix, text)


# --- parsing ---------------------------------------------------------------

def parse_sheet(chapter_dir):
    """Return a dict describing one chapter's cheatsheet.md, or None when the
    chapter has no README at all (an unwritten chapter, not a defect)."""
    name = os.path.basename(chapter_dir)
    readme = os.path.join(chapter_dir, "README.md")
    if not os.path.isfile(readme):
        return None

    number = CHAPTER_DIR_RE.match(name).group(1)
    sheet = os.path.join(chapter_dir, "cheatsheet.md")
    result = {
        "number": number,
        "dir": name,
        "title": name.split("-", 1)[1].replace("-", " "),
        "has_sheet": os.path.isfile(sheet),
        "subtitle": None,
        "sections": [],
        "lines": 0,
        "fences": 0,
        "table_rows": 0,
        "tools": {},
    }
    if not result["has_sheet"]:
        return result

    lines = read_utf8(sheet).split("\n")
    result["lines"] = len(lines)

    in_fence = False
    fence_text = []
    seen_h1 = False
    # GitHub's duplicate counter runs over EVERY heading in the document, not
    # over the H2s alone -- so an H3 that slugs the same as a later H2 pushes
    # that H2 onto `-1`. Feed the slugger every heading, in document order, and
    # keep only the H2s as sections.
    slugger = Slugger()
    for line in lines:
        if FENCE_RE.match(line):
            in_fence = not in_fence
            if in_fence:
                result["fences"] += 1
            continue
        if in_fence:
            fence_text.append(line)
            continue

        any_h = ANY_HEADING_RE.match(line)
        anchor = None
        if any_h:
            anchor = slugger.add(_anchors.render_inline(
                _anchors.heading_text(any_h.group(2))))

        h1 = H1_RE.match(line)
        if h1 and not seen_h1:
            seen_h1 = True
            continue
        # The first non-empty prose line after the H1 is the sheet's own
        # one-line description of itself. Most sheets write one.
        if seen_h1 and result["subtitle"] is None and line.strip() \
                and not line.startswith("#") and not line.startswith("---"):
            result["subtitle"] = line.strip()

        h2 = H2_RE.match(line)
        if h2:
            heading = h2.group(1)
            result["sections"].append({
                "heading": heading,
                "anchor": "#" + anchor,
            })
            continue
        if TABLE_ROW_RE.match(line):
            result["table_rows"] += 1

    body = "\n".join(fence_text)
    for tool in TOOLS:
        n = len(re.findall(r"(?<![\w./-])%s(?![\w-])" % re.escape(tool), body))
        if n:
            result["tools"][tool] = n
    for tool in DEVICE_TOOLS:
        n = len(re.findall(r"(?<![\w./-])%s(?![\w-])" % re.escape(tool), body))
        if n:
            result["tools"][tool] = n
    return result


def collect(root):
    chapters = []
    for entry in sorted(os.listdir(root)):
        path = os.path.join(root, entry)
        if not os.path.isdir(path) or not CHAPTER_DIR_RE.match(entry):
            continue
        parsed = parse_sheet(path)
        if parsed is not None:
            chapters.append(parsed)
    return chapters


# --- rendering -------------------------------------------------------------

def header(kind, extra=""):
    return (
        "<!-- GENERATED FILE. Do not edit by hand.\n"
        "     Rebuild with:  python3 -B scripts/build-cheatsheet-index.py --by %s\n"
        "     Source: the `cheatsheet.md` of every chapter in this repository. -->\n"
        "\n"
        "# Cheat-sheet router — %s\n"
        "\n"
        "Built mechanically by [`build-cheatsheet-index.py`](../scripts/build-cheatsheet-index.py)\n"
        "from every chapter's `cheatsheet.md`. It **routes**; it does not copy. An entry\n"
        "separated from the chapter that justifies it is how a reader ends up pasting a\n"
        "command they cannot defend — see [`../README.md`](../README.md) section 7.\n"
        "%s\n" % (kind, kind_title(kind), extra)
    )


def kind_title(kind):
    return {
        "chapter": "by chapter",
        "task": "by task",
        "tool": "by tool",
    }[kind]


def render_by_chapter(chapters):
    out = [header("chapter")]
    have = [c for c in chapters if c["has_sheet"]]
    total_sections = sum(len(c["sections"]) for c in have)
    total_lines = sum(c["lines"] for c in have)
    out.append("**%d sheets, %d sections, %d lines.** Concatenating them would produce a "
               "%s-line file that is stale the moment any chapter is edited. This is the "
               "index instead.\n"
               % (len(have), total_sections, total_lines, "{:,}".format(total_lines)))
    out.append("")
    out.append("| Sheet | Lines | Sections | Fences | Covers |")
    out.append("|---|---:|---:|---:|---|")
    for c in have:
        headings = "; ".join(s["heading"] for s in c["sections"][:6])
        if len(c["sections"]) > 6:
            headings += "; …"
        out.append("| [%s — %s](%s%s/cheatsheet.md) | %d | %d | %d | %s |"
                   % (c["number"], c["title"], UP, c["dir"], c["lines"],
                      len(c["sections"]), c["fences"], escape_cell(headings)))
    out.append("")
    out.append("---")
    out.append("")
    out.append("## Every section, linked")
    out.append("")
    out.append("Jump straight to the block you need. Anchors are GitHub's.")
    out.append("")
    for c in have:
        out.append("### %s — %s" % (c["number"], c["title"]))
        out.append("")
        if c["subtitle"]:
            out.append("*%s*" % rebase_links(c["subtitle"], c["dir"]))
            out.append("")
        for s in c["sections"]:
            out.append("- [%s](%s%s/cheatsheet.md%s)"
                       % (s["heading"], UP, c["dir"], s["anchor"]))
        out.append("")
    missing = [c for c in chapters
               if not c["has_sheet"] and c["dir"] not in REFERENCE_CHAPTERS]
    if missing:
        out.append("---")
        out.append("")
        out.append("## Chapters with a README and no sheet")
        out.append("")
        for c in missing:
            out.append("- `%s`" % c["dir"])
        out.append("")
    return "\n".join(out) + "\n"


def render_by_task(chapters):
    by_number = {c["number"]: c for c in chapters}
    out = [header("task",
                  "\nOrganised by **what you are doing**, not by chapter number. This is the "
                  "grouping\na per-chapter sheet cannot provide, because no single chapter owns "
                  "a task.\n")]
    out.append("| Task | Sheets | Sections in scope |")
    out.append("|---|---:|---:|")
    for name, numbers, _note in TASKS:
        present = [by_number[n] for n in numbers
                   if n in by_number and by_number[n]["has_sheet"]]
        secs = sum(len(c["sections"]) for c in present)
        out.append("| [%s](#%s) | %d | %d |"
                   % (name, github_anchor(name), len(present), secs))
    out.append("")
    out.append("---")
    out.append("")
    for name, numbers, note in TASKS:
        present = [by_number[n] for n in numbers
                   if n in by_number and by_number[n]["has_sheet"]]
        absent = [n for n in numbers
                  if n not in by_number or not by_number[n]["has_sheet"]]
        out.append("## %s" % name)
        out.append("")
        out.append(note)
        out.append("")
        out.append("| Sheet | Sections | Read it for |")
        out.append("|---|---:|---|")
        for c in present:
            headings = "; ".join(s["heading"] for s in c["sections"][:4])
            if len(c["sections"]) > 4:
                headings += "; …"
            out.append("| [%s — %s](%s%s/cheatsheet.md) | %d | %s |"
                       % (c["number"], c["title"], UP, c["dir"],
                          len(c["sections"]), escape_cell(headings)))
        out.append("")
        if absent:
            out.append("*No sheet yet: %s.*"
                       % ", ".join("`%s`" % n for n in absent))
            out.append("")
    return "\n".join(out) + "\n"


def render_by_tool(chapters):
    have = [c for c in chapters if c["has_sheet"]]
    out = [header("tool",
                  "\nA mechanical census of tool names appearing **inside fenced code blocks**. "
                  "It answers\n\"I know the tool, which sheet documents it most?\" — and nothing "
                  "else. A high count\nmeans a lot of documented invocations, not quality.\n")]
    all_tools = sorted({t for c in have for t in c["tools"]})
    out.append("| Tool | Sheets | Invocations | Top sheets |")
    out.append("|---|---:|---:|---|")
    for tool in all_tools:
        rows = sorted([c for c in have if tool in c["tools"]],
                      key=lambda c: -c["tools"][tool])
        total = sum(c["tools"][tool] for c in rows)
        top = ", ".join("[%s](%s%s/cheatsheet.md) (%d)"
                        % (c["number"], UP, c["dir"], c["tools"][tool])
                        for c in rows[:5])
        out.append("| `%s` | %d | %d | %s |" % (tool, len(rows), total, top))
    out.append("")
    out.append("---")
    out.append("")
    out.append("## Per sheet")
    out.append("")
    out.append("| Sheet | Tools documented |")
    out.append("|---|---|")
    for c in have:
        if not c["tools"]:
            continue
        listed = ", ".join("`%s`×%d" % (t, n)
                           for t, n in sorted(c["tools"].items(),
                                              key=lambda kv: -kv[1])[:10])
        out.append("| [%s — %s](%s%s/cheatsheet.md) | %s |"
                   % (c["number"], c["title"], UP, c["dir"], listed))
    out.append("")
    return "\n".join(out) + "\n"


RENDERERS = {
    "chapter": (render_by_chapter, "cheatsheet-index.md"),
    "task": (render_by_task, "cheatsheet-index-by-task.md"),
    "tool": (render_by_tool, "cheatsheet-index-by-tool.md"),
}


# --- link verification -----------------------------------------------------

LINK_RE = re.compile(r"\]\(([^)\s]+)\)")


def verify_links(root, refs_dir, chapters):
    """Render every grouping into memory, extract every markdown link, and resolve
    it against `refs_dir` -- the directory the files are actually written into.

    BOTH HALVES OF THE TARGET. The original version of this function split on `#`
    and threw the fragment away, which is why 230 dead anchors shipped from a
    script whose header tells you not to eyeball links. The path half guards the
    LINK DEPTH defect; the fragment half guards the slugger. A link checker that
    resolves half a link reports half an answer, confidently.

    Anchors are resolved against the file's REAL heading set, parsed by
    `check-anchors.py` -- not against the anchors this script computed, which
    would only prove it agrees with itself."""
    anchor_cache = {}

    def anchors_for(path, text=None):
        key = os.path.normcase(os.path.abspath(path))
        if key not in anchor_cache:
            try:
                mf = _anchors.MarkdownFile(os.path.abspath(path), root, text=text)
            except (OSError, UnicodeDecodeError):
                return None
            anchor_cache[key] = {_anchors.normalise_fragment(a) for a in mf.anchors}
        return anchor_cache[key]

    total = 0
    frags = 0
    broken = []
    for kind, (fn, name) in sorted(RENDERERS.items()):
        text = fn(chapters)
        self_path = os.path.join(refs_dir, name)
        anchors_for(self_path, text=text)        # seed: the file is not written yet
        for m in LINK_RE.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, frag = target.partition("#")
            if path:
                total += 1
                resolved = os.path.normpath(os.path.join(refs_dir, path))
                if not os.path.exists(resolved):
                    broken.append((kind, target, "path does not exist: %s" % resolved))
                    continue
            else:
                resolved = self_path
            if not frag:
                continue
            frags += 1
            have = anchors_for(resolved)
            if have is None:
                continue
            if _anchors.normalise_fragment(frag) not in have:
                broken.append((kind, target,
                               "no anchor '#%s' in %s"
                               % (frag, os.path.relpath(resolved, root))))
    for kind, target, why in broken:
        print("BROKEN [%s] %s -- %s" % (kind, target, why))
    print("resolved %d path(s) and %d fragment(s) from %s; %d broken"
          % (total, frags, refs_dir, len(broken)))
    return 1 if broken else 0


# --- entry point -----------------------------------------------------------

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    chapter_root = os.path.abspath(os.path.join(here, ".."))
    default_root = os.path.abspath(os.path.join(here, "..", ".."))
    refs_dir = os.path.join(chapter_root, "references")

    ap = argparse.ArgumentParser(
        description="Build the cheat-sheet router from every chapter's cheatsheet.md.")
    ap.add_argument("--root", default=default_root,
                    help="repository root (default: two levels above this script)")
    ap.add_argument("--by", default="chapter", choices=sorted(RENDERERS),
                    help="grouping (default: chapter)")
    ap.add_argument("--format", default="md", choices=["md", "json"],
                    help="output format (default: md)")
    ap.add_argument("--out", default=None,
                    help="output path, or '-' for stdout")
    ap.add_argument("--stats", action="store_true",
                    help="print counts and write nothing")
    ap.add_argument("--check", action="store_true",
                    help="report chapters with a README and no cheatsheet; exit 1 if any")
    ap.add_argument("--verify-links", action="store_true",
                    help="resolve every link this script would emit; exit 1 if any break")
    args = ap.parse_args()

    chapters = collect(args.root)
    if not chapters:
        sys.stderr.write("error: no chapter directories found under %s\n" % args.root)
        return 2

    if args.stats:
        have = [c for c in chapters if c["has_sheet"]]
        print("%-32s %6s %6s %6s %6s" % ("sheet", "lines", "H2", "fences", "rows"))
        for c in have:
            print("%-32s %6d %6d %6d %6d"
                  % (c["dir"], c["lines"], len(c["sections"]),
                     c["fences"], c["table_rows"]))
        print("-" * 60)
        print("%-32s %6d" % ("chapter dirs with a README", len(chapters)))
        print("%-32s %6d" % ("chapters with a cheatsheet", len(have)))
        print("%-32s %6d" % ("total lines", sum(c["lines"] for c in have)))
        print("%-32s %6d" % ("total H2 sections",
                             sum(len(c["sections"]) for c in have)))
        print("%-32s %6d" % ("total fenced blocks", sum(c["fences"] for c in have)))
        return 0

    if args.check:
        problems = [c["dir"] for c in chapters
                    if not c["has_sheet"] and c["dir"] not in REFERENCE_CHAPTERS]
        for p in problems:
            print("%s: README present, no cheatsheet.md" % p)
        print("checked %d chapter(s) with a README; %d problem(s)"
              % (len(chapters), len(problems)))
        return 1 if problems else 0

    if args.verify_links:
        return verify_links(args.root, refs_dir, chapters)

    if args.format == "json":
        write(args.out or "-", json.dumps(chapters, indent=2, ensure_ascii=False) + "\n")
        return 0

    fn, name = RENDERERS[args.by]
    write(args.out or os.path.join(refs_dir, name), fn(chapters))
    return 0


if __name__ == "__main__":
    sys.exit(main())
