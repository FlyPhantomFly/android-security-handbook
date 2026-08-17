#!/usr/bin/env python3
# 75-InterviewQuestions/scripts/build-interview-index.py
#
# PURPOSE
#   Build the cross-chapter interview-question index MECHANICALLY, by parsing the
#   "## 10. Common Interview Questions" section out of every chapter README in this
#   repository. Nothing here is transcribed by hand, so the index cannot drift out of
#   date: re-run it after any chapter changes and the output is correct again.
#
#   Chapter 75's whole reason to exist is that concatenating 73 chapters' question
#   sections would be worthless. This script does the ONE part of aggregation that is
#   worth doing -- navigation -- and leaves the analysis to the chapter prose.
#
# USAGE
#   # write the default artefact (references/question-index.md), grouped by tier
#   python3 -B scripts/build-interview-index.py
#
#   # other groupings, to stdout
#   python3 -B scripts/build-interview-index.py --by chapter --out -
#   python3 -B scripts/build-interview-index.py --by role    --out -
#   python3 -B scripts/build-interview-index.py --by round   --out -
#
#   # machine-readable, for a drill tool (mock-round.py consumes this)
#   python3 -B scripts/build-interview-index.py --format json --out ../scratch/q.json
#
#   # counts only, no file written
#   python3 -B scripts/build-interview-index.py --stats
#
#   # CI-style gate: which written chapters are missing a tier?
#   python3 -B scripts/build-interview-index.py --check
#
#   Run with -B so no __pycache__ is written into the repository.
#
# WAS THIS EXECUTED?
#   YES. Run against this repository on 2026-08-16 with CPython 3 on Windows 11.
#   Measured result at that time, over the 73 chapters that have a README:
#
#       chapters carrying an interview section : 71
#       Beginner                               : 321
#       Intermediate                           : 333
#       Senior                                 : 272
#       Staff Engineer                         : 177
#       Principal Engineer                     : 155
#       TOTAL                                  : 1258
#
#   `--check` reports 0 problems: every one of the 71 carries all five tiers.
#   The two reference chapters with a README (79-Glossary, 80-Appendix) have no
#   interview section by design and are excluded from the gate.
#
#   The first version of this script reported 1,242 questions and flagged
#   25-Binder as having none. That was a defect in THIS SCRIPT, not in 25: that
#   chapter writes its questions as "**text?**" with no "Q." prefix. The lesson is
#   the repository's own -- a detector that disagrees with one sample out of 71 is
#   more likely to be wrong than the sample.
#
# EXIT STATUS
#   0 normally; 1 from --check if a non-reference chapter with a README is missing
#   an interview section or a tier.

import argparse
import json
import os
import re
import sys

# --- constants -------------------------------------------------------------

# Reference chapters follow STYLE-GUIDE.md section 4a and have no numbered
# interview section by design. They are not defects.
REFERENCE_CHAPTERS = {"76-CheatSheets", "78-Diagrams", "79-Glossary", "80-Appendix"}

# The five tiers, in escalation order. Everything else normalises into these.
TIERS = ["Beginner", "Intermediate", "Senior", "Staff Engineer", "Principal Engineer"]

# Heading text -> canonical tier. Chapters write the tier heading several ways:
#   "### Beginner", "### 10.1 Beginner", "### Tier 1 -- Beginner".
TIER_PATTERNS = [
    (re.compile(r"principal", re.I), "Principal Engineer"),
    (re.compile(r"\bstaff\b", re.I), "Staff Engineer"),
    (re.compile(r"\bsenior\b", re.I), "Senior"),
    (re.compile(r"\bintermediate\b", re.I), "Intermediate"),
    (re.compile(r"\bbeginner\b|\bjunior\b", re.I), "Beginner"),
]

# A question line. Chapters write these three ways, all of which occur in the repo:
#   **Q. text**      most chapters
#   **Q: text**      13-ART, 37-RootDetection, 10-APK-Internals and others
#   **text?**        25-Binder drops the Q prefix entirely
# The third form is why this matcher accepts any whole-line bold run that either
# carries a Q prefix or ends in a question mark. Restricting to whole-line bold is
# what keeps ordinary emphasis inside an answer from being counted as a question.
#
# The ANSWER is the prose that follows, and is deliberately NOT captured: the index
# links to it rather than duplicating it. See the header comment.
Q_RE = re.compile(r"^\*\*(?:Q[0-9]*\s*[.:]\s*)?(.+?)\?\*\*\s*$|^\*\*Q[0-9]*\s*[.:]\s*(.+?)\*\*\s*$")

# The section heading. STYLE-GUIDE.md defines this section by its TITLE, not by
# its number, so match on the words. Keying on "## 10." would drop a renumbered
# chapter silently -- no error, just a smaller corpus.
SECTION_RE = re.compile(r"^##\s+(\d+)\.\s*(.*interview.*)$", re.I)
ANY_H2_RE = re.compile(r"^##\s+")
H3_RE = re.compile(r"^###\s+(.*)$")

CHAPTER_DIR_RE = re.compile(r"^(\d{2})-")

# --- curation --------------------------------------------------------------
# The two groupings below are the only hand-written data in this file. They map
# chapters onto the shape of a real hiring process rather than onto the reading
# order, which is what makes the index navigable by someone preparing for a
# specific interview. Keyed by chapter NUMBER so renaming a directory cannot
# break them.

ROLE_TRACKS = {
    "Mobile Application Pentester": [
        "10", "21", "23", "26", "27", "29", "30", "32", "33", "34", "35", "36",
        "43", "44", "45", "46", "47", "48", "49", "51", "52", "53", "54", "55",
        "56", "60", "67", "71",
    ],
    "Android Platform / OS Security Engineer": [
        "02", "06", "07", "08", "11", "13", "20", "21", "22", "23", "24", "25",
        "28", "32", "50", "61", "62",
    ],
    "Reverse Engineer / Malware Analyst": [
        "04", "10", "12", "13", "14", "15", "16", "18", "19", "40", "41", "42",
        "56", "57", "58", "59", "64", "65", "68", "69",
    ],
    "Product Security / AppSec (defensive)": [
        "08", "20", "23", "32", "34", "35", "36", "41", "42", "44", "45", "46",
        "47", "48", "49", "50", "71",
    ],
    "Vulnerability Researcher / Exploit Developer": [
        "01", "15", "16", "18", "19", "22", "24", "25", "27", "29", "30", "65",
        "70",
    ],
    "Detection / Anti-Fraud Engineer": [
        "37", "38", "39", "50", "62", "63", "64", "67",
    ],
}

ROUND_MAP = {
    "Recruiter screen": {
        "tiers": ["Beginner"],
        "chapters": ["00", "06", "20", "71"],
        "note": "Vocabulary and orientation. Optimised for being understood by a "
                "non-specialist, not for depth.",
    },
    "Technical phone screen": {
        "tiers": ["Beginner", "Intermediate"],
        "chapters": ["10", "21", "23", "26", "32", "33", "35", "37", "52", "53", "60"],
        "note": "Breadth under time pressure. One wrong confident answer costs more "
                "than three honest gaps.",
    },
    "Deep technical round": {
        "tiers": ["Intermediate", "Senior"],
        "chapters": ["13", "22", "25", "27", "29", "34", "36", "43", "44", "46",
                     "47", "48", "49", "56", "65", "67", "68"],
        "note": "Mechanism, not vocabulary. Expect to be pushed one layer below "
                "whatever you volunteer.",
    },
    "Practical / take-home": {
        "tiers": ["Intermediate", "Senior"],
        "chapters": ["10", "51", "52", "53", "55", "56", "60", "69", "70", "71"],
        "note": "Graded on method and honest severity, not on finding count.",
    },
    "System design / architecture": {
        "tiers": ["Senior", "Staff Engineer", "Principal Engineer"],
        "chapters": ["20", "24", "34", "45", "46", "47", "49", "50", "71"],
        "note": "Where the trust boundary is, and what you do when it is on the "
                "attacker's side of the wire.",
    },
    "Behavioural / values": {
        "tiers": ["Senior", "Staff Engineer", "Principal Engineer"],
        "chapters": ["20", "51", "52", "70", "71"],
        "note": "Disagreement, disclosure, being wrong in public, and severity "
                "under commercial pressure.",
    },
}


# --- parsing ---------------------------------------------------------------

def read_utf8(path):
    """Read a file as strict UTF-8. Raises on invalid bytes rather than replacing
    them, so an encoding accident is loud instead of silent."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        # The repository standard is BOM-less UTF-8; tolerate but report.
        sys.stderr.write("warning: BOM in %s\n" % path)
        raw = raw[3:]
    return raw.decode("utf-8")


def github_anchor(heading_text):
    """Reproduce GitHub's heading-anchor algorithm closely enough for these
    headings: lower-case, strip anything that is not a word character, space or
    hyphen, then spaces to hyphens."""
    text = heading_text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s+", "-", text)


def normalise_tier(heading_text):
    for pattern, tier in TIER_PATTERNS:
        if pattern.search(heading_text):
            return tier
    return None


def parse_chapter(chapter_dir):
    """Return a dict describing one chapter's interview section, or None if the
    chapter has no README."""
    readme = os.path.join(chapter_dir, "README.md")
    if not os.path.isfile(readme):
        return None

    name = os.path.basename(chapter_dir)
    number = CHAPTER_DIR_RE.match(name).group(1)
    lines = read_utf8(readme).split("\n")

    # Locate the section and its bounds.
    start = None
    section_heading = None
    for i, line in enumerate(lines):
        m = SECTION_RE.match(line.rstrip())
        if m:
            start = i
            section_heading = line.rstrip().lstrip("# ").strip()
            break

    result = {
        "number": number,
        "dir": name,
        "title": name.split("-", 1)[1].replace("-", " "),
        "section_anchor": None,
        "section_heading": section_heading,
        "questions": [],
        "tiers_present": [],
    }
    if start is None:
        return result

    result["section_anchor"] = "#" + github_anchor(section_heading)

    end = len(lines)
    for j in range(start + 1, len(lines)):
        if ANY_H2_RE.match(lines[j]):
            end = j
            break

    current_tier = None
    for line in lines[start + 1:end]:
        h3 = H3_RE.match(line.rstrip())
        if h3:
            tier = normalise_tier(h3.group(1))
            if tier:
                current_tier = tier
                if tier not in result["tiers_present"]:
                    result["tiers_present"].append(tier)
            continue
        q = Q_RE.match(line.rstrip())
        if q and current_tier:
            # Group 1 is the "ends with ?" alternative (the ? was consumed by the
            # pattern, so put it back); group 2 is the "Q. prefix, no ?" one.
            text = (q.group(1) + "?") if q.group(1) is not None else q.group(2)
            result["questions"].append({
                "tier": current_tier,
                "text": text.strip(),
            })
    return result


def collect(root):
    chapters = []
    for entry in sorted(os.listdir(root)):
        path = os.path.join(root, entry)
        if not os.path.isdir(path) or not CHAPTER_DIR_RE.match(entry):
            continue
        parsed = parse_chapter(path)
        if parsed is not None:
            chapters.append(parsed)
    return chapters


# --- rendering -------------------------------------------------------------

HEADER = """<!-- GENERATED FILE. Do not edit by hand.
     Rebuild with:  python3 -B scripts/build-interview-index.py
     Source: the "## 10. Common Interview Questions" section of every chapter README. -->

# Cross-chapter interview question index

This file is **built mechanically** from the per-chapter interview sections by
[`scripts/build-interview-index.py`](../scripts/build-interview-index.py). It lists every
question in the repository and links to the chapter that answers it. It deliberately does
**not** copy the answers: an answer separated from the chapter that justifies it is how
people end up reciting a claim they cannot defend, which is exactly the failure mode
[`../README.md`](../README.md) section 5 is about.

"""


def render_markdown(chapters, group_by):
    out = [HEADER]
    total = sum(len(c["questions"]) for c in chapters)
    with_section = [c for c in chapters if c["questions"]]
    out.append("**%d questions across %d chapters, in %d tiers.** Generated grouping: `%s`.\n"
               % (total, len(with_section), len(TIERS), group_by))
    out.append("")

    if group_by == "tier":
        for tier in TIERS:
            rows = [(c, q) for c in chapters for q in c["questions"] if q["tier"] == tier]
            out.append("## %s (%d)" % (tier, len(rows)))
            out.append("")
            out.append("| Chapter | Question |")
            out.append("|---|---|")
            for c, q in rows:
                out.append("| [%s](../../%s/README.md%s) | %s |"
                           % (c["number"], c["dir"], c["section_anchor"] or "",
                              escape_cell(q["text"])))
            out.append("")

    elif group_by == "chapter":
        for c in chapters:
            if not c["questions"]:
                continue
            out.append("## %s — %s (%d)" % (c["number"], c["title"], len(c["questions"])))
            out.append("")
            out.append("Section: [%s](../../%s/README.md%s)"
                       % (c["section_heading"], c["dir"], c["section_anchor"] or ""))
            out.append("")
            for tier in TIERS:
                qs = [q for q in c["questions"] if q["tier"] == tier]
                if not qs:
                    continue
                out.append("**%s**" % tier)
                out.append("")
                for q in qs:
                    out.append("- %s" % q["text"])
                out.append("")

    elif group_by == "role":
        by_number = {c["number"]: c for c in chapters}
        for role, numbers in ROLE_TRACKS.items():
            present = [by_number[n] for n in numbers
                       if n in by_number and by_number[n]["questions"]]
            count = sum(len(c["questions"]) for c in present)
            out.append("## %s (%d questions across %d chapters)"
                       % (role, count, len(present)))
            out.append("")
            out.append("| Chapter | Questions | B | I | Sr | St | P |")
            out.append("|---|---:|---:|---:|---:|---:|---:|")
            for c in present:
                counts = [len([q for q in c["questions"] if q["tier"] == t]) for t in TIERS]
                out.append("| [%s — %s](../../%s/README.md%s) | %d | %d | %d | %d | %d | %d |"
                           % (c["number"], c["title"], c["dir"], c["section_anchor"] or "",
                              len(c["questions"]), counts[0], counts[1], counts[2],
                              counts[3], counts[4]))
            out.append("")

    elif group_by == "round":
        by_number = {c["number"]: c for c in chapters}
        for round_name, spec in ROUND_MAP.items():
            present = [by_number[n] for n in spec["chapters"]
                       if n in by_number and by_number[n]["questions"]]
            pool = [q for c in present for q in c["questions"]
                    if q["tier"] in spec["tiers"]]
            out.append("## %s" % round_name)
            out.append("")
            out.append("%s" % spec["note"])
            out.append("")
            out.append("Tiers in scope: %s. Pool: **%d questions** across %d chapters."
                       % (", ".join(spec["tiers"]), len(pool), len(present)))
            out.append("")
            out.append("| Chapter | In-scope questions |")
            out.append("|---|---:|")
            for c in present:
                n = len([q for q in c["questions"] if q["tier"] in spec["tiers"]])
                out.append("| [%s — %s](../../%s/README.md%s) | %d |"
                           % (c["number"], c["title"], c["dir"],
                              c["section_anchor"] or "", n))
            out.append("")

    return "\n".join(out) + "\n"


def escape_cell(text):
    """A markdown table cell cannot contain an unescaped pipe."""
    return text.replace("|", "\\|")


# --- entry point -----------------------------------------------------------

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, "..", ".."))
    default_out = os.path.join(here, "..", "references", "question-index.md")

    ap = argparse.ArgumentParser(
        description="Build the cross-chapter interview index from chapter READMEs.")
    ap.add_argument("--root", default=default_root,
                    help="repository root (default: two levels above this script)")
    ap.add_argument("--by", default="tier",
                    choices=["tier", "chapter", "role", "round"],
                    help="how to group the output (default: tier)")
    ap.add_argument("--format", default="md", choices=["md", "json", "csv"],
                    help="output format (default: md)")
    ap.add_argument("--out", default=None,
                    help="output path, or '-' for stdout "
                         "(default: references/question-index.md for md)")
    ap.add_argument("--stats", action="store_true",
                    help="print counts to stdout and write nothing")
    ap.add_argument("--check", action="store_true",
                    help="report chapters missing a section or a tier; exit 1 if any")
    args = ap.parse_args()

    chapters = collect(args.root)
    if not chapters:
        sys.stderr.write("error: no chapter directories found under %s\n" % args.root)
        return 2

    if args.stats:
        total = 0
        print("%-32s %6s  %s" % ("chapter", "count", "tiers"))
        for c in chapters:
            if not c["questions"]:
                continue
            total += len(c["questions"])
            print("%-32s %6d  %s" % (c["dir"], len(c["questions"]),
                                     ", ".join(c["tiers_present"])))
        print("-" * 60)
        for tier in TIERS:
            n = sum(len([q for q in c["questions"] if q["tier"] == tier])
                    for c in chapters)
            print("%-32s %6d" % (tier, n))
        print("%-32s %6d" % ("TOTAL", total))
        print("%-32s %6d" % ("chapters with a section",
                             len([c for c in chapters if c["questions"]])))
        return 0

    if args.check:
        problems = []
        for c in chapters:
            if c["dir"] in REFERENCE_CHAPTERS:
                continue
            if not c["questions"]:
                problems.append("%s: no interview section found" % c["dir"])
                continue
            missing = [t for t in TIERS if t not in c["tiers_present"]]
            if missing:
                problems.append("%s: missing tier(s): %s"
                                % (c["dir"], ", ".join(missing)))
        for p in problems:
            print(p)
        print("checked %d chapters with a README; %d problem(s)"
              % (len(chapters), len(problems)))
        return 1 if problems else 0

    if args.format == "json":
        payload = json.dumps(chapters, indent=2, ensure_ascii=False)
        write(args.out or "-", payload + "\n")
        return 0

    if args.format == "csv":
        rows = ["chapter,tier,question"]
        for c in chapters:
            for q in c["questions"]:
                rows.append('%s,"%s","%s"'
                            % (c["dir"], q["tier"], q["text"].replace('"', '""')))
        write(args.out or "-", "\n".join(rows) + "\n")
        return 0

    text = render_markdown(chapters, args.by)
    write(args.out or default_out, text)
    return 0


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


if __name__ == "__main__":
    sys.exit(main())
