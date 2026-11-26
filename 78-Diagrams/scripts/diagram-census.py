#!/usr/bin/env python3
# 78-Diagrams/scripts/diagram-census.py
#
# PURPOSE
#   Census and index EVERY Mermaid diagram in this repository, MECHANICALLY.
#
#   Chapter 78 exists because the repository is full of diagrams and nobody can
#   find one again. The wrong fix is to paste them all into one file: they would
#   be stale the moment any chapter is edited, and each one would be separated
#   from the prose that STYLE-GUIDE.md section 2 requires to sit beside it.
#
#   The right fix is an index that is regenerated, never transcribed. This script
#   walks every .md file under the repository root, extracts every fenced
#   ```mermaid block and every standalone .mmd source file, classifies it by
#   diagram type, records the heading (or file name) it lives under, measures its
#   size, and emits:
#
#       references/diagram-index.md          every diagram, grouped by chapter
#       references/diagram-index-by-type.md  the same set, grouped by diagram type
#
#   It also reports the census numbers themselves -- how many diagrams, of which
#   types, in which chapters, and which chapters are diagram-POOR. That count is a
#   measurement of the repository and is quoted in ../README.md section 3.
#
# WHAT IT DOES NOT DO
#   It does not copy diagram source into the index, and it does not copy the prose
#   that explains a diagram. Both live in the chapter. The index is navigation.
#
# USAGE
#   # regenerate both index artefacts (the default)
#   python3 -B scripts/diagram-census.py
#
#   # numbers only, write nothing
#   python3 -B scripts/diagram-census.py --stats
#
#   # the diagram-poor report used in README section 3
#   python3 -B scripts/diagram-census.py --poor
#
#   # machine-readable, for validate-mermaid.mjs
#   python3 -B scripts/diagram-census.py --format json --out - > blocks.json
#
#   # CI gate: fail if any chapter README has fewer than 2 diagrams
#   python3 -B scripts/diagram-census.py --check
#
#   Always run with -B so no __pycache__ lands in the repository.
#
# WAS THIS EXECUTED?
#   YES, repeatedly. Final run against this repository on 2026-08-16, CPython
#   3.13.3, Windows 11. Measured at that time:
#
#       TOTAL diagrams                        812
#         in 78-Diagrams (this chapter)        37
#         everywhere else (indexed)           775
#       files containing a diagram            180
#       in a chapter README                   677
#       outside a README (mindmap, faq, labs) 135
#       drawing a trust boundary (subgraph)   225
#       marking attacker input #f9d0d0        309
#       UNRECOGNISED first keyword              0
#       median node count                       7
#       largest node count                     46
#
#   `--check` reports 0 problems across 80 chapter READMEs.
#
#   The count moved from 771 to 775 DURING the writing of chapter 78, because
#   76-CheatSheets landed in parallel. Nothing was retyped; the script was re-run.
#   That is the argument for generating this index rather than transcribing it,
#   and it demonstrated itself inside a single afternoon.
#
#   TWO DEFECTS WERE FOUND IN THIS SCRIPT AND FIXED, both in github_anchor():
#     1. Collapsing RUNS of whitespace to one hyphen. GitHub substitutes each
#        space individually, so a heading containing " — " yields "--". Every
#        em-dashed heading in the repository was pointed at a non-existent anchor
#        until this was corrected against the chapters' hand-written contents
#        tables.
#     2. The same function in verify-index-links.py stripped underscores, which
#        mangled 18 anchors. Both now agree, and both agree with GitHub.
#   Re-run before quoting any number here; they move every time a chapter is
#   edited.
#
#   RE-AUDITED 2026-08-17 by `76-CheatSheets/scripts/check-anchors.py`, an
#   independent repository-wide anchor checker that shares no code with this
#   script: every anchor both index files emit resolves. Two cautions it raised
#   and this script does NOT currently get wrong, but could:
#     * github_anchor() has no duplicate-slug counter. GitHub suffixes the second
#       identical heading in a file `-1`, the third `-2`. No chapter currently has
#       two same-slug headings that this index links, so nothing is broken -- but
#       an index entry for the second one would silently point at the first.
#     * verify-index-links.py checks this script's output using a COPY of this
#       function, so it cannot detect an error in the function itself. Trust the
#       independent checker for that, not this chapter's own.
#
# EXIT STATUS
#   0 normally; 1 from --check when a non-reference chapter README carries fewer
#   than MIN_DIAGRAMS_PER_CHAPTER diagrams.

import argparse
import json
import os
import re
import sys

# --- constants -------------------------------------------------------------

# STYLE-GUIDE.md section 2 requires "at least two Mermaid diagrams" in the
# High-Level Architecture section of every teaching chapter. Reference chapters
# (section 4a) are exempt from the 14-section template and therefore from this.
MIN_DIAGRAMS_PER_CHAPTER = 2

REFERENCE_CHAPTERS = {"76-CheatSheets", "78-Diagrams", "79-Glossary", "80-Appendix"}

CHAPTER_DIR_RE = re.compile(r"^(\d{2})-")

# A fence opens with three-or-more backticks and an optional info string, and is
# closed by a run of at least as many backticks with no info string. Tracking the
# run length is what stops a ```mermaid shown as an EXAMPLE inside a ````markdown
# fence from being counted as a real diagram.
FENCE_RE = re.compile(r"^(\s*)(`{3,})\s*([A-Za-z0-9_-]*)\s*$")

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")

# Mermaid frontmatter:  ---\ntitle: Something\n---
FRONTMATTER_TITLE_RE = re.compile(r"^\s*title\s*:\s*(.+?)\s*$")
# An inline title directive inside the body, e.g. "  title Boot chain"
INLINE_TITLE_RE = re.compile(r"^\s*title\s+(.+?)\s*$")
# %%{init: {...}}%% and %% comments
DIRECTIVE_RE = re.compile(r"^\s*%%")

# Canonical diagram type keywords, longest-prefix first so "stateDiagram-v2"
# is not swallowed by "stateDiagram".
TYPE_KEYWORDS = [
    "sequenceDiagram",
    "stateDiagram-v2",
    "stateDiagram",
    "classDiagram",
    "erDiagram",
    "requirementDiagram",
    "gitGraph",
    "quadrantChart",
    "xychart-beta",
    "sankey-beta",
    "block-beta",
    "packet-beta",
    "architecture-beta",
    "flowchart",
    "graph",
    "mindmap",
    "timeline",
    "journey",
    "gantt",
    "pie",
    "C4Context",
    "C4Container",
    "C4Component",
    "C4Dynamic",
    "zenuml",
]

# How the type is described in the index. The point of this column is that a
# reader choosing a diagram to COPY needs to know what shape it is, not just
# what it is called.
TYPE_HUMAN = {
    "flowchart": "flowchart",
    "graph": "flowchart (legacy `graph` keyword)",
    "sequenceDiagram": "sequence",
    "classDiagram": "class",
    "stateDiagram-v2": "state",
    "stateDiagram": "state (legacy v1 keyword)",
    "erDiagram": "entity-relationship",
    "mindmap": "mindmap",
    "block-beta": "block layout",
    "timeline": "timeline",
    "journey": "user journey",
    "gantt": "gantt",
    "pie": "pie",
    "gitGraph": "git graph",
    "quadrantChart": "quadrant",
    "requirementDiagram": "requirement",
    "xychart-beta": "xy chart",
    "sankey-beta": "sankey",
    "packet-beta": "packet layout",
    "architecture-beta": "architecture",
}

# Node/participant counters, per family. Crude on purpose: the number is a size
# signal for the index ("is this a 4-box sketch or a 30-node monster?"), not an
# analysis.
NODE_ID_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\[|\(\(|\(\[|\[|\(|\{|>)")
PARTICIPANT_RE = re.compile(r"^\s*(?:participant|actor)\s+([A-Za-z0-9_]+)")
CLASS_RE = re.compile(r"^\s*class\s+([A-Za-z0-9_]+)")
SUBGRAPH_RE = re.compile(r"^\s*subgraph\s+")
STYLE_FILL_RE = re.compile(r"^\s*(?:style|classDef)\s+\S+.*fill\s*:\s*(#[0-9A-Fa-f]{3,8})")

# The repository's own convention, STYLE-GUIDE.md section 6: attacker-controlled
# input is coloured #f9d0d0. Counting how many diagrams actually use it is the
# only way to know whether the convention is real or aspirational.
ATTACKER_FILL = "#f9d0d0"


# --- helpers ---------------------------------------------------------------

def read_utf8(path):
    """Strict UTF-8. Raise on invalid bytes rather than replacing them, so an
    encoding accident is loud instead of silent. Report a BOM -- the repository
    standard is BOM-less UTF-8."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        sys.stderr.write("warning: BOM in %s\n" % path)
        raw = raw[3:]
    return raw.decode("utf-8")


def github_anchor(heading_text):
    """Reproduce GitHub's heading-anchor algorithm closely enough for the
    headings this repository uses: lower-case, drop everything that is not a word
    character, space or hyphen, then spaces to hyphens."""
    text = heading_text.strip().lower()
    text = re.sub(r"`", "", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    # ONE hyphen per whitespace character, not per RUN. GitHub deletes punctuation
    # first, so a heading containing " — " leaves two adjacent spaces and becomes
    # "--". Collapsing runs here pointed every em-dashed heading at an anchor that
    # does not exist. Ground truth: the hand-written tables of contents in the
    # chapters, which do carry the doubled hyphen.
    return re.sub(r"\s", "-", text)


def classify(body_lines):
    """Return (type_keyword, title_or_None) for one mermaid block body."""
    title = None
    in_frontmatter = False
    seen_any = False
    for raw in body_lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if not seen_any and stripped == "---":
            in_frontmatter = not in_frontmatter
            continue
        if in_frontmatter:
            m = FRONTMATTER_TITLE_RE.match(stripped)
            if m:
                title = m.group(1).strip().strip('"').strip("'")
            continue
        if DIRECTIVE_RE.match(stripped):
            continue
        seen_any = True
        for kw in TYPE_KEYWORDS:
            if stripped == kw or stripped.startswith(kw + " ") or \
               stripped.startswith(kw + "\t"):
                return kw, title
        # First meaningful line did not name a known type.
        return None, title
    return None, title


def find_inline_title(body_lines, dtype):
    """sequenceDiagram/pie/gantt/journey/xychart accept a `title X` line."""
    for raw in body_lines[:8]:
        stripped = raw.strip()
        if stripped.startswith("title ") and not stripped.startswith("title:"):
            m = INLINE_TITLE_RE.match(stripped)
            if m:
                return m.group(1).strip()
    return None


def measure(body_lines, dtype):
    """Crude size and convention metrics for one block."""
    ids = set()
    subgraphs = 0
    marks_attacker = False
    for raw in body_lines:
        line = raw.rstrip()
        low = line.lower()
        if SUBGRAPH_RE.match(line):
            subgraphs += 1
        fill = STYLE_FILL_RE.match(line)
        if fill and fill.group(1).lower() == ATTACKER_FILL:
            marks_attacker = True
        elif ATTACKER_FILL in low:
            marks_attacker = True
        if dtype == "sequenceDiagram":
            m = PARTICIPANT_RE.match(line)
            if m:
                ids.add(m.group(1))
        elif dtype == "classDiagram":
            m = CLASS_RE.match(line)
            if m:
                ids.add(m.group(1))
        else:
            for m in NODE_ID_RE.finditer(line):
                ids.add(m.group(1))
    return {
        "nodes": len(ids),
        "subgraphs": subgraphs,
        "marks_attacker_input": marks_attacker,
        "lines": len(body_lines),
    }


def extract_blocks(path, rel_path):
    """Yield one dict per fenced ```mermaid block in a markdown file."""
    text = read_utf8(path).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    blocks = []
    heading_stack = {}       # level -> text
    fence_ticks = None       # length of the currently open fence, or None
    fence_info = None
    fence_start = None
    body = []

    for i, line in enumerate(lines, start=1):
        fm = FENCE_RE.match(line)
        if fence_ticks is None:
            if fm:
                fence_ticks = len(fm.group(2))
                fence_info = (fm.group(3) or "").lower()
                fence_start = i
                body = []
                continue
            hm = HEADING_RE.match(line)
            if hm:
                level = len(hm.group(1))
                heading_stack[level] = hm.group(2).strip()
                for deeper in [k for k in heading_stack if k > level]:
                    del heading_stack[deeper]
            continue

        # Inside a fence.
        if fm and len(fm.group(2)) >= fence_ticks and not fm.group(3):
            if fence_info == "mermaid":
                dtype, title = classify(body)
                if title is None:
                    title = find_inline_title(body, dtype)
                trail = [heading_stack[k] for k in sorted(heading_stack) if k >= 2]
                anchor_source = trail[-1] if trail else None
                blocks.append({
                    "file": rel_path,
                    "line": fence_start,
                    "type": dtype,
                    "type_human": TYPE_HUMAN.get(dtype, dtype or "UNRECOGNISED"),
                    "title": title,
                    "heading": anchor_source,
                    "heading_trail": trail,
                    "anchor": ("#" + github_anchor(anchor_source)) if anchor_source else "",
                    "source": "\n".join(body),
                    **measure(body, dtype),
                })
            fence_ticks = None
            fence_info = None
            body = []
            continue

        body.append(line)

    if fence_ticks is not None:
        sys.stderr.write("warning: unclosed fence opened at %s:%d\n"
                         % (rel_path, fence_start))
    return blocks


def extract_mmd(path, rel_path):
    """Return one block for a standalone .mmd source file.

    Chapter 81 keeps its Mermaid sources as .mmd files because GitHub's Mermaid
    iframe times out on slow connections; the rendered page uses committed SVG.
    The diagram still exists, so the census counts it and the index links to the
    source file rather than to a fence in a Markdown page.
    """
    text = read_utf8(path).replace("\r\n", "\n").replace("\r", "\n")
    body = text.split("\n")
    dtype, title = classify(body)
    if title is None:
        title = find_inline_title(body, dtype)
    return {
        "file": rel_path,
        "line": 1,
        "type": dtype,
        "type_human": TYPE_HUMAN.get(dtype, dtype or "UNRECOGNISED"),
        "title": title,
        "heading": os.path.basename(rel_path),
        "heading_trail": [os.path.basename(rel_path)],
        "anchor": "",
        "source": text,
        **measure(body, dtype),
    }


def collect(root):
    """Walk the repository and return every Mermaid block and .mmd source."""
    blocks = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames)
                       if d not in (".git", "node_modules", "__pycache__")]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if fn.lower().endswith(".mmd"):
                try:
                    blocks.append(extract_mmd(full, rel))
                except UnicodeDecodeError as exc:
                    sys.stderr.write("error: %s is not valid UTF-8 (%s)\n" % (rel, exc))
                continue
            if not fn.lower().endswith(".md"):
                continue
            try:
                blocks.extend(extract_blocks(full, rel))
            except UnicodeDecodeError as exc:
                sys.stderr.write("error: %s is not valid UTF-8 (%s)\n" % (rel, exc))
    for b in blocks:
        parts = b["file"].split("/")
        b["chapter"] = parts[0] if CHAPTER_DIR_RE.match(parts[0]) else "(root)"
        b["chapter_number"] = parts[0][:2] if CHAPTER_DIR_RE.match(parts[0]) else ""
    return blocks


# --- rendering -------------------------------------------------------------
#
# LINK DEPTH. These artefacts are written into 78-Diagrams/references/, which is
# TWO levels below the repository root, so a link to another chapter needs
# "../../". Getting this wrong is not hypothetical: an earlier generator in this
# repository emitted "../" from a file in references/ and produced 1,495 broken
# links that nothing caught for months. verify-index-links.py exists precisely to
# stop that recurring, and it resolves every link on disk rather than eyeballing
# a sample.

LINK_PREFIX = "../../"

HEADER = """<!-- GENERATED FILE. Do not edit by hand.
     Rebuild with:  python3 -B scripts/diagram-census.py
     Source: every fenced ```mermaid block in every .md file in this repository,
     plus every standalone .mmd source file. -->

# %s

Built mechanically by [`scripts/diagram-census.py`](../scripts/diagram-census.py).

This index deliberately does **not** reproduce the diagrams. A diagram copied out of
its chapter loses the prose that STYLE-GUIDE.md requires to sit beside it, and goes
stale the moment the original is edited. What you get here is the location, the shape,
and the size — enough to decide whether to open it.

Columns: **Type** is the Mermaid diagram family. **Nodes** is a crude count of distinct
node, participant or class identifiers — a size signal, not an analysis. **Boundaries**
counts `subgraph` blocks, which is how this repository draws a trust boundary. **Atk**
marks a diagram that colours attacker-controlled input `%s`, the convention in
STYLE-GUIDE.md section 6.

"""


def render_by_chapter(blocks):
    out = [HEADER % ("Diagram index — by chapter", ATTACKER_FILL)]
    chapters = sorted({b["chapter"] for b in blocks})
    out.append("**%d diagrams across %d files in %d chapters.**\n"
               % (len(blocks), len({b["file"] for b in blocks}), len(chapters)))
    out.append("")
    for ch in chapters:
        rows = [b for b in blocks if b["chapter"] == ch]
        out.append("## %s (%d)" % (ch, len(rows)))
        out.append("")
        out.append("| # | Depicts | Type | Nodes | Boundaries | Atk | Location |")
        out.append("|---:|---|---|---:|---:|:---:|---|")
        for n, b in enumerate(rows, start=1):
            out.append("| %d | %s | %s | %d | %d | %s | %s |"
                       % (n, depicts(b), b["type_human"], b["nodes"],
                          b["subgraphs"], "yes" if b["marks_attacker_input"] else "",
                          location_link(b)))
        out.append("")
    return "\n".join(out) + "\n"


def render_by_type(blocks):
    out = [HEADER % ("Diagram index — by diagram type", ATTACKER_FILL)]
    types = sorted({b["type_human"] for b in blocks})
    out.append("**%d diagrams in %d Mermaid families.** Use this view when you want a "
               "worked example of a particular diagram type to copy the shape of.\n"
               % (len(blocks), len(types)))
    out.append("")
    out.append("| Type | Count | Share |")
    out.append("|---|---:|---:|")
    for t in sorted(types, key=lambda t: -len([b for b in blocks if b["type_human"] == t])):
        n = len([b for b in blocks if b["type_human"] == t])
        out.append("| %s | %d | %.1f%% |" % (t, n, 100.0 * n / len(blocks)))
    out.append("")
    for t in sorted(types, key=lambda t: -len([b for b in blocks if b["type_human"] == t])):
        rows = [b for b in blocks if b["type_human"] == t]
        out.append("## %s (%d)" % (t, len(rows)))
        out.append("")
        out.append("| Chapter | Depicts | Nodes | Atk | Location |")
        out.append("|---|---|---:|:---:|---|")
        for b in rows:
            out.append("| %s | %s | %d | %s | %s |"
                       % (b["chapter"], depicts(b), b["nodes"],
                          "yes" if b["marks_attacker_input"] else "", location_link(b)))
        out.append("")
    return "\n".join(out) + "\n"


def depicts(b):
    """What the diagram is about, taken from its own title if it has one and
    otherwise from the heading it sits under. Never invented."""
    if b["title"]:
        return escape_cell(b["title"])
    if b["heading"]:
        return escape_cell(b["heading"])
    return "_(no heading above it)_"


def location_link(b):
    label = "%s:%d" % (b["file"].split("/", 1)[-1] if "/" in b["file"] else b["file"],
                       b["line"])
    return "[%s](%s%s%s)" % (escape_cell(label), LINK_PREFIX, b["file"], b["anchor"])


def escape_cell(text):
    return text.replace("|", "\\|")


# --- entry point -----------------------------------------------------------

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, "..", ".."))
    refs = os.path.abspath(os.path.join(here, "..", "references"))

    ap = argparse.ArgumentParser(
        description="Census and index every Mermaid diagram in the repository.")
    ap.add_argument("--root", default=default_root,
                    help="repository root (default: two levels above this script)")
    ap.add_argument("--format", default="md", choices=["md", "json", "csv"])
    ap.add_argument("--out", default=None,
                    help="output path, or '-' for stdout. Ignored for the default "
                         "two-file markdown run.")
    ap.add_argument("--by", default="both", choices=["chapter", "type", "both"])
    ap.add_argument("--stats", action="store_true", help="print counts, write nothing")
    ap.add_argument("--poor", action="store_true",
                    help="list the least-illustrated chapter READMEs")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if a teaching chapter README has < %d diagrams"
                         % MIN_DIAGRAMS_PER_CHAPTER)
    args = ap.parse_args()

    blocks = collect(args.root)
    if not blocks:
        sys.stderr.write("error: no mermaid blocks found under %s\n" % args.root)
        return 2

    if args.stats:
        return do_stats(blocks, args.root)
    if args.poor:
        return do_poor(blocks, args.root)
    if args.check:
        return do_check(blocks, args.root)

    if args.format == "json":
        write(args.out or "-", json.dumps(blocks, indent=1, ensure_ascii=False) + "\n")
        return 0
    if args.format == "csv":
        rows = ["file,line,type,nodes,subgraphs,attacker_marked,depicts"]
        for b in blocks:
            rows.append('%s,%d,%s,%d,%d,%s,"%s"'
                        % (b["file"], b["line"], b["type"] or "UNRECOGNISED",
                           b["nodes"], b["subgraphs"], b["marks_attacker_input"],
                           depicts(b).replace('"', '""')))
        write(args.out or "-", "\n".join(rows) + "\n")
        return 0

    if args.by in ("chapter", "both"):
        write(os.path.join(refs, "diagram-index.md"), render_by_chapter(blocks))
    if args.by in ("type", "both"):
        write(os.path.join(refs, "diagram-index-by-type.md"), render_by_type(blocks))
    return 0


def readme_chapters(root):
    out = []
    for entry in sorted(os.listdir(root)):
        if not CHAPTER_DIR_RE.match(entry):
            continue
        if os.path.isfile(os.path.join(root, entry, "README.md")):
            out.append(entry)
    return out


def do_stats(blocks, root):
    print("%-34s %6s" % ("diagram type", "count"))
    counts = {}
    for b in blocks:
        counts[b["type_human"]] = counts.get(b["type_human"], 0) + 1
    for t in sorted(counts, key=lambda t: -counts[t]):
        print("%-34s %6d" % (t, counts[t]))
    print("-" * 42)
    print("%-34s %6d" % ("TOTAL diagrams", len(blocks)))
    print("%-34s %6d" % ("files containing a diagram", len({b["file"] for b in blocks})))
    print("%-34s %6d" % ("chapters containing a diagram",
                         len({b["chapter"] for b in blocks})))
    print("%-34s %6d" % ("in a chapter README",
                         len([b for b in blocks if b["file"].endswith("/README.md")
                              and b["file"].count("/") == 1])))
    print("%-34s %6d" % ("outside README (labs, faq, ...)",
                         len([b for b in blocks
                              if not (b["file"].endswith("/README.md")
                                      and b["file"].count("/") == 1)])))
    print("%-34s %6d" % ("  of which .mmd sources",
                         len([b for b in blocks if b["file"].endswith(".mmd")])))
    # Chapter 78 indexes the other 80 chapters and also authors diagrams of its
    # own. Reporting the two separately is the difference between "the repository
    # has N diagrams" and a number that quietly counts this chapter's own work.
    print("%-34s %6d" % ("in 78-Diagrams (this chapter)",
                         len([b for b in blocks if b["chapter"] == "78-Diagrams"])))
    print("%-34s %6d" % ("everywhere else (indexed)",
                         len([b for b in blocks if b["chapter"] != "78-Diagrams"])))
    print("%-34s %6d" % ("drawing a trust boundary (subgraph)",
                         len([b for b in blocks if b["subgraphs"] > 0])))
    print("%-34s %6d" % ("marking attacker input " + ATTACKER_FILL,
                         len([b for b in blocks if b["marks_attacker_input"]])))
    unrec = [b for b in blocks if b["type"] is None]
    print("%-34s %6d" % ("UNRECOGNISED first keyword", len(unrec)))
    for b in unrec:
        print("    %s:%d" % (b["file"], b["line"]))
    sizes = sorted(b["nodes"] for b in blocks)
    print("%-34s %6d" % ("median node count", sizes[len(sizes) // 2]))
    print("%-34s %6d" % ("largest node count", sizes[-1]))
    return 0


def chapter_diagram_counts(blocks):
    """Count fenced README diagrams and standalone .mmd sources per chapter.

    A .mmd source is a full substitute for a fence: chapter 81 moved its
    diagrams out of the rendered Markdown so GitHub would stop timing out on
    the Mermaid iframe, and the source still lives in the repository.
    """
    fenced = {}
    sources = {}
    for b in blocks:
        if b["file"].count("/") == 1 and b["file"].endswith("/README.md"):
            fenced[b["chapter"]] = fenced.get(b["chapter"], 0) + 1
        elif b["file"].endswith(".mmd"):
            sources[b["chapter"]] = sources.get(b["chapter"], 0) + 1
    return fenced, sources


def do_poor(blocks, root):
    fenced, sources = chapter_diagram_counts(blocks)
    rows = []
    for ch in readme_chapters(root):
        n = fenced.get(ch, 0)
        if n < MIN_DIAGRAMS_PER_CHAPTER:
            n += sources.get(ch, 0)
        rows.append((n, ch))
    rows.sort()
    print("%-6s %s" % ("count", "chapter README (ascending) — reference chapters marked *"))
    for n, ch in rows:
        mark = " *" if ch in REFERENCE_CHAPTERS else ""
        print("%-6d %s%s" % (n, ch, mark))
    return 0


def do_check(blocks, root):
    fenced, sources = chapter_diagram_counts(blocks)
    problems = []
    for ch in readme_chapters(root):
        if ch in REFERENCE_CHAPTERS:
            continue
        n = fenced.get(ch, 0)
        if n < MIN_DIAGRAMS_PER_CHAPTER:
            n += sources.get(ch, 0)
        if n < MIN_DIAGRAMS_PER_CHAPTER:
            problems.append("%s: %d diagram(s), STYLE-GUIDE section 2 wants >= %d"
                            % (ch, n, MIN_DIAGRAMS_PER_CHAPTER))
    for b in blocks:
        if b["type"] is None:
            problems.append("%s:%d: first line names no known diagram type"
                            % (b["file"], b["line"]))
    for p in problems:
        print(p)
    print("checked %d chapter READMEs; %d problem(s)"
          % (len(readme_chapters(root)), len(problems)))
    return 1 if problems else 0


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
