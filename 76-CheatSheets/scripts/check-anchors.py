#!/usr/bin/env python3
# 76-CheatSheets/scripts/check-anchors.py
#
# PURPOSE
#   Resolve every in-page anchor link in this repository's markdown -- the
#   `](path#fragment)` and `](#fragment)` forms -- against the anchor set GitHub
#   actually generates for the target file.
#
#   THIS CHECK HAD NEVER RUN. The repository's own link sweep -- the one that
#   reports "broken=0" -- splits every target on `#` and resolves only the path
#   half, so a link to a heading that does not exist has always passed.
#
#   THE DEFECT SHAPE: A CHECKER THAT ANSWERS A NARROWER QUESTION THAN THE ONE IT
#   APPEARS TO ANSWER. This repository's tooling has now produced it three times,
#   and the first two are worth stating in full because they are why this file
#   exists at all:
#
#     1. THE `forward` LINK EXEMPTION HID 1,512 BROKEN LINKS. The link check had
#        two buckets: `broken` for a dead link, and `forward` for a link naming a
#        chapter directory that did not exist yet -- a legitimate exemption when
#        it was written, because most chapters genuinely were unwritten and the
#        deliberate forward references would have drowned the signal. The bug is
#        that `forward` never re-asked whether the target was STILL unwritten.
#        Once a chapter shipped, every wrong path pointing at it kept landing in
#        the excused bucket. The count reached 1,512. The cause was almost always
#        one line of relative path: a file in `references/` or `labs/` is TWO
#        levels below the repository root, so `../16-JNI/README.md` resolves
#        inside the chapter and `../../16-JNI/README.md` is correct. 1,495 of the
#        1,512 came from three GENERATED index files, so the defect was fixed at
#        the generator and the files rebuilt -- never patched in the output. The
#        bucket now requires the target chapter to have no README, and `forward`
#        fell from 1,520 to 8.
#
#     2. THE BOM CHECK MISSED EVERY BOM, BECAUSE A BOM IS VALID UTF-8. The
#        verifier decoded with a strict UTF-8 decoder, which throws on INVALID
#        bytes -- but `EF BB BF` decodes cleanly to U+FEFF, so ten BOM-carrying
#        files in `03`, `05`, `12`, `34` and `45` passed silently against a
#        BOM-less standard. A VALIDITY check is not a CONFORMANCE check: "it
#        decodes" and "it matches our convention" are different questions, and
#        only the first was being asked. This script now reports a BOM column of
#        its own for the same reason.
#
#   The general rule both cost: EVERY EXEMPTION NEEDS AN EXPIRY CONDITION THAT
#   THE TOOL EVALUATES, not a comment explaining when it applies. An exception
#   category that does not re-check its own precondition becomes the place where
#   defects accumulate silently -- and the number it prints goes UP for a reason
#   that looks benign.
#
# WAS THIS EXECUTED?
#   YES. First run against this repository on 2026-08-17, CPython 3.13.3,
#   Windows 11, Git Bash:
#
#       markdown files scanned              :    826
#       headings slugged                    :  22109
#       links carrying a fragment           :   7668
#       BROKEN fragments                    :    273
#
#   230 of those 273 were in ONE generated file, `references/cheatsheet-index.md`,
#   from one defect in `build-cheatsheet-index.py`'s slugger, and 2 more came from
#   the same class of defect in `78-Diagrams/scripts/diagram-census.py`. A
#   generated file is never patched; the generator is fixed and the file rebuilt.
#   The remaining 41 were hand-written and were repaired one at a time.
#
#   Re-run before quoting any figure here. The counts move whenever a chapter is
#   edited, and they moved twice during the session that wrote this file.
#
# WHY A SEPARATE SLUGGER, AND WHY IT IS NOT "OBVIOUS"
#   GitHub does not slug the raw heading source. It renders the heading to HTML,
#   takes the text content, and slugs that. Four consequences this repository has
#   actually been bitten by:
#
#     1. AN EM-DASH VANISHES; IT DOES NOT BECOME A HYPHEN. `## 3.8 Flags — x`
#        slugs to `38-flags--x`: the dash is deleted, and the two SPACES that
#        surrounded it each become a hyphen. Naive sluggers collapse whitespace
#        runs (`\s+` -> `-`) and lose one of those hyphens. This single mistake
#        was 215 of the 273 broken anchors above.
#
#     2. SYMBOLS ARE DELETED TOO, NOT JUST PUNCTUATION. `→`, `⚠`, `×` and every
#        emoji are removed, and a heading that STARTS with one therefore anchors
#        at a LEADING HYPHEN -- `## ⚠ Prose-promised files` is
#        `#-prose-promised-files`. See the note above NON_SLUG_RE: getting this
#        backwards is how a checker "corrects" links that were already right.
#
#     3. LINK AND CODE SYNTAX IS RENDERED AWAY, NOT DELETED. `## See [docs](url)`
#        slugs from the text `See docs`, not from `See docs url`. Slugging the
#        raw source drags the URL into the anchor.
#
#     4. DUPLICATE HEADINGS GET `-1`, `-2` SUFFIXES IN DOCUMENT ORDER, and the
#        FIRST one is unsuffixed. A file with three `## Summary` headings owns
#        `#summary`, `#summary-1`, `#summary-2`. The counter runs over EVERY
#        heading level, not per level. Ignore this and every link to the second
#        one is silently dead.
#
#   A `§3.1`-style cross-reference in prose is NOT an anchor and is not checked.
#   Only `](...#...)` and reference definitions are.
#
# USAGE
#   # the whole repository (default: two levels above this script)
#   python3 -B scripts/check-anchors.py
#
#   # one chapter, or one file
#   python3 -B scripts/check-anchors.py --path ../47-Authentication
#
#   # every anchor a file offers, in document order -- the fixing tool
#   python3 -B scripts/check-anchors.py --list-anchors ../25-Binder/README.md
#
#   # what does THIS heading slug to?
#   python3 -B scripts/check-anchors.py --slug '3.8 Flags — `--disable-verity`'
#
#   # machine-readable, and counts-only
#   python3 -B scripts/check-anchors.py --format json
#   python3 -B scripts/check-anchors.py --stats
#
#   # also report links whose FILE half does not resolve (the older, weaker check)
#   python3 -B scripts/check-anchors.py --files-too
#
#   # 55 cases covering every rule above; run it after touching the slugger
#   python3 -B scripts/check-anchors.py --self-test
#
#   Run with -B so no __pycache__ lands in the repository.
#
# EXIT STATUS
#   0 when every fragment resolves. 1 when any does not (and 1 from --self-test
#   on any failing case, and from --files-too when a file half dangles). 2 on a
#   usage error.

import argparse
import json
import os
import re
import sys
import unicodedata
from urllib.parse import unquote

# --- the slugger -----------------------------------------------------------

# GitHub's rule is a WHITELIST OF SURVIVORS, not a list of punctuation to strip:
# keep word characters, the hyphen and the literal space; delete everything else.
# GitHub's own filter is
#
#     id.gsub(/[^\p{Word}\- ]/u, '').tr(' ', '-')
#
# and `github-slugger`, the published reference implementation, generates a
# character class equivalent to it.
#
# THE TEMPTING WRONG ANSWER IS A PUNCTUATION LIST -- and it was the first answer
# this script shipped, for one afternoon. Under a punctuation list `->` (U+2192),
# `!` (U+26A0), `x` (U+00D7) and every emoji SURVIVE into the slug, because they
# are symbols rather than punctuation. They do not survive. GitHub deletes them,
# and this repository proves it: `53-Frida/README.md` hand-writes
#
#     [the callout at the top of this chapter](#-read-this-before-you-install-…)
#
# for its own `## <warning sign> Read this before you install anything: ...`
# heading, and the link works on GitHub today -- two of them do, at lines 2524
# and 3085, against the heading at line 20.
# The symbol is gone and the space that followed it is the LEADING HYPHEN. That
# leading hyphen is the fingerprint of a symbol-led heading, and it is the same
# reason `## <rocket> Getting started` anchors at `#-getting-started`.
#
# Believing the punctuation list cost a full pass over this repository: it made
# 30 correct links look broken and, worse, it "corrected" one that was right.
# A slugger is only worth what it was validated against -- see --self-test.
#
# Two survivors a naive class gets wrong in the other direction: `_` is a word
# character and stays (this repo is full of `string_id_item`), and `-` stays, so
# a heading whose text begins `-keepattributes` keeps that hyphen AND gains
# another from the space before it.
NON_SLUG_RE = re.compile(r"[^\w\- ]", re.UNICODE)


def slug(text):
    r"""Lower-case, delete every character that is not a word character, a hyphen
    or a space, then turn EACH space into ONE hyphen.

    Two traps, both of which this repository has shipped:

      * NO WHITESPACE COLLAPSING. `re.sub(r"\s+", "-", ...)` is wrong. GitHub
        deletes the em-dash in `A - B` first, leaving two ADJACENT spaces, and
        substitutes each one: `a--b`. Collapsing gives `a-b` and a dead jump.
        This defect alone accounted for 215 broken anchors here.
      * A TAB IS DELETED, NOT HYPHENATED. It is not a word character and it is
        not the literal space character, so it falls to the first rule. That is
        why the substitution below is `.replace(" ", "-")` and never `\s`."""
    return NON_SLUG_RE.sub("", text.lower()).replace(" ", "-")


class Slugger(object):
    """github-slugger's stateful `slug()`: first occurrence unsuffixed, then
    `-1`, `-2`, ... in document order."""

    def __init__(self):
        self.seen = {}

    def add(self, text):
        base = slug(text)
        result = base
        while result in self.seen:
            self.seen[base] += 1
            result = "%s-%d" % (base, self.seen[base])
        self.seen[result] = 0
        return result


# --- heading source -> rendered text ---------------------------------------

CODE_SPAN_RE = re.compile(r"(`+)(.+?)\1", re.DOTALL)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
HTML_TAG_RE = re.compile(r"</?[A-Za-z][^<>]*>")
IMAGE_RE = re.compile(r"!\[([^\]]*)\]\([^()]*\)")
INLINE_LINK_RE = re.compile(r"\[([^\]]*)\]\([^()]*\)")
REF_LINK_RE = re.compile(r"\[([^\]]*)\]\[[^\]]*\]")
AUTOLINK_RE = re.compile(r"<((?:https?|mailto):[^>]+)>")
FOOTNOTE_RE = re.compile(r"\[\^[^\]]*\]")


def render_inline(text):
    """Approximate CommonMark inline rendering closely enough to slug a heading:
    code spans keep their LITERAL content, link and image syntax collapses to its
    text, HTML is dropped, emphasis markers are dropped.

    Code spans are pulled out FIRST and put back LAST, so `**` inside `` ` ``
    survives as two literal asterisks (which the slugger then deletes anyway --
    but `_` inside a code span does NOT, and that is the case that matters)."""
    spans = []

    def stash(m):
        spans.append(m.group(2).strip())
        return "\x00%d\x00" % (len(spans) - 1)

    text = HTML_COMMENT_RE.sub("", text)
    text = CODE_SPAN_RE.sub(stash, text)
    text = AUTOLINK_RE.sub(r"\1", text)
    text = FOOTNOTE_RE.sub("", text)
    for _ in range(4):                      # nested link text, e.g. [**a**](x)
        new = IMAGE_RE.sub(r"\1", text)
        new = INLINE_LINK_RE.sub(r"\1", new)
        new = REF_LINK_RE.sub(r"\1", new)
        if new == text:
            break
        text = new
    text = HTML_TAG_RE.sub("", text)
    # Emphasis. `*` and `~` are deleted by the slugger regardless, so only the
    # underscore forms change the answer -- but strip all of them for --slug.
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"__(.+?)__", r"\1", text)
    text = re.sub(r"~~(.+?)~~", r"\1", text)
    text = re.sub(r"\*(.+?)\*", r"\1", text)
    text = re.sub(r"(?<![0-9A-Za-z_])_(\S(?:.*?\S)?)_(?![0-9A-Za-z_])", r"\1", text)
    text = re.sub(r"\\([!-/:-@\[-`{-~])", r"\1", text)      # backslash escapes

    def unstash(m):
        return spans[int(m.group(1))]

    text = re.sub(r"\x00(\d+)\x00", unstash, text)
    return text.strip()


ATX_RE = re.compile(r"^(?P<indent>[ ]{0,3})(?P<hashes>#{1,6})(?:[ \t]+(?P<text>.*?))?[ \t]*$")
TRAILING_HASH_RE = re.compile(r"(?:^|[ \t])#+[ \t]*$")
FENCE_OPEN_RE = re.compile(r"^(?P<indent>[ ]{0,3})(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
ANCHOR_TAG_RE = re.compile(r"""<a\s[^>]*name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
ID_ATTR_RE = re.compile(r"""<[a-z][^>]*\sid\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def heading_text(raw):
    """Strip the trailing closing-hash sequence GitHub allows: `## Foo ##`."""
    return TRAILING_HASH_RE.sub("", raw).strip()


# --- file scanning ---------------------------------------------------------

def read_utf8(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    bom = raw.startswith(b"\xef\xbb\xbf")
    if bom:
        raw = raw[3:]
    return raw.decode("utf-8"), bom


INLINE_CODE_MASK_RE = re.compile(r"(`+)(?:.*?)\1")


def mask_inline_code(line):
    """Blank out inline code spans so a path inside backticks is not read as a
    link. Length is preserved so column numbers stay honest."""
    return INLINE_CODE_MASK_RE.sub(lambda m: " " * len(m.group(0)), line)


LINK_RE = re.compile(
    r"\]\(\s*(?:<(?P<angle>[^>]*)>|(?P<bare>[^()\s]+))"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^()]*\)))?\s*\)"
)
REF_DEF_RE = re.compile(
    r"^[ ]{0,3}\[(?P<label>[^\]]+)\]:\s*(?:<(?P<angle>[^>]*)>|(?P<bare>\S+))"
)


class MarkdownFile(object):
    def __init__(self, path, root, text=None):
        """`text` lets a GENERATOR check the file it is about to write without
        writing it first -- `build-cheatsheet-index.py --verify-links` renders
        each grouping into memory and resolves its own same-file anchors."""
        self.path = path
        self.rel = os.path.relpath(path, root).replace("\\", "/")
        if text is None:
            text, self.bom = read_utf8(path)
        else:
            self.bom = False
        self.lines = text.split("\n")
        self.anchors = []       # slugs, in document order
        self.headings = []      # (lineno, level, rendered text, slug)
        self.links = []         # (lineno, raw target)
        self._parse()

    def _parse(self):
        slugger = Slugger()
        fence = None            # (char, length, indent) while inside a fence
        in_comment = False
        for lineno, line in enumerate(self.lines, 1):
            # ---- fenced code -------------------------------------------
            if fence is not None:
                m = FENCE_OPEN_RE.match(line)
                if m and m.group("fence")[0] == fence[0] \
                        and len(m.group("fence")) >= fence[1] \
                        and not m.group("info").strip():
                    fence = None
                continue
            m = FENCE_OPEN_RE.match(line)
            if m and "`" not in m.group("info"):
                fence = (m.group("fence")[0], len(m.group("fence")), m.group("indent"))
                continue

            # ---- html comments (may span lines) -------------------------
            work = line
            if in_comment:
                end = work.find("-->")
                if end < 0:
                    continue
                work = " " * (end + 3) + work[end + 3:]
                in_comment = False
            work = HTML_COMMENT_RE.sub(lambda mm: " " * len(mm.group(0)), work)
            start = work.find("<!--")
            if start >= 0:
                work = work[:start]
                in_comment = True

            # ---- headings ------------------------------------------------
            hm = ATX_RE.match(work)
            if hm and hm.group("hashes"):
                raw = hm.group("text") or ""
                rendered = render_inline(heading_text(raw))
                s = slugger.add(rendered)
                self.anchors.append(s)
                self.headings.append((lineno, len(hm.group("hashes")), rendered, s))
                continue

            # ---- explicit html anchors -----------------------------------
            for am in ANCHOR_TAG_RE.finditer(work):
                self.anchors.append(am.group(1))
            for im in ID_ATTR_RE.finditer(work):
                self.anchors.append(im.group(1))

            # ---- links ---------------------------------------------------
            masked = mask_inline_code(work)
            for lm in LINK_RE.finditer(masked):
                self.links.append((lineno, lm.group("angle") or lm.group("bare") or ""))
            rd = REF_DEF_RE.match(masked)
            if rd:
                self.links.append((lineno, rd.group("angle") or rd.group("bare") or ""))

    @property
    def anchor_set(self):
        return set(self.anchors)


# --- resolution ------------------------------------------------------------

SKIP_SCHEMES = ("http://", "https://", "mailto:", "ftp://", "tel:", "data:", "//")


def normalise_fragment(frag):
    """A fragment in a URL is percent-encoded and, on GitHub, matched against the
    slug after Unicode NFC. Both halves are normalised the same way."""
    frag = unquote(frag)
    return unicodedata.normalize("NFC", frag)


def collect_files(root, path_filter):
    out = []
    if os.path.isfile(path_filter):
        return [os.path.abspath(path_filter)]
    for dirpath, dirnames, filenames in os.walk(path_filter):
        dirnames[:] = [d for d in sorted(dirnames)
                       if d not in (".git", "node_modules", "__pycache__", ".venv")]
        for name in sorted(filenames):
            if name.lower().endswith(".md"):
                out.append(os.path.join(dirpath, name))
    return out


def check(root, path_filter, files_too=False):
    root = os.path.abspath(root)
    scan = [os.path.abspath(p) for p in collect_files(root, os.path.abspath(path_filter))]

    # Every .md in the REPO is a potential target, not just the scanned subset.
    universe = {}
    for p in collect_files(root, root):
        ap = os.path.abspath(p)
        try:
            universe[os.path.normcase(ap)] = MarkdownFile(ap, root)
        except UnicodeDecodeError as exc:
            sys.stderr.write("error: %s is not valid UTF-8 (%s)\n" % (ap, exc))

    findings = []
    stats = {"files": len(universe), "scanned": len(scan), "headings": 0,
             "anchor_links": 0, "file_links": 0, "broken_anchors": 0,
             "broken_files": 0, "skipped_nonmd": 0, "boms": 0}
    for mf in universe.values():
        stats["headings"] += len(mf.headings)
        if mf.bom:
            stats["boms"] += 1

    for path in scan:
        mf = universe.get(os.path.normcase(path))
        if mf is None:
            continue
        here = os.path.dirname(path)
        for lineno, target in mf.links:
            if not target or target.startswith(SKIP_SCHEMES):
                continue
            if "#" in target:
                pathpart, frag = target.split("#", 1)
            else:
                pathpart, frag = target, None

            resolved = None
            if pathpart:
                stats["file_links"] += 1
                resolved = os.path.normpath(os.path.join(here, unquote(pathpart)))
                if os.path.isdir(resolved):
                    readme = os.path.join(resolved, "README.md")
                    resolved = readme if os.path.isfile(readme) else resolved
                if not os.path.exists(resolved):
                    stats["broken_files"] += 1
                    if files_too:
                        findings.append({
                            "kind": "file", "file": mf.rel, "line": lineno,
                            "target": target,
                            "reason": "path does not exist: %s"
                                      % os.path.relpath(resolved, root).replace("\\", "/"),
                            "did_you_mean": [],
                        })
                    continue
            else:
                resolved = path

            if frag is None or frag == "":
                continue
            stats["anchor_links"] += 1

            tgt = universe.get(os.path.normcase(os.path.abspath(resolved)))
            if tgt is None:
                stats["skipped_nonmd"] += 1
                continue

            want = normalise_fragment(frag)
            have = {normalise_fragment(a) for a in tgt.anchors}
            if want in have:
                continue
            stats["broken_anchors"] += 1
            findings.append({
                "kind": "anchor", "file": mf.rel, "line": lineno,
                "target": target,
                "reason": "no anchor '%s' in %s" % (want, tgt.rel),
                "did_you_mean": suggest(want, tgt.anchors),
            })
    return findings, stats, universe


def suggest(want, anchors, limit=3):
    """Cheap similarity: shared prefix length, then shared token count. Enough to
    turn a report line into a fix without opening the target file."""
    def score(a):
        n = 0
        for x, y in zip(want, a):
            if x != y:
                break
            n += 1
        toks_w, toks_a = set(want.split("-")), set(a.split("-"))
        return (n, len(toks_w & toks_a), -abs(len(a) - len(want)))
    ranked = sorted(set(anchors), key=score, reverse=True)
    out = []
    for a in ranked[:limit]:
        if score(a)[0] >= 3 or score(a)[1] >= 2:
            out.append(a)
    return out


# --- self test -------------------------------------------------------------

SELF_TEST = [
    # (heading source, expected slug)
    ("Introduction", "introduction"),
    ("1. Introduction", "1-introduction"),
    ("2. High-Level Architecture", "2-high-level-architecture"),
    ("Source Code Walkthrough (AOSP)", "source-code-walkthrough-aosp"),
    ("3.14 Parcel format", "314-parcel-format"),
    ("snake_case_survives", "snake_case_survives"),
    ("UPPER Case", "upper-case"),
    ("trailing spaces   ", "trailing-spaces"),
    # the em-dash rule: dash deleted, BOTH surrounding spaces hyphenated
    ("3.8 Flags — x", "38-flags--x"),
    ("A — B — C", "a--b--c"),
    ("A – B", "a--b"),                      # en-dash, same rule
    ("A -- B", "a----b"),                   # literal double hyphen survives
    ("3.8 Flags — `--disable-verity`", "38-flags----disable-verity"),
    # code spans render to their literal content
    ("`adb shell`", "adb-shell"),
    ("The `IIntentReceiver` seam", "the-iintentreceiver-seam"),
    ("``a ` b``", "a--b"),
    # emphasis
    ("**Bold** heading", "bold-heading"),
    ("*Italic* heading", "italic-heading"),
    ("_Italic_ heading", "italic-heading"),
    ("__Bold__ heading", "bold-heading"),
    ("~~Struck~~ heading", "struck-heading"),
    ("intra_word_underscores", "intra_word_underscores"),
    # links render to their text, not their URL
    ("See [docs](https://example.com/x)", "see-docs"),
    ("[`53-Frida`](../53-Frida/README.md)", "53-frida"),
    ("![img](a.png) caption", "img-caption"),
    ("[**bold link**](x)", "bold-link"),
    # html and comments
    ("Foo <br> bar", "foo--bar"),
    ("Foo <!-- note --> bar", "foo--bar"),
    # punctuation
    ("What? Why! Yes.", "what-why-yes"),
    ("a/b/c", "abc"),
    ("100% coverage", "100-coverage"),
    ("C++ and C#", "c-and-c"),
    ("uid:1000", "uid1000"),
    ("§3.1 Section signs", "31-section-signs"),
    ("\"quoted\" and 'quoted'", "quoted-and-quoted"),
    ("smart “quotes”", "smart-quotes"),
    ("a  b", "a--b"),                       # double space -> double hyphen
    ("a\tb", "ab"),                         # TAB is DELETED, not hyphenated
    ("Ünïcödé Léttérs", "ünïcödé-léttérs"),
    ("naïve — café", "naïve--café"),
    ("trailing hashes ##", "trailing-hashes"),
    ("escaped \\* star", "escaped--star"),
    # SYMBOLS ARE DELETED, NOT KEPT. Every case below was wrong in the first
    # version of this file, which used a punctuation list instead of a
    # word-character whitelist. Ground truth for the first one is
    # `53-Frida/README.md`, whose hand-written links at lines 2524 and 3085
    # resolve against its symbol-led heading at line 20 on GitHub today.
    ("⚠ Read this before you install anything: `frida-server` does not run on every image",
     "-read-this-before-you-install-anything-frida-server-does-not-run-on-every-image"),
    ("🚀 Getting started", "-getting-started"),
    ("✅ Complete", "-complete"),
    ("emoji 🔒 heading", "emoji--heading"),
    ("A → B", "a--b"),
    ("`System.loadLibrary` → `JNI_OnLoad`", "systemloadlibrary--jni_onload"),
    ("Static ↔ dynamic address arithmetic", "static--dynamic-address-arithmetic"),
    ("2 × 3 ÷ 4", "2--3--4"),
    ("§ and ¶ and ©", "-and--and-"),
    # ...and the corresponding negative: a WORD character that looks decorative
    # is kept. `_` above all -- this repo is full of `string_id_item`.
    ("3.8 `-keepattributes` — the attribute reference",
     "38--keepattributes--the-attribute-reference"),
]

DUP_TEST = [
    (["Summary", "Summary", "Summary", "Other", "Summary"],
     ["summary", "summary-1", "summary-2", "other", "summary-3"]),
    # The counter lives on the BASE slug, and the suffixed candidate is re-tested
    # against everything already taken -- so a heading that literally spells the
    # suffix out is stepped over rather than collided with.
    (["A", "A-1", "A", "A"], ["a", "a-1", "a-2", "a-3"]),
    (["Summary", "Summary-1", "Summary"], ["summary", "summary-1", "summary-2"]),
]


def self_test():
    failures = 0
    total = 0
    for src, want in SELF_TEST:
        total += 1
        got = slug(render_inline(heading_text(src)))
        if got != want:
            failures += 1
            print("FAIL  %-40r  want %-34r got %r" % (src, want, got))
    for headings, want in DUP_TEST:
        total += 1
        s = Slugger()
        got = [s.add(h) for h in headings]
        if got != want:
            failures += 1
            print("FAIL  dup %r  want %r got %r" % (headings, want, got))
    print("self-test: %d case(s), %d failure(s)" % (total, failures))
    return 1 if failures else 0


# --- reporting -------------------------------------------------------------

def report_text(findings, stats):
    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    for name in sorted(by_file):
        print("")
        print("%s" % name)
        for f in by_file[name]:
            hint = ""
            if f["did_you_mean"]:
                hint = "   did you mean: %s" % ", ".join("#" + a for a in f["did_you_mean"])
            print("  %-6s line %-5d %s" % (f["kind"].upper(), f["line"], f["target"]))
            print("         %s%s" % (f["reason"], hint))
    print("")
    print("-" * 72)
    print("%-34s %6d" % ("markdown files in repository", stats["files"]))
    print("%-34s %6d" % ("files scanned", stats["scanned"]))
    print("%-34s %6d" % ("headings slugged", stats["headings"]))
    print("%-34s %6d" % ("links with a fragment", stats["anchor_links"]))
    print("%-34s %6d" % ("links with a path", stats["file_links"]))
    print("%-34s %6d" % ("fragments into non-markdown", stats["skipped_nonmd"]))
    print("%-34s %6d" % ("files with a UTF-8 BOM", stats["boms"]))
    print("%-34s %6d" % ("BROKEN file paths", stats["broken_files"]))
    print("%-34s %6d" % ("BROKEN anchors", stats["broken_anchors"]))


# --- entry point -----------------------------------------------------------

def main():
    # Windows consoles and redirected pipes default to cp1252 here, and half the
    # headings in this repository contain an em-dash. Report in UTF-8 or the
    # checker dies on its own findings.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, "..", ".."))

    ap = argparse.ArgumentParser(
        description="Resolve every markdown anchor link against GitHub's real slugs.")
    ap.add_argument("--root", default=default_root,
                    help="repository root (default: two levels above this script)")
    ap.add_argument("--path", default=None,
                    help="restrict the scan to this file or directory (default: --root)")
    ap.add_argument("--format", default="text", choices=["text", "json"])
    ap.add_argument("--stats", action="store_true", help="counts only, no findings")
    ap.add_argument("--files-too", action="store_true",
                    help="also report links whose path half does not resolve")
    ap.add_argument("--list-anchors", metavar="FILE", default=None,
                    help="print every anchor FILE offers, in document order")
    ap.add_argument("--slug", metavar="HEADING", default=None,
                    help="print the slug for one heading and exit")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--no-fail", action="store_true",
                    help="always exit 0 (for report generation)")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.slug is not None:
        print(slug(render_inline(heading_text(args.slug))))
        return 0

    if args.list_anchors:
        path = os.path.abspath(args.list_anchors)
        if not os.path.isfile(path):
            sys.stderr.write("error: no such file: %s\n" % path)
            return 2
        mf = MarkdownFile(path, os.path.abspath(args.root))
        for lineno, level, text, s in mf.headings:
            print("%-5d %s %-58s #%s" % (lineno, "#" * level, text[:58], s))
        return 0

    root = os.path.abspath(args.root)
    path_filter = os.path.abspath(args.path) if args.path else root
    if not os.path.exists(path_filter):
        sys.stderr.write("error: no such path: %s\n" % path_filter)
        return 2

    findings, stats, _ = check(root, path_filter, files_too=args.files_too)

    if args.format == "json":
        print(json.dumps({"findings": [] if args.stats else findings,
                          "stats": stats}, indent=2, ensure_ascii=False))
    elif args.stats:
        report_text([], stats)
    else:
        report_text(findings, stats)

    if args.no_fail:
        return 0
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
