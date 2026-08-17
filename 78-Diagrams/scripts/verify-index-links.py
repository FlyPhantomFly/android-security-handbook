#!/usr/bin/env python3
# 78-Diagrams/scripts/verify-index-links.py
#
# PURPOSE
#   Resolve EVERY relative link in this chapter on disk, and check that the
#   heading anchor it points at actually exists in the target file.
#
#   This script exists because of a specific, measured defect. Chapter 75
#   generated its question index into `references/` and emitted links of the form
#   `../NN-Chapter/README.md`. A file in `references/` is TWO levels below the
#   repository root, so the correct prefix is `../../`. The result was 1,495 dead
#   links, and they survived for months because the repository-wide checker had a
#   "forward reference" exemption that swallowed exactly this shape of failure.
#
#   The lesson is not "be careful with ../". The lesson is that a generated link
#   must be verified by RESOLVING it, not by reading it. Eyes cannot count `../`.
#
# WHAT IT CHECKS
#   1. The target path exists on disk.
#   2. If the link carries a `#anchor`, some heading in the target file produces
#      that anchor under GitHub's slug algorithm.
#   3. Reports, separately, links that point outside the repository root — which
#      is what an off-by-one `../` count looks like when it escapes upward.
#
# WHAT IT DOES NOT CHECK
#   External http(s) URLs. Those are not resolvable offline and a network check
#   would make this script non-deterministic.
#
# USAGE
#   # check every markdown file in chapter 78 (the default)
#   python3 -B scripts/verify-index-links.py
#
#   # check specific files
#   python3 -B scripts/verify-index-links.py references/diagram-index.md
#
#   # check the whole repository
#   python3 -B scripts/verify-index-links.py --all
#
#   # list every checked link, not just the broken ones
#   python3 -B scripts/verify-index-links.py --verbose
#
#   Run with -B so no __pycache__ lands in the repository.
#
# WAS THIS EXECUTED?
#   YES, repeatedly. Final run against chapter 78 on 2026-08-16, CPython 3.13.3,
#   Windows 11, after every generated artefact and every hand-written file was in
#   place:
#
#       13 file(s); 1801 relative link(s) resolved;
#       1 external link(s) skipped; 0 problem(s)
#
#   It earned its place three times over. Every one of the following was a REAL
#   defect that this script caught and nothing else would have:
#     1. github_anchor() stripped underscores -> 18 phantom broken anchors, in
#        headings such as `string_id_item`.
#     2. github_anchor() collapsed runs of whitespace -> every em-dashed heading
#        resolved to a single hyphen where GitHub emits two.
#     3. FENCE_RE was not anchored to end-of-line -> a paragraph BEGINNING with
#        backticks opened a phantom fence and hid every heading after it, giving
#        20 more false reports.
#   Numbers 1 and 3 were false positives and number 2 was a false negative --
#   which is exactly why a link checker must be run against a file whose correct
#   answer you already know.
#
# KNOW WHAT THIS CANNOT TELL YOU
#   Fixing defect 2 made this file's github_anchor() a COPY of the one in
#   `diagram-census.py`. From that moment this script could no longer detect an
#   error in the slug ALGORITHM: it computes the expected anchor with the same
#   function the generator used to write it, so the two agree by construction.
#   It still catches a wrong path, a missing file and a renamed heading -- but on
#   the algorithm itself it is a mirror, and a mirror reports 0 problems forever.
#
#   For that layer, use `76-CheatSheets/scripts/check-anchors.py`, which shares
#   no code with any generator, slugs from GitHub's own rule, and resolves every
#   anchor in the repository rather than only this chapter's. Run on 2026-08-17
#   it confirmed both index files here: 0 broken anchors.
#
# EXIT STATUS
#   0 if every link resolves; 1 otherwise.

import argparse
import os
import re
import sys

# Markdown inline links: [text](target). Reference-style links and bare autolinks
# are not used by the generators in this chapter, and a link inside a code fence
# is not a link, so fenced regions are skipped.
LINK_RE = re.compile(r"\[(?:[^\]\[]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
# A fence line is a WHOLE line of backticks plus an optional info string. Anchoring
# with $ is load-bearing: without it, a paragraph that merely BEGINS with backticks
# was treated as opening a fence, and every heading after it vanished from the
# anchor table. That produced 20 phantom "no such anchor" reports in this chapter.
FENCE_RE = re.compile(r"^\s*(`{3,})\s*([A-Za-z0-9_-]*)\s*$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR_RE = re.compile(r'<a\s+[^>]*(?:name|id)\s*=\s*["\']([^"\']+)["\']', re.I)

SKIP_SCHEMES = ("http://", "https://", "mailto:", "ftp://", "data:", "tel:")


def read_utf8(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        sys.stderr.write("warning: BOM in %s\n" % path)
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace")


def github_anchor(text):
    text = text.strip().lower()
    text = re.sub(r"`", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)   # links keep their text
    # Strip bold/italic asterisks only. NOT underscores: GitHub keeps them, and
    # this repository is full of headings like `string_id_item`. Stripping `_`
    # here silently mangled 18 anchors on the first run of this script.
    text = re.sub(r"\*", "", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    # ONE hyphen per whitespace character, not per RUN of whitespace. GitHub
    # deletes punctuation and then substitutes each remaining space, so a heading
    # containing " — " becomes "--". Collapsing runs here produced a single
    # hyphen, which silently disagreed with every em-dashed heading in this
    # repository. Ground truth: hand-written tables of contents in the chapters.
    return re.sub(r"\s", "-", text)


_anchor_cache = {}


def anchors_of(path):
    """Every anchor a markdown file offers, as GitHub would generate them.
    Duplicate headings get -1, -2 suffixes, exactly as GitHub does."""
    if path in _anchor_cache:
        return _anchor_cache[path]
    found = set()
    seen = {}
    fence = None
    try:
        text = read_utf8(path)
    except OSError:
        _anchor_cache[path] = found
        return found
    for line in text.replace("\r\n", "\n").split("\n"):
        fm = FENCE_RE.match(line)
        if fm:
            n = len(fm.group(1))
            if fence is None:
                fence = n
            elif n >= fence and not fm.group(2):
                fence = None
            continue
        if fence is not None:
            continue
        hm = HEADING_RE.match(line)
        if hm:
            base = github_anchor(hm.group(2))
            count = seen.get(base, 0)
            seen[base] = count + 1
            found.add(base if count == 0 else "%s-%d" % (base, count))
        for am in HTML_ANCHOR_RE.finditer(line):
            found.add(am.group(1))
    _anchor_cache[path] = found
    return found


def links_in(path):
    """Yield (line_number, target) for every inline link outside a code fence."""
    fence = None
    for i, line in enumerate(read_utf8(path).replace("\r\n", "\n").split("\n"), 1):
        fm = FENCE_RE.match(line)
        if fm:
            n = len(fm.group(1))
            if fence is None:
                fence = n
            elif n >= fence and not fm.group(2):
                fence = None
            continue
        if fence is not None:
            continue
        for m in LINK_RE.finditer(line):
            yield i, m.group(1)


def check_file(path, root, verbose=False):
    problems = []
    checked = 0
    skipped = 0
    base = os.path.dirname(os.path.abspath(path))
    for lineno, target in links_in(path):
        if target.startswith(SKIP_SCHEMES):
            skipped += 1
            continue
        if target.startswith("#"):
            anchor = target[1:]
            if anchor and anchor not in anchors_of(os.path.abspath(path)):
                problems.append("%s:%d: no such anchor in this file: %s"
                                % (rel(path, root), lineno, target))
            checked += 1
            continue
        frag = ""
        if "#" in target:
            target, frag = target.split("#", 1)
        if not target:
            skipped += 1
            continue
        resolved = os.path.normpath(os.path.join(base, target.replace("/", os.sep)))
        checked += 1
        if not os.path.commonpath([os.path.abspath(root), resolved]) == \
                os.path.abspath(root):
            problems.append("%s:%d: ESCAPES the repository root (too many '../'): %s"
                            % (rel(path, root), lineno, target))
            continue
        if not os.path.exists(resolved):
            problems.append("%s:%d: target does not exist: %s  ->  %s"
                            % (rel(path, root), lineno, target, rel(resolved, root)))
            continue
        if frag and resolved.lower().endswith(".md"):
            if frag not in anchors_of(resolved):
                problems.append("%s:%d: target exists but has no anchor '#%s': %s"
                                % (rel(path, root), lineno, frag, target))
                continue
        if verbose:
            print("ok   %s:%d  %s" % (rel(path, root), lineno, target))
    return checked, skipped, problems


def rel(path, root):
    try:
        return os.path.relpath(os.path.abspath(path),
                               os.path.abspath(root)).replace(os.sep, "/")
    except ValueError:
        return path


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    chapter = os.path.abspath(os.path.join(here, ".."))
    root = os.path.abspath(os.path.join(chapter, ".."))

    ap = argparse.ArgumentParser(description="Resolve every relative link on disk.")
    ap.add_argument("files", nargs="*", help="markdown files (default: all of chapter 78)")
    ap.add_argument("--root", default=root)
    ap.add_argument("--all", action="store_true",
                    help="check every .md file in the repository, not just chapter 78")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.files:
        targets = [os.path.abspath(f) for f in args.files]
    else:
        scan_root = args.root if args.all else chapter
        targets = []
        for dirpath, dirnames, filenames in os.walk(scan_root):
            dirnames[:] = [d for d in sorted(dirnames)
                           if d not in (".git", "node_modules", "__pycache__")]
            for fn in sorted(filenames):
                if fn.lower().endswith(".md"):
                    targets.append(os.path.join(dirpath, fn))

    total_checked = total_skipped = 0
    all_problems = []
    for t in targets:
        c, s, p = check_file(t, args.root, args.verbose)
        total_checked += c
        total_skipped += s
        all_problems.extend(p)

    for p in all_problems:
        print(p)
    print("%d file(s); %d relative link(s) resolved; %d external link(s) skipped; "
          "%d problem(s)" % (len(targets), total_checked, total_skipped,
                             len(all_problems)))
    return 1 if all_problems else 0


if __name__ == "__main__":
    sys.exit(main())
