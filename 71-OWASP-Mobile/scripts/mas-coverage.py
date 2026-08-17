#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mas-coverage.py -- turn a findings/results list into a MASVS coverage view, and turn
                   several apps' lists into a portfolio heatmap.

WHAT IT DOES
    A coverage table is a set of claims about YOUR OWN WORK, not about the app. Each row
    says "here is what I did and what it showed". This script reads such a table and
    checks that the claims are the kind a second person could verify.

    Given one CSV it prints:

        SUMMARY      per-category counts, and a coverage figure with a stated denominator
        CONTROLS     one row per control: state, evidence, finding, note
        GAPS         controls in the reference catalogue with no row at all
        PROBLEMS     rows that do not support the claim they make

    Given a CSV with an 'app' column and --heatmap it prints a control-by-app matrix,
    marks the rows that fail everywhere as systemic candidates, and lists every empty
    cell -- because at portfolio scale a blank cell is a gap in the assessment, and
    blanks are invisible in a coloured table.

    THE ONE OPINION THIS SCRIPT HOLDS
    A control marked PASS, FAIL or PARTIAL with no evidence reference is not covered. It
    is reported as UNSUBSTANTIATED and excluded from the coverage figure, whatever the
    state column says. That single rule is the difference between a coverage table and a
    wish list, and it is the most common defect in real mobile reports: "no finding" and
    "passed" are different claims, and only the second one needs evidence -- which is
    exactly why the second one is the one people assert without any.

    It also flags RETIRED identifiers. MASVS v1 requirement IDs took the form
    MSTG-<CATEGORY>-<n> and do not resolve against the current standard; v1 additionally
    had an ARCH group that no longer exists. Copying an old identifier forward into a new
    tracker silently corrupts it, so retired IDs are refused rather than translated --
    translation by number is exactly the mistake. Translate by CATEGORY, by hand, after
    re-reading the original finding text.

WHAT THIS IS *NOT* -- the boundary with other chapters
    It does not rate severity, produce a report, or hold a CVSS opinion. The rubric, the
    templates and the engagement checklist belong to 80-Appendix; the severity column
    here is passed through untouched and never computed.

    It does not test anything. Every state in the input was decided by a human, and this
    script only checks that the bookkeeping is honest.

WHAT THIS WILL *NOT* TELL YOU
    - Whether your evidence is any good. It checks that a reference EXISTS, not that the
      artefact behind it supports the conclusion. A row citing an empty file passes here
      and fails in review. Open your own evidence -- lab-02 step 8 makes you do exactly
      that, and most people downgrade at least one PASS.
    - Whether a PASS is true. "Tested and the requirement holds" is a judgement about an
      app; nothing mechanical can make it.
    - Whether your control subset was the right one. A tidy 100% over eight controls you
      chose for their cheapness is worth less than 60% over the ones that mattered.
    - Whether a control identifier is current. The built-in catalogue has a stated
      provenance and may lag the project. Override it with --controls when the standard
      moves, and resolve identifiers at https://mas.owasp.org/.
    - Anything at all about the backend. MASVS is a mobile application standard; scope
      OWASP ASVS separately.
    - Whether a pattern across apps has a shared CAUSE. The heatmap surfaces patterns.
      Turning a pattern into a cause is labs/lab-04-portfolio-heatmap.md step 6, and it
      needs evidence this script never sees.

INPUT FORMAT
    CSV. Lines beginning with '#' are skipped, so a fixture can document itself.

        app       optional. Present => portfolio mode is available
        control   required. MASVS-<CATEGORY>-<n>
        state     required. PASS | FAIL | PARTIAL | NOT-TESTED | BLOCKED | N/A
        evidence  pointer to a stored artefact. REQUIRED for PASS, FAIL, PARTIAL
        finding   finding identifier. Expected whenever state is FAIL
        severity  passed through, never computed
        note      one line, in report voice

HOW TO RUN
    # host -- single app
    python3 mas-coverage.py ../examples/findings-ovaa.csv

    # host -- portfolio heatmap across three apps
    python3 mas-coverage.py ../examples/portfolio-findings.csv --heatmap

    # host -- straight into a report
    python3 mas-coverage.py ../examples/portfolio-findings.csv --heatmap --markdown

    # host -- fail the build if anything is unsubstantiated or missing
    python3 mas-coverage.py results.csv --strict

    # host -- a control catalogue of your own, one "ID|CATEGORY|title" per line
    python3 mas-coverage.py results.csv --controls my-subset.txt

REQUIREMENTS
    Python 3.6+. Standard library only (csv, argparse, textwrap). Output is pure ASCII so
    that a Windows console codepage cannot turn a report into a UnicodeEncodeError.

    The script writes nothing and imports nothing local. Run it as a script so it leaves
    no __pycache__ beside the repository source.

EXIT CODES
    0  ran to completion
    1  --strict was given and the table has unsubstantiated rows, blanks or bad ids
    2  input could not be read or parsed

AUTHORISED TESTING ONLY.
"""

import argparse
import csv
import os
import re
import sys
import textwrap

# ---------------------------------------------------------------------------
#  Control catalogue.
#
#  PROVENANCE: MASVS v2.x control identifiers as published by the OWASP MAS project,
#  with titles PARAPHRASED for testers -- not quotations, and not for pasting into a
#  report as the standard's own words. The identifiers have changed before and may change
#  again; resolve them at https://mas.owasp.org/ and use --controls to override.
# ---------------------------------------------------------------------------

DEFAULT_CONTROLS = [
    ("MASVS-STORAGE-1",    "STORAGE",    "Sensitive data is stored securely"),
    ("MASVS-STORAGE-2",    "STORAGE",    "Sensitive data does not leak by unintended channels"),
    ("MASVS-CRYPTO-1",     "CRYPTO",     "Strong cryptography, used correctly"),
    ("MASVS-CRYPTO-2",     "CRYPTO",     "Sound key management"),
    ("MASVS-AUTH-1",       "AUTH",       "Authentication and authorization enforced server-side"),
    ("MASVS-AUTH-2",       "AUTH",       "Local authentication implemented properly"),
    ("MASVS-AUTH-3",       "AUTH",       "Additional authentication for sensitive operations"),
    ("MASVS-NETWORK-1",    "NETWORK",    "All network traffic secured to current practice"),
    ("MASVS-NETWORK-2",    "NETWORK",    "Identity pinning for developer-controlled endpoints"),
    ("MASVS-PLATFORM-1",   "PLATFORM",   "IPC mechanisms used securely"),
    ("MASVS-PLATFORM-2",   "PLATFORM",   "WebViews used securely"),
    ("MASVS-PLATFORM-3",   "PLATFORM",   "User interface used securely"),
    ("MASVS-CODE-1",       "CODE",       "An up-to-date platform version is required"),
    ("MASVS-CODE-2",       "CODE",       "A mechanism exists for enforcing app updates"),
    ("MASVS-CODE-3",       "CODE",       "No components with known vulnerabilities"),
    ("MASVS-CODE-4",       "CODE",       "Untrusted input validated and sanitised"),
    ("MASVS-RESILIENCE-1", "RESILIENCE", "Platform integrity is validated"),
    ("MASVS-RESILIENCE-2", "RESILIENCE", "Anti-tampering measures"),
    ("MASVS-RESILIENCE-3", "RESILIENCE", "Anti-static-analysis measures"),
    ("MASVS-RESILIENCE-4", "RESILIENCE", "Anti-dynamic-analysis measures"),
    ("MASVS-PRIVACY-1",    "PRIVACY",    "Access to sensitive data and resources minimised"),
    ("MASVS-PRIVACY-2",    "PRIVACY",    "Identification of the user prevented"),
    ("MASVS-PRIVACY-3",    "PRIVACY",    "Transparency about collection and use"),
    ("MASVS-PRIVACY-4",    "PRIVACY",    "User control over their own data"),
]

CATEGORY_ORDER = ["STORAGE", "CRYPTO", "AUTH", "NETWORK",
                  "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]

STATES = ["PASS", "FAIL", "PARTIAL", "NOT-TESTED", "BLOCKED", "N/A"]

STATE_ALIASES = {
    "PASS": "PASS", "PASSED": "PASS", "OK": "PASS",
    "FAIL": "FAIL", "FAILED": "FAIL",
    "PARTIAL": "PARTIAL", "PART": "PARTIAL",
    "NOT-TESTED": "NOT-TESTED", "NOT TESTED": "NOT-TESTED",
    "NOTTESTED": "NOT-TESTED", "EXCLUDED": "NOT-TESTED",
    "BLOCKED": "BLOCKED",
    "N/A": "N/A", "NA": "N/A", "N-A": "N/A", "NOT-APPLICABLE": "N/A",
}

# Glyphs for the heatmap. One character each, so columns stay narrow and a wide
# portfolio still fits an 80-column terminal.
GLYPH = {
    "PASS": "P", "FAIL": "F", "PARTIAL": "~", "NOT-TESTED": ".",
    "BLOCKED": "B", "N/A": "-", "UNSUBSTANTIATED": "!", "MISSING": "?",
}

# States that constitute an assessment of the control, and therefore require evidence.
EVIDENCE_REQUIRED = ("PASS", "FAIL", "PARTIAL")

CONTROL_RE = re.compile(r"^MASVS-([A-Z]+)-(\d+)$")
RETIRED_RE = re.compile(r"^MSTG-([A-Z]+)-(\d+)$", re.IGNORECASE)


# ---------------------------------------------------------------------------
#  Model
# ---------------------------------------------------------------------------

class Row(object):
    __slots__ = ("app", "control", "state", "evidence", "finding", "severity",
                 "note", "lineno", "problem")

    def __init__(self, app, control, state, evidence, finding, severity, note, lineno):
        self.app = app
        self.control = control
        self.state = state
        self.evidence = evidence
        self.finding = finding
        self.severity = severity
        self.note = note
        self.lineno = lineno
        self.problem = None   # set by validate()

    @property
    def effective(self):
        """The state after the evidence rule is applied."""
        if self.problem == "UNSUBSTANTIATED":
            return "UNSUBSTANTIATED"
        return self.state

    @property
    def counts_as_covered(self):
        return self.state in EVIDENCE_REQUIRED and bool(self.evidence)


def norm_state(raw):
    key = " ".join(str(raw or "").split()).upper()
    return STATE_ALIASES.get(key)


def read_rows(path):
    """Return (rows, header_fields, errors)."""
    errors = []
    if path == "-":
        text = sys.stdin.read()
        shown = "<stdin>"
    else:
        if not os.path.isfile(path):
            return None, None, ["no such file: %s" % path]
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        shown = path

    # Strip comment lines before handing to csv, and keep original line numbers.
    lines, numbers = [], []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if not line.strip():
            continue
        lines.append(line)
        numbers.append(i)

    if not lines:
        return None, None, ["%s contains no data rows" % shown]

    reader = csv.DictReader(lines)
    if not reader.fieldnames:
        return None, None, ["%s has no header row" % shown]

    fields = [(f or "").strip().lower() for f in reader.fieldnames]
    for required in ("control", "state"):
        if required not in fields:
            return None, None, [
                "%s: header must contain a '%s' column; found: %s"
                % (shown, required, ", ".join(fields) or "(nothing)")]

    rows = []
    for idx, rec in enumerate(reader):
        lineno = numbers[idx + 1] if idx + 1 < len(numbers) else -1

        def get(name):
            for k, v in rec.items():
                if k and k.strip().lower() == name:
                    return (v or "").strip()
            return ""

        control = get("control")
        if not control:
            errors.append("line %d: empty control identifier; row ignored" % lineno)
            continue
        state = norm_state(get("state"))
        if state is None:
            errors.append(
                "line %d: control %s has state '%s', which is not one of %s. "
                "A typo'd state is how a cell goes blank without anyone noticing, so "
                "the row is ignored rather than guessed at."
                % (lineno, control, get("state"), "/".join(STATES)))
            continue
        rows.append(Row(get("app") or "", control, state, get("evidence"),
                        get("finding"), get("severity"), get("note"), lineno))
    return rows, fields, errors


def validate(rows, catalogue_ids):
    """Annotate rows with problems. Returns a list of (severity, message)."""
    problems = []
    seen = {}
    for r in rows:
        key = (r.app, r.control)
        if key in seen:
            problems.append(("DUPLICATE",
                             "line %d: %s%s appears again (first at line %d). Two states "
                             "for one control is not a coverage table."
                             % (r.lineno, (r.app + " / ") if r.app else "",
                                r.control, seen[key])))
        else:
            seen[key] = r.lineno

        m = CONTROL_RE.match(r.control)
        retired = RETIRED_RE.match(r.control)
        if retired:
            r.problem = "RETIRED"
            problems.append((
                "RETIRED",
                "line %d: '%s' is a MASVS v1 requirement identifier. v1 IDs do not "
                "resolve against the current standard, numbers were not preserved across "
                "the renumbering, and v1's ARCH group no longer exists. The row is NOT "
                "counted. Re-read the original finding text, translate by CATEGORY (%s) "
                "and not by number, and record both forms in your report."
                % (r.lineno, r.control, retired.group(1).upper())))
            continue
        if not m:
            r.problem = "UNKNOWN-ID"
            problems.append((
                "UNKNOWN-ID",
                "line %d: '%s' does not look like a MASVS control identifier "
                "(expected MASVS-<CATEGORY>-<n>). Resolve it at https://mas.owasp.org/ "
                "rather than inventing one -- a wrong control ID in a report is worse "
                "than none." % (r.lineno, r.control)))
            continue
        if m.group(1) not in CATEGORY_ORDER and r.control not in catalogue_ids:
            problems.append((
                "UNKNOWN-CATEGORY",
                "line %d: '%s' names category '%s', which is not one of the eight. If the "
                "standard has gained a category, supply the new catalogue with --controls."
                % (r.lineno, r.control, m.group(1))))

        if r.state in EVIDENCE_REQUIRED and not r.evidence:
            r.problem = "UNSUBSTANTIATED"
            problems.append((
                "UNSUBSTANTIATED",
                "line %d: %s is marked %s with no evidence reference, so it is NOT "
                "counted as covered. '%s' is a claim about your own work; if you cannot "
                "point at an artefact a second person could open, the row is empty."
                % (r.lineno, r.control, r.state, r.state)))
        if r.state == "FAIL" and not r.finding:
            problems.append((
                "NO-FINDING-ID",
                "line %d: %s is marked FAIL with no finding identifier. A failed control "
                "with no finding is a control the report will not mention."
                % (r.lineno, r.control)))
        if r.state in ("NOT-TESTED", "BLOCKED", "N/A") and not r.note:
            problems.append((
                "NO-REASON",
                "line %d: %s is marked %s with no note. NOT-TESTED without a reason is "
                "indistinguishable from forgotten, and BLOCKED without an obstacle is "
                "indistinguishable from EXCLUDED."
                % (r.lineno, r.control, r.state)))
    return problems


# ---------------------------------------------------------------------------
#  Rendering helpers
# ---------------------------------------------------------------------------

def fit(text, width):
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[:width - 3] + "..."


def wrap(text, width, indent=""):
    text = " ".join(str(text).split())
    return textwrap.wrap(text, width=width, initial_indent=indent,
                         subsequent_indent=indent) or [indent]


def esc(s):
    return " ".join(str(s).split()).replace("|", "\\|")


def category_of(control, catalogue):
    for cid, cat, _t in catalogue:
        if cid == control:
            return cat
    m = CONTROL_RE.match(control)
    return m.group(1) if m else "?"


# ---------------------------------------------------------------------------
#  Single-app view
# ---------------------------------------------------------------------------

def render_single(rows, problems, catalogue, path, width, markdown):
    by_control = {r.control: r for r in rows}
    cat_ids = [c[0] for c in catalogue]
    gaps = [c for c in catalogue if c[0] not in by_control]

    assessable = [r for r in rows if r.state != "N/A" and r.problem != "RETIRED"]
    covered = [r for r in assessable if r.counts_as_covered]
    denom = len(assessable) + len(gaps)
    pct = (100.0 * len(covered) / denom) if denom else 0.0

    tally = {}
    for r in rows:
        tally[r.effective] = tally.get(r.effective, 0) + 1

    if markdown:
        out = ["# MASVS coverage -- `%s`" % path, "",
               "| | |", "|---|---|",
               "| Rows | %d |" % len(rows),
               "| Controls in reference catalogue | %d |" % len(catalogue),
               "| Covered (assessed **with evidence**) | %d |" % len(covered),
               "| Coverage | **%.0f%%** of %d assessable controls |" % (pct, denom),
               "| Not applicable | %d |" % tally.get("N/A", 0),
               ""]
        out.append("Coverage counts only rows whose state is PASS, FAIL or PARTIAL "
                   "**and** which carry an evidence reference. `N/A` rows are excluded "
                   "from the denominator; missing rows are included in it.")
        out.append("")
        out.append("## Controls")
        out.append("")
        out.append("| Control | State | Evidence | Finding | Severity | Note |")
        out.append("|---|---|---|---|---|---|")
        for cid, _cat, _title in catalogue:
            r = by_control.get(cid)
            if r is None:
                out.append("| `%s` | **MISSING** | -- | -- | -- | no row in the input |"
                           % cid)
                continue
            out.append("| `%s` | %s | %s | %s | %s | %s |" % (
                cid, r.effective,
                ("`%s`" % esc(r.evidence)) if r.evidence else "**none**",
                esc(r.finding) or "--", esc(r.severity) or "--", esc(r.note) or ""))
        extra = [r for r in rows if r.control not in cat_ids]
        for r in extra:
            out.append("| `%s` | %s | %s | %s | %s | %s |" % (
                r.control, r.effective,
                ("`%s`" % esc(r.evidence)) if r.evidence else "**none**",
                esc(r.finding) or "--", esc(r.severity) or "--",
                esc(r.note) or "not in the reference catalogue"))
        out.append("")
        out += markdown_problems(problems, gaps)
        return "\n".join(out)

    bar, rule = "=" * width, "-" * width
    out = [bar, "  MASVS COVERAGE -- %s" % path, bar]
    out.append("  rows          : %d" % len(rows))
    out.append("  catalogue     : %d controls" % len(catalogue))
    out.append("  covered       : %d  (state in PASS/FAIL/PARTIAL *and* evidence present)"
               % len(covered))
    out.append("  coverage      : %.0f%% of %d assessable controls "
               "(N/A excluded, missing included)" % (pct, denom))
    out.append("  states        : " + ", ".join(
        "%s %d" % (s, tally[s]) for s in
        ["PASS", "FAIL", "PARTIAL", "NOT-TESTED", "BLOCKED", "N/A",
         "UNSUBSTANTIATED"] if s in tally))
    out.append("")

    w_id, w_state, w_ev = 20, 16, 32
    w_note = max(20, width - (w_id + w_state + w_ev + 6))
    out.append("  note and evidence columns are truncated to fit; use --markdown, or")
    out.append("  --width, for the full text of every cell.")
    out.append("")
    out.append(rule)
    out.append("  %-*s %-*s %-*s %s" % (w_id, "CONTROL", w_state, "STATE",
                                        w_ev, "EVIDENCE", "NOTE"))
    out.append(rule)
    last_cat = None
    for cid, cat, _title in catalogue:
        if cat != last_cat:
            out.append("  -- %s" % cat)
            last_cat = cat
        r = by_control.get(cid)
        if r is None:
            out.append("  %-*s %-*s %-*s %s" % (w_id, cid, w_state, "MISSING",
                                                w_ev, "--", "no row in the input"))
            continue
        out.append("  %-*s %-*s %-*s %s" % (
            w_id, cid, w_state, r.effective,
            w_ev, fit(r.evidence or "NONE", w_ev), fit(r.note, w_note)))
    extra = [r for r in rows if r.control not in cat_ids]
    if extra:
        out.append("  -- NOT IN CATALOGUE")
        for r in extra:
            out.append("  %-*s %-*s %-*s %s" % (
                w_id, fit(r.control, w_id), w_state, r.effective,
                w_ev, fit(r.evidence or "NONE", w_ev), fit(r.note, w_note)))
    out.append(rule)
    out.append("")
    out += text_problems(problems, gaps, width)
    return "\n".join(out)


# ---------------------------------------------------------------------------
#  Portfolio view
# ---------------------------------------------------------------------------

def render_heatmap(rows, problems, catalogue, path, width, markdown):
    apps = []
    for r in rows:
        if r.app and r.app not in apps:
            apps.append(r.app)
    if not apps:
        return ("[-] no 'app' column values found. --heatmap needs one row per "
                "(app, control) pair.")

    cell = {}
    for r in rows:
        if r.problem in ("RETIRED", "UNKNOWN-ID"):
            continue          # deliberately leaves a hole; that is the lesson
        cell[(r.app, r.control)] = r

    used = [c for c in catalogue
            if any((a, c[0]) in cell for a in apps)]
    # Controls present in the data but not in the catalogue still deserve a row.
    for r in rows:
        if r.problem in ("RETIRED", "UNKNOWN-ID"):
            continue
        if not any(c[0] == r.control for c in used):
            used.append((r.control, category_of(r.control, catalogue), ""))

    blanks = [(a, c[0]) for c in used for a in apps if (a, c[0]) not in cell]
    systemic, single = [], []
    for cid, _cat, _t in used:
        states = [cell[(a, cid)].state for a in apps if (a, cid) in cell]
        fails = states.count("FAIL")
        assessed = [s for s in states if s in ("PASS", "FAIL", "PARTIAL")]
        if assessed and fails == len(assessed) and fails > 1:
            systemic.append((cid, fails, len(assessed)))
        elif fails == 1 and len(assessed) > 1:
            single.append((cid, fails, len(assessed)))

    colw = max(6, max(len(a) for a in apps) + 1)

    if markdown:
        out = ["# MASVS portfolio heatmap -- `%s`" % path, "",
               "%d apps, %d controls, %d cells, %d blank."
               % (len(apps), len(used), len(apps) * len(used), len(blanks)), "",
               "| Glyph | Meaning |", "|---|---|"]
        for k in ["PASS", "FAIL", "PARTIAL", "NOT-TESTED", "BLOCKED", "N/A",
                  "UNSUBSTANTIATED", "MISSING"]:
            out.append("| `%s` | %s |" % (GLYPH[k], k))
        out.append("")
        out.append("| Control | " + " | ".join(apps) + " | fails |")
        out.append("|---" * (len(apps) + 2) + "|")
        for cid, _cat, _t in used:
            cells, fails = [], 0
            for a in apps:
                r = cell.get((a, cid))
                if r is None:
                    cells.append("`%s`" % GLYPH["MISSING"])
                else:
                    cells.append("`%s`" % GLYPH[r.effective])
                    if r.state == "FAIL":
                        fails += 1
            out.append("| `%s` | %s | %d/%d |"
                       % (cid, " | ".join(cells), fails, len(apps)))
        out.append("")
        out += markdown_portfolio_notes(systemic, single, blanks, apps)
        out += markdown_problems(problems, [])
        return "\n".join(out)

    bar, rule = "=" * width, "-" * width
    out = [bar, "  MASVS PORTFOLIO HEATMAP -- %s" % path, bar]
    out.append("  apps       : %d  (%s)" % (len(apps), ", ".join(apps)))
    out.append("  controls   : %d" % len(used))
    out.append("  cells      : %d, of which %d blank" % (len(apps) * len(used), len(blanks)))
    out.append("  legend     : " + "  ".join(
        "%s=%s" % (GLYPH[k], k) for k in
        ["PASS", "FAIL", "PARTIAL", "NOT-TESTED", "BLOCKED", "N/A",
         "UNSUBSTANTIATED", "MISSING"]))
    out.append("")
    out.append(rule)
    header = "  %-20s" % "CONTROL"
    for a in apps:
        header += "%-*s" % (colw, fit(a, colw - 1))
    header += " FAILS"
    out.append(header)
    out.append(rule)
    last_cat = None
    for cid, cat, _t in used:
        if cat != last_cat:
            out.append("  -- %s" % cat)
            last_cat = cat
        line = "  %-20s" % fit(cid, 20)
        fails = 0
        for a in apps:
            r = cell.get((a, cid))
            g = GLYPH["MISSING"] if r is None else GLYPH[r.effective]
            if r is not None and r.state == "FAIL":
                fails += 1
            line += "%-*s" % (colw, g)
        line += " %d/%d" % (fails, len(apps))
        out.append(line)
    out.append(rule)
    out.append("")
    out += text_portfolio_notes(systemic, single, blanks, apps, width)
    out += text_problems(problems, [], width)
    return "\n".join(out)


def text_portfolio_notes(systemic, single, blanks, apps, width):
    rule = "-" * width
    out = [rule, "  READ IT THREE WAYS", rule]
    out.append("  BY ROW    which controls fail across the portfolio -- systemic candidates")
    out.append("  BY COLUMN which apps are weakest overall -- remediation priorities")
    out.append("  BY BLANK  which cells have no state at all -- gaps in YOUR work, not theirs")
    out.append("")
    out.append("  SYSTEMIC CANDIDATES (%d) -- failed in every app where they were assessed"
               % len(systemic))
    if systemic:
        for cid, f, n in systemic:
            out.append("    %-22s %d/%d assessed apps failed" % (cid, f, n))
        out.append("")
        for line in wrap(
                "A pattern is not a cause. Generate hypotheses -- shared dependency, "
                "shared internal SDK, copy-pasted pattern, platform default, missing "
                "guidance, coincidence -- and then TEST them. State what evidence would "
                "disprove each. With a handful of apps, coincidence is a live possibility "
                "and saying so is part of the finding.", width - 4, ""):
            out.append("    " + line)
    else:
        out.append("    none")
    out.append("")
    out.append("  APP-SPECIFIC (%d) -- failed in exactly one assessed app" % len(single))
    for cid, _f, n in single:
        out.append("    %-22s 1/%d" % (cid, n))
    if not single:
        out.append("    none")
    out.append("")
    out.append("  BLANK CELLS (%d)" % len(blanks))
    if blanks:
        for a, cid in blanks[:20]:
            out.append("    %-22s %s" % (cid, a))
        if len(blanks) > 20:
            out.append("    ... and %d more" % (len(blanks) - 20))
        out.append("")
        for line in wrap(
                "Every blank is a pair you did not record. The format exists so that "
                "skipping is impossible to do quietly: the file should have exactly "
                "apps x controls rows, with N/A and BLOCKED as real states rather than "
                "as absences.", width - 4, ""):
            out.append("    " + line)
    else:
        out.append("    none -- the matrix is complete")
    out.append("")
    return out


def markdown_portfolio_notes(systemic, single, blanks, apps):
    out = ["## Systemic candidates", ""]
    if systemic:
        out.append("| Control | Failed in |")
        out.append("|---|---|")
        for cid, f, n in systemic:
            out.append("| `%s` | %d of %d assessed apps |" % (cid, f, n))
    else:
        out.append("None.")
    out.append("")
    out.append("A pattern is not a cause. Generate hypotheses -- shared dependency, shared "
               "internal SDK, copy-pasted pattern, platform default, missing guidance, "
               "coincidence -- then test them, and state what would disprove each.")
    out.append("")
    out.append("## App-specific failures")
    out.append("")
    if single:
        for cid, _f, n in single:
            out.append("- `%s` -- 1 of %d assessed apps" % (cid, n))
    else:
        out.append("None.")
    out.append("")
    out.append("## Blank cells (%d)" % len(blanks))
    out.append("")
    if blanks:
        for a, cid in blanks:
            out.append("- `%s` / %s" % (cid, a))
        out.append("")
        out.append("Every blank is a pair that was not recorded. A complete file has "
                   "exactly apps x controls rows.")
    else:
        out.append("None -- the matrix is complete.")
    out.append("")
    return out


# ---------------------------------------------------------------------------
#  Problem rendering
# ---------------------------------------------------------------------------

def text_problems(problems, gaps, width):
    rule = "-" * width
    out = []
    if gaps:
        out.append(rule)
        out.append("  COVERAGE GAPS (%d) -- in the catalogue, absent from the input" % len(gaps))
        out.append(rule)
        for cid, cat, title in gaps:
            out.append("    %-22s %-11s %s" % (cid, cat, fit(title, width - 40)))
        out.append("")
        for line in wrap(
                "A control that appears nowhere leaves the reader unable to tell whether "
                "it passed, was skipped, or was forgotten. Give every control a state: "
                "PASS, FAIL, PARTIAL, NOT-TESTED with a reason, or BLOCKED with an "
                "obstacle.", width - 4, ""):
            out.append("    " + line)
        out.append("")

    if problems:
        out.append(rule)
        out.append("  PROBLEMS (%d)" % len(problems))
        out.append(rule)
        for kind, msg in problems:
            head = "  [%s] " % kind
            pad = " " * len(head)
            for i, line in enumerate(wrap(msg, width - len(head), "")):
                out.append((head if i == 0 else pad) + line)
            out.append("")
    out.append(rule)
    out.append("  This checks that an evidence reference EXISTS. It cannot check that the")
    out.append("  artefact behind it supports the conclusion -- open your own evidence and")
    out.append("  downgrade anything it does not carry. Severity and reporting belong to")
    out.append("  80-Appendix; the backend belongs to OWASP ASVS.")
    out.append(rule)
    return out


def markdown_problems(problems, gaps):
    out = []
    if gaps:
        out.append("## Coverage gaps")
        out.append("")
        out.append("| Control | Category | Title |")
        out.append("|---|---|---|")
        for cid, cat, title in gaps:
            out.append("| `%s` | %s | %s |" % (cid, cat, esc(title)))
        out.append("")
    if problems:
        out.append("## Problems")
        out.append("")
        out.append("| Kind | Detail |")
        out.append("|---|---|")
        for kind, msg in problems:
            out.append("| `%s` | %s |" % (kind, esc(msg)))
        out.append("")
    out.append("---")
    out.append("")
    out.append("This checks that an evidence reference exists, not that the artefact behind "
               "it supports the conclusion. Severity and report structure belong to "
               "80-Appendix; backend coverage belongs to OWASP ASVS.")
    return out


# ---------------------------------------------------------------------------
#  Catalogue loading
# ---------------------------------------------------------------------------

def load_controls(path):
    controls = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in line.split("|")]
            if len(parts) != 3:
                sys.stderr.write("[-] %s:%d: expected 'ID|CATEGORY|title'\n"
                                 % (path, lineno))
                return None
            controls.append((parts[0], parts[1].upper(), parts[2]))
    return controls


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Turn a findings/results list into a MASVS coverage view, and several "
                    "apps' lists into a portfolio heatmap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="A control marked PASS, FAIL or PARTIAL with no evidence reference is "
               "reported as UNSUBSTANTIATED and is not counted as covered. That is the "
               "one opinion this script holds.")
    ap.add_argument("results", help="CSV of results. '-' for stdin. '#' lines skipped.")
    ap.add_argument("--heatmap", action="store_true",
                    help="Portfolio matrix. Needs an 'app' column.")
    ap.add_argument("--markdown", action="store_true", help="Emit Markdown.")
    ap.add_argument("--controls", metavar="FILE",
                    help="Override the built-in catalogue. One 'ID|CATEGORY|title' per "
                         "line; '#' comments allowed.")
    ap.add_argument("--strict", action="store_true",
                    help="Exit 1 if anything is unsubstantiated, blank, or a bad id.")
    ap.add_argument("--width", type=int, default=112, help="Text output width.")
    args = ap.parse_args(argv)

    catalogue = DEFAULT_CONTROLS
    if args.controls:
        catalogue = load_controls(args.controls)
        if catalogue is None:
            return 2
        if not catalogue:
            sys.stderr.write("[-] control catalogue is empty: %s\n" % args.controls)
            return 2

    rows, fields, errors = read_rows(args.results)
    if rows is None:
        for e in errors:
            sys.stderr.write("[-] %s\n" % e)
        return 2

    problems = [("INPUT", e) for e in errors]
    problems += validate(rows, {c[0] for c in catalogue})

    if args.heatmap:
        if "app" not in (fields or []):
            sys.stderr.write(
                "[-] --heatmap needs an 'app' column; this file has none.\n"
                "    A single-app result set has no portfolio to compare.\n")
            return 2
        print(render_heatmap(rows, problems, catalogue, args.results,
                             args.width, args.markdown))
    else:
        if "app" in (fields or []):
            sys.stderr.write(
                "[!] this file has an 'app' column; showing the combined single-app "
                "view.\n    Add --heatmap for the portfolio matrix.\n")
        print(render_single(rows, problems, catalogue, args.results,
                            args.width, args.markdown))

    if args.strict:
        bad = [p for p in problems
               if p[0] in ("UNSUBSTANTIATED", "RETIRED", "UNKNOWN-ID", "INPUT",
                           "DUPLICATE")]
        if bad:
            sys.stderr.write("[-] --strict: %d blocking problem(s)\n" % len(bad))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
