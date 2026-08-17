#!/usr/bin/env python3
"""
claim-ledger.py -- audit a written case study for the four defects that make one
                   unusable, and report its refuted-to-supported ratio.

WHY THIS EXISTS
    Chapter 74 is the only chapter in this repository whose PRODUCT is a
    narrative, and a narrative is the easiest security artefact to fake: a story
    is persuasive whether or not it is true. Code has a compiler. Prose has this.

    The four defects it looks for are chapter 74 section 8.2's:

      1. THE TIDY NARRATIVE     -- zero refuted hypotheses. A report wearing a
                                   case study's clothes. Real investigations
                                   refute most of what they try; 68's worked
                                   journal runs seven refuted of nine.
      2. THE ABSENT VANTAGE     -- "I checked and the file was there". As whom?
                                   root, shell and an app uid give three
                                   different answers, and this repository has
                                   measured that four separate times.
      3. THE UNLABELLED COMPOSITE -- reads as one session, is three. Composing a
                                   case study from separate measurements is fine;
                                   not saying so is not.
      4. THE COUNT WITH NO DENOMINATOR -- "58 applications reference Xposed".
                                   Out of how many, and were the hits adjudicated?
                                   The measured answer to that one was 0 of 1,141.

USAGE
    python3 -B claim-ledger.py <file.md> [<file.md> ...]
    python3 -B claim-ledger.py --self-test
    python3 -B claim-ledger.py --strict <file.md>      # exit 1 on any defect

    -B (or PYTHONDONTWRITEBYTECODE=1) keeps __pycache__ out of the tree. Note
    that the environment variable alone is NOT always enough -- a script using
    importlib.util.module_from_spec writes bytecode regardless, which is how this
    repository acquired stray __pycache__ directories twice. -B is the reliable
    form.

WHAT IT IS NOT
    Not a truth checker. It cannot tell whether a measurement is correct; it can
    only tell whether the document gives you enough to CHECK it. A case study
    that passes every test here can still be wrong. One that fails is not
    checkable at all, which is worse.

    It is also tuned for CASE STUDIES, not for reference material. Run it on a
    cheatsheet, an FAQ or a chapter README and it will produce heuristic hits on
    headings, summary-table cells and cross-references, because those legitimately
    quote a count whose denominator lives three sections away.

    DO NOT CHASE THE TOTAL TO ZERO. Read the per-file split, and treat a hit in a
    narrative document as real and a hit in a lookup document as suspect. That is
    the same discipline this repository's prose-promised-file sweep needs: its raw
    count is never zero, because the documents that DESCRIBE the checker quote
    example paths and trip it, so driving the total to zero would mean creating
    files nobody wants. An exemption category that nobody audits is where defects
    accumulate silently -- so check the split, and treat any hit outside the known
    false-positive classes as real.

EXIT CODES
    0   no defects, or defects found without --strict
    1   --strict and at least one defect
    2   usage error / unreadable file

EXECUTED?
    YES. Run on 2026-08-16 against this chapter's own examples/replay-journal.md
    and examples/reproduction-log.md, against
    68-ReverseEngineering/examples/worked-journal.md (the reference
    implementation, which it scores 7 refuted of 9), and via --self-test, which
    exercises every detector against inline fixtures. Python 3.13.
"""

import argparse
import os
import re
import sys

# Audited files are UTF-8 and routinely contain em-dashes and arrows. A Windows
# console defaults to a legacy code page and would raise UnicodeEncodeError while
# printing an excerpt -- a crash in the auditor, caused by the document it is
# auditing being perfectly valid. Degrade the OUTPUT rather than the analysis.
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, ValueError):        # Python < 3.7, or a non-tty stream
    pass

# --------------------------------------------------------------------- rules --

# Verdict tokens, as used by 68's H/P/R/E/O/V notation and by this chapter.
RE_REFUTED = re.compile(r'\bREFUTED\b')
RE_SUPPORTED = re.compile(r'\bSUPPORTED\b')
RE_INCONCLUSIVE = re.compile(r'\bINCONCLUSIVE\b')
RE_ANSWERED = re.compile(r'\bANSWERED\b')
RE_REPRODUCED = re.compile(r'\bREPRODUCED\b')
RE_DIVERGED = re.compile(r'\bDIVERGED\b')

# A hypothesis block: an `H` line, optionally numbered, at the start of a line.
RE_HYPOTHESIS = re.compile(r'^\s*H\d*\s{2,}\S', re.M)
# The refutation criterion. Its ABSENCE is the single most important defect,
# because without it every observation is something you can explain away.
RE_REFUTATION = re.compile(r'^\s*R\d*\s{2,}\S', re.M)
RE_EXPERIMENT = re.compile(r'^\s*E\d*\s{2,}\S', re.M)
RE_OBSERVATION = re.compile(r'^\s*O\d*\s{2,}\S', re.M)

# Evidence that a device was named. Deliberately broad: the goal is to catch a
# document that never mentions hardware at all, not to police phrasing.
RE_DEVICE = re.compile(
    r'\b(?:API\s*\d{2}|Android\s*\d{1,2}\b|sdk_gphone\w*|emulator-\d+|emu64\w*|'
    r'M2101K6P|i9000S|arm64|aarch64|x86_64|AVD)\b', re.I)

# Evidence that an actual command is present, not a description of one.
RE_COMMAND = re.compile(
    r'(?:^|\s)(?:\$\s*)?(?:adb|getprop|run-as|su\s+0|frida|jadx|apktool|grep|'
    r'llvm-\w+|clang|objdump|strings|python3|dumpsys|pm\s+list)\b')

# A bare count with no visible denominator: "58 applications", "132 hits".
RE_BARE_COUNT = re.compile(
    r'\b(\d[\d,]{1,})\s+(APKs?|apps?|applications?|packages?|hits?|matches?|'
    r'findings?|occurrences?|leads?|files?)\b', re.I)
# Any of these near a count means a denominator or an adjudication is present.
#
# NOTE the two alternations. The first version of this put everything in one
# group with a trailing \b, and the numeric alternatives broke: `of\s+\d`
# consumes ONE digit, and the \b then demanded a boundary immediately after it --
# which fails for every multi-digit number, because "2" in "237" is followed by
# another word character. So "zero of 237 applications" was reported as a count
# with no denominator, while "zero of 7" would have passed.
#
# This is the same defect class as the extension-alternation bugs this
# repository's own path checker shipped with, where a missing trailing
# (?![A-Za-z0-9]) anchor captured `build.gradle.kts` as `build.gradle.kt` and
# `findings-ovaa.csv` as `findings-ovaa.c`, producing 29 spurious warnings
# against a chapter whose files all existed.
# A checker that cries wolf is worse than no checker, because the next reader
# starts skimming its output.
#
# Numeric forms get \d+ and NO trailing boundary; word forms keep theirs.
RE_DENOM_NUM = re.compile(r'\b(?:of\s+\d+|out\s+of\s+\d+|/\s*\d+)', re.I)
RE_DENOM_WORD = re.compile(
    r'(?:\b(?:out\s+of|per\s+cent|percent|denominator|adjudicat\w+|'
    r'accounted\s+for|unexplained|explained|false\s+positive|'
    r'corpus|sample\s+of)\b|%)', re.I)


def has_denominator(line):
    """True if a line carrying a count also carries a denominator or evidence
    that the hits were adjudicated."""
    return bool(RE_DENOM_NUM.search(line) or RE_DENOM_WORD.search(line))

# Composition disclosure.
#
# The negative lookbehind is not decoration. The first version of this regex
# matched the bare word `provenance`, and it duly "found" a provenance statement
# in a fixture whose heading read "Two devices, no provenance" -- reporting a
# clean document because the text said the disclosure was MISSING.
#
# That is precisely the defect class this chapter is about: a substring matched
# something other than what the sentence claimed it matched, and it is the same
# shape as 48-Biometrics' grader reading its files' explanatory comments and
# scoring them backwards. A detector that reads a denial as a confirmation fails
# in the direction that looks clean, which is the dangerous direction.
#
# Fixed by refusing a match preceded by a negation within a few words. Kept
# deliberately simple: this is a heuristic over prose and is documented as one.
RE_NEGATION = re.compile(
    r'\b(?:no|not|without|lacks?|lacking|missing|absent|never|omits?|'
    r'fails?\s+to|does\s+not)\b\W+(?:\w+\W+){0,2}$', re.I)

RE_COMPOSED_TOKEN = re.compile(
    r'\b(?:composed|reconstruct\w*|transcrib\w*|assembled\s+from|'
    r'provenance|re-?run)\b', re.I)


def has_provenance(text):
    """True if the document discloses whether it is a transcript or a
    composition -- and NOT merely if it contains a disclosure keyword. See the
    comment above RE_NEGATION for why the distinction cost a bug."""
    for m in RE_COMPOSED_TOKEN.finditer(text):
        preceding = text[max(0, m.start() - 40):m.start()]
        if RE_NEGATION.search(preceding):
            continue          # "no provenance", "not transcribed", "never re-run"
        return True
    return False

# ------------------------------------------------------------------ helpers --


def strip_code_fences(text):
    """Return (prose, fenced) so a path or count inside a fence is not read as
    a claim. A command in a fence is evidence; the same text in prose is a
    description of evidence. They are graded differently."""
    prose, fenced, in_fence = [], [], False
    for line in text.splitlines():
        if line.lstrip().startswith('```'):
            in_fence = not in_fence
            continue
        (fenced if in_fence else prose).append(line)
    return '\n'.join(prose), '\n'.join(fenced)


class Report:
    def __init__(self, path):
        self.path = path
        self.defects = []
        self.notes = []
        self.stats = {}

    def defect(self, code, msg, fix):
        self.defects.append((code, msg, fix))

    def note(self, msg):
        self.notes.append(msg)


# ------------------------------------------------------------------ checks ---


def audit(path):
    rep = Report(path)
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            text = fh.read()
    except OSError as exc:
        rep.defect('IO', 'cannot read: %s' % exc, 'check the path')
        return rep

    prose, fenced = strip_code_fences(text)
    whole = text

    # ---- verdict tallies -------------------------------------------------
    n_hyp = len(RE_HYPOTHESIS.findall(whole))
    n_ref_crit = len(RE_REFUTATION.findall(whole))
    n_exp = len(RE_EXPERIMENT.findall(whole))
    n_obs = len(RE_OBSERVATION.findall(whole))

    n_refuted = len(RE_REFUTED.findall(whole))
    n_supported = len(RE_SUPPORTED.findall(whole))
    n_inconc = len(RE_INCONCLUSIVE.findall(whole))
    n_answered = len(RE_ANSWERED.findall(whole))
    n_repro = len(RE_REPRODUCED.findall(whole))
    n_diverged = len(RE_DIVERGED.findall(whole))

    rep.stats = {
        'hypotheses': n_hyp,
        'refutation criteria': n_ref_crit,
        'experiments': n_exp,
        'observations': n_obs,
        'REFUTED': n_refuted,
        'SUPPORTED': n_supported,
        'INCONCLUSIVE': n_inconc,
        'ANSWERED': n_answered,
        'REPRODUCED': n_repro,
        'DIVERGED': n_diverged,
        'lines': len(whole.splitlines()),
    }

    verdicts = n_refuted + n_supported + n_inconc + n_answered
    outcomes = verdicts + n_repro + n_diverged

    # ---- defect 1: the tidy narrative ------------------------------------
    if outcomes == 0:
        rep.note('no verdict tokens at all -- not written as a case study. '
                 'Nothing below applies; grade it as prose.')
    elif n_refuted == 0 and n_diverged == 0:
        rep.defect(
            'TIDY',
            'zero REFUTED and zero DIVERGED across %d outcome(s)' % outcomes,
            'A real investigation refutes most of what it tries; the reference '
            'journals in this repository sit near two thirds. Zero means the '
            'dead ends were edited out -- which makes this a report, not a '
            'case study.')
    elif verdicts and (n_refuted / max(verdicts, 1)) < 0.2:
        rep.note('refuted ratio %.0f%% of %d verdicts -- low. Plausible for a '
                 'pure replication, suspicious for an investigation.'
                 % (100.0 * n_refuted / verdicts, verdicts))

    # ---- the missing refutation criterion --------------------------------
    if n_hyp and n_ref_crit < n_hyp:
        rep.defect(
            'NO-R',
            '%d hypothesis line(s) but only %d refutation criterion line(s)'
            % (n_hyp, n_ref_crit),
            'Write the R line BEFORE looking. Without it every observation is '
            'something you can explain away, which is the whole failure mode '
            'this notation exists to prevent.')
    if n_hyp and n_obs < n_hyp:
        rep.note('%d hypotheses but %d observation lines -- some hypothesis has '
                 'a verdict with no recorded observation.' % (n_hyp, n_obs))

    # ---- defect 2: the absent vantage ------------------------------------
    if not RE_DEVICE.search(whole):
        rep.defect(
            'NO-DEVICE',
            'no device, API level or architecture named anywhere',
            'Every version-gated claim depends on it. State model, API level '
            'and ABI once, near the top, and say which device produced which '
            'number when more than one is involved.')

    mentions_vantage = re.search(
        r'\b(?:run-as|uid\s*2000|untrusted_app|runas_app|app\s+uid|as\s+root|'
        r'su\s+0|shell\s+vantage|vantage)\b', whole, re.I)
    probes_files = re.search(
        r'\b(?:File\(|\.exists\(\)|ls\s+-l|stat\b|access\(|getprop)\b', whole)
    if probes_files and not mentions_vantage:
        rep.defect(
            'NO-VANTAGE',
            'probes files or properties but never says as WHICH uid',
            'root, shell (uid 2000) and an app uid give three different '
            'answers to the same question. This repository has measured that '
            'independently four times. An unstated vantage makes the result '
            'unusable, not merely imprecise.')

    # ---- defect 3: the unlabelled composite ------------------------------
    devices = set(m.group(0).lower()
                  for m in re.finditer(
                      r'\b(?:sdk_gphone\w*|emulator-\d+|M2101K6P|i9000S)\b',
                      whole, re.I))
    if len(devices) > 1 and not has_provenance(whole):
        rep.defect(
            'COMPOSITE',
            'names %d distinct devices (%s) with no provenance statement'
            % (len(devices), ', '.join(sorted(devices))),
            'Say whether this is a transcript of one session or composed from '
            'several. A transcript proves the ORDER of events; a composition '
            'only proves the events. Both are legitimate; conflating them is '
            'not.')

    # ---- defect 4: counts with no denominator ----------------------------
    bare = []
    for line in prose.splitlines():
        m = RE_BARE_COUNT.search(line)
        if not m:
            continue
        if has_denominator(line):
            continue
        try:
            if int(m.group(1).replace(',', '')) < 10:
                continue          # small numbers are rarely population claims
        except ValueError:
            continue
        # A chapter number is not a count. In this repository "58 hit the same
        # class" means CHAPTER 58, and the detector read it as fifty-eight of
        # something. Same failure as the substring cases this chapter is about:
        # the token matched, and it meant something else entirely. Skip a number
        # that is a bare two-digit chapter reference at the start of a clause.
        if re.match(r'^\s*(?:[-*|>#\s]*)?\d{2}\b(?!\s*[,.]?\d)', line) and \
           re.search(r'\b\d{2}\s+(?:hit|measured|swept|found|reported|owns|'
                     r'records|built|shipped|says|writes)\b', line, re.I):
            continue
        bare.append(line.strip()[:96])
    if bare:
        rep.defect(
            'NO-DENOM',
            '%d count(s) in prose with no visible denominator or adjudication'
            % len(bare),
            'A count is a lead, not a finding. State the denominator and say '
            'whether the top band was adjudicated by hand. The measured worked '
            'example is 1,141 hits, 1,141 explained, 0 findings.')
        for b in bare[:5]:
            rep.note('  count: %s' % b)

    # ---- supporting quality notes ----------------------------------------
    if not RE_COMMAND.search(fenced or whole):
        rep.note('no runnable command found in any code fence -- "I checked the '
                 'property" is not reproducible; the command is.')
    if not re.search(r'\b20\d\d-\d\d-\d\d\b', whole):
        rep.note('no ISO date found. Devices are updated and corpora change; '
                 'an undated measurement cannot be re-run against its own '
                 'conditions.')
    if not re.search(r'\b(?:residue|limit\w*|not\s+re-?run|unknown|'
                     r'cause not established|declin\w+ to)\b', whole, re.I):
        rep.note('no residue or limits section detected. What you chose not to '
                 'measure belongs in the document.')

    return rep


# ------------------------------------------------------------------ output ---


def emit(rep):
    print('=' * 72)
    print(' %s' % rep.path)
    print('=' * 72)

    if rep.stats:
        keys = [k for k in rep.stats if rep.stats[k]]
        print(' ' + '   '.join('%s=%s' % (k, rep.stats[k]) for k in keys))

    v = rep.stats.get('REFUTED', 0)
    tot = (rep.stats.get('REFUTED', 0) + rep.stats.get('SUPPORTED', 0)
           + rep.stats.get('INCONCLUSIVE', 0) + rep.stats.get('ANSWERED', 0))
    if tot:
        print(' refuted ratio: %d/%d (%.0f%%)' % (v, tot, 100.0 * v / tot))

    if not rep.defects:
        print('\n  no defects found')
    for code, msg, fix in rep.defects:
        print('\n  [%s] %s' % (code, msg))
        for line in _wrap(fix, 66):
            print('        %s' % line)
    for n in rep.notes:
        print('  note: %s' % n)
    print()


def _wrap(text, width):
    words, line, out = text.split(), '', []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + ' ' + w).strip()
    if line:
        out.append(line)
    return out


# --------------------------------------------------------------- self-test ---

_GOOD = """
# A case study
Measured on sdk_gphone16k_x86_64, Android 15 / API 35, on 2026-08-16.
Provenance: transcribed from one session, not composed.

H1  the property reports the bootloader verdict
P   it reads one of four documented values
R   it reads something else
E   adb shell getprop ro.boot.verifiedbootstate
O   (the empty string)
V   REFUTED

Probed as root, as shell (uid 2000) and via run-as at an app uid.
Residue: one device, one session. Cause of the emptiness not established.
"""

_TIDY = """
# A finding dressed as a case study
Measured on sdk_gphone16k_x86_64, API 35, 2026-08-16, via run-as at an app uid.
H1  the token is stored insecurely
P   it appears in shared_prefs
R   it does not
E   adb shell run-as pkg cat shared_prefs/auth.xml
O   the token, in cleartext
V   SUPPORTED
Residue: none.
"""

_COUNTS = """
# A sweep
Measured on sdk_gphone16k_x86_64, API 35, 2026-08-16, as root and via run-as.
H1  the signature is specific
R   it matches unrelated strings
E   grep -ic xposed
O   many
V   REFUTED
We found 58 applications referencing the framework and 1141 occurrences.
Residue: one corpus.
"""

_COMPOSITE = """
# Two devices, no provenance
H1  the property is honest
R   a second source disagrees
E   getprop and an attestation
O   they disagree
V   REFUTED
Measured on M2101K6P at API 30, and also on emulator-5554 at API 35,
as root and via run-as. Date 2026-08-16. Residue: none.
"""


def self_test():
    import tempfile
    cases = [
        ('clean case study', _GOOD, []),
        ('tidy narrative', _TIDY, ['TIDY']),
        ('counts, no denominator', _COUNTS, ['NO-DENOM']),
        ('unlabelled composite', _COMPOSITE, ['COMPOSITE']),
    ]
    failures = 0
    tmp = tempfile.mkdtemp()
    print('self-test\n' + '-' * 72)
    for name, body, expect in cases:
        p = os.path.join(tmp, re.sub(r'\W+', '_', name) + '.md')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(body)
        rep = audit(p)
        got = sorted(c for c, _, _ in rep.defects)
        want = sorted(expect)
        ok = got == want
        failures += 0 if ok else 1
        print('  %-26s expect=%-14s got=%-14s %s'
              % (name, ','.join(want) or '(none)',
                 ','.join(got) or '(none)', 'OK' if ok else 'FAIL'))
        os.remove(p)
    os.rmdir(tmp)
    print('-' * 72)
    print('self-test: %s' % ('all passed' if failures == 0
                             else '%d FAILED' % failures))
    return 0 if failures == 0 else 1


# ------------------------------------------------------------------- main ----


def main():
    ap = argparse.ArgumentParser(
        description='Audit a written case study for the four defects that make '
                    'one unusable.')
    ap.add_argument('files', nargs='*', help='markdown files to audit')
    ap.add_argument('--strict', action='store_true',
                    help='exit 1 if any defect is found')
    ap.add_argument('--self-test', action='store_true',
                    help='run the built-in detector fixtures and exit')
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.files:
        ap.print_help()
        return 2

    total = 0
    for path in args.files:
        rep = audit(path)
        emit(rep)
        total += len(rep.defects)

    print('=' * 72)
    print(' %d file(s) audited, %d defect(s) total' % (len(args.files), total))
    print('=' * 72)
    print(' A file that passes every test here can still be WRONG. This checks')
    print(' whether the document gives a reader enough to CHECK it, which is a')
    print(' weaker and more mechanical property than being correct.')
    return 1 if (args.strict and total) else 0


if __name__ == '__main__':
    sys.exit(main())
