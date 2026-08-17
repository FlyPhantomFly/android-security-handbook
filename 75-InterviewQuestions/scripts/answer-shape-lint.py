#!/usr/bin/env python3
# 75-InterviewQuestions/scripts/answer-shape-lint.py
#
# PURPOSE
#   Lint a WRITTEN interview answer (or a take-home submission) for the failures
#   that cost candidates offers, which are almost never "did not know the fact":
#
#     1. Opening with a tool instead of with the problem.
#     2. Absolute claims with no hedge, no measurement and no denominator.
#     3. Never naming the trust boundary.
#     4. Never distinguishing what was measured from what was read.
#     5. Never reaching the edge of knowledge and saying so.
#     6. A word count that could not be delivered inside the time budget.
#
#   This is a LINT, not a grader. It counts word shapes; it cannot read. Treat
#   every hit as a LEAD, exactly as this repository treats every hit from a grep
#   sweep -- 52-StaticAnalysis rejected 15 of 17 of its own high-confidence hits
#   by hand, and this tool is not better than that one. It is useful because it is
#   consistent and instant, not because it is right.
#
# USAGE
#   # lint one answer
#   python3 -B scripts/answer-shape-lint.py my-answer.md
#
#   # lint a multi-answer file: split on markdown H2/H3 headings
#   python3 -B scripts/answer-shape-lint.py --split submission.md
#
#   # a spoken answer has a budget in seconds, not words
#   python3 -B scripts/answer-shape-lint.py --budget 150 my-answer.md
#
#   # from stdin
#   cat answer.txt | python3 -B scripts/answer-shape-lint.py -
#
#   # gate a take-home: non-zero exit if any section scores below 7 of 12
#   python3 -B scripts/answer-shape-lint.py --split --min 7 submission.md
#
#   Run with -B so no __pycache__ is written into the repository.
#
# WAS THIS EXECUTED?
#   YES. Run on 2026-08-16 against ../examples/02-weak-and-strong-at-the-same-tier.md,
#   which holds three questions each answered twice at the SAME tier. Measured:
#
#       Q1 WEAK    5/12      Q1 STRONG  11/12
#       Q2 WEAK    3/12      Q2 STRONG   9/12
#       Q3 WEAK    3/12      Q3 STRONG  10/12
#
#   Every pair separates in the right direction, which is the only claim being
#   made. It is NOT a claim that the tool would rank two unseen answers correctly.
#
#   Two things the first version got wrong, both fixed and both worth knowing:
#     * "i measured" does not match "i have measured", so a heavily-evidenced
#       answer scored 0/2 for evidence. Substring vocabularies must carry their
#       own inflections.
#     * Every fallacy pattern fired on the STRONG answers too, because a strong
#       answer DISCUSSES the fallacy in order to refute it. Hits are now
#       downgraded to NOTE when the surrounding sentence reads as a rebuttal.
#       An unfixed version of this would have punished the best answers hardest.
#
# EXIT STATUS
#   0 normally; 1 if --min is given and any section scores below it.

import argparse
import os
import re
import sys

# Spoken delivery rate. 130 words per minute is an unhurried technical pace; a
# nervous candidate runs faster and says less.
WORDS_PER_MINUTE = 130

# --- signal vocabularies ---------------------------------------------------
# Every list below is short and deliberately so. This repository's own measured
# lesson from 64-Xposed is that a short token in a high-confidence tier
# manufactures false positives, so nothing here is shorter than four characters
# and none of it is used to make a claim on its own.

OPENS_WITH_TOOL = re.compile(
    r"^\s*(?:[-*>#\s]*)?(?:you |i |we )?(?:just |simply )?"
    r"(?:run|open|use|launch|fire up|install|hook|grep|decompile|attach)\b"
    r"|^\s*(?:frida|jadx|objection|apktool|burp|mobsf|adb|magisk|drozer|ghidra)\b",
    re.I)

ABSOLUTES = [
    "always", "never", "impossible", "unbreakable", "cannot be bypassed",
    "completely secure", "100%", "guaranteed", "every single", "no way to",
    "totally", "bulletproof", "fully protects",
]

HEDGES = [
    "usually", "typically", "in practice", "on the devices i", "as far as",
    "i would expect", "depends on", "in the case where", "at least on",
    "measured on", "on this device", "i am not certain", "i would verify",
    "at least as often", "unless i say otherwise", "caveat", "roughly",
    "may be", "might be", "not necessarily", "on the device i",
]

# Provenance vocabulary. Written as substrings of the LOWER-CASED text, so each
# entry has to cover its own inflections -- "i measured" does not match "i have
# measured", which is exactly the gap that made the first version of this script
# score a well-evidenced answer at 0 for evidence.
MEASURED = [
    "i measured", "i have measured", "have measured", "i observed", "i ran",
    "measured on", "i reproduced", "i verified", "the device returned",
    "the output was", "i timed", "i counted", "in my test", "i tested",
    "i have tested", "a device i tested", "i have seen", "i read the",
    "when i ran", "on a benchmark", "i pulled",
]

READ = [
    "the documentation says", "aosp", "according to", "the source says",
    "the standard says", "masvs", "mastg", "the spec", "the docs",
    "the published", "the api docs", "the bulletin", "the cve",
]

BOUNDARY = [
    "trust boundary", "attacker-controlled", "attacker controls",
    "server-side", "client-side", "outside the process", "inside the process",
    "the attacker's machine", "the attacker's device", "uid boundary",
    "sandbox boundary", "on the attacker's side", "in the app's own process",
    "own process", "outside the app", "the process they control",
    "the process the attacker", "evaluated outside", "on the server",
]

HONESTY = [
    "i do not know", "i don't know", "i am not sure", "i'm not sure",
    "i would measure", "i would check", "i would test", "i would look it up",
    "i have not measured", "i would want to verify", "i could be wrong",
    "i would confirm", "i cannot answer", "i would say so",
    "i would want to check", "i have not verified", "before i rate",
    "i would find out",
]

# Words that, appearing in the SAME sentence as a fallacy pattern, indicate the
# writer is REBUTTING the fallacy rather than committing it. Without this, an
# answer that correctly explains why /dev/qemu_pipe is dead trips the same flag
# as one that recommends checking it -- which is the classic detector failure
# this repository keeps measuring.
REBUTTAL = [
    "enoent", "dead", "inverted", "faster", "measured", "absent",
    "does not exist", "no longer", "goldfish", "does not start",
    "returns false", "not the binary", "acceptcrypto", "software",
    "wrong answer", "backwards", "is not", "corruption",
]

SEVERITY = [
    "severity", "false positive", "denominator", "informational",
    "exploitable", "reachable", "preconditions", "impact", "who can reach",
    "leads, not findings", "i would rate", "rate it", "rating",
    "before i rate", "defend that",
]

# The specific fallacies this repository has measured, each with the chapter that
# owns the measurement. Naming the chapter is what makes the warning actionable.
FALLACIES = [
    (re.compile(r"grepp?e?d?[^.]{0,40}(found|finds) nothing", re.I),
     "\"I grepped and found nothing\" is a statement about your grep. "
     "See 56-JADX and 52-StaticAnalysis."),
    (re.compile(r"grep[^.]{0,60}FLAG_SECURE|FLAG_SECURE[^.]{0,40}grep", re.I),
     "Grepping for FLAG_SECURE has a measured true-positive rate of ZERO -- "
     "javac constant-folds 0x2000 and the name never reaches the DEX. See 47."),
    (re.compile(r"/dev/qemu_pipe", re.I),
     "/dev/qemu_pipe is ENOENT on API 35; the node is /dev/goldfish_pipe_dprctd. "
     "See 39-EmulatorDetection."),
    (re.compile(r"emulators?[^.]{0,40}(slower|slow)", re.I),
     "Measured INVERTED: the AVD ran 1.47x FASTER than the physical phone. "
     "See 39-EmulatorDetection."),
    (re.compile(r"fingerprint[^.]{0,40}generic|startsWith\(\s*[\"']generic", re.I),
     "Build.FINGERPRINT does not start with \"generic\" on a stock current AVD. "
     "See 39-EmulatorDetection."),
    (re.compile(r"(valid|verified?)[^.]{0,50}chain[^.]{0,50}"
                r"(hardware|hardware-backed|tee)", re.I),
     "A verifying attestation chain proves the CHAIN, not the hardware -- on an "
     "emulator every key is SOFTWARE and the chain still verifies. See 50 and 49."),
    (re.compile(r"biometric[^.]{0,60}(secure|proves|proof)", re.I),
     "A BiometricPrompt success callback proves nothing on its own. Compare "
     "dumpsys fingerprint's accept against acceptCrypto. See 48-Biometrics."),
    (re.compile(r"File\s*\(\s*[\"']/system/(x?bin)/su|exists\(\)[^.]{0,30}su\b"),
     "/system/xbin is 0750 root:shell, so an app gets EACCES and File.exists() "
     "reads false on a rooted device. See 37, 59 and 63."),
    (re.compile(r"disable-verity[^.]{0,60}(turns? off|disables?) (verity|avb)", re.I),
     "--disable-verity flips one byte INSIDE the region AVB hashes, so it breaks "
     "the image's own signature. It is a corruption an unlocked bootloader "
     "tolerates, not a supported option. See 61-Fastboot."),
]


def count(text_lower, phrases):
    return sum(1 for p in phrases if p in text_lower)


def score_section(title, body, budget_seconds):
    """Return (score_out_of_12, list_of_notes)."""
    notes = []
    points = 0
    lower = body.lower()
    words = len(body.split())

    # --- Shape (0-2) --------------------------------------------------------
    first_line = next((ln for ln in body.split("\n") if ln.strip()), "")
    if OPENS_WITH_TOOL.match(first_line):
        notes.append("SHAPE  0/2  Opens with a tool or a command. The first "
                     "sentence should say what problem exists; the tool is the "
                     "third or fourth sentence.")
    else:
        # A strong opening is a claim, not a hedge and not a question.
        if len(first_line.split()) >= 6:
            points += 2
            notes.append("SHAPE  2/2  Opens with a statement rather than a tool.")
        else:
            points += 1
            notes.append("SHAPE  1/2  Opening line is very short; make it a "
                         "complete claim the rest of the answer defends.")

    # --- Scope (0-2) --------------------------------------------------------
    if budget_seconds:
        allowed = int(budget_seconds / 60.0 * WORDS_PER_MINUTE)
        if words > allowed * 1.25:
            notes.append("SCOPE  0/2  %d words against a %ds budget (~%d words at "
                         "%d wpm). This answer gets interrupted."
                         % (words, budget_seconds, allowed, WORDS_PER_MINUTE))
        elif words < allowed * 0.35:
            points += 1
            notes.append("SCOPE  1/2  %d words against a %ds budget (~%d words). "
                         "Room left; add the mechanism or the consequence."
                         % (words, budget_seconds, allowed))
        else:
            points += 2
            notes.append("SCOPE  2/2  %d words fits a %ds budget."
                         % (words, budget_seconds))
    else:
        points += 1
        notes.append("SCOPE  1/2  No --budget given, so scope was not assessed.")

    # --- Boundary (0-2) -----------------------------------------------------
    n = count(lower, BOUNDARY)
    if n >= 2:
        points += 2
        notes.append("BOUND  2/2  Names the trust boundary (%d phrase(s))." % n)
    elif n == 1:
        points += 1
        notes.append("BOUND  1/2  Mentions the boundary once. Say explicitly what "
                     "is on the attacker's side of it.")
    else:
        notes.append("BOUND  0/2  Never says where the trust boundary is. Almost "
                     "every Android security answer bottoms out there.")

    # --- Evidence (0-2) -----------------------------------------------------
    m, r = count(lower, MEASURED), count(lower, READ)
    if m and r:
        points += 2
        notes.append("EVID   2/2  Separates measured (%d) from read (%d)." % (m, r))
    elif m or r:
        points += 1
        notes.append("EVID   1/2  Cites evidence but only one kind (measured %d, "
                     "read %d). Say which claims you have run and which you have "
                     "only read." % (m, r))
    else:
        notes.append("EVID   0/2  No provenance anywhere. Every claim reads as "
                     "equally certain, so none of them does.")

    # --- Honesty (0-2) ------------------------------------------------------
    absolutes = [a for a in ABSOLUTES if a in lower]
    hedged = count(lower, HEDGES)
    honest = count(lower, HONESTY)
    if honest and not absolutes:
        points += 2
        notes.append("HONEST 2/2  Reaches an edge and names it, with no "
                     "unqualified absolutes.")
    elif honest or hedged:
        points += 1
        notes.append("HONEST 1/2  Some hedging (%d) or edge-naming (%d), but "
                     "%d unqualified absolute(s): %s"
                     % (hedged, honest, len(absolutes),
                        ", ".join(absolutes) or "none"))
    else:
        notes.append("HONEST 0/2  No hedge, no edge, %d absolute(s): %s. An answer "
                     "with no uncertainty in it is either trivial or wrong."
                     % (len(absolutes), ", ".join(absolutes) or "none"))

    # --- Severity (0-2) -----------------------------------------------------
    n = count(lower, SEVERITY)
    if n >= 2:
        points += 2
        notes.append("SEV    2/2  Reasons about severity or false positives "
                     "(%d phrase(s))." % n)
    elif n == 1:
        points += 1
        notes.append("SEV    1/2  Touches severity once. Add the false-positive "
                     "case and who can actually reach the defect.")
    else:
        notes.append("SEV    0/2  No severity, reachability or false-positive "
                     "reasoning. If a finding was described, it was described "
                     "without its denominator.")

    # --- measured-contradiction fallacies (do not score; always report) ------
    # A hit is downgraded from FLAG to NOTE when the surrounding sentence shows
    # the writer is rebutting the fallacy rather than committing it.
    for pattern, message in FALLACIES:
        m = pattern.search(body)
        if not m:
            continue
        sentence = sentence_around(body, m.start()).lower()
        rebutting = any(word in sentence for word in REBUTTAL)
        notes.append("%s  %s" % ("NOTE " if rebutting else "FLAG ", message))
        if rebutting:
            notes.append("           (downgraded: the sentence around it reads as "
                         "a rebuttal, not a claim. Check it anyway.)")

    return points, notes


def sentence_around(text, index):
    """Return the sentence containing the character at `index`. Crude on purpose:
    splitting English into sentences properly is a research problem, and this only
    has to be good enough to tell 'X is the check' from 'X is dead'."""
    start = max(text.rfind(".", 0, index), text.rfind("\n\n", 0, index)) + 1
    end = text.find(".", index)
    if end == -1:
        end = len(text)
    return text[start:end + 1]


def split_sections(text):
    """Split on markdown H2/H3 headings. Returns [(title, body), ...]."""
    lines = text.split("\n")
    sections = []
    title = "(whole file)"
    buf = []
    for line in lines:
        if re.match(r"^#{2,3}\s+\S", line):
            if "".join(buf).strip():
                sections.append((title, "\n".join(buf)))
            title = line.lstrip("# ").strip()
            buf = []
        else:
            buf.append(line)
    if "".join(buf).strip():
        sections.append((title, "\n".join(buf)))
    return sections or [("(whole file)", text)]


def read_input(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8")


def main():
    ap = argparse.ArgumentParser(
        description="Lint a written interview answer for shape, evidence and honesty.")
    ap.add_argument("path", help="file to lint, or '-' for stdin")
    ap.add_argument("--split", action="store_true",
                    help="treat each markdown H2/H3 as a separate answer")
    ap.add_argument("--budget", type=int, default=None,
                    help="spoken budget in seconds, for the scope check")
    ap.add_argument("--min", type=int, default=None,
                    help="exit 1 if any section scores below this (out of 12)")
    ap.add_argument("--quiet", action="store_true",
                    help="print only the score lines")
    args = ap.parse_args()

    if args.path != "-" and not os.path.isfile(args.path):
        sys.stderr.write("error: no such file: %s\n" % args.path)
        return 2

    text = read_input(args.path)
    sections = split_sections(text) if args.split else [("(whole file)", text)]

    failed = False
    for title, body in sections:
        if not body.strip():
            continue
        points, notes = score_section(title, body, args.budget)
        verdict = ("RECITATION" if points <= 4
                   else "CORRECT BUT SHAPELESS" if points <= 8
                   else "READY")
        print("=" * 74)
        print("%-52s %2d/12  %s" % (title[:52], points, verdict))
        print("=" * 74)
        if not args.quiet:
            for n in notes:
                print("  " + n)
            print()
        if args.min is not None and points < args.min:
            failed = True

    if args.min is not None:
        print("threshold %d/12: %s" % (args.min, "FAIL" if failed else "PASS"))
    print()
    print("This is a lint, not a grader. It counts word shapes and cannot read.")
    print("Adjudicate every FLAG by hand -- a detector that agrees with you about")
    print("everything is a detector to distrust.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
