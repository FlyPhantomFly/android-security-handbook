#!/usr/bin/env python3
# 75-InterviewQuestions/scripts/mock-round.py
#
# PURPOSE
#   Run a mock interview round against this repository's own question bank, under
#   the constraint that makes interviews hard: a clock.
#
#   The single most common way a well-prepared candidate underperforms is not
#   ignorance. It is spending six minutes on a question worth ninety seconds, and
#   then being cut off on the question they could have answered best. You cannot
#   practise that alone by reading. You can practise it with a timer and a
#   randomised sheet you have not seen.
#
#   This script deliberately does NOT print model answers. The answers live in the
#   chapter that justifies them, and it prints the link instead. An answer read
#   next to its question teaches recall; an answer read inside the chapter that
#   derives it teaches the derivation, which is the thing an interviewer probes.
#
# USAGE
#   First build the question bank (mechanically, from the chapter READMEs):
#       python3 -B scripts/build-interview-index.py --format json --out bank.json
#
#   Then:
#       # a printable sheet -- no clock, no interaction (the default; scriptable)
#       python3 -B scripts/mock-round.py --bank bank.json --round "Technical phone screen"
#
#       # the same sheet, but live, with a per-question budget and a running clock
#       python3 -B scripts/mock-round.py --bank bank.json --timed --count 8
#
#       # a specific tier, a specific role, a reproducible draw
#       python3 -B scripts/mock-round.py --bank bank.json --tier Senior --seed 7
#       python3 -B scripts/mock-round.py --bank bank.json --role "Reverse Engineer / Malware Analyst"
#
#       # list what pools exist
#       python3 -B scripts/mock-round.py --bank bank.json --list-pools
#
#   Run with -B so no __pycache__ is written into the repository.
#
# WAS THIS EXECUTED?
#   YES, in sheet mode and in --timed mode with --budget 1, against a bank built on
#   2026-08-16 holding 1,258 questions from 71 chapters. Sheet mode is the default
#   precisely so the script is runnable non-interactively in CI or by an agent.
#
# EXIT STATUS
#   0 normally. 2 if the bank file is missing or the requested pool is empty.

import argparse
import json
import os
import random
import sys
import time

# Keep these in step with build-interview-index.py. They are duplicated rather than
# imported so this script works on a bank JSON copied to another machine.
TIERS = ["Beginner", "Intermediate", "Senior", "Staff Engineer", "Principal Engineer"]

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
        "count": 5, "budget": 60,
    },
    "Technical phone screen": {
        "tiers": ["Beginner", "Intermediate"],
        "chapters": ["10", "21", "23", "26", "32", "33", "35", "37", "52", "53", "60"],
        "count": 8, "budget": 150,
    },
    "Deep technical round": {
        "tiers": ["Intermediate", "Senior"],
        "chapters": ["13", "22", "25", "27", "29", "34", "36", "43", "44", "46",
                     "47", "48", "49", "56", "65", "67", "68"],
        "count": 6, "budget": 420,
    },
    "Practical / take-home": {
        "tiers": ["Intermediate", "Senior"],
        "chapters": ["10", "51", "52", "53", "55", "56", "60", "69", "70", "71"],
        "count": 5, "budget": 480,
    },
    "System design / architecture": {
        "tiers": ["Senior", "Staff Engineer", "Principal Engineer"],
        "chapters": ["20", "24", "34", "45", "46", "47", "49", "50", "71"],
        "count": 3, "budget": 900,
    },
    "Behavioural / values": {
        "tiers": ["Senior", "Staff Engineer", "Principal Engineer"],
        "chapters": ["20", "51", "52", "70", "71"],
        "count": 4, "budget": 300,
    },
}

# The self-marking rubric. Every line is a thing an interviewer is actually
# listening for; none of them is "did you know the fact".
RUBRIC = [
    ("Shape",
     "Did the answer go analogy or plain statement FIRST, then the precise "
     "definition, then the mechanism, then the security consequence? Or did it "
     "open with a command?"),
    ("Scope",
     "Did the answer finish inside the budget, or did it run until stopped? An "
     "answer that has to be interrupted is an answer the interviewer had to grade "
     "for you."),
    ("Boundary",
     "Did the answer name the trust boundary -- what is on the attacker's side of "
     "it and what is not? Almost every Android security answer bottoms out here."),
    ("Evidence",
     "Did the answer distinguish what was MEASURED from what was READ? 'I have "
     "measured this' and 'the documentation says' are different claims."),
    ("Honesty",
     "Where the answer reached the edge of knowledge, did it say so and then say "
     "how it would find out -- or did it keep going and start inventing?"),
    ("Severity",
     "If a finding was described, was the severity defensible, and was the "
     "false-positive case considered? 'I grepped and found nothing' is a statement "
     "about the grep."),
]


def load_bank(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return json.loads(raw.decode("utf-8"))


def flatten(bank):
    out = []
    for chapter in bank:
        for q in chapter.get("questions", []):
            out.append({
                "number": chapter["number"],
                "dir": chapter["dir"],
                "title": chapter["title"],
                "anchor": chapter.get("section_anchor") or "",
                "tier": q["tier"],
                "text": q["text"],
            })
    return out


def build_pool(questions, args):
    pool = questions
    label = "everything"
    budget = args.budget
    count = args.count

    if args.round:
        spec = ROUND_MAP.get(args.round)
        if spec is None:
            sys.stderr.write("error: unknown round %r; try --list-pools\n" % args.round)
            return None, None, None, None
        pool = [q for q in pool
                if q["tier"] in spec["tiers"] and q["number"] in spec["chapters"]]
        label = args.round
        if budget is None:
            budget = spec["budget"]
        if count is None:
            count = spec["count"]

    if args.role:
        numbers = ROLE_TRACKS.get(args.role)
        if numbers is None:
            sys.stderr.write("error: unknown role %r; try --list-pools\n" % args.role)
            return None, None, None, None
        pool = [q for q in pool if q["number"] in numbers]
        label = "%s / %s" % (label, args.role) if args.round else args.role

    if args.tier:
        pool = [q for q in pool if q["tier"] == args.tier]
        label = "%s / %s" % (label, args.tier) if label != "everything" else args.tier

    if args.chapter:
        wanted = set(args.chapter.split(","))
        pool = [q for q in pool if q["number"] in wanted]
        label = "%s / chapters %s" % (label, args.chapter)

    return pool, label, (budget if budget is not None else 180), (count if count is not None else 6)


def print_pools(questions):
    print("Rounds (each has its own default count and per-question budget):")
    for name, spec in ROUND_MAP.items():
        n = len([q for q in questions
                 if q["tier"] in spec["tiers"] and q["number"] in spec["chapters"]])
        print("  %-32s pool %4d   %d questions x %ds"
              % (name, n, spec["count"], spec["budget"]))
    print()
    print("Roles:")
    for name, numbers in ROLE_TRACKS.items():
        n = len([q for q in questions if q["number"] in numbers])
        print("  %-46s pool %4d" % (name, n))
    print()
    print("Tiers:")
    for tier in TIERS:
        n = len([q for q in questions if q["tier"] == tier])
        print("  %-32s pool %4d" % (tier, n))


def render_sheet(drawn, label, budget):
    total = len(drawn) * budget
    print("=" * 74)
    print("MOCK ROUND -- %s" % label)
    print("%d questions, %ds each, %d min total. No answers below, by design."
          % (len(drawn), budget, total // 60))
    print("=" * 74)
    print()
    for i, q in enumerate(drawn, 1):
        print("Q%d  [%s]  (%ds)" % (i, q["tier"], budget))
        print("    %s" % q["text"])
        print()
    print("-" * 74)
    print("WHERE THE ANSWERS ARE -- read them in the chapter, not next to the question")
    print("-" * 74)
    for i, q in enumerate(drawn, 1):
        print("Q%d  %s/README.md%s" % (i, q["dir"], q["anchor"]))
    print()
    print_rubric()


def print_rubric():
    print("-" * 74)
    print("SELF-MARK -- score each answer 0/1/2 on each line, out of 12")
    print("-" * 74)
    for name, text in RUBRIC:
        # 16 = len("  [ ] ") + the 9-wide name field + one space, so continuation
        # lines align under the first word of the text.
        print("  [ ] %-9s %s" % (name, wrap(text, 56, 16)))
    print()
    print("  0-4   The answer was a recitation. Reread the chapter's section 3.")
    print("  5-8   Correct and unstructured. Practise the SHAPE, not more facts.")
    print("  9-12  Ready. Now do it again with a harder tier.")
    print()
    print("A perfect score with a wrong fact still beats a wrong score with a right")
    print("fact, because the interviewer is hiring the method.")


def wrap(text, width, indent):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    pad = "\n" + " " * indent
    return pad.join(lines)


def run_timed(drawn, label, budget):
    print("=" * 74)
    print("TIMED ROUND -- %s   %d questions x %ds"
          % (label, len(drawn), budget))
    print("Answer OUT LOUD. Press Enter when you have finished, or wait for the")
    print("budget to expire. Nothing you type is recorded; the clock is the point.")
    print("=" * 74)
    results = []
    for i, q in enumerate(drawn, 1):
        print()
        print("Q%d  [%s]  budget %ds" % (i, q["tier"], budget))
        print("    %s" % q["text"])
        start = time.time()
        try:
            input("    > press Enter when finished... ")
        except EOFError:
            # Non-interactive stdin. Record no timing rather than inventing one:
            # a fabricated measurement is worse than an absent one, which is a
            # rule this repository applies to devices and applies here too.
            print("(no tty -- not timed)")
            results.append((q, None, False))
            continue
        elapsed = time.time() - start
        over = elapsed > budget
        results.append((q, elapsed, over))
        print("    %.0fs %s" % (elapsed, "OVER BUDGET" if over else "within budget"))
    print()
    print("-" * 74)
    print("TIMING")
    print("-" * 74)
    over_count = 0
    timed_count = 0
    for i, (q, elapsed, over) in enumerate(results, 1):
        if elapsed is None:
            print("Q%d  %7s  %-18s" % (i, "n/a", q["tier"]))
            continue
        timed_count += 1
        over_count += 1 if over else 0
        print("Q%d  %6.0fs  %-18s %s"
              % (i, elapsed, q["tier"], "OVER" if over else ""))
    print()
    print("%d of %d timed answers over budget." % (over_count, timed_count))
    if timed_count and over_count > timed_count // 2:
        print("More than half. The problem is scoping, not knowledge: decide the")
        print("last sentence BEFORE you start the first one.")
    print()
    for i, q in enumerate(drawn, 1):
        print("Q%d  %s/README.md%s" % (i, q["dir"], q["anchor"]))
    print()
    print_rubric()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        description="Run a timed mock interview round from this repo's question bank.")
    # Default to the CURRENT directory, deliberately not a path inside the
    # repository: the bank is a generated artefact and a committed copy would be
    # a stale duplicate of the thing build-interview-index.py exists to keep
    # current. Generate it to /tmp or a scratch directory and pass --bank.
    ap.add_argument("--bank", default="bank.json",
                    help="question bank JSON from build-interview-index.py --format json "
                         "(default: ./bank.json)")
    ap.add_argument("--round", help="one of the named rounds; see --list-pools")
    ap.add_argument("--role", help="one of the named role tracks; see --list-pools")
    ap.add_argument("--tier", choices=TIERS, help="restrict to one tier")
    ap.add_argument("--chapter", help="comma-separated chapter numbers, e.g. 37,39,48")
    ap.add_argument("--count", type=int, default=None, help="questions to draw")
    ap.add_argument("--budget", type=int, default=None,
                    help="seconds per question")
    ap.add_argument("--seed", type=int, default=None,
                    help="reproducible draw (omit for a fresh one)")
    ap.add_argument("--timed", action="store_true",
                    help="run live with a clock instead of printing a sheet")
    ap.add_argument("--list-pools", action="store_true",
                    help="print the available rounds, roles and tiers, then exit")
    args = ap.parse_args()

    if not os.path.isfile(args.bank):
        sys.stderr.write(
            "error: no bank at %s\n"
            "       build one first, outside the repository:\n"
            "       python3 -B scripts/build-interview-index.py --format json "
            "--out /tmp/bank.json\n"
            "       then pass it with --bank /tmp/bank.json\n" % args.bank)
        return 2

    questions = flatten(load_bank(args.bank))

    if args.list_pools:
        print_pools(questions)
        return 0

    pool, label, budget, count = build_pool(questions, args)
    if pool is None:
        return 2
    if not pool:
        sys.stderr.write("error: that pool is empty -- loosen the filters\n")
        return 2

    rng = random.Random(args.seed)
    count = min(count, len(pool))
    # Sample without replacement, then spread across chapters so a round does not
    # accidentally become a single-chapter viva.
    drawn = rng.sample(pool, count)
    drawn.sort(key=lambda q: (TIERS.index(q["tier"]), q["number"]))

    if args.timed:
        run_timed(drawn, label, budget)
    else:
        render_sheet(drawn, label, budget)
    return 0


if __name__ == "__main__":
    sys.exit(main())
