#!/usr/bin/env python3
"""
bug6.py — Debugging challenge 6: the one that only fires sometimes.
Difficulty: * * * * -

RUN
  host $ python3 bug6.py                  # random inputs; fails eventually
  host $ python3 bug6.py --seed 12345     # deterministic; fails the same way every time
  host $ python3 bug6.py --minimise       # shrink a failing input automatically

This one cannot be found by reading the eight-line function, and 10 000 random inputs find it in
about a second. That contrast is the entire lesson.

See labs/lab-03-debugging-challenge.md.
"""

import argparse
import random
import sys


def allocate_slots(requests, capacity=100):
    """Distribute `capacity` slots across requests, proportionally to their weights."""
    total = sum(r["weight"] for r in requests)
    assigned = []
    remaining = capacity
    for r in requests:
        share = int(capacity * r["weight"] / total)
        assigned.append({"id": r["id"], "slots": share})
        remaining -= share
    # Give any leftover to the first request.
    assigned[0]["slots"] += remaining
    return assigned


def check(requests):
    """The invariants the function is supposed to maintain."""
    result = allocate_slots(requests)
    total = sum(a["slots"] for a in result)
    assert total == 100, f"allocated {total}, expected 100: {result}"
    for a in result:
        assert a["slots"] >= 0, f"negative allocation: {a}"
    return result


def fuzz(trials, seed=None, verbose=False):
    """Property-based testing, by hand. Generate inputs, assert the invariants, report the first
    failure with the exact input that produced it."""
    if seed is not None:
        random.seed(seed)
    else:
        random.seed()

    for trial in range(trials):
        n = random.randint(1, 8)
        reqs = [{"id": i, "weight": random.randint(0, 50)} for i in range(n)]
        try:
            check(reqs)
        except Exception as exc:
            print(f"FAILED on trial {trial}")
            print(f"  input : {reqs}")
            print(f"  error : {type(exc).__name__}: {exc}")
            return reqs
        if verbose and trial % 1000 == 0:
            print(f"  ... {trial} trials passed")

    print(f"{trials} trials passed (this run found nothing — try another seed)")
    return None


def minimise(failing):
    """Shrink a failing input to the smallest one that still fails.

    This is the automated version of the bisection in chapter 03 section 7.1.3, and it is what
    turns 'it broke on this eight-element list of random numbers' into 'it breaks on [{w:0}]',
    which is a bug report someone can act on.
    """
    def fails(candidate):
        if not candidate:
            return False
        try:
            check(candidate)
            return False
        except Exception:
            return True

    current = list(failing)

    changed = True
    while changed:
        changed = False

        # Try removing each element.
        for i in range(len(current)):
            trial = current[:i] + current[i + 1:]
            if fails(trial):
                current = trial
                changed = True
                break
        if changed:
            continue

        # Try shrinking each weight towards zero.
        for i in range(len(current)):
            for candidate_weight in (0, 1, current[i]["weight"] // 2):
                if candidate_weight == current[i]["weight"]:
                    continue
                trial = [dict(r) for r in current]
                trial[i]["weight"] = candidate_weight
                if fails(trial):
                    current = trial
                    changed = True
                    break
            if changed:
                break

    return current


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=None,
                    help="fix the seed so the failure is reproducible")
    ap.add_argument("--minimise", action="store_true",
                    help="shrink the failing input to the smallest one that still fails")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    failing = fuzz(args.trials, args.seed, args.verbose)
    if failing is None:
        return 0

    if args.minimise:
        print("\nminimising...")
        small = minimise(failing)
        print(f"  smallest failing input: {small}")
        try:
            check(small)
        except Exception as exc:
            print(f"  still fails: {type(exc).__name__}: {exc}")
    return 1


if __name__ == "__main__":
    sys.exit(main())


# ==================================================================================================
# QUESTIONS
#   1. Run it a few times. What exception appears, and what is the failing input?
#   2. Fix the seed with --seed so it fails identically every run. Why is that the FIRST step in
#      debugging anything intermittent?
#   3. Run with --minimise. What is the smallest failing input? Is the cause obvious now?
#   4. There is more than one path to failure. Find at least two.
#   5. Why did 10 000 random trials find in one second what reading the eight-line function did not?
#      Write one sentence about what that implies for how you should test parsers.
#
# THE ROOT CAUSES (do not read until you have tried)
#
#   a. ZeroDivisionError. If every weight is 0 — which random.randint(0, 50) produces regularly for
#      small n — then `total` is 0 and `capacity * weight / total` divides by zero. The developer's
#      mental model was "weights are positive"; nothing in the code says so.
#
#   b. The rounding. int() truncates, so each share loses a fraction, and `remaining` accumulates
#      all of them. That is intentional and works. But if the FIRST request's own truncated share
#      plus the accumulated remainder is computed when total is very small relative to capacity,
#      the first entry can end up holding almost everything — and if weights were allowed to be
#      negative (nothing forbids it), `remaining` can exceed capacity and `assigned[0]` goes wrong
#      in the other direction.
#
#   c. Empty input. `assigned[0]` raises IndexError if `requests` is empty. Again the developer's
#      model — "there is always at least one request" — is not written down anywhere.
#
# THE FIX
#   Validate the precondition explicitly, at the top, in one place:
#
#       if not requests:
#           return []
#       if any(r["weight"] < 0 for r in requests):
#           raise ValueError("weights must be non-negative")
#       total = sum(r["weight"] for r in requests)
#       if total == 0:
#           # every weight is zero: distribute evenly, which is the only defensible answer
#           base, extra = divmod(capacity, len(requests))
#           return [{"id": r["id"], "slots": base + (1 if i < extra else 0)}
#                   for i, r in enumerate(requests)]
#
#   Notice that the fix is mostly about writing down assumptions that already existed in the
#   developer's head. That is what most parser hardening turns out to be.
# ==================================================================================================
