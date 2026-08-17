#!/usr/bin/env python3
"""
sum_demo.py — the chapter's reference program, at the HIGHEST level of abstraction.

PURPOSE
  One program, written four ways. This is version 1 of 4. Compare it against:
      sum_demo.c    — statically typed, compiled ahead of time to native code
      SumDemo.java  — statically typed, compiled to bytecode, run by a VM
      sum_demo.s    — the level the CPU actually works at

  All four do EXACTLY the same thing. They look nothing alike. That is the whole point of
  chapter 03 section 2.3: there is one program, and four ways of writing it down.

THE PROGRAM
  Start a total at zero. For each number from 1 up to n, add it to the total. If at any point
  the total exceeds the limit, stop immediately and report failure. Otherwise report the total.

USAGE
  host $ python3 sum_demo.py
  host $ python3 sum_demo.py 100 1000        # n and limit as arguments
  host $ python3 sum_demo.py --trace 10 20   # print every step

WHAT TO NOTICE
  * No type declarations anywhere. Python decides at run time what `total` is.
  * No compilation step. The file IS the program; delete it and there is nothing left.
  * Python integers NEVER overflow. Try sum_demo.py 100000 999999999999999999999 and
    compare with what the C version does. That difference is chapter 03 section 3.4.

Chapter 03 — Programming Fundamentals, sections 2.3 and 9.1
"""

import sys


def bounded_sum(n, limit, trace=False):
    """Sum 1..n, aborting with -1 if the running total exceeds `limit`.

    Note what is NOT here compared with the C version:
      * no type on n, limit, total or i
      * no declared return type
      * no possibility of integer overflow — Python integers grow without bound
    """
    total = 0                          # a name bound to an integer object
    for i in range(1, n + 1):          # range is a generator: it does not build a list
        total = total + i
        if trace:
            print(f"  i={i:3d}  total={total}")
        if total > limit:
            return -1                  # sentinel meaning "exceeded the limit"
    return total


def main(argv):
    trace = "--trace" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]

    n = int(args[0]) if len(args) > 0 else 10
    limit = int(args[1]) if len(args) > 1 else 1000

    result = bounded_sum(n, limit, trace)
    print(result)

    # A note for the reader, not part of the program's job.
    if result == -1:
        print(f"# the running total exceeded {limit} before reaching n={n}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# -----------------------------------------------------------------------------------------------
# EXPERIMENTS — do these, they are the point of the file.
#
# 1. Delete this file and try to run it again. Compare with deleting sum_demo.c after building it.
#    Question: for an interpreted language, what IS "the program"?
#
# 2. Run:   python3 sum_demo.py 100000 99999999999999999999999999
#    Python happily computes a total far beyond 2^63. Now run the C version with the same
#    arguments and watch it produce a wrong answer silently. That is integer overflow, and the
#    reason chapter 03 spends a whole section on it.
#
# 3. Run:   python3 -c "import dis, sum_demo; dis.dis(sum_demo.bounded_sum)"
#    Python compiles to bytecode too — it just does it invisibly, at import time, and caches it
#    in __pycache__. Compare that bytecode with `javap -c SumDemo`. Both are stack machines.
#    You will recognise the loop: a comparison, a forward jump out, a backward jump in.
#
# 4. Time it against the C version for n = 10_000_000. The ratio is roughly the cost of
#    interpretation, and it is why ART does not interpret everything.
# -----------------------------------------------------------------------------------------------
