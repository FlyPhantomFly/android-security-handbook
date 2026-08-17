#!/usr/bin/env python3
"""
provider-reachability-probe.py -- take exported ContentProviders from a corpus
                                  sweep and establish, READ-ONLY, whether each
                                  is actually reachable -- and, when it is not,
                                  WHICH LAYER refused.

WHY THIS EXISTS
    "Exported provider with no permission" is an observation. Chapter 72's Gate 2
    asks whether a defined attacker can reach it, and the only honest way to
    answer that is to try. Section 3.5 measured 2,674 exported components
    collapsing to 77 provider leads; this script is what turns those leads into
    a verdict.

THE DISTINCTION THIS SCRIPT EXISTS FOR
    A failed query is not one outcome, it is three, and they lead to different
    conclusions. The exception type tells you which layer refused you:

      SecurityException: Permission Denial ...
          Raised by ContentProvider.enforceReadPermissionInner BEFORE the target
          app's code runs. You are OUTSIDE. Gate 2 fails.

      UnsupportedOperationException / IllegalStateException, with app frames
          Raised by the TARGET APPLICATION'S OWN CODE. The binder transaction
          landed and the framework's permission check passed. You are INSIDE,
          holding the wrong verb -- query() is unimplemented, but call(),
          openFile() or insert() may not be. STILL A LEAD.

      "No result found."
          The query executed and the table was empty. Reachable. On a
          freshly-provisioned device this says nothing about a real user's
          phone -- Gate 3 is UNTESTED, not failed.

    A classifier that buckets the first two together as "error" throws away the
    distinction that decides the finding. In the reference run below, that
    mistake would have discarded 25 reachable providers.

VANTAGE -- READ THIS BEFORE READING ANY RESULT
    This probe runs `adb shell content query`, so it measures reachability from
    uid 2000, which is NOT an app. `com.android.shell` requests 200 permissions,
    holds 183 at install and 16 pre-granted runtime permissions flagged
    SYSTEM_FIXED -- including READ_CONTACTS, verified on the reference device.
    A provider answering this probe may be answering the SHELL, not an attacker.

    Use --note-vantage to stamp that caveat into the output, and confirm any
    load-bearing result from an app uid (run-as, a probe APK, or Frida
    in-process) before it reaches a report. This is chapter 72 section 3.4's
    vantage rule, and it invalidates results silently in both directions.

SAFETY
    Read-only by construction. The only device command issued is
    `content query --uri ...`. Nothing is inserted, updated, deleted or called,
    and nothing is written to the device. Run it only against a device and
    applications you are authorised to test.

USAGE
    # from a ledger written by manifest-corpus-sweep.py --json
    python3 -B provider-reachability-probe.py --ledger ledger.json

    # from an explicit list of authorities, one per line
    python3 -B provider-reachability-probe.py --authorities auths.txt

    # include providers that DO declare a guard, to see the refusals
    python3 -B provider-reachability-probe.py --ledger ledger.json --include-guarded

    python3 -B provider-reachability-probe.py --ledger ledger.json --json out.json

WAS THIS EXECUTED?
    YES. Run on 2026-08-16 against AVD `sdk_gphone16k_x86_64` (emulator-5554),
    Android 15 / API 35 -- the only device attached. 82 distinct authorities
    belonging to exported providers that declare no read guard were probed:

        REACHABLE  - returned rows                    1   ( 1.2%)
        REACHABLE  - empty result set                36   (43.9%)
        REACHED    - app code ran, query unimplemented 25  (30.5%)
        REFUSED    - framework permission denial       7   ( 8.5%)
        INDETERMINATE - authority root not queryable  13   (15.9%)

    62 of 82 (75.6%) reachable in some form; 7 actually refused. Corpus caveat:
    four of the 243 packages on that image are third-party, so this describes
    the platform, not the applications a commercial assessment targets.
"""

import argparse
import json
import subprocess
import sys

# Ordered most-specific first. The first pattern that matches wins, which is why
# the framework denial is tested before the generic exception bucket.
VERDICTS = [
    ("REFUSED_PERMISSION",
     ("permission denial", "securityexception"),
     "Framework refused before the app ran. Gate 2 FAILS at this vantage."),
    ("REACHED_UNIMPLEMENTED",
     ("unsupportedoperationexception", "unimplemented", "not supported",
      "query not supported"),
     "App code ran and refused the VERB. You are inside. Still a lead: try "
     "call/openFile/insert, and enumerate paths."),
    ("INDETERMINATE_PATH",
     ("could not find provider", "unknown uri", "illegalargumentexception",
      "unknown url"),
     "Authority root is not a queryable path. NOT a negative result -- "
     "enumerate path segments before concluding anything."),
]


def classify(text):
    low = text.lower()
    for name, needles, note in VERDICTS:
        if any(n in low for n in needles):
            return name, note
    stripped = text.strip()
    if stripped.startswith("Row:"):
        return ("REACHABLE_ROWS",
                "Data crossed the boundary. Gate 2 passes; Gate 3 opens -- "
                "now argue what the data is worth.")
    if "no result found" in low:
        return ("REACHABLE_EMPTY",
                "Query executed, table empty. Gate 2 passes. Gate 3 is "
                "UNTESTED, not failed -- a clean device is not a clean app.")
    if not stripped:
        return "NO_OUTPUT", "No output at all. Re-run; check the device is alive."
    # An exception raised by the app that is not in the lists above still means
    # the app's code ran, which is the load-bearing fact.
    if "exception" in low or "error" in low:
        return ("REACHED_APP_ERROR",
                "An exception carrying app frames. The transaction landed. "
                "Read the stack: whose code threw?")
    return "UNKNOWN", "Unrecognised output. Adjudicate by hand."


def authorities_from_ledger(path, include_guarded):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows, seen = [], set()
    for app in data.get("apps", []):
        for comp in app.get("exported", []):
            if comp.get("kind") != "provider":
                continue
            if comp.get("guard") and not include_guarded:
                continue
            auth = comp.get("authorities")
            if not auth:
                continue
            if isinstance(auth, str) and auth.startswith("@ref/"):
                # TYPE_REFERENCE: the real value lives in resources.arsc.
                # Emitting the integer would produce a nonsense authority and a
                # nonsense negative -- chapter 72 section 8.2.
                rows.append({"pkg": app["pkg"], "authority": None,
                             "guard": comp.get("guard"), "unresolved": auth})
                continue
            for a in str(auth).split(";"):
                a = a.strip()
                if a and (app["pkg"], a) not in seen:
                    seen.add((app["pkg"], a))
                    rows.append({"pkg": app["pkg"], "authority": a,
                                 "guard": comp.get("guard"),
                                 "grantUri": comp.get("grantUri", False)})
    return rows


def probe(auth, serial, timeout):
    cmd = ["adb"] + (["-s", serial] if serial else []) + \
          ["shell", "content", "query", "--uri", "content://" + auth]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "<timeout>"
    except OSError as exc:
        return f"<adb failed: {exc}>"


def main():
    ap = argparse.ArgumentParser(
        description="Read-only reachability probe for exported ContentProviders. "
                    "Classifies WHICH LAYER refused, not merely whether it failed.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ledger", help="JSON from manifest-corpus-sweep.py --json")
    src.add_argument("--authorities", help="text file, one authority per line")
    ap.add_argument("--serial", help="adb device serial")
    ap.add_argument("--include-guarded", action="store_true",
                    help="also probe providers that declare a guard")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--json", metavar="FILE", help="write full results")
    ap.add_argument("--note-vantage", action="store_true", default=True,
                    help="stamp the shell-vantage caveat into the output (default on)")
    args = ap.parse_args()

    if args.ledger:
        rows = authorities_from_ledger(args.ledger, args.include_guarded)
    else:
        with open(args.authorities, encoding="utf-8") as fh:
            rows = [{"pkg": "?", "authority": ln.strip(), "guard": None}
                    for ln in fh if ln.strip() and not ln.startswith("#")]

    unresolved = [r for r in rows if not r.get("authority")]
    rows = [r for r in rows if r.get("authority")]
    if not rows:
        sys.exit("error: no authorities to probe")

    who = subprocess.run(["adb"] + (["-s", args.serial] if args.serial else []) +
                         ["shell", "id"], capture_output=True, text=True).stdout.strip()
    print("=" * 74)
    print("PROVIDER REACHABILITY PROBE -- read-only")
    print("=" * 74)
    print(f"  vantage : {who or '(could not read `id` -- is a device attached?)'}")
    if args.note_vantage:
        print("  CAVEAT  : uid 2000 is NOT an app. com.android.shell holds 16")
        print("            pre-granted SYSTEM_FIXED runtime permissions. Confirm any")
        print("            load-bearing result from an app uid before reporting it.")
    print(f"  probing : {len(rows)} authorities")
    if unresolved:
        print(f"  skipped : {len(unresolved)} with an unresolved @ref authority "
              "(needs resources.arsc)")

    results, tally = [], {}
    for r in rows:
        raw = probe(r["authority"], args.serial, args.timeout)
        verdict, note = classify(raw)
        tally[verdict] = tally.get(verdict, 0) + 1
        results.append({**r, "verdict": verdict, "note": note,
                        "raw": raw.strip()[:400]})
        print(f"  {verdict:<24} {r['authority'][:46]}")

    total = len(results)
    print("\n" + "=" * 74)
    print(f"OUTCOMES  (n={total})")
    print("=" * 74)
    order = ["REACHABLE_ROWS", "REACHABLE_EMPTY", "REACHED_UNIMPLEMENTED",
             "REACHED_APP_ERROR", "REFUSED_PERMISSION", "INDETERMINATE_PATH",
             "NO_OUTPUT", "UNKNOWN"]
    for k in order:
        if k in tally:
            v = tally[k]
            print(f"  {k:<24} {v:>4}  {100.0*v/total:5.1f}%")
    reach = sum(tally.get(k, 0) for k in
                ("REACHABLE_ROWS", "REACHABLE_EMPTY",
                 "REACHED_UNIMPLEMENTED", "REACHED_APP_ERROR"))
    refused = tally.get("REFUSED_PERMISSION", 0)
    print(f"\n  reachable in some form   {reach:>4}  {100.0*reach/total:5.1f}%")
    print(f"  actually refused         {refused:>4}  {100.0*refused/total:5.1f}%")
    print("\n  Reachable is Gate 2, not a finding. Gate 3 -- what is behind it --")
    print("  is still yours to argue, and an empty table on a clean device is")
    print("  UNTESTED rather than harmless.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"vantage": who, "results": results,
                       "unresolved": unresolved}, fh, indent=1)
        print(f"\n[*] full results written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
