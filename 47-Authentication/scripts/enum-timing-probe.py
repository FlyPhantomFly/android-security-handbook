#!/usr/bin/env python3
# 47-Authentication/scripts/enum-timing-probe.py
#
# PURPOSE
#   Decide whether a login (or registration, or password-reset) endpoint leaks
#   ACCOUNT EXISTENCE, through any of four independent oracles:
#
#       1. the response BODY differing between known and unknown accounts
#       2. the STATUS CODE differing
#       3. the response LENGTH differing
#       4. the RESPONSE TIME differing        <- the one people miss
#
#   Oracle 4 is the interesting one because it survives the usual fix. A team
#   told "your error messages leak" makes both messages identical and considers
#   the matter closed, while the code still returns early for an unknown user
#   and skips a ~90 ms password hash. That is CWE-203 and it is still an oracle.
#
# WHAT MAKES THIS SCRIPT DIFFERENT FROM A STOPWATCH
#   It REFUSES TO CONCLUDE when the distributions overlap. Network jitter
#   routinely produces a difference that looks like a finding and is not, and a
#   timing claim you cannot reproduce destroys a report's credibility. The
#   verdict is one of DIFFERENT / INCONCLUSIVE, it is derived from the
#   interquartile ranges rather than the means, and it discards the slowest
#   decile before comparing (that decile is almost entirely network noise).
#
# USAGE
#   # against the chapter's local lab server - START HERE
#   python3 -B ../labs/authlab/auth_server.py --mode vulnerable &
#   python3 -B enum-timing-probe.py \
#       --url http://127.0.0.1:8047/api/v1/login \
#       --known alice@example.invalid \
#       --unknown nobody-8f2a@example.invalid \
#       --samples 40
#
#   # against an authorised target
#   python3 -B enum-timing-probe.py --url https://api.example.invalid/login \
#       --known you@yourdomain.invalid --unknown not-a-user@yourdomain.invalid \
#       --samples 40 --field username --password-field password
#
# ETHICS - READ BEFORE RUNNING
#   * BOTH addresses must be YOURS. `--known` is an account you own. `--unknown`
#     is an address that is yours to use and has no account.
#   * This confirms an ORACLE. It is not an enumeration tool and it will not
#     become one: it accepts exactly two identifiers and refuses a list.
#   * Default sample count is deliberately modest. You are demonstrating a
#     measurable difference, not running a campaign.
#   * It sends a fixed WRONG password every time, so it never authenticates and
#     never touches an account it should not.
#   * Rate limiting is a control, not an obstacle: if the target locks you out
#     part way through, that is a POSITIVE finding about the target and the
#     script reports it.
#
# DEPENDENCIES
#   Standard library only (urllib).

import argparse
import json
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.request

WRONG_PASSWORD = "not-the-password-Ch47-probe"


def post_json(url, payload, timeout, insecure):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Identify the tool. An assessment that cannot be distinguished from
            # an attack in the target's logs is a bad assessment.
            "User-Agent": "ch47-enum-timing-probe/1.0 (authorised testing)",
        })
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        data = e.read()
        status = e.code
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as e:
        return None, None, None, str(e)
    elapsed = time.perf_counter() - t0
    return elapsed, status, data, None


def sample(url, identifier, field, pwfield, n, timeout, insecure, delay):
    times, statuses, lengths, bodies = [], [], [], []
    errors = 0
    for i in range(n):
        payload = {field: identifier, pwfield: WRONG_PASSWORD}
        el, status, data, err = post_json(url, payload, timeout, insecure)
        if err is not None:
            errors += 1
            if errors > max(3, n // 4):
                print("  too many transport errors (%s); aborting this population"
                      % err, file=sys.stderr)
                break
            continue
        times.append(el)
        statuses.append(status)
        lengths.append(len(data))
        if len(bodies) < 3:
            bodies.append(data[:400])
        if delay:
            time.sleep(delay)
        # Progress, because a 40-sample run against a slow KDF takes a while.
        print("\r  %-40s %d/%d" % (identifier, i + 1, n), end="", file=sys.stderr)
    print("", file=sys.stderr)
    return {
        "times": times, "statuses": statuses, "lengths": lengths,
        "bodies": bodies, "errors": errors,
    }


def quartiles(v):
    s = sorted(v)
    n = len(s)
    return s[n // 4], s[n // 2], s[(3 * n) // 4]


def trimmed(v, drop_slowest_fraction=0.10):
    """Drop the slowest decile. That tail is network scheduling noise, and
    including it makes both populations look identical."""
    s = sorted(v)
    keep = max(4, int(len(s) * (1.0 - drop_slowest_fraction)))
    return s[:keep]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Detect account-enumeration oracles, including timing. "
                    "Two identifiers only; both must be yours.")
    ap.add_argument("--url", required=True, help="the login/reset endpoint")
    ap.add_argument("--known", required=True, help="an identifier that EXISTS (yours)")
    ap.add_argument("--unknown", required=True, help="an identifier that does NOT exist")
    ap.add_argument("--field", default="username", help="JSON field for the identifier")
    ap.add_argument("--password-field", default="password", dest="pwfield")
    ap.add_argument("--samples", type=int, default=40, help="requests per population")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds between requests; raise it to be gentle")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (for an intercepting proxy)")
    args = ap.parse_args(argv)

    if args.known == args.unknown:
        ap.error("--known and --unknown must differ")
    if args.samples < 8:
        ap.error("--samples below 8 cannot support any conclusion")
    if args.samples > 200:
        ap.error("--samples above 200 is a campaign, not a demonstration. "
                 "If you need more, the difference is too small to report.")

    print("=" * 74)
    print("47-Authentication / account-enumeration probe")
    print("  url      : %s" % args.url)
    print("  known    : %s" % args.known)
    print("  unknown  : %s" % args.unknown)
    print("  samples  : %d per population" % args.samples)
    print("=" * 74)
    print()
    print("Sampling (a fixed wrong password is sent every time; nothing")
    print("authenticates and no account is modified)...")

    k = sample(args.url, args.known, args.field, args.pwfield,
               args.samples, args.timeout, args.insecure, args.delay)
    u = sample(args.url, args.unknown, args.field, args.pwfield,
               args.samples, args.timeout, args.insecure, args.delay)

    if not k["times"] or not u["times"]:
        print("Insufficient responses to analyse. Check connectivity and the URL.")
        return 1

    findings = []

    # ---- Oracle 1: body ---------------------------------------------------
    print()
    print("-" * 74)
    print("ORACLE 1 - response body")
    kb = k["bodies"][0] if k["bodies"] else b""
    ub = u["bodies"][0] if u["bodies"] else b""
    print("  known   : %r" % kb[:160])
    print("  unknown : %r" % ub[:160])
    if kb != ub:
        print("  >> DIFFERENT. This is a direct oracle and needs no statistics.")
        findings.append("response body differs")
    else:
        print("  identical")

    # ---- Oracle 2: status -------------------------------------------------
    print()
    print("-" * 74)
    print("ORACLE 2 - status code")
    ks, us = set(k["statuses"]), set(u["statuses"])
    print("  known   : %s" % sorted(ks))
    print("  unknown : %s" % sorted(us))
    if ks != us:
        print("  >> DIFFERENT.")
        findings.append("status code differs")
    else:
        print("  identical")

    # Lockout detection - a positive result about the target.
    if len(ks) > 1 or len(us) > 1:
        print()
        print("  NOTE: the status changed part way through. That is very likely a")
        print("  RATE LIMIT or LOCKOUT engaging - which is a control working, and")
        print("  is worth recording as such. Re-run later with --delay if you need")
        print("  clean timing data.")

    # ---- Oracle 3: length -------------------------------------------------
    print()
    print("-" * 74)
    print("ORACLE 3 - response length")
    kl, ul = set(k["lengths"]), set(u["lengths"])
    print("  known   : %s bytes" % sorted(kl)[:5])
    print("  unknown : %s bytes" % sorted(ul)[:5])
    if kl.isdisjoint(ul):
        print("  >> DIFFERENT (disjoint), even if the bodies looked similar.")
        findings.append("response length differs")
    else:
        print("  overlapping")

    # ---- Oracle 4: timing -------------------------------------------------
    print()
    print("-" * 74)
    print("ORACLE 4 - response time")
    kt = trimmed(k["times"])
    ut = trimmed(u["times"])
    kq1, kmed, kq3 = quartiles(kt)
    uq1, umed, uq3 = quartiles(ut)
    ms = lambda x: x * 1000.0

    print("  known    n=%-3d  median=%7.1f ms   IQR=[%7.1f, %7.1f]"
          % (len(kt), ms(kmed), ms(kq1), ms(kq3)))
    print("  unknown  n=%-3d  median=%7.1f ms   IQR=[%7.1f, %7.1f]"
          % (len(ut), ms(umed), ms(uq1), ms(uq3)))
    delta = ms(kmed) - ms(umed)
    print("  delta (known - unknown) = %+.1f ms" % delta)

    overlapping = (kq1 <= umed <= kq3) or (uq1 <= kmed <= uq3)
    if overlapping:
        print()
        print("  >> INCONCLUSIVE. The interquartile ranges overlap, so this")
        print("     difference is not distinguishable from jitter at this sample")
        print("     size. DO NOT REPORT A TIMING ORACLE ON THIS EVIDENCE.")
    else:
        print()
        print("  >> DIFFERENT. The distributions are separated.")
        if delta > 0:
            print("     The KNOWN account is SLOWER, which is the expected shape:")
            print("     the server runs a slow password KDF only when the account")
            print("     exists, and returns early when it does not.")
        else:
            print("     The UNKNOWN account is slower. That is the inverse of the")
            print("     usual shape - look for a directory lookup, an outbound")
            print("     call, or logging on the not-found path before concluding.")
        findings.append("response time differs by %+.1f ms" % delta)

    # ---- Verdict ----------------------------------------------------------
    print()
    print("=" * 74)
    if findings:
        print("ENUMERATION ORACLE PRESENT via:")
        for f in findings:
            print("  - %s" % f)
        print()
        print("SEVERITY GUIDANCE (README section 5.4): Low on its own for a")
        print("consumer service, and it will be argued down. It rises when the")
        print("user base is itself sensitive - existence IS the disclosure - or")
        print("when chained with missing rate limiting, because enumeration turns")
        print("a broad campaign into a targeted one. Report it chained where you")
        print("can, and state which oracle you actually demonstrated.")
    else:
        print("No enumeration oracle detected on any of the four channels.")
        print()
        print("That is a real negative result and it is worth stating in the")
        print("report. Note the limit honestly: this tested the LOGIN endpoint.")
        print("Registration and password-reset are frequently weaker and are")
        print("tested separately.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
