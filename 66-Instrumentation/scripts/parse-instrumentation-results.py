#!/usr/bin/env python3
# scripts/parse-instrumentation-results.py
#
# PURPOSE
#   Turn the output of `am instrument -r` into something a script can consume,
#   and -- more importantly -- tell the difference between the four outcomes that
#   all look similar on a terminal:
#
#       PASS      the instrumentation ran and reported RESULT_OK (-1)
#       FAIL      the instrumentation ran and reported a failure code
#       CRASH     the instrumentation process died; a stack trace came back
#       REFUSED   ActivityManagerService never started it at all
#
#   The last one is the one that costs people time. A refused start still exits
#   0 from `adb shell`, still prints INSTRUMENTATION_STATUS lines, and in a CI
#   log looks almost exactly like a test that ran and passed nothing. Grepping
#   for "OK (0 tests)" will not save you; grepping for the absence of an error
#   will not either. Parse the stream.
#
# USAGE
#   # host -- pipe am instrument straight in
#   adb shell am instrument -w -r <pkg>/<runner> | python3 -B parse-instrumentation-results.py
#
#   # host -- read a saved log
#   python3 -B parse-instrumentation-results.py run.txt
#
#   # host -- JSON for a harness, and a non-zero exit on anything but PASS
#   adb shell am instrument -w -r <pkg>/<runner> \
#       | python3 -B parse-instrumentation-results.py --json --strict
#
#   # host -- only these result keys
#   python3 -B parse-instrumentation-results.py run.txt --key read. --key deny.
#
# WAS THIS SCRIPT EXECUTED?
#   YES, and here is exactly how far, because two of the four verdicts were
#   exercised against synthetic input rather than a device:
#
#     PASS      LIVE. `am instrument` output from vault-probe on the AVD
#               sdk_gphone16k_x86_64 (Android 15 / API 35). 55 result keys
#               parsed, verdict PASS, --strict exit 0.
#     REFUSED   LIVE. Matrix row 3 (signature mismatch). Verdict REFUSED, denial
#               text recovered from inside a status value, 17 stack frames
#               counted, --strict exit 1.
#     CRASH     SYNTHETIC transcript. The shipped probe catches Throwable and
#               therefore cannot crash on demand, so this path was exercised
#               against a hand-written stream carrying shortMsg plus three stack
#               frames. Verdict CRASH.
#     FAIL      SYNTHETIC transcript, same reason. Verdict FAIL.
#
#   The distinction matters: a verdict validated against a fabricated stream has
#   been shown to be self-consistent, not shown to be right about a real device.
#
# THE WIRE FORMAT, BRIEFLY
#   With -r ("raw"), `am` prints the protocol instead of decoding it:
#
#       INSTRUMENTATION_STATUS: <key>=<value>       progress, may repeat
#       INSTRUMENTATION_STATUS_CODE: <int>          end of one status block
#       INSTRUMENTATION_RESULT: <key>=<value>       final bundle, once
#       INSTRUMENTATION_CODE: <int>                 overall result code
#       INSTRUMENTATION_FAILED: <component>         AMS could not start it
#
#   Values may span lines: a stack trace arrives as one key whose value contains
#   newlines, and every continuation line is un-prefixed. Anything that splits
#   the stream on '\n' and then on '=' will silently truncate exactly the
#   diagnostic you needed. This parser accumulates continuations.
#
#   INSTRUMENTATION_CODE carries android.app.Activity.RESULT_OK, which is -1.
#   A code of -1 is SUCCESS. This surprises everybody once.
#
# AUTHORISED TESTING ONLY.

import argparse
import json
import re
import sys

RESULT_OK = -1
RESULT_CANCELED = 0

RX_STATUS = re.compile(r"^INSTRUMENTATION_STATUS: (.*)$")
RX_STATUS_CODE = re.compile(r"^INSTRUMENTATION_STATUS_CODE: (-?\d+)\s*$")
RX_RESULT = re.compile(r"^INSTRUMENTATION_RESULT: (.*)$")
RX_CODE = re.compile(r"^INSTRUMENTATION_CODE: (-?\d+)\s*$")
RX_FAILED = re.compile(r"^INSTRUMENTATION_FAILED: (.*)$")
RX_ABORTED = re.compile(r"^INSTRUMENTATION_ABORTED: (.*)$")

# A refusal comes back as a SecurityException from AMS, not as a status code.
RX_DENIAL = re.compile(r"(Permission Denial:.*|java\.lang\.SecurityException:.*)")


def parse(lines):
    out = {
        "results": {},
        "status": {},
        "code": None,
        "status_codes": [],
        "failed": None,
        "aborted": None,
        "denial": None,
        "stack_frames": 0,
        "verdict": None,
    }

    current = None          # ("results"|"status", key)

    for raw in lines:
        line = raw.rstrip("\n").rstrip("\r")

        m = RX_CODE.match(line)
        if m:
            out["code"] = int(m.group(1))
            current = None
            continue

        m = RX_STATUS_CODE.match(line)
        if m:
            out["status_codes"].append(int(m.group(1)))
            current = None
            continue

        m = RX_FAILED.match(line)
        if m:
            out["failed"] = m.group(1)
            current = None
            continue

        m = RX_ABORTED.match(line)
        if m:
            out["aborted"] = m.group(1)
            current = None
            continue

        for rx, bucket in ((RX_RESULT, "results"), (RX_STATUS, "status")):
            m = rx.match(line)
            if m:
                body = m.group(1)
                key, sep, value = body.partition("=")
                if sep:
                    out[bucket][key] = value
                    current = (bucket, key)
                else:
                    out[bucket][body] = ""
                    current = (bucket, body)
                break
        else:
            # Not a protocol line. Either a continuation of the previous value
            # (a stack trace) or free-form noise from `am` itself.
            if line.startswith("\tat ") or line.startswith("        at "):
                out["stack_frames"] += 1
            d = RX_DENIAL.search(line)
            if d and not out["denial"]:
                out["denial"] = d.group(1).strip()
            if current is not None and line:
                bucket, key = current
                out[bucket][key] += "\n" + line

    # Also catch a denial that arrived inside a status value rather than on its
    # own line -- which is what actually happens with `am instrument -r`.
    if not out["denial"]:
        for v in list(out["status"].values()) + list(out["results"].values()):
            d = RX_DENIAL.search(v)
            if d:
                out["denial"] = d.group(1).strip()
                break

    out["verdict"] = classify(out)
    return out


def classify(o):
    if o["failed"] or o["aborted"]:
        return "REFUSED"
    if o["code"] is None:
        # No overall code ever arrived. Either AMS refused, or the stream was cut.
        return "REFUSED" if o["denial"] else "TRUNCATED"
    if o["code"] == RESULT_OK:
        return "PASS"
    if o["stack_frames"] >= 3 or "shortMsg" in o["results"]:
        return "CRASH"
    return "FAIL"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file", nargs="?", help="log file; omit to read stdin")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--key", action="append", default=[],
                    help="print only result keys starting with this prefix; repeatable")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero unless the verdict is PASS")
    args = ap.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            data = parse(fh)
    else:
        data = parse(sys.stdin)

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print("verdict            %s" % data["verdict"])
        print("INSTRUMENTATION_CODE %s%s" % (
            data["code"],
            "  (RESULT_OK)" if data["code"] == RESULT_OK else
            ("  (RESULT_CANCELED)" if data["code"] == RESULT_CANCELED else "")))
        if data["denial"]:
            print("denial             %s" % data["denial"][:300])
        if data["failed"]:
            print("failed             %s" % data["failed"])
        if data["stack_frames"]:
            print("stack frames       %d" % data["stack_frames"])
        print("result keys        %d" % len(data["results"]))
        print()
        for k in sorted(data["results"]):
            if args.key and not any(k.startswith(p) for p in args.key):
                continue
            v = data["results"][k].replace("\n", " | ")
            print("  %-34s %s" % (k, v[:170]))

    if args.strict and data["verdict"] != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
