#!/usr/bin/env python3
# scripts/instrumentation-surface.py
#
# PURPOSE
#   Answer, for a corpus of APKs, the two static questions this chapter cares
#   about:
#
#     1. Does this APK DECLARE an <instrumentation> component? If so it is a test
#        APK -- or a shipping APK that accidentally kept one, which is a finding.
#     2. Does this APK CONTAIN test-harness code (androidx.test, JUnit, Espresso,
#        UiAutomator, or a subclass of android.app.Instrumentation) that a release
#        build should have dropped?
#
#   Both are cheap, both are commonly true in the wild, and both hand a reviewer
#   a large amount of information about internal endpoints, staging credentials
#   and control flow that the shipping code was supposed to hide.
#
# USAGE
#   # host -- scan APKs on disk
#   python3 -B instrumentation-surface.py app1.apk app2.apk
#
#   # host -- scan a directory tree
#   python3 -B instrumentation-surface.py --dir /path/to/apks
#
#   # host -- pull every installed package off the attached device first
#   python3 -B instrumentation-surface.py --pull-device /tmp/corpus
#
#   # host -- machine-readable
#   python3 -B instrumentation-surface.py --json --dir /tmp/corpus
#
#   Run it as `python3 -B`. PYTHONDONTWRITEBYTECODE is not always enough; this
#   repository has had __pycache__ committed twice because of that.
#
# WAS THIS SCRIPT EXECUTED?
#   YES. Run on 2026-08-16 against a 40-APK sample pulled from the AVD
#   sdk_gphone16k_x86_64 (Android 15 / API 35). Results and their denominator are
#   quoted in README.md section 8.4. The numbers are a SAMPLE, not the device;
#   the script prints its own denominator for that reason.
#
# WHY IT READS THE ZIP RATHER THAN GREPPING THE FILE
#   Chapter 64 measured 234 classes.dex entries STORED and 16 DEFLATED across a
#   237-APK corpus on this same emulator image -- and all 16 DEFLATED entries were
#   in /data/app, ten of them Chrome's. A `grep` over raw APK bytes silently skips
#   exactly the third-party apps worth scanning. Reading through zipfile costs a
#   few milliseconds and removes the blind spot entirely.
#
# WHAT IT IS NOT
#   It is not a decision procedure. A hit is a LEAD. `androidx.test` strings can
#   arrive through a dependency's test fixtures without a single test class being
#   reachable; a class named ...Instrumentation may extend nothing. Adjudicate the
#   top band by hand before you write a finding -- this repository has measured a
#   detector agreeing with itself into a 100% false-positive rate more than once.
#
# AUTHORISED TESTING ONLY.

import argparse
import json
import os
import re
import subprocess
import sys
import zipfile

# --------------------------------------------------------------------------- #
# Signatures.
#
# Every token here is at least eight characters and contains a path separator or
# a package-qualified prefix. That is a deliberate rule adopted in this
# repository after chapter 64 measured a three-character token ("vxp") producing
# 16 STRONG hits, ALL of them R8-generated class names -- and getting worse on
# better-obfuscated apps, because minified identifiers are short and numerous.
# --------------------------------------------------------------------------- #
DEX_MARKERS = {
    "androidx.test":       b"Landroidx/test/",
    "android.support.test": b"Landroid/support/test/",
    "espresso":            b"Landroidx/test/espresso/",
    "uiautomator":         b"Landroidx/test/uiautomator/",
    "junit4":              b"Lorg/junit/runner/",
    "junit3":              b"Ljunit/framework/",
    "Instrumentation-ref": b"Landroid/app/Instrumentation;",
    "InstrumentationRegistry": b"Landroidx/test/platform/app/InstrumentationRegistry;",
    "AndroidJUnitRunner":  b"Landroidx/test/runner/AndroidJUnitRunner;",
    "mockito":             b"Lorg/mockito/",
    "robolectric":         b"Lorg/robolectric/",
}

# Binary AndroidManifest.xml keeps tag and attribute names in a UTF-16 string
# pool, so a plain ASCII search misses them. Search for both encodings.
def _both_encodings(s):
    return (s.encode("utf-8"), s.encode("utf-16-le"))


MANIFEST_MARKERS = {
    "instrumentation-tag": _both_encodings("instrumentation"),
    "targetPackage":       _both_encodings("targetPackage"),
    "testOnly":            _both_encodings("testOnly"),
    "android.test.runner": _both_encodings("android.test.runner"),
    "debuggable":          _both_encodings("debuggable"),
}


def scan_apk(path):
    """Return a findings dict for one APK. Never raises on a malformed file."""
    out = {
        "apk": path,
        "size": None,
        "ok": False,
        "error": None,
        "manifest": [],
        "dex": {},
        "dex_entries": 0,
        "dex_stored": 0,
        "dex_deflated": 0,
    }
    try:
        out["size"] = os.path.getsize(path)
    except OSError:
        pass

    try:
        with zipfile.ZipFile(path) as z:
            try:
                manifest = z.read("AndroidManifest.xml")
            except KeyError:
                manifest = b""
            for name, encodings in MANIFEST_MARKERS.items():
                if any(e in manifest for e in encodings):
                    out["manifest"].append(name)

            for info in z.infolist():
                if not re.fullmatch(r"classes\d*\.dex", info.filename):
                    continue
                out["dex_entries"] += 1
                if info.compress_type == zipfile.ZIP_STORED:
                    out["dex_stored"] += 1
                else:
                    out["dex_deflated"] += 1
                blob = z.read(info.filename)
                for name, token in DEX_MARKERS.items():
                    n = blob.count(token)
                    if n:
                        out["dex"][name] = out["dex"].get(name, 0) + n
        out["ok"] = True
    except Exception as exc:                       # noqa: BLE001 - report, never crash
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def verdict(f):
    """
    Three bands, and the middle one is the interesting one.

      DECLARED  the manifest carries an <instrumentation> component. This APK is
                a test APK, or a shipping APK that kept one.
      RESIDUE   no <instrumentation> component, but test-harness code is present.
                A release build that still ships androidTest sources.
      CLEAN     neither.

    Note that "Instrumentation-ref" alone is NOT enough for RESIDUE: the string
    Landroid/app/Instrumentation; appears in any APK that touches
    ActivityManager or the support library's activity test rules transitively,
    and on its own it is noise.
    """
    if "instrumentation-tag" in f["manifest"] and "targetPackage" in f["manifest"]:
        return "DECLARED"
    strong = [k for k in f["dex"]
              if k not in ("Instrumentation-ref",)]
    if strong:
        return "RESIDUE"
    return "CLEAN"


def pull_device(dest):
    """Pull every installed APK the shell can read into dest/. Returns paths."""
    os.makedirs(dest, exist_ok=True)
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    listing = subprocess.run(["adb", "shell", "pm", "list", "packages", "-f"],
                             capture_output=True, text=True, env=env).stdout
    pulled = []
    for line in listing.splitlines():
        line = line.strip().replace("\r", "")
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):]
        remote, _, pkg = body.rpartition("=")
        if not remote:
            continue
        local = os.path.join(dest, pkg + ".apk")
        if os.path.exists(local):
            pulled.append(local)
            continue
        r = subprocess.run(["adb", "pull", remote, local],
                           capture_output=True, text=True, env=env)
        if r.returncode == 0 and os.path.exists(local):
            pulled.append(local)
    return pulled


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("apks", nargs="*", help="APK files to scan")
    ap.add_argument("--dir", help="scan every .apk under this directory")
    ap.add_argument("--pull-device", metavar="DEST",
                    help="pull all installed APKs from the attached device into DEST first")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--only", choices=["DECLARED", "RESIDUE", "CLEAN"],
                    help="print only this band")
    args = ap.parse_args()

    targets = list(args.apks)
    if args.pull_device:
        targets += pull_device(args.pull_device)
    if args.dir:
        for root, _dirs, files in os.walk(args.dir):
            for fn in files:
                if fn.lower().endswith(".apk"):
                    targets.append(os.path.join(root, fn))
    targets = sorted(set(targets))

    if not targets:
        ap.error("no APKs given. Use positional paths, --dir, or --pull-device.")

    results = []
    for t in targets:
        f = scan_apk(t)
        f["verdict"] = verdict(f)
        results.append(f)

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0

    bands = {"DECLARED": 0, "RESIDUE": 0, "CLEAN": 0}
    unreadable = 0
    stored = deflated = 0
    for f in results:
        bands[f["verdict"]] += 1
        stored += f["dex_stored"]
        deflated += f["dex_deflated"]
        if not f["ok"]:
            unreadable += 1
        if args.only and f["verdict"] != args.only:
            continue
        if f["verdict"] == "CLEAN" and not args.only:
            continue
        print("%-9s %s" % (f["verdict"], os.path.basename(f["apk"])))
        if f["manifest"]:
            print("          manifest: %s" % ", ".join(sorted(f["manifest"])))
        if f["dex"]:
            print("          dex     : %s" % ", ".join(
                "%s=%d" % (k, v) for k, v in sorted(f["dex"].items())))
        if f["error"]:
            print("          error   : %s" % f["error"])

    print()
    print("scanned              %d APK(s)" % len(results))
    print("  DECLARED           %d   (manifest has <instrumentation targetPackage=...>)"
          % bands["DECLARED"])
    print("  RESIDUE            %d   (test-harness code, no <instrumentation> tag)"
          % bands["RESIDUE"])
    print("  CLEAN              %d" % bands["CLEAN"])
    print("  unreadable         %d" % unreadable)
    print("classes.dex entries  %d STORED / %d DEFLATED"
          % (stored, deflated))
    print()
    print("Every line above is a LEAD, not a finding. Open the top band by hand.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
