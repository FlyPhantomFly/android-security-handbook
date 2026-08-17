#!/usr/bin/env python3
"""
scripts/xposed-detection-scan.py

PURPOSE
    Find Xposed-DETECTION code inside application APKs, and separate the real
    hits from the very large number of false ones.

    This is the inverse of 63-LSPosed's detect-xposed-module.py.  That script
    asks "is this APK an Xposed MODULE?".  This one asks "does this APK contain
    code that goes LOOKING for Xposed?" -- which is the question that actually
    comes up on an engagement, because Xposed-detection code is still shipped
    in real applications years after the framework it looks for stopped
    working.

    Chapter 64's thesis, in one script:

      * The classic Xposed framework is dead above API 27.
      * Its DETECTION SURFACE is not.  Apps still check for
        de.robv.android.xposed.XposedBridge, /system/framework/XposedBridge.jar
        and a modified app_process.
      * Almost all of those checks are dead weight against a device running
        LSPosed, which creates none of those artefacts.
      * And a naive `grep -i xposed` over an APK is worse than useless,
        because the English word "exposed" contains the substring "xposed".

WHY THE SUBSTRING TRAP MATTERS ENOUGH TO BUILD A TOOL AROUND
    Measured on the 236 APKs installed on the API 35 AVD this chapter used:

        grep -a "xposed"  matched 58 of 236 packages
        genuine Xposed references                     0

    Every single one of the 58 was the word "exposed" or "Exposed".  Verified
    by counting: Chrome had 4 "xposed" and 4 "exposed"; Settings had 113
    "xposed" against 15 "exposed" + 98 "Exposed"; GMS had 30 against 15 + 15.
    Three apps, 147 hits, zero genuine, and the arithmetic closes exactly.

    So this script NEVER matches a bare "xposed".  Every signature below is
    anchored on something that cannot occur in ordinary English or in ordinary
    Android code.

USAGE
    python3 -B xposed-detection-scan.py APK...
    python3 -B xposed-detection-scan.py CORPUS_DIR/ --recursive
    python3 -B xposed-detection-scan.py CORPUS_DIR/ --recursive --json
    python3 -B xposed-detection-scan.py app.apk --verbose
    python3 -B xposed-detection-scan.py CORPUS_DIR/ --recursive --substring-audit

    Options:
      --recursive          Walk a directory for *.apk
      --json               Machine-readable output
      --verbose            Print every match with its offset and 60 bytes of
                           context
      --substring-audit    Also count bare "xposed" / "exposed" / "Exposed"
                           over the WHOLE apk file, to reproduce the
                           false-positive measurement above.  Slow-ish.
      --quiet              Only print APKs with at least one STRONG hit
      --min-tier N         Only report APKs reaching tier N (1=STRONG,
                           2=MEDIUM, 3=WEAK).  Default 3.

    Run with -B.  This repository has had __pycache__ committed twice by
    scripts that trusted PYTHONDONTWRITEBYTECODE.

REQUIREMENTS
    Python 3.8+.  Standard library only.  No androguard, no aapt, no network,
    no device.  It reads APKs off disk, which is what you have when somebody
    hands you a corpus.

WHAT IT SEARCHES
    Every classes*.dex in the APK, decompressed if necessary, plus the raw
    AndroidManifest.xml (binary XML -- string constants in it are still
    plain UTF-8 and a <queries> entry naming an Xposed package shows up).

    It does NOT search resources.arsc or native libraries by default; a native
    Xposed check is real but rare, and --native adds a pass over lib/**/*.so.

EXECUTION STATUS
    EXECUTED.  Run to completion against 236 APKs pulled from the
    sdk_gphone16k_x86_64 AVD (Android 15 / API 35) on 2026-08-16.  Every number
    quoted in README section 8.1 and section 5.6 came out of this script.  The
    corpus was deleted afterwards; the script rebuilds it from any device with:

        adb shell 'pm list packages -f' | ...   (see scripts/pull-apk-corpus.sh)

LIMITS, STATED HONESTLY
    * A string constant is evidence that a name appears in the app, not that
      the app executes a check with it.  A hit is a LEAD.  52-StaticAnalysis
      measured 15 of 17 high-confidence leads rejected by hand on a real app;
      the same discipline applies here.
    * String encryption defeats this completely.  An app that encrypts its
      constant pool will show zero hits and may check for everything.
    * Reflection with a runtime-assembled class name defeats it too.
    * A DEX inside an APK is normally STORED (uncompressed) so that Android can
      mmap it.  This script handles both, but it reports the split, because an
      on-DEVICE `grep` over the .apk file only sees the STORED ones and that
      blind spot needs quantifying rather than assuming.

AUTHORISED TESTING ONLY.  Scan APKs you own, apps you are authorised to
assess, or a device you control.
"""

import argparse
import json
import os
import re
import sys
import zipfile

# ---------------------------------------------------------------------------
# The signature catalogue.
#
# Three tiers.  The tier is a claim about how much a hit is worth, not about
# how confident the regex is:
#
#   STRONG  -- cannot plausibly appear except in code that knows about Xposed.
#   MEDIUM  -- appears in Xposed detection but has legitimate other uses.
#   WEAK    -- correlated with Xposed detection, worthless on its own.
#
# Every pattern is a bytes literal and is anchored on something that is not an
# English word.  Nothing here matches a bare b"xposed".
# ---------------------------------------------------------------------------

SIGNATURES = [
    # ---- tier 1: STRONG -------------------------------------------------
    ("STRONG", "api.bridge.desc",
     rb"Lde/robv/android/xposed/XposedBridge;",
     "DEX type descriptor for XposedBridge. The app links against, or reflects on, the framework class."),
    ("STRONG", "api.helpers.desc",
     rb"Lde/robv/android/xposed/XposedHelpers;",
     "DEX type descriptor for XposedHelpers."),
    ("STRONG", "api.hook.desc",
     rb"Lde/robv/android/xposed/XC_MethodHook;",
     "DEX type descriptor for XC_MethodHook -- the callback base class."),
    ("STRONG", "api.iface.desc",
     rb"Lde/robv/android/xposed/IXposedHook",
     "One of the module entry-point interfaces."),
    ("STRONG", "api.pkg.dotted",
     rb"de\.robv\.android\.xposed",
     "Dotted package name as a string constant -- the form Class.forName() takes."),
    ("STRONG", "api.pkg.slashed",
     rb"de/robv/android/xposed",
     "Slashed package name -- a path or a JNI-style class name."),
    ("STRONG", "path.bridge.jar",
     rb"/system/framework/XposedBridge\.jar",
     "The classic Xposed installer's jar. LSPosed never creates this file."),
    ("STRONG", "path.libxposed",
     rb"libxposed_art\.so|libxposed_dalvik\.so",
     "The classic Xposed native hooking engine."),
    ("STRONG", "path.xposedprop",
     rb"/system/xposed\.prop",
     "Classic Xposed's version marker on the system partition."),
    ("STRONG", "pkg.installer",
     rb"de\.robv\.android\.xposed\.installer",
     "The classic Xposed Installer package name."),
    ("STRONG", "pkg.edxposed",
     rb"org\.meowcat\.edxposed\.manager|com\.elderdrivers\.riru\.edxp",
     "EdXposed manager / EdXposed Riru module package."),
    ("STRONG", "pkg.lsposed",
     rb"org\.lsposed\.manager|org\.lsposed\.daemon",
     "LSPosed manager package name."),
    ("STRONG", "pkg.taichi",
     rb"me\.weishu\.exp",
     "TaiChi -- rootless Xposed by app repackaging."),
    ("STRONG", "pkg.virtualxposed",
     rb"io\.va\.exposed|io\.virtualapp",
     "VirtualXposed / VirtualApp -- Xposed inside a container app."),
    ("STRONG", "stack.dispatcher",
     rb"handleHookedMethod",
     "XposedBridge's generic dispatcher. Named in stack-trace scanners."),
    ("STRONG", "module.marker",
     rb"assets/xposed_init|xposedmodule|xposedminversion",
     "Module packaging markers. In a NON-module app these appear only in code "
     "that scans other packages for modules."),
    ("STRONG", "fw.edxposed",
     rb"EdXposed|edxp\.|riru_?edxposed",
     "EdXposed, the Riru-era successor. Distinct enough not to collide."),

    # ---- REMOVED SIGNATURE, KEPT AS A COMMENT ON PURPOSE ------------------
    # An earlier revision of this script carried:
    #
    #     ("STRONG", "prop.xposed", rb"vxp|ro\.build\.xposed", ...)
    #
    # `vxp` produced 16 STRONG hits across the 237-APK corpus and ALL 16 WERE
    # FALSE.  Every one was an R8-generated class name -- `Lvxp;`, `Lavxp;`,
    # `Lbvxp;` -- because R8 assigns short lowercase identifiers and a
    # three-letter probe is eventually manufactured by the obfuscator itself.
    # The more aggressively minified an app is, the more likely the match.
    #
    # That is a different false-positive mechanism from the "exposed" one, and
    # worse, because it gets MORE likely as apps get better protected.  Rule:
    # never put a token shorter than about eight characters in a STRONG tier.
    # See README section 8.3.

    # ---- tier 2: MEDIUM -------------------------------------------------
    ("MEDIUM", "path.appprocess",
     rb"/system/bin/app_process",
     "The binary classic Xposed replaced. Also referenced legitimately by "
     "shell tooling, profilers and anything that spawns a Java process."),
    ("MEDIUM", "path.appprocess.bare",
     rb"app_process(?:32|64)?\x00",
     "app_process as a NUL-terminated DEX string. Same caveat as above."),
    ("MEDIUM", "stack.getstacktrace",
     rb"getStackTrace",
     "Stack-trace inspection. The mechanism of the strongest in-process "
     "Xposed check -- and of every crash reporter ever written."),
    ("MEDIUM", "pkg.magisk",
     rb"com\.topjohnwu\.magisk",
     "Detects the root substrate, not the hooking framework."),
    ("MEDIUM", "path.dataadb",
     rb"/data/adb/",
     "Magisk / LSPosed module store. Unreadable to an app -- see 63-LSPosed."),

    # ---- tier 3: WEAK ---------------------------------------------------
    ("WEAK", "generic.zygoteinit",
     rb"com\.android\.internal\.os\.ZygoteInit",
     "Named in stack-trace-based hook detection, and in ordinary framework code."),
    ("WEAK", "generic.classloader.enum",
     rb"getClassLoader\x00|dalvik\.system\.PathClassLoader",
     "Class-loader inspection: the shape of a foreign-loader check, and of "
     "every plugin framework."),
]

COMPILED = [(tier, name, re.compile(pat), why) for tier, name, pat, why in SIGNATURES]

TIER_RANK = {"STRONG": 1, "MEDIUM": 2, "WEAK": 3}

# The substring trap, as a measurable thing rather than an anecdote.
RX_XPOSED_LOWER = re.compile(rb"xposed")
RX_EXPOSED_ANY = re.compile(rb"[eE]xposed")


def dex_blobs(apk_path):
    """Yield (member_name, compress_type, bytes) for every classes*.dex and
    for AndroidManifest.xml.  Handles STORED and DEFLATED alike."""
    out = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            for info in z.infolist():
                n = info.filename
                if re.fullmatch(r"classes\d*\.dex", n) or n == "AndroidManifest.xml":
                    try:
                        out.append((n, info.compress_type, z.read(n)))
                    except Exception as e:              # noqa: BLE001
                        out.append((n, info.compress_type, b""))
                        sys.stderr.write("[!] %s: cannot read %s (%s)\n"
                                         % (os.path.basename(apk_path), n, e))
    except zipfile.BadZipFile:
        sys.stderr.write("[!] %s: not a zip\n" % os.path.basename(apk_path))
    except Exception as e:                              # noqa: BLE001
        sys.stderr.write("[!] %s: %s\n" % (os.path.basename(apk_path), e))
    return out


def native_blobs(apk_path):
    out = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            for info in z.infolist():
                if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                    try:
                        out.append((info.filename, info.compress_type, z.read(info.filename)))
                    except Exception:                   # noqa: BLE001
                        pass
    except Exception:                                   # noqa: BLE001
        pass
    return out


def scan_apk(apk_path, want_native=False, want_audit=False, verbose=False):
    result = {
        "apk": os.path.basename(apk_path),
        "path": apk_path,
        "size": os.path.getsize(apk_path) if os.path.exists(apk_path) else 0,
        "dex_count": 0,
        "dex_stored": 0,
        "dex_deflated": 0,
        "hits": {},          # name -> {tier, count, why, samples}
        "tier": None,
        "readable": False,
    }

    blobs = dex_blobs(apk_path)
    if want_native:
        blobs += native_blobs(apk_path)
    if not blobs:
        return result
    result["readable"] = True

    audit_x = audit_e = 0

    for member, ctype, data in blobs:
        if member.startswith("classes"):
            result["dex_count"] += 1
            if ctype == zipfile.ZIP_STORED:
                result["dex_stored"] += 1
            else:
                result["dex_deflated"] += 1

        for tier, name, rx, why in COMPILED:
            found = rx.findall(data)
            if not found:
                continue
            slot = result["hits"].setdefault(
                name, {"tier": tier, "count": 0, "why": why, "members": set(), "samples": []})
            slot["count"] += len(found)
            slot["members"].add(member)
            if verbose and len(slot["samples"]) < 3:
                m = rx.search(data)
                if m:
                    lo = max(0, m.start() - 24)
                    hi = min(len(data), m.end() + 36)
                    ctx = data[lo:hi]
                    printable = bytes(c if 32 <= c < 127 else 0x2E for c in ctx)
                    slot["samples"].append(
                        {"member": member, "offset": m.start(),
                         "context": printable.decode("ascii", "replace")})

    if want_audit:
        try:
            with open(apk_path, "rb") as fh:
                whole = fh.read()
            audit_x = len(RX_XPOSED_LOWER.findall(whole))
            audit_e = len(RX_EXPOSED_ANY.findall(whole))
        except Exception:                               # noqa: BLE001
            pass
        result["audit"] = {"xposed_substring": audit_x,
                           "exposed_word": audit_e,
                           "unexplained": audit_x - audit_e}

    for slot in result["hits"].values():
        slot["members"] = sorted(slot["members"])

    if result["hits"]:
        result["tier"] = min(TIER_RANK[s["tier"]] for s in result["hits"].values())
    return result


def collect(paths, recursive):
    apks = []
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for f in sorted(files):
                        if f.lower().endswith(".apk"):
                            apks.append(os.path.join(root, f))
            else:
                for f in sorted(os.listdir(p)):
                    if f.lower().endswith(".apk"):
                        apks.append(os.path.join(p, f))
        else:
            apks.append(p)
    return apks


def report_text(results, args):
    total = len(results)
    readable = [r for r in results if r["readable"]]
    strong = [r for r in readable if r["tier"] == 1]
    medium = [r for r in readable if r["tier"] == 2]
    weak = [r for r in readable if r["tier"] == 3]
    clean = [r for r in readable if r["tier"] is None]

    for r in sorted(readable, key=lambda x: (x["tier"] or 9, x["apk"])):
        if r["tier"] is None:
            continue
        if r["tier"] > args.min_tier:
            continue
        if args.quiet and r["tier"] != 1:
            continue
        label = {1: "STRONG", 2: "MEDIUM", 3: "WEAK"}[r["tier"]]
        print("\n=== %-9s %s  (%.1f MiB, %d dex)" %
              (label, r["apk"], r["size"] / 1048576.0, r["dex_count"]))
        for name, slot in sorted(r["hits"].items(),
                                 key=lambda kv: (TIER_RANK[kv[1]["tier"]], kv[0])):
            print("    [%-6s] %-24s x%-6d %s"
                  % (slot["tier"], name, slot["count"], ",".join(slot["members"])[:60]))
            if args.verbose:
                print("             %s" % slot["why"])
                for s in slot["samples"]:
                    print("             @%-8d %s" % (s["offset"], s["context"]))
        if "audit" in r:
            a = r["audit"]
            print("    [audit ] bare 'xposed'=%d  'exposed|Exposed'=%d  unexplained=%d"
                  % (a["xposed_substring"], a["exposed_word"], a["unexplained"]))

    print("\n" + "=" * 72)
    print("CORPUS SUMMARY")
    print("=" * 72)
    print("  APKs given                 : %d" % total)
    print("  APKs readable as zip       : %d" % len(readable))
    print("  classes*.dex STORED        : %d" % sum(r["dex_stored"] for r in readable))
    print("  classes*.dex DEFLATED      : %d" % sum(r["dex_deflated"] for r in readable))
    print("  -- the DEFLATED ones are the blind spot of an on-device `grep` over the .apk")
    print("  reaching STRONG            : %d" % len(strong))
    print("  reaching MEDIUM (no STRONG): %d" % len(medium))
    print("  reaching WEAK only         : %d" % len(weak))
    print("  no signature at all        : %d" % len(clean))

    if any("audit" in r for r in readable):
        ax = sum(r["audit"]["xposed_substring"] for r in readable if "audit" in r)
        ae = sum(r["audit"]["exposed_word"] for r in readable if "audit" in r)
        nx = sum(1 for r in readable if r.get("audit", {}).get("xposed_substring", 0) > 0)
        print("\n  SUBSTRING AUDIT -- why `grep -i xposed` is not a check")
        print("    APKs containing the substring 'xposed' : %d" % nx)
        print("    total 'xposed' occurrences             : %d" % ax)
        print("    accounted for by 'exposed'/'Exposed'   : %d" % ae)
        print("    unexplained                            : %d" % (ax - ae))

    print("\n  Per-signature totals (APKs, not occurrences):")
    per = {}
    for r in readable:
        for name, slot in r["hits"].items():
            per.setdefault(name, [slot["tier"], 0])[1] += 1
    for name, (tier, n) in sorted(per.items(), key=lambda kv: (TIER_RANK[kv[1][0]], -kv[1][1])):
        print("    [%-6s] %-24s %4d / %d" % (tier, name, n, len(readable)))

    print("""
  READ THIS BEFORE QUOTING THE NUMBERS ABOVE
    A hit is a lead, not a finding.  A STRONG hit means the app's constant
    pool names an Xposed artefact; it does not mean the app executes a check,
    and it certainly does not mean the check works.  Every classic-Xposed
    path signature is dead weight on a device running LSPosed, which creates
    none of those files.  Adjudicate by hand -- 52-StaticAnalysis rejected 15
    of 17 high-confidence leads on one real application.""")


def main():
    ap = argparse.ArgumentParser(
        description="Find Xposed-detection code in APKs, without the 'exposed' false positives.")
    ap.add_argument("paths", nargs="+", help="APK files or directories")
    ap.add_argument("--recursive", action="store_true", help="walk directories for *.apk")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--verbose", action="store_true", help="print match context")
    ap.add_argument("--quiet", action="store_true", help="only APKs with a STRONG hit")
    ap.add_argument("--native", action="store_true", help="also scan lib/**/*.so")
    ap.add_argument("--substring-audit", action="store_true",
                    help="count bare 'xposed' vs 'exposed' over the whole file")
    ap.add_argument("--min-tier", type=int, default=3, choices=(1, 2, 3),
                    help="report APKs reaching this tier or better (default 3)")
    args = ap.parse_args()

    apks = collect(args.paths, args.recursive)
    if not apks:
        sys.stderr.write("no APKs found\n")
        return 2

    results = [scan_apk(a, args.native, args.substring_audit, args.verbose) for a in apks]

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        report_text(results, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
