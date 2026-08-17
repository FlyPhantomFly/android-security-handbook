#!/usr/bin/env python3
# scripts/boundary-map.py
#
# PURPOSE
#   Build the STATIC half of the managed/native boundary map for an APK: every
#   method declared `native` in the DEX, every Java_* symbol exported by the
#   bundled shared libraries, and the matching between them.
#
#   The interesting output is the MISMATCH. Measured over 18 real APKs while
#   writing chapter 68, only 1,049 of 8,140 distinct declared native methods
#   (12.9%) could be resolved to an exported symbol. If your method for crossing
#   the boundary is "grep the .so for the mangled name", it fails on roughly six
#   of every seven methods -- and it fails silently, because a missing match and
#   a match that was never possible look identical.
#
#   This tool therefore refuses to say WHY a method is unresolvable. There are
#   four causes and it cannot distinguish them (see --explain). Distinguishing
#   them needs the runtime half: scripts/boundary-confirm.js.
#
# USAGE
#   # host -- one-line triage summary
#   python3 -B boundary-map.py base.apk --summary
#
#   # host -- the unresolvable methods: your RegisterNatives target list
#   python3 -B boundary-map.py base.apk --unresolved
#
#   # host -- everything, human readable
#   python3 -B boundary-map.py base.apk --report
#
#   # host -- machine readable, for a CI baseline
#   python3 -B boundary-map.py base.apk --json > native-surface.json
#
#   # host -- a whole corpus (this is how the 18-APK figure was produced)
#   python3 -B boundary-map.py /path/to/apks/ --corpus
#
#   # host -- pick a different ABI (default: arm64-v8a)
#   python3 -B boundary-map.py base.apk --abi armeabi-v7a --summary
#
#   # host -- why an unresolved method is not evidence of RegisterNatives
#   python3 -B boundary-map.py --explain
#
# REQUIREMENTS
#   * `dexdump` from the Android SDK build-tools, and `llvm-nm` from the NDK.
#     Found automatically via ANDROID_HOME / ANDROID_SDK_ROOT / ANDROID_NDK, or
#     set DEXDUMP and LLVM_NM explicitly.
#   * Python 3.8+. No third-party packages.
#
# A WINDOWS TRAP THIS SCRIPT WORKS AROUND
#   dexdump.exe CANNOT read a DEX from inside an APK on Windows. It fails with
#     Failed anonymous mmap(...): Invalid argument
#   and then prints "Processing 'base.apk'..." as though nothing were wrong. The
#   first version of this measurement reported 0 native methods for all 18 APKs
#   -- a clean, uniform, plausible and completely wrong result. Every classes*.dex
#   is therefore extracted to a real file first. See chapter 68 section 8.4.
#
# ETHICS
#   Run this against APKs you own or are authorised to analyse. See section 1.6.

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ACC_NATIVE = 0x0100

EXPLAIN = """
An UNRESOLVED method -- one declared `native` in the DEX with no matching
exported symbol in the bundled libraries -- has four possible causes. This tool
cannot tell them apart, and reporting any one of them as the cause would be the
"scope error" failure mode from chapter 68 section 3.10.

  1. EXPLICIT BINDING. Native code called RegisterNatives, handing ART a
     function pointer directly. The function can be `static` and stripped, so
     there is no symbol and there never was one. This is the common case.
     -> Confirm with scripts/boundary-confirm.js, or by finding JNI_OnLoad.

  2. THE LIBRARY IS SOMEWHERE ELSE. Split APKs, Play Feature Delivery modules,
     or a library downloaded at first run. Measured in the chapter's corpus:
     three APKs declared 480, 618 and 329 native methods and shipped no arm64
     library at all in base.apk.
     -> Check `adb shell pm path <pkg>`; pull every APK it lists.

  3. A DIFFERENT ABI. The library ships for armeabi-v7a or x86_64 but not the
     ABI you asked for.
     -> Re-run with --abi, or --all-abis.

  4. THE CLASS IS NEVER LOADED. Dead code, a compile-time-only stub, or a
     platform class the app never touches.
     -> Only a runtime observation settles this.

Report the number as what it is: the fraction of the declared boundary that is
visible to symbol lookup in the file you analysed. Do not report it as a count
of RegisterNatives bindings.
"""


# --------------------------------------------------------------------------
# tool discovery
# --------------------------------------------------------------------------
def _newest_subdir(path):
    if not os.path.isdir(path):
        return None
    subs = sorted(os.listdir(path))
    return os.path.join(path, subs[-1]) if subs else None


def find_tool(env_var, exe_names, *search_roots):
    """Explicit env var wins; then PATH; then the SDK/NDK layout."""
    if os.environ.get(env_var):
        return os.environ[env_var]
    for name in exe_names:
        found = shutil.which(name)
        if found:
            return found
    for root in search_roots:
        if not root:
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in exe_names:
                if name in filenames:
                    return os.path.join(dirpath, name)
            # do not descend forever
            if dirpath.count(os.sep) - root.count(os.sep) > 3:
                _dirnames[:] = []
    return None


def locate_tools():
    sdk = (os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
           or os.path.join(os.path.expanduser("~"), "AppData", "Local", "Android", "Sdk"))
    ndk = os.environ.get("ANDROID_NDK") or os.environ.get("ANDROID_NDK_HOME")
    if not ndk:
        ndk = _newest_subdir(os.path.join(sdk, "ndk"))

    dexdump = find_tool("DEXDUMP", ["dexdump", "dexdump.exe"],
                        os.path.join(sdk, "build-tools"))
    nm = find_tool("LLVM_NM", ["llvm-nm", "llvm-nm.exe"],
                   os.path.join(ndk, "toolchains") if ndk else None)
    return dexdump, nm


# --------------------------------------------------------------------------
# JNI short-form mangling  (JNI spec; see 16-JNI for the full rules)
# --------------------------------------------------------------------------
def jni_mangle(class_internal, method):
    """Java_<escaped class>_<escaped method>, class in a/b/C form."""
    def esc(s):
        out = []
        for ch in s:
            if ch == "_":
                out.append("_1")
            elif ch == ";":
                out.append("_2")
            elif ch == "[":
                out.append("_3")
            elif ch == "/":
                out.append("_")
            elif ch.isascii() and ch.isalnum():
                out.append(ch)
            else:
                # NOTE: _0 plus FOUR hex digits. '$' -> _00024, not _0024.
                # 16-JNI records this as a correction; getting it wrong makes
                # every inner-class method look unresolvable.
                out.append("_0%04x" % ord(ch))
        return "".join(out)
    return "Java_" + esc(class_internal) + "_" + esc(method)


# --------------------------------------------------------------------------
# DEX side
# --------------------------------------------------------------------------
def parse_dexdump(text):
    """Yield (class_internal, method_name) for every ACC_NATIVE method."""
    out, cur_class, cur_name = [], None, None
    for line in text.splitlines():
        m = re.match(r"\s*Class descriptor\s*:\s*'L([^;]+);'", line)
        if m:
            cur_class = m.group(1)
            continue
        m = re.match(r"\s*name\s*:\s*'([^']*)'", line)
        if m:
            cur_name = m.group(1)
            continue
        m = re.match(r"\s*access\s*:\s*0x([0-9a-fA-F]+)", line)
        if m and cur_class and cur_name:
            if int(m.group(1), 16) & ACC_NATIVE:
                out.append((cur_class, cur_name))
    return out


def dex_native_methods(apk, dexdump, workdir):
    """Extract every classes*.dex to a real file, then dexdump each."""
    methods, ndex = [], 0
    with zipfile.ZipFile(apk) as z:
        for name in z.namelist():
            if not re.fullmatch(r"classes\d*\.dex", name):
                continue
            ndex += 1
            dst = os.path.join(workdir, name)
            with open(dst, "wb") as f:
                f.write(z.read(name))
            try:
                r = subprocess.run([dexdump, dst], capture_output=True, timeout=1800)
                methods += parse_dexdump(r.stdout.decode("utf-8", "replace"))
            except (OSError, subprocess.SubprocessError) as exc:
                print("WARN: dexdump failed on %s: %s" % (name, exc), file=sys.stderr)
            finally:
                try:
                    os.remove(dst)
                except OSError:
                    pass
    return methods, ndex


# --------------------------------------------------------------------------
# native side
# --------------------------------------------------------------------------
def so_exports(apk, nm, abi, workdir, all_abis=False):
    """Return {symbol: libname} for exported Java_* symbols, and lib inventory."""
    syms, libs = {}, []
    with zipfile.ZipFile(apk) as z:
        for name in z.namelist():
            if not name.endswith(".so"):
                continue
            if not all_abis and ("/%s/" % abi) not in name:
                continue
            base = os.path.basename(name)
            data = z.read(name)
            if not data:                      # placeholder .so files exist
                continue
            libs.append((name, len(data)))
            dst = os.path.join(workdir, base)
            with open(dst, "wb") as f:
                f.write(data)
            try:
                r = subprocess.run([nm, "-D", "--defined-only", dst],
                                   capture_output=True, timeout=600)
                for line in r.stdout.decode("utf-8", "replace").splitlines():
                    parts = line.split()
                    if parts and parts[-1].startswith("Java_"):
                        syms.setdefault(parts[-1], base)
            except (OSError, subprocess.SubprocessError) as exc:
                print("WARN: llvm-nm failed on %s: %s" % (base, exc), file=sys.stderr)
            finally:
                try:
                    os.remove(dst)
                except OSError:
                    pass
    return syms, libs


# --------------------------------------------------------------------------
# the map
# --------------------------------------------------------------------------
def build_map(apk, dexdump, nm, abi, all_abis=False):
    with tempfile.TemporaryDirectory(prefix="boundary-map-") as work:
        methods, ndex = dex_native_methods(apk, dexdump, work)
        syms, libs = so_exports(apk, nm, abi, work, all_abis)

    distinct = sorted(set(methods))
    resolved, unresolved = [], []
    used = set()
    for cls, meth in distinct:
        mangled = jni_mangle(cls, meth)
        if mangled in syms:
            resolved.append((cls, meth, mangled, syms[mangled]))
            used.add(mangled)
        else:
            unresolved.append((cls, meth, mangled))

    orphan_exports = sorted(s for s in syms if s not in used)

    return {
        "apk": os.path.basename(apk),
        "size_bytes": os.path.getsize(apk),
        "abi": "all" if all_abis else abi,
        "dex_count": ndex,
        "declared_total": len(methods),
        "declared_distinct": len(distinct),
        "libs": [{"path": p, "size": s} for p, s in libs],
        "exports_java": len(syms),
        "resolved": [{"class": c, "method": m, "symbol": s, "lib": l}
                     for c, m, s, l in resolved],
        "unresolved": [{"class": c, "method": m, "expected_symbol": s}
                       for c, m, s in unresolved],
        "orphan_exports": orphan_exports,
    }


def pct(a, b):
    return (100.0 * a / b) if b else 0.0


def print_summary(r):
    d = r["declared_distinct"]
    n = len(r["resolved"])
    print("%-42s %7.1f MB  dex=%-3d native=%-5d libs=%-3d exports=%-5d "
          "resolved=%-5d (%5.1f%%)"
          % (r["apk"], r["size_bytes"] / 1048576.0, r["dex_count"], d,
             len(r["libs"]), r["exports_java"], n, pct(n, d)))


def print_report(r):
    print("=" * 78)
    print("BOUNDARY MAP  %s" % r["apk"])
    print("=" * 78)
    print("  size                 : %.1f MB" % (r["size_bytes"] / 1048576.0))
    print("  ABI                  : %s" % r["abi"])
    print("  classes*.dex         : %d" % r["dex_count"])
    print("  native declarations  : %d (%d distinct class.method pairs)"
          % (r["declared_total"], r["declared_distinct"]))
    print("  bundled libraries    : %d" % len(r["libs"]))
    for lib in r["libs"]:
        print("      %-52s %8d B" % (lib["path"], lib["size"]))
    print("  Java_* exports       : %d" % r["exports_java"])
    print()
    d = r["declared_distinct"]
    print("  RESOLVED by symbol   : %d  (%.1f%% of the declared boundary)"
          % (len(r["resolved"]), pct(len(r["resolved"]), d)))
    print("  UNRESOLVED           : %d  (%.1f%%)"
          % (len(r["unresolved"]), pct(len(r["unresolved"]), d)))
    print("  exports with no DEX declaration : %d" % len(r["orphan_exports"]))
    print()
    if r["orphan_exports"]:
        print("  An export with no declaration usually means the declaring class")
        print("  lives in a split APK you have not pulled. Check `pm path`.")
        print()
    print("  The unresolved count is NOT a count of RegisterNatives bindings.")
    print("  Run with --explain for the four causes it cannot distinguish, or")
    print("  confirm at runtime with scripts/boundary-confirm.js.")


def print_unresolved(r):
    for u in r["unresolved"]:
        print("%s.%s\t%s" % (u["class"].replace("/", "."), u["method"],
                             u["expected_symbol"]))


def corpus(path, dexdump, nm, abi, all_abis):
    rows = []
    for fn in sorted(os.listdir(path)):
        if not fn.endswith(".apk"):
            continue
        try:
            r = build_map(os.path.join(path, fn), dexdump, nm, abi, all_abis)
        except (zipfile.BadZipFile, OSError) as exc:
            print("SKIP %s: %s" % (fn, exc), file=sys.stderr)
            continue
        rows.append(r)
        print_summary(r)

    td = sum(r["declared_distinct"] for r in rows)
    tr = sum(len(r["resolved"]) for r in rows)
    te = sum(r["exports_java"] for r in rows)
    print()
    print("=== TOTALS over %d APKs ===" % len(rows))
    print("distinct native methods declared        : %d" % td)
    print("of those, resolvable by exported symbol : %d (%.1f%%)" % (tr, pct(tr, td)))
    print("Java_* symbols exported                 : %d" % te)
    print("APKs with native methods, zero matches  : %d"
          % sum(1 for r in rows if r["declared_distinct"] and not r["resolved"]))
    print("APKs with native methods, no matching so: %d"
          % sum(1 for r in rows if r["declared_distinct"] and not r["libs"]))
    print()
    print("Quote this with its denominator, or not at all: it is the fraction of")
    print("methods declared native IN THE FILE ANALYSED that match a symbol")
    print("exported by a library IN THE SAME FILE. See --explain.")
    return rows


def main():
    ap = argparse.ArgumentParser(
        description="Static managed/native boundary map for an APK.")
    ap.add_argument("target", nargs="?", help="an .apk, or a directory with --corpus")
    ap.add_argument("--abi", default="arm64-v8a")
    ap.add_argument("--all-abis", action="store_true")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--unresolved", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--corpus", action="store_true")
    ap.add_argument("--explain", action="store_true")
    args = ap.parse_args()

    if args.explain:
        print(EXPLAIN)
        return 0

    if not args.target:
        ap.error("a target APK (or directory with --corpus) is required")

    dexdump, nm = locate_tools()
    missing = [n for n, v in (("dexdump", dexdump), ("llvm-nm", nm)) if not v]
    if missing:
        print("ERROR: could not find %s.\n"
              "Set ANDROID_HOME / ANDROID_NDK, or DEXDUMP / LLVM_NM explicitly."
              % " and ".join(missing), file=sys.stderr)
        return 1

    if args.corpus:
        rows = corpus(args.target, dexdump, nm, args.abi, args.all_abis)
        if args.json:
            print(json.dumps(rows, indent=1))
        return 0

    r = build_map(args.target, dexdump, nm, args.abi, args.all_abis)

    if args.json:
        print(json.dumps(r, indent=1))
    elif args.unresolved:
        print_unresolved(r)
    elif args.summary:
        print_summary(r)
    else:
        print_report(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
