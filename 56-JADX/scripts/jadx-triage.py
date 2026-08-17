#!/usr/bin/env python3
"""
jadx-triage.py -- batch decompile, failure census, and class ranking over jadx CLI output.

PURPOSE
    Answer, for an APK you have never seen, the two questions you must answer before you read
    a single line of it:

      1. HOW MUCH OF THIS CAN I ACTUALLY READ?  jadx does not tell you. Its console summary
         reports only the methods that threw during processing. On a measured 17.5 MB app it
         said "finished with errors, count: 61" while the output tree contained 2,104 methods
         replaced by `throw new UnsupportedOperationException("Method not decompiled: ...")`.
         That is an under-count by a factor of thirty. This script censuses the tree.

      2. WHICH TWENTY OF THESE TWENTY THOUSAND CLASSES SHOULD I OPEN FIRST?  Ranking by size
         is useless. This script scores every class on signals that survive obfuscation --
         endpoint-shaped strings, crypto API calls, framework security contracts, native
         declarations, storage and logging calls -- and penalises third-party packages.

    It will run jadx for you, or work on a tree you already decompiled.

USAGE
    # decompile and triage in one step
    python3 -B jadx-triage.py --apk app.apk --out ./work

    # triage a tree you already have
    python3 -B jadx-triage.py --sources ./work/sources

    # focus the ranking on the app's own package (strongly recommended)
    python3 -B jadx-triage.py --sources ./work/sources --app-package com.example.app

    # machine-readable, for a pipeline
    python3 -B jadx-triage.py --sources ./work/sources --json report.json

    # search the tree with the built-in catalogue instead of ranking
    python3 -B jadx-triage.py --sources ./work/sources --grep secrets,network,crypto

    Use `python3 -B` (or set PYTHONDONTWRITEBYTECODE=1) so no __pycache__ is created.

REQUIREMENTS
    - Python 3.8+. Standard library only; no pip installs.
    - For --apk: jadx 1.5.x. Discovery order:
        $JADX      -- path to a jadx launcher
        $JADX_JAR  -- path to a jadx jar, invoked as `java -cp <jar> jadx.cli.JadxCLI`
        `jadx` on PATH
      On a Windows jadx-gui-only install, jadx.exe answers --version but opens the GUI for a
      real invocation. Set JADX_JAR to lib/jadx-gui-<ver>-all.jar instead.
    - No device, no root, no network.

WHAT THIS WILL NOT TELL YOU
    - It will NOT tell you where the vulnerabilities are. A high score means "a human should
      look at this next", nothing more. The ranking has no idea what the code means.
    - It will NOT see code that is not in the tree: dynamically loaded DEX, native code in
      .so files, anything in a split APK you did not pass to jadx, and anything R8 removed as
      unreachable. A class scoring zero may be the most important class in the app.
    - It will NOT tell you whether the Java it counted is CORRECT. jadx can be silently wrong
      (chapter section 6.6), and a file with no JADX WARN comments is a file where jadx had no
      doubts -- not a file that decompiled correctly.
    - It will NOT distinguish a refusal that matters from one that does not. Kotlin's synthetic
      default-argument constructors and generated JSON adapters refuse routinely and benignly.
      Read the DISTRIBUTION of refusals, which the report prints, not the total.
    - Its "app package" guess is a heuristic. Pass --app-package when you know the answer.

CHAPTER
    ../README.md -- sections 3.14, 8.4, 8.5, 9.4, 9.5
    When a class you care about is full of JADX WARN comments, the destination is
    ../../14-Dalvik/README.md
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict

# --------------------------------------------------------------------------- jadx discovery


def jadx_command():
    """Return an argv prefix that runs the jadx CLI, or None."""
    explicit = os.environ.get("JADX")
    if explicit and os.path.exists(explicit):
        return [explicit]
    jar = os.environ.get("JADX_JAR")
    if jar and os.path.exists(jar):
        java = shutil.which("java")
        if not java:
            return None
        return [java, "-cp", jar, "jadx.cli.JadxCLI"]
    found = shutil.which("jadx")
    if found:
        return [found]
    return None


def run_jadx(apk, outdir, extra_args, heap):
    cmd = jadx_command()
    if cmd is None:
        sys.exit(
            "error: jadx not found.\n"
            "  Set JADX to a launcher, or JADX_JAR to a jadx jar, or put jadx on PATH.\n"
            "  On a Windows jadx-gui-only install:\n"
            '    export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"'
        )
    # Insert the heap setting only when we are the ones invoking java.
    if heap and len(cmd) > 1 and cmd[1] == "-cp":
        cmd = [cmd[0], "-Xmx" + heap] + cmd[1:]
    cmd = cmd + ["--no-res", "--log-level", "error", "-d", outdir] + extra_args + [apk]
    print("[*] " + " ".join(cmd), file=sys.stderr)
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - started
    console_errors = 0
    m = re.search(r"finished with errors, count:\s*(\d+)", proc.stdout + proc.stderr)
    if m:
        console_errors = int(m.group(1))
    print("[*] jadx finished in %.0fs (console error count: %d)" % (elapsed, console_errors),
          file=sys.stderr)
    return elapsed, console_errors


# --------------------------------------------------------------------------- signal catalogue
#
# Each entry: (name, weight, compiled regex).
# Weights are deliberately coarse. The ranking is a reading order, not a risk score.

SIGNALS = [
    ("endpoint",      6, re.compile(r'"https?://[^"\s]{6,}"')),
    ("crypto",        6, re.compile(r'\b(Cipher\.getInstance|SecretKeySpec|IvParameterSpec|'
                                    r'MessageDigest\.getInstance|KeyGenerator|Mac\.getInstance)\b')),
    ("keystore",      6, re.compile(r'\b(AndroidKeyStore|KeyStore\.getInstance|KeyGenParameterSpec)\b')),
    ("tls",           7, re.compile(r'\b(checkServerTrusted|X509TrustManager|setHostnameVerifier|'
                                    r'CertificatePinner|sslSocketFactory|onReceivedSslError)\b')),
    ("webview",       6, re.compile(r'\b(addJavascriptInterface|setJavaScriptEnabled|'
                                    r'shouldOverrideUrlLoading|setAllowUniversalAccessFromFileURLs)\b')),
    ("secret_like",   7, re.compile(r'(?i)\b(api[_-]?key|secret|passwd|password|token|bearer)\b'
                                    r'\s*=\s*"[^"]{6,}"')),
    ("key_pattern",   9, re.compile(r'"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|'
                                    r'sk_(live|test)_[0-9a-zA-Z]{20,}|gh[pousr]_[0-9A-Za-z]{36})"')),
    ("private_key",  10, re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
    ("ipc",           4, re.compile(r'\b(extends ContentProvider|onReceive\s*\(|extends BroadcastReceiver|'
                                    r'getStringExtra|getParcelableExtra|PendingIntent\.get)\b')),
    ("native",        5, re.compile(r'\bnative\s+[\w.\[\]<>]+\s+\w+\s*\(|System\.loadLibrary|System\.load\(')),
    ("dynamic_load",  7, re.compile(r'\b(DexClassLoader|InMemoryDexClassLoader|PathClassLoader)\b')),
    ("reflection",    3, re.compile(r'\b(Class\.forName|getDeclaredMethod|setAccessible\s*\(\s*true)\b')),
    ("storage",       3, re.compile(r'\b(getSharedPreferences|openOrCreateDatabase|getExternalFilesDir|'
                                    r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\b')),
    ("logging",       2, re.compile(r'\bLog\.[vdiwe]\s*\(')),
    ("rootcheck",     5, re.compile(r'(/system/xbin/su|/system/bin/su|Superuser\.apk|magisk|test-keys)',
                                    re.IGNORECASE)),
    ("signature",     5, re.compile(r'\b(GET_SIGNATURES|GET_SIGNING_CERTIFICATES|signingInfo)\b')),
    ("auth",          4, re.compile(r'\b(isAdmin|isPremium|isPurchased|hasEntitlement|isRooted|isEmulator)\b')),
]

# Packages that are almost always somebody else's code.
LIBRARY_PREFIXES = (
    "android/", "androidx/", "com/google/", "com/android/", "kotlin/", "kotlinx/",
    "java/", "javax/", "org/jetbrains/", "okhttp3/", "okio/", "retrofit2/", "com/squareup/",
    "io/reactivex/", "com/facebook/", "com/bumptech/", "org/apache/", "org/json/",
    "com/fasterxml/", "dagger/", "javassist/", "org/slf4j/", "com/airbnb/", "io/grpc/",
)

REFUSAL = "Method not decompiled"
WARN_RE = re.compile(r"JADX WARN: ([A-Za-z'][A-Za-z' -]*)")

# Grep catalogue for --grep. Names map to the SIGNALS above plus a couple of extras.
GREP_GROUPS = {
    "secrets":  ["secret_like", "key_pattern", "private_key"],
    "network":  ["endpoint", "tls"],
    "crypto":   ["crypto", "keystore"],
    "webview":  ["webview"],
    "ipc":      ["ipc"],
    "native":   ["native", "dynamic_load"],
    "storage":  ["storage", "logging"],
    "antitamper": ["rootcheck", "signature", "auth"],
    "reflection": ["reflection"],
}


# --------------------------------------------------------------------------- scanning


def iter_java(sources):
    for root, _dirs, files in os.walk(sources):
        for f in files:
            if f.endswith(".java"):
                yield os.path.join(root, f)


def rel_package(path, sources):
    rel = os.path.relpath(path, sources).replace("\\", "/")
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def is_library(pkg):
    p = pkg + "/"
    return any(p.startswith(x) for x in LIBRARY_PREFIXES)


def guess_app_package(pkg_counts):
    """Largest non-library package at depth 3, e.g. com/example/app."""
    best, best_n = None, 0
    agg = Counter()
    for pkg, n in pkg_counts.items():
        if is_library(pkg):
            continue
        parts = pkg.split("/")
        if len(parts) >= 3:
            agg["/".join(parts[:3])] += n
    for pkg, n in agg.items():
        if n > best_n:
            best, best_n = pkg, n
    return best


def scan(sources, app_package):
    files = 0
    lines = 0
    refused_methods = 0
    refused_files = 0
    warn_counter = Counter()
    pkg_counts = Counter()
    refusals_by_pkg = Counter()
    scored = []

    app_prefix = app_package.replace(".", "/") if app_package else None

    for path in iter_java(sources):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue

        files += 1
        lines += len(text.splitlines())
        pkg = rel_package(path, sources)
        pkg_counts[pkg] += 1

        n_ref = text.count(REFUSAL)
        if n_ref:
            refused_methods += n_ref
            refused_files += 1
            refusals_by_pkg[pkg] += 1

        for w in WARN_RE.findall(text):
            warn_counter[w.strip()] += 1

        score = 0
        hits = []
        for name, weight, rx in SIGNALS:
            n = len(rx.findall(text))
            if n:
                # Diminishing returns: a class with 40 Log calls is not 40x more interesting.
                score += weight * min(n, 3)
                hits.append("%s x%d" % (name, n))

        if score:
            if app_prefix and pkg.startswith(app_prefix):
                score = int(score * 3.0)
                origin = "APP"
            elif is_library(pkg):
                score = int(score * 0.3)
                origin = "lib"
            else:
                origin = "?"
            scored.append({
                "file": os.path.relpath(path, sources).replace("\\", "/"),
                "package": pkg,
                "origin": origin,
                "score": score,
                "signals": hits,
                "refusals": n_ref,
            })

    scored.sort(key=lambda d: (-d["score"], d["file"]))
    return {
        "files": files,
        "lines": lines,
        "refused_methods": refused_methods,
        "refused_files": refused_files,
        "warn_histogram": warn_counter.most_common(),
        "packages": pkg_counts.most_common(),
        "refusals_by_package": refusals_by_pkg.most_common(),
        "ranked": scored,
    }


# --------------------------------------------------------------------------- reporting


def top_packages(pkg_counts, depth=3, limit=15):
    agg = Counter()
    for pkg, n in pkg_counts:
        agg["/".join(pkg.split("/")[:depth])] += n
    return agg.most_common(limit)


def report(res, app_package, elapsed, console_errors, limit):
    w = sys.stdout.write
    w("\n" + "=" * 78 + "\n")
    w("DECOMPILATION COVERAGE\n")
    w("=" * 78 + "\n")
    w("  java files                 : %d\n" % res["files"])
    w("  lines of java              : %d\n" % res["lines"])
    w("  methods refused            : %d\n" % res["refused_methods"])
    w("  files with >=1 refusal     : %d (%.1f%%)\n" % (
        res["refused_files"],
        100.0 * res["refused_files"] / res["files"] if res["files"] else 0.0))
    if console_errors is not None:
        w("  jadx console error count   : %d" % console_errors)
        if console_errors < res["refused_methods"]:
            w("   <-- UNDER-REPORTS the tree by %dx\n" % (
                res["refused_methods"] // max(console_errors, 1)))
        else:
            w("\n")
    if elapsed:
        w("  decompile wall time        : %.0fs\n" % elapsed)

    w("\n" + "-" * 78 + "\n")
    w("WARNING HISTOGRAM -- each of these is jadx telling you where it was unsure\n")
    w("-" * 78 + "\n")
    if not res["warn_histogram"]:
        w("  (none)\n")
    for name, n in res["warn_histogram"][:20]:
        w("  %7d  %s\n" % (n, name))
    w("\n  'Removed duplicated region for block' means the Java below it is MISSING a\n")
    w("  control-flow path. It is printed as ordinary Java with no other marker.\n")

    w("\n" + "-" * 78 + "\n")
    w("WHOSE CODE IS THIS? -- top packages by file count\n")
    w("-" * 78 + "\n")
    for pkg, n in top_packages(res["packages"]):
        tag = "lib" if is_library(pkg) else "   "
        w("  %7d  %s  %s\n" % (n, tag, pkg or "(default)"))
    if app_package:
        w("\n  app package: %s\n" % app_package)

    w("\n" + "-" * 78 + "\n")
    w("WHERE DID jadx FAIL? -- refusals by package\n")
    w("-" * 78 + "\n")
    agg = Counter()
    for pkg, n in res["refusals_by_package"]:
        agg["/".join(pkg.split("/")[:3])] += n
    if not agg:
        w("  (none)\n")
    for pkg, n in agg.most_common(15):
        w("  %7d  %s\n" % (n, pkg or "(default)"))
    w("\n  Read the DISTRIBUTION, not the total. Refusals spread across library packages are\n")
    w("  normal (Kotlin default-argument constructors, generated adapters, reflection\n")
    w("  internals). Refusals concentrated in the app's own security-relevant package mean\n")
    w("  a control-flow obfuscator ran there -- see ../../40-Obfuscation/README.md\n")

    w("\n" + "-" * 78 + "\n")
    w("READ THESE FIRST -- top %d by signal score\n" % limit)
    w("-" * 78 + "\n")
    if not res["ranked"]:
        w("  (nothing matched any signal -- check that --sources points at jadx's sources/ dir)\n")
    for row in res["ranked"][:limit]:
        flag = "!" if row["refusals"] else " "
        w("  %5d %s [%s] %s\n" % (row["score"], flag, row["origin"], row["file"]))
        w("        %s\n" % ", ".join(row["signals"]))
    w("\n  '!' marks a file that also contains a refused method: read it in Smali.\n")
    w("  A high score means 'a human should look at this next'. It is not a risk rating,\n")
    w("  and a class scoring zero may be the most important class in the app.\n")
    w("\n" + "=" * 78 + "\n")


def do_grep(sources, groups, limit):
    wanted = set()
    for g in groups:
        g = g.strip()
        if g in GREP_GROUPS:
            wanted.update(GREP_GROUPS[g])
        else:
            wanted.add(g)
    active = [(n, rx) for (n, _w, rx) in SIGNALS if n in wanted]
    if not active:
        sys.exit("error: no known signal groups in %r. Known: %s"
                 % (",".join(groups), ", ".join(sorted(GREP_GROUPS))))
    total = 0
    for path in iter_java(sources):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(path, sources).replace("\\", "/")
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, rx in active:
                if rx.search(line):
                    print("%s:%d: [%s] %s" % (rel, lineno, name, line.strip()[:160]))
                    total += 1
                    if total >= limit:
                        print("... (limit %d reached; raise it with --grep-limit)" % limit)
                        return
                    break


# --------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description="Batch decompile, census jadx's failures, and rank classes worth reading.",
        epilog="Chapter 56 sections 3.14, 8.4, 8.5, 9.4, 9.5.")
    ap.add_argument("--apk", help="APK/DEX to decompile first")
    ap.add_argument("--out", default="./jadx-out", help="output dir for --apk (default ./jadx-out)")
    ap.add_argument("--sources", help="an existing jadx sources/ directory to triage")
    ap.add_argument("--app-package", help="the app's own package, e.g. com.example.app")
    ap.add_argument("--app-only", action="store_true",
                    help="rank only classes inside --app-package (coverage stats stay app-wide). "
                         "On a real app this is the difference between reading 2,000 files and "
                         "20,000 -- see chapter section 9.4")
    ap.add_argument("--deobf", action="store_true",
                    help="pass --deobf to jadx (unique greppable names; recovers nothing)")
    ap.add_argument("--heap", default="4g", help="JVM -Xmx for jadx when invoked via JADX_JAR")
    ap.add_argument("--limit", type=int, default=40, help="how many ranked classes to print")
    ap.add_argument("--json", help="also write the full report as JSON to this path")
    ap.add_argument("--grep", help="comma-separated signal groups to grep for instead of ranking: "
                                   + ", ".join(sorted(GREP_GROUPS)))
    ap.add_argument("--grep-limit", type=int, default=400, help="max --grep hits to print")
    args = ap.parse_args()

    elapsed, console_errors = None, None

    if args.apk:
        extra = ["--deobf"] if args.deobf else []
        elapsed, console_errors = run_jadx(args.apk, args.out, extra, args.heap)
        sources = os.path.join(args.out, "sources")
        if not os.path.isdir(sources):
            sources = args.out
    elif args.sources:
        sources = args.sources
    else:
        ap.error("give --apk or --sources")

    if not os.path.isdir(sources):
        sys.exit("error: %s is not a directory" % sources)

    if args.grep:
        do_grep(sources, args.grep.split(","), args.grep_limit)
        return

    # First pass just to guess the app package, if it was not given.
    app_package = args.app_package
    if not app_package:
        counts = Counter()
        for p in iter_java(sources):
            counts[rel_package(p, sources)] += 1
        guessed = guess_app_package(counts)
        if guessed:
            app_package = guessed.replace("/", ".")
            print("[*] app package guessed as %s (override with --app-package)" % app_package,
                  file=sys.stderr)

    res = scan(sources, app_package)

    if args.app_only:
        if not app_package:
            sys.exit("error: --app-only needs --app-package (or a package this script can guess)")
        only_app = [r for r in res["ranked"] if r["origin"] == "APP"]
        if only_app:
            res["ranked"] = only_app
        else:
            # --sources was probably already pointed INSIDE the app package, so no path in
            # the tree starts with it. Fall back to "everything that is not a known library"
            # rather than printing an empty list, which looks like a bug in the ranking.
            print("[*] --app-only matched nothing: --sources looks like it is already scoped "
                  "inside %s. Falling back to 'exclude known libraries'." % app_package,
                  file=sys.stderr)
            res["ranked"] = [r for r in res["ranked"] if r["origin"] != "lib"]

    report(res, app_package, elapsed, console_errors, args.limit)

    if args.json:
        payload = dict(res)
        payload["app_package"] = app_package
        payload["decompile_seconds"] = elapsed
        payload["jadx_console_error_count"] = console_errors
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print("[*] wrote %s" % args.json, file=sys.stderr)


if __name__ == "__main__":
    main()
