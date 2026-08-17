#!/usr/bin/env python3
"""
r2-triage.py -- corpus-scale triage of Android native libraries with r2pipe.

PURPOSE
    Answers one question across hundreds of .so files at once: "which of these are worth
    a human's attention?" It emits one CSV row per library with architecture, hardening
    flags, stripped status, import/export counts, a SHA-256 for deduplication, and a
    column per "watched" import.

    It deliberately runs NO code analysis. Imports, exports, strings, sections and
    hardening flags all come from parsing the ELF structure, whose cost is bounded by the
    symbol table rather than by the size of .text. That distinction is the whole reason
    this job belongs to radare2 rather than to a decompiler -- see README.md sections 2,
    3.6 and 9.5. A 13 MB libhwui.so has 1,080 dynamic symbols against 6.3 MB of code;
    structural parsing reads the former and never touches the latter.

USAGE
    python3 -B r2-triage.py <directory> [...] [options]

    python3 -B r2-triage.py extracted/lib/arm64-v8a
    python3 -B r2-triage.py work/ --out portfolio.csv \
        --watch ptrace,__system_property_get,dlopen,dlsym,fork,execve,system,popen
    python3 -B r2-triage.py work/ --strings --out portfolio.csv

    Options:
      --out FILE      write CSV here (default: stdout)
      --watch LIST    comma-separated imports to add as columns
                      (default: the anti-analysis / process-control set below)
      --strings       also scan strings for suspicious patterns (slower, still no analysis)
      --dedup         collapse rows with identical SHA-256, keeping the first path
      --quiet         suppress progress on stderr

REQUIREMENTS
    radare2 on PATH, and the r2pipe Python module:
        pip install r2pipe

    Note that `pip install r2pipe` installs only a CLIENT. It launches `r2` as a
    subprocess, so a machine with r2pipe and no radare2 imports fine and then fails at
    open(). This script checks for both up front and exits non-zero with an explanation.

WHY IT FAILS LOUDLY
    A batch scanner that prints an empty report when its tools are missing produces a
    false negative that is indistinguishable from a clean result. Every failure path here
    exits non-zero so a shell loop notices.

EXIT CODES
    0  at least one library was scanned
    1  r2pipe or radare2 missing, or bad arguments
    2  a named path does not exist
    3  no ELF files found under the given paths
"""

import argparse
import csv
import hashlib
import os
import shutil
import sys

# Imports worth a column by default. Each is a capability, not a verdict: presence means
# the library CAN do the thing, not that it does. See README.md section 5.1.
DEFAULT_WATCH = [
    "ptrace",                    # anti-debug
    "prctl",                     # anti-debug (PR_SET_DUMPABLE)
    "__system_property_get",     # emulator / root / device fingerprinting
    "dlopen",                    # dynamic loading -- hides the real dependency graph
    "dlsym",
    "fork",
    "execve",
    "system",                    # shell out
    "popen",
    "access",                    # filesystem probes -- root detection
    "stat",
    "inotify_init",              # watching for tampering
]

# Cheap string heuristics, used only with --strings.
STRING_PATTERNS = [
    ("su_path",   ("/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su")),
    ("root_pkg",  ("magisk", "supersu", "superuser", "busybox", "xposed")),
    ("hook_tool", ("frida", "gum-js-loop", "gadget", "substrate")),
    ("emulator",  ("goldfish", "ranchu", "qemu", "vbox", "genymotion")),
    ("url",       ("http://", "https://")),
]


def die(msg, code=1):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(code)


def preflight():
    """Verify both halves of the toolchain before scanning anything."""
    try:
        import r2pipe  # noqa: F401
    except ImportError:
        die(
            "the r2pipe Python module is not installed.\n"
            "  Install it with:  pip install r2pipe\n"
            "  Note that this installs only the client; radare2 itself must also be\n"
            "  present, because r2pipe works by launching `r2` as a subprocess.",
        )
    if shutil.which("r2") is None and shutil.which("radare2") is None:
        die(
            "radare2 is not on PATH.\n"
            "  r2pipe launches `r2` as a subprocess, so the module importing successfully\n"
            "  is not enough. Install radare2:\n"
            "    git clone https://github.com/radareorg/radare2 && "
            "cd radare2 && sys/install.sh\n"
            "  or:  sudo apt-get install radare2",
        )
    import r2pipe
    return r2pipe


def is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def find_libs(paths):
    out = []
    for p in paths:
        if not os.path.exists(p):
            die("path does not exist: %s" % p, 2)
        if os.path.isfile(p):
            if is_elf(p):
                out.append(p)
            continue
        for root, _dirs, files in os.walk(p):
            for name in files:
                if ".so" not in name:
                    continue
                full = os.path.join(root, name)
                if is_elf(full):
                    out.append(full)
    return sorted(out)


def scan_one(r2pipe, path, watch, want_strings):
    """Open one library and extract structural facts. No code analysis is performed."""
    row = {"file": path, "basename": os.path.basename(path), "sha256": sha256(path)}
    try:
        row["size"] = os.path.getsize(path)
    except OSError:
        row["size"] = 0

    r2 = None
    try:
        # -2 silences r2's stderr so a warning on one file does not pollute the run.
        r2 = r2pipe.open(path, flags=["-2"])

        info = r2.cmdj("ij") or {}
        bink = info.get("bin", {}) or {}
        row["arch"] = bink.get("arch", "")
        row["bits"] = bink.get("bits", "")
        row["os"] = bink.get("os", "")
        row["type"] = bink.get("bintype", "")
        # radare2 reports these as booleans; normalise to 1/0 so the CSV sorts sensibly.
        for flag in ("stripped", "pic", "canary", "nx", "relro", "static"):
            val = bink.get(flag, "")
            if isinstance(val, bool):
                row[flag] = 1 if val else 0
            else:
                row[flag] = val

        imports = r2.cmdj("iij") or []
        exports = r2.cmdj("iEj") or []
        libs = r2.cmdj("ilj") or []

        imp_names = set()
        for i in imports:
            n = i.get("name", "")
            # r2 sometimes prefixes with the library, e.g. "libc.so_access"
            imp_names.add(n.split("_")[-1] if "_" in n else n)
            imp_names.add(n)

        row["n_imports"] = len(imports)
        row["n_exports"] = len(exports)
        row["n_libs"] = len(libs)
        row["libs"] = ";".join(sorted(str(x) for x in libs))

        # JNI surface: statically registered entry points are Java_-prefixed exports.
        jni = [e.get("name", "") for e in exports
               if "Java_" in e.get("name", "")]
        row["n_jni_static"] = len(jni)
        row["has_jni_onload"] = 1 if any(
            "JNI_OnLoad" in e.get("name", "") for e in exports) else 0
        # Only JNI_OnLoad and no Java_* exports strongly suggests dynamic registration.
        row["likely_dynamic_jni"] = (
            1 if (row["has_jni_onload"] and row["n_jni_static"] == 0) else 0)

        for w in watch:
            row["imp_" + w] = 1 if any(w == n or n.endswith(w) for n in imp_names) else 0

        if want_strings:
            strings = r2.cmdj("izj") or []
            blob = "\n".join(
                (s.get("string", "") or "") for s in strings).lower()
            for label, needles in STRING_PATTERNS:
                row["str_" + label] = 1 if any(n in blob for n in needles) else 0
            row["n_strings"] = len(strings)

        row["error"] = ""
    except Exception as exc:                                  # noqa: BLE001
        # Record the failure in the row rather than aborting the whole corpus scan --
        # but keep it visible, so it can never be mistaken for a clean result.
        row["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:                                 # noqa: BLE001
                pass
    return row


def main():
    ap = argparse.ArgumentParser(
        description="Corpus triage of Android native libraries (structural parsing only).")
    ap.add_argument("paths", nargs="+", help="directories or files to scan")
    ap.add_argument("--out", default=None, help="CSV output path (default: stdout)")
    ap.add_argument("--watch", default=",".join(DEFAULT_WATCH),
                    help="comma-separated imports to add as columns")
    ap.add_argument("--strings", action="store_true",
                    help="also scan strings for suspicious patterns")
    ap.add_argument("--dedup", action="store_true",
                    help="collapse rows with identical sha256")
    ap.add_argument("--quiet", action="store_true", help="no progress on stderr")
    args = ap.parse_args()

    r2pipe = preflight()

    watch = [w.strip() for w in args.watch.split(",") if w.strip()]
    libs = find_libs(args.paths)
    if not libs:
        die("no ELF shared objects found under: %s" % ", ".join(args.paths), 3)

    if not args.quiet:
        print("scanning %d libraries..." % len(libs), file=sys.stderr)

    rows = []
    seen_hashes = {}
    skipped = 0
    for idx, path in enumerate(libs, 1):
        if not args.quiet and idx % 25 == 0:
            print("  %d/%d" % (idx, len(libs)), file=sys.stderr)
        row = scan_one(r2pipe, path, watch, args.strings)
        if args.dedup:
            h = row.get("sha256", "")
            if h and h in seen_hashes:
                skipped += 1
                continue
            if h:
                seen_hashes[h] = path
        rows.append(row)

    # Union of all keys, with a stable, readable leading order.
    lead = ["basename", "arch", "bits", "size", "stripped", "pic", "canary", "nx",
            "relro", "n_imports", "n_exports", "n_libs", "n_jni_static",
            "has_jni_onload", "likely_dynamic_jni"]
    allkeys = []
    for k in lead:
        if any(k in r for r in rows):
            allkeys.append(k)
    for r in rows:
        for k in r:
            if k not in allkeys:
                allkeys.append(k)

    fh = open(args.out, "w", newline="", encoding="utf-8") if args.out else sys.stdout
    try:
        writer = csv.DictWriter(fh, fieldnames=allkeys, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    finally:
        if args.out:
            fh.close()

    errs = sum(1 for r in rows if r.get("error"))
    if not args.quiet:
        print("wrote %d rows%s%s" % (
            len(rows),
            (" (%d duplicates collapsed)" % skipped) if args.dedup and skipped else "",
            (" -- %d had errors, see the 'error' column" % errs) if errs else ""),
            file=sys.stderr)
        print("\nNext: sort the CSV by the imp_* columns. Libraries with imp_ptrace=1 are\n"
              "the anti-debug ones; those are the handful a human should actually open.",
              file=sys.stderr)

    # A run in which every single file errored is a tooling failure, not a clean corpus.
    if rows and errs == len(rows):
        die("every library failed to parse -- check the radare2 installation", 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
