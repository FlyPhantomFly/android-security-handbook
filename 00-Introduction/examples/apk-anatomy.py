#!/usr/bin/env python3
# =============================================================================
# apk-anatomy.py - inventory the inside of an APK using nothing but the stdlib
# =============================================================================
#
# WHAT THIS DOES
#   Opens an APK as what it actually is - a ZIP archive - and reports:
#     * every entry, grouped by what kind of artefact it is
#     * compressed and uncompressed sizes per group, and the share of the file
#     * whether a v1 (JAR) signature is present, detected via META-INF/*.SF
#     * which native ABIs are shipped, read from the lib/<abi>/ directory names
#     * a handful of findings a first-pass reviewer should always look for
#
# WHY IT EXISTS
#   The first question about any APK is "what is in it and where did the bytes
#   go?" A 90 MB app that is 80 MB of native libraries is a different target
#   from a 90 MB app that is 80 MB of DEX. This script answers that in one
#   command, with no dependencies, so it runs on a locked-down machine and on
#   an air-gapped analysis box.
#
# HOW TO RUN
#   python3 00-Introduction/examples/apk-anatomy.py path/to/app.apk
#   python3 00-Introduction/examples/apk-anatomy.py app.apk --list      # every entry
#   python3 00-Introduction/examples/apk-anatomy.py app.apk --top 40    # biggest 40
#
# REQUIREMENTS
#   Python 3.8 or newer. Standard library only: no pip install, ever.
#
# LIMITS - read these, they matter
#   This script does NOT parse binary XML, DEX, or the APK Signing Block. It
#   deliberately reads only the ZIP central directory. Absence of META-INF/*.SF
#   therefore means "no v1 signature", NOT "unsigned": v2/v3/v4 signatures live
#   in the APK Signing Block, which sits between the file entries and the ZIP
#   central directory and is invisible to zipfile. Use apksigner to verify
#   signatures properly. See ../../10-APK-Internals/README.md.
# =============================================================================

import argparse
import os
import sys
import zipfile
from collections import defaultdict

# -----------------------------------------------------------------------------
# Classification
# -----------------------------------------------------------------------------
# Each entry in the archive is put into exactly one bucket. Order matters:
# the first rule that matches wins, so the more specific rules come first.

GROUP_ORDER = [
    "dex",       # compiled Java/Kotlin bytecode
    "native",    # .so shared libraries under lib/<abi>/
    "arsc",      # the compiled resource table
    "res-xml",   # binary (compiled) XML under res/ and the manifest
    "res-other", # everything else under res/: PNGs, WebP, fonts, raw files
    "assets",    # verbatim developer-supplied files
    "meta-inf",  # signature material and build markers
    "kotlin",    # Kotlin metadata
    "other",     # anything that did not match above
]

GROUP_DESCRIPTION = {
    "dex":       "Compiled bytecode (classes*.dex) - the application logic",
    "native":    "Native shared libraries (lib/<abi>/*.so)",
    "arsc":      "Compiled resource table (resources.arsc)",
    "res-xml":   "Binary XML: manifest, layouts, and res/xml/*",
    "res-other": "Non-XML resources: images, fonts, raw files",
    "assets":    "Verbatim developer files (assets/)",
    "meta-inf":  "META-INF/ - v1 signature material and build markers",
    "kotlin":    "Kotlin metadata (kotlin/, *.kotlin_module)",
    "other":     "Unclassified entries",
}


def classify(name):
    """Return the bucket name for one ZIP entry path."""
    lower = name.lower()

    # The manifest is binary XML but is special enough to keep with res-xml.
    if lower == "androidmanifest.xml":
        return "res-xml"
    if lower == "resources.arsc":
        return "arsc"
    if lower.startswith("meta-inf/"):
        return "meta-inf"
    # assets/ is checked BEFORE .dex and .so on purpose. A .dex or .so shipped
    # under assets/ is not part of the normal layout: it is code the app intends
    # to load itself at runtime. Classifying it as an asset keeps it visible
    # instead of hiding it among the ordinary DEX files.
    if lower.startswith("assets/"):
        return "assets"
    # DEX files are classes.dex, classes2.dex, classes3.dex ...
    if lower.endswith(".dex"):
        return "dex"
    # Native libraries in the standard location the platform extracts from.
    if lower.startswith("lib/") and lower.endswith(".so"):
        return "native"
    if lower.startswith("res/"):
        return "res-xml" if lower.endswith(".xml") else "res-other"
    if lower.startswith("kotlin/") or lower.endswith(".kotlin_module"):
        return "kotlin"
    return "other"


# -----------------------------------------------------------------------------
# Formatting helpers
# -----------------------------------------------------------------------------

def human(n):
    """Format a byte count the way a person reads it."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0 or unit == "GB":
            if unit == "B":
                return "%d B" % n
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f GB" % n


def rule(char="-", width=78):
    print(char * width)


def heading(text):
    print()
    print("=" * 78)
    print(text)
    print("=" * 78)


# -----------------------------------------------------------------------------
# Analysis
# -----------------------------------------------------------------------------

def analyse(path, show_all=False, top_n=15):
    if not os.path.isfile(path):
        print("ERROR: not a file: %s" % path, file=sys.stderr)
        return 2

    if not zipfile.is_zipfile(path):
        print("ERROR: %s is not a ZIP archive." % path, file=sys.stderr)
        print("       An APK is always a ZIP. If this fails, you have an", file=sys.stderr)
        print("       incomplete download, an AAB, or an encrypted container.", file=sys.stderr)
        return 2

    file_size = os.path.getsize(path)

    with zipfile.ZipFile(path) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]

        # --- Overview -------------------------------------------------------
        heading("APK ANATOMY - %s" % os.path.basename(path))
        print("Path              : %s" % os.path.abspath(path))
        print("File size on disk : %s (%d bytes)" % (human(file_size), file_size))
        print("Entries in archive: %d" % len(infos))

        # --- Group totals ---------------------------------------------------
        groups = defaultdict(list)
        for info in infos:
            groups[classify(info.filename)].append(info)

        heading("CONTENTS BY GROUP")
        header = "%-10s %6s %12s %12s %7s  %s"
        print(header % ("GROUP", "FILES", "COMPRESSED", "ORIGINAL", "SHARE", "MEANING"))
        rule()

        total_comp = sum(i.compress_size for i in infos)
        total_orig = sum(i.file_size for i in infos)

        for group in GROUP_ORDER:
            entries = groups.get(group)
            if not entries:
                continue
            comp = sum(i.compress_size for i in entries)
            orig = sum(i.file_size for i in entries)
            share = (comp / total_comp * 100.0) if total_comp else 0.0
            print(header % (
                group,
                len(entries),
                human(comp),
                human(orig),
                "%.1f%%" % share,
                GROUP_DESCRIPTION[group],
            ))

        rule()
        print(header % ("TOTAL", len(infos), human(total_comp), human(total_orig), "100.0%", ""))
        if total_orig:
            print("Compression ratio : %.2fx" % (total_orig / float(total_comp or 1)))

        # --- Native ABIs ----------------------------------------------------
        heading("NATIVE ABIs")
        abis = defaultdict(lambda: [0, 0])  # abi -> [count, compressed bytes]
        for info in groups.get("native", []):
            parts = info.filename.split("/")
            if len(parts) >= 3:
                abi = parts[1]
                abis[abi][0] += 1
                abis[abi][1] += info.compress_size

        if not abis:
            print("No lib/<abi>/*.so entries. This app ships no native libraries in")
            print("the standard location. Note that native code can still be present:")
            print("  * hidden under assets/ and extracted at runtime")
            print("  * downloaded after install")
            print("  * inside a nested APK or JAR")
        else:
            print("%-16s %6s %12s" % ("ABI", "LIBS", "COMPRESSED"))
            rule()
            for abi in sorted(abis):
                count, size = abis[abi]
                print("%-16s %6d %12s" % (abi, count, human(size)))
            print()
            print("Why this matters: an APK containing only arm64-v8a will refuse to")
            print("install on an x86_64 emulator with INSTALL_FAILED_NO_MATCHING_ABIS,")
            print("and the frida-server build you push must match the device ABI.")

        # --- Signing scheme v1 ----------------------------------------------
        heading("SIGNING - v1 (JAR) DETECTION")
        meta = [i.filename for i in groups.get("meta-inf", [])]
        sf_files = [n for n in meta if n.upper().endswith(".SF")]
        sig_blocks = [n for n in meta if n.upper().endswith((".RSA", ".DSA", ".EC"))]
        manifest_mf = [n for n in meta if n.upper() == "META-INF/MANIFEST.MF"]

        if sf_files:
            print("v1 (JAR) signature: PRESENT")
            print()
            print("  Signature files (.SF)  : %s" % ", ".join(sorted(sf_files)))
            if sig_blocks:
                print("  Signature blocks       : %s" % ", ".join(sorted(sig_blocks)))
            if manifest_mf:
                print("  MANIFEST.MF            : present")
            print()
            print("  A v1 signature is a JAR signature: MANIFEST.MF lists a digest per")
            print("  entry, the .SF file digests those lines, and the .RSA/.DSA/.EC")
            print("  block holds the PKCS#7 signature over the .SF file. It protects")
            print("  entry CONTENT but not the ZIP structure itself, which is why")
            print("  v2+ signs the whole file instead.")
        else:
            print("v1 (JAR) signature: ABSENT")
            print()
            print("  No META-INF/*.SF entry was found. Modern apps targeting API 24+")
            print("  are commonly signed with v2/v3 only, and those signatures live in")
            print("  the APK Signing Block, which this script does not read. ABSENT")
            print("  here therefore does NOT mean unsigned.")

        print()
        print("  To verify signatures properly:")
        print("    apksigner verify --verbose --print-certs %s" % os.path.basename(path))

        # --- Quick observations ---------------------------------------------
        heading("FIRST-PASS OBSERVATIONS")
        notes = []

        dex_count = len(groups.get("dex", []))
        if dex_count > 1:
            notes.append(
                "%d DEX files: the app exceeded the 65,536-method limit of a single "
                "DEX and was built with multidex. Expect a large codebase." % dex_count)
        elif dex_count == 1:
            notes.append("Single classes.dex - a small or well-shrunk application.")
        else:
            notes.append(
                "NO .dex entries. This is unusual: it may be a split APK carrying only "
                "resources or native code, or a packed app that loads DEX at runtime.")

        if groups.get("kotlin"):
            notes.append("Kotlin metadata present - the app is written in or uses Kotlin.")

        suspicious_assets = [
            i.filename for i in groups.get("assets", [])
            if i.filename.lower().endswith((".dex", ".so", ".jar", ".apk", ".zip"))
        ]
        if suspicious_assets:
            notes.append(
                "Executable-looking files under assets/ (%s%s). Code shipped outside "
                "lib/ and classes*.dex is usually loaded dynamically, which is both a "
                "packing technique and a place static analysers stop looking." % (
                    ", ".join(suspicious_assets[:3]),
                    ", ..." if len(suspicious_assets) > 3 else ""))

        if not any(i.filename.lower() == "androidmanifest.xml" for i in infos):
            notes.append(
                "No AndroidManifest.xml. Every installable APK has one; its absence "
                "means this is not a complete APK.")

        if len(abis) > 1:
            notes.append(
                "%d ABIs shipped (%s). A universal APK - larger, but installable "
                "everywhere." % (len(abis), ", ".join(sorted(abis))))

        stored = [i for i in infos if i.compress_type == zipfile.ZIP_STORED]
        if stored:
            notes.append(
                "%d entries are STORED (uncompressed). resources.arsc and native "
                "libraries are stored deliberately so the platform can mmap them "
                "directly from the APK without extraction." % len(stored))

        for n in notes:
            print("  * %s" % n)

        # --- Largest entries -------------------------------------------------
        heading("LARGEST %d ENTRIES (by compressed size)" % top_n)
        biggest = sorted(infos, key=lambda i: i.compress_size, reverse=True)[:top_n]
        print("%12s %12s %-10s %s" % ("COMPRESSED", "ORIGINAL", "GROUP", "NAME"))
        rule()
        for info in biggest:
            print("%12s %12s %-10s %s" % (
                human(info.compress_size),
                human(info.file_size),
                classify(info.filename),
                info.filename,
            ))

        # --- Optional full listing -------------------------------------------
        if show_all:
            heading("ALL ENTRIES, GROUPED")
            for group in GROUP_ORDER:
                entries = groups.get(group)
                if not entries:
                    continue
                print()
                print("--- %s (%d) - %s" % (group, len(entries), GROUP_DESCRIPTION[group]))
                for info in sorted(entries, key=lambda i: i.filename):
                    print("  %12s  %s" % (human(info.compress_size), info.filename))

        print()
        print("Next step: decode the binary XML and produce Smali -")
        print("  apktool d %s -o decoded" % os.path.basename(path))
        print("Then read the code -")
        print("  jadx -d out %s" % os.path.basename(path))
        print()

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Inventory an APK's contents using only the Python standard library.",
        epilog="See 00-Introduction/labs/lab-02-first-60-minutes.md for the walkthrough.",
    )
    parser.add_argument("apk", help="path to the .apk file")
    parser.add_argument("--list", action="store_true", dest="show_all",
                        help="print every entry, grouped, not just the largest")
    parser.add_argument("--top", type=int, default=15, metavar="N",
                        help="how many of the largest entries to show (default 15)")
    args = parser.parse_args()

    try:
        return analyse(args.apk, show_all=args.show_all, top_n=args.top)
    except zipfile.BadZipFile as exc:
        print("ERROR: corrupt or truncated archive: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
