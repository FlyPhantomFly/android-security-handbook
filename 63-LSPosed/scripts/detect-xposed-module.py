#!/usr/bin/env python3
"""
scripts/detect-xposed-module.py

PURPOSE
    Decide, from an APK alone and without running anything, whether it is an
    Xposed / LSPosed module -- and if so, what it declares, what it wants, and
    what it appears to target.

    Five questions, in the order a triage actually asks them:

      1. Is it a module?      assets/xposed_init, META-INF/xposed/*, and the
                              xposedmodule manifest declaration
      2. Which API?           classic de.robv, or the newer libxposed
      3. Entry classes?       named in plaintext, always -- see WHY below
      4. What scope?          xposedscope, with "android" flagged LOUDLY,
                              because that scope means system_server
      5. What does it hook?   class-name-shaped string constants near API call
                              sites.  LEADS, NOT FINDINGS.

WHY THIS WORKS AT ALL, AND WHY IT KEEPS WORKING
    Two facts about the format are structural rather than incidental, so
    obfuscation cannot remove them:

      * A module MUST reference de.robv.android.xposed types by their real
        names, because those classes are supplied by the framework at runtime.
        R8 can rename everything the module owns and nothing it imports.
      * A module MUST name its entry class in plaintext in assets/xposed_init
        (or META-INF/xposed/java_init.list), because the framework reads that
        file with no knowledge of any obfuscation mapping.

    Everything else this script reports is heuristic and is labelled as such.

USAGE
    python3 -B detect-xposed-module.py MODULE.apk
    python3 -B detect-xposed-module.py DIR/ --recursive
    python3 -B detect-xposed-module.py MODULE.apk --json
    python3 -B detect-xposed-module.py MODULE.apk --verbose

    Options:
      --recursive   Walk a directory for *.apk
      --json        Machine-readable output
      --verbose     Also print every extracted target-name candidate
      --quiet       Only print modules; skip ordinary APKs

    Run with -B so no __pycache__ is written next to the script.  This
    repository has had __pycache__ committed twice by scripts that ignored
    PYTHONDONTWRITEBYTECODE.

REQUIREMENTS
    Python 3.8+.  Standard library only -- no androguard, no aapt, no network.
    That is deliberate: this is the tool you run on a module somebody sent you,
    on a machine you did not set up.

LIMITS, STATED HONESTLY
    * The manifest is binary XML.  This script does a targeted string scan of
      it rather than a full AXML parse, so it reports the PRESENCE of a
      declaration reliably and its exact VALUE only when the value is a plain
      string in the pool.  For a full decode use apktool; 10-APK-Internals
      covers the format.
    * Target extraction is a string heuristic over the DEX string pool.  A
      module with encrypted strings yields nothing, and a module that embeds an
      unrelated package name yields a false positive.  Chapter 52 measured a
      real sweep at 15 of 17 high-confidence hits rejected by hand.  The output
      says "leads" for that reason.
    * It does not verify signatures, and a module's signature is worth checking
      separately.
"""

import argparse
import json
import os
import re
import sys
import zipfile

# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------

CLASSIC_INIT = "assets/xposed_init"
LIBX_INIT = "META-INF/xposed/java_init.list"
LIBX_PROP = "META-INF/xposed/module.prop"
LIBX_SCOPE = "META-INF/xposed/scope.list"

# Manifest declarations.  In binary XML these appear as UTF-16 or UTF-8 entries
# in the string pool, so both encodings are searched.
MANIFEST_KEYS = [
    "xposedmodule",
    "xposedminversion",
    "xposeddescription",
    "xposedscope",
]

# The obfuscation-proof fingerprint: type descriptors the framework supplies.
CLASSIC_TYPE_RE = re.compile(rb"Lde/robv/android/xposed/[A-Za-z0-9$/_]+;")
LIBX_TYPE_RE = re.compile(rb"Lio/github/libxposed/[A-Za-z0-9$/_]+;")

# A class-name-shaped constant: at least three dot-separated segments, first
# segment lower case.  Tuned to match "com.example.Gate" and not "1.2.3".
TARGET_RE = re.compile(
    rb"(?<![A-Za-z0-9_.$])"
    rb"[a-z][a-z0-9_]*(?:\.[a-zA-Z][A-Za-z0-9_]*){2,}"
    rb"(?![A-Za-z0-9_.$])"
)

# A comma-separated scope list, e.g. "com.example.a,com.example.b,android".
# Matched directly rather than reassembled from single names, because the
# comma is the only thing that distinguishes a scope declaration from any
# other package name in the pool.
SCOPE_LIST_RE = re.compile(
    rb"[a-z][a-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+"
    rb"(?:,[a-z][A-Za-z0-9_.]*)+"
)

# Names that are class-name-shaped but are never a hook target.
TARGET_DENY_PREFIXES = (
    b"java.", b"javax.", b"kotlin.", b"kotlinx.", b"de.robv.",
    b"io.github.libxposed.", b"org.jetbrains.", b"dalvik.", b"sun.",
    b"org.intellij.", b"androidx.annotation.",
)

# Scope entries that are not ordinary applications.
PRIVILEGED_SCOPES = {"android", "system", "com.android.systemui"}

# API calls whose presence says the module CHANGES behaviour rather than only
# observing it.  See the chapter's section 6.3 for why absence proves little.
MUTATING_CALLS = [
    b"XC_MethodReplacement",
    b"->setResult(",
    b"->setThrowable(",
    b"->setObjectField(",
    b"->setStaticObjectField(",
    b"->setIntField(",
    b"->setBooleanField(",
]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _both_encodings(needle: str):
    """Binary AXML stores strings as UTF-16LE; some pools use UTF-8."""
    return [needle.encode("utf-8"), needle.encode("utf-16-le")]


def _read(zf, name):
    try:
        return zf.read(name)
    except KeyError:
        return None


def _dex_blobs(zf):
    """Every classes*.dex in the archive, concatenated names -> bytes."""
    out = {}
    for n in zf.namelist():
        if re.fullmatch(r"classes\d*\.dex", n):
            out[n] = zf.read(n)
    return out


def _decode_lines(blob):
    if blob is None:
        return []
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        text = blob.decode("latin-1")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def analyse(path):
    r = {
        "path": path,
        "is_module": False,
        "confidence": "none",
        "api": None,
        "entry_classes": [],
        "manifest_declarations": {},
        "scope": [],
        "privileged_scope": [],
        "xposed_types": [],
        "mutating_calls": [],
        "target_leads": [],
        "extra": [],
        "errors": [],
    }

    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        r["errors"].append("not a readable zip: %s" % exc)
        return r

    with zf:
        names = set(zf.namelist())

        # --- 1 & 3: entry declarations -------------------------------------
        if CLASSIC_INIT in names:
            r["api"] = "classic (de.robv.android.xposed)"
            r["entry_classes"] = _decode_lines(_read(zf, CLASSIC_INIT))
            r["is_module"] = True
        if LIBX_INIT in names:
            r["api"] = "libxposed" if r["api"] is None else r["api"] + " + libxposed"
            r["entry_classes"] += _decode_lines(_read(zf, LIBX_INIT))
            r["is_module"] = True
        if LIBX_SCOPE in names:
            r["scope"] += _decode_lines(_read(zf, LIBX_SCOPE))
        if LIBX_PROP in names:
            r["extra"].append(LIBX_PROP)

        # --- 2: manifest declarations --------------------------------------
        manifest = _read(zf, "AndroidManifest.xml")
        if manifest:
            for key in MANIFEST_KEYS:
                found = any(v in manifest for v in _both_encodings(key))
                r["manifest_declarations"][key] = found
            if r["manifest_declarations"].get("xposedmodule"):
                r["is_module"] = True
            # Best-effort value extraction for xposedscope.  The pool holds the
            # whole comma-separated list as ONE string, so look for that shape
            # directly.  UTF-16LE entries are NUL-interleaved, so strip NULs
            # first and search the flattened bytes.
            flat = manifest.replace(b"\x00", b"")
            for m in SCOPE_LIST_RE.finditer(flat):
                for part in m.group(0).split(b","):
                    part = part.strip().decode("utf-8", "replace")
                    if not part or part.startswith(("java.", "kotlin.")):
                        continue
                    # Sanity filter.  Without a full AXML decode the string
                    # pool has no length prefixes to key on, so an adjacent
                    # entry can bleed into the front of the match.  A real
                    # package label is short; a 30+ character first label means
                    # the match swallowed its neighbour.  This trims the noise
                    # WITHOUT dropping the entry -- the trimmed form is kept.
                    head = part.split(".", 1)[0]
                    if len(head) > 30:
                        part = part[len(head) - 30:]
                    r["scope"].append(part)
            # If the manifest declares xposedscope but no comma-bearing string
            # was recovered, say so rather than silently reporting no scope --
            # a single-entry scope has no comma, and the exact value needs a
            # real AXML decode.
            if r["manifest_declarations"].get("xposedscope") and not r["scope"]:
                r["extra"].append(
                    "manifest declares xposedscope but the value was not recovered "
                    "from the string pool (a single-entry scope has no comma). "
                    "Decode it: apktool d -f -o out MODULE.apk && grep -A2 xposedscope out/AndroidManifest.xml")

        # --- the obfuscation-proof fingerprint ------------------------------
        dexes = _dex_blobs(zf)
        types = set()
        mutating = set()
        targets = set()
        for blob in dexes.values():
            for m in CLASSIC_TYPE_RE.finditer(blob):
                types.add(m.group(0).decode("ascii"))
            for m in LIBX_TYPE_RE.finditer(blob):
                types.add(m.group(0).decode("ascii"))
            for call in MUTATING_CALLS:
                if call in blob:
                    mutating.add(call.decode("ascii"))
            for m in TARGET_RE.finditer(blob):
                cand = m.group(0)
                if cand.startswith(TARGET_DENY_PREFIXES):
                    continue
                targets.add(cand.decode("utf-8", "replace"))

        r["xposed_types"] = sorted(types)
        r["mutating_calls"] = sorted(mutating)
        if types:
            r["is_module"] = True
            if r["api"] is None:
                r["api"] = "classic (de.robv.android.xposed)" \
                    if any(t.startswith("Lde/robv") for t in types) else "libxposed"

        # Targets: prefer names that look like a foreign application's classes,
        # i.e. the last segment starts upper case (a class, not a package).
        leads = [t for t in targets if re.search(r"\.[A-Z][A-Za-z0-9_]*$", t)]
        r["target_leads"] = sorted(leads)

        # --- 4: scope -------------------------------------------------------
        r["scope"] = sorted(set(r["scope"]))
        r["privileged_scope"] = sorted(s for s in r["scope"] if s in PRIVILEGED_SCOPES)

        # --- confidence ------------------------------------------------------
        strong = 0
        if r["entry_classes"]:
            strong += 1
        if r["manifest_declarations"].get("xposedmodule"):
            strong += 1
        if r["xposed_types"]:
            strong += 1
        r["confidence"] = {0: "none", 1: "weak", 2: "strong", 3: "certain"}[min(strong, 3)]

        # A module that declares itself but references no API types is odd and
        # worth saying so out loud rather than silently.
        if r["entry_classes"] and not r["xposed_types"]:
            r["extra"].append(
                "declares an entry class but references NO Xposed API types -- "
                "either the real code is in a second DEX loaded at runtime, or "
                "this is a decoy")

    return r


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def report(r, verbose=False):
    print("=" * 72)
    print(r["path"])
    print("=" * 72)
    if r["errors"]:
        for e in r["errors"]:
            print("  ERROR: %s" % e)
        return

    if not r["is_module"]:
        print("  NOT an Xposed/LSPosed module (no entry file, no manifest")
        print("  declaration, no de.robv or libxposed type references).")
        return

    print("  MODULE            yes   (confidence: %s)" % r["confidence"])
    print("  API               %s" % (r["api"] or "unknown"))

    print("  entry classes     %s" % (", ".join(r["entry_classes"]) or "<none found>"))
    if not r["entry_classes"]:
        print("                    ^ unusual: the framework needs this. Check")
        print("                      META-INF/xposed/ and the manifest by hand.")

    md = r["manifest_declarations"]
    if md:
        print("  manifest          " + ", ".join(
            "%s=%s" % (k, "yes" if v else "no") for k, v in md.items()))

    if r["scope"]:
        print("  declared scope    %s" % ", ".join(r["scope"]))
    if r["privileged_scope"]:
        print()
        print("  " + "!" * 66)
        print("  !! PRIVILEGED SCOPE REQUESTED: %s" % ", ".join(r["privileged_scope"]))
        print("  !! 'android' scope loads this module into system_server, at uid")
        print("  !! 1000 with the platform's permissions.  A hook there sees every")
        print("  !! Binder transaction on the device.  Treat enabling it as")
        print("  !! equivalent to installing a system app you did not build.")
        print("  " + "!" * 66)
        print()

    print("  API types (%d)" % len(r["xposed_types"]))
    for t in r["xposed_types"]:
        print("      %s" % t)

    if r["mutating_calls"]:
        print("  MUTATING calls    %s" % ", ".join(r["mutating_calls"]))
        print("                    ^ this build CHANGES behaviour, not only observes")
    else:
        print("  MUTATING calls    none found in the DEX")
        print("                    ^ ABSENCE PROVES LITTLE.  A compile-time")
        print("                      `static final boolean` guard removes the whole")
        print("                      branch; the capability can be one character")
        print("                      away in the source.  Review the source, not")
        print("                      the APK, when the question is trust.")

    print("  target LEADS (%d)  -- string constants, NOT confirmed hook targets"
          % len(r["target_leads"]))
    show = r["target_leads"] if verbose else r["target_leads"][:15]
    for t in show:
        print("      %s" % t)
    if not verbose and len(r["target_leads"]) > len(show):
        print("      ... %d more (use --verbose)" % (len(r["target_leads"]) - len(show)))

    for x in r["extra"]:
        print("  note: %s" % x)


def main():
    ap = argparse.ArgumentParser(
        description="Static triage of Xposed / LSPosed module APKs.")
    ap.add_argument("target", help="an .apk, or a directory with --recursive")
    ap.add_argument("--recursive", action="store_true", help="walk a directory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--verbose", action="store_true", help="print every target lead")
    ap.add_argument("--quiet", action="store_true", help="skip non-modules")
    args = ap.parse_args()

    paths = []
    if os.path.isdir(args.target):
        if not args.recursive:
            ap.error("%s is a directory; pass --recursive" % args.target)
        for root, _dirs, files in os.walk(args.target):
            for f in files:
                if f.lower().endswith(".apk"):
                    paths.append(os.path.join(root, f))
    else:
        paths.append(args.target)

    if not paths:
        print("no APKs found under %s" % args.target, file=sys.stderr)
        return 1

    results = [analyse(p) for p in paths]

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    modules = 0
    for r in results:
        if args.quiet and not r["is_module"]:
            continue
        report(r, verbose=args.verbose)
        print()
        if r["is_module"]:
            modules += 1

    print("%d APK(s) examined, %d module(s)." % (len(results), modules))
    priv = [r["path"] for r in results if r["privileged_scope"]]
    if priv:
        print("%d requested PRIVILEGED scope: %s" % (len(priv), ", ".join(priv)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
