#!/usr/bin/env python3
"""
detect-kotlin.py — determine whether an APK was written in Kotlin, and how much.

WHAT IT DOES
    Scores an APK against several INDEPENDENT Kotlin markers rather than relying
    on any single one, because each marker on its own has a false-positive mode:

      - a `kotlin/` directory and *.kotlin_builtins files   (strong, but a
        transitive Kotlin dependency in a Java app also produces these)
      - kotlin.Metadata annotations in the DEX               (strong)
      - Intrinsics.checkNotNull* references                  (strong)
      - Companion / INSTANCE / DefaultConstructorMarker      (moderate)
      - $default synthetic bridges                           (moderate)
      - coroutine markers: Continuation, invokeSuspend,
        SuspendLambda, COROUTINE_SUSPENDED                   (moderate)
      - DebugProbesKt.bin                                    (weak, but tells
        you the coroutines debug agent shipped)

    It also estimates the Kotlin stdlib version where possible, and reports the
    proportion of classes that look Kotlin-generated — which distinguishes "a
    Kotlin app" from "a Java app with one Kotlin library".

    See ../README.md sections 6 and 8.

HOW TO RUN
    python3 detect-kotlin.py target.apk
    python3 detect-kotlin.py target.apk --json
    python3 detect-kotlin.py target.apk --verbose

REQUIREMENTS
    Python 3.8+. Standard library only — no androguard, no dexlib.
    Works directly on the APK; does not need apktool or jadx.

WHY IT MATTERS
    Knowing an app is Kotlin changes your whole approach: you expect
    Intrinsics boilerplate, Companion indirection, $default bridges, and
    coroutine state machines instead of readable control flow. It also tells
    you to harvest parameter names from checkNotNullParameter literals, which
    is one of the highest-yield tricks against an obfuscated app.
"""

import argparse
import json
import re
import sys
import zipfile
from collections import Counter

# --------------------------------------------------------------------------
# Marker definitions. Each carries a weight and a note explaining what it
# actually proves, so the output teaches rather than just scoring.
# --------------------------------------------------------------------------

DEX_MARKERS = [
    # (byte pattern, weight, short name, what it means)
    (b"Lkotlin/jvm/internal/Intrinsics;", 30, "Intrinsics",
     "Compiler-inserted null checks. The most reliable Kotlin fingerprint."),
    (b"Lkotlin/Metadata;", 30, "@Metadata",
     "Per-class Kotlin signature metadata. Often survives obfuscation."),
    (b"checkNotNullParameter", 20, "checkNotNullParameter",
     "Non-null parameter checks. Their string args are ORIGINAL parameter names."),
    (b"checkNotNull", 10, "checkNotNull",
     "The !! operator, or an internal null assertion."),
    (b"Lkotlin/coroutines/Continuation;", 20, "Continuation",
     "suspend functions present. Expect state machines, not linear control flow."),
    (b"invokeSuspend", 15, "invokeSuspend",
     "Coroutine bodies. The real logic lives here, not in the suspend function."),
    (b"COROUTINE_SUSPENDED", 10, "COROUTINE_SUSPENDED",
     "The suspension sentinel. Confirms compiled coroutines."),
    (b"Lkotlin/coroutines/jvm/internal/SuspendLambda;", 12, "SuspendLambda",
     "Generated coroutine body classes."),
    (b"DefaultConstructorMarker", 12, "DefaultConstructorMarker",
     "Compiler plumbing for synthetic constructors. Ignore it when reading."),
    (b"$default", 8, "$default bridges",
     "Default-argument bridges taking a bitmask of omitted parameters."),
    (b"Lkotlin/jvm/functions/Function", 10, "Function types",
     "Kotlin lambda/function types."),
    (b"$Companion", 10, "Companion",
     "companion object -> static nested class named Companion."),
    (b"Lkotlin/Unit;", 8, "Unit",
     "Kotlin's void equivalent."),
    (b"Lkotlin/Lazy;", 6, "by lazy",
     "Lazy delegates. Initialisation happens on first access."),
    (b"Lkotlin/Result;", 5, "Result",
     "Kotlin's Result type."),
    (b"Lkotlinx/coroutines/", 10, "kotlinx.coroutines",
     "The coroutines library, not just the language feature."),
    (b"Lkotlinx/serialization/", 8, "kotlinx.serialization",
     "Serialization plugin. Generated serializers need R8 keep rules."),
]

ENTRY_MARKERS = [
    # (predicate on the entry name, weight, short name, meaning)
    (lambda n: n.startswith("kotlin/") and n.endswith(".kotlin_builtins"), 25,
     "kotlin_builtins", "Kotlin stdlib builtins shipped in the APK."),
    (lambda n: n == "DebugProbesKt.bin", 10,
     "DebugProbesKt.bin", "Coroutines debug agent. Check this against the build type."),
    (lambda n: n.startswith("META-INF/") and n.endswith(".kotlin_module"), 20,
     ".kotlin_module", "Per-module Kotlin metadata."),
    (lambda n: n.startswith("kotlin/"), 10,
     "kotlin/ directory", "Kotlin stdlib resources present."),
]

VERSION_PATTERNS = [
    re.compile(rb"kotlin-stdlib[/-](\d+\.\d+\.\d+)"),
    re.compile(rb"Kotlin/JVM\s+(\d+\.\d+)"),
    re.compile(rb"kotlin\.jvm\.internal.{0,40}?(\d+\.\d+\.\d+)"),
]


def read_dex_blobs(zf):
    """Return the concatenated bytes of every classes*.dex in the APK."""
    blobs = []
    for name in zf.namelist():
        if re.fullmatch(r"classes\d*\.dex", name):
            try:
                blobs.append((name, zf.read(name)))
            except Exception as e:
                print(f"  warning: could not read {name}: {e}", file=sys.stderr)
    return blobs


def harvest_parameter_names(dex_bytes, limit=40):
    """
    Pull the string literals that checkNotNullParameter uses.

    These are original parameter names and they survive most obfuscators,
    because removing them would change exception messages. On a heavily
    obfuscated app this recovers a meaningful slice of the original vocabulary.

    We approximate by extracting short, identifier-shaped ASCII strings from
    the DEX string pool. It is a heuristic, not a parse — good enough to be
    useful, and it never claims more than it knows.
    """
    candidates = re.findall(rb"[a-z][a-zA-Z0-9_]{2,24}", dex_bytes)
    common_noise = {
        b"java", b"lang", b"kotlin", b"android", b"string", b"object",
        b"value", b"this", b"void", b"int", b"boolean", b"class",
        b"invoke", b"init", b"get", b"set", b"length", b"size",
    }
    counts = Counter(c for c in candidates if c.lower() not in common_noise)
    return [(c.decode("ascii", "replace"), n) for c, n in counts.most_common(limit)]


def detect_version(zf, dex_blobs):
    """Best-effort Kotlin version detection from resources and DEX strings."""
    haystacks = []
    for name in zf.namelist():
        if name.endswith(".kotlin_module") or "kotlin" in name.lower():
            try:
                haystacks.append(zf.read(name))
            except Exception:
                pass
    for _, blob in dex_blobs:
        haystacks.append(blob[:2_000_000])   # cap: version strings live early

    for pat in VERSION_PATTERNS:
        for h in haystacks:
            m = pat.search(h)
            if m:
                return m.group(1).decode("ascii", "replace")
    return None


def analyse(path, verbose=False):
    result = {
        "apk": path,
        "score": 0,
        "verdict": "unknown",
        "markers": [],
        "kotlin_version": None,
        "dex_files": [],
        "notes": [],
    }

    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        result["error"] = f"cannot open APK: {e}"
        return result

    with zf:
        names = zf.namelist()

        # --- entry-based markers ---------------------------------------
        for pred, weight, short, meaning in ENTRY_MARKERS:
            hits = [n for n in names if pred(n)]
            if hits:
                result["score"] += weight
                result["markers"].append({
                    "marker": short, "weight": weight, "count": len(hits),
                    "meaning": meaning,
                    "examples": hits[:3] if verbose else [],
                })

        # --- DEX-based markers -----------------------------------------
        dex_blobs = read_dex_blobs(zf)
        if not dex_blobs:
            result["notes"].append(
                "No classes*.dex found. Packed APK, or an App Bundle split "
                "that carries no code — pull ALL splits with `pm path`.")
        combined = b"".join(b for _, b in dex_blobs)

        for _, (name, blob) in enumerate(dex_blobs):
            result["dex_files"].append({"name": name, "size": len(blob)})

        for pattern, weight, short, meaning in DEX_MARKERS:
            count = combined.count(pattern)
            if count > 0:
                result["score"] += weight
                result["markers"].append({
                    "marker": short, "weight": weight, "count": count,
                    "meaning": meaning, "examples": [],
                })

        result["kotlin_version"] = detect_version(zf, dex_blobs)

        # --- proportion estimate ---------------------------------------
        # Roughly: how many class definitions mention Intrinsics vs total.
        # This distinguishes "a Kotlin app" from "a Java app with a Kotlin lib".
        total_classes = combined.count(b"Landroid/") + combined.count(b"Lcom/")
        intrinsics_refs = combined.count(b"checkNotNullParameter") + \
                          combined.count(b"checkNotNullExpressionValue")
        if total_classes > 0:
            ratio = min(1.0, intrinsics_refs / max(1, total_classes))
            result["kotlin_density"] = round(ratio, 3)
            if intrinsics_refs > 0 and ratio < 0.02:
                result["notes"].append(
                    "Very low Intrinsics density. This looks like a Java app "
                    "with a Kotlin dependency, not a Kotlin app.")

    # --- verdict -------------------------------------------------------
    s = result["score"]
    if s >= 100:
        result["verdict"] = "KOTLIN (high confidence)"
    elif s >= 50:
        result["verdict"] = "KOTLIN (likely)"
    elif s >= 20:
        result["verdict"] = "MIXED / Kotlin dependency present"
    elif s > 0:
        result["verdict"] = "JAVA (trace Kotlin artefacts only)"
    else:
        result["verdict"] = "JAVA (no Kotlin markers)"

    return result


def main():
    ap = argparse.ArgumentParser(
        description="Detect Kotlin usage in an Android APK")
    ap.add_argument("apk", help="path to the APK")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="show example entries and harvested identifiers")
    ap.add_argument("--names", action="store_true",
                    help="harvest likely original parameter names from the DEX")
    args = ap.parse_args()

    result = analyse(args.apk, verbose=args.verbose)

    if "error" in result:
        print(f"error: {result['error']}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"\n=== {result['apk']} ===")
    print(f"\nVerdict : {result['verdict']}")
    print(f"Score   : {result['score']}")
    if result.get("kotlin_version"):
        print(f"Version : Kotlin {result['kotlin_version']}")
    if "kotlin_density" in result:
        print(f"Density : {result['kotlin_density']} "
              f"(Intrinsics refs per class-ish reference)")

    if result["dex_files"]:
        print(f"\nDEX files ({len(result['dex_files'])}):")
        for d in result["dex_files"]:
            print(f"  {d['name']:<18} {d['size']:>12,} bytes")

    if result["markers"]:
        print("\nMarkers found:")
        for m in sorted(result["markers"], key=lambda x: -x["weight"]):
            print(f"  [{m['weight']:>2}] {m['marker']:<26} x{m['count']}")
            print(f"       {m['meaning']}")
            for ex in m.get("examples", []):
                print(f"       e.g. {ex}")

    for n in result["notes"]:
        print(f"\nNOTE: {n}")

    # --- actionable guidance -------------------------------------------
    if result["score"] >= 50:
        print("\nWhat this means for your analysis:")
        print("  - Expect Intrinsics boilerplate at the top of most methods; ignore it.")
        print("  - companion object -> static nested `Companion` class.")
        print("  - Default arguments -> synthetic `$default` bridges taking a bitmask.")
        print("  - Extension functions -> STATIC methods with the receiver as arg 0.")
        if any(m["marker"] in ("Continuation", "invokeSuspend") for m in result["markers"]):
            print("  - Coroutines present: the real logic is in generated")
            print("    SuspendLambda.invokeSuspend, structured as a switch on `label`.")
            print("    Hooking a suspend function REQUIRES the trailing")
            print("    kotlin.coroutines.Continuation parameter in the overload.")
        if any(m["marker"] == "@Metadata" for m in result["markers"]):
            print("  - @Metadata is present and may carry ORIGINAL signatures even if")
            print("    class names are obfuscated. Worth parsing — see references/.")
        print("\n  Harvest original parameter names with:")
        print(f"    python3 {sys.argv[0]} {result['apk']} --names")

    if args.names:
        try:
            with zipfile.ZipFile(result["apk"]) as zf:
                blobs = read_dex_blobs(zf)
            combined = b"".join(b for _, b in blobs)
            print("\nMost frequent identifier-shaped strings in the DEX string pool.")
            print("Many of these are original parameter names preserved by")
            print("checkNotNullParameter. This is a heuristic, not a parse.\n")
            for name, count in harvest_parameter_names(combined):
                print(f"  {count:>6}  {name}")
        except Exception as e:
            print(f"  harvest failed: {e}", file=sys.stderr)

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
