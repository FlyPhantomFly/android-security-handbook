#!/usr/bin/env python3
# grade-biometric-usage.py - grade an app's biometric implementation against the only line that
# matters: is the authentication bound to a cryptographic operation, or is it a callback?
#
# PURPOSE
#   Point it at a jadx output tree, an apktool smali tree, a raw source tree, or a directory of
#   any of those, and it produces a graded report:
#
#       GRADE A   per-use CryptoObject binding   (setUserAuthenticationRequired + no validity window)
#       GRADE B   time-bound binding             (setUserAuthenticationValidityDurationSeconds > 0)
#       GRADE C   CryptoObject present, binding unproven from static evidence
#       GRADE D   callback-only                  (prompt, no CryptoObject, no auth-bound key)
#       GRADE F   deprecated FingerprintManager path with a self-drawn dialog
#
#   It is a LEAD GENERATOR, not an oracle. Chapter 52 of this repository measured a real sweep at
#   16,836 raw hits -> 168 leads -> 2 survivors. Expect the same shape here. Every grade below A is
#   a hypothesis you confirm dynamically with ./hook-biometric-prompt.js.
#
# USAGE
#   python3 grade-biometric-usage.py <path> [<path> ...]
#   python3 grade-biometric-usage.py ./jadx-out --json
#   python3 grade-biometric-usage.py ./jadx-out --show-evidence
#   python3 grade-biometric-usage.py ./smali --min-grade C      # only print C and worse
#
#   Typical pipeline:
#       jadx -d jadx-out target.apk
#       python3 grade-biometric-usage.py jadx-out --show-evidence
#
# EXIT CODES
#   0  ran successfully (regardless of grade - the grade is data, not a pass/fail)
#   1  bad arguments or unreadable path
#
# HONEST LIMITS - read these before quoting a grade in a report
#   * Reflection defeats it. An app that calls authenticate() through Method.invoke() is invisible.
#   * Native code defeats it. A JNI wrapper around the crypto is invisible.
#   * Obfuscation degrades it. androidx.biometric ships consumer ProGuard rules so its own class
#     names usually survive, but the APP's callback class will be renamed; the grader keys on
#     framework symbols for exactly this reason.
#   * GRADE A is a claim about the CODE PATH THAT WAS FOUND. An app can hold a grade-A key and
#     still ship a second, unbound path that the attacker uses. Multiple grades in one app is the
#     normal result, and the WORST one is the finding.
#   * A grade is not a severity. "Callback-only" on a gate protecting a settings screen is
#     informational; the same gate on a password vault is high. The tool cannot see what is behind
#     the gate. You can.
#
# Run with `python3 -B` to avoid writing __pycache__.

import argparse
import json
import os
import re
import sys
from collections import defaultdict

# --------------------------------------------------------------------------------------------
# Signal definitions.
#
# Each signal is (name, regex, weight-note). Both Java-ish and smali forms are covered, because a
# smali tree writes `Landroidx/biometric/BiometricPrompt;->authenticate(...)` and a jadx tree
# writes `biometricPrompt.authenticate(promptInfo, cryptoObject)`.
# --------------------------------------------------------------------------------------------

SIGNALS = {
    # ---- the prompt itself -------------------------------------------------------------------
    "prompt_androidx": re.compile(
        r"androidx[./]biometric[./]BiometricPrompt|androidx\.biometric\.BiometricPrompt"),
    "prompt_platform": re.compile(
        r"android[./]hardware[./]biometrics[./]BiometricPrompt"),
    "prompt_fingerprintmanager": re.compile(
        r"android[./]hardware[./]fingerprint[./]FingerprintManager"),

    # ---- the binding -------------------------------------------------------------------------
    # A CryptoObject *type reference* is the cheapest signal and the most over-trusted. Its mere
    # presence proves an import, not a call, which is why it only ever reaches grade C on its own.
    "cryptoobject_type": re.compile(r"BiometricPrompt\$CryptoObject|BiometricPrompt\.CryptoObject"),
    # A two-argument authenticate() is the real evidence on the androidx path.
    "authenticate_two_arg": re.compile(
        r"authenticate\s*\(\s*[A-Za-z0-9_$.]+\s*,\s*[A-Za-z0-9_$.]+\s*\)"
        r"|->authenticate\(Landroidx/biometric/BiometricPrompt\$PromptInfo;"
        r"Landroidx/biometric/BiometricPrompt\$CryptoObject;\)"),
    "authenticate_one_arg_only": re.compile(
        r"->authenticate\(Landroidx/biometric/BiometricPrompt\$PromptInfo;\)V"),

    # ---- the key -----------------------------------------------------------------------------
    "auth_required_true": re.compile(
        r"setUserAuthenticationRequired\s*\(\s*true\s*\)"
        r"|setUserAuthenticationRequired\(Z\)"),
    "auth_required_false": re.compile(r"setUserAuthenticationRequired\s*\(\s*false\s*\)"),
    "validity_duration": re.compile(
        r"setUserAuthenticationValidityDurationSeconds\s*\(\s*(-?\d+)\s*\)"
        r"|setUserAuthenticationValidityDurationSeconds\(I\)"),
    "auth_parameters": re.compile(r"setUserAuthenticationParameters\s*\("),
    "invalidated_by_enrolment_false": re.compile(
        r"setInvalidatedByBiometricEnrollment\s*\(\s*false\s*\)"),
    "invalidated_by_enrolment_true": re.compile(
        r"setInvalidatedByBiometricEnrollment\s*\(\s*true\s*\)"),
    "keygenparameterspec": re.compile(r"KeyGenParameterSpec"),
    "androidkeystore": re.compile(r"\"AndroidKeyStore\"|AndroidKeyStore"),

    # ---- authenticator class requested --------------------------------------------------------
    "authenticators_strong": re.compile(r"BIOMETRIC_STRONG|Authenticators\s*\.\s*BIOMETRIC_STRONG"),
    "authenticators_weak": re.compile(r"BIOMETRIC_WEAK|Authenticators\s*\.\s*BIOMETRIC_WEAK"),
    "device_credential": re.compile(r"DEVICE_CREDENTIAL|setDeviceCredentialAllowed"),
    "setDeviceCredentialAllowed": re.compile(r"setDeviceCredentialAllowed"),

    # ---- smells -------------------------------------------------------------------------------
    # A boolean field flipped inside onAuthenticationSucceeded is the canonical callback-only shape.
    "success_sets_boolean": re.compile(
        r"onAuthenticationSucceeded[\s\S]{0,400}?"
        r"(?:=\s*true|const/4\s+v\d+,\s*0x1[\s\S]{0,80}?iput-boolean)"),
    "success_starts_activity": re.compile(
        r"onAuthenticationSucceeded[\s\S]{0,400}?(?:startActivity|navigate|setResult)"),
    "shared_prefs_near_biometric": re.compile(
        r"(?:biometric|fingerprint)[\s\S]{0,300}?getSharedPreferences"),
    # An app that stores its own "biometric enabled" flag and trusts it.
    "self_managed_flag": re.compile(
        r"(?:isBiometric(?:Enabled|Set)|biometric_enabled|use_fingerprint|fingerprint_enabled)"),
}

# Files worth reading. Everything else is skipped for speed, not for correctness.
SOURCE_EXT = {".java", ".kt", ".smali", ".txt", ".xml"}

# Framework/library paths that produce structural false positives: the androidx library's OWN
# sources, if the tree happens to include them, will match every signal perfectly and grade A.
NOISE_PATH = re.compile(
    r"(^|[/\\])(androidx[/\\]biometric|android[/\\]hardware[/\\]biometrics|"
    r"kotlin[/\\]|kotlinx[/\\]|com[/\\]google[/\\]android[/\\]gms[/\\])")


# --------------------------------------------------------------------------------------------
# Comment stripping.
#
# This is not a nicety. The first run of this script against this chapter's own reference
# implementations graded 01-CallbackOnlyVault.java as C and 02-CryptoBoundVault.java as B -
# exactly backwards - because it was reading the EXPLANATORY COMMENTS. File 01's comments discuss
# CryptoObject at length while the code never uses one; file 02's comments quote a 30-second
# validity window as an example of what NOT to do.
#
# Decompiler output is essentially comment-free, so this rarely bites a jadx tree. It bites hard on
# a source tree, on a documented codebase, and on anything a human wrote prose into. Any grep-based
# tool that skips this step will report the opposite of the truth on well-commented code, and it
# will do so confidently.
#
# Newlines are preserved so that reported line numbers stay correct.
# --------------------------------------------------------------------------------------------

_BLOCK_COMMENT = re.compile(r"/\*[\s\S]*?\*/")
_LINE_COMMENT = re.compile(r"//[^\n]*")
_SMALI_COMMENT = re.compile(r"(?m)^\s*#[^\n]*")
_XML_COMMENT = re.compile(r"<!--[\s\S]*?-->")
_KDOC = re.compile(r"(?m)^\s*\*[^\n]*")


def _blank_preserving_newlines(m):
    return "\n" * m.group(0).count("\n")


def strip_comments(text, ext):
    """Replace comment bodies with whitespace, preserving line structure."""
    if ext == ".smali":
        return _SMALI_COMMENT.sub("", text)
    if ext == ".xml":
        return _XML_COMMENT.sub(_blank_preserving_newlines, text)
    text = _BLOCK_COMMENT.sub(_blank_preserving_newlines, text)
    text = _LINE_COMMENT.sub("", text)
    text = _KDOC.sub("", text)
    return text


# --------------------------------------------------------------------------------------------
# Constant resolution.
#
# Second failure this tool had against its own examples: 03-TimeBoundTrap.kt writes
#
#     private const val VALIDITY_SECONDS = 86_400
#     ...
#     .setUserAuthenticationValidityDurationSeconds(VALIDITY_SECONDS)
#
# A regex looking for a literal argument sees a symbol and finds nothing, so the file graded A when
# it should have graded B - the tool reported the WORST case as the BEST one. Real code names its
# constants; only a decompiler inlines them. Resolve simple same-file definitions, and where the
# value still cannot be resolved, say so and refuse to grade A rather than guessing.
# --------------------------------------------------------------------------------------------

_CONST_DEFS = [
    # Kotlin: const val NAME = 86_400   /   val NAME: Int = 30
    re.compile(r"(?:const\s+)?va[lr]\s+([A-Za-z_]\w*)\s*(?::\s*\w+\s*)?=\s*([\d_]+)"),
    # Java:   static final int NAME = 86400;
    re.compile(r"(?:static\s+)?final\s+(?:int|long)\s+([A-Za-z_]\w*)\s*=\s*([\d_]+)"),
    # smali:  .field private static final NAME:I = 0x15180
    re.compile(r"\.field[^\n]*\s([A-Za-z_]\w*):[IJ]\s*=\s*(0x[0-9a-fA-F]+|\d+)"),
]

_VALIDITY_CALL = re.compile(
    r"setUserAuthenticationValidityDurationSeconds\s*\(\s*([A-Za-z_]\w*|-?[\d_]+)\s*\)")
_PARAMS_CALL = re.compile(
    r"setUserAuthenticationParameters\s*\(\s*([A-Za-z_]\w*|-?[\d_]+)\s*,")


def collect_constants(text):
    out = {}
    for rx in _CONST_DEFS:
        for m in rx.finditer(text):
            name, raw = m.group(1), m.group(2).replace("_", "")
            try:
                out[name] = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
            except ValueError:
                pass
    return out


def resolve_validity(text):
    """
    Return (resolved_values, unresolved_symbols) for every validity-window argument in the file.
    """
    consts = collect_constants(text)
    values, unresolved = [], []
    for rx in (_VALIDITY_CALL, _PARAMS_CALL):
        for m in rx.finditer(text):
            tok = m.group(1)
            if re.fullmatch(r"-?[\d_]+", tok):
                values.append(int(tok.replace("_", "")))
            elif tok in consts:
                values.append(consts[tok])
            else:
                unresolved.append(tok)
    return values, unresolved


class FileFindings:
    __slots__ = ("path", "hits", "validity_values", "unresolved_validity")

    def __init__(self, path):
        self.path = path
        self.hits = defaultdict(list)   # signal -> [(lineno, line)]
        self.validity_values = []
        self.unresolved_validity = []

    def add(self, signal, lineno, line):
        if len(self.hits[signal]) < 5:      # cap evidence; a 3,000-hit file helps nobody
            self.hits[signal].append((lineno, line.strip()[:160]))

    def has(self, *signals):
        return any(s in self.hits for s in signals)


def scan_file(path, keep_comments=False):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except (OSError, UnicodeError):
        return None

    ext = os.path.splitext(path)[1].lower()
    text = raw if keep_comments else strip_comments(raw, ext)

    # Cheap pre-filter: if the file mentions nothing biometric or key-related, skip the 20 regexes.
    lowered = text.lower()
    if not any(k in lowered for k in
               ("biometric", "fingerprint", "cryptoobject", "keygenparameterspec",
                "setuserauthentication")):
        return None

    ff = FileFindings(path)
    lines = text.splitlines()

    for name, rx in SIGNALS.items():
        for m in rx.finditer(text):
            lineno = text.count("\n", 0, m.start()) + 1
            line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
            ff.add(name, lineno, line)

    ff.validity_values, ff.unresolved_validity = resolve_validity(text)
    return ff if ff.hits else None


def grade(ff):
    """
    Return (grade, one-line rationale). Order matters: the checks run worst-case-first for the
    things that are unambiguous, then best-case for the things that need positive evidence.
    """
    # F - the deprecated path, which draws its own UI and has no system dialog to trust.
    if ff.has("prompt_fingerprintmanager") and not ff.has("prompt_androidx", "prompt_platform"):
        if not ff.has("cryptoobject_type"):
            return "F", ("FingerprintManager only, no CryptoObject: an app-drawn authentication "
                         "dialog whose result is a boolean this process owns")
        return "C", ("FingerprintManager with a CryptoObject: the binding may be real, but the "
                     "deprecated path has no DEVICE_CREDENTIAL fallback and no system dialog")

    prompts = ff.has("prompt_androidx", "prompt_platform")
    bound = ff.has("auth_required_true")
    crypto = ff.has("cryptoobject_type", "authenticate_two_arg")

    if bound:
        # Time-bound or per-use? The validity window decides, and a long one is the trap.
        positive = [v for v in ff.validity_values if v > 0]
        if positive:
            worst = max(positive)
            if worst >= 3600:
                return "B", (f"time-bound key, validity {worst}s (>= 1 hour): satisfied by ANY "
                             f"device unlock in that window, by any process, with no prompt "
                             f"from this app")
            return "B", (f"time-bound key, validity {worst}s: satisfied by any unlock in that "
                         f"window, not specifically by this app's prompt")

        # A window the tool could not resolve is NOT evidence of per-use. Refuse to grade A.
        if ff.unresolved_validity:
            syms = ", ".join(sorted(set(ff.unresolved_validity)))
            return "C", (f"auth-bound key whose validity window is the unresolved symbol(s) "
                         f"[{syms}] - read them by hand; a positive value makes this grade B")

        if ff.validity_values:
            # Only zero or the -1 per-use sentinel reached here.
            return "A", ("per-use binding: setUserAuthenticationRequired(true) with a per-use "
                         "validity value (0 or -1) - the strong form")
        if ff.has("auth_parameters"):
            return "C", ("setUserAuthenticationParameters used (API 30+) but its timeout argument "
                         "could not be read - a non-zero timeout makes this time-bound")
        if crypto:
            return "A", ("setUserAuthenticationRequired(true) with no validity window plus a "
                         "CryptoObject: per-use binding, the strong form")
        return "C", ("setUserAuthenticationRequired(true) found but no CryptoObject reference in "
                     "this file - the key may be bound while the prompt is not")

    if crypto and prompts:
        return "C", ("CryptoObject referenced but no setUserAuthenticationRequired(true) found: "
                     "the object may wrap a key the hardware never gates")

    if prompts:
        why = "prompt with no CryptoObject and no auth-bound key"
        if ff.has("success_sets_boolean"):
            why += "; onAuthenticationSucceeded sets a boolean"
        if ff.has("success_starts_activity"):
            why += "; onAuthenticationSucceeded navigates directly"
        return "D", why

    if ff.has("keygenparameterspec") and ff.has("auth_required_false"):
        return "D", "explicitly setUserAuthenticationRequired(false) on a KeyGenParameterSpec"

    return "C", "biometric-adjacent symbols only; not enough evidence to grade the path"


GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def walk(paths):
    for root in paths:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "build", ".gradle")]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in SOURCE_EXT:
                    yield os.path.join(dirpath, fn)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Grade an app's biometric implementation against CryptoObject binding.")
    ap.add_argument("paths", nargs="+", help="jadx output, smali tree, or source tree")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--show-evidence", action="store_true",
                    help="print the matching lines, capped at 5 per signal")
    ap.add_argument("--min-grade", default="A", choices=list("ABCDF"),
                    help="only report this grade or worse (default A = everything)")
    ap.add_argument("--include-library", action="store_true",
                    help="do not skip androidx.biometric's own sources (they always grade A)")
    ap.add_argument("--keep-comments", action="store_true",
                    help="do NOT strip comments before matching. Only useful to reproduce the "
                         "false-positive class documented above strip_comments().")
    args = ap.parse_args(argv)

    for p in args.paths:
        if not os.path.exists(p):
            print(f"error: no such path: {p}", file=sys.stderr)
            return 1

    threshold = GRADE_ORDER[args.min_grade]
    results = []
    scanned = 0
    skipped_library = 0

    for path in walk(args.paths):
        scanned += 1
        if not args.include_library and NOISE_PATH.search(path):
            skipped_library += 1
            continue
        ff = scan_file(path, keep_comments=args.keep_comments)
        if ff is None:
            continue
        g, why = grade(ff)
        if GRADE_ORDER[g] < threshold:
            continue
        results.append((g, why, ff))

    results.sort(key=lambda r: (-GRADE_ORDER[r[0]], r[2].path))

    if args.json:
        out = {
            "filesScanned": scanned,
            "librarySourcesSkipped": skipped_library,
            "results": [
                {
                    "path": ff.path,
                    "grade": g,
                    "rationale": why,
                    "signals": {k: [{"line": ln, "text": tx} for ln, tx in v]
                                for k, v in ff.hits.items()},
                    "validityValues": ff.validity_values,
                }
                for g, why, ff in results
            ],
        }
        print(json.dumps(out, indent=2))
        return 0

    print(f"scanned {scanned} files; {len(results)} carry biometric evidence")
    if skipped_library:
        print(f"skipped {skipped_library} library-path files "
              f"(they grade A structurally and mean nothing about the app)")
    print()

    if not results:
        print("No biometric implementation found.")
        print("That is a result, not an error - but confirm it. Reflection, native code and")
        print("a heavily obfuscated tree all produce this same empty output.")
        return 0

    counts = defaultdict(int)
    for g, _, _ in results:
        counts[g] += 1
    print("grade distribution: " + "  ".join(f"{g}={counts[g]}" for g in "ABCDF" if counts[g]))
    print()

    worst = max(results, key=lambda r: GRADE_ORDER[r[0]])[0]

    for g, why, ff in results:
        print(f"[{g}] {ff.path}")
        print(f"     {why}")
        if args.show_evidence:
            for sig in sorted(ff.hits):
                for ln, tx in ff.hits[sig]:
                    print(f"       {sig:34s} :{ln:<6d} {tx}")
        print()

    print("=" * 78)
    print(f"WORST GRADE IN TREE: {worst}")
    print("The worst grade is the finding. An app holding one grade-A key while shipping a")
    print("grade-D path is exactly as bypassable as an app with only the grade-D path.")
    print()
    print("Confirm every grade below A dynamically before reporting it:")
    print("  frida -U -n <package> -l hook-biometric-prompt.js     then  report()")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
