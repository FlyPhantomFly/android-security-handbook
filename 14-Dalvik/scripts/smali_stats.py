#!/usr/bin/env python3
"""
smali_stats.py -- instruction-frequency profile and obfuscation heuristics for a
                  decoded APK's Smali trees.

WHAT IT DOES
    Walks one or more .smali files or directories and builds a statistical
    profile of the bytecode:

      - every instruction, counted by mnemonic, validated against the complete
        Dalvik opcode set (README section 3.10.16)
      - aggregation into instruction FAMILIES (invoke, const, iget, branch, ...)
      - class / method / field counts, and the access-flag breakdown
      - debug-metadata presence (.line, .source, .local)
      - a small set of interpreted HEURISTICS: string-encryption, reflection,
        dynamic loading, native offloading, control-flow flattening, Kotlin
        content, and leftover release logging

WHY YOU WOULD RUN IT
    Because an instruction profile tells you what KIND of application you are
    holding before you read a single line of it. A normal app has a recognisable
    shape -- lots of invoke-virtual, lots of iget-object, a healthy number of
    const-string. An app with almost no const-string and an unusual concentration
    of xor-int and aget-byte is decrypting something, and you now know to go
    looking for the decryptor instead of reading 4,000 classes in order.

    The second reason is regression tracking. Run it on every release, keep the
    --json output, and "obfuscation was added between 4.2 and 4.3" becomes a
    fact you can show rather than an impression.

HOW TO RUN
    python3 smali_stats.py work/                        # whole decoded APK
    python3 smali_stats.py work/ --top 25               # top 25 mnemonics
    python3 smali_stats.py work/ --families             # family rollup only
    python3 smali_stats.py work/ --heuristics           # the interpretation
    python3 smali_stats.py work/ --json > profile.json
    python3 smali_stats.py work/smali/com/example/Foo.smali --top 40
    python3 smali_stats.py work/ --unknown              # list unrecognised mnemonics

    A decoded APK usually has SEVERAL trees. Pass the parent, or pass them all:
        apktool d -r app.apk -o work/
        python3 smali_stats.py work/                    # finds smali/, smali_classes2/, ...

REQUIREMENTS
    Python 3.8+. No third-party modules. Nothing is written to disk.

WHAT THIS WILL *NOT* TELL YOU
    - It will not tell you what the app DOES. It counts instructions; it does not
      follow control flow, resolve types, or build a call graph. Every heuristic
      below is a prompt to go and look, never a conclusion.
    - It will not find code that is not in the .smali files you gave it. Packed
      apps ship a stub; the real DEX exists only in memory. Dump it first
      (see 13-ART) and run this on the dump.
    - It will not see native code at all. A high native-method count means the
      logic left the DEX and this tool has stopped being useful -- switch to a
      native RE workflow.
    - Its thresholds are calibrated against ordinary Play Store applications and
      will produce false positives on very small apps, on libraries, and on
      generated code. Profile three or four apps you understand first, so you
      know what normal looks like on your corpus.
    - It does not decode instruction operands. "const-string appears 8,000 times"
      is not the same as knowing what those strings are -- use smali-hunt.sh.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# The complete Dalvik opcode mnemonic set.
# Verified against libdexfile/dex/dex_instruction_list.h in AOSP.
# README section 3.10.16 is the same data laid out for reading.
# ---------------------------------------------------------------------------

_BASE = ["add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"]
_FP = ["add", "sub", "mul", "div", "rem"]


def _binops():
    out = []
    for op in _BASE:
        out.append("%s-int" % op)
        out.append("%s-long" % op)
        out.append("%s-int/2addr" % op)
        out.append("%s-long/2addr" % op)
    for op in _FP:
        out.append("%s-float" % op)
        out.append("%s-double" % op)
        out.append("%s-float/2addr" % op)
        out.append("%s-double/2addr" % op)
    # /lit16 -- note rsub-int carries NO width suffix. That is not a typo here
    # and it is not a typo in the specification either. README 3.10.13.
    for op in ["add", "mul", "div", "rem", "and", "or", "xor"]:
        out.append("%s-int/lit16" % op)
    out.append("rsub-int")
    # /lit8 -- shifts exist here but not in /lit16
    for op in ["add", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"]:
        out.append("%s-int/lit8" % op)
    out.append("rsub-int/lit8")
    return out


def _typed(prefix, suffixes):
    return [prefix] + ["%s-%s" % (prefix, s) for s in suffixes]


_FIELD_SUFFIXES = ["wide", "object", "boolean", "byte", "char", "short"]

OPCODES = set(
    ["nop"]
    + ["move", "move/from16", "move/16",
       "move-wide", "move-wide/from16", "move-wide/16",
       "move-object", "move-object/from16", "move-object/16",
       "move-result", "move-result-wide", "move-result-object", "move-exception"]
    + ["return-void", "return", "return-wide", "return-object"]
    + ["const/4", "const/16", "const", "const/high16",
       "const-wide/16", "const-wide/32", "const-wide", "const-wide/high16",
       "const-string", "const-string/jumbo", "const-class"]
    + ["monitor-enter", "monitor-exit", "check-cast", "instance-of", "array-length"]
    + ["new-instance", "new-array", "filled-new-array", "filled-new-array/range",
       "fill-array-data"]
    + ["throw", "goto", "goto/16", "goto/32", "packed-switch", "sparse-switch"]
    + ["cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long"]
    + ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"]
    + ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"]
    + _typed("aget", _FIELD_SUFFIXES) + _typed("aput", _FIELD_SUFFIXES)
    + _typed("iget", _FIELD_SUFFIXES) + _typed("iput", _FIELD_SUFFIXES)
    + _typed("sget", _FIELD_SUFFIXES) + _typed("sput", _FIELD_SUFFIXES)
    + ["invoke-virtual", "invoke-super", "invoke-direct", "invoke-static",
       "invoke-interface",
       "invoke-virtual/range", "invoke-super/range", "invoke-direct/range",
       "invoke-static/range", "invoke-interface/range"]
    + ["neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
       "int-to-long", "int-to-float", "int-to-double",
       "long-to-int", "long-to-float", "long-to-double",
       "float-to-int", "float-to-long", "float-to-double",
       "double-to-int", "double-to-long", "double-to-float",
       "int-to-byte", "int-to-char", "int-to-short"]
    + _binops()
    + ["invoke-polymorphic", "invoke-polymorphic/range",
       "invoke-custom", "invoke-custom/range",
       "const-method-handle", "const-method-type"]
)

# Quickened forms -- ART, Android 8.0 to 10 only. Their presence means the DEX
# came out of a VDEX and needs unquickening. README 3.10.15.
QUICKENED = set(
    ["iget-quick", "iget-wide-quick", "iget-object-quick",
     "iput-quick", "iput-wide-quick", "iput-object-quick",
     "invoke-virtual-quick", "invoke-virtual/range-quick",
     "iput-boolean-quick", "iput-byte-quick", "iput-char-quick", "iput-short-quick",
     "iget-boolean-quick", "iget-byte-quick", "iget-char-quick", "iget-short-quick",
     "invoke-super-quick", "invoke-super/range-quick",
     "execute-inline", "execute-inline/range"]
)

FAMILIES = [
    ("invoke", lambda m: m.startswith("invoke-")),
    ("const", lambda m: m.startswith("const")),
    ("move", lambda m: m.startswith("move")),
    ("return", lambda m: m.startswith("return")),
    ("iget/iput", lambda m: m.startswith("iget") or m.startswith("iput")),
    ("sget/sput", lambda m: m.startswith("sget") or m.startswith("sput")),
    ("aget/aput", lambda m: m.startswith("aget") or m.startswith("aput")),
    ("branch", lambda m: m.startswith("if-") or m.startswith("goto")),
    ("switch", lambda m: m.endswith("-switch")),
    ("compare", lambda m: m.startswith("cmp")),
    ("arith", lambda m: re.match(r"^(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr|neg|not|rsub)-", m)),
    ("convert", lambda m: re.match(r"^(int|long|float|double)-to-", m)),
    ("alloc", lambda m: m.startswith("new-") or m.startswith("filled-new-array")
     or m == "fill-array-data"),
    ("typecheck", lambda m: m in ("check-cast", "instance-of", "array-length")),
    ("monitor", lambda m: m.startswith("monitor-")),
    ("throw", lambda m: m == "throw"),
    ("nop", lambda m: m == "nop"),
]

# Directive blocks whose bodies are data, not instructions. Everything between
# the opener and the matching .end is skipped.
BLOCK_OPENERS = {
    ".array-data": ".end array-data",
    ".packed-switch": ".end packed-switch",
    ".sparse-switch": ".end sparse-switch",
    ".annotation": ".end annotation",
    ".subannotation": ".end subannotation",
    ".field": ".end field",          # only when the field carries annotations
    ".param": ".end param",          # only when the param carries annotations
}

ACCESS_KEYWORDS = [
    "public", "private", "protected", "static", "final", "synchronized",
    "volatile", "bridge", "transient", "varargs", "native", "interface",
    "abstract", "strictfp", "synthetic", "annotation", "enum", "constructor",
    "declared-synchronized",
]

REFLECTION_MARKERS = (
    "Ljava/lang/Class;->forName",
    "->getDeclaredMethod",
    "->getDeclaredField",
    "->getMethod(",
    "Ljava/lang/reflect/Method;->invoke",
    "Ljava/lang/reflect/Field;->",
    "->setAccessible",
)

LOADER_MARKERS = (
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
    "Ldalvik/system/DelegateLastClassLoader;",
    "Ldalvik/system/BaseDexClassLoader;",
    "Ljava/lang/System;->load",
    "Ljava/lang/Runtime;->load",
)

CRYPTO_MARKERS = (
    "Ljavax/crypto/Cipher;->getInstance",
    "Ljavax/crypto/spec/SecretKeySpec;-><init>",
    "Ljava/security/MessageDigest;->getInstance",
    "Ljavax/crypto/Mac;->getInstance",
)

KOTLIN_MARKER = "Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter"


class Profile(object):
    def __init__(self):
        self.files = 0
        self.classes = 0
        self.methods = 0
        self.abstract_or_native_methods = 0
        self.fields = 0
        self.instructions = 0
        self.mnemonics = Counter()
        self.unknown = Counter()
        self.quickened = Counter()
        self.method_flags = Counter()
        self.class_flags = Counter()
        self.line_directives = 0
        self.source_directives = 0
        self.local_directives = 0
        self.runtime_annotations = 0
        self.reflection_hits = 0
        self.loader_hits = 0
        self.crypto_hits = 0
        self.kotlin_hits = 0
        self.log_calls = 0
        self.biggest_method = ("", 0)
        self.switch_case_max = 0

    def as_dict(self, top=20):
        fam = self.family_counts()
        return {
            "files": self.files,
            "classes": self.classes,
            "methods": self.methods,
            "methods_without_body": self.abstract_or_native_methods,
            "fields": self.fields,
            "instructions": self.instructions,
            "distinct_mnemonics": len(self.mnemonics),
            "top_mnemonics": self.mnemonics.most_common(top),
            "families": fam,
            "unknown_mnemonics": self.unknown.most_common(top),
            "quickened_mnemonics": self.quickened.most_common(top),
            "method_flags": dict(self.method_flags),
            "class_flags": dict(self.class_flags),
            "debug": {
                "line_directives": self.line_directives,
                "source_directives": self.source_directives,
                "local_directives": self.local_directives,
            },
            "markers": {
                "runtime_annotations": self.runtime_annotations,
                "reflection": self.reflection_hits,
                "class_loaders": self.loader_hits,
                "crypto": self.crypto_hits,
                "kotlin_intrinsics": self.kotlin_hits,
                "log_calls": self.log_calls,
            },
            "biggest_method": {
                "name": self.biggest_method[0],
                "instructions": self.biggest_method[1],
            },
            "largest_switch_cases": self.switch_case_max,
            "rates_per_1000_instructions": self.rates(),
        }

    def family_counts(self):
        out = {}
        for name, pred in FAMILIES:
            out[name] = 0
        for m, n in self.mnemonics.items():
            for name, pred in FAMILIES:
                if pred(m):
                    out[name] += n
                    break
        return out

    def rates(self):
        if not self.instructions:
            return {}
        scale = 1000.0 / self.instructions

        def r(x):
            return round(x * scale, 2)

        return {
            "const-string": r(self.mnemonics["const-string"]
                              + self.mnemonics["const-string/jumbo"]),
            "invoke-virtual": r(self.mnemonics["invoke-virtual"]),
            "invoke-static": r(self.mnemonics["invoke-static"]),
            "iget-object": r(self.mnemonics["iget-object"]),
            "goto": r(self.mnemonics["goto"] + self.mnemonics["goto/16"]
                      + self.mnemonics["goto/32"]),
            "xor-int-any": r(sum(v for k, v in self.mnemonics.items()
                                 if k.startswith("xor-int"))),
            "aget-byte": r(self.mnemonics["aget-byte"]),
            "fill-array-data": r(self.mnemonics["fill-array-data"]),
            "packed-switch": r(self.mnemonics["packed-switch"]),
        }


def strip_comment(line):
    """Remove a trailing # comment, respecting double-quoted string literals."""
    out = []
    in_str = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
                out.append(c)
            elif c == "#":
                break
            else:
                out.append(c)
        i += 1
    return "".join(out)


def parse_file(path, prof):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().split("\n")
    except OSError as exc:
        sys.stderr.write("cannot read %s: %s\n" % (path, exc))
        return

    prof.files += 1
    skip_until = None
    current_method = None
    current_count = 0
    switch_cases = 0
    in_switch_payload = False

    for raw in lines:
        line = strip_comment(raw).strip()
        if not line:
            continue

        if skip_until is not None:
            if line.startswith(skip_until):
                skip_until = None
                if in_switch_payload:
                    prof.switch_case_max = max(prof.switch_case_max, switch_cases)
                    in_switch_payload = False
                    switch_cases = 0
            elif in_switch_payload:
                switch_cases += 1
            continue

        if line.startswith(":"):
            continue

        if line.startswith("."):
            head = line.split()[0]
            if head == ".class":
                prof.classes += 1
                for kw in line.split()[1:]:
                    if kw in ACCESS_KEYWORDS:
                        prof.class_flags[kw] += 1
            elif head == ".source":
                prof.source_directives += 1
            elif head == ".line":
                prof.line_directives += 1
            elif head == ".local" or head == ".restart":
                prof.local_directives += 1
            elif head == ".method":
                prof.methods += 1
                current_method = line
                current_count = 0
                for kw in line.split()[1:]:
                    if kw in ACCESS_KEYWORDS:
                        prof.method_flags[kw] += 1
                if " native " in line + " " or " abstract " in line + " ":
                    prof.abstract_or_native_methods += 1
            elif head == ".end" and line.startswith(".end method"):
                if current_method and current_count > prof.biggest_method[1]:
                    prof.biggest_method = (
                        "%s :: %s" % (os.path.basename(path),
                                      current_method[len(".method "):]),
                        current_count,
                    )
                current_method = None
                current_count = 0
            elif head == ".annotation":
                if " runtime " in line + " ":
                    prof.runtime_annotations += 1

            if head in BLOCK_OPENERS:
                # A .field or .param line only opens a block when annotations
                # follow; both forms are terminated by their own .end, and a
                # one-line .field simply never matches, so guard on that.
                if head in (".field", ".param"):
                    continue
                skip_until = BLOCK_OPENERS[head]
                if head in (".packed-switch", ".sparse-switch"):
                    in_switch_payload = True
                    switch_cases = 0
            continue

        # Anything else is an instruction line.
        mnemonic = line.split()[0].rstrip(",")
        prof.instructions += 1
        current_count += 1
        if mnemonic in OPCODES:
            prof.mnemonics[mnemonic] += 1
        elif mnemonic in QUICKENED:
            prof.quickened[mnemonic] += 1
            prof.mnemonics[mnemonic] += 1
        else:
            prof.unknown[mnemonic] += 1

        if "Landroid/util/Log;->" in line:
            prof.log_calls += 1
        for marker in REFLECTION_MARKERS:
            if marker in line:
                prof.reflection_hits += 1
                break
        for marker in LOADER_MARKERS:
            if marker in line:
                prof.loader_hits += 1
                break
        for marker in CRYPTO_MARKERS:
            if marker in line:
                prof.crypto_hits += 1
                break
        if KOTLIN_MARKER in line:
            prof.kotlin_hits += 1


def collect(paths):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs.sort()
                for n in sorted(names):
                    if n.endswith(".smali"):
                        files.append(os.path.join(root, n))
        else:
            sys.stderr.write("no such path: %s\n" % p)
    return files


# ---------------------------------------------------------------------------
# Heuristics. Every one of these is a PROMPT, not a verdict. README 8.3.
# ---------------------------------------------------------------------------

def heuristics(prof):
    findings = []
    if prof.instructions == 0:
        return [("ERROR", "no instructions parsed -- wrong path, or an empty tree")]

    r = prof.rates()
    per_method = prof.instructions / max(prof.methods, 1)

    cs = r.get("const-string", 0.0)
    if cs < 5.0:
        findings.append((
            "STRING ENCRYPTION",
            "const-string density is %.2f per 1000 instructions (ordinary apps sit "
            "roughly 15-40). The constants have probably been moved into "
            "fill-array-data payloads or resources and are decrypted at runtime. "
            "Look for a static method taking [B or String and returning String that "
            "is called from everywhere." % cs))
    elif cs > 60.0:
        findings.append((
            "STRING-HEAVY",
            "const-string density is %.2f per 1000 instructions, unusually high. "
            "Often a config/resource-generated class, a large protocol parser, or "
            "logging left in. Run smali-hunt.sh and read the ranked string list." % cs))

    if prof.quickened:
        findings.append((
            "QUICKENED BYTECODE",
            "%d quickened instructions found (%s). This DEX came from a VDEX on an "
            "Android 8-10 device. baksmali cannot render it symbolically -- unquicken "
            "it first (vdexExtractor) or pass --allow-odex-opcodes."
            % (sum(prof.quickened.values()),
               ", ".join(sorted(prof.quickened))[:120])))

    if prof.unknown:
        top = ", ".join("%s(%d)" % (k, v) for k, v in prof.unknown.most_common(5))
        findings.append((
            "UNRECOGNISED MNEMONICS",
            "%d instruction lines used a mnemonic not in the Dalvik opcode set: %s. "
            "Either the parser met a construct it does not model, or the file is not "
            "baksmali output. Run with --unknown to see them all."
            % (sum(prof.unknown.values()), top)))

    nat = prof.method_flags.get("native", 0)
    if nat > 0:
        share = 100.0 * nat / max(prof.methods, 1)
        level = "NATIVE OFFLOADING" if share > 1.0 else "NATIVE SURFACE"
        findings.append((
            level,
            "%d native methods (%.2f%% of all methods). That much logic has left the "
            "DEX and this tool cannot see it. The JNI boundary is your chokepoint; "
            "switch to a native RE workflow for the .so." % (nat, share)))

    if prof.reflection_hits > 0:
        rate = 1000.0 * prof.reflection_hits / prof.instructions
        if rate > 1.0:
            findings.append((
                "REFLECTION",
                "%d reflection call sites (%.2f per 1000 instructions). Call targets "
                "are resolved from strings at runtime, so the method_ids table does "
                "not name them. Hook getDeclaredMethod to recover them."
                % (prof.reflection_hits, rate)))

    if prof.loader_hits > 0:
        findings.append((
            "DYNAMIC CODE LOADING",
            "%d references to a ClassLoader or System.load. Code may be loaded that "
            "is not in these .smali files at all. Confirm what is actually loaded at "
            "runtime before concluding anything from a static read."
            % prof.loader_hits))

    if prof.crypto_hits > 0:
        findings.append((
            "CRYPTO IN USE",
            "%d Cipher/MessageDigest/Mac setup sites. Read the const-string argument "
            "at each one -- it names the algorithm and mode, and 'AES/ECB/' or a "
            "hardcoded IV is a finding on its own." % prof.crypto_hits))

    fad = prof.mnemonics.get("fill-array-data", 0)
    if fad > 0:
        findings.append((
            "ARRAY LITERALS",
            "%d fill-array-data instructions. This is where hardcoded byte arrays "
            "live -- including key material, which `strings` cannot find because it "
            "is not text. Inspect every .array-data payload of width 1." % fad))

    goto_rate = r.get("goto", 0.0)
    if goto_rate > 40.0:
        findings.append((
            "HIGH BRANCH DENSITY",
            "goto density is %.2f per 1000 instructions. Combined with a large "
            "packed-switch this is the signature of control-flow flattening."
            % goto_rate))

    if prof.switch_case_max >= 40:
        findings.append((
            "LARGE SWITCH",
            "the largest switch payload has %d cases. A very large switch inside a "
            "while(true) loop, with each case assigning the switch variable, is "
            "control-flow flattening. It can also be a Kotlin coroutine state "
            "machine -- check for a Continuation parameter before calling it "
            "obfuscation." % prof.switch_case_max))

    if prof.biggest_method[1] > 2000:
        findings.append((
            "OUTSIZED METHOD",
            "the largest method holds %d instructions (%s). Hand-written methods are "
            "rarely this big; generated code, flattened control flow and merged "
            "classes are."
            % (prof.biggest_method[1], prof.biggest_method[0][:100])))

    if prof.kotlin_hits > 0:
        findings.append((
            "KOTLIN",
            "%d Intrinsics.checkNotNullParameter call sites, so a substantial part of "
            "this app is Kotlin. Expect coroutine state machines, INSTANCE fields, "
            "Companion classes and $default bridge methods -- none of which are "
            "obfuscation." % prof.kotlin_hits))

    if prof.line_directives > 0 and prof.instructions > 20000:
        density = 1000.0 * prof.line_directives / prof.instructions
        if density > 20.0:
            findings.append((
                "DEBUG INFO RETAINED",
                ".line directives at %.1f per 1000 instructions. A release build "
                "normally strips these. Their presence leaks source structure and "
                "line numbers, and is reportable under MASVS-CODE." % density))

    if prof.log_calls > 0:
        rate = 1000.0 * prof.log_calls / prof.instructions
        if rate > 2.0:
            findings.append((
                "RELEASE LOGGING",
                "%d android.util.Log call sites (%.2f per 1000 instructions). Read "
                "what they log -- tokens and PII in logcat are a recurring finding."
                % (prof.log_calls, rate)))

    syn = prof.method_flags.get("synthetic", 0)
    if syn and prof.methods:
        share = 100.0 * syn / prof.methods
        if share > 25.0:
            findings.append((
                "HIGH SYNTHETIC RATIO",
                "%.1f%% of methods are synthetic. Heavy lambda/desugaring use, or an "
                "obfuscator that generated wrappers. Filter them out before reading: "
                "they are almost never where the interesting logic is." % share))

    if per_method < 4.0:
        findings.append((
            "TRIVIAL METHODS DOMINATE",
            "%.1f instructions per method on average. Typical of generated model "
            "classes, or of an obfuscator that split methods apart." % per_method))

    if not findings:
        findings.append((
            "NOTHING FLAGGED",
            "the profile looks like an ordinary application. That is a statement "
            "about statistics, not about security -- go and read the code."))
    return findings


def render(prof, args):
    w = sys.stdout.write
    d = prof.as_dict(top=args.top)

    if args.json:
        w(json.dumps(d, indent=2, sort_keys=True) + "\n")
        return

    if args.unknown:
        if not prof.unknown:
            w("No unrecognised mnemonics.\n")
        else:
            w("Unrecognised mnemonics (count, token):\n")
            for m, n in prof.unknown.most_common():
                w("  %8d  %s\n" % (n, m))
        return

    w("=" * 72 + "\n")
    w("SMALI PROFILE\n")
    w("=" * 72 + "\n")
    w("  files                %d\n" % prof.files)
    w("  classes              %d\n" % prof.classes)
    w("  methods              %d  (%d with no body: native or abstract)\n"
      % (prof.methods, prof.abstract_or_native_methods))
    w("  instructions         %d\n" % prof.instructions)
    w("  distinct mnemonics   %d of %d possible\n"
      % (len(prof.mnemonics), len(OPCODES)))
    if prof.methods:
        w("  instructions/method  %.1f\n" % (prof.instructions / prof.methods))
    w("\n")

    if not args.families:
        w("TOP %d MNEMONICS\n" % args.top)
        w("-" * 72 + "\n")
        for m, n in prof.mnemonics.most_common(args.top):
            share = 100.0 * n / max(prof.instructions, 1)
            bar = "#" * int(share * 1.5)
            w("  %-28s %9d  %5.2f%%  %s\n" % (m, n, share, bar))
        w("\n")

    w("FAMILIES\n")
    w("-" * 72 + "\n")
    fam = d["families"]
    for name in sorted(fam, key=lambda k: -fam[k]):
        if fam[name] == 0:
            continue
        share = 100.0 * fam[name] / max(prof.instructions, 1)
        w("  %-14s %9d  %5.2f%%\n" % (name, fam[name], share))
    w("\n")

    w("RATES per 1000 instructions\n")
    w("-" * 72 + "\n")
    for k, v in sorted(d["rates_per_1000_instructions"].items()):
        w("  %-20s %8.2f\n" % (k, v))
    w("\n")

    w("MARKERS\n")
    w("-" * 72 + "\n")
    for k, v in sorted(d["markers"].items()):
        w("  %-22s %8d\n" % (k, v))
    w("  %-22s %8d\n" % ("native methods", prof.method_flags.get("native", 0)))
    w("  %-22s %8d\n" % ("synthetic methods", prof.method_flags.get("synthetic", 0)))
    w("  %-22s %8d\n" % (".line directives", prof.line_directives))
    w("  %-22s %8d\n" % (".source directives", prof.source_directives))
    w("\n")

    if prof.quickened:
        w("QUICKENED INSTRUCTIONS PRESENT -- this DEX needs unquickening\n")
        for m, n in prof.quickened.most_common():
            w("  %-28s %9d\n" % (m, n))
        w("\n")

    if prof.unknown:
        w("UNRECOGNISED MNEMONICS (top 10; run --unknown for all)\n")
        for m, n in prof.unknown.most_common(10):
            w("  %-28s %9d\n" % (m, n))
        w("\n")

    if args.heuristics:
        w("=" * 72 + "\n")
        w("HEURISTICS -- prompts to investigate, never conclusions\n")
        w("=" * 72 + "\n")
        for tag, text in heuristics(prof):
            w("\n[%s]\n" % tag)
            for chunk in wrap(text, 70):
                w("    %s\n" % chunk)
        w("\n")


def wrap(text, width):
    words = text.split()
    line = ""
    out = []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = word if not line else line + " " + word
    if line:
        out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Instruction-frequency profile for Smali trees.",
        epilog="Every heuristic is a prompt to investigate, not a finding.")
    ap.add_argument("paths", nargs="+",
                    help="one or more .smali files or directories")
    ap.add_argument("--top", type=int, default=20,
                    help="how many mnemonics to list (default 20)")
    ap.add_argument("--families", action="store_true",
                    help="family rollup only, no per-mnemonic table")
    ap.add_argument("--heuristics", action="store_true",
                    help="print the interpreted findings")
    ap.add_argument("--unknown", action="store_true",
                    help="list unrecognised mnemonics and exit")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    args = ap.parse_args()

    files = collect(args.paths)
    if not files:
        sys.stderr.write("no .smali files found under: %s\n" % ", ".join(args.paths))
        return 2

    prof = Profile()
    for f in files:
        parse_file(f, prof)

    render(prof, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
