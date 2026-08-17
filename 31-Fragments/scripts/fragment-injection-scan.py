#!/usr/bin/env python3
"""
scripts/fragment-injection-scan.py

PURPOSE
    Find reflective Fragment instantiation driven by attacker-controllable input
    inside application APKs, and separate the small number of real leads from
    the much larger number of structural coincidences.

    The question this answers is not "does this app use Fragments" -- every app
    does -- but the much narrower:

        Is there a METHOD in this app that reads a value out of an Intent, a
        Uri or a Bundle, AND, in the same method, hands a class name to a
        reflective Fragment loader?

    That co-occurrence, at method granularity, is the fragment injection shape.
    A hit is still a LEAD and not a finding; see LIMITS.

WHY THIS PARSES DEX INSTEAD OF GREPPING
    52-StaticAnalysis measured 16,836 raw grep hits collapsing to 168 leads, of
    which 15 of the top 17 were rejected by hand.  64-Xposed measured 1,141 raw
    hits resolving to exactly 0 findings.  33-Storage measured 132 hits and 132
    false positives.  The repository's standing rule came out of those three:
    a signature is not evidence until every hit is accounted for.

    A byte-level grep for "instantiate" or ":android:show_fragment" cannot tell
    you WHERE in the app the string lives, so it cannot tell you whether the
    class name is a constant the developer wrote or a value a stranger sent.
    This script therefore walks the DEX structures -- string_ids, type_ids,
    method_ids, class_defs, class_data and the instruction stream -- and reports
    per method.  It costs about 100 extra lines and removes an entire class of
    false positive.

USAGE
    python3 -B fragment-injection-scan.py APK...
    python3 -B fragment-injection-scan.py CORPUS_DIR --recursive
    python3 -B fragment-injection-scan.py CORPUS_DIR --recursive --json
    python3 -B fragment-injection-scan.py app.apk --verbose
    python3 -B fragment-injection-scan.py CORPUS_DIR --recursive --summary

    Options:
      --recursive   Walk a directory for *.apk
      --json        Machine readable, one object per APK
      --verbose     Print every class and method that matched, not just counts
      --summary     Print corpus totals and the denominator, and nothing else
      --quiet       Only print APKs with at least one tier 1 finding

    Always run with -B.  This repository has had __pycache__ committed twice by
    scripts that trusted PYTHONDONTWRITEBYTECODE.

REQUIREMENTS
    Python 3.8+, standard library only.  No androguard, no aapt, no jadx, no
    device.  It reads APKs off disk, which is what you have when somebody hands
    you a corpus.

EXECUTION STATUS
    EXECUTED.  Run to completion on 2026-08-16 against 241 APKs pulled from the
    `sdk_gphone16k_x86_64` AVD (Android 15 / API 35) -- every package installed
    on a stock Android 15 GMS image that could be pulled.  Every number quoted
    in README section 8.4 came out of this script, including the denominator and
    the per-hit adjudication.  The corpus was deleted afterwards; rebuild it
    with scripts/pull-apk-corpus.sh.

    Validated before it was trusted: its instruction walker was checked against
    `dexdump -d` on this chapter's own victim APK, where the answer is known by
    construction, and it found exactly the four invoke sites that are there.

WHAT IT LOOKS FOR

    Tier 1  A single method that reads external input AND reflectively loads a
            Fragment.  This is the bug shape.
    Tier 2  A PreferenceActivity subclass whose isValidFragment override is
            suspiciously short, or absent.  The absent case matters differently
            depending on targetSdkVersion; see README section 3.9.
    Tier 3  Structural presence only: the app subclasses PreferenceActivity, or
            references :android:show_fragment, or calls a Fragment loader
            somewhere.  On its own this means nothing -- opening another app's
            settings screen uses the same extra.

LIMITS, STATED HONESTLY
    * R8 renames androidx.fragment.app.FragmentFactory and its methods.  In a
      minified app the tier 1 signature CANNOT fire through the AndroidX path,
      because there is no longer a method named `instantiate` on a class named
      `FragmentFactory`.  The platform path (android.app.Fragment.instantiate)
      survives minification, because the framework class is not renamed.  This
      is the single largest blind spot and it is not fixable from the DEX alone.
    * String encryption defeats the :android:show_fragment signature entirely.
    * Input that arrives through a helper -- `getIntent()` in one method, the
      loader in another -- is invisible to a per-method rule.  Widening to
      per-class trades a real drop in precision for a small gain in recall, and
      this script deliberately does not.
    * A method that matches is a LEAD.  Read it.

AUTHORISED TESTING ONLY.  Scan APKs you own or are authorised to assess.
"""

import argparse
import json
import os
import struct
import sys
import zipfile

# --------------------------------------------------------------------------- #
# DEX structural constants
# --------------------------------------------------------------------------- #

DEX_MAGICS = (b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00",
              b"dex\n038\x00", b"dex\n039\x00", b"dex\n040\x00",
              b"dex\n041\x00")

# Instruction size, in 16-bit code units, indexed by opcode byte.
# Built from the Dalvik format table.  The three payload pseudo-instructions
# (0x0100, 0x0200, 0x0300) are variable-length and handled separately.
def _build_widths():
    w = [1] * 256
    fixed = {
        0x02: 2, 0x03: 3, 0x05: 2, 0x06: 3, 0x08: 2, 0x09: 3,
        0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2,
        0x1a: 2, 0x1b: 3, 0x1c: 2, 0x1f: 2, 0x20: 2, 0x22: 2, 0x23: 2,
        0x24: 3, 0x25: 3, 0x26: 3, 0x29: 2, 0x2a: 3, 0x2b: 3, 0x2c: 3,
        0xfa: 4, 0xfb: 4, 0xfc: 3, 0xfd: 3, 0xfe: 2, 0xff: 2,
    }
    for op in range(0x2d, 0x32):      # cmp*
        fixed[op] = 2
    for op in range(0x32, 0x3e):      # if-* / if-*z
        fixed[op] = 2
    for op in range(0x44, 0x52):      # aget / aput
        fixed[op] = 2
    for op in range(0x52, 0x60):      # iget / iput
        fixed[op] = 2
    for op in range(0x60, 0x6e):      # sget / sput
        fixed[op] = 2
    for op in range(0x6e, 0x73):      # invoke-*
        fixed[op] = 3
    for op in range(0x74, 0x79):      # invoke-*/range
        fixed[op] = 3
    for op in range(0x90, 0xb0):      # binop
        fixed[op] = 2
    for op in range(0xd0, 0xe3):      # binop/lit16 and /lit8
        fixed[op] = 2
    for op, n in fixed.items():
        w[op] = n
    return w

WIDTHS = _build_widths()

INVOKE_OPS = set(range(0x6e, 0x73)) | set(range(0x74, 0x79))


def uleb128(buf, off):
    """Read an unsigned LEB128. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 too long")


class Dex:
    """Just enough of a DEX reader for this script. Nothing here is generic."""

    def __init__(self, data):
        self.d = data
        if data[:8] not in DEX_MAGICS:
            raise ValueError("not a dex")
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from(
            "<12I", data, 56)
        self._strings = {}
        self._types = {}

    def string(self, idx):
        s = self._strings.get(idx)
        if s is not None:
            return s
        off = struct.unpack_from("<I", self.d, self.string_ids_off + idx * 4)[0]
        _, off = uleb128(self.d, off)          # utf16 length, not byte length
        end = self.d.index(b"\x00", off)
        # MUTF-8. Ordinary ASCII identifiers decode identically; surrogate pairs
        # and embedded NUL do not, and are irrelevant to every signature here.
        s = self.d[off:end].decode("utf-8", "replace")
        self._strings[idx] = s
        return s

    def type(self, idx):
        t = self._types.get(idx)
        if t is None:
            t = self.string(struct.unpack_from(
                "<I", self.d, self.type_ids_off + idx * 4)[0])
            self._types[idx] = t
        return t

    def method(self, idx):
        """Return (class_descriptor, method_name)."""
        cls_idx, _proto, name_idx = struct.unpack_from(
            "<HHI", self.d, self.method_ids_off + idx * 8)
        return self.type(cls_idx), self.string(name_idx)

    def class_defs(self):
        for i in range(self.class_defs_size):
            base = self.class_defs_off + i * 32
            (class_idx, access, super_idx, _iface, _src,
             _anno, data_off, _static) = struct.unpack_from("<8I", self.d, base)
            yield {
                "name": self.type(class_idx),
                "access": access,
                "super": self.type(super_idx) if super_idx != 0xFFFFFFFF else None,
                "data_off": data_off,
            }

    def methods_of(self, data_off):
        """Yield (method_idx, access_flags, code_off) for one class_data_item."""
        if not data_off:
            return
        off = data_off
        sf, off = uleb128(self.d, off)
        inf, off = uleb128(self.d, off)
        dm, off = uleb128(self.d, off)
        vm, off = uleb128(self.d, off)
        for _ in range(sf):
            _, off = uleb128(self.d, off)
            _, off = uleb128(self.d, off)
        for _ in range(inf):
            _, off = uleb128(self.d, off)
            _, off = uleb128(self.d, off)
        for count in (dm, vm):
            idx = 0
            for _ in range(count):
                diff, off = uleb128(self.d, off)
                access, off = uleb128(self.d, off)
                code_off, off = uleb128(self.d, off)
                idx += diff
                yield idx, access, code_off

    def invoked_methods(self, code_off):
        """Every method_idx invoked by one code item, plus its size in units."""
        if not code_off:
            return [], 0
        _regs, _ins, _outs, _tries, _debug, insns_size = struct.unpack_from(
            "<HHHHII", self.d, code_off)
        start = code_off + 16
        out = []
        pc = 0
        d = self.d
        while pc < insns_size:
            unit = struct.unpack_from("<H", d, start + pc * 2)[0]
            op = unit & 0xFF
            if op == 0x00 and unit != 0x0000:
                ident = unit >> 8
                if ident == 1:      # packed-switch-payload
                    size = struct.unpack_from("<H", d, start + (pc + 1) * 2)[0]
                    step = 4 + size * 2
                elif ident == 2:    # sparse-switch-payload
                    size = struct.unpack_from("<H", d, start + (pc + 1) * 2)[0]
                    step = 2 + size * 4
                elif ident == 3:    # fill-array-data-payload
                    width = struct.unpack_from("<H", d, start + (pc + 1) * 2)[0]
                    n = struct.unpack_from("<I", d, start + (pc + 2) * 2)[0]
                    step = 4 + (n * width + 1) // 2
                else:
                    step = 1
                pc += step
                continue
            if op in INVOKE_OPS:
                out.append(struct.unpack_from("<H", d, start + (pc + 1) * 2)[0])
            step = WIDTHS[op]
            if step <= 0:
                break
            pc += step
        return out, insns_size


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #

# Reflective Fragment loaders. Class descriptor -> set of method names.
SINKS = {
    "Landroid/app/Fragment;": {"instantiate"},
    "Landroidx/fragment/app/Fragment;": {"instantiate"},
    "Landroidx/fragment/app/FragmentFactory;": {"instantiate", "loadFragmentClass"},
    "Landroid/support/v4/app/Fragment;": {"instantiate"},
    "Landroid/support/v4/app/FragmentFactory;": {"instantiate", "loadFragmentClass"},
    # The generic reflective route. A Fragment host that builds the object
    # itself rather than asking the framework hits these instead.
    "Ljava/lang/ClassLoader;": {"loadClass"},
    "Ljava/lang/Class;": {"forName", "newInstance"},
}

# Reads of attacker-controllable input.
SOURCES = {
    "Landroid/content/Intent;": {
        "getStringExtra", "getBundleExtra", "getExtras", "getData",
        "getCharSequenceExtra", "getSerializableExtra", "getParcelableExtra",
        "getDataString",
    },
    "Landroid/os/Bundle;": {"getString", "getBundle", "getCharSequence"},
    "Landroid/net/Uri;": {
        "getQueryParameter", "getLastPathSegment", "getPath",
        "getPathSegments", "getFragment",
    },
}

PREFERENCE_ACTIVITY = "Landroid/preference/PreferenceActivity;"
SHOW_FRAGMENT_EXTRA = ":android:show_fragment"


def classify(name, table):
    return table.get(name)


def scan_dex(data, report):
    dex = Dex(data)

    # -- cheap pass 1: is the interesting extra a constant anywhere in here?
    for i in range(dex.string_ids_size):
        s = dex.string(i)
        if s == SHOW_FRAGMENT_EXTRA:
            report["show_fragment_extra"] = True
            break

    # -- pass 2: which method_ids are sources and which are sinks
    src_idx = {}
    sink_idx = {}
    for i in range(dex.method_ids_size):
        cls, name = dex.method(i)
        t = SOURCES.get(cls)
        if t and name in t:
            src_idx[i] = cls + "->" + name
            continue
        t = SINKS.get(cls)
        if t and name in t:
            sink_idx[i] = cls + "->" + name

    # -- pass 3: classes and methods
    for cd in dex.class_defs():
        is_pref = cd["super"] == PREFERENCE_ACTIVITY
        if is_pref:
            report["preference_activities"].append(cd["name"])

        found_isvalid = False
        for midx, _access, code_off in dex.methods_of(cd["data_off"]):
            cls, mname = dex.method(midx)
            if mname == "isValidFragment":
                found_isvalid = True
                invoked, size = dex.invoked_methods(code_off)
                report["isvalid_overrides"].append({
                    "class": cd["name"],
                    "insns": size,
                    "calls": sorted({"%s->%s" % dex.method(m) for m in invoked}),
                })
            if not code_off:
                continue
            invoked, _size = dex.invoked_methods(code_off)
            if not invoked:
                continue
            hits_sink = sorted({sink_idx[m] for m in invoked if m in sink_idx})
            if not hits_sink:
                continue
            hits_src = sorted({src_idx[m] for m in invoked if m in src_idx})
            frag_sink = [h for h in hits_sink
                         if "Fragment" in h or "FragmentFactory" in h]
            entry = {
                "method": "%s->%s" % (cd["name"], mname),
                "sinks": hits_sink,
                "sources": hits_src,
            }
            if hits_src and frag_sink:
                report["tier1"].append(entry)
            elif frag_sink:
                report["fragment_loader_calls"].append(entry)
            elif hits_src:
                report["reflection_from_input"].append(entry)

        if is_pref and not found_isvalid:
            report["preference_no_override"].append(cd["name"])


def scan_apk(path):
    report = {
        "apk": os.path.basename(path),
        "dex_count": 0,
        "dex_stored": 0,
        "dex_deflated": 0,
        "show_fragment_extra": False,
        "preference_activities": [],
        "preference_no_override": [],
        "isvalid_overrides": [],
        "tier1": [],
        "fragment_loader_calls": [],
        "reflection_from_input": [],
        "errors": [],
    }
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:                                # noqa: BLE001
        report["errors"].append("zip: %s" % e)
        return report
    with z:
        for info in z.infolist():
            n = info.filename
            if not (n.startswith("classes") and n.endswith(".dex")):
                continue
            report["dex_count"] += 1
            if info.compress_type == zipfile.ZIP_STORED:
                report["dex_stored"] += 1
            else:
                report["dex_deflated"] += 1
            try:
                scan_dex(z.read(n), report)
            except Exception as e:                        # noqa: BLE001
                report["errors"].append("%s: %s" % (n, e))
    return report


def tier(report):
    if report["tier1"]:
        return 1
    if report["preference_no_override"] or report["isvalid_overrides"]:
        return 2
    if (report["preference_activities"] or report["show_fragment_extra"]
            or report["fragment_loader_calls"]):
        return 3
    return 0


def print_report(r, verbose):
    t = tier(r)
    if t == 0:
        return
    print("%-58s tier %d  dex=%d(%dS/%dD)" % (
        r["apk"][:58], t, r["dex_count"], r["dex_stored"], r["dex_deflated"]))
    if r["tier1"]:
        print("   TIER 1  external input reaches a Fragment loader in one method:")
        for e in r["tier1"]:
            print("      %s" % e["method"])
            print("         sources: %s" % ", ".join(e["sources"]))
            print("         sinks  : %s" % ", ".join(e["sinks"]))
    for c in r["preference_no_override"]:
        print("   TIER 2  PreferenceActivity subclass with NO isValidFragment: %s" % c)
    for o in r["isvalid_overrides"]:
        flag = "  <-- body is tiny, check it" if o["insns"] <= 8 else ""
        print("   TIER 2  isValidFragment override in %s (%d code units)%s"
              % (o["class"], o["insns"], flag))
        if verbose and o["calls"]:
            for c in o["calls"]:
                print("            calls %s" % c)
    if verbose:
        if r["show_fragment_extra"]:
            print("   TIER 3  the string %s is in the constant pool" % SHOW_FRAGMENT_EXTRA)
        for c in r["preference_activities"]:
            print("   TIER 3  PreferenceActivity subclass: %s" % c)
        for e in r["fragment_loader_calls"]:
            print("   TIER 3  Fragment loader call, no external input in the same "
                  "method: %s" % e["method"])
    for e in r["errors"]:
        print("   ERROR   %s" % e)


def main():
    ap = argparse.ArgumentParser(
        description="Find reflective Fragment instantiation from external input.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    apks = []
    for p in args.paths:
        if os.path.isdir(p):
            if not args.recursive:
                print("%s is a directory; pass --recursive" % p, file=sys.stderr)
                return 2
            for root, _dirs, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith(".apk"):
                        apks.append(os.path.join(root, f))
        else:
            apks.append(p)

    reports = []
    for a in apks:
        r = scan_apk(a)
        reports.append(r)
        if args.json or args.summary:
            continue
        if args.quiet and tier(r) != 1:
            continue
        print_report(r, args.verbose)

    if args.json:
        json.dump(reports, sys.stdout, indent=2)
        print()
        return 0

    counts = {1: 0, 2: 0, 3: 0}
    for r in reports:
        t = tier(r)
        if t:
            counts[t] += 1
    total_dex = sum(r["dex_count"] for r in reports)
    stored = sum(r["dex_stored"] for r in reports)
    deflated = sum(r["dex_deflated"] for r in reports)
    errs = sum(1 for r in reports if r["errors"])

    print()
    print("=" * 72)
    print("APKs scanned                                    : %d" % len(reports))
    print("  tier 1  input reaches a Fragment loader       : %d" % counts[1])
    print("  tier 2  PreferenceActivity gate to adjudicate : %d" % counts[2])
    print("  tier 3  structural presence only              : %d" % counts[3])
    print("  no signal at all                              : %d"
          % (len(reports) - sum(counts.values())))
    print("classes*.dex entries                            : %d (%d STORED, %d DEFLATED)"
          % (total_dex, stored, deflated))
    print("APKs with a parse error                         : %d" % errs)
    print("=" * 72)
    print("Every tier 1 and tier 2 hit must be read before it is reported.")
    print("Tier 3 is not a finding and must never be counted as one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
