#!/usr/bin/env python3
"""
mapping-reader.py -- read, query and retrace an R8 `mapping.txt` with nothing
                     installed. No JDK, no Android SDK, no `retrace`.

PURPOSE
    When a `mapping.txt` leaks -- out of an APK's assets, off a symbol-upload
    endpoint, out of a public CI artefact -- the person who finds it is usually
    not sitting at a configured Android workstation. This script turns that file
    into answers using only Python:

      * retrace an obfuscated stack trace, INCLUDING inlined frames, which is the
        part hand-reading gets wrong;
      * look up what `a.b.c` used to be called, and the reverse: where did
        `LicenceVault.verify` end up;
      * report what the mapping file discloses even before you retrace anything
        -- package structure, class count, and how much of the program R8
        inlined, merged or synthesised.

USAGE
    python3 -B mapping-reader.py <mapping.txt> retrace [trace.txt]
    python3 -B mapping-reader.py <mapping.txt> lookup <obfuscated.name>
    python3 -B mapping-reader.py <mapping.txt> reverse <Original.Name>
    python3 -B mapping-reader.py <mapping.txt> stats
    python3 -B mapping-reader.py <mapping.txt> tree [--depth N]

    `retrace` reads the trace from the named file, or from stdin if omitted:
        adb logcat -d | python3 -B mapping-reader.py mapping.txt retrace

REQUIREMENTS
    Python 3.8+, standard library only. Runs offline.

WHAT THIS WILL *NOT* TELL YOU
    - It will not verify that this mapping belongs to this APK. R8 writes a
      `pg_map_id` / `pg_map_hash` header; `stats` prints it, but matching it to a
      build is your job. A mapping from v4.2 applied to v4.9 produces confident,
      wrong answers -- R8's name assignment is NOT stable across builds.
    - It will not recover names R8 never wrote down. Fully removed code has no
      entry, and `R8$$REMOVED$$CLASS$$n` entries name a class that is not in the
      APK at all.
    - It will not deobfuscate strings, resources, or native symbols. A mapping
      file covers Java/Kotlin type and member names only.
    - It will not tell you the original line for a frame whose mapping records
      line 0. R8 emits 0 when the source line is unknown; the frame is still
      identified, but the line is genuinely absent, not hidden.
    - It does not implement ProGuard's older mapping dialects beyond the parts R8
      still emits. `stats` prints the `# compiler:` header so you know what wrote
      the file.
    - It cannot undo a build that shipped no mapping at all. This is a tool for
      exploiting a disclosure, not for defeating obfuscation from first
      principles.

MAPPING GRAMMAR IMPLEMENTED (measured against R8 8.6.2 output, map version 2.2)
    <original.Class> -> <obf.Class>:
    # {"id":"sourceFile","fileName":"LicenceVault.kt"}
        <type> <field> -> <obf>
        <ret> <method>(<args>) -> <obf>
        <os>:<oe>:<ret> [<inlineOriginClass>.]<method>(<args>)[:<ls>[:<le>]] -> <obf>

    Consecutive member lines that share the same <os>:<oe> AND the same <obf>
    name are ONE inline chain. The FIRST such line is the innermost frame (it
    carries two trailing line numbers); each following line is its caller (one
    trailing line number). Reproducing that ordering is what makes an inlined
    stack trace readable, and it is the single thing hand-retracing loses.
"""

import io
import os
import re
import sys
import json
import argparse
from collections import defaultdict

CLASS_LINE = re.compile(r"^([^\s#][^\n]*?) -> ([^\s:]+):\s*$")
# <lines?><ret> <name>(<args>)<origlines?> -> <obf>
MEMBER_LINE = re.compile(
    r"^\s+"
    r"(?:(\d+):(\d+):)?"          # obfuscated line range
    r"([\w$.\[\]<>]+)\s+"         # return type / field type
    r"([\w$.<>]+)"                # (possibly qualified) member name
    r"(?:\(([^)]*)\))?"           # argument list, absent for fields
    r"(?::(\d+)(?::(\d+))?)?"     # original line / range
    r"\s+->\s+(\S+)\s*$"
)


class Member:
    __slots__ = ("obf_name", "orig_name", "orig_class", "ret", "args",
                 "obf_start", "obf_end", "line_start", "line_end",
                 "is_method", "synthesized")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def covers(self, line):
        if self.obf_start is None:
            return True
        return self.obf_start <= line <= self.obf_end

    def original_line(self, line):
        """Map an obfuscated line number back to a source line."""
        if self.line_start is None:
            return None
        if self.line_end is None or self.line_start == self.line_end:
            return self.line_start or None
        if self.obf_start is None:
            return self.line_start or None
        return self.line_start + (line - self.obf_start)

    def signature(self):
        if not self.is_method:
            return "%s %s" % (self.ret, self.orig_name)
        return "%s %s(%s)" % (self.ret, self.orig_name, self.args or "")


class ClassEntry:
    __slots__ = ("orig", "obf", "source_file", "members", "by_obf", "synthesized")

    def __init__(self, orig, obf):
        self.orig = orig
        self.obf = obf
        self.source_file = None
        self.members = []
        self.by_obf = defaultdict(list)
        self.synthesized = False

    def add(self, m):
        self.members.append(m)
        self.by_obf[m.obf_name].append(m)


class Mapping:
    def __init__(self):
        self.classes_by_obf = {}
        self.classes_by_orig = {}
        self.headers = []
        self.order = []

    # -- parsing ---------------------------------------------------------
    @classmethod
    def parse(cls, path):
        self = cls()
        current = None
        pending_synth = False
        with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.rstrip("\n").rstrip("\r")
                if not line.strip():
                    continue
                stripped = line.strip()
                if stripped.startswith("#"):
                    body = stripped[1:].strip()
                    if current is None:
                        self.headers.append(body)
                    if body.startswith("{"):
                        try:
                            obj = json.loads(body)
                        except ValueError:
                            continue
                        if obj.get("id") == "sourceFile" and current is not None:
                            current.source_file = obj.get("fileName")
                        if obj.get("id") == "com.android.tools.r8.synthesized":
                            # Applies to whatever was declared immediately above.
                            if current is not None and current.members:
                                current.members[-1].synthesized = True
                            elif current is not None:
                                current.synthesized = True
                            pending_synth = True
                    continue

                m = CLASS_LINE.match(line)
                if m and not line[0].isspace():
                    orig, obf = m.group(1).strip(), m.group(2).strip()
                    current = ClassEntry(orig, obf)
                    self.classes_by_obf[obf] = current
                    self.classes_by_orig.setdefault(orig, current)
                    self.order.append(current)
                    pending_synth = False
                    continue

                if current is None:
                    continue
                mm = MEMBER_LINE.match(line)
                if not mm:
                    continue
                os_, oe_, ret, name, args, ls, le, obf = mm.groups()
                orig_class = None
                if "." in name:
                    orig_class, name = name.rsplit(".", 1)
                current.add(Member(
                    obf_name=obf,
                    orig_name=name,
                    orig_class=orig_class,
                    ret=ret,
                    args=args,
                    obf_start=int(os_) if os_ else None,
                    obf_end=int(oe_) if oe_ else None,
                    line_start=int(ls) if ls else None,
                    line_end=int(le) if le else None,
                    is_method=args is not None,
                    synthesized=False,
                ))
        return self

    # -- queries ---------------------------------------------------------
    def frames_for(self, obf_class, obf_method, line):
        """
        Return the inline chain for one obfuscated frame, innermost first.

        The chain is the maximal run of consecutive member entries that share the
        same obfuscated line range and the same obfuscated name.
        """
        ce = self.classes_by_obf.get(obf_class)
        if ce is None:
            return None, []
        cands = ce.by_obf.get(obf_method, [])
        if not cands:
            return ce, []
        if line is None:
            return ce, [cands[0]]

        hit_idx = None
        for i, mem in enumerate(ce.members):
            if mem.obf_name == obf_method and mem.is_method and mem.covers(line):
                hit_idx = i
                break
        if hit_idx is None:
            return ce, [c for c in cands if c.is_method][:1]

        first = ce.members[hit_idx]
        chain = [first]
        for mem in ce.members[hit_idx + 1:]:
            if (mem.obf_name == obf_method
                    and mem.obf_start == first.obf_start
                    and mem.obf_end == first.obf_end):
                chain.append(mem)
            else:
                break
        return ce, chain


# --------------------------------------------------------------------------
# Retracing
# --------------------------------------------------------------------------

FRAME = re.compile(
    r"^(?P<indent>\s*)at\s+(?P<cls>[\w$.]+)\.(?P<meth>[\w$<>]+)"
    r"\((?P<file>[^):]*)(?::(?P<line>\d+))?\)(?P<tail>.*)$"
)
# `Caused by: com.foo.a: message` and the leading exception line
EXC = re.compile(r"^(?P<pre>(?:Caused by:\s*|Exception in thread \"[^\"]*\"\s*)?)"
                 r"(?P<cls>[\w$.]+(?:Exception|Error|Throwable|[\w$.]*))"
                 r"(?P<rest>:.*)?$")


def retrace_stream(mapping, lines, out):
    for raw in lines:
        line = raw.rstrip("\n")
        m = FRAME.match(line)
        if m:
            obf_cls = m.group("cls")
            obf_meth = m.group("meth")
            lineno = int(m.group("line")) if m.group("line") else None
            ce, chain = mapping.frames_for(obf_cls, obf_meth, lineno)
            if ce is None:
                out.write(line + "    # <no mapping entry>\n")
                continue
            src = ce.source_file or m.group("file") or "Unknown"
            if not chain:
                out.write("%sat %s.%s(%s%s)\n" % (
                    m.group("indent"), ce.orig, obf_meth, src,
                    ":%d" % lineno if lineno else ""))
                continue
            for mem in chain:
                owner = mem.orig_class or ce.orig
                # The source file belongs to the frame's OWNER class, not to the
                # class the frame was inlined into. When the owner has no entry
                # of its own -- because R8 merged or removed it -- R8 synthesizes
                # "<SimpleName>.java", and matching that is what makes this
                # script's output identical to `retrace`.
                owner_file = src
                if mem.orig_class is not None:
                    oce = mapping.classes_by_orig.get(mem.orig_class)
                    if oce is not None and oce.source_file:
                        owner_file = oce.source_file
                    else:
                        simple = mem.orig_class.rsplit(".", 1)[-1].split("$")[0]
                        owner_file = simple + ".java"
                oline = mem.original_line(lineno) if lineno is not None else None
                loc = "%s:%d" % (owner_file, oline) if oline else owner_file
                note = "   # R8-synthesized" if mem.synthesized else ""
                out.write("%sat %s.%s(%s)%s\n" % (
                    m.group("indent"), owner, mem.orig_name, loc, note))
            continue

        # Exception type names are obfuscated too, and people forget this.
        e = EXC.match(line.strip())
        if e and e.group("cls") in mapping.classes_by_obf:
            ce = mapping.classes_by_obf[e.group("cls")]
            indent = line[:len(line) - len(line.lstrip())]
            out.write("%s%s%s%s\n" % (indent, e.group("pre"), ce.orig,
                                      e.group("rest") or ""))
            continue
        out.write(line + "\n")


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def cmd_stats(mapping, _args):
    n_cls = len(mapping.order)
    removed = sum(1 for c in mapping.order if c.obf.startswith("R8$$REMOVED"))
    renamed = sum(1 for c in mapping.order if c.obf != c.orig
                  and not c.obf.startswith("R8$$REMOVED"))
    synth_cls = sum(1 for c in mapping.order if c.synthesized
                    or "$$Synthetic" in c.orig or "$$Nest$" in c.orig)
    ext_lambda = sum(1 for c in mapping.order if "$$ExternalSyntheticLambda" in c.orig)
    int_lambda = sum(1 for c in mapping.order if "$$InternalSyntheticLambda" in c.orig)
    r8lambda = sum(1 for c in mapping.order if "$r8$lambda$" in c.orig)
    n_mem = sum(len(c.members) for c in mapping.order)
    n_syn_mem = sum(1 for c in mapping.order for m in c.members if m.synthesized)
    inlined = 0
    for c in mapping.order:
        for m in c.members:
            if m.orig_class is not None:
                inlined += 1

    print("header lines")
    for h in mapping.headers:
        print("    # %s" % h)
    print()
    print("classes total                 : %d" % n_cls)
    print("  renamed                     : %d" % renamed)
    print("  recorded but REMOVED by R8  : %d" % removed)
    print("  synthetic (any kind)        : %d" % synth_cls)
    print("    $$ExternalSyntheticLambda : %d" % ext_lambda)
    print("    $$InternalSyntheticLambda : %d" % int_lambda)
    print("    $r8$lambda$               : %d" % r8lambda)
    print("members total                 : %d" % n_mem)
    print("  marked r8.synthesized       : %d" % n_syn_mem)
    print("  inline frames (foreign owner): %d" % inlined)
    print()
    pkgs = defaultdict(int)
    for c in mapping.order:
        pkgs[c.orig.rsplit(".", 1)[0] if "." in c.orig else "<default>"] += 1
    print("top packages disclosed by this file:")
    for p, n in sorted(pkgs.items(), key=lambda kv: -kv[1])[:15]:
        print("    %-58s %d" % (p, n))


def cmd_lookup(mapping, args):
    name = args.name
    ce = mapping.classes_by_obf.get(name)
    if ce is None:
        # maybe they passed a.b.c$d or a member
        for c in mapping.order:
            if c.obf == name.split("$")[0]:
                ce = c
                break
    if ce is None:
        print("No class with obfuscated name %r." % name)
        return 1
    print("%s  ->  %s" % (ce.obf, ce.orig))
    if ce.source_file:
        print("  SourceFile: %s" % ce.source_file)
    seen = set()
    for m in ce.members:
        key = (m.obf_name, m.signature())
        if key in seen:
            continue
        seen.add(key)
        owner = (" [inlined from %s]" % m.orig_class) if m.orig_class else ""
        synth = "  # synthesized" if m.synthesized else ""
        print("    %-14s -> %s%s%s" % (m.obf_name, m.signature(), owner, synth))
    return 0


def cmd_reverse(mapping, args):
    needle = args.name
    hits = 0
    for c in mapping.order:
        if needle in c.orig:
            print("%s  ->  %s" % (c.orig, c.obf))
            hits += 1
        seen = set()
        for m in c.members:
            if needle not in m.orig_name:
                continue
            # For an inlined frame the member's true owner is m.orig_class, NOT
            # the class whose block it appears in. Reporting the block's class
            # would claim the method lives somewhere it never did.
            owner = m.orig_class or c.orig
            if m.orig_class:
                note = "   # inlined into %s.%s" % (c.obf, m.obf_name)
                line = "%s.%s  ->  (inlined; no standalone member)%s" % (
                    owner, m.orig_name, note)
            else:
                line = "%s.%s  ->  %s.%s" % (owner, m.orig_name, c.obf, m.obf_name)
            if line in seen:
                continue
            seen.add(line)
            print(line)
            hits += 1
    if not hits:
        print("Nothing matching %r." % needle)
        return 1
    return 0


def cmd_tree(mapping, args):
    depth = args.depth
    counts = defaultdict(int)
    for c in mapping.order:
        parts = c.orig.split(".")[:-1]
        key = ".".join(parts[:depth]) if parts else "<default>"
        counts[key] += 1
    for k in sorted(counts):
        print("%-60s %d" % (k, counts[k]))


def cmd_retrace(mapping, args):
    if args.trace and args.trace != "-":
        with io.open(args.trace, "r", encoding="utf-8", errors="replace") as fh:
            retrace_stream(mapping, fh, sys.stdout)
    else:
        retrace_stream(mapping, sys.stdin, sys.stdout)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read and retrace an R8 mapping.txt.")
    ap.add_argument("mapping", help="path to mapping.txt")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("retrace", help="deobfuscate a stack trace")
    p.add_argument("trace", nargs="?", default=None)
    p.set_defaults(fn=cmd_retrace)

    p = sub.add_parser("lookup", help="obfuscated name -> original")
    p.add_argument("name")
    p.set_defaults(fn=cmd_lookup)

    p = sub.add_parser("reverse", help="original substring -> obfuscated")
    p.add_argument("name")
    p.set_defaults(fn=cmd_reverse)

    p = sub.add_parser("stats", help="what this mapping file discloses")
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("tree", help="package histogram")
    p.add_argument("--depth", type=int, default=3)
    p.set_defaults(fn=cmd_tree)

    args = ap.parse_args(argv)
    if not os.path.exists(args.mapping):
        raise SystemExit("no such mapping file: %s" % args.mapping)
    mapping = Mapping.parse(args.mapping)
    return args.fn(mapping, args) or 0


if __name__ == "__main__":
    sys.exit(main())
