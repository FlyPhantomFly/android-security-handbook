#!/usr/bin/env python3
# scripts/what-survived.py
#
# PURPOSE
#   Answer, for a built APK or DEX, the question this chapter is about:
#   WHAT SURVIVED RENAMING, and WHY.
#
#   It reads the DEX directly -- no jadx, no apktool, no baksmali, no Android
#   SDK -- and reports:
#
#     * the class census: how many types are renamed, how many are not, and
#       what fraction of the app's own code that is
#     * every UNRENAMED class, and which of your keep rules explains it. A
#       class that survived with no rule to explain it was kept by something
#       you are not looking at -- AGP's manifest rules, a library's consumer
#       rules, a Kotlin metadata reference, or an entry point
#     * every keep rule that matched NOTHING (a rule you can delete)
#     * the SourceFile attributes: whether original .java/.kt filenames shipped
#     * the survivors that renaming never touches at all -- string constants,
#       framework symbols, JNI symbol names in bundled .so files, and, if aapt2
#       is available, resource names
#     * build artefacts that should never be inside an APK: mapping.txt,
#       seeds.txt, usage.txt, configuration.txt, a stray proguard-rules.pro
#
# USAGE
#   # host -- the basic census
#   python3 -B scripts/what-survived.py app.apk
#
#   # host -- correlate against the rules that built it
#   python3 -B scripts/what-survived.py app.apk --rules app/proguard-rules.pro
#
#   # host -- restrict the census to the application's own package, which is
#   # what you almost always want; libraries drag the numbers around
#   python3 -B scripts/what-survived.py app.apk --package com.example.app
#
#   # host -- a bare DEX, or a directory of them
#   python3 -B scripts/what-survived.py build/b-tightened/classes.dex
#
#   # host -- machine-readable
#   python3 -B scripts/what-survived.py app.apk --rules rules.pro --json
#
# REQUIREMENTS
#   Python 3.8+, standard library only. `aapt2` on PATH is optional and is used
#   only for the resource-name section; everything else works without it.
#   Run with `python3 -B` so no __pycache__ appears next to the script.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * It will NOT tell you whether the app is "obfuscated enough". There is no
#     threshold. A 98%-renamed app with its crypto class kept by name is worse
#     off than a 60%-renamed app whose secrets are server-side.
#   * A class being unrenamed is NOT evidence of a bad rule. Entry points,
#     native-bound classes, reflection targets and serialisation models all
#     have legitimate reasons to keep their names. The tool tells you WHICH
#     rule explains each survivor; deciding whether that rule is justified
#     needs the app, not the APK.
#   * "explained by no rule" does NOT mean "kept for no reason". The most
#     common cause is that you gave it only YOUR rules file while the build
#     also used AGP's generated manifest keeps and every dependency's consumer
#     rules. Feed it the merged configuration.txt instead and the unexplained
#     list will shrink dramatically.
#   * Rule matching here is TEXTUAL. `extends`/`implements` clauses are
#     resolved one level deep, from the DEX's own superclass and interface
#     tables -- not transitively -- so a rule keying on a grandparent class
#     will be reported as matching nothing when it in fact matched. Member
#     specifications are NOT evaluated at all: a rule's member block is
#     ignored when deciding whether the rule matched a class.
#   * It does NOT decompile. If you need to know what a surviving class DOES,
#     that is jadx's job -- see chapter 56.
#   * It does NOT detect string encryption, packing, or native protection. See
#     chapter 40 for the technique landscape.
#   * The renaming heuristic is a HEURISTIC. A developer who genuinely names a
#     class `Ab` will be counted as renamed. The tool prints its rule so you
#     can argue with it.
#
# Nothing here writes to a device and nothing here modifies the input file.

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

NO_INDEX = 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# A minimal DEX reader.
#
# Only the index tables are parsed -- strings, types, fields, methods and class
# definitions. That is everything needed to answer "what is this thing called",
# which is the entire subject of this chapter. Method BODIES are not decoded.
#
# The layout below is the DEX format as documented at
# https://source.android.com/docs/core/runtime/dex-format and as described in
# chapter 12 of this repository.
# --------------------------------------------------------------------------- #
class Dex:
    def __init__(self, data, name="classes.dex"):
        self.d = data
        self.name = name
        if data[:4] not in (b"dex\n",):
            raise ValueError("%s: not a DEX file (bad magic)" % name)
        self.version = data[4:7].decode("ascii", "replace")
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from("<12I", data, 56)
        self._strings = None

    # ---- primitives ------------------------------------------------------- #
    def uleb128(self, off):
        result = 0
        shift = 0
        while True:
            b = self.d[off]
            off += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, off
            shift += 7

    def string(self, idx):
        if self._strings is None:
            self._strings = [None] * self.string_ids_size
        if idx == NO_INDEX or idx >= self.string_ids_size:
            return None
        cached = self._strings[idx]
        if cached is not None:
            return cached
        off = struct.unpack_from("<I", self.d, self.string_ids_off + 4 * idx)[0]
        _, data_off = self.uleb128(off)          # utf16_size, unused here
        end = self.d.index(b"\x00", data_off)
        raw = self.d[data_off:end]
        # MUTF-8: the two-byte encoding of NUL is 0xC0 0x80. Everything else
        # decodes as UTF-8 closely enough for a name census; surrogate pairs
        # are left as-is and replaced rather than recombined.
        s = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "replace")
        self._strings[idx] = s
        return s

    def type_name(self, idx):
        if idx == NO_INDEX or idx >= self.type_ids_size:
            return None
        sidx = struct.unpack_from("<I", self.d, self.type_ids_off + 4 * idx)[0]
        return self.string(sidx)

    def type_list(self, off):
        if not off:
            return []
        size = struct.unpack_from("<I", self.d, off)[0]
        return [self.type_name(struct.unpack_from("<H", self.d, off + 4 + 2 * i)[0])
                for i in range(size)]

    # ---- tables ----------------------------------------------------------- #
    def all_strings(self):
        return [self.string(i) for i in range(self.string_ids_size)]

    def all_types(self):
        return [self.type_name(i) for i in range(self.type_ids_size)]

    def method_names(self):
        out = []
        for i in range(self.method_ids_size):
            base = self.method_ids_off + 8 * i
            cls_idx, _proto, name_idx = struct.unpack_from("<HHI", self.d, base)
            out.append((self.type_name(cls_idx), self.string(name_idx)))
        return out

    def field_names(self):
        out = []
        for i in range(self.field_ids_size):
            base = self.field_ids_off + 8 * i
            cls_idx, _type, name_idx = struct.unpack_from("<HHI", self.d, base)
            out.append((self.type_name(cls_idx), self.string(name_idx)))
        return out

    def class_defs(self):
        out = []
        for i in range(self.class_defs_size):
            base = self.class_defs_off + 32 * i
            (class_idx, access, super_idx, interfaces_off,
             source_idx, _anno_off, _data_off, _static_off) = struct.unpack_from("<8I", self.d, base)
            out.append({
                "descriptor": self.type_name(class_idx),
                "access": access,
                "super": self.type_name(super_idx) if super_idx != NO_INDEX else None,
                "interfaces": self.type_list(interfaces_off),
                "source_file": self.string(source_idx) if source_idx != NO_INDEX else None,
            })
        return out


# --------------------------------------------------------------------------- #
# Naming heuristics
# --------------------------------------------------------------------------- #
def desc_to_java(desc):
    """Lcom/example/Foo$Bar; -> com.example.Foo$Bar"""
    if not desc or not desc.startswith("L") or not desc.endswith(";"):
        return desc
    return desc[1:-1].replace("/", ".")


# A renamed identifier, as every shrinker on this platform emits them: one to
# three characters drawn from the dictionary, optionally with a digit. R8's
# default dictionary starts a, b, c ... z, a0, a1 ... and ProGuard's is the
# same shape. Anything longer than three characters is almost never generated.
RENAMED_SEGMENT = re.compile(r"^[a-zA-Z][a-zA-Z0-9]{0,2}$")


def looks_renamed(java_name):
    """
    True if the LAST segment of a class name looks machine-generated.

    The rule, stated so you can argue with it: the simple name is at most three
    characters and contains no underscore. That catches a, b, aa, a0, and misses
    a developer's own `Ui` or `Db` -- which is why the report prints the count
    and the list, not just a percentage.
    """
    simple = java_name.split(".")[-1]
    # Inner classes: judge the outermost part that is not itself generated.
    simple = simple.split("$")[-1] if "$" in simple else simple
    if simple.isdigit():          # anonymous inner class Foo$1
        return False
    return bool(RENAMED_SEGMENT.match(simple))


def package_of(java_name):
    return java_name.rsplit(".", 1)[0] if "." in java_name else ""


# --------------------------------------------------------------------------- #
# Rules: parse just enough to know which classes a keep rule matches
# --------------------------------------------------------------------------- #
KEEP_FAMILY = ("keep", "keepclassmembers", "keepclasseswithmembers", "keepnames",
               "keepclassmembernames", "keepclasseswithmembernames")


def parse_rules(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    text = "\n".join(ln.split("#")[0] for ln in text.splitlines())

    rules = []
    for m in re.finditer(r"^\s*-([A-Za-z]+)([^\n{]*)", text, re.M):
        directive = m.group(1)
        if directive not in KEEP_FAMILY:
            continue
        spec = m.group(2).strip()
        mods = []
        if spec.startswith(","):
            head, _, rest = spec.partition(" ")
            mods = [x for x in head.split(",") if x]
            spec = rest.strip()
        lineno = text.count("\n", 0, m.start()) + 1
        rules.append(compile_rule(directive, mods, spec, lineno, path))
    return rules


def compile_rule(directive, mods, spec, lineno, source):
    s = spec.strip()
    anno = None
    am = re.match(r"^@(\S+)\s*", s)
    if am:
        anno = am.group(1)
        s = s[am.end():]
    s = re.sub(r"^(?:!?(?:public|final|abstract|static|synthetic|private|protected)\s+)*", "", s)
    kind = "class"
    km = re.match(r"^(class|interface|enum|@interface)\s+", s)
    if km:
        kind = km.group(1)
        s = s[km.end():]
    extends = None
    em = re.search(r"\s+(?:extends|implements)\s+(\S+)", s)
    if em:
        extends = em.group(1)
        s = s[:em.start()]
    pattern = s.strip()
    return {
        "directive": directive, "modifiers": mods, "kind": kind,
        "annotation": anno, "pattern": pattern, "extends": extends,
        "line": lineno, "source": source,
        "regex": glob_to_regex(pattern), "matched": [],
    }


def glob_to_regex(pattern):
    """
    Translate a ProGuard class-name pattern into a regex.

        **   any sequence, INCLUDING the package separator
        *    any sequence, NOT crossing the package separator
        ?    exactly one character, not the package separator

    Getting this wrong in either direction is the classic mistake: people write
    `com.app.*` expecting it to cover subpackages (it does not) and write
    `com.app.**` expecting it to cover only subpackages (it also covers
    com.app.Foo itself).
    """
    if not pattern:
        return re.compile(r".*")
    # THE DOCUMENTED SPECIAL CASE. The ProGuard manual states that, for
    # convenience and backward compatibility, the class name `*` on its own
    # matches any class irrespective of its package -- even though `*` does not
    # otherwise cross the package separator. So `-keep class *` keeps
    # everything, while `-keep class com.app.*` keeps one package's classes.
    # Miss this and you will read `-keepclassmembers class * { ... }` as narrow.
    if pattern == "*":
        return re.compile(r".*")
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^.]*")
        elif c == "?":
            out.append("[^.]")
        elif c == "$":
            out.append(r"\$")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def rule_matches(rule, cls):
    name = cls["java"]
    if not rule["regex"].match(name):
        return False
    if rule["kind"] == "interface" and not (cls["access"] & 0x200):
        return False
    if rule["kind"] == "enum" and not (cls["access"] & 0x4000):
        return False
    if rule["extends"]:
        rx = glob_to_regex(rule["extends"])
        parents = [p for p in ([cls["super"]] + cls["interfaces"]) if p]
        if not any(rx.match(desc_to_java(p)) for p in parents):
            return False
    return True


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #
def load_dexes(path):
    """Return (list of Dex, list of archive member names, raw zip or None)."""
    if os.path.isdir(path):
        dexes = []
        for fn in sorted(os.listdir(path)):
            if fn.endswith(".dex"):
                with open(os.path.join(path, fn), "rb") as fh:
                    dexes.append(Dex(fh.read(), fn))
        return dexes, sorted(os.listdir(path)), None
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        names = z.namelist()
        dexes = []
        for n in sorted(names):
            if n.endswith(".dex") and "/" not in n:
                dexes.append(Dex(z.read(n), n))
        return dexes, names, z
    with open(path, "rb") as fh:
        return [Dex(fh.read(), os.path.basename(path))], [], None


# --------------------------------------------------------------------------- #
# Report sections
# --------------------------------------------------------------------------- #
def section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Report what survived shrinking and renaming in a built APK or DEX.")
    ap.add_argument("target", help="APK, DEX, or a directory containing classes*.dex")
    ap.add_argument("--rules", action="append", default=[],
                    help="a .pro rules file to correlate against; repeatable. "
                         "Prefer the merged configuration.txt.")
    ap.add_argument("--package", default=None,
                    help="restrict the census to this package prefix (recommended)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-list", type=int, default=40,
                    help="how many names to print per list (default 40)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.target):
        sys.stderr.write("error: no such file: %s\n" % args.target)
        return 2

    try:
        dexes, members, zf = load_dexes(args.target)
    except ValueError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    if not dexes:
        sys.stderr.write("error: no DEX found in %s\n" % args.target)
        return 2

    # ---- gather ----------------------------------------------------------- #
    classes = []
    strings = []
    all_types = set()
    for dx in dexes:
        for cd in dx.class_defs():
            java = desc_to_java(cd["descriptor"])
            classes.append({
                "java": java, "access": cd["access"], "super": cd["super"],
                "interfaces": cd["interfaces"], "source_file": cd["source_file"],
                "dex": dx.name,
            })
        strings.extend(s for s in dx.all_strings() if s)
        all_types.update(t for t in dx.all_types() if t)

    scoped = classes
    if args.package:
        scoped = [c for c in classes if c["java"].startswith(args.package)]

    renamed = [c for c in scoped if looks_renamed(c["java"])]
    kept = [c for c in scoped if not looks_renamed(c["java"])]

    rules = []
    for rp in args.rules:
        if not os.path.isfile(rp):
            sys.stderr.write("error: no such rules file: %s\n" % rp)
            return 2
        rules.extend(parse_rules(rp))

    for c in kept:
        for r in rules:
            if rule_matches(r, c):
                r["matched"].append(c["java"])
    for c in renamed:
        for r in rules:
            if rule_matches(r, c):
                r.setdefault("matched_renamed", []).append(c["java"])

    explained = set()
    for r in rules:
        explained.update(r["matched"])
    unexplained = [c["java"] for c in kept if c["java"] not in explained]

    # ---- output ----------------------------------------------------------- #
    if args.json:
        print(json.dumps({
            "target": args.target,
            "dex_files": [d.name for d in dexes],
            "classes_total": len(classes),
            "classes_in_scope": len(scoped),
            "renamed": [c["java"] for c in renamed],
            "not_renamed": [c["java"] for c in kept],
            "unexplained": unexplained,
            "rules": [{"line": r["line"], "directive": r["directive"],
                       "pattern": r["pattern"], "matched": r["matched"],
                       "matched_but_renamed": r.get("matched_renamed", [])}
                      for r in rules],
        }, indent=2))
        return 0

    print("=" * 78)
    print("what survived: %s" % args.target)
    print("  dex files      : %s" % ", ".join("%s (v%s)" % (d.name, d.version) for d in dexes))
    print("  classes        : %d total" % len(classes))
    if args.package:
        print("  in scope       : %d under '%s'" % (len(scoped), args.package))
    print("=" * 78)

    # 1. the census
    section("1. NAME CENSUS")
    total = len(scoped) or 1
    print("machine-generated-looking names : %4d  (%.1f%%)" % (len(renamed), 100.0 * len(renamed) / total))
    print("original-looking names          : %4d  (%.1f%%)" % (len(kept), 100.0 * len(kept) / total))
    print()
    print("Heuristic: a class counts as renamed when its simple name is 1-3")
    print("characters with no underscore. It over-counts a developer's own `Db`")
    print("and under-counts an obfuscator that emits long names. Read the lists.")
    # --package is the option people reach for first, and on a well-obfuscated
    # app it under-reports badly: renaming also rewrites the PACKAGE, so the
    # renamed classes are no longer under the prefix you scoped to. Say so.
    if args.package:
        outside = [c for c in classes if not c["java"].startswith(args.package)]
        outside_renamed = [c for c in outside if looks_renamed(c["java"])]
        if outside_renamed:
            print()
            print("note: %d class(es) OUTSIDE '%s' also look renamed." % (len(outside_renamed), args.package))
            print("      Renaming rewrites the package as well as the class, so classes")
            print("      that started life in your package end up in `a`, `b`, `a.a` and")
            print("      are invisible to --package. Run without --package too, and")
            print("      compare. Example from this run: %s"
                  % ", ".join(sorted(c["java"] for c in outside_renamed)[:5]))
    if len(renamed) == 0:
        print()
        print(">> NOTHING in scope is renamed. Before concluding that minification")
        print(">> is off, check the note above: the renamed classes may simply have")
        print(">> been moved out of the package you scoped to. If nothing anywhere")
        print(">> is renamed, check the build file for minifyEnabled, then check the")
        print(">> rules for -dontobfuscate and for '-keep class <pkg>.** { *; }'.")

    # 2. packages
    section("2. PACKAGES IN SCOPE")
    pkgs = {}
    for c in scoped:
        p = package_of(c["java"])
        pkgs.setdefault(p, [0, 0])
        if looks_renamed(c["java"]):
            pkgs[p][0] += 1
        else:
            pkgs[p][1] += 1
    for p in sorted(pkgs, key=lambda k: -(pkgs[k][0] + pkgs[k][1]))[:args.max_list]:
        r, k = pkgs[p]
        print("  %-52s renamed=%-4d kept=%-4d" % (p or "(default package)", r, k))
    short_pkgs = [p for p in pkgs if p and all(len(seg) <= 2 for seg in p.split("."))]
    if short_pkgs:
        print()
        print("  %d package(s) have entirely short segments (%s...) -- these are the"
              % (len(short_pkgs), ", ".join(sorted(short_pkgs)[:4])))
        print("  obfuscator's own output. jadx prefixes them pNNN because a Java")
        print("  package segment may not start with a digit; see chapter 56.")

    # 3. unrenamed survivors
    section("3. CLASSES THAT KEPT THEIR NAMES")
    if not kept:
        print("  none in scope.")
    for c in kept[:args.max_list]:
        why = [r for r in rules if c["java"] in r["matched"]]
        tag = ("<- %s:%d  -%s %s" % (os.path.basename(why[0]["source"]), why[0]["line"],
                                     why[0]["directive"], why[0]["pattern"])) if why else ""
        print("  %-50s %s" % (c["java"], tag))
    if len(kept) > args.max_list:
        print("  ... and %d more" % (len(kept) - args.max_list))

    if rules:
        section("4. RULE CORRELATION")
        for r in rules:
            n = len(r["matched"])
            nr = len(r.get("matched_renamed", []))
            status = "matched %d unrenamed" % n
            if nr:
                status += ", %d matched-but-renamed" % nr
            if n == 0 and nr == 0:
                status = "MATCHED NOTHING -- candidate for deletion"
            print("  %-6s -%s %s" % ("[%d]" % r["line"], r["directive"], r["pattern"]))
            print("         %s" % status)
        print()
        print("  'MATCHED NOTHING' has three innocent explanations before it means")
        print("  the rule is dead: the class was removed by shrinking anyway; the")
        print("  rule targets a library that is not in this DEX; or the rule keys")
        print("  on an extends/implements relationship deeper than one level,")
        print("  which this tool does not resolve.")

        section("5. SURVIVORS YOUR RULES DO NOT EXPLAIN")
        if not unexplained:
            print("  none -- every unrenamed class in scope is matched by a rule you gave me.")
        else:
            print("  %d class(es) kept their names with no matching rule in the files"
                  % len(unexplained))
            print("  you supplied. In a real build the usual causes, in order:")
            print("    * AGP's generated manifest keeps (build/intermediates/")
            print("      aapt_proguard_file/<variant>/aapt_rules.txt)")
            print("    * a dependency's consumer rules, merged invisibly")
            print("    * proguard-android-optimize.txt's own defaults")
            print("    * the class is referenced from kotlin.Metadata or an")
            print("      annotation that another rule keeps")
            print()
            for n in unexplained[:args.max_list]:
                print("    %s" % n)
            if len(unexplained) > args.max_list:
                print("    ... and %d more" % (len(unexplained) - args.max_list))

    # 6. attributes that leak names
    section("6. SourceFile ATTRIBUTES")
    srcs = {}
    for c in classes:
        if c["source_file"]:
            srcs[c["source_file"]] = srcs.get(c["source_file"], 0) + 1
    if not srcs:
        print("  No SourceFile attribute on any class. Either -keepattributes")
        print("  SourceFile was not set, or the build stripped debug info. Stack")
        print("  traces from this build carry no file names.")
    elif len(srcs) == 1:
        only = list(srcs)[0]
        print("  One constant SourceFile value across %d classes: %r" % (sum(srcs.values()), only))
        print("  No original filenames shipped. Two things produce this and you")
        print("  cannot tell them apart from the APK: an explicit")
        print("  -renamesourcefileattribute, or R8's own default -- measured on R8")
        print("  8.6.2, a minified build emits the constant 'SourceFile' even with")
        print("  -keepattributes * and -dontobfuscate and no rename rule at all.")
        print("  Either way, line numbers stay resolvable through mapping.txt and")
        print("  the filenames do not ship. This is the state you want.")
    else:
        originals = [s for s in srcs if s.endswith(".java") or s.endswith(".kt")]
        print("  %d distinct SourceFile values across %d classes." % (len(srcs), sum(srcs.values())))
        if originals:
            print()
            print("  >> %d of them are original source filenames. These hand an" % len(originals))
            print("  >> analyst the developer's own class names for free -- jadx will")
            print("  >> use them via --use-source-name-as-class-name-alias, which")
            print("  >> recovers much of what renaming removed.")
            print("  >> Fix: add -renamesourcefileattribute SourceFile")
            print()
            for s in sorted(originals)[:args.max_list]:
                print("    %s  (%d classes)" % (s, srcs[s]))
            if len(originals) > args.max_list:
                print("    ... and %d more" % (len(originals) - args.max_list))

    # 7. things renaming never touches
    section("7. SURVIVORS RENAMING NEVER TOUCHES")
    print("  These are present at ANY obfuscation setting. They are the footholds")
    print("  chapter 40 section 3.1 tabulates, and they are why an app whose every")
    print("  class is called `a` is still readable.")
    print()

    kotlin_meta = "Lkotlin/Metadata;" in all_types
    print("  kotlin.Metadata annotation present : %s" % ("YES" if kotlin_meta else "no"))
    if kotlin_meta:
        print("      Kotlin's metadata annotation carries original names in a")
        print("      protobuf so that kotlin-reflect works. R8 rewrites it to track")
        print("      renames, but it also keeps enough structure to be worth")
        print("      reading. It is retained by default in Kotlin builds.")

    fw = sum(1 for t in all_types if t.startswith(("Landroid/", "Landroidx/", "Ljava/", "Ljavax/")))
    print("  framework/library type references  : %d" % fw)
    print("      Not in the APK, resolved by name at runtime, therefore")
    print("      unrenameable. Every one is a semantic anchor.")

    urls = sorted({s for s in strings if s.startswith(("http://", "https://", "ws://", "wss://"))})
    print("  distinct URL-shaped strings        : %d" % len(urls))
    for u in urls[:min(args.max_list, 15)]:
        print("      %s" % u)
    if len(urls) > 15:
        print("      ... and %d more" % (len(urls) - 15))

    longstr = [s for s in strings if len(s) >= 20 and " " not in s and s.isprintable()]
    print("  strings >= 20 chars, no spaces     : %d  (key/token shaped)" % len(longstr))
    print("      A string constant is NOT affected by renaming at any setting.")
    print("      Renaming is not string encryption; see chapter 40 section 3.2.")

    # 8. archive-level findings
    if members:
        section("8. FILES INSIDE THE ARCHIVE THAT SHOULD NOT BE THERE")
        bad = []
        for n in members:
            base = os.path.basename(n).lower()
            if base in ("mapping.txt", "seeds.txt", "usage.txt", "configuration.txt") \
               or base.endswith(".pro") or "proguard" in base or base.endswith(".jobf"):
                bad.append(n)
        if bad:
            for n in bad:
                print("  >> %s" % n)
            print()
            print("  A shipped mapping.txt de-obfuscates the entire application in one")
            print("  jadx invocation:")
            print("      jadx -Prename-mappings.format=PROGUARD_FILE \\")
            print("           --mappings-path mapping.txt -d out app.apk")
            print("  Report it as a finding in its own right -- the control the")
            print("  developer paid for is present and defeated by a build artefact.")
        else:
            print("  none found (checked for mapping.txt, seeds.txt, usage.txt,")
            print("  configuration.txt, *.pro and *.jobf).")

        sos = [n for n in members if n.endswith(".so")]
        if sos and zf is not None:
            print()
            print("  bundled native libraries: %d" % len(sos))
            jni = set()
            for n in sos[:8]:
                blob = zf.read(n)
                for m in re.finditer(rb"Java_[A-Za-z0-9_]{4,200}", blob):
                    jni.add(m.group(0).decode("ascii", "replace"))
            for s in sorted(jni)[:min(args.max_list, 20)]:
                print("      %s" % s)
            if jni:
                print()
                print("  A JNI symbol is built from the POST-rename class and method")
                print("  names, so it tells you the obfuscated fully qualified name of a")
                print("  class that matters enough to have native code behind it. Nothing")
                print("  in the AGP toolchain renames these away; see chapter 16.")
            elif sos:
                print("      no Java_* symbols found -- the libraries use dynamic")
                print("      registration via RegisterNatives, which hides the mapping.")

    # 9. resources, if aapt2 is available
    if zipfile.is_zipfile(args.target) and shutil.which("aapt2"):
        section("9. RESOURCE NAMES (via aapt2)")
        try:
            # aapt2 writes resource values verbatim, so its stdout is not
            # necessarily valid text in the platform's default codepage.
            # Decode explicitly and replace, or this crashes on any APK
            # containing a non-ASCII string resource.
            out = subprocess.run(["aapt2", "dump", "resources", args.target],
                                 capture_output=True, timeout=180).stdout.decode("utf-8", "replace")
            names = sorted(set(re.findall(r"\b(?:string|id|layout|drawable|xml)/[A-Za-z0-9_]+", out)))
            print("  %d distinct resource names. R8 never renames these at any" % len(names))
            print("  setting; a separate resource obfuscator is required.")
            for n in names[:args.max_list]:
                print("    %s" % n)
            if len(names) > args.max_list:
                print("    ... and %d more" % (len(names) - args.max_list))
        except Exception as e:                                   # noqa: BLE001
            print("  aapt2 failed: %s" % e)

    section("VERDICT")
    pct = 100.0 * len(renamed) / total
    if pct >= 85:
        print("  %.0f%% of in-scope classes carry generated names." % pct)
        print("  Renaming is doing its job on the app's own code.")
    elif pct >= 40:
        print("  %.0f%% of in-scope classes carry generated names." % pct)
        print("  Partial coverage. Look at section 3: the survivors are where the")
        print("  rules are broader than they need to be.")
    else:
        print("  Only %.0f%% of in-scope classes carry generated names." % pct)
        print("  Either minification is off, or a keep rule is matching almost")
        print("  everything. Run scripts/proguard-rules-audit.py on the rules file.")
    print()
    print("  Say this in a report as a HARDENING observation. Weak obfuscation is")
    print("  not itself a vulnerability, it does not make anything else worse, and")
    print("  it must never be offered as the fix for a real defect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
