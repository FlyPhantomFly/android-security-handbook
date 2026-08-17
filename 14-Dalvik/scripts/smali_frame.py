#!/usr/bin/env python3
"""
smali_frame.py -- compute a Smali method's register frame, and find the hazards
                  that break hand-written patches.

WHAT IT DOES
    For every method in a .smali file it works out, from the method descriptor
    and the .registers/.locals directive:

      - ins_size in WORDS (a long or double counts as two)
      - the first parameter register:  registers_size - ins_size
      - the full p-to-v mapping, with wide values shown as the pair they occupy
      - how many registers are free for locals

    With --check it then scans the method body for the five mistakes that
    actually cause patched APKs to fail:

      1. move-result* that does not immediately follow its invoke   (VerifyError)
      2. move-exception that is not the first instruction of a handler
      3. a register number at or beyond registers_size               (assembler)
      4. a register above v15 used in an instruction whose format has
         only a 4-bit field for it                                   (assembler)
      5. a raw vN in the body that aliases a PARAMETER register while the
         method declares .registers -- the silent one, because raising
         .registers moves the parameters and this reference does not move

WHY YOU WOULD RUN IT
    Because the register model is the single largest source of wasted hours in
    Smali patching, and every one of the five checks above is something a human
    gets wrong regularly. Hazard 5 in particular produces a method that VERIFIES
    and BEHAVES WRONGLY, with no error anywhere -- the worst possible failure
    mode. Run --check on a file before you edit it and again after.

HOW TO RUN
    python3 smali_frame.py Foo.smali
    python3 smali_frame.py Foo.smali --method verify
    python3 smali_frame.py Foo.smali --check
    python3 smali_frame.py work/ --check                 # a whole decoded APK
    python3 smali_frame.py work/ --check --quiet         # only files with hazards
    python3 smali_frame.py --descriptor '(Ljava/lang/String;JI)Z' --registers 9 --instance

REQUIREMENTS
    Python 3.8+. Standard library only. Reads; never writes.

WHAT THIS WILL *NOT* TELL YOU
    - It is not a verifier. It checks five specific, mechanically-detectable
      rules. ART's verifier checks type consistency along every control-flow
      path, which this tool does not model at all. A clean run here does not
      mean the method will verify.
    - It does not track register TYPES. It cannot tell you that you used
      `return` where `return-object` was needed -- that is a type question and
      the answer is in the method descriptor, not in the frame.
    - Hazard 5 is reported for every raw parameter-register reference, including
      the ones baksmali emitted deliberately. Most are harmless TODAY; they
      become hazards the moment you change .registers. Treat it as "these lines
      will bite you if you resize the frame", not as "these lines are wrong".
    - It does not follow branches, so "first instruction of a handler" is judged
      from the .catch directives' target labels, which is accurate for baksmali
      output and may not be for hand-written files with unusual layouts.
    - Register numbers inside string literals or comments are ignored, but a
      pathological literal could still confuse the tokenizer. Sanity-check
      anything surprising against the source line it came from.
"""

import argparse
import os
import re
import sys

# Instructions whose format gives a register only 4 bits (v0-v15).
# Derived from the format table: 12x, 11n, 22c, 22s, 22t, and the 35c invoke
# register list. README section 3.4 and 12-DEX-Internals section 3.25.
FOUR_BIT = set()
for _m in ["move", "move-wide", "move-object", "array-length",
           "neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
           "int-to-long", "int-to-float", "int-to-double",
           "long-to-int", "long-to-float", "long-to-double",
           "float-to-int", "float-to-long", "float-to-double",
           "double-to-int", "double-to-long", "double-to-float",
           "int-to-byte", "int-to-char", "int-to-short",
           "const/4", "instance-of", "new-array",
           "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"]:
    FOUR_BIT.add(_m)
for _p in ["iget", "iput"]:
    for _s in ["", "-wide", "-object", "-boolean", "-byte", "-char", "-short"]:
        FOUR_BIT.add(_p + _s)
for _op in ["add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"]:
    for _t in ["int", "long"]:
        FOUR_BIT.add("%s-%s/2addr" % (_op, _t))
    FOUR_BIT.add("%s-int/lit16" % _op)
for _op in ["add", "sub", "mul", "div", "rem"]:
    for _t in ["float", "double"]:
        FOUR_BIT.add("%s-%s/2addr" % (_op, _t))
FOUR_BIT.add("rsub-int")

# invoke-* in the 35c form also packs its register list 4 bits at a time.
INVOKE_35C = set(["invoke-virtual", "invoke-super", "invoke-direct",
                  "invoke-static", "invoke-interface",
                  "invoke-custom", "invoke-polymorphic"])

RESULT_PRODUCERS = set(list(INVOKE_35C) + [
    "invoke-virtual/range", "invoke-super/range", "invoke-direct/range",
    "invoke-static/range", "invoke-interface/range",
    "invoke-custom/range", "invoke-polymorphic/range",
    "filled-new-array", "filled-new-array/range",
])

MOVE_RESULTS = set(["move-result", "move-result-wide", "move-result-object"])

ACCESS_KEYWORDS = set([
    "public", "private", "protected", "static", "final", "synchronized",
    "volatile", "bridge", "transient", "varargs", "native", "interface",
    "abstract", "strictfp", "synthetic", "annotation", "enum", "constructor",
    "declared-synchronized",
])

REG_RE = re.compile(r"(?<![A-Za-z0-9_$])([vp])(\d+)(?![0-9])")

BLOCK_OPENERS = {
    ".array-data": ".end array-data",
    ".packed-switch": ".end packed-switch",
    ".sparse-switch": ".end sparse-switch",
    ".annotation": ".end annotation",
    ".subannotation": ".end subannotation",
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


def strip_strings(line):
    """Blank out the contents of string literals so register regexes cannot
    match inside them."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)


def parse_params(desc):
    """Split the parameter section of a method descriptor into descriptors.

    '(Ljava/lang/String;[IJ)Z'  ->  ['Ljava/lang/String;', '[I', 'J']
    """
    inner = desc[desc.index("(") + 1:desc.index(")")]
    out = []
    i = 0
    while i < len(inner):
        start = i
        while i < len(inner) and inner[i] == "[":
            i += 1
        if i >= len(inner):
            break
        if inner[i] == "L":
            end = inner.index(";", i)
            i = end + 1
        else:
            i += 1
        out.append(inner[start:i])
    return out


def words(descriptor):
    """How many 32-bit registers this parameter occupies."""
    return 2 if descriptor in ("J", "D") else 1


class Method(object):
    def __init__(self, decl, path, lineno):
        self.decl = decl               # the full .method line
        self.path = path
        self.lineno = lineno
        self.flags = set()
        self.name = ""
        self.descriptor = ""
        self.registers = None          # from .registers
        self.locals = None             # from .locals
        self.body = []                 # (lineno, text) instruction lines only
        self.labels = {}               # label -> index into self.body
        self.handler_labels = set()
        self.parse_decl()

    def parse_decl(self):
        toks = self.decl.split()
        for t in toks[1:]:
            if t in ACCESS_KEYWORDS:
                self.flags.add(t)
            else:
                sig = t
                if "(" in sig:
                    self.name = sig[:sig.index("(")]
                    self.descriptor = sig[sig.index("("):]
                break

    @property
    def is_static(self):
        return "static" in self.flags

    @property
    def has_body(self):
        return not ("abstract" in self.flags or "native" in self.flags)

    @property
    def ins_size(self):
        if not self.descriptor:
            return 0
        n = 0 if self.is_static else 1
        for p in parse_params(self.descriptor):
            n += words(p)
        return n

    @property
    def registers_size(self):
        if self.registers is not None:
            return self.registers
        if self.locals is not None:
            return self.locals + self.ins_size
        return None

    @property
    def first_param_reg(self):
        rs = self.registers_size
        if rs is None:
            return None
        return rs - self.ins_size

    def param_map(self):
        """Return a list of (pName, vIndex, descriptor, isWideHigh)."""
        base = self.first_param_reg
        if base is None:
            return []
        out = []
        idx = 0
        if not self.is_static:
            out.append(("p0", base, "this", False))
            idx = 1
        cur = base + (0 if self.is_static else 1)
        for p in parse_params(self.descriptor):
            out.append(("p%d" % idx, cur, p, False))
            idx += 1
            if words(p) == 2:
                out.append(("p%d" % idx, cur + 1, p + " (high half)", True))
                idx += 1
                cur += 2
            else:
                cur += 1
        return out

    def p_to_v(self, n):
        base = self.first_param_reg
        return None if base is None else base + n


def parse_file(path):
    """Return a list of Method objects."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.read().split("\n")

    methods = []
    cur = None
    skip_until = None

    for i, raw in enumerate(raw_lines, start=1):
        line = strip_comment(raw).strip()
        if not line:
            continue

        if skip_until is not None:
            if line.startswith(skip_until):
                skip_until = None
            continue

        if line.startswith(".method"):
            cur = Method(line, path, i)
            continue

        if line.startswith(".end method"):
            if cur is not None:
                methods.append(cur)
            cur = None
            continue

        if cur is None:
            continue

        if line.startswith(".registers"):
            try:
                cur.registers = int(line.split()[1], 0)
            except (IndexError, ValueError):
                pass
            continue
        if line.startswith(".locals"):
            try:
                cur.locals = int(line.split()[1], 0)
            except (IndexError, ValueError):
                pass
            continue
        if line.startswith(".catch"):
            m = re.search(r":(\S+)\s*$", line)
            if m:
                cur.handler_labels.add(":" + m.group(1))
            continue
        if line.startswith(":"):
            cur.labels[line.split()[0]] = len(cur.body)
            continue
        if line.startswith("."):
            head = line.split()[0]
            if head in BLOCK_OPENERS:
                skip_until = BLOCK_OPENERS[head]
            continue

        cur.body.append((i, line))

    return methods


def registers_in(text):
    """Yield (kind, number, token) for every register reference on a line."""
    for m in REG_RE.finditer(strip_strings(text)):
        yield m.group(1), int(m.group(2)), m.group(0)


def check(method):
    """Return a list of (severity, lineno, message)."""
    issues = []
    if not method.has_body:
        return issues

    rs = method.registers_size
    if rs is None:
        issues.append(("ERROR", method.lineno,
                       "method has a body but no .registers or .locals directive"))
        return issues

    base = method.first_param_reg
    if base < 0:
        issues.append(("ERROR", method.lineno,
                       "frame is too small: ins_size=%d needs at least that many "
                       "registers, but registers_size=%d" % (method.ins_size, rs)))
        return issues

    param_regs = set(range(base, rs))

    # 1 / 2 -- adjacency rules.
    prev_mnemonic = None
    for idx, (ln, text) in enumerate(method.body):
        mnemonic = text.split()[0].rstrip(",")

        if mnemonic in MOVE_RESULTS:
            if prev_mnemonic not in RESULT_PRODUCERS:
                issues.append((
                    "VERIFY", ln,
                    "%s does not immediately follow an invoke (previous "
                    "instruction is '%s'). This is a VerifyError at class load."
                    % (mnemonic, prev_mnemonic or "start of method")))

        if mnemonic == "move-exception":
            at_handler_start = False
            for lbl, pos in method.labels.items():
                if pos == idx and lbl in method.handler_labels:
                    at_handler_start = True
                    break
            if not at_handler_start:
                issues.append((
                    "VERIFY", ln,
                    "move-exception is not the first instruction of a labelled "
                    "catch handler. Legal only at handler entry."))

        # 3 / 4 -- register range and field width.
        four_bit = mnemonic in FOUR_BIT
        invoke_35c = mnemonic in INVOKE_35C
        for kind, num, token in registers_in(text):
            vnum = num if kind == "v" else method.p_to_v(num)
            if vnum is None:
                continue
            if kind == "p" and num >= method.ins_size:
                issues.append((
                    "ASSEMBLE", ln,
                    "%s does not exist: the method has only %d incoming register "
                    "words (p0..p%d)"
                    % (token, method.ins_size, max(method.ins_size - 1, 0))))
                continue
            if vnum >= rs:
                issues.append((
                    "ASSEMBLE", ln,
                    "%s resolves to v%d but registers_size is %d. Raise .locals."
                    % (token, vnum, rs)))
            elif vnum > 15 and (four_bit or invoke_35c):
                where = "the register list of a 35c invoke" if invoke_35c \
                    else "a 4-bit field"
                issues.append((
                    "ASSEMBLE", ln,
                    "%s resolves to v%d, but '%s' encodes it in %s (v0-v15 only). "
                    "Use a low register, the /from16 variant, or /range."
                    % (token, vnum, mnemonic, where)))

            # 5 -- raw v-number aliasing a parameter.
            if kind == "v" and num in param_regs and method.registers is not None:
                pnum = num - base
                issues.append((
                    "FRAGILE", ln,
                    "raw v%d is parameter p%d. Correct today, but raising "
                    ".registers moves the parameters and this reference will not "
                    "move with them. Write p%d instead."
                    % (num, pnum, pnum)))

        prev_mnemonic = mnemonic

    return issues


def describe(method, out):
    w = out.write
    sig = "%s%s" % (method.name, method.descriptor)
    w("\n" + "-" * 72 + "\n")
    w("%s\n" % sig)
    w("  flags            %s\n" % (" ".join(sorted(method.flags)) or "(none)"))
    if not method.has_body:
        w("  no body (abstract or native) -- no frame\n")
        return
    rs = method.registers_size
    if rs is None:
        w("  !! no .registers or .locals directive\n")
        return
    w("  directive        %s\n"
      % (".registers %d" % method.registers if method.registers is not None
         else ".locals %d" % method.locals))
    w("  registers_size   %d\n" % rs)
    w("  ins_size         %d word(s)%s\n"
      % (method.ins_size, "" if method.is_static else "  (includes 'this')"))
    w("  first param reg  v%d      (registers_size - ins_size)\n"
      % method.first_param_reg)
    w("  free for locals  v0..v%d  (%d register(s))\n"
      % (method.first_param_reg - 1, method.first_param_reg)
      if method.first_param_reg > 0 else
      "  free for locals  none -- every register holds a parameter\n")
    w("  body             %d instruction(s)\n" % len(method.body))
    pm = method.param_map()
    if pm:
        w("\n  alias   register   holds\n")
        for name, vidx, desc, high in pm:
            w("  %-6s  v%-8d  %s\n" % (name, vidx, desc))


def main():
    ap = argparse.ArgumentParser(
        description="Compute Smali register frames and find patching hazards.")
    ap.add_argument("paths", nargs="*",
                    help=".smali files or directories")
    ap.add_argument("--method", help="only methods whose name matches this")
    ap.add_argument("--check", action="store_true",
                    help="run the five hazard checks")
    ap.add_argument("--quiet", action="store_true",
                    help="with --check, print only files that have hazards")
    ap.add_argument("--descriptor",
                    help="standalone mode: a method descriptor such as '(JI)Z'")
    ap.add_argument("--registers", type=int,
                    help="standalone mode: the .registers value")
    ap.add_argument("--instance", action="store_true",
                    help="standalone mode: treat as an instance method")
    args = ap.parse_args()

    if args.descriptor:
        if args.registers is None:
            sys.stderr.write("--descriptor needs --registers\n")
            return 2
        m = Method(".method %s x%s" % ("public" if args.instance else "static",
                                       args.descriptor), "<stdin>", 0)
        m.name = "x"
        m.descriptor = args.descriptor
        m.flags = set() if args.instance else set(["static"])
        m.registers = args.registers
        describe(m, sys.stdout)
        return 0

    if not args.paths:
        sys.stderr.write("give at least one path, or use --descriptor\n")
        return 2

    files = []
    for p in args.paths:
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

    if not files:
        sys.stderr.write("no .smali files found\n")
        return 2

    total_issues = 0
    counts = {"ERROR": 0, "VERIFY": 0, "ASSEMBLE": 0, "FRAGILE": 0}

    for f in files:
        methods = parse_file(f)
        if args.method:
            methods = [m for m in methods if args.method in m.name]
        if not methods:
            continue

        if args.check:
            file_issues = []
            for m in methods:
                for sev, ln, msg in check(m):
                    file_issues.append((sev, ln, m.name + m.descriptor, msg))
                    counts[sev] = counts.get(sev, 0) + 1
            total_issues += len(file_issues)
            if file_issues:
                sys.stdout.write("\n=== %s\n" % f)
                for sev, ln, sig, msg in sorted(file_issues, key=lambda x: x[1]):
                    sys.stdout.write("  [%-8s] line %-5d %s\n" % (sev, ln, sig))
                    sys.stdout.write("             %s\n" % msg)
            elif not args.quiet:
                sys.stdout.write("=== %s  -- clean (%d method(s))\n"
                                 % (f, len(methods)))
        else:
            sys.stdout.write("\n=== %s\n" % f)
            for m in methods:
                describe(m, sys.stdout)

    if args.check:
        sys.stdout.write("\n" + "=" * 72 + "\n")
        sys.stdout.write("%d file(s) scanned, %d issue(s):"
                         "  ERROR=%d VERIFY=%d ASSEMBLE=%d FRAGILE=%d\n"
                         % (len(files), total_issues, counts["ERROR"],
                            counts["VERIFY"], counts["ASSEMBLE"],
                            counts["FRAGILE"]))
        sys.stdout.write(
            "FRAGILE is informational: those lines are correct now and become\n"
            "wrong the moment you change .registers. See README section 3.2.\n")
        return 1 if counts["ERROR"] or counts["VERIFY"] or counts["ASSEMBLE"] else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
