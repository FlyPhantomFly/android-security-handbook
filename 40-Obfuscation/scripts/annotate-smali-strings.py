#!/usr/bin/env python3
"""
annotate-smali-strings.py
===========================================================================
WHAT IT DOES
    Takes the strings you recovered at runtime and writes them back into the
    Smali, as comments, at the exact call sites that produce them.

    Before:

        const/16 v0, 0x2f
        invoke-static {v0}, Lcom/x/a/q;->a(I)Ljava/lang/String;
        move-result-object v1
        invoke-static {v1, v2}, Lcom/x/b/c;->d(Ljava/lang/String;Ljava/lang/String;)V

    After:

        const/16 v0, 0x2f
        invoke-static {v0}, Lcom/x/a/q;->a(I)Ljava/lang/String;    # [str] "https://api.example.com/v2/transfer"
        move-result-object v1
        invoke-static {v1, v2}, Lcom/x/b/c;->d(Ljava/lang/String;Ljava/lang/String;)V

    You now know, without running anything, that this method talks to the
    transfer endpoint.

WHY IT MATTERS
    Chapter 40 section 6.1 puts string recovery at Phase 4 — before control
    flow, before renaming — because after identifier renaming, strings are the
    only remaining semantics. But a flat list of four thousand recovered
    strings is a haystack. The same four thousand strings placed next to the
    call sites that use them is a MAP.

    That is the difference this script makes, and section 6.1 calls it "the
    highest-leverage twenty lines of scripting in Android RE" for a reason:
    it converts a dump into readable code, mechanically, at scale, in seconds.

    Once the Smali is annotated you can grep it:

        grep -rn '\\[str\\].*api\\|token\\|password' apktool_out/smali*

    ...and land directly in the methods that matter, skipping every method the
    strings say is uninteresting. That is usually the moment an obfuscated app
    stops being frightening.

HOW TO RUN
    # host — 1. recover the strings
    frida -U -f com.target.app -l frida-string-decryptor.js --pause
    #   sd.candidates() ; sd.exhaust("com.x.a.q", "a", 0, 4096) ; sd.save()
    adb pull /data/local/tmp/strings-dump.json .

    # host — 2. decode the app
    apktool d -f -o apktool_out target.apk

    # host — 3. annotate (dry run first — always)
    python3 annotate-smali-strings.py --smali apktool_out --json strings-dump.json
    python3 annotate-smali-strings.py --smali apktool_out --json strings-dump.json --write

    # host — 4. read the result
    grep -rn '\\[str\\]' apktool_out/smali*/com/x/ | less

REQUIREMENTS
    Python 3.8+. No third-party packages. Reads only files you point it at and
    writes only when you pass --write.

INPUT FORMATS
    --json  the file written by frida-string-decryptor.js:
              [ {"source": "com.x.a.q.a", "args": "47", "value": "..."} , ... ]
            "args" may be a bare index ("47") or a tuple ("(47,3,0)").

    --map   a simple TSV alternative, for strings you recovered by hand:
              com.x.a.q.a <TAB> 47 <TAB> https://api.example.com

    --plain a newline-separated list of plaintext strings with no call-site
            information. These cannot be placed at call sites; they are
            appended as a legend at the end of each file that references the
            decryptor, which is still better than nothing.

WHAT IT CANNOT DO — read this before trusting the output
    The register tracking here is deliberately simple: a linear scan that
    remembers the last literal assigned to each register within a method. It
    is correct for the overwhelmingly common shape emitted by string
    obfuscators (a constant loaded immediately before the call) and it is
    WRONG whenever:

      - the index arrives from a field, an array, or another method's return
      - the constant is assigned in a different basic block (a loop, a branch)
      - a register is reassigned between the const and the invoke by code the
        scanner does not model

    Unresolved call sites are reported, not guessed. An annotation is evidence;
    a missing annotation is not evidence of absence. When a value matters,
    confirm it dynamically.

AUTHORISED TESTING ONLY.
===========================================================================
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

# ---------------------------------------------------------------------------
# Smali patterns
# ---------------------------------------------------------------------------

# .method public static a(I)Ljava/lang/String;
RE_METHOD_START = re.compile(r'^\s*\.method\b')
RE_METHOD_END = re.compile(r'^\s*\.end method\b')

# const/4 v0, 0x2      const/16 v0, 0x2f      const v0, 0x1f4      const-wide/16 ...
RE_CONST_NUM = re.compile(
    r'^\s*const(?:/4|/16|/high16|-wide/16|-wide/32|-wide/high16|-wide)?\s+'
    r'([vp]\d+)\s*,\s*(-?0x[0-9a-fA-F]+|-?\d+)\s*$')

# const-string v0, "ciphertext"      const-string/jumbo v0, "..."
RE_CONST_STR = re.compile(
    r'^\s*const-string(?:/jumbo)?\s+([vp]\d+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*$')

# invoke-static {v0, v1}, Lcom/x/a/q;->a(II)Ljava/lang/String;
RE_INVOKE = re.compile(
    r'^\s*invoke-(?:static|virtual|direct|super|interface)'
    r'(?:/range)?\s*\{([^}]*)\}\s*,\s*'
    r'L([^;]+);->([^(]+)\(([^)]*)\)(\S+)\s*$')

# Registers can be written as a range: {v0 .. v3}
RE_RANGE = re.compile(r'^\s*([vp]\d+)\s*\.\.\s*([vp]\d+)\s*$')

# An annotation we previously added, so re-running is idempotent.
ANNOTATION = '# [str]'


def parse_int(token):
    """Parse a Smali numeric literal into a Python int."""
    t = token.strip()
    neg = t.startswith('-')
    if neg:
        t = t[1:]
    try:
        v = int(t, 16) if t.lower().startswith('0x') else int(t, 10)
    except ValueError:
        return None
    return -v if neg else v


def expand_registers(spec):
    """'{v0, v1}' body -> ['v0','v1'];  'v0 .. v3' -> ['v0','v1','v2','v3']."""
    spec = spec.strip()
    if not spec:
        return []
    m = RE_RANGE.match(spec)
    if m:
        kind = m.group(1)[0]
        lo = int(m.group(1)[1:])
        hi = int(m.group(2)[1:])
        if hi < lo or hi - lo > 64:
            return []
        return [f'{kind}{i}' for i in range(lo, hi + 1)]
    return [r.strip() for r in spec.split(',') if r.strip()]


# ---------------------------------------------------------------------------
# Loading recovered strings
# ---------------------------------------------------------------------------

class StringTable:
    """
    Maps (class_dotted, method_name, args_key) -> plaintext.

    args_key is a tuple of stringified arguments, so that a single-argument
    decryptor keyed on 47 and a three-argument one keyed on (47, 3, 0) both
    work without special cases.
    """

    def __init__(self):
        self.by_key = {}
        self.by_class_method = defaultdict(list)
        self.plain = []

    @staticmethod
    def _norm_args(raw):
        s = str(raw).strip()
        if s.startswith('(') and s.endswith(')'):
            s = s[1:-1]
        if s == '':
            return ()
        parts = [p.strip() for p in s.split(',')]
        out = []
        for p in parts:
            # Normalise numeric arguments so 0x2f and 47 collide correctly.
            n = parse_int(p)
            out.append(str(n) if n is not None else p.strip('"'))
        return tuple(out)

    def add(self, source, args, value):
        if '.' not in source:
            return
        cls, _, meth = source.rpartition('.')
        key = (cls, meth, self._norm_args(args))
        self.by_key[key] = value
        self.by_class_method[(cls, meth)].append((key[2], value))

    def add_plain(self, value):
        self.plain.append(value)

    def lookup(self, cls, meth, args):
        return self.by_key.get((cls, meth, tuple(str(a) for a in args)))

    def knows_method(self, cls, meth):
        return (cls, meth) in self.by_class_method

    def __len__(self):
        return len(self.by_key)


def load_json(path, table):
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get('results', [])
    for row in data:
        try:
            table.add(row['source'], row.get('args', ''), row['value'])
        except (KeyError, TypeError):
            continue


def load_map(path, table):
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line or line.lstrip().startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            table.add(parts[0].strip(), parts[1].strip(), '\t'.join(parts[2:]))


def load_plain(path, table):
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            s = line.rstrip('\n')
            if s:
                table.add_plain(s)


# ---------------------------------------------------------------------------
# Annotation
# ---------------------------------------------------------------------------

def escape_for_comment(value, max_len):
    s = value.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
    if len(s) > max_len:
        s = s[:max_len - 3] + '...'
    return s


class Stats:
    def __init__(self):
        self.files_scanned = 0
        self.files_changed = 0
        self.invokes_seen = 0
        self.decryptor_calls = 0
        self.resolved = 0
        self.unresolved = 0
        self.already = 0
        self.unresolved_examples = []


def annotate_file(path, table, stats, args):
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        lines = fh.read().split('\n')

    out = []
    regs = {}          # register -> literal (int or str), within one method
    changed = False
    in_method = False
    used_plain = False

    for idx, line in enumerate(lines):
        if RE_METHOD_START.match(line):
            in_method = True
            regs = {}
            out.append(line)
            continue
        if RE_METHOD_END.match(line):
            in_method = False
            regs = {}
            out.append(line)
            continue

        if in_method:
            m = RE_CONST_NUM.match(line)
            if m:
                v = parse_int(m.group(2))
                if v is not None:
                    regs[m.group(1)] = str(v)
                out.append(line)
                continue

            m = RE_CONST_STR.match(line)
            if m:
                regs[m.group(1)] = m.group(2)
                out.append(line)
                continue

            m = RE_INVOKE.match(line)
            if m:
                stats.invokes_seen += 1
                reg_spec, cls_slash, meth, sig_args, ret = m.groups()
                cls_dotted = cls_slash.replace('/', '.')

                # Only care about calls that return a String and that we have
                # recovered data for. Everything else is left untouched.
                if table.knows_method(cls_dotted, meth):
                    stats.decryptor_calls += 1

                    if ANNOTATION in line:
                        stats.already += 1
                        out.append(line)
                        continue

                    registers = expand_registers(reg_spec)
                    values = [regs.get(r) for r in registers]

                    plaintext = None
                    if all(v is not None for v in values):
                        plaintext = table.lookup(cls_dotted, meth, values)
                        # Some decryptors take (index, junk, junk); try the
                        # first argument alone before giving up.
                        if plaintext is None and len(values) > 1:
                            plaintext = table.lookup(cls_dotted, meth, values[:1])

                    if plaintext is not None:
                        note = escape_for_comment(plaintext, args.max_len)
                        line = f'{line}    {ANNOTATION} "{note}"'
                        stats.resolved += 1
                        changed = True
                    else:
                        stats.unresolved += 1
                        if len(stats.unresolved_examples) < 20:
                            stats.unresolved_examples.append(
                                f'{path}:{idx + 1}  {cls_dotted}.{meth} '
                                f'regs={registers} known={values}')
                        if args.mark_unresolved:
                            line = (f'{line}    {ANNOTATION} <unresolved: '
                                    f'args not literal at this call site>')
                            changed = True

                    # Registers holding the return value are handled by the
                    # following move-result-object; we do not model that, and
                    # we deliberately do not guess.
                out.append(line)
                continue

        out.append(line)

    # Plain-list legend: no call sites available, so append what we have to any
    # file that referenced a known decryptor at all.
    if table.plain and args.plain_legend and stats.decryptor_calls > 0:
        out.append('')
        out.append('# ---- recovered strings (no call-site mapping available) ----')
        for s in table.plain[:args.legend_limit]:
            out.append(f'#   {escape_for_comment(s, args.max_len)}')
        if len(table.plain) > args.legend_limit:
            out.append(f'#   ... and {len(table.plain) - args.legend_limit} more')
        changed = True
        used_plain = True

    if changed and args.write:
        if args.backup:
            bak = path + '.orig'
            if not os.path.exists(bak):
                with open(bak, 'w', encoding='utf-8') as fh:
                    fh.write('\n'.join(lines))
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(out))

    if changed:
        stats.files_changed += 1
    return changed


def walk_smali(root):
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith('.smali'):
                yield os.path.join(dirpath, name)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

TRIAGE = [
    ('endpoints',
     re.compile(r'https?://|/api/|/v[0-9]+/|\.com\b|\.net\b', re.I)),
    ('credentials',
     re.compile(r'key|secret|token|password|passwd|pwd|auth|bearer|api[-_]?key', re.I)),
    ('crypto',
     re.compile(r'\bAES\b|\bRSA\b|HMAC|SHA-?\d|PBKDF|\bECB\b|\bCBC\b|\bGCM\b|PKCS', re.I)),
    ('anti-analysis',
     re.compile(r'(^|/)su$|/system/bin|magisk|frida|xposed|emulator|goldfish|'
                r'ptrace|TracerPid', re.I)),
    ('sql',
     re.compile(r'\bselect\s|\binsert\s|\bupdate\s|\bdelete\s|\bfrom\s|\bwhere\s', re.I)),
    ('files',
     re.compile(r'^/(data|sdcard|storage|proc|sys)/')),
]


def print_triage(table):
    values = list(table.by_key.values()) + table.plain
    if not values:
        return
    print('\n=== recovered-string triage ===')
    print('    (section 6.1 phase 4: these are the four buckets that pay)')
    for name, pattern in TRIAGE:
        hits = sorted({v for v in values if pattern.search(v)})
        print(f'\n  {name}: {len(hits)}')
        for h in hits[:12]:
            print(f'      {escape_for_comment(h, 110)}')
        if len(hits) > 12:
            print(f'      ... and {len(hits) - 12} more')


def main():
    ap = argparse.ArgumentParser(
        description='Annotate Smali with strings recovered at runtime.',
        epilog='Dry run by default. Pass --write to modify files.')
    ap.add_argument('--smali', required=True,
                    help='apktool output directory (contains smali*/ trees)')
    ap.add_argument('--json',
                    help='strings-dump.json from frida-string-decryptor.js')
    ap.add_argument('--map',
                    help='TSV: <class.method> TAB <args> TAB <plaintext>')
    ap.add_argument('--plain',
                    help='newline-separated plaintext strings, no call sites')
    ap.add_argument('--write', action='store_true',
                    help='actually modify the .smali files (default: dry run)')
    ap.add_argument('--backup', action='store_true',
                    help='keep a .orig copy of every file modified')
    ap.add_argument('--max-len', type=int, default=160,
                    help='truncate annotations longer than this (default 160)')
    ap.add_argument('--mark-unresolved', action='store_true',
                    help='also comment call sites whose arguments were not literal')
    ap.add_argument('--plain-legend', action='store_true',
                    help='append the --plain list as a legend in touched files')
    ap.add_argument('--legend-limit', type=int, default=200,
                    help='maximum legend entries per file (default 200)')
    ap.add_argument('--filter',
                    help='only process files whose path contains this substring')
    ap.add_argument('--triage', action='store_true',
                    help='print the endpoint/credential/crypto triage buckets')
    args = ap.parse_args()

    if not os.path.isdir(args.smali):
        print(f'error: {args.smali} is not a directory', file=sys.stderr)
        return 2
    if not (args.json or args.map or args.plain):
        print('error: supply at least one of --json, --map, --plain',
              file=sys.stderr)
        return 2

    table = StringTable()
    if args.json:
        load_json(args.json, table)
    if args.map:
        load_map(args.map, table)
    if args.plain:
        load_plain(args.plain, table)

    print(f'loaded {len(table)} call-site-mapped string(s), '
          f'{len(table.plain)} unmapped')
    if len(table) == 0 and not table.plain:
        print('nothing to do — is the JSON in the expected format?')
        return 1

    known = sorted(table.by_class_method.items(),
                   key=lambda kv: -len(kv[1]))
    print(f'decryptor(s) referenced: {len(known)}')
    for (cls, meth), entries in known[:10]:
        print(f'    {cls}.{meth}  ({len(entries)} entries)')
    if len(known) > 10:
        print(f'    ... and {len(known) - 10} more')

    stats = Stats()
    for path in walk_smali(args.smali):
        if args.filter and args.filter not in path:
            continue
        stats.files_scanned += 1
        annotate_file(path, table, stats, args)

    print('\n=== results ===')
    print(f'  files scanned          : {stats.files_scanned}')
    print(f'  invoke instructions    : {stats.invokes_seen}')
    print(f'  calls to known decryptors: {stats.decryptor_calls}')
    print(f'  annotated              : {stats.resolved}')
    print(f'  already annotated      : {stats.already}')
    print(f'  unresolved             : {stats.unresolved}')
    print(f'  files changed          : {stats.files_changed}'
          f'{"" if args.write else "  (DRY RUN — nothing written)"}')

    if stats.unresolved and stats.unresolved_examples:
        print('\n  unresolved examples (arguments were not literal at the call site):')
        for e in stats.unresolved_examples:
            print(f'    {e}')
        print('\n  These are expected. The index may come from a field, an array,')
        print('  a loop variable, or another method. A missing annotation is NOT')
        print('  evidence that the call is uninteresting — confirm dynamically')
        print('  with frida-string-decryptor.js sd.harvest().')

    if stats.decryptor_calls == 0:
        print('\n  No call sites matched. Check that:')
        print('    - the class names in the JSON match the Smali (a packed app')
        print('      may have been decompiled from a DIFFERENT dump)')
        print('    - you decoded the same APK you instrumented')
        print('    - the decryptor is invoked directly rather than reflectively')

    if args.triage:
        print_triage(table)

    if not args.write and stats.resolved:
        print('\n  Re-run with --write to apply. Then read the result:')
        print(f"    grep -rn '\\[str\\]' {args.smali}/smali*/ | less")
        print('    grep -rniE \'\\[str\\].*(api|token|password|key)\' '
              f'{args.smali}/smali*/')

    return 0


if __name__ == '__main__':
    sys.exit(main())
