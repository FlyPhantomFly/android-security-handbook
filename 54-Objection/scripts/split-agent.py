#!/usr/bin/env python3
# scripts/split-agent.py
#
# PURPOSE
#   Split objection's `agent.js` into its individual browserify modules, and
#   print a map from module number to source path -- so you can read what a
#   canned command actually does instead of guessing.
#
#   This is the single highest-value habit in the whole chapter. Every claim in
#   README sections 3.5 and 3.6 -- "android root disable installs exactly three
#   hooks", "the path list has thirteen entries", "android sslpinning disable
#   hard-codes an R8-obfuscated type name" -- was obtained by running this
#   script and reading the output. Your installed version is probably not the
#   one the chapter measured, so run it against yours rather than trusting the
#   numbers here.
#
#   agent.js is a browserify bundle: one file in which each module appears as
#       ],<N>:[function(require,module,exports){ ... }, {"../dep": 12, ...}]
#   The trailing object maps each `require()` path to the module number that
#   satisfies it, which is what lets this script recover human-readable names
#   for numbers.
#
# USAGE
#   # host -- split the installed agent into ./agent-modules/
#   python3 -B scripts/split-agent.py
#
#   # host -- choose the output directory
#   python3 -B scripts/split-agent.py --out /tmp/agent-modules
#
#   # host -- point at a specific agent.js (a different objection install)
#   python3 -B scripts/split-agent.py --agent /path/to/agent.js
#
#   # host -- just the map, write nothing
#   python3 -B scripts/split-agent.py --list
#
#   # host -- extract only the android modules
#   python3 -B scripts/split-agent.py --filter android
#
#   Then read them:
#     grep -n '"/' agent-modules/*android_root*.js         # the hard-coded paths
#     grep -oE 'Java\.use\("[^"]+"\)' agent-modules/*pinning*.js | sort -u
#     grep -oE '^\s+android[A-Za-z]+:' agent-modules/*api_android*.js
#
#   Run with `python3 -B` so no __pycache__ is written into the repository.
#
# REQUIREMENTS
#   Python 3.7+. Nothing else. It does not import objection (it only searches
#   sys.path for the file), it does not execute any JavaScript, and it does not
#   touch a device or the network.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * It will NOT deobfuscate or beautify. The bundle is compiled from
#     TypeScript with comments and identifier names preserved, so it is already
#     readable; this script only cuts it up. If a future release ships a
#     minified agent, the output will be one long line and you will want a
#     JavaScript formatter.
#   * It will NOT tell you which hooks WORK. It shows you what the agent
#     intends. Whether a hook installs depends on the app (is the class
#     present?) and whether it fires depends on the code path. README section
#     3.6.1 measured a hook that installs against an app that cannot possibly
#     use it.
#   * It will NOT prove your version behaves like the chapter's. That is the
#     point of running it.
#   * The module-number-to-name map is recovered from the bundle's own
#     dependency objects. A module that nothing requires by a relative path --
#     the bundle entry point, for instance -- will have no recovered name and is
#     written as `modNNN.js`. That is expected, not a failure.
#
# AUTHORISED TESTING ONLY.

import argparse
import os
import re
import sys

# ],<N>:[function(require,module,exports){
MODULE_RE = re.compile(r'\],(\d+):\[function\(require,module,exports\)\{')

# The dependency object that closes each module: {"../lib/color":117,"./x":87}
DEPS_RE = re.compile(r'\},\{("(?:[^"\\]|\\.)*":\d+(?:,"(?:[^"\\]|\\.)*":\d+)*)\}')

PAIR_RE = re.compile(r'"((?:[^"\\]|\\.)*)":(\d+)')


def find_agent():
    """Locate objection's agent.js without importing the package."""
    for base in sys.path:
        if not base:
            continue
        cand = os.path.join(base, 'objection', 'agent.js')
        if os.path.isfile(cand):
            return cand
    return None


def split(text):
    """Return [(number, source_text)] in bundle order."""
    marks = [(m.start(), int(m.group(1))) for m in MODULE_RE.finditer(text)]
    out = []
    for i, (pos, num) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append((num, text[pos:end]))
    return out


def recover_names(modules):
    """
    Build {number: friendly-name} from the dependency objects.

    Each module ends with a map of require-path -> module number. Reading all of
    them gives a name for (almost) every number. A number can be referenced by
    several different relative paths from different directories -- './lib/libjava'
    and '../android/lib/libjava' are the same module -- so the longest, most
    specific path is kept, which is the one that reads best as a filename.
    """
    names = {}
    for _, src in modules:
        for m in DEPS_RE.finditer(src):
            for path, num in PAIR_RE.findall(m.group(1)):
                num = int(num)
                cleaned = path.lstrip('./')
                if not cleaned:
                    continue
                if num not in names or len(cleaned) > len(names[num]):
                    names[num] = cleaned
    return names


def filename(num, names):
    friendly = names.get(num)
    if not friendly:
        return 'mod%03d.js' % num
    safe = re.sub(r'[^A-Za-z0-9]+', '_', friendly).strip('_')
    return 'mod%03d_%s.js' % (num, safe)


def main():
    ap = argparse.ArgumentParser(
        description="Split objection's agent.js into browserify modules.")
    ap.add_argument('--agent', default=None, help='path to agent.js')
    ap.add_argument('--out', default='agent-modules', help='output directory')
    ap.add_argument('--list', action='store_true',
                    help='print the module map and write nothing')
    ap.add_argument('--filter', default=None,
                    help='only handle modules whose recovered name contains this')
    args = ap.parse_args()

    agent = args.agent or find_agent()
    if not agent or not os.path.isfile(agent):
        print('error: could not find agent.js. Pass --agent /path/to/agent.js.\n'
              '       Locate it with:\n'
              '         python -c "import objection,os;'
              'print(os.path.dirname(objection.__file__))"', file=sys.stderr)
        return 2

    size = os.path.getsize(agent)
    with open(agent, encoding='utf-8', errors='replace') as fh:
        text = fh.read()

    modules = split(text)
    if not modules:
        print('error: no browserify module markers found in %s.\n'
              '       The bundle format may have changed in this release; the\n'
              '       marker this script looks for is:\n'
              '         ],<N>:[function(require,module,exports){'
              % agent, file=sys.stderr)
        return 2

    names = recover_names(modules)

    print('agent   : %s' % agent)
    print('size    : %d bytes' % size)
    print('modules : %d' % len(modules))
    print()

    selected = []
    for num, src in modules:
        friendly = names.get(num, '')
        if args.filter and args.filter not in friendly:
            continue
        selected.append((num, src, friendly))

    if args.filter:
        print('filter  : %r -> %d modules' % (args.filter, len(selected)))
        print()

    print('%-6s %-42s %s' % ('MODULE', 'SOURCE PATH', 'BYTES'))
    print('-' * 62)
    for num, src, friendly in sorted(selected):
        print('%-6d %-42s %d' % (num, friendly or '(no recovered name)', len(src)))

    if args.list:
        return 0

    os.makedirs(args.out, exist_ok=True)
    for num, src, friendly in selected:
        dest = os.path.join(args.out, filename(num, names))
        with open(dest, 'w', encoding='utf-8') as fh:
            fh.write(src)

    print()
    print('wrote %d files to %s/' % (len(selected), args.out))
    print()
    print('Start here:')
    print('  grep -n \'"/\'                 %s/*android_root*.js' % args.out)
    print('  grep -oE \'Java\\.use\\("[^"]+"\\)\'  %s/*pinning*.js | sort -u' % args.out)
    print('  grep -oE \'^\\s+android[A-Za-z]+:\'  %s/*api_android*.js' % args.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
