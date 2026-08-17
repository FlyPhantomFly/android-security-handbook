#!/usr/bin/env python3
"""
find-check-shapes.py -- find the functions in an AArch64 shared library that
                        LOOK like boolean checks, and rank them by how easy
                        they would be to patch.

WHY THIS EXISTS
    Opening a 4 MB stripped .so in a decompiler and reading it function by
    function is not a plan. Almost every native "is this allowed?" check --
    licence validation, root detection, signature verification, emulator
    detection, pin comparison -- compiles to one of a very small number of
    shapes, and those shapes are mechanically findable:

        * a short function whose only job is a comparison and a `cset`
        * a function that returns a hard 0 or 1 on distinct paths
        * a function ending in `mov w0, wzr` / `ret` on one path and
          `mov w0, #1` / `ret` on another
        * a function that calls strcmp/strstr/access/fopen and then branches

    This script sweeps .text for those shapes and prints the candidates with
    the exact address you would hand to arm64-patch.py. It is a TRIAGE tool:
    it tells you where to look, never what is true.

HOW TO RUN
    python3 find-check-shapes.py liblicence.so
    python3 find-check-shapes.py liblicence.so --max-insns 24
    python3 find-check-shapes.py libnative.so --min-score 3 --show
    python3 find-check-shapes.py libnative.so --json

    A worked flow:
    python3 find-check-shapes.py liblicence.so
    python3 arm64-patch.py liblicence.so --symbol lc_is_licensed --show
    python3 arm64-patch.py liblicence.so --symbol lc_is_licensed --skip 1 \
            --patch "mov w0,#1" --write

REQUIREMENTS
    Python 3.6+, standard library only. It imports the decoder and ELF reader
    from arm64-patch.py in the same directory -- keep the two together.

WHAT THIS WILL *NOT* TELL YOU
    - Whether a candidate is a security check. A function returning a boolean
      might be `isEmpty()`. The score is a shape score, nothing more, and a
      high score on a getter is not a bug in the script.
    - Anything about functions with no symbol AND no obvious boundary. It
      walks symbols; where a library is fully stripped of .symtab it sees only
      .dynsym exports, and internal helpers are invisible. Use the decompiler's
      function detection for those -- 57-Ghidra section 4.
    - Anything about inlined checks. This is the big one. If the compiler
      inlined the check into its caller there is no function to find, and
      patching the standalone copy changes nothing that runs. README section
      5.4 has the worked case where exactly this happens.
    - Whether patching is the right move at all. A check whose result crosses
      to a server is not defeated by editing bytes on your own device.
    - Anything about ARM32 or Thumb. It refuses to run on ELF32.
"""

from __future__ import print_function

import argparse
import importlib.util
import json
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PATCHER = os.path.join(_HERE, "arm64-patch.py")

if not os.path.exists(_PATCHER):
    sys.exit("arm64-patch.py must sit next to this script; it holds the "
             "ELF reader and the instruction decoder.")

_spec = importlib.util.spec_from_file_location("arm64_patch", _PATCHER)
_ap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ap)

# Imports whose presence in a function is evidence of a decision being made
# about the outside world rather than about arithmetic.
INTERESTING_CALLS = {
    "strcmp": "string comparison",
    "strncmp": "string comparison",
    "memcmp": "buffer comparison",
    "strstr": "substring search",
    "strlen": "length check",
    "access": "filesystem probe",
    "fopen": "filesystem probe",
    "stat": "filesystem probe",
    "lstat": "filesystem probe",
    "open": "filesystem probe",
    "opendir": "directory probe",
    "readlink": "path resolution",
    "popen": "shell out",
    "system": "shell out",
    "fork": "process creation",
    "ptrace": "anti-debug",
    "getpid": "process identity",
    "gettid": "thread identity",
    "__system_property_get": "system property read",
    "property_get": "system property read",
    "sprintf": "string building",
    "snprintf": "string building",
}


def load_plt_map(elf):
    """address of each PLT stub -> imported symbol name.

    A PLT stub on AArch64 is exactly four instructions:
        adrp x16, <page>
        ldr  x17, [x16, #off]
        add  x16, x16, #off
        br   x17
    and the GOT slot it names is the r_offset of a JUMP_SLOT relocation. Rather
    than parse .rela.plt (that is 15-Native-Code's job and its elf-inspect.py
    does it properly), this uses a cheaper route that is good enough for
    triage: symbol names ending in the linker's own PLT naming, plus any
    .symtab/.dynsym FUNC entry that falls inside .plt.
    """
    plt = {}
    sec = None
    for s in elf.sections:
        if s.get("name") == ".plt":
            sec = s
            break
    if sec is None:
        return plt

    # Walk .rela.plt to pair GOT slots with names, then pair stubs with slots
    # in order -- the linker emits them in the same order, which is not
    # guaranteed by the standard but is true of every Android toolchain.
    relaplt = None
    dynsym = None
    dynstr = None
    for s in elf.sections:
        if s.get("name") == ".rela.plt":
            relaplt = s
        elif s.get("name") == ".dynsym":
            dynsym = s
        elif s.get("name") == ".dynstr":
            dynstr = s
    if not (relaplt and dynsym and dynstr):
        return plt

    names = []
    n = relaplt["size"] // 24
    for i in range(n):
        off = relaplt["offset"] + i * 24
        r_info = struct.unpack_from("<Q", elf.data, off + 8)[0]
        symidx = r_info >> 32
        soff = dynsym["offset"] + symidx * 24
        st_name = struct.unpack_from("<I", elf.data, soff)[0]
        blob = elf.data[dynstr["offset"]:dynstr["offset"] + dynstr["size"]]
        end = blob.find(b"\x00", st_name)
        names.append(blob[st_name:end].decode("utf-8", "replace"))

    # The first 32 bytes of .plt are the resolver header; stubs are 16 bytes.
    stub0 = sec["addr"] + 32
    for i, nm in enumerate(names):
        plt[stub0 + i * 16] = nm
    return plt


def functions(elf):
    """(name, addr, size) for every FUNC symbol inside an executable section."""
    out = []
    for name, (addr, size, table, thumb) in elf.symbols().items():
        if size < 8 or size > 4096:
            continue
        if name.startswith("$"):
            continue
        off, seg = elf.vaddr_to_offset(addr)
        if off is None:
            continue
        if not (seg["flags"] & 1):          # PF_X
            continue
        out.append((name, addr, size, table))
    out.sort(key=lambda t: t[1])
    # de-duplicate: the same address can appear in both .symtab and .dynsym
    seen = set()
    uniq = []
    for name, addr, size, table in out:
        if addr in seen:
            continue
        seen.add(addr)
        uniq.append((name, addr, size, table))
    return uniq


def analyse(elf, name, addr, size, plt, max_insns):
    n = min(size // 4, max_insns)
    off, _ = elf.vaddr_to_offset(addr)
    words = struct.unpack_from("<%dI" % n, elf.data, off)
    text = [_ap.decode(w, addr + i * 4) for i, w in enumerate(words)]

    score = 0
    why = []
    calls = []

    joined = " | ".join(text)

    # 1. cset -- the branchless boolean. The single strongest signal.
    csets = [i for i, t in enumerate(text) if t.startswith("cset")]
    if csets:
        score += 3
        why.append("cset at +0x%x (the boolean is produced here)" % (csets[0] * 4))

    # 2. returns a literal 0 and a literal 1 on different paths
    has0 = any(t.startswith("mov") and (", wzr" in t or t.endswith(", #0"))
               for t in text)
    has1 = any(t.startswith("mov") and t.endswith(", #1") for t in text)
    if has0 and has1:
        score += 2
        why.append("returns both a literal 0 and a literal 1")
    elif has0 or has1:
        score += 1
        why.append("returns a literal boolean on at least one path")

    # 3. short. A check is usually small; a parser is not.
    if size <= 64:
        score += 2
        why.append("only %d bytes -- a whole function this small is doing "
                   "one thing" % size)
    elif size <= 160:
        score += 1

    # 4. calls something that looks at the world
    for i, w in enumerate(words):
        if (w & 0xFC000000) != 0x94000000:      # bl
            continue
        imm = _ap._sx(w & 0x03FFFFFF, 26) * 4
        target = addr + i * 4 + imm
        nm = plt.get(target)
        if nm:
            first_time = nm not in calls
            calls.append(nm)
            # Score each distinct import once. A loop that calls fopen five
            # times is one behaviour, not five, and counting it five times
            # buries genuinely different candidates underneath it.
            if first_time and nm in INTERESTING_CALLS:
                score += 2
                why.append("calls %s (%s)" % (nm, INTERESTING_CALLS[nm]))

    # 5. a comparison against a printable ASCII constant -- a magic byte check
    for i, t in enumerate(text):
        if t.startswith("cmp") and "#" in t:
            try:
                v = int(t.split("#")[1].split(",")[0])
            except ValueError:
                continue
            if 32 <= v <= 126:
                score += 1
                why.append("compares against %d ('%s') at +0x%x -- a literal "
                           "character test" % (v, chr(v), i * 4))
                break

    # 6. multiple conditional branches to one place: the classic
    #    "any failure returns 0" shape
    bcond = sum(1 for t in text if t.startswith("b.") or
                t.startswith("cbz") or t.startswith("cbnz") or
                t.startswith("tbz") or t.startswith("tbnz"))
    if bcond >= 3:
        score += 1
        why.append("%d conditional branches -- several checks feeding one "
                   "answer" % bcond)

    # 7. name heuristics, last and weakest, because a stripped library has none
    lowered = name.lower()
    for kw in ("check", "verify", "valid", "is_", "isroot", "root", "licen",
               "signature", "auth", "detect", "emulator", "debug", "tamper"):
        if kw in lowered:
            score += 2
            why.append("name contains %r" % kw)
            break

    # The patch suggestion: where the boolean is decided.
    suggestion = None
    if csets:
        a = addr + csets[0] * 4
        suggestion = ('--vaddr 0x%x --patch "mov w0,#1"' % a,
                      "replace the cset that computes the answer")
    elif has0 or has1:
        suggestion = ('--vaddr 0x%x --patch "mov w0,#1" --patch ret' % addr,
                      "overwrite the first two instructions of the function")

    return dict(name=name, addr=addr, size=size, score=score, why=why,
                calls=calls, text=text, suggestion=suggestion)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Find patch-shaped boolean checks in an AArch64 .so.")
    ap.add_argument("file")
    ap.add_argument("--min-score", type=int, default=3,
                    help="hide candidates below this shape score (default 3)")
    ap.add_argument("--max-insns", type=int, default=64,
                    help="instructions to read per function (default 64)")
    ap.add_argument("--show", action="store_true",
                    help="print the disassembly of each candidate")
    ap.add_argument("--json", action="store_true", help="machine-readable")
    args = ap.parse_args(argv)

    with open(args.file, "rb") as fh:
        data = fh.read()
    elf = _ap.Elf(data)

    if elf.arch != "aarch64":
        sys.exit("this script only handles AArch64 (%s found). ARM32 and Thumb "
                 "need a variable-length decoder; README section 3.13."
                 % elf.arch)

    plt = load_plt_map(elf)
    results = []
    for name, addr, size, table in functions(elf):
        r = analyse(elf, name, addr, size, plt, args.max_insns)
        r["table"] = table
        if r["score"] >= args.min_score:
            results.append(r)
    results.sort(key=lambda r: (-r["score"], r["addr"]))

    if args.json:
        for r in results:
            r.pop("text", None)
            r["addr"] = "0x%x" % r["addr"]
        print(json.dumps(results, indent=2))
        return 0

    print("%s -- %d candidate check-shaped functions "
          "(score >= %d)" % (os.path.basename(args.file), len(results),
                             args.min_score))
    print("Shape score only. Nothing here is a finding; it is a reading list.\n")

    for r in results:
        print("=" * 72)
        print("%-40s  0x%08x  %d bytes  score %d"
              % (r["name"], r["addr"], r["size"], r["score"]))
        for w in r["why"]:
            print("   - " + w)
        if r["calls"]:
            counts = {}
            for c in r["calls"]:
                counts[c] = counts.get(c, 0) + 1
            print("   calls: " + ", ".join(
                "%s%s" % (c, ("  x%d" % counts[c]) if counts[c] > 1 else "")
                for c in sorted(counts)))
        if r["suggestion"]:
            cmd, note = r["suggestion"]
            print("   try  : python3 arm64-patch.py %s %s --show"
                  % (os.path.basename(args.file), cmd.split(" --patch")[0]))
            print("          (%s)" % note)
        if args.show:
            print()
            for i, t in enumerate(r["text"]):
                print("     %08x  %s" % (r["addr"] + i * 4, t))
        print()

    if not results:
        print("Nothing scored that high. Lower --min-score, or the checks are "
              "inlined into their callers -- which is common at -O2 and is\n"
              "the case README section 5.4 works through.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
