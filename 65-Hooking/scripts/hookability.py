#!/usr/bin/env python3
# scripts/hookability.py
"""
hookability.py -- decide, statically, whether an exported AArch64 function can
                  be safely inline-hooked, and say exactly what would go wrong.

WHAT IT DOES
    Given an ELF shared object and a symbol name, it answers the four questions
    you must answer before you overwrite a function prologue, and it answers
    them from the bytes rather than from optimism:

      1. IS THERE ROOM?
         A 16-byte absolute-jump patch needs 16 bytes of function. A 4-byte
         branch patch needs 4. Functions shorter than the patch exist, and
         patching one walks into the next function.

      2. WHICH DISPLACED INSTRUCTIONS ARE PC-RELATIVE?
         adrp, adr, ldr (literal), b, bl, b.cond, cbz/cbnz, tbz/tbnz all encode
         a displacement from their own address. Copy one to a trampoline
         unchanged and it computes the wrong answer, silently. The report says
         which are re-encodable (adrp is, within +/-4 GiB) and which this
         engine refuses.

      3. DOES ANYTHING BRANCH INTO THE PATCH REGION?
         This is the check almost nothing does, and the failure it prevents is
         the ugliest. If an instruction later in the function branches back to,
         say, target+8, then after patching it lands in the MIDDLE of your
         64-bit address literal and executes it as an instruction. The function
         will appear to work until that path is taken.

      4. IS THE FUNCTION EVEN CALLED?
         Scans every `bl` in .text for one that targets this symbol. Zero
         callers usually means the compiler inlined the body into its callers
         at -O2 -- in which case the hook will install perfectly and change
         nothing. See ../examples/libinline.c.

    It also reports whether the prologue opens with a BTI landing pad
    (`bti c`, 0xd503245f), because a patch that removes it can cause an
    indirect branch to fault on hardware with branch-target identification
    enabled.

HOW TO RUN
    # analyse one function
    python3 hookability.py libguard.so --symbol guard_check

    # analyse every exported function and print a summary table
    python3 hookability.py libguard.so --all

    # assume a 4-byte branch patch rather than the 16-byte absolute form
    python3 hookability.py libguard.so --symbol guard_check --patch-bytes 4

    # show the decoded prologue with reasons
    python3 hookability.py libinline.so --symbol lic_is_valid -v

    Run with `python3 -B` if you care about not leaving __pycache__ behind.

REQUIREMENTS
    Python 3.6+, standard library only. No pyelftools, no capstone, no NDK,
    no network, no device. It reads a file.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the hook is a good idea. It reports mechanical safety, not
      whether the function you picked is the one making the decision.
    - Whether the trampoline will be in range at RUNTIME. adrp reaches
      +/-4 GiB and `b` reaches +/-128 MiB, both measured from addresses that do
      not exist until the library is loaded. The script reports the RANGE
      REQUIREMENT; only the process can confirm it is met. Measured reality:
      an mmap() hint is advisory and was ignored on a real device, returning a
      page 10.3 GiB away -- see ../examples/trampoline-hook.c, alloc_near().
    - Anything about ARM32 or Thumb. The script refuses 32-bit ELF outright.
      Thumb instructions are 2 or 4 bytes and a fixed-size prologue patch on a
      variable-length encoding is wrong in ways that do not announce themselves.
    - Whether the function is reached through a PLT from another library. It
      analyses one file. A caller in a different .so is invisible here, so
      "0 callers" means "no caller in THIS file", which is stated as such.
    - Whether the target is hooked already, or whether the app is watching for
      hooks. That is 67-BypassingProtections' subject.

ACCURACY NOTE
    The instruction classification masks are the same ones used by
    ../examples/trampoline-hook.c, deliberately, so the analyser and the engine
    cannot disagree about what is relocatable. Encodings quoted in the output
    (bti c = 0xd503245f, ret = 0xd65f03c0, nop = 0xd503201f) come from an
    assemble/disassemble round trip with the NDK's clang, reproducible with
    ../../18-ARM/scripts/arm64-patch.py --show-encodings.
"""

import argparse
import struct
import sys

# ---------------------------------------------------------------- ELF reading

ET_DYN, ET_EXEC = 3, 2
SHT_SYMTAB, SHT_DYNSYM, SHT_PROGBITS = 2, 11, 1
STT_FUNC = 2


class ElfError(Exception):
    pass


class Elf64:
    """Just enough ELF64 to find sections, symbols and section bytes."""

    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        if len(d) < 64 or d[:4] != b"\x7fELF":
            raise ElfError("not an ELF file")
        if d[4] != 2:
            raise ElfError("32-bit ELF: this script is AArch64-only. "
                           "Thumb makes fixed-size prologue patching unsound; "
                           "see the header comment.")
        if d[5] != 1:
            raise ElfError("big-endian ELF is not supported")
        (self.e_type, self.e_machine) = struct.unpack_from("<HH", d, 16)
        if self.e_machine != 183:          # EM_AARCH64
            raise ElfError("e_machine is %d, not 183 (EM_AARCH64)" % self.e_machine)
        (self.e_shoff,) = struct.unpack_from("<Q", d, 0x28)
        (self.e_shentsize, self.e_shnum, self.e_shstrndx) = \
            struct.unpack_from("<HHH", d, 0x3A)
        self.sections = self._read_sections()

    def _read_sections(self):
        out = []
        d = self.data
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            (name, typ, flags, addr, offset, size, link, info, align, entsize) = \
                struct.unpack_from("<IIQQQQIIQQ", d, off)
            out.append(dict(name_off=name, type=typ, flags=flags, addr=addr,
                            offset=offset, size=size, link=link, info=info,
                            entsize=entsize, name=""))
        if self.e_shstrndx < len(out):
            strtab = out[self.e_shstrndx]
            base = strtab["offset"]
            for s in out:
                end = d.index(b"\x00", base + s["name_off"])
                s["name"] = d[base + s["name_off"]:end].decode("utf-8", "replace")
        return out

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def section_bytes(self, s):
        return self.data[s["offset"]:s["offset"] + s["size"]]

    def symbols(self):
        """Every FUNC symbol from .dynsym and .symtab: (name, value, size, tab)."""
        out = []
        for s in self.sections:
            if s["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if s["link"] >= len(self.sections):
                continue
            strtab = self.sections[s["link"]]
            sbase = strtab["offset"]
            n = s["size"] // 24 if s["entsize"] == 0 else s["size"] // s["entsize"]
            for i in range(n):
                off = s["offset"] + i * 24
                if off + 24 > len(self.data):
                    break
                (nm, info, other, shndx, value, size) = \
                    struct.unpack_from("<IBBHQQ", self.data, off)
                if (info & 0xF) != STT_FUNC or value == 0:
                    continue
                end = self.data.index(b"\x00", sbase + nm)
                name = self.data[sbase + nm:end].decode("utf-8", "replace")
                if name:
                    out.append((name, value, size, s["name"]))
        return out

    def vaddr_to_off(self, vaddr):
        """Map a virtual address to a file offset using section headers."""
        for s in self.sections:
            if s["type"] == SHT_PROGBITS and s["addr"] != 0 and \
               s["addr"] <= vaddr < s["addr"] + s["size"]:
                return s["offset"] + (vaddr - s["addr"])
        return None


# --------------------------------------------------- instruction classification
#
# Identical masks to ../examples/trampoline-hook.c. If you change one, change
# both, or the analyser will bless something the engine refuses.

def is_adrp(w):     return (w & 0x9F000000) == 0x90000000
def is_adr(w):      return (w & 0x9F000000) == 0x10000000
def is_ldr_lit(w):  return (w & 0x3B000000) == 0x18000000
def is_b(w):        return (w & 0xFC000000) == 0x14000000
def is_bl(w):       return (w & 0xFC000000) == 0x94000000
def is_bcond(w):    return (w & 0xFF000010) == 0x54000000
def is_cbz(w):      return (w & 0x7E000000) == 0x34000000
def is_tbz(w):      return (w & 0x7E000000) == 0x36000000
def is_ret(w):      return (w & 0xFFFFFC1F) == 0xD65F0000
def is_bti(w):      return (w & 0xFFFFFF3F) == 0xD503241F


def sx(value, bits):
    if value & (1 << (bits - 1)):
        value -= (1 << bits)
    return value


def branch_target(w, pc):
    """Return the absolute target of a PC-relative branch, or None."""
    if is_b(w) or is_bl(w):
        return pc + (sx(w & 0x03FFFFFF, 26) << 2)
    if is_bcond(w):
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2)
    if is_cbz(w):
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2)
    if is_tbz(w):
        return pc + (sx((w >> 5) & 0x3FFF, 14) << 2)
    if is_ldr_lit(w):
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2)
    return None


def classify(w, pc):
    """
    Return (kind, relocatable, note).

    kind          short label for the report
    relocatable   True  copy or re-encode is possible
                  False this engine refuses to move it
                  None  not PC-relative, trivially copyable
    """
    if is_adrp(w):
        imm = sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21)
        page = (pc & ~0xFFF) + (imm << 12)
        return ("adrp", True,
                "PC-relative: forms page 0x%x. Re-encodable at any new address "
                "within +/-4 GiB of that page." % page)
    if is_adr(w):
        imm = sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21)
        return ("adr", False,
                "PC-relative: forms 0x%x. Range is only +/-1 MiB, so a "
                "relocated copy usually cannot reach. Displace fewer bytes or "
                "pick another hook point." % (pc + imm))
    if is_ldr_lit(w):
        return ("ldr literal", False,
                "PC-relative load from 0x%x. Moving it reads the wrong bytes; "
                "the +/-1 MiB range rarely survives relocation."
                % (branch_target(w, pc) or 0))
    if is_bl(w):
        return ("bl", False,
                "PC-relative call to 0x%x (+/-128 MiB). Re-encodable in "
                "principle, refused by this engine because a wrong branch "
                "fails far from the bug." % (branch_target(w, pc) or 0))
    if is_b(w):
        return ("b", False,
                "PC-relative jump to 0x%x (+/-128 MiB), same caveat as bl."
                % (branch_target(w, pc) or 0))
    if is_bcond(w):
        return ("b.cond", False,
                "Conditional branch to 0x%x, range only +/-1 MiB."
                % (branch_target(w, pc) or 0))
    if is_cbz(w):
        return ("cbz/cbnz", False,
                "Compare-and-branch to 0x%x, range +/-1 MiB."
                % (branch_target(w, pc) or 0))
    if is_tbz(w):
        return ("tbz/tbnz", False,
                "Test-bit-and-branch to 0x%x, range only +/-32 KiB."
                % (branch_target(w, pc) or 0))
    if is_bti(w):
        return ("bti", None,
                "Branch-target landing pad. Position independent, but see the "
                "BTI warning below.")
    if is_ret(w):
        return ("ret", None, "Function returns here.")
    return ("", None, "")


# ---------------------------------------------------------------- analysis

class Report(object):
    def __init__(self, name, addr, size):
        self.name = name
        self.addr = addr
        self.size = size
        self.words = []          # (offset, word, kind, relocatable, note)
        self.problems = []       # blocking
        self.warnings = []       # non-blocking
        self.callers = 0
        self.inbound = []        # branch targets landing inside the patch region

    @property
    def verdict(self):
        if self.problems:
            return "UNSAFE"
        if any(w[3] is True for w in self.words):
            return "NEEDS RELOCATION"
        return "SAFE"


def collect_text(elf):
    """All executable PROGBITS sections as (addr, bytes)."""
    out = []
    for s in elf.sections:
        if s["type"] == SHT_PROGBITS and (s["flags"] & 0x4) and s["size"]:
            out.append((s["addr"], elf.section_bytes(s)))
    return out


def count_callers(text, addr):
    """Count `bl` instructions anywhere in .text that target addr."""
    n = 0
    for base, blob in text:
        for i in range(0, len(blob) - 3, 4):
            w = struct.unpack_from("<I", blob, i)[0]
            if is_bl(w) and branch_target(w, base + i) == addr:
                n += 1
    return n


def analyse(elf, name, addr, size, patch_bytes, text):
    r = Report(name, addr, size)
    nwords = patch_bytes // 4

    off = elf.vaddr_to_off(addr)
    if off is None:
        r.problems.append("address 0x%x is not inside any PROGBITS section" % addr)
        return r

    # -- question 1: is there room?
    if size and size < patch_bytes:
        r.problems.append(
            "function is %d bytes but the patch needs %d. Writing it would "
            "overwrite whatever follows." % (size, patch_bytes))
    elif not size:
        r.warnings.append(
            "symbol has st_size 0, so the function's extent is unknown. The "
            "room check could not run. Common in stripped or hand-written "
            "assembly.")

    # -- question 2: which displaced instructions are PC-relative?
    for i in range(nwords):
        if off + i * 4 + 4 > len(elf.data):
            r.problems.append("function runs past the end of the file")
            break
        w = struct.unpack_from("<I", elf.data, off + i * 4)[0]
        pc = addr + i * 4
        kind, reloc, note = classify(w, pc)
        r.words.append((i * 4, w, kind, reloc, note))
        if reloc is False:
            msg = ("displaced instruction +%d (%08x, %s) cannot be relocated: %s"
                   % (i * 4, w, kind, note))
            if patch_bytes == 8:
                # The replacement model discards these instructions rather than
                # moving them, so relocatability is informational, not blocking.
                r.warnings.append(msg + " Not blocking for a wholesale "
                                        "replacement, which never re-runs them.")
            else:
                r.problems.append(msg)

    # BTI: a landing pad at +0 that the patch would destroy
    if r.words and r.words[0][2] == "bti":
        r.warnings.append(
            "prologue opens with a BTI landing pad (%08x). Overwriting it "
            "means any INDIRECT branch to this function faults with a Branch "
            "Target exception on hardware with BTI enabled. Re-emit `bti c` "
            "(0xd503245f) as the first patched instruction, or hook elsewhere."
            % r.words[0][1])

    # -- question 3: does anything branch INTO the patch region?
    end = addr + (size if size else patch_bytes)
    for base, blob in text:
        for i in range(0, len(blob) - 3, 4):
            src = base + i
            if addr <= src < end and src >= addr + patch_bytes:
                pass                     # inside this function, past the patch
            elif not (addr <= src < end):
                continue                 # outside this function entirely
            w = struct.unpack_from("<I", blob, i)[0]
            tgt = branch_target(w, src)
            if tgt is None or is_bl(w):
                continue
            if addr < tgt < addr + patch_bytes:
                r.inbound.append((src, tgt, w))

    for src, tgt, w in r.inbound:
        r.problems.append(
            "instruction at 0x%x branches to 0x%x, which is INSIDE the %d-byte "
            "patch region. After patching it would land in the middle of the "
            "jump -- on the 64-bit address literal, executed as instructions."
            % (src, tgt, patch_bytes))

    # -- question 4: is it called at all?
    r.callers = count_callers(text, addr)
    if r.callers == 0:
        r.warnings.append(
            "no `bl` in this file targets 0x%x. Either the function is only "
            "called from another module, or -- far more often at -O2 -- the "
            "compiler INLINED its body into its callers and this standalone "
            "copy is dead. A hook here will install perfectly and change "
            "nothing. See ../examples/libinline.c." % addr)
    return r


# ---------------------------------------------------------------- output

def print_report(r, patch_bytes, verbose):
    print("=" * 72)
    print("%s  @ 0x%x  (size %s)" % (r.name, r.addr,
                                     ("%d bytes" % r.size) if r.size else "unknown"))
    print("=" * 72)
    models = {
        16: "absolute jump (ldr x16,#8 / br x16 / .quad)",
        8:  "wholesale replacement, e.g. `mov w0,#1; ret` -- no trampoline, so "
            "the displaced instructions are DISCARDED, not relocated",
        4:  "direct branch (b), reachable +/-128 MiB only",
    }
    print("patch model     : %d-byte %s" % (patch_bytes, models[patch_bytes]))
    if patch_bytes == 8:
        print("                  (relocation findings below are informational: "
              "you are\n                   destroying these instructions, not "
              "moving them)")
    print("callers in file : %d" % r.callers)
    print()
    print("displaced instructions:")
    for off, w, kind, reloc, note in r.words:
        flag = {True: "RELOC", False: "BLOCK", None: "copy "}[reloc]
        print("  +%-3d  %08x  %-5s %-12s" % (off, w, flag, kind))
        if note and (verbose or reloc is not None):
            print("        %s" % note)
    print()
    if r.problems:
        print("PROBLEMS:")
        for p in r.problems:
            print("  [!] %s" % p)
        print()
    if r.warnings:
        print("WARNINGS:")
        for wmsg in r.warnings:
            print("  [?] %s" % wmsg)
        print()
    print("VERDICT: %s" % r.verdict)
    if r.verdict == "NEEDS RELOCATION":
        print("  A trampoline must RE-ENCODE the instructions marked RELOC.")
        print("  Range requirement: the trampoline must sit within +/-4 GiB of")
        print("  the adrp target page. mmap hints are advisory -- use")
        print("  MAP_FIXED_NOREPLACE and search. See ../examples/trampoline-hook.c.")
    elif r.verdict == "SAFE" and patch_bytes == 8:
        print("  Nothing blocks a wholesale replacement. Remember that the")
        print("  original body will NEVER run again -- if it had side effects")
        print("  the caller depends on, you have broken them.")
    elif r.verdict == "SAFE":
        print("  Every displaced instruction is position independent. Copy them")
        print("  to the trampoline verbatim, append a jump back to +%d, patch,"
              % patch_bytes)
        print("  and flush the instruction cache.")
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Report whether an AArch64 function can be safely inline-hooked.")
    ap.add_argument("elf", help="shared object or executable to analyse")
    ap.add_argument("--symbol", "-s", help="function to analyse")
    ap.add_argument("--all", action="store_true",
                    help="analyse every FUNC symbol and print a summary table")
    ap.add_argument("--patch-bytes", type=int, default=16, choices=(4, 8, 16),
                    help="16 = absolute jump (default), 8 = two-instruction "
                         "replacement such as `mov w0,#1; ret`, 4 = direct branch")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="explain every displaced instruction, not just the "
                         "PC-relative ones")
    args = ap.parse_args()

    try:
        elf = Elf64(args.elf)
    except (ElfError, IOError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    text = collect_text(elf)
    syms = elf.symbols()
    if not syms:
        print("error: no FUNC symbols found (fully stripped?). Without symbols "
              "you must supply an address; this script does not guess function "
              "boundaries.", file=sys.stderr)
        return 2

    # de-duplicate: a symbol can appear in both .dynsym and .symtab
    seen, uniq = set(), []
    for name, value, size, tab in syms:
        if (name, value) in seen:
            continue
        seen.add((name, value))
        uniq.append((name, value, size, tab))

    if args.all:
        rows = []
        for name, value, size, _tab in sorted(uniq, key=lambda x: x[1]):
            r = analyse(elf, name, value, size, args.patch_bytes, text)
            rows.append(r)
        print("%-28s %-12s %-6s %-8s %s" %
              ("SYMBOL", "ADDR", "SIZE", "CALLERS", "VERDICT"))
        print("-" * 72)
        for r in rows:
            print("%-28s 0x%-10x %-6s %-8d %s" %
                  (r.name[:28], r.addr, r.size or "?", r.callers, r.verdict))
        print()
        print("%d SAFE, %d NEEDS RELOCATION, %d UNSAFE" % (
            sum(1 for r in rows if r.verdict == "SAFE"),
            sum(1 for r in rows if r.verdict == "NEEDS RELOCATION"),
            sum(1 for r in rows if r.verdict == "UNSAFE")))
        print("Re-run with --symbol <name> for the reasons behind any row.")
        return 0

    if not args.symbol:
        ap.error("give --symbol NAME or --all")

    hits = [s for s in uniq if s[0] == args.symbol]
    if not hits:
        print("error: no FUNC symbol named %r. Available (first 30):"
              % args.symbol, file=sys.stderr)
        for name, value, _s, _t in sorted(uniq, key=lambda x: x[1])[:30]:
            print("  %-40s 0x%x" % (name, value), file=sys.stderr)
        return 2

    rc = 0
    for name, value, size, _tab in hits:
        r = analyse(elf, name, value, size, args.patch_bytes, text)
        print_report(r, args.patch_bytes, args.verbose)
        if r.verdict == "UNSAFE":
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
