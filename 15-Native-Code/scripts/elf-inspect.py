#!/usr/bin/env python3
"""
elf-inspect.py -- the readelf you always have.

WHAT IT DOES
    Prints the parts of an ELF file that chapter 15 teaches, from a parser
    written against the System V gABI rather than a wrapper around a tool:

      --header      the 64 (or 52) byte ELF header, field by field, WITH the
                    file offset of each field so you can check it in a hex
                    editor yourself
      --segments    the program header table: what the LOADER reads
      --sections    the section header table: what TOOLS read
      --dynamic     the DT_* array, decoded, including the Android-specific
                    packed-relocation tags
      --dynsyms     .dynsym -- exports and imports, the table that survives
                    stripping and the table Module.findExportByName searches
      --symbols     .symtab -- everything, present only in unstripped builds
      --relocs      .rela.dyn and .rela.plt, with the AArch64/ARM relocation
                    type names, so you can see the GOT being described
      --plt         the PLT/GOT correspondence: which stub calls which import
      --notes       .note.gnu.build-id and .note.android.ident
      --init        constructors that run before JNI_OnLoad
      --strings     printable runs from .rodata only, which is far quieter
                    than running strings(1) over the whole file
      --hex SECTION a labelled hex dump of one section
      --all         everything above except --strings and --hex

HOW TO RUN
    python3 elf-inspect.py libnative.so --header
    python3 elf-inspect.py libnative.so --segments --sections
    python3 elf-inspect.py libnative.so --dynsyms --defined-only
    python3 elf-inspect.py libnative.so --relocs
    python3 elf-inspect.py libnative.so --plt
    python3 elf-inspect.py libnative.so --hex .init_array
    python3 elf-inspect.py libnative.so --strings --min 8
    python3 elf-inspect.py libnative.so --all

REQUIREMENTS
    Python 3.6+. Standard library only. Works on a file extracted from an APK
    with `unzip`, on a file pulled off a device with `adb pull`, and on a file
    dumped out of a live process -- though a dumped image has already been
    relocated, so its GOT entries hold runtime addresses rather than the
    link-time values printed here.

WHAT THIS WILL *NOT* TELL YOU
    - What the code does. There is no disassembler here. Once you know WHERE
      to look, take the address to Ghidra (57-Ghidra) or objdump.
    - Whether a symbol is reached at run time. An export is an offer, not a
      promise; a relocation is a plan, not an event.
    - The correct interpretation of every relocation type. Only the handful
      that matter on Android are named; the rest print as numbers, honestly,
      rather than being guessed at.
    - Anything about DWARF. Debug information is parsed by neither this script
      nor most release binaries, because release binaries do not have it.
    - Whether the file is hardened. That is elf-harden-check.py, deliberately
      kept separate: this script describes, that one judges.
"""

from __future__ import print_function

import argparse
import os
import string
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Reuse the parser rather than maintaining two. Import by file name because the
# module name contains hyphens, which `import` cannot express.
try:
    import importlib.util as _ilu
    # Loading a module by path would otherwise drop a __pycache__ directory
    # next to the script, inside the repository. Never do that.
    sys.dont_write_bytecode = True
    _spec = _ilu.spec_from_file_location(
        "elf_harden_check", os.path.join(HERE, "elf-harden-check.py"))
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
except Exception as exc:                                # pragma: no cover
    sys.stderr.write("could not load elf-harden-check.py from %s: %s\n"
                     % (HERE, exc))
    raise

Elf = _mod.Elf
ElfError = _mod.ElfError
Reader = _mod.Reader
PT_NAMES = _mod.PT_NAMES
DT_NAMES = _mod.DT_NAMES
EM_NAMES = _mod.EM_NAMES
ET_NAMES = _mod.ET_NAMES
PF_X, PF_W, PF_R = _mod.PF_X, _mod.PF_W, _mod.PF_R
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = (_mod.SHF_WRITE, _mod.SHF_ALLOC,
                                       _mod.SHF_EXECINSTR)
SHN_UNDEF, SHN_ABS, SHN_COMMON = _mod.SHN_UNDEF, _mod.SHN_ABS, _mod.SHN_COMMON
DT_JMPREL, DT_PLTRELSZ, DT_RELA, DT_RELASZ = (_mod.DT_JMPREL, _mod.DT_PLTRELSZ,
                                              _mod.DT_RELA, _mod.DT_RELASZ)
DT_REL, DT_RELSZ, DT_PLTGOT = _mod.DT_REL, _mod.DT_RELSZ, _mod.DT_PLTGOT
DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ = (_mod.DT_INIT, _mod.DT_INIT_ARRAY,
                                           _mod.DT_INIT_ARRAYSZ)
DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ = (_mod.DT_PREINIT_ARRAY,
                                        _mod.DT_PREINIT_ARRAYSZ)
DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ = (_mod.DT_FINI, _mod.DT_FINI_ARRAY,
                                           _mod.DT_FINI_ARRAYSZ)
DT_ANDROID_REL, DT_ANDROID_RELA = _mod.DT_ANDROID_REL, _mod.DT_ANDROID_RELA
DT_ANDROID_RELR, DT_RELR = _mod.DT_ANDROID_RELR, _mod.DT_RELR

PT_LOAD_T = 1

SHT_NAMES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM",
    14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
    18: "SYMTAB_SHNDX", 19: "RELR",
    0x6FFFFFF6: "GNU_HASH", 0x6FFFFFFD: "GNU_verdef",
    0x6FFFFFFE: "GNU_verneed", 0x6FFFFFFF: "GNU_versym",
    0x60000001: "ANDROID_REL", 0x60000002: "ANDROID_RELA",
    0x6FFFFF00: "ANDROID_RELR",
}

STT_NAMES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
             5: "COMMON", 6: "TLS", 10: "GNU_IFUNC"}
STB_NAMES = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE"}
STV_NAMES = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}

# Only the relocation types that actually appear in Android shared objects are
# named. Values verified by building a library with the NDK and reading the raw
# r_info fields back, not from memory.
R_AARCH64 = {257: "R_AARCH64_ABS64", 1025: "R_AARCH64_GLOB_DAT",
             1026: "R_AARCH64_JUMP_SLOT", 1027: "R_AARCH64_RELATIVE",
             1030: "R_AARCH64_TLS_TPREL64", 1031: "R_AARCH64_TLSDESC",
             1032: "R_AARCH64_IRELATIVE"}
R_ARM = {2: "R_ARM_ABS32", 21: "R_ARM_GLOB_DAT", 22: "R_ARM_JUMP_SLOT",
         23: "R_ARM_RELATIVE", 160: "R_ARM_IRELATIVE"}
R_X86_64 = {1: "R_X86_64_64", 6: "R_X86_64_GLOB_DAT", 7: "R_X86_64_JUMP_SLOT",
            8: "R_X86_64_RELATIVE", 37: "R_X86_64_IRELATIVE"}
R_386 = {1: "R_386_32", 6: "R_386_GLOB_DAT", 7: "R_386_JMP_SLOT",
         8: "R_386_RELATIVE", 42: "R_386_IRELATIVE"}

RELOC_TABLES = {183: R_AARCH64, 40: R_ARM, 62: R_X86_64, 3: R_386}


def perm_str(flags):
    return ("R" if flags & PF_R else "-") + \
           ("W" if flags & PF_W else "-") + \
           ("X" if flags & PF_X else "-")


def shflag_str(flags):
    s = ""
    s += "W" if flags & SHF_WRITE else ""
    s += "A" if flags & SHF_ALLOC else ""
    s += "X" if flags & SHF_EXECINSTR else ""
    return s or "-"


# ---------------------------------------------------------------------------
# Printers
# ---------------------------------------------------------------------------

def show_header(elf, out):
    out.write("ELF header\n")
    out.write("  %-10s %-22s %s\n" % ("offset", "field", "value"))
    mach = EM_NAMES.get(elf.e_machine, ("unknown", "?"))
    rows = [
        ("0x00", "e_ident[EI_MAG]", "7F 45 4C 46  (\"\\x7fELF\")"),
        ("0x04", "e_ident[EI_CLASS]", "%d  (%s)" % (
            elf.elfclass, "ELF64" if elf.is64 else "ELF32")),
        ("0x05", "e_ident[EI_DATA]", "%d  (%s-endian)" % (
            elf.data, "little" if elf.little else "big")),
        ("0x06", "e_ident[EI_VERSION]", str(elf.ei_version)),
        ("0x07", "e_ident[EI_OSABI]", "%d  (%s)" % (
            elf.osabi, {0: "System V", 3: "Linux"}.get(elf.osabi, "other"))),
        ("0x08", "e_ident[EI_ABIVERSION]", str(elf.abiversion)),
        ("0x10", "e_type", "%d  (%s)" % (
            elf.e_type, ET_NAMES.get(elf.e_type, "?"))),
        ("0x12", "e_machine", "%d  (%s -> lib/%s/)" % (
            elf.e_machine, mach[0], mach[1])),
        ("0x14", "e_version", str(elf.e_version)),
    ]
    if elf.is64:
        rows += [("0x18", "e_entry", "0x%x" % elf.e_entry),
                 ("0x20", "e_phoff", "%d" % elf.e_phoff),
                 ("0x28", "e_shoff", "%d" % elf.e_shoff),
                 ("0x30", "e_flags", "0x%x" % elf.e_flags),
                 ("0x34", "e_ehsize", "%d" % elf.e_ehsize),
                 ("0x36", "e_phentsize", "%d" % elf.e_phentsize),
                 ("0x38", "e_phnum", "%d" % elf.e_phnum),
                 ("0x3A", "e_shentsize", "%d" % elf.e_shentsize),
                 ("0x3C", "e_shnum", "%d" % elf.e_shnum),
                 ("0x3E", "e_shstrndx", "%d" % elf.e_shstrndx)]
    else:
        rows += [("0x18", "e_entry", "0x%x" % elf.e_entry),
                 ("0x1C", "e_phoff", "%d" % elf.e_phoff),
                 ("0x20", "e_shoff", "%d" % elf.e_shoff),
                 ("0x24", "e_flags", "0x%x" % elf.e_flags),
                 ("0x28", "e_ehsize", "%d" % elf.e_ehsize),
                 ("0x2A", "e_phentsize", "%d" % elf.e_phentsize),
                 ("0x2C", "e_phnum", "%d" % elf.e_phnum),
                 ("0x2E", "e_shentsize", "%d" % elf.e_shentsize),
                 ("0x30", "e_shnum", "%d" % elf.e_shnum),
                 ("0x32", "e_shstrndx", "%d" % elf.e_shstrndx)]
    for off, field, val in rows:
        out.write("  %-10s %-22s %s\n" % (off, field, val))
    out.write("\n  The first 16 bytes at offset 0 are e_ident. Everything after\n"
              "  offset 0x10 has a different size and layout on ELF32; the\n"
              "  offsets above are for THIS file.\n\n")


def show_segments(elf, out):
    out.write("Program headers (%d) -- what the dynamic linker reads\n"
              % len(elf.phdrs))
    out.write("  %-3s %-14s %-10s %-18s %-10s %-10s %-4s %s\n"
              % ("#", "type", "offset", "vaddr", "filesz", "memsz", "flg", "align"))
    for ph in elf.phdrs:
        out.write("  %-3d %-14s 0x%-8x 0x%-16x 0x%-8x 0x%-8x %-4s 0x%x\n"
                  % (ph["index"], ph["name"], ph["offset"], ph["vaddr"],
                     ph["filesz"], ph["memsz"], perm_str(ph["flags"]),
                     ph["align"]))
    out.write("\n  A PT_LOAD line reads: take filesz bytes from file offset\n"
              "  `offset`, map them at base+vaddr with these permissions, and\n"
              "  zero-fill up to memsz. memsz > filesz is .bss.\n\n")


def show_sections(elf, out):
    if not elf.shdrs:
        out.write("No section header table in this file.\n\n")
        return
    out.write("Section headers (%d) -- what analysis tools read\n" % len(elf.shdrs))
    out.write("  %-3s %-22s %-14s %-18s %-10s %-10s %s\n"
              % ("#", "name", "type", "addr", "offset", "size", "flg"))
    for sh in elf.shdrs:
        out.write("  %-3d %-22s %-14s 0x%-16x 0x%-8x 0x%-8x %s\n"
                  % (sh["index"], sh["name"][:22],
                     SHT_NAMES.get(sh["type"], "0x%x" % sh["type"]),
                     sh["addr"], sh["offset"], sh["size"],
                     shflag_str(sh["flags"])))
    out.write("\n  addr == 0 means the section is not mapped into memory:\n"
              "  .symtab, .strtab, .comment and every .debug_* section are\n"
              "  metadata for tools, never loaded, and removed by strip.\n\n")


def show_dynamic(elf, out):
    dyn = elf.dynamic()
    if not dyn:
        out.write("No dynamic array.\n\n")
        return
    strs = Reader(elf.dynstr(), elf.little, elf.is64)
    out.write("Dynamic array (%d entries)\n" % len(dyn))
    out.write("  %-20s %-20s %s\n" % ("tag", "name", "value"))
    string_tags = {_mod.DT_NEEDED: "library", _mod.DT_SONAME: "soname",
                   _mod.DT_RPATH: "path", _mod.DT_RUNPATH: "path"}
    for tag, val in dyn:
        name = DT_NAMES.get(tag, "0x%x" % tag)
        if tag in string_tags:
            shown = "%s (\"%s\")" % (val, strs.cstr(val))
        elif val > 0xFFFF:
            shown = "0x%x" % val
        else:
            shown = str(val)
        out.write("  0x%-18x %-20s %s\n" % (tag, name, shown))
    if elf.dt_present(DT_ANDROID_REL) or elf.dt_present(DT_ANDROID_RELA):
        out.write("\n  ANDROID_REL/RELA present: relocations are stored in "
                  "Android's packed\n  format, which readelf from binutils "
                  "cannot decode. llvm-readelf can.\n")
    if elf.dt_present(DT_ANDROID_RELR) or elf.dt_present(DT_RELR):
        out.write("\n  RELR present: relative relocations are bitmap-encoded, "
                  "a large size\n  win over RELA. API 30+ for the standard tag; "
                  "Android's own tag is older.\n")
    out.write("\n")


def show_symbols(elf, out, dynamic=True, defined_only=False,
                 undefined_only=False, pattern=None, limit=0):
    syms = elf.dynsyms() if dynamic else elf.symtab()
    label = ".dynsym" if dynamic else ".symtab"
    if not syms:
        out.write("%s: empty or absent%s\n\n"
                  % (label, " (this file is stripped)" if not dynamic else ""))
        return
    rows = []
    for s in syms:
        if not s["name"]:
            continue
        if defined_only and not s["defined"]:
            continue
        if undefined_only and s["defined"]:
            continue
        if pattern and pattern not in s["name"]:
            continue
        rows.append(s)
    out.write("%s -- %d shown of %d\n" % (label, len(rows), len(syms)))
    out.write("  %-18s %-8s %-8s %-10s %-6s %s\n"
              % ("value", "size", "type", "bind", "vis", "name"))
    for s in rows[:limit or len(rows)]:
        where = "UND" if not s["defined"] else "0x%x" % s["value"]
        out.write("  %-18s %-8d %-8s %-10s %-6s %s\n"
                  % (where, s["size"],
                     STT_NAMES.get(s["type"], str(s["type"])),
                     STB_NAMES.get(s["bind"], str(s["bind"])),
                     STV_NAMES.get(s["visibility"], "?"),
                     s["name"]))
    if limit and len(rows) > limit:
        out.write("  ... %d more\n" % (len(rows) - limit))
    if dynamic:
        out.write("\n  UND rows are IMPORTS: this library asks another library "
                  "for them.\n  Rows with an address are EXPORTS: this is the "
                  "table\n  Module.findExportByName(\"libfoo.so\", name) "
                  "searches. A HIDDEN\n  symbol is not in it and cannot be "
                  "found by name at run time.\n")
    out.write("\n")


def _reloc_entries(elf, va, size):
    """Yield (r_offset, sym_index, r_type, addend) from a RELA/REL region."""
    off = elf.vaddr_to_offset(va)
    if off is None:
        return
    if elf.is64:
        ent, has_addend = 24, True
    else:
        ent, has_addend = 8, False       # ARM32 shared objects use REL
    # A 64-bit file may still use REL; decide from DT_PLTREL where possible.
    count = size // ent
    for i in range(count):
        base = off + i * ent
        try:
            if elf.is64:
                r_off = elf.r.u64(base)
                info = elf.r.u64(base + 8)
                add = elf.r.sword(base + 16) if has_addend else 0
                yield r_off, info >> 32, info & 0xFFFFFFFF, add
            else:
                r_off = elf.r.u32(base)
                info = elf.r.u32(base + 4)
                yield r_off, info >> 8, info & 0xFF, 0
        except ElfError:
            return


def show_relocs(elf, out):
    table = RELOC_TABLES.get(elf.e_machine, {})
    syms = elf.dynsyms()
    regions = []
    if elf.dt_first(DT_RELA) is not None:
        regions.append((".rela.dyn", elf.dt_first(DT_RELA),
                        elf.dt_first(DT_RELASZ, 0)))
    if elf.dt_first(DT_REL) is not None:
        regions.append((".rel.dyn", elf.dt_first(DT_REL),
                        elf.dt_first(DT_RELSZ, 0)))
    if elf.dt_first(DT_JMPREL) is not None:
        regions.append(("PLT relocations", elf.dt_first(DT_JMPREL),
                        elf.dt_first(DT_PLTRELSZ, 0)))
    if not regions:
        if elf.dt_present(DT_ANDROID_REL) or elf.dt_present(DT_ANDROID_RELA):
            out.write("Relocations are in Android's packed format; this script "
                      "does not\nunpack them. Use llvm-readelf -r.\n\n")
        else:
            out.write("No relocation regions found via the dynamic array.\n\n")
        return
    for name, va, size in regions:
        out.write("%s at vaddr 0x%x, %d bytes\n" % (name, va, size))
        out.write("  %-18s %-24s %-22s %s\n"
                  % ("r_offset", "type", "symbol", "addend"))
        n = 0
        for r_off, symidx, rtype, add in _reloc_entries(elf, va, size):
            sname = ""
            if symidx and symidx < len(syms):
                sname = syms[symidx]["name"]
            out.write("  0x%-16x %-24s %-22s 0x%x\n"
                      % (r_off, table.get(rtype, "type=%d" % rtype),
                         sname or "-", add & 0xFFFFFFFFFFFFFFFF))
            n += 1
        out.write("  (%d entries)\n\n" % n)
    out.write("  RELATIVE relocations have no symbol: they say 'add the load\n"
              "  base to the value already stored here'. GLOB_DAT and\n"
              "  JUMP_SLOT name a symbol: they say 'look this name up and write\n"
              "  the answer here'. The 'here' is a GOT slot, which is why the\n"
              "  GOT is a hooking target -- see README section 3.8.\n\n")


def show_plt(elf, out):
    """Correlate PLT relocation slots with the imports they will hold."""
    va = elf.dt_first(DT_JMPREL)
    if va is None:
        out.write("No DT_JMPREL: this library has no lazily-bindable PLT "
                  "relocations.\n\n")
        return
    size = elf.dt_first(DT_PLTRELSZ, 0)
    syms = elf.dynsyms()
    gotva = elf.dt_first(DT_PLTGOT)
    out.write("PLT / GOT correspondence\n")
    if gotva is not None:
        out.write("  DT_PLTGOT (.got.plt base) = 0x%x\n" % gotva)
    out.write("  %-18s %-8s %s\n" % ("GOT slot (r_offset)", "index", "import"))
    idx = 0
    for r_off, symidx, rtype, _add in _reloc_entries(elf, va, size):
        sname = syms[symidx]["name"] if symidx < len(syms) else "?"
        out.write("  0x%-16x %-8d %s\n" % (r_off, idx, sname))
        idx += 1
    out.write("\n  Each row is one GOT slot. A call to that import in .text "
              "goes to a\n  small PLT stub, the stub loads a function pointer "
              "from this slot,\n  and jumps to it. Overwrite the slot at run "
              "time and every future\n  call through it goes where you say. "
              "With full RELRO the slot is\n  read-only after startup, so the "
              "overwrite needs mprotect first.\n\n")


def show_notes(elf, out):
    bid = elf.build_id()
    out.write("Notes\n")
    out.write("  build-id: %s\n" % (bid or "(none)"))
    ident = elf.android_ident()
    out.write("  .note.android.ident target API: %s\n"
              % (ident if ident else "(none)"))
    com = elf.comment()
    for c in com:
        out.write("  .comment: %s\n" % c)
    out.write("\n")


def _relative_map(elf):
    """vaddr -> resolved value, for RELATIVE relocations.

    This matters more than it looks. On AArch64 the toolchain emits RELA, and a
    RELA relocation carries its value in the ADDEND -- the slot in the file is
    left as zero and the linker writes base+addend into it at load time. So
    reading .init_array straight out of the file on arm64 gives you a list of
    zeros, and a reader who does not know this concludes there are no
    constructors. On ARM32 the toolchain emits REL, which has no addend, so the
    value really is stored in the slot and reading it directly works. The two
    architectures genuinely behave differently here.
    """
    out = {}
    table = RELOC_TABLES.get(elf.e_machine, {})
    rel_names = ("R_AARCH64_RELATIVE", "R_ARM_RELATIVE", "R_X86_64_RELATIVE",
                 "R_386_RELATIVE")
    regions = []
    if elf.dt_first(DT_RELA) is not None:
        regions.append((elf.dt_first(DT_RELA), elf.dt_first(DT_RELASZ, 0)))
    if elf.dt_first(DT_REL) is not None:
        regions.append((elf.dt_first(DT_REL), elf.dt_first(DT_RELSZ, 0)))
    for va, size in regions:
        for r_off, _symidx, rtype, add in _reloc_entries(elf, va, size):
            if table.get(rtype) in rel_names and add:
                out[r_off] = add
    return out


def show_init(elf, out):
    ptr = 8 if elf.is64 else 4
    relmap = _relative_map(elf)
    out.write("Load-time and unload-time code\n")
    init = elf.dt_first(DT_INIT)
    if init is not None:
        out.write("  DT_INIT              0x%x   (legacy single constructor)\n" % init)
    fini = elf.dt_first(DT_FINI)
    if fini is not None:
        out.write("  DT_FINI              0x%x\n" % fini)
    for tag_va, tag_sz, label in ((DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ,
                                   ".preinit_array"),
                                  (DT_INIT_ARRAY, DT_INIT_ARRAYSZ,
                                   ".init_array"),
                                  (DT_FINI_ARRAY, DT_FINI_ARRAYSZ,
                                   ".fini_array")):
        va = elf.dt_first(tag_va)
        sz = elf.dt_first(tag_sz, 0) or 0
        if va is None or not sz:
            continue
        off = elf.vaddr_to_offset(va)
        out.write("  %s at 0x%x, %d entries\n" % (label, va, sz // ptr))
        if off is None:
            out.write("      (not covered by any PT_LOAD -- suspicious)\n")
            continue
        for i in range(sz // ptr):
            slot_va = va + i * ptr
            try:
                fn = elf.r.word(off + i * ptr)
            except ElfError:
                break
            if fn == 0 and slot_va in relmap:
                out.write("      [%d] 0x%x   (slot is 0 in the file; the value "
                          "comes from the RELATIVE relocation addend)\n"
                          % (i, relmap[slot_va]))
            elif fn == 0:
                out.write("      [%d] 0x0     (no value in the file and no "
                          "relocation found -- packed relocations?)\n" % i)
            else:
                out.write("      [%d] 0x%x\n" % (i, fn))
    out.write("\n  Every .preinit_array and .init_array entry runs when the\n"
              "  linker finishes with this library -- before JNI_OnLoad, before\n"
              "  any Java code sees anything. Read these addresses in a\n"
              "  decompiler first. See README section 3.12.\n"
              "\n  If an entry reads 0x0 with no relocation behind it, the file\n"
              "  uses Android's packed relocation format and this script does\n"
              "  not unpack it. llvm-readelf -r will.\n\n")


PRINTABLE = set(bytearray(string.printable.replace("\r", "")
                          .replace("\x0b", "").replace("\x0c", ""), "ascii"))


def show_strings(elf, out, minlen=6, section=".rodata"):
    data = elf.section_bytes(section)
    sh = elf.section(section)
    base = sh["addr"] if sh else 0
    if not data:
        # No usable section -- either it was stripped away, or the section
        # header is lying about its size. Fall back to the read-only PT_LOAD
        # segment, which is where .rodata lives and which the loader trusts.
        ro = None
        for ph in elf.phdrs:
            if ph["type"] == PT_LOAD_T and ph["flags"] == PF_R:
                ro = ph
                break
        if ro is None:
            for ph in elf.phdrs:
                if ph["type"] == PT_LOAD_T and not (ph["flags"] & PF_X):
                    ro = ph
                    break
        if ro is None:
            out.write("no %s section and no read-only PT_LOAD to fall back to\n\n"
                      % section)
            return
        out.write("  (%s is absent or claims zero size; reading the read-only\n"
                  "   PT_LOAD segment at 0x%x instead -- the loader trusts this\n"
                  "   and a section header cannot change it)\n"
                  % (section, ro["vaddr"]))
        data = elf.blob[ro["offset"]:ro["offset"] + ro["filesz"]]
        base = ro["vaddr"]
    run, start = [], 0
    found = 0
    for i, b in enumerate(bytearray(data)):
        if b in PRINTABLE and b >= 0x20:
            if not run:
                start = i
            run.append(b)
            continue
        if len(run) >= minlen:
            out.write("  0x%-10x %s\n"
                      % (base + start, bytes(bytearray(run)).decode("ascii")))
            found += 1
        run = []
    if len(run) >= minlen:
        out.write("  0x%-10x %s\n"
                  % (base + start, bytes(bytearray(run)).decode("ascii")))
        found += 1
    out.write("\n  %d strings of %d+ characters in %s.\n"
              "  A large library with very few here has encrypted them; see\n"
              "  40-Obfuscation. The addresses are LINK-TIME: add the runtime\n"
              "  module base before using them with a debugger.\n\n"
              % (found, minlen, section))


def show_hex(elf, out, name):
    sh = elf.section(name)
    if sh is None:
        out.write("no section named %s\n\n" % name)
        return
    data = elf.section_bytes(name)
    base = sh["addr"]
    for off in range(0, len(data), 16):
        chunk = bytearray(data[off:off + 16])
        hexpart = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        out.write("  %08x  %-47s  |%s|\n" % (base + off, hexpart, asc))
    out.write("\n")


def main():
    ap = argparse.ArgumentParser(description="Inspect an ELF file without readelf.")
    ap.add_argument("path")
    ap.add_argument("--header", action="store_true")
    ap.add_argument("--segments", action="store_true")
    ap.add_argument("--sections", action="store_true")
    ap.add_argument("--dynamic", action="store_true")
    ap.add_argument("--dynsyms", action="store_true")
    ap.add_argument("--symbols", action="store_true")
    ap.add_argument("--relocs", action="store_true")
    ap.add_argument("--plt", action="store_true")
    ap.add_argument("--notes", action="store_true")
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--section", default=".rodata",
                    help="which section --strings reads (default .rodata)")
    ap.add_argument("--min", type=int, default=6, help="--strings minimum length")
    ap.add_argument("--hex", metavar="SECTION", help="hex dump one section")
    ap.add_argument("--defined-only", action="store_true")
    ap.add_argument("--undefined-only", action="store_true")
    ap.add_argument("--grep", help="only symbols containing this substring")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-sections", action="store_true",
                    help="ignore the section header table entirely and answer "
                         "only from the program headers and PT_DYNAMIC -- the "
                         "same information the dynamic linker uses. Use this "
                         "when you suspect the section headers are lying, or "
                         "to see what a packed file still gives up")
    args = ap.parse_args()

    with open(args.path, "rb") as fh:
        blob = fh.read()
    try:
        elf = Elf(blob, os.path.basename(args.path))
    except ElfError as exc:
        sys.stderr.write("%s: %s\n" % (args.path, exc))
        return 2

    if args.no_sections:
        # Everything below then resolves through PT_DYNAMIC exactly as the
        # linker would. A section header table can say anything at all; the
        # dynamic array cannot, because the file would not load.
        elf.shdrs = []
        elf._dynstr_cache = None
        elf.warnings.append(
            "--no-sections: section headers ignored. Every answer below comes "
            "from the program headers and PT_DYNAMIC, which is what the "
            "dynamic linker itself reads.")

    out = sys.stdout
    out.write("== %s (%d bytes) ==\n\n" % (args.path, len(blob)))
    for w in elf.warnings:
        out.write("  ! %s\n" % w)
    if elf.warnings:
        out.write("\n")

    any_flag = any([args.header, args.segments, args.sections, args.dynamic,
                    args.dynsyms, args.symbols, args.relocs, args.plt,
                    args.notes, args.init, args.strings, args.hex])
    if args.all or not any_flag:
        args.header = args.segments = args.sections = True
        args.dynamic = args.dynsyms = args.relocs = True
        args.plt = args.notes = args.init = True

    if args.header:
        show_header(elf, out)
    if args.segments:
        show_segments(elf, out)
    if args.sections:
        show_sections(elf, out)
    if args.dynamic:
        show_dynamic(elf, out)
    if args.dynsyms:
        show_symbols(elf, out, True, args.defined_only, args.undefined_only,
                     args.grep, args.limit)
    if args.symbols:
        show_symbols(elf, out, False, args.defined_only, args.undefined_only,
                     args.grep, args.limit)
    if args.relocs:
        show_relocs(elf, out)
    if args.plt:
        show_plt(elf, out)
    if args.notes:
        show_notes(elf, out)
    if args.init:
        show_init(elf, out)
    if args.strings:
        show_strings(elf, out, args.min, args.section)
    if args.hex:
        show_hex(elf, out, args.hex)
    return 0


if __name__ == "__main__":
    sys.exit(main())
