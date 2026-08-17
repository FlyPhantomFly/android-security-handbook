#!/usr/bin/env python3
"""
elf_header_by_hand.py -- parse an ELF header, program headers and section
                         headers with nothing but struct.unpack, and print the
                         file offset of every field so you can check the answer
                         in a hex editor.

WHY THIS EXISTS, GIVEN scripts/elf-inspect.py ALREADY DOES MORE
    Because you should write this once before you use anything that does it
    for you. Reading the specification is not the same as making the offsets
    work; the format only becomes real when your own subtraction is wrong and
    you find out why. This file is short enough to read in one sitting -- about
    two hundred lines, of which half are comments -- and it deliberately
    handles only the common case, so nothing distracts from the layout.

    labs/lab-01-elf-by-hand.md walks you through writing it yourself. Read that
    first and use this only to check your answer.

WHAT IT PARSES
    The 64-byte ELF64 header, the 52-byte ELF32 header, both program header
    layouts (they differ by more than width -- the flags field MOVES), and both
    section header layouts. That is enough to answer:

      Which architecture is this, and therefore which lib/<abi>/ directory?
      Is it position independent?
      Where does each part of the file get mapped, and with what permissions?
      Is the stack executable?
      Has it been stripped?

HOW TO RUN
    python3 elf_header_by_hand.py libnative.so
    python3 elf_header_by_hand.py libnative.so --hexdump

REQUIREMENTS
    Python 3.6+. Standard library only.

WHAT THIS WILL *NOT* DO
    - Handle a hostile file gracefully. It has almost no bounds checking, on
      purpose: the exception traceback tells you which field was out of range,
      which is more educational than a caught error. scripts/elf-harden-check.py
      is the one written to survive a damaged file.
    - Parse the dynamic array, symbols, relocations or notes. Those need the
      string tables and a second pass, and they are what the scripts directory
      is for.
    - Handle big-endian files, or 32-bit files with unusual e_ehsize. No
      Android ABI is big-endian.
"""

import struct
import sys

# The four magic bytes. Written as an escape, never as a raw byte: 0x7F is a
# control character and a source file containing one stops being text.
ELF_MAGIC = b"\x7fELF"

ET = {0: "NONE", 1: "REL (relocatable object, a .o)",
      2: "EXEC (fixed-address executable)",
      3: "DYN (shared object, or a position-independent executable)",
      4: "CORE (a crash dump)"}

EM = {3: ("EM_386", "x86"), 40: ("EM_ARM", "armeabi-v7a"),
      62: ("EM_X86_64", "x86_64"), 183: ("EM_AARCH64", "arm64-v8a"),
      243: ("EM_RISCV", "riscv64")}

PT = {0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP",
      4: "PT_NOTE", 6: "PT_PHDR", 7: "PT_TLS",
      0x6474E550: "PT_GNU_EH_FRAME", 0x6474E551: "PT_GNU_STACK",
      0x6474E552: "PT_GNU_RELRO", 0x6474E553: "PT_GNU_PROPERTY"}

SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
       5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
       11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY",
       0x6FFFFFF6: "GNU_HASH"}


def perms(p_flags):
    """p_flags is a bitmask: 4 = read, 2 = write, 1 = execute."""
    return ("R" if p_flags & 4 else "-") + \
           ("W" if p_flags & 2 else "-") + \
           ("X" if p_flags & 1 else "-")


def parse(path, hexdump=False):
    data = open(path, "rb").read()
    print("%s -- %d bytes\n" % (path, len(data)))

    # ---------------------------------------------------------------- e_ident
    # The first 16 bytes are e_ident and are IDENTICAL in every ELF file,
    # 32-bit or 64-bit, big-endian or little. They have to be: nothing can be
    # decoded until you have read them, because they tell you the width and the
    # byte order of everything that follows.
    if data[:4] != ELF_MAGIC:
        print("Not an ELF file. First four bytes are %s."
              % " ".join("%02X" % b for b in data[:4]))
        return 1

    ei_class = data[4]          # 1 = ELF32, 2 = ELF64
    ei_data = data[5]           # 1 = little-endian, 2 = big-endian
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"

    print("e_ident, file offsets 0x00-0x0F")
    print("  0x00  EI_MAG        %s" % " ".join("%02X" % b for b in data[:4]))
    print("  0x04  EI_CLASS      %d  -> %s" % (ei_class, "ELF64" if is64 else "ELF32"))
    print("  0x05  EI_DATA       %d  -> %s-endian"
          % (ei_data, "little" if ei_data == 1 else "big"))
    print("  0x06  EI_VERSION    %d" % data[6])
    print("  0x07  EI_OSABI      %d" % data[7])
    print("  0x08  EI_ABIVERSION %d" % data[8])
    print("  0x09  EI_PAD        7 unused bytes\n")

    # ----------------------------------------------------------- the header
    # From offset 16 the two widths diverge. The FIELD ORDER is the same; the
    # sizes of e_entry, e_phoff and e_shoff are what change (4 bytes on ELF32,
    # 8 on ELF64), and every later offset shifts by 12 as a result.
    if is64:
        fmt = endian + "HHIQQQIHHHHHH"
        names = ("e_type e_machine e_version e_entry e_phoff e_shoff e_flags "
                 "e_ehsize e_phentsize e_phnum e_shentsize e_shnum "
                 "e_shstrndx").split()
        offsets = [0x10, 0x12, 0x14, 0x18, 0x20, 0x28, 0x30,
                   0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E]
    else:
        fmt = endian + "HHIIIIIHHHHHH"
        names = ("e_type e_machine e_version e_entry e_phoff e_shoff e_flags "
                 "e_ehsize e_phentsize e_phnum e_shentsize e_shnum "
                 "e_shstrndx").split()
        offsets = [0x10, 0x12, 0x14, 0x18, 0x1C, 0x20, 0x24,
                   0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32]

    vals = struct.unpack_from(fmt, data, 16)
    h = dict(zip(names, vals))

    print("ELF header, from offset 0x10")
    for name, off in zip(names, offsets):
        v = h[name]
        note = ""
        if name == "e_type":
            note = "  <- %s" % ET.get(v, "?")
        elif name == "e_machine":
            m = EM.get(v)
            note = "  <- %s, belongs in lib/%s/" % m if m else "  <- unknown"
        elif name in ("e_entry", "e_flags"):
            note = ""
        shown = "0x%x" % v if name in ("e_entry", "e_flags") else str(v)
        print("  0x%02X  %-12s %s%s" % (off, name, shown, note))

    if h["e_type"] == 3:
        print("\n  e_type is 3, so every address in this file is RELATIVE to a")
        print("  load base the linker chooses at run time. An address you note")
        print("  here is not the address you will see in a debugger; the")
        print("  relationship is runtime = base + this_value.")
    print()

    # -------------------------------------------------------- program headers
    # This is the table the LOADER reads. Note that on ELF32 p_flags sits at the
    # END of the structure and on ELF64 it sits right after p_type. Getting this
    # wrong is the single most common mistake when writing an ELF parser by
    # hand, and the symptom is nonsense permissions on a 32-bit file.
    print("Program headers -- what the dynamic linker reads (%d entries of %d "
          "bytes at offset %d)" % (h["e_phnum"], h["e_phentsize"], h["e_phoff"]))
    print("  %-3s %-18s %-10s %-18s %-10s %-10s %-5s %s"
          % ("#", "p_type", "p_offset", "p_vaddr", "p_filesz", "p_memsz",
             "flags", "p_align"))
    exec_stack = None
    for i in range(h["e_phnum"]):
        base = h["e_phoff"] + i * h["e_phentsize"]
        if is64:
            (p_type, p_flags, p_offset, p_vaddr, _p_paddr,
             p_filesz, p_memsz, p_align) = struct.unpack_from(
                endian + "IIQQQQQQ", data, base)
        else:
            (p_type, p_offset, p_vaddr, _p_paddr, p_filesz,
             p_memsz, p_flags, p_align) = struct.unpack_from(
                endian + "IIIIIIII", data, base)
        print("  %-3d %-18s 0x%-8x 0x%-16x 0x%-8x 0x%-8x %-5s 0x%x"
              % (i, PT.get(p_type, "0x%08x" % p_type), p_offset, p_vaddr,
                 p_filesz, p_memsz, perms(p_flags), p_align))
        if p_type == 0x6474E551:
            exec_stack = bool(p_flags & 1)

    print("\n  A PT_LOAD row is an instruction to the loader: take p_filesz")
    print("  bytes from file offset p_offset, map them at base + p_vaddr with")
    print("  these permissions, and zero-fill the rest up to p_memsz. The gap")
    print("  between p_filesz and p_memsz is .bss, which occupies no bytes in")
    print("  the file at all.")
    if exec_stack is True:
        print("\n  PT_GNU_STACK is EXECUTABLE. That is a real hardening defect.")
    elif exec_stack is False:
        print("\n  PT_GNU_STACK is present and not executable: NX is in effect.")
    else:
        print("\n  No PT_GNU_STACK: the kernel's default applies.")
    print()

    # -------------------------------------------------------- section headers
    # This is the table TOOLS read. The loader never looks at it. Removing it
    # entirely leaves a file that still runs, which is why packers do exactly
    # that.
    if not h["e_shoff"] or not h["e_shnum"]:
        print("No section header table. The file still loads -- the linker")
        print("never reads sections -- but every tool that names things will")
        print("struggle. This is a deliberate anti-analysis measure.")
        return 0

    # Section names live in their own string table, whose index is e_shstrndx.
    # So you must parse the section header table twice: once to find the string
    # table, once to name everything.
    shent = h["e_shentsize"]
    def raw_section(i):
        b = h["e_shoff"] + i * shent
        if is64:
            return struct.unpack_from(endian + "IIQQQQIIQQ", data, b)
        return struct.unpack_from(endian + "IIIIIIIIII", data, b)

    strtab_hdr = raw_section(h["e_shstrndx"])
    str_off, str_size = strtab_hdr[4], strtab_hdr[5]
    shstr = data[str_off:str_off + str_size]

    def name_at(off):
        end = shstr.find(b"\x00", off)
        return shstr[off:end].decode("utf-8", "replace")

    print("Section headers -- what analysis tools read (%d entries of %d bytes "
          "at offset %d)" % (h["e_shnum"], shent, h["e_shoff"]))
    print("  %-3s %-24s %-14s %-18s %-10s %s"
          % ("#", "name", "sh_type", "sh_addr", "sh_offset", "sh_size"))
    stripped = True
    for i in range(h["e_shnum"]):
        s = raw_section(i)
        nm = name_at(s[0])
        print("  %-3d %-24s %-14s 0x%-16x 0x%-8x %d"
              % (i, nm[:24], SHT.get(s[1], "0x%x" % s[1]), s[3], s[4], s[5]))
        if nm == ".symtab":
            stripped = False

    print("\n  sh_addr == 0 means the section is never mapped into memory.")
    print("  .symtab, .strtab, .comment and every .debug_* section are like")
    print("  that: metadata for tools, invisible to the running program.")
    print("  %s" % ("This file is STRIPPED: .symtab is gone. .dynsym is not, "
                    "and\n  cannot be, because the linker needs it."
                    if stripped else
                    "This file still has .symtab, so internal function names\n"
                    "  survive. That is unusual in a release build."))

    if hexdump:
        print("\nFirst 64 bytes:")
        for off in range(0, min(64, len(data)), 16):
            chunk = data[off:off + 16]
            hx = " ".join("%02x" % b for b in chunk)
            asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            print("  %04x  %-47s  |%s|" % (off, hx, asc))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[0])
        print("usage: elf_header_by_hand.py <file.so> [--hexdump]")
        sys.exit(2)
    sys.exit(parse(sys.argv[1], "--hexdump" in sys.argv))
