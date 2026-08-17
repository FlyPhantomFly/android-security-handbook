#!/usr/bin/env python3
"""
scripts/01-make-flirt-pat.py

PURPOSE
    Turn a static archive (.a) or a relocatable object (.o) into FLAIR pattern
    lines -- the `.pat` format that Hex-Rays' `sigmake` compiles into a `.sig`
    file, which IDA then uses to put real names on library functions in a
    stripped binary.

    The chapter's claim is that FLIRT is not magic and not opaque: it is a
    first-32-bytes pattern, a CRC over what follows, a length, and a name, with
    the bytes a linker would rewrite blanked out. This script is that claim,
    executable. Reading its output next to `llvm-objdump -d` on the same
    archive is the fastest way to understand why FLIRT identifies a function
    that was compiled at a different address, and why it fails on a function
    whose first 32 bytes are all relocations.

    It is deliberately NOT a reimplementation of `pelf`. `pelf` is the right
    tool if you have FLAIR. This exists so that you can see the format, so
    that you can build patterns on a machine with no IDA licence, and so that
    the chapter can make measured claims about signature coverage instead of
    repeating the documentation.

USAGE
    # host -- an archive
    python3 -B scripts/01-make-flirt-pat.py /tmp/ch58/libcrcutil.a

    # host -- write the pattern file where sigmake would want it
    python3 -B scripts/01-make-flirt-pat.py /tmp/ch58/libcrcutil.a -o crcutil.pat

    # host -- show the masking decisions, which is where the learning is
    python3 -B scripts/01-make-flirt-pat.py /tmp/ch58/libcrcutil.a --explain

    Then, IF you have FLAIR (it ships with an IDA Pro licence; it is not
    downloadable separately and this repository will not tell you otherwise):
        sigmake -n"ch58 crcutil" crcutil.pat crcutil.sig
    and drop crcutil.sig into <IDA>/sig/arm/.

    Build the input first:
        cd examples && OUTDIR=/tmp/ch58 ./build.sh

EXECUTION STATUS
    EXECUTED. Run against /tmp/ch58/libcrcutil.a, built by examples/build.sh
    from NDK 25.2.9519653 (clang 14.0.7, aarch64). The three functions it
    finds, their lengths and their masks are quoted in the chapter's section
    3.7 and in labs/lab-03-flirt-and-typelibs.md.

    NOT VERIFIED AGAINST sigmake. IDA is not installed on the machine where
    this chapter was written, so the output has never been compiled into a
    .sig and loaded. What HAS been verified here:
      * the ar and ELF64 parsing, against llvm-nm and llvm-readelf output
      * the field widths and ordering, against the published .pat grammar
      * that every emitted line round-trips through this file's own parser
    What has NOT been verified: that sigmake accepts these lines, and that the
    CRC16 below is byte-for-byte the one FLAIR uses. Treat the CRC column as
    structurally correct and numerically unconfirmed, and say so if you ever
    put a number from it in a report.

REQUIREMENTS
    Python 3.8+. Standard library only. No IDA, no FLAIR, no network.

AUTHORISED TESTING ONLY. Build signatures from libraries you are entitled to
possess. Redistributing signatures for a proprietary library can carry the same
licensing questions as redistributing the library.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# The .pat grammar, stated once so the code below can be read against it.
#
#   <PATTERN> <ALEN> <ACRC> <TLEN> <:OFF NAME>... [<^OFF NAME>...] [TAIL]
#
#   PATTERN  exactly 64 hex characters = the function's first 32 bytes.
#            A byte the linker may rewrite is written as '..' -- two dots.
#            If the function is shorter than 32 bytes the remainder is dots.
#   ALEN     2 hex digits: how many bytes AFTER the first 32 the CRC covers.
#            Counting stops at the first variant byte, and at 0xFF.
#   ACRC     4 hex digits: the CRC16 over exactly those ALEN bytes.
#   TLEN     4 hex digits: the function's total length.
#   :OFF NAME  a public name at that offset inside the function. Offset is
#            4 hex digits. There is normally exactly one, at :0000.
#   ^OFF NAME  a name this function REFERENCES at that offset -- how FLIRT
#            resolves the "two functions with identical bodies that differ only
#            in what they call" case.
#
# The file ends with a line containing three hyphens.
#
# The design consequence worth understanding: FLIRT identifies a function by
# its FIRST 32 BYTES. A function whose prologue is generic -- and AArch64
# prologues are extremely generic -- collides with every other function that
# starts the same way, which is what the CRC and the length are for, and what
# sigmake's collision file (.exc) exists to arbitrate.
# --------------------------------------------------------------------------- #

PATTERN_BYTES = 32
MAX_CRC_BYTES = 0xFF
VARIANT = ".."


# --------------------------------------------------------------------------- #
# CRC16.
#
# FLAIR uses a reflected CRC16 with polynomial 0x8408 (the reversed form of
# 0x1021), seeded with 0xFFFF and finally complemented and byte-swapped. That
# is the algorithm published in FLAIR's crc16.cpp and reproduced in many
# places; it is implemented here from that description.
#
# It has NOT been checked against sigmake on this machine -- see the header.
# If you have FLAIR, the one-command check is: run pelf over the same archive,
# and diff its ACRC column against this script's.
# --------------------------------------------------------------------------- #
POLY = 0x8408


def crc16(data: bytes) -> int:
    if not data:
        return 0
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
    crc = (~crc) & 0xFFFF
    # byte-swap
    return ((crc >> 8) | (crc << 8)) & 0xFFFF


# --------------------------------------------------------------------------- #
# ar archive reader.
# --------------------------------------------------------------------------- #
AR_MAGIC = b"!<arch>\n"


def read_ar(blob: bytes) -> List[Tuple[str, bytes]]:
    """Return [(member name, member bytes)] from a System V / GNU ar archive."""
    if not blob.startswith(AR_MAGIC):
        raise ValueError("not an ar archive (bad magic)")

    members: List[Tuple[str, bytes]] = []
    longnames = b""
    pos = len(AR_MAGIC)

    while pos + 60 <= len(blob):
        header = blob[pos:pos + 60]
        if header[58:60] != b"`\n":
            # Some writers pad; try to resynchronise on the next even offset.
            pos += 1
            continue
        raw_name = header[0:16].decode("ascii", "replace").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            break
        data = blob[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)

        if raw_name == "//":
            longnames = data                      # GNU long-name string table
            continue
        if raw_name in ("/", "/SYM64/"):
            continue                              # the symbol index; not an object

        name = raw_name
        if name.startswith("/") and name[1:].isdigit() and longnames:
            off = int(name[1:])
            end = longnames.find(b"/\n", off)
            if end < 0:
                end = longnames.find(b"\n", off)
            name = longnames[off:end].decode("ascii", "replace")
        name = name.rstrip("/")
        members.append((name, data))

    return members


# --------------------------------------------------------------------------- #
# Minimal ELF64 relocatable-object reader.
#
# Only what this script needs: section table, .symtab, and the RELA sections.
# Chapter 15 owns ELF properly; this is the fifty lines of it that matter here.
# --------------------------------------------------------------------------- #
SHT_SYMTAB = 2
SHT_RELA = 4
STT_FUNC = 2


@dataclass
class Section:
    name: str
    sh_type: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int
    addralign: int


@dataclass
class Func:
    name: str
    obj: str
    sec_index: int
    value: int
    size: int
    data: bytes = b""
    variant: List[int] = field(default_factory=list)   # byte offsets to mask


class Elf64Obj:
    def __init__(self, blob: bytes, label: str):
        self.blob = blob
        self.label = label
        if blob[:4] != b"\x7fELF":
            raise ValueError(f"{label}: not an ELF file")
        if blob[4] != 2:
            raise ValueError(f"{label}: not ELF64 (this script is arm64/x86_64 only)")
        if blob[5] != 1:
            raise ValueError(f"{label}: not little-endian")

        (self.e_type, self.e_machine) = struct.unpack_from("<HH", blob, 0x10)
        (self.e_shoff,) = struct.unpack_from("<Q", blob, 0x28)
        (self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
            "<HHH", blob, 0x3A)
        self.sections = self._read_sections()

    def _read_sections(self) -> List[Section]:
        raw = []
        for i in range(self.e_shnum):
            base = self.e_shoff + i * self.e_shentsize
            (sh_name, sh_type, _flags, _addr, sh_off, sh_size,
             sh_link, sh_info, sh_align, sh_entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", self.blob, base)
            raw.append((sh_name, Section("", sh_type, sh_off, sh_size,
                                         sh_link, sh_info, sh_entsize, sh_align)))
        strtab = raw[self.e_shstrndx][1]
        names = self.blob[strtab.offset:strtab.offset + strtab.size]
        out = []
        for sh_name, sec in raw:
            end = names.find(b"\x00", sh_name)
            sec.name = names[sh_name:end].decode("ascii", "replace")
            out.append(sec)
        return out

    def functions(self) -> List[Func]:
        symtab = next((s for s in self.sections if s.sh_type == SHT_SYMTAB), None)
        if symtab is None:
            return []
        strtab = self.sections[symtab.link]
        strs = self.blob[strtab.offset:strtab.offset + strtab.size]

        funcs: List[Func] = []
        count = symtab.size // 24
        for i in range(count):
            base = symtab.offset + i * 24
            (st_name, st_info, _st_other, st_shndx, st_value, st_size) = \
                struct.unpack_from("<IBBHQQ", self.blob, base)
            if (st_info & 0xF) != STT_FUNC or st_size == 0:
                continue
            if st_shndx == 0 or st_shndx >= len(self.sections):
                continue
            end = strs.find(b"\x00", st_name)
            name = strs[st_name:end].decode("ascii", "replace")
            if not name:
                continue
            funcs.append(Func(name=name, obj=self.label, sec_index=st_shndx,
                              value=st_value, size=st_size))

        for f in funcs:
            sec = self.sections[f.sec_index]
            f.data = self.blob[sec.offset + f.value: sec.offset + f.value + f.size]
            f.variant = self._variant_offsets(f)
        return funcs

    def _variant_offsets(self, f: Func) -> List[int]:
        """Byte offsets inside f that a linker will rewrite.

        Every RELA entry whose target section is f's section and whose offset
        falls inside f marks a fixup. On AArch64 the fixup patches a field
        inside a 4-byte instruction word, and the instruction's own opcode bits
        are untouched -- but FLIRT cannot express "these 11 bits vary", so the
        whole word is marked variant. That over-masking is the honest cost of a
        byte-level format on a fixed-width RISC, and it is why AArch64 FLIRT
        coverage is weaker than x86 FLIRT coverage.
        """
        marks: List[int] = []
        for sec in self.sections:
            if sec.sh_type != SHT_RELA or sec.info != f.sec_index:
                continue
            n = sec.size // 24
            for i in range(n):
                (r_offset, _r_info, _r_addend) = struct.unpack_from(
                    "<QQq", self.blob, sec.offset + i * 24)
                rel = r_offset - f.value
                if 0 <= rel < f.size:
                    word = rel - (rel % 4) if self.e_machine == 183 else rel
                    width = 4 if self.e_machine == 183 else 4
                    for b in range(word, min(word + width, f.size)):
                        marks.append(b)
        return sorted(set(marks))


# --------------------------------------------------------------------------- #
# .pat line construction.
# --------------------------------------------------------------------------- #
def pat_line(f: Func) -> Tuple[str, Dict[str, object]]:
    variant = set(f.variant)

    # Field 1 -- the first 32 bytes, with variant bytes as '..'
    cells: List[str] = []
    for i in range(PATTERN_BYTES):
        if i >= len(f.data):
            cells.append(VARIANT)
        elif i in variant:
            cells.append(VARIANT)
        else:
            cells.append("%02X" % f.data[i])
    pattern = "".join(cells)

    # Fields 2 and 3 -- CRC over bytes 32.., stopping at the first variant byte
    crc_len = 0
    i = PATTERN_BYTES
    while i < len(f.data) and crc_len < MAX_CRC_BYTES and i not in variant:
        crc_len += 1
        i += 1
    crc_data = f.data[PATTERN_BYTES:PATTERN_BYTES + crc_len]
    crc = crc16(crc_data)

    line = "%s %02X %04X %04X :0000 %s" % (pattern, crc_len, crc, f.size, f.name)

    info = {
        "name": f.name,
        "obj": f.obj,
        "size": f.size,
        "variant_in_pattern": sorted(b for b in variant if b < PATTERN_BYTES),
        "variant_total": len(variant),
        "crc_len": crc_len,
        "crc": crc,
        "pattern_all_variant": all(c == VARIANT for c in cells),
    }
    return line, info


# --------------------------------------------------------------------------- #
def parse_pat_line(line: str) -> Dict[str, object]:
    """Round-trip check: parse a line this script produced.

    This is the only correctness guarantee the script can offer without FLAIR,
    so it is run over every emitted line by default. It verifies field widths
    and that the pattern field is exactly 64 characters of hex-or-dot.
    """
    parts = line.split()
    if len(parts) < 6:
        raise ValueError("too few fields")
    pattern, alen, acrc, tlen, off, name = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
    if len(pattern) != PATTERN_BYTES * 2:
        raise ValueError("pattern field is %d chars, expected %d"
                         % (len(pattern), PATTERN_BYTES * 2))
    for i in range(0, len(pattern), 2):
        cell = pattern[i:i + 2]
        if cell != VARIANT:
            int(cell, 16)
    if len(alen) != 2 or len(acrc) != 4 or len(tlen) != 4:
        raise ValueError("field widths wrong: %r %r %r" % (alen, acrc, tlen))
    if not off.startswith(":"):
        raise ValueError("public-name marker missing")
    return {"name": name, "crc_len": int(alen, 16),
            "crc": int(acrc, 16), "size": int(tlen, 16)}


# --------------------------------------------------------------------------- #
MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}


def collect(path: str) -> Tuple[List[Func], Optional[int]]:
    with open(path, "rb") as fh:
        blob = fh.read()

    members: List[Tuple[str, bytes]]
    if blob.startswith(AR_MAGIC):
        members = read_ar(blob)
    elif blob[:4] == b"\x7fELF":
        members = [(path.rsplit("/", 1)[-1], blob)]
    else:
        raise SystemExit("error: %s is neither an ar archive nor an ELF file" % path)

    funcs: List[Func] = []
    machine = None
    for name, data in members:
        if data[:4] != b"\x7fELF":
            continue
        obj = Elf64Obj(data, name)
        machine = obj.e_machine
        funcs.extend(obj.functions())
    return funcs, machine


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate FLAIR .pat lines from a static archive or object file.")
    ap.add_argument("input", help="path to a .a archive or a .o object")
    ap.add_argument("-o", "--output", help="write the .pat file here (default: stdout)")
    ap.add_argument("--explain", action="store_true",
                    help="print, per function, why each byte was masked")
    ap.add_argument("--min-size", type=int, default=0,
                    help="skip functions shorter than this many bytes")
    args = ap.parse_args()

    funcs, machine = collect(args.input)
    if not funcs:
        print("no sized STT_FUNC symbols found in %s" % args.input, file=sys.stderr)
        print("  (a fully stripped .so has none -- FLIRT patterns are built from",
              file=sys.stderr)
        print("   the LIBRARY you have symbols for, then applied to the target",
              file=sys.stderr)
        print("   you do not. That direction is the whole point.)", file=sys.stderr)
        return 1

    lines: List[str] = []
    reports: List[Dict[str, object]] = []
    skipped = 0
    for f in sorted(funcs, key=lambda x: x.name):
        if f.size < args.min_size:
            skipped += 1
            continue
        line, info = pat_line(f)
        parse_pat_line(line)          # round-trip or die
        lines.append(line)
        reports.append(info)

    out = "\n".join(lines) + "\n---\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
        print("wrote %d patterns to %s" % (len(lines), args.output), file=sys.stderr)
    else:
        sys.stdout.write(out)

    arch = MACHINES.get(machine or -1, "machine %s" % machine)
    print("", file=sys.stderr)
    print("architecture      : %s" % arch, file=sys.stderr)
    print("functions found   : %d  (%d skipped by --min-size)"
          % (len(lines), skipped), file=sys.stderr)
    print("round-trip parse  : all %d lines OK" % len(lines), file=sys.stderr)

    weak = [r for r in reports if r["pattern_all_variant"]]
    if weak:
        print("", file=sys.stderr)
        print("WARNING: %d function(s) are entirely variant in the first 32 bytes"
              % len(weak), file=sys.stderr)
        print("  and cannot be matched by pattern at all:", file=sys.stderr)
        for r in weak:
            print("    %s" % r["name"], file=sys.stderr)

    if args.explain:
        print("", file=sys.stderr)
        print("per-function detail", file=sys.stderr)
        print("-" * 70, file=sys.stderr)
        for r in reports:
            print("%-16s from %-16s size %4d bytes" %
                  (r["name"], r["obj"], r["size"]), file=sys.stderr)
            v = r["variant_in_pattern"]
            if v:
                print("   masked in the first 32 bytes: %s"
                      % ", ".join("+0x%02x" % b for b in v), file=sys.stderr)
                print("   -> each is a 4-byte instruction word carrying a", file=sys.stderr)
                print("      relocation the linker will rewrite", file=sys.stderr)
            else:
                print("   nothing masked in the first 32 bytes -- a strong pattern",
                      file=sys.stderr)
            print("   CRC covers %d byte(s) after the pattern, value 0x%04X"
                  % (r["crc_len"], r["crc"]), file=sys.stderr)
            if r["crc_len"] == 0:
                print("      (zero, because byte 32 is either past the end of the",
                      file=sys.stderr)
                print("       function or is itself variant -- a weaker signature)",
                      file=sys.stderr)
            print("", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
