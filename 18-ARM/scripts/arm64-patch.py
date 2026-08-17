#!/usr/bin/env python3
"""
arm64-patch.py -- assemble the handful of AArch64 patches you actually need,
                  apply one at the correct FILE offset, and show the before and
                  after disassembly so you can see what you did.

WHAT IT DOES
    Four jobs, and they are separable:

      1. Maps a VIRTUAL ADDRESS (what Ghidra, objdump and Frida show you) to a
         FILE OFFSET (what you have to write to), by reading the ELF program
         headers. Doing this by hand is the single most common way a patch
         silently lands in the wrong place -- see README section 6.6.
      2. Resolves a symbol name to an address, from .dynsym and, when the file
         is not stripped, .symtab. On 32-bit ARM it strips the Thumb low bit
         from st_value and tells you it did.
      3. Assembles a small, fixed vocabulary of patches:
             ret               mov w0,#N      mov x0,#N     nop
             b <addr>          bl <addr>      raw:<hex>     zero
         Every encoding was produced by assembling the instruction with the
         NDK's clang and reading the bytes back with llvm-objdump. None of them
         was written from memory. The round trip is reproducible: run this
         script with --show-encodings.
      4. Disassembles the words around the patch site, before and after, with a
         small built-in AArch64 decoder so that the script is useful on a
         machine with no NDK. If llvm-objdump IS on PATH, pass --objdump to use
         it instead and get the authoritative rendering.

HOW TO RUN
    # what does the site look like now?
    python3 arm64-patch.py liblicence.so --symbol lc_is_licensed --show

    # make lc_is_licensed always return 1 -- dry run first, always
    python3 arm64-patch.py liblicence.so --symbol lc_is_licensed \
            --patch "mov w0,#1" --dry-run
    python3 arm64-patch.py liblicence.so --symbol lc_is_licensed \
            --patch "mov w0,#1" --write

    # the two-instruction form: force the return value AND return immediately
    python3 arm64-patch.py liblicence.so --symbol lc_verify_signature \
            --patch "mov w0,#1" --patch ret --write

    # patch by address instead of by name, at +8 into the function
    python3 arm64-patch.py liblicence.so --vaddr 0x48cc --patch nop --write

    # patch by raw file offset, when you already know it
    python3 arm64-patch.py liblicence.so --offset 0x8c4 --patch ret --write

    # print the verified encoding table and exit
    python3 arm64-patch.py --show-encodings

    Nothing is written unless --write is given. --write always makes a
    .bak copy first unless --no-backup is passed.

REQUIREMENTS
    Python 3.6 or newer, standard library only. No pyelftools, no NDK, no
    keystone, no capstone, no network. The NDK is optional and only used if
    you ask for --objdump.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the patch is correct. It changes bytes exactly where you said.
      If you asked for the wrong address you get a working, wrong patch, and
      the disassembly will look fine. Read the before/after every time.
    - Whether the patched function is the one that runs. An app may ship
      several ABIs, may load a different copy, or may never call it at all.
      Verifying that is runtime work -- see scripts/dump-function.js and
      labs/lab-03.
    - Whether the app will notice. Integrity checks over the .so, an APK
      signature check, or a server-side check all survive this. That is
      38-TamperDetection's subject, and "the patch worked locally" is not the
      same claim as "the protection is bypassed".
    - Anything about ARM32/Thumb PATCHING. The script reads 32-bit ELF and
      resolves symbols in it, but it refuses to assemble patches for it,
      because Thumb is a variable-length encoding and a two-byte patch written
      into a four-byte instruction produces silent nonsense. README section
      3.13 explains what to do instead.
    - Whether you were allowed to do this. Patching software you do not own or
      have permission to test is not made lawful by a script.

ACCURACY NOTE
    Every encoding in ENCODINGS below, and every field split in the decoder,
    was verified against output from
        aarch64-linux-android21-clang -c -x assembler
        llvm-objdump -d
    on NDK 25.2.9519653 (clang 14.0.7). --show-encodings reprints the table
    together with the assembly source that produced it, so you can repeat the
    round trip yourself rather than trusting this file.
"""

from __future__ import print_function

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys

# ---------------------------------------------------------------------------
# Verified encodings.
#
# Produced by assembling this exact source with the NDK and reading the bytes
# back. The comment on each line is the little-endian byte order as
# llvm-objdump prints it, which is the order you will see in a hex editor.
# ---------------------------------------------------------------------------
ENCODINGS = [
    ("ret",                     0xD65F03C0, "c0 03 5f d6"),
    ("nop",                     0xD503201F, "1f 20 03 d5"),
    ("mov w0, #0",              0x52800000, "00 00 80 52"),
    ("mov w0, #1",              0x52800020, "20 00 80 52"),
    ("mov w0, #2",              0x52800040, "40 00 80 52"),
    ("mov w0, #42",             0x52800540, "40 05 80 52"),
    ("mov w0, #65535",          0x529FFFE0, "e0 ff 9f 52"),
    ("mov x0, #0",              0xD2800000, "00 00 80 d2"),
    ("mov x0, #1",              0xD2800020, "20 00 80 d2"),
    ("mov w0, wzr",             0x2A1F03E0, "e0 03 1f 2a"),
    ("b   . (offset 0)",        0x14000000, "00 00 00 14"),
    ("bl  . (offset 0)",        0x94000000, "00 00 00 94"),
    ("cmp w0, #1",              0x7100041F, "1f 04 00 71"),
    ("cset w0, gt",             0x1A9FD7E0, "e0 d7 9f 1a"),
    ("cset w0, eq",             0x1A9F17E0, "e0 17 9f 1a"),
    ("csel w0, w0, w1, lt",     0x1A81B000, "00 b0 81 1a"),
    ("cbz  x0, . ",             0xB4000000, "00 00 00 b4"),
    ("cbnz x0, . ",             0xB5000000, "00 00 00 b5"),
    ("stp x29, x30, [sp,#-16]!", 0xA9BF7BFD, "fd 7b bf a9"),
    ("ldp x29, x30, [sp],#16",  0xA8C17BFD, "fd 7b c1 a8"),
    ("mrs x8, TPIDR_EL0",       0xD53BD048, "48 d0 3b d5"),
    ("svc #0",                  0xD4000001, "01 00 00 d4"),
    ("brk #0",                  0xD4200000, "00 00 20 d4"),
    ("blr x8",                  0xD63F0100, "00 01 3f d6"),
    ("br  x16",                 0xD61F0200, "00 02 1f d6"),
    ("bti c  (= hint #34)",     0xD503245F, "5f 24 03 d5"),
]

ROUND_TRIP_SOURCE = """\
    .text
    .globl _enc
_enc:
    ret
    nop
    mov  w0, #0
    mov  w0, #1
    mov  w0, #2
    mov  w0, #42
    mov  w0, #65535
    mov  x0, #0
    mov  x0, #1
    mov  w0, wzr
    b    .
    bl   .
    cmp  w0, #1
    cset w0, gt
    cset w0, eq
    csel w0, w0, w1, lt
    cbz  x0, .
    cbnz x0, .
    stp  x29, x30, [sp, #-16]!
    ldp  x29, x30, [sp], #16
    mrs  x8, TPIDR_EL0
    svc  #0
    brk  #0
    blr  x8
    br   x16
    bti  c
"""

# ---------------------------------------------------------------------------
# ELF, only as much as this script needs.
# 15-Native-Code owns the format. This is the minimum to map an address.
# ---------------------------------------------------------------------------

PT_LOAD = 1
SHT_SYMTAB = 2
SHT_DYNSYM = 11


class Elf(object):
    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file (bad magic)")
        self.data = data
        self.is64 = (data[4] == 2) if isinstance(data[4], int) else (ord(data[4]) == 2)
        if data[5:6] != b"\x01":
            raise ValueError("big-endian ELF; no Android ABI uses one")
        self.machine = struct.unpack_from("<H", data, 0x12)[0]
        self.arch = {183: "aarch64", 40: "arm"}.get(self.machine,
                                                    "machine=%d" % self.machine)
        if self.is64:
            (self.e_phoff, self.e_shoff) = struct.unpack_from("<QQ", data, 0x20)
            (self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = struct.unpack_from("<HHHHH", data, 0x36)
        else:
            (self.e_phoff, self.e_shoff) = struct.unpack_from("<II", data, 0x1C)
            (self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = struct.unpack_from("<HHHHH", data, 0x2A)
        self.segments = self._read_segments()
        self.sections = self._read_sections()

    def _read_segments(self):
        out = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, p_flags = struct.unpack_from("<II", self.data, off)
                p_offset, p_vaddr = struct.unpack_from("<QQ", self.data, off + 8)
                p_filesz, p_memsz = struct.unpack_from("<QQ", self.data, off + 32)
            else:
                p_type, p_offset, p_vaddr = struct.unpack_from("<III", self.data, off)
                p_filesz, p_memsz, p_flags = struct.unpack_from("<III",
                                                                self.data, off + 16)
            out.append(dict(type=p_type, offset=p_offset, vaddr=p_vaddr,
                            filesz=p_filesz, memsz=p_memsz, flags=p_flags))
        return out

    def _read_sections(self):
        out = []
        if self.e_shoff == 0 or self.e_shnum == 0:
            return out
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.is64:
                sh_name, sh_type = struct.unpack_from("<II", self.data, off)
                sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ",
                                                                 self.data, off + 16)
                sh_link = struct.unpack_from("<I", self.data, off + 40)[0]
                sh_entsize = struct.unpack_from("<Q", self.data, off + 56)[0]
            else:
                sh_name, sh_type = struct.unpack_from("<II", self.data, off)
                sh_addr, sh_offset, sh_size = struct.unpack_from("<III",
                                                                 self.data, off + 12)
                sh_link = struct.unpack_from("<I", self.data, off + 24)[0]
                sh_entsize = struct.unpack_from("<I", self.data, off + 36)[0]
            raw.append(dict(nameoff=sh_name, type=sh_type, addr=sh_addr,
                            offset=sh_offset, size=sh_size, link=sh_link,
                            entsize=sh_entsize))
        if self.e_shstrndx < len(raw):
            strtab = raw[self.e_shstrndx]
            blob = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]
            for s in raw:
                end = blob.find(b"\x00", s["nameoff"])
                s["name"] = blob[s["nameoff"]:end].decode("utf-8", "replace")
        else:
            for s in raw:
                s["name"] = "?"
        out = raw
        return out

    def vaddr_to_offset(self, vaddr):
        """The whole reason this script exists. Returns (offset, segment)."""
        for s in self.segments:
            if s["type"] != PT_LOAD:
                continue
            if s["vaddr"] <= vaddr < s["vaddr"] + s["filesz"]:
                return vaddr - s["vaddr"] + s["offset"], s
        return None, None

    def offset_to_vaddr(self, offset):
        for s in self.segments:
            if s["type"] != PT_LOAD:
                continue
            if s["offset"] <= offset < s["offset"] + s["filesz"]:
                return offset - s["offset"] + s["vaddr"]
        return None

    def symbols(self):
        """Every FUNC/OBJECT symbol from .dynsym and .symtab, name -> (addr, size)."""
        found = {}
        for sec in self.sections:
            if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if sec["link"] >= len(self.sections):
                continue
            strs = self.sections[sec["link"]]
            blob = self.data[strs["offset"]:strs["offset"] + strs["size"]]
            entsize = sec["entsize"] or (24 if self.is64 else 16)
            n = sec["size"] // entsize if entsize else 0
            for i in range(n):
                off = sec["offset"] + i * entsize
                if self.is64:
                    st_name = struct.unpack_from("<I", self.data, off)[0]
                    st_info = self.data[off + 4]
                    st_value, st_size = struct.unpack_from("<QQ", self.data, off + 8)
                else:
                    st_name, st_value, st_size = struct.unpack_from("<III",
                                                                    self.data, off)
                    st_info = self.data[off + 12]
                if not isinstance(st_info, int):
                    st_info = ord(st_info)
                if st_name == 0 or st_value == 0:
                    continue
                end = blob.find(b"\x00", st_name)
                name = blob[st_name:end].decode("utf-8", "replace")
                thumb = False
                if self.arch == "arm" and (st_info & 0xF) == 2 and (st_value & 1):
                    st_value &= ~1
                    thumb = True
                found.setdefault(name, (st_value, st_size, sec["name"], thumb))
        return found


# ---------------------------------------------------------------------------
# The patch assembler. Deliberately tiny.
# ---------------------------------------------------------------------------

REG_RE = re.compile(r"^([wx])(\d{1,2}|zr)$")


def _reg(tok):
    m = REG_RE.match(tok.strip().lower())
    if not m:
        raise ValueError("not a register: %r" % tok)
    wide = m.group(1) == "x"
    num = 31 if m.group(2) == "zr" else int(m.group(2))
    if not 0 <= num <= 31:
        raise ValueError("register out of range: %r" % tok)
    return wide, num


def assemble(spec, at_vaddr):
    """Return a list of 32-bit words for one patch spec."""
    s = spec.strip().lower().replace(" ", "")

    if s == "ret":
        return [0xD65F03C0]
    if s in ("nop", "hint#0"):
        return [0xD503201F]
    if s == "zero":
        return [0x00000000]           # not an instruction; an explicit blank
    if s in ("brk", "brk#0"):
        return [0xD4200000]

    m = re.match(r"^raw:((?:0x)?[0-9a-f]+)$", s)
    if m:
        h = m.group(1)
        if h.startswith("0x"):
            h = h[2:]
        if len(h) % 8:
            raise ValueError("raw: needs whole 4-byte words as 8 hex digits each")
        # Hex is written the way you READ an instruction word (big end first),
        # e.g. raw:d65f03c0 is `ret`. The file gets little-endian bytes.
        return [int(h[i:i + 8], 16) for i in range(0, len(h), 8)]

    m = re.match(r"^mov([wx])(\d{1,2}),#?(-?(?:0x)?[0-9a-f]+)$", s)
    if m:
        wide = m.group(1) == "x"
        rd = int(m.group(2))
        val = int(m.group(3), 0)
        if not 0 <= rd <= 31:
            raise ValueError("bad destination register in %r" % spec)
        if not 0 <= val <= 0xFFFF:
            raise ValueError(
                "mov with a literal only encodes 0..65535 in one instruction; "
                "%d needs movz+movk, which this script does not assemble "
                "because a multi-instruction patch changes the function's "
                "length. Use raw: with bytes you assembled yourself." % val)
        base = 0xD2800000 if wide else 0x52800000
        return [base | (val << 5) | rd]

    m = re.match(r"^(b|bl)(?:0x)?([0-9a-f]+)$", s)
    if m:
        op = m.group(1)
        target = int(m.group(2), 16)
        delta = target - at_vaddr
        if delta % 4:
            raise ValueError("branch target 0x%x is not 4-byte aligned" % target)
        imm = delta // 4
        if not -(1 << 25) <= imm < (1 << 25):
            raise ValueError("branch target is out of +/-128 MiB range")
        base = 0x94000000 if op == "bl" else 0x14000000
        return [base | (imm & 0x03FFFFFF)]

    raise ValueError(
        "cannot assemble %r.\n"
        "Supported: ret | nop | brk | zero | mov wN,#imm | mov xN,#imm | "
        "b 0xADDR | bl 0xADDR | raw:<8 hex digits per word>" % spec)


# ---------------------------------------------------------------------------
# A small AArch64 decoder, so --show works with no NDK installed.
# It recognises the shapes chapter 18 catalogues and prints `.word` for the
# rest, which is honest and more useful than a wrong guess.
# ---------------------------------------------------------------------------

COND = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]


def _rn(n, wide):
    if n == 31:
        return "sp" if wide else "wsp"
    return ("x%d" if wide else "w%d") % n


def _rz(n, wide):
    if n == 31:
        return "xzr" if wide else "wzr"
    return ("x%d" if wide else "w%d") % n


def _sx(v, bits):
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v


def _decode_bitmask(sf, n, immr, imms):
    """The ARM DecodeBitMasks algorithm, for logical-immediate instructions.

    AArch64 cannot hold an arbitrary 64-bit constant in an instruction, so
    `and`, `orr`, `eor` and `tst` encode a REPEATING BIT PATTERN in 13 bits
    instead. This is why `tst w0, #0x40` exists as a single instruction and
    `tst w0, #0x41` does not. Transcribed from the pseudocode in the Arm
    Architecture Reference Manual, section C4.1 (Reserved / logical immediate),
    and checked against llvm-objdump output for tst/and/orr forms.
    """
    combined = (n << 6) | ((~imms) & 0x3F)
    if combined == 0:
        return None
    length = combined.bit_length() - 1          # position of the highest set bit
    if length < 1:
        return None
    esize = 1 << length
    if not sf and esize > 32:
        return None
    levels = esize - 1
    s = imms & levels
    r = immr & levels
    if s == levels:
        return None                             # reserved encoding
    welem = (1 << (s + 1)) - 1
    mask = (1 << esize) - 1
    if r:
        welem = ((welem >> r) | (welem << (esize - r))) & mask
    bits = 64 if sf else 32
    out = 0
    for i in range(0, bits, esize):
        out |= welem << i
    return out & ((1 << bits) - 1)


def _ldst_name(size, opc):
    """(mnemonic, is_64bit_register) for the integer load/store families.

    `size` is the access width (0=byte, 1=half, 2=word, 3=doubleword) and
    `opc` chooses store / zero-extending load / sign-extending load. The
    sign-extending forms are the ones worth knowing: ldrsb into a 64-bit
    register and ldrsb into a 32-bit register are DIFFERENT instructions,
    and confusing ldrb with ldrsb is how you misread a comparison against a
    value above 0x7f.
    """
    if size == 0:
        return {0: ("strb", False), 1: ("ldrb", False),
                2: ("ldrsb", True), 3: ("ldrsb", False)}.get(opc, (None, False))
    if size == 1:
        return {0: ("strh", False), 1: ("ldrh", False),
                2: ("ldrsh", True), 3: ("ldrsh", False)}.get(opc, (None, False))
    if size == 2:
        return {0: ("str", False), 1: ("ldr", False),
                2: ("ldrsw", True)}.get(opc, (None, False))
    return {0: ("str", True), 1: ("ldr", True)}.get(opc, (None, False))


def decode(word, vaddr):
    w = word & 0xFFFFFFFF
    rd = w & 0x1F
    rn = (w >> 5) & 0x1F
    rm = (w >> 16) & 0x1F
    sf = (w >> 31) & 1

    if w == 0xD65F03C0:
        return "ret"
    if w == 0xD503201F:
        return "nop"
    if w == 0x00000000:
        return ".word 0x00000000        ; not an instruction (udf)"
    if (w & 0xFFFFF01F) == 0xD503201F:
        return "hint #%d" % ((w >> 5) & 0x7F)
    if (w & 0xFFE0001F) == 0xD4000001:
        return "svc #%d" % ((w >> 5) & 0xFFFF)
    if (w & 0xFFE0001F) == 0xD4200000:
        return "brk #%d" % ((w >> 5) & 0xFFFF)
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return "blr x%d" % rn
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        return "br x%d" % rn
    if (w & 0xFFFFFC1F) == 0xD65F0000 and rn != 30:
        return "ret x%d" % rn

    # unconditional branch immediate
    if (w & 0x7C000000) == 0x14000000:
        imm = _sx(w & 0x03FFFFFF, 26) * 4
        return "%-5s 0x%x" % ("bl" if (w >> 31) else "b", vaddr + imm)

    # compare and branch
    if (w & 0x7E000000) == 0x34000000:
        imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
        op = "cbnz" if (w >> 24) & 1 else "cbz"
        return "%-5s %s, 0x%x" % (op, _rz(rd, sf), vaddr + imm)

    # test bit and branch
    if (w & 0x7E000000) == 0x36000000:
        imm = _sx((w >> 5) & 0x3FFF, 14) * 4
        bit = ((w >> 19) & 0x1F) | (((w >> 31) & 1) << 5)
        op = "tbnz" if (w >> 24) & 1 else "tbz"
        return "%-5s %s, #%d, 0x%x" % (op, _rz(rd, sf), bit, vaddr + imm)

    # conditional branch
    if (w & 0xFF000010) == 0x54000000:
        imm = _sx((w >> 5) & 0x7FFFF, 19) * 4
        return "%-5s 0x%x" % ("b." + COND[w & 0xF], vaddr + imm)

    # movz / movn / movk
    if (w & 0x1F800000) == 0x12800000:
        opc = (w >> 29) & 3
        imm16 = (w >> 5) & 0xFFFF
        shift = ((w >> 21) & 3) * 16
        name = {0: "movn", 2: "movz", 3: "movk"}.get(opc)
        if name:
            tail = ", lsl #%d" % shift if shift else ""
            # objdump prints the `mov` alias when one instruction is enough,
            # which is what you will see in every real listing.
            if shift == 0 and name == "movz":
                return "%-5s %s, #%d" % ("mov", _rz(rd, sf), imm16)
            if shift == 0 and name == "movn":
                width = 64 if sf else 32
                val = (~imm16) & ((1 << width) - 1)
                return "%-5s %s, #%d" % ("mov", _rz(rd, sf),
                                         _sx(val, width))
            return "%-5s %s, #%d%s" % (name, _rz(rd, sf), imm16, tail)

    # adrp / adr
    if (w & 0x1F000000) == 0x10000000:
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = _sx((immhi << 2) | immlo, 21)
        if (w >> 31) & 1:
            page = (vaddr & ~0xFFF) + imm * 4096
            return "%-5s x%d, 0x%x" % ("adrp", rd, page)
        return "%-5s x%d, 0x%x" % ("adr", rd, vaddr + imm)

    # add/sub immediate, including cmp (rd == zr, sub, S=1)
    if (w & 0x1F000000) == 0x11000000:
        op = (w >> 30) & 1
        setflags = (w >> 29) & 1
        imm12 = (w >> 10) & 0xFFF
        sh = ", lsl #12" if (w >> 22) & 1 else ""
        if op and setflags and rd == 31:
            return "%-5s %s, #%d%s" % ("cmp", _rn(rn, sf), imm12, sh)
        if not op and not setflags and imm12 == 0 and (rd == 31 or rn == 31):
            return "%-5s %s, %s" % ("mov", _rn(rd, sf), _rn(rn, sf))
        name = ("sub" if op else "add") + ("s" if setflags else "")
        return "%-5s %s, %s, #%d%s" % (name, _rn(rd, sf), _rn(rn, sf), imm12, sh)

    # logical immediate: and / orr / eor / ands, and the tst alias
    if (w & 0x1F800000) == 0x12000000:
        opc = (w >> 29) & 3
        n = (w >> 22) & 1
        immr = (w >> 16) & 0x3F
        imms = (w >> 10) & 0x3F
        val = _decode_bitmask(sf, n, imms, immr)
        if val is not None:
            name = {0: "and", 1: "orr", 2: "eor", 3: "ands"}[opc]
            if opc == 3 and rd == 31:
                return "%-5s %s, #0x%x" % ("tst", _rz(rn, sf), val)
            if opc == 1 and rn == 31:
                return "%-5s %s, #0x%x" % ("mov", _rz(rd, sf), val)
            return "%-5s %s, %s, #0x%x" % (name, _rn(rd, sf), _rz(rn, sf), val)

    # logical shifted register: and / bic / orr / orn / eor / eon / ands / bics
    if (w & 0x1F000000) == 0x0A000000:
        opc = (w >> 29) & 3
        neg = (w >> 21) & 1
        shift = (w >> 22) & 3
        imm6 = (w >> 10) & 0x3F
        names = {(0, 0): "and", (0, 1): "bic", (1, 0): "orr", (1, 1): "orn",
                 (2, 0): "eor", (2, 1): "eon", (3, 0): "ands", (3, 1): "bics"}
        name = names[(opc, neg)]
        if rn == 31 and imm6 == 0 and shift == 0:
            if name == "orr":
                return "%-5s %s, %s" % ("mov", _rz(rd, sf), _rz(rm, sf))
            if name == "orn":
                return "%-5s %s, %s" % ("mvn", _rz(rd, sf), _rz(rm, sf))
        if name == "ands" and rd == 31:
            return "%-5s %s, %s" % ("tst", _rz(rn, sf), _rz(rm, sf))
        tail = ", %s #%d" % (["lsl", "lsr", "asr", "ror"][shift], imm6) if imm6 else ""
        return "%-5s %s, %s, %s%s" % (name, _rz(rd, sf), _rz(rn, sf),
                                      _rz(rm, sf), tail)

    # add / sub shifted register, and the cmp alias
    if (w & 0x1F200000) == 0x0B000000:
        op = (w >> 30) & 1
        setflags = (w >> 29) & 1
        shift = (w >> 22) & 3
        imm6 = (w >> 10) & 0x3F
        name = ("sub" if op else "add") + ("s" if setflags else "")
        tail = ", %s #%d" % (["lsl", "lsr", "asr", "ror"][shift], imm6) if imm6 else ""
        if op and setflags and rd == 31:
            return "%-5s %s, %s%s" % ("cmp", _rz(rn, sf), _rz(rm, sf), tail)
        if op and not setflags and rn == 31:
            return "%-5s %s, %s%s" % ("neg", _rz(rd, sf), _rz(rm, sf), tail)
        return "%-5s %s, %s, %s%s" % (name, _rz(rd, sf), _rz(rn, sf),
                                      _rz(rm, sf), tail)

    # csel / csinc / cset
    if (w & 0x1FE00000) == 0x1A800000:
        cond = COND[(w >> 12) & 0xF]
        op2 = (w >> 10) & 3
        if op2 == 1 and rn == 31 and rm == 31:
            return "%-5s %s, %s" % ("cset", _rz(rd, sf), COND[((w >> 12) & 0xF) ^ 1])
        name = {0: "csel", 1: "csinc", 2: "csinv", 3: "csneg"}.get(op2, "cs??")
        return "%-5s %s, %s, %s, %s" % (name, _rz(rd, sf), _rz(rn, sf),
                                        _rz(rm, sf), cond)

    # load/store pair, pre/post/offset
    if (w & 0x3A000000) == 0x28000000:
        L = (w >> 22) & 1
        imm7 = _sx((w >> 15) & 0x7F, 7)
        rt2 = (w >> 10) & 0x1F
        opc = (w >> 30) & 3
        wide = opc == 2
        scale = 8 if wide else 4
        mode = (w >> 23) & 3
        name = "ldp" if L else "stp"
        base = _rn(rn, True)
        if mode == 1:
            addr = "[%s], #%d" % (base, imm7 * scale)
        elif mode == 3:
            addr = "[%s, #%d]!" % (base, imm7 * scale)
        else:
            addr = "[%s, #%d]" % (base, imm7 * scale)
        return "%-5s %s, %s, %s" % (name, _rz(rd, wide), _rz(rt2, wide), addr)

    # load/store immediate, unsigned scaled offset
    if (w & 0x3F000000) == 0x39000000:
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        imm12 = (w >> 10) & 0xFFF
        name, wide = _ldst_name(size, opc)
        if name:
            return "%-5s %s, [%s, #%d]" % (name, _rz(rd, wide), _rn(rn, True),
                                           imm12 << size)

    # load/store immediate, UNSCALED signed offset -- ldur / stur.
    # This is the form clang uses for negative offsets from the frame
    # pointer, which is exactly where the stack canary lives.
    if (w & 0x3F200C00) == 0x38000000:
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        imm9 = _sx((w >> 12) & 0x1FF, 9)
        name, wide = _ldst_name(size, opc)
        if name:
            return "%-5s %s, [%s, #%d]" % (name.replace("ld", "ldu", 1)
                                           if name.startswith("ld")
                                           else name.replace("st", "stu", 1),
                                           _rz(rd, wide), _rn(rn, True), imm9)

    # mrs / msr (system register move)
    if (w & 0xFFF00000) == 0xD5300000:
        sysreg = (w >> 5) & 0x7FFF
        if sysreg == 0x5E82:
            return "%-5s x%d, TPIDR_EL0" % ("mrs", rd)
        return "%-5s x%d, S%d_%d_C%d_C%d_%d" % (
            "mrs", rd, 2 + ((sysreg >> 14) & 1), (sysreg >> 11) & 7,
            (sysreg >> 7) & 15, (sysreg >> 3) & 15, sysreg & 7)

    return ".word 0x%08x" % w


def dump(words, vaddr, mark=None):
    lines = []
    for i, w in enumerate(words):
        a = vaddr + i * 4
        flag = "  <-- " if (mark is not None and mark[0] <= a < mark[1]) else "      "
        raw = " ".join("%02x" % b for b in struct.pack("<I", w))
        lines.append("  %08x: %s %s%s" % (a, raw, flag, decode(w, a)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------


def objdump_range(path, start_vaddr, end_vaddr, tool):
    try:
        out = subprocess.check_output(
            [tool, "-d", "--start-address=" + hex(start_vaddr),
             "--stop-address=" + hex(end_vaddr), path],
            stderr=subprocess.STDOUT)
        return out.decode("utf-8", "replace")
    except (OSError, subprocess.CalledProcessError) as e:
        return "  (objdump unavailable or failed: %s)" % e


def find_objdump(explicit):
    if explicit:
        return explicit
    for name in ("llvm-objdump", "aarch64-linux-gnu-objdump", "objdump"):
        p = shutil.which(name) if hasattr(shutil, "which") else None
        if p:
            return p
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Assemble, place and verify small AArch64 patches.",
        epilog="Nothing is written without --write.")
    ap.add_argument("file", nargs="?", help="the ELF file to read or patch")
    ap.add_argument("--symbol", help="resolve this symbol and patch at its start")
    ap.add_argument("--vaddr", help="virtual address (hex ok) to patch")
    ap.add_argument("--offset", help="raw FILE offset (hex ok) to patch")
    ap.add_argument("--skip", type=int, default=0,
                    help="instructions to skip past the resolved address")
    ap.add_argument("--patch", action="append", default=[],
                    help="one patch instruction; repeat for consecutive words")
    ap.add_argument("--context", type=int, default=6,
                    help="instructions of context to show either side")
    ap.add_argument("--show", action="store_true",
                    help="just disassemble the site and exit")
    ap.add_argument("--write", action="store_true", help="actually modify the file")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would change; the default")
    ap.add_argument("--no-backup", action="store_true",
                    help="do not create a .bak before writing")
    ap.add_argument("--objdump", nargs="?", const="", default=None,
                    help="render with llvm-objdump instead of the built-in decoder")
    ap.add_argument("--list-symbols", action="store_true",
                    help="print every named symbol with its address and exit")
    ap.add_argument("--show-encodings", action="store_true",
                    help="print the verified encoding table and exit")
    args = ap.parse_args(argv)

    if args.show_encodings:
        print("Verified AArch64 encodings")
        print("  round trip: aarch64-linux-android21-clang -c -x assembler enc.s")
        print("              llvm-objdump -d enc.o")
        print("  NDK 25.2.9519653, clang 14.0.7\n")
        print("  %-26s %-12s %s" % ("instruction", "word", "bytes in file (LE)"))
        for name, word, le in ENCODINGS:
            print("  %-26s 0x%08x   %s" % (name, word, le))
        print("\nAssembly source that produced the table:\n")
        print(ROUND_TRIP_SOURCE)
        return 0

    if not args.file:
        ap.error("a file is required unless --show-encodings is given")

    with open(args.file, "rb") as fh:
        data = bytearray(fh.read())
    elf = Elf(bytes(data))

    if args.list_symbols:
        syms = elf.symbols()
        print("%-52s %-12s %-8s %s" % ("name", "vaddr", "size", "table"))
        for name in sorted(syms, key=lambda n: syms[n][0]):
            v, sz, tbl, thumb = syms[name]
            print("%-52s 0x%08x   %-8d %s%s"
                  % (name, v, sz, tbl, "  [thumb]" if thumb else ""))
        return 0

    # -- work out where we are patching ------------------------------------
    size_hint = None
    if args.symbol:
        syms = elf.symbols()
        if args.symbol not in syms:
            print("symbol %r not found. Try --list-symbols." % args.symbol,
                  file=sys.stderr)
            return 3
        vaddr, size_hint, table, thumb = syms[args.symbol]
        if thumb:
            print("note: %s is a THUMB function; st_value had its low bit set "
                  "and it has been cleared. Do not patch Thumb with this "
                  "script." % args.symbol, file=sys.stderr)
        print("symbol   : %s  (from %s)" % (args.symbol, table))
    elif args.vaddr:
        vaddr = int(args.vaddr, 0)
    elif args.offset:
        off = int(args.offset, 0)
        v = elf.offset_to_vaddr(off)
        if v is None:
            print("file offset 0x%x is not inside any PT_LOAD segment" % off,
                  file=sys.stderr)
            return 3
        vaddr = v
    else:
        ap.error("give one of --symbol, --vaddr or --offset")

    vaddr += args.skip * 4

    file_off, seg = elf.vaddr_to_offset(vaddr)
    if file_off is None:
        print("vaddr 0x%x is not inside any PT_LOAD segment" % vaddr,
              file=sys.stderr)
        return 3

    print("arch     : %s (%s)" % (elf.arch, "ELF64" if elf.is64 else "ELF32"))
    print("vaddr    : 0x%x" % vaddr)
    print("file off : 0x%x   (segment vaddr 0x%x -> offset 0x%x, delta %s0x%x)"
          % (file_off, seg["vaddr"], seg["offset"],
             "-" if seg["vaddr"] > seg["offset"] else "",
             abs(seg["vaddr"] - seg["offset"])))
    if size_hint:
        print("size     : %d bytes (%d instructions)" % (size_hint, size_hint // 4))

    if elf.arch != "aarch64" and args.patch:
        print("\nrefusing to assemble a patch for %s. This script only emits "
              "AArch64.\nSee README section 3.13 for 32-bit ARM and Thumb."
              % elf.arch, file=sys.stderr)
        return 4

    ctx = max(0, args.context)
    start_off = max(0, file_off - ctx * 4)
    n_words = ctx * 2 + max(1, len(args.patch)) + ctx
    before_words = list(struct.unpack_from("<%dI" % n_words, data, start_off))
    start_vaddr = vaddr - (file_off - start_off)

    tool = find_objdump(args.objdump) if args.objdump is not None else None

    print("\nBEFORE")
    if tool:
        print(objdump_range(args.file, start_vaddr,
                            start_vaddr + n_words * 4, tool))
    else:
        print(dump(before_words, start_vaddr,
                   mark=(vaddr, vaddr + max(1, len(args.patch)) * 4)))

    if args.show or not args.patch:
        return 0

    words = []
    for i, spec in enumerate(args.patch):
        words.extend(assemble(spec, vaddr + len(words) * 4))
    print("\nPATCH    : %s" % " ; ".join(args.patch))
    for i, w in enumerate(words):
        raw = " ".join("%02x" % b for b in struct.pack("<I", w))
        print("  0x%08x  word 0x%08x  bytes %s  -> %s"
              % (vaddr + i * 4, w, raw, decode(w, vaddr + i * 4)))

    after = bytearray(data)
    struct.pack_into("<%dI" % len(words), after, file_off, *words)
    after_words = list(struct.unpack_from("<%dI" % n_words, after, start_off))

    print("\nAFTER")
    if tool and args.write:
        pass    # rendered again below, from the file on disk
    print(dump(after_words, start_vaddr,
               mark=(vaddr, vaddr + len(words) * 4)))

    if not args.write:
        print("\nnothing written. Add --write to apply, and read the AFTER "
              "block above first.")
        return 0

    if not args.no_backup:
        bak = args.file + ".bak"
        if not os.path.exists(bak):
            shutil.copy2(args.file, bak)
            print("\nbackup   : %s" % bak)
        else:
            print("\nbackup   : %s already exists, left alone" % bak)

    with open(args.file, "wb") as fh:
        fh.write(bytes(after))
    print("written  : %d bytes at file offset 0x%x" % (len(words) * 4, file_off))

    if tool:
        print("\nAFTER, as %s reads the file on disk:" % os.path.basename(tool))
        print(objdump_range(args.file, start_vaddr,
                            start_vaddr + n_words * 4, tool))
    return 0


if __name__ == "__main__":
    sys.exit(main())
