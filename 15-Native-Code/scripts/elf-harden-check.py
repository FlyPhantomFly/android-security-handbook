#!/usr/bin/env python3
"""
elf-harden-check.py -- run the chapter 15 hardening checklist against a native
                       library, an APK, or a directory of them, WITHOUT readelf.

WHAT IT DOES
    Parses ELF from first principles -- the header, the program header table,
    the section header table, the dynamic array, .dynsym, .symtab and the notes
    -- using only the Python standard library, and reports the state of every
    mitigation the README section 5 checklist covers:

        PIE / ET_DYN            ASLR is only possible if the file is relocatable
        NX (PT_GNU_STACK)       is the stack mapped executable
        W^X across PT_LOAD      is any segment mapped writable AND executable
        RELRO                   none / partial / full
        Stack canaries          __stack_chk_fail / __stack_chk_guard references
        _FORTIFY_SOURCE         the __*_chk import family
        TEXTREL                 relocations against read-only code
        RPATH / RUNPATH         where this library will look for its dependencies
        Stripped                is .symtab still present, and what survives if not
        CFI                     __cfi_check / __cfi_slowpath evidence
        Load-time code          .init_array / DT_INIT entries that run before JNI_OnLoad
        16 KiB page readiness   PT_LOAD p_align, which decides whether it loads at all
        Dangerous imports       the unbounded-copy and shell-out families
        JNI surface             Java_* exports and JNI_OnLoad

    In --apk mode it additionally reports, for every lib/<abi>/*.so entry, the
    ZIP storage method and data alignment -- which is what decides whether the
    library is mapped straight out of the APK or unpacked to
    /data/app/.../lib/ first. See README section 3.11.

HOW TO RUN
    python3 elf-harden-check.py libnative.so
    python3 elf-harden-check.py lib/arm64-v8a/*.so
    python3 elf-harden-check.py --apk target.apk
    python3 elf-harden-check.py --apk target.apk --abi arm64-v8a
    python3 elf-harden-check.py libnative.so --verbose      # every symbol, not a summary
    python3 elf-harden-check.py libnative.so --json         # machine-readable
    python3 elf-harden-check.py --apk target.apk --json > hardening.json

    Exit status is 0 unless --strict is given, in which case any check in the
    BAD state exits 1. Use --strict in CI; do not use it to decide severity.

REQUIREMENTS
    Python 3.6 or newer. Standard library only -- no pyelftools, no readelf,
    no NDK, no network. It runs on a locked-down laptop and on a CI box that
    has nothing installed, which is the whole point: `readelf` is absent from
    Windows, from most containers, and from the average corporate image.

WHAT THIS WILL *NOT* TELL YOU
    - Whether anything here is a vulnerability. Every line of output is a
      PROPERTY OF A FILE, not a finding. A missing stack canary is a missing
      mitigation; it becomes a finding only when a memory-safety bug exists,
      is reachable from attacker-controlled input, and the missing canary
      changes its exploitability. Read README section 5.7 before you copy any
      of this into a report. The script deliberately prints "MISSING" and not
      "VULNERABLE".
    - Whether a mitigation is EFFECTIVE. A canary reference proves the compiler
      emitted a check in at least one function, not that the function you care
      about has one. Full RELRO protects the GOT, not a function pointer the
      program stores in .data itself.
    - Whether the code is reached. A .so shipped in an APK may never be loaded.
      Reachability is a runtime question; see scripts/native-map.js.
    - What the code does. No disassembly, no decompilation, no control flow.
      That is 57-Ghidra's job and this script is the triage that precedes it.
    - Anything about the JNI calling convention or JNIEnv. That is 16-JNI.
    - Which third-party library is bundled or which version it is. That is
      17-Libraries and its lib-fingerprint.py, which shares this ELF parser's
      approach for exactly that reason.
    - Shadow Call Stack. SCS reserves x18 and leaves no reliable import; the
      script says "not statically detectable" rather than guessing.

ACCURACY NOTES
    Every numeric constant below was checked against a primary source rather
    than recalled: the NDK sysroot's own elf.h (usr/include/elf.h in any NDK
    r21+), and the System V gABI chapters 4 and 5. The Android-specific packed
    relocation tags in particular are easy to misremember --
    DT_ANDROID_RELRENT is 0x6fffe003, not 0x6fffe002.
"""

from __future__ import print_function

import argparse
import json
import os
import struct
import sys
import zipfile

# ---------------------------------------------------------------------------
# ELF constants. gABI chapters 4 and 5, cross-checked against NDK usr/include/elf.h
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"

ELFCLASS32, ELFCLASS64 = 1, 2
ELFDATA2LSB, ELFDATA2MSB = 1, 2

ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE = 0, 1, 2, 3, 4
ET_NAMES = {0: "NONE", 1: "REL (object file)", 2: "EXEC (fixed-address executable)",
            3: "DYN (shared object or PIE)", 4: "CORE"}

EM_NAMES = {
    3: ("x86", "x86"),
    40: ("ARM", "armeabi-v7a"),
    62: ("x86-64", "x86_64"),
    183: ("AArch64", "arm64-v8a"),
    243: ("RISC-V", "riscv64"),
}

# Program header types
PT_NULL, PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 0, 1, 2, 3, 4
PT_SHLIB, PT_PHDR, PT_TLS = 5, 6, 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_GNU_PROPERTY = 0x6474E553

PT_NAMES = {
    PT_NULL: "NULL", PT_LOAD: "LOAD", PT_DYNAMIC: "DYNAMIC", PT_INTERP: "INTERP",
    PT_NOTE: "NOTE", PT_SHLIB: "SHLIB", PT_PHDR: "PHDR", PT_TLS: "TLS",
    PT_GNU_EH_FRAME: "GNU_EH_FRAME", PT_GNU_STACK: "GNU_STACK",
    PT_GNU_RELRO: "GNU_RELRO", PT_GNU_PROPERTY: "GNU_PROPERTY",
}

PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

# Section header types
SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA = 0, 1, 2, 3, 4
SHT_HASH, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_REL = 5, 6, 7, 8, 9
SHT_SHLIB, SHT_DYNSYM = 10, 11
SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_PREINIT_ARRAY = 14, 15, 16
SHT_GNU_HASH = 0x6FFFFFF6
SHT_ANDROID_REL, SHT_ANDROID_RELA = 0x60000001, 0x60000002
SHT_ANDROID_RELR = 0x6FFFFF00

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4

# Dynamic array tags
DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH = 0, 1, 2, 3, 4
DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_RELAENT = 5, 6, 7, 8, 9
DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI, DT_SONAME = 10, 11, 12, 13, 14
DT_RPATH, DT_SYMBOLIC, DT_REL, DT_RELSZ, DT_RELENT = 15, 16, 17, 18, 19
DT_PLTREL, DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW = 20, 21, 22, 23, 24
DT_INIT_ARRAY, DT_FINI_ARRAY = 25, 26
DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ = 27, 28
DT_RUNPATH, DT_FLAGS = 29, 30
DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ = 32, 33
DT_RELRSZ, DT_RELR, DT_RELRENT = 35, 36, 37
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_RELACOUNT, DT_RELCOUNT = 0x6FFFFFF9, 0x6FFFFFFA
DT_FLAGS_1 = 0x6FFFFFFB
DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFFE, 0x6FFFFFFF
# Android packed relocations. Values from NDK usr/include/elf.h -- note RELRENT.
DT_ANDROID_REL, DT_ANDROID_RELSZ = 0x6000000F, 0x60000010
DT_ANDROID_RELA, DT_ANDROID_RELASZ = 0x60000011, 0x60000012
DT_ANDROID_RELR, DT_ANDROID_RELRSZ = 0x6FFFE000, 0x6FFFE001
DT_ANDROID_RELRENT, DT_ANDROID_RELRCOUNT = 0x6FFFE003, 0x6FFFE005

DT_NAMES = {
    DT_NEEDED: "NEEDED", DT_PLTRELSZ: "PLTRELSZ", DT_PLTGOT: "PLTGOT",
    DT_HASH: "HASH", DT_STRTAB: "STRTAB", DT_SYMTAB: "SYMTAB", DT_RELA: "RELA",
    DT_RELASZ: "RELASZ", DT_RELAENT: "RELAENT", DT_STRSZ: "STRSZ",
    DT_SYMENT: "SYMENT", DT_INIT: "INIT", DT_FINI: "FINI", DT_SONAME: "SONAME",
    DT_RPATH: "RPATH", DT_SYMBOLIC: "SYMBOLIC", DT_REL: "REL", DT_RELSZ: "RELSZ",
    DT_RELENT: "RELENT", DT_PLTREL: "PLTREL", DT_DEBUG: "DEBUG",
    DT_TEXTREL: "TEXTREL", DT_JMPREL: "JMPREL", DT_BIND_NOW: "BIND_NOW",
    DT_INIT_ARRAY: "INIT_ARRAY", DT_FINI_ARRAY: "FINI_ARRAY",
    DT_INIT_ARRAYSZ: "INIT_ARRAYSZ", DT_FINI_ARRAYSZ: "FINI_ARRAYSZ",
    DT_RUNPATH: "RUNPATH", DT_FLAGS: "FLAGS",
    DT_PREINIT_ARRAY: "PREINIT_ARRAY", DT_PREINIT_ARRAYSZ: "PREINIT_ARRAYSZ",
    DT_RELRSZ: "RELRSZ", DT_RELR: "RELR", DT_RELRENT: "RELRENT",
    DT_GNU_HASH: "GNU_HASH", DT_VERSYM: "VERSYM", DT_RELACOUNT: "RELACOUNT",
    DT_RELCOUNT: "RELCOUNT", DT_FLAGS_1: "FLAGS_1", DT_VERNEED: "VERNEED",
    DT_VERNEEDNUM: "VERNEEDNUM",
    DT_ANDROID_REL: "ANDROID_REL", DT_ANDROID_RELSZ: "ANDROID_RELSZ",
    DT_ANDROID_RELA: "ANDROID_RELA", DT_ANDROID_RELASZ: "ANDROID_RELASZ",
    DT_ANDROID_RELR: "ANDROID_RELR", DT_ANDROID_RELRSZ: "ANDROID_RELRSZ",
    DT_ANDROID_RELRENT: "ANDROID_RELRENT",
    DT_ANDROID_RELRCOUNT: "ANDROID_RELRCOUNT",
}

# DT_FLAGS bits
DF_ORIGIN, DF_SYMBOLIC, DF_TEXTREL, DF_BIND_NOW, DF_STATIC_TLS = 1, 2, 4, 8, 0x10
# DT_FLAGS_1 bits
DF_1_NOW, DF_1_GLOBAL, DF_1_GROUP, DF_1_NODELETE = 1, 2, 4, 8
DF_1_NOOPEN, DF_1_ORIGIN = 0x40, 0x80
DF_1_PIE = 0x08000000

# Symbol table
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE = 0, 1, 2, 3, 4
STT_COMMON, STT_TLS, STT_GNU_IFUNC = 5, 6, 10
STV_DEFAULT, STV_INTERNAL, STV_HIDDEN, STV_PROTECTED = 0, 1, 2, 3
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2

NT_GNU_BUILD_ID = 3

# ---------------------------------------------------------------------------
# Symbol families the checklist cares about
# ---------------------------------------------------------------------------

CANARY_SYMBOLS = ("__stack_chk_fail", "__stack_chk_guard", "__stack_smash_handler")

CFI_SYMBOLS = ("__cfi_check", "__cfi_slowpath", "__cfi_slowpath_diag",
               "__cfi_check_fail")

# Unbounded or easily-misused copies. Not bugs; call sites to read.
DANGEROUS_IMPORTS = {
    "strcpy": "unbounded copy into a fixed buffer",
    "strcat": "unbounded append into a fixed buffer",
    "sprintf": "unbounded formatted write",
    "vsprintf": "unbounded formatted write",
    "gets": "unbounded line read -- removed from C11, never correct",
    "stpcpy": "unbounded copy, returns end pointer",
    "wcscpy": "unbounded wide copy",
    "alloca": "stack allocation with an attacker-influenced size",
    "system": "spawns a shell -- inspect the command string",
    "popen": "spawns a shell -- inspect the command string",
    "execl": "process execution",
    "execve": "process execution",
    "execvp": "process execution -- resolves via PATH",
    "fork": "process creation",
    "ptrace": "anti-debugging, or the library is itself a tracer",
    "dlopen": "loads another library at runtime -- possibly a packer",
    "dlsym": "resolves a symbol by name at runtime",
    "mprotect": "changes page permissions -- runtime code generation or unpacking",
    "mmap": "maps memory -- with PROT_EXEC this is a code loader",
    "syscall": "direct syscall -- bypasses libc-level hooks",
    "prctl": "PR_SET_DUMPABLE(0) anti-debug, or PR_SET_NAME to hide",
    "inotify_add_watch": "watching its own files for tampering",
    "__system_property_get": "reads ro.debuggable, ro.secure and friends",
    "getauxval": "reads AT_SECURE / AT_HWCAP",
    "pthread_create": "background thread -- often a periodic integrity check",
}

# ---------------------------------------------------------------------------
# Small readers. The whole file is held in memory; Android .so files are MBs.
# ---------------------------------------------------------------------------


class ElfError(Exception):
    pass


class Reader(object):
    """Endian- and width-aware integer reads over a bytes object."""

    def __init__(self, blob, little=True, is64=True):
        self.b = blob
        self.e = "<" if little else ">"
        self.is64 = is64

    def u8(self, o):
        self._need(o, 1)
        return self.b[o] if isinstance(self.b[o], int) else ord(self.b[o])

    def u16(self, o):
        self._need(o, 2)
        return struct.unpack_from(self.e + "H", self.b, o)[0]

    def u32(self, o):
        self._need(o, 4)
        return struct.unpack_from(self.e + "I", self.b, o)[0]

    def u64(self, o):
        self._need(o, 8)
        return struct.unpack_from(self.e + "Q", self.b, o)[0]

    def word(self, o):
        """Native address width: 8 bytes on ELF64, 4 on ELF32."""
        return self.u64(o) if self.is64 else self.u32(o)

    def sword(self, o):
        self._need(o, 8 if self.is64 else 4)
        f = self.e + ("q" if self.is64 else "i")
        return struct.unpack_from(f, self.b, o)[0]

    def cstr(self, o, limit=4096):
        if o < 0 or o >= len(self.b):
            return ""
        end = self.b.find(b"\x00", o, min(len(self.b), o + limit))
        if end < 0:
            end = min(len(self.b), o + limit)
        return self.b[o:end].decode("utf-8", "replace")

    def _need(self, o, n):
        if o < 0 or o + n > len(self.b):
            raise ElfError("read of %d bytes at offset 0x%x is outside the file "
                           "(%d bytes)" % (n, o, len(self.b)))


# ---------------------------------------------------------------------------
# The ELF model
# ---------------------------------------------------------------------------


class Elf(object):
    """A deliberately small ELF reader: enough for the hardening checklist.

    Nothing here validates the file the way the kernel or the linker does. The
    goal is to survive a hostile or damaged file and say what went wrong,
    because packed and anti-analysis libraries are exactly the ones you most
    want a reading of.
    """

    def __init__(self, blob, name="<elf>"):
        self.name = name
        self.blob = blob
        self.warnings = []

        if len(blob) < 64:
            raise ElfError("file is %d bytes -- too short to be an ELF" % len(blob))
        if blob[:4] != ELF_MAGIC:
            raise ElfError("no ELF magic (first four bytes are %s, expected 7F 45 4C 46)"
                           % " ".join("%02X" % b for b in bytearray(blob[:4])))

        self.elfclass = bytearray(blob)[4]
        self.data = bytearray(blob)[5]
        self.ei_version = bytearray(blob)[6]
        self.osabi = bytearray(blob)[7]
        self.abiversion = bytearray(blob)[8]

        if self.elfclass not in (ELFCLASS32, ELFCLASS64):
            raise ElfError("EI_CLASS is %d; expected 1 (32-bit) or 2 (64-bit)"
                           % self.elfclass)
        if self.data not in (ELFDATA2LSB, ELFDATA2MSB):
            raise ElfError("EI_DATA is %d; expected 1 (LSB) or 2 (MSB)" % self.data)

        self.is64 = self.elfclass == ELFCLASS64
        self.little = self.data == ELFDATA2LSB
        if not self.little:
            self.warnings.append(
                "big-endian ELF. No Android ABI is big-endian; treat this file "
                "as suspicious or as something other than an Android library.")

        r = Reader(blob, self.little, self.is64)
        self.r = r

        self.e_type = r.u16(16)
        self.e_machine = r.u16(18)
        self.e_version = r.u32(20)
        if self.is64:
            self.e_entry = r.u64(24)
            self.e_phoff = r.u64(32)
            self.e_shoff = r.u64(40)
            self.e_flags = r.u32(48)
            self.e_ehsize = r.u16(52)
            self.e_phentsize = r.u16(54)
            self.e_phnum = r.u16(56)
            self.e_shentsize = r.u16(58)
            self.e_shnum = r.u16(60)
            self.e_shstrndx = r.u16(62)
        else:
            self.e_entry = r.u32(24)
            self.e_phoff = r.u32(28)
            self.e_shoff = r.u32(32)
            self.e_flags = r.u32(36)
            self.e_ehsize = r.u16(40)
            self.e_phentsize = r.u16(42)
            self.e_phnum = r.u16(44)
            self.e_shentsize = r.u16(46)
            self.e_shnum = r.u16(48)
            self.e_shstrndx = r.u16(50)

        expect_eh = 64 if self.is64 else 52
        if self.e_ehsize != expect_eh:
            self.warnings.append(
                "e_ehsize is %d, expected %d. Hand-edited or corrupt header."
                % (self.e_ehsize, expect_eh))

        self.phdrs = self._read_phdrs()
        self.shdrs = self._read_shdrs()
        self._dyn = None
        self._dynstr_cache = None

    # -- program headers ----------------------------------------------------

    def _read_phdrs(self):
        out = []
        if not self.e_phoff or not self.e_phnum:
            self.warnings.append("no program header table: this file cannot be "
                                 "loaded by the dynamic linker as it stands.")
            return out
        want = 56 if self.is64 else 32
        if self.e_phentsize != want:
            self.warnings.append("e_phentsize is %d, expected %d"
                                 % (self.e_phentsize, want))
        for i in range(self.e_phnum):
            base = self.e_phoff + i * self.e_phentsize
            try:
                if self.is64:
                    ph = {"type": self.r.u32(base),
                          "flags": self.r.u32(base + 4),
                          "offset": self.r.u64(base + 8),
                          "vaddr": self.r.u64(base + 16),
                          "paddr": self.r.u64(base + 24),
                          "filesz": self.r.u64(base + 32),
                          "memsz": self.r.u64(base + 40),
                          "align": self.r.u64(base + 48)}
                else:
                    ph = {"type": self.r.u32(base),
                          "offset": self.r.u32(base + 4),
                          "vaddr": self.r.u32(base + 8),
                          "paddr": self.r.u32(base + 12),
                          "filesz": self.r.u32(base + 16),
                          "memsz": self.r.u32(base + 20),
                          "flags": self.r.u32(base + 24),
                          "align": self.r.u32(base + 28)}
            except ElfError as exc:
                self.warnings.append("program header %d unreadable: %s" % (i, exc))
                break
            ph["index"] = i
            ph["name"] = PT_NAMES.get(ph["type"], "0x%08x" % ph["type"])
            out.append(ph)
        return out

    def phdr(self, ptype):
        for ph in self.phdrs:
            if ph["type"] == ptype:
                return ph
        return None

    # -- section headers ----------------------------------------------------

    def _read_shdrs(self):
        out = []
        if not self.e_shoff or not self.e_shnum:
            self.warnings.append(
                "no section header table. The file still loads -- the linker "
                "never reads sections -- but every section-based answer below "
                "falls back to PT_DYNAMIC and is less complete.")
            return out
        want = 64 if self.is64 else 40
        if self.e_shentsize != want:
            self.warnings.append("e_shentsize is %d, expected %d"
                                 % (self.e_shentsize, want))
        raw = []
        for i in range(self.e_shnum):
            base = self.e_shoff + i * self.e_shentsize
            try:
                if self.is64:
                    sh = {"name_off": self.r.u32(base),
                          "type": self.r.u32(base + 4),
                          "flags": self.r.u64(base + 8),
                          "addr": self.r.u64(base + 16),
                          "offset": self.r.u64(base + 24),
                          "size": self.r.u64(base + 32),
                          "link": self.r.u32(base + 40),
                          "info": self.r.u32(base + 44),
                          "addralign": self.r.u64(base + 48),
                          "entsize": self.r.u64(base + 56)}
                else:
                    sh = {"name_off": self.r.u32(base),
                          "type": self.r.u32(base + 4),
                          "flags": self.r.u32(base + 8),
                          "addr": self.r.u32(base + 12),
                          "offset": self.r.u32(base + 16),
                          "size": self.r.u32(base + 20),
                          "link": self.r.u32(base + 24),
                          "info": self.r.u32(base + 28),
                          "addralign": self.r.u32(base + 32),
                          "entsize": self.r.u32(base + 36)}
            except ElfError as exc:
                self.warnings.append("section header %d unreadable: %s" % (i, exc))
                break
            sh["index"] = i
            raw.append(sh)

        shstr = b""
        if self.e_shstrndx < len(raw):
            s = raw[self.e_shstrndx]
            shstr = self.blob[s["offset"]:s["offset"] + s["size"]]
        elif raw:
            self.warnings.append("e_shstrndx (%d) is out of range; section names "
                                 "are unavailable" % self.e_shstrndx)
        sr = Reader(shstr, self.little, self.is64)
        for sh in raw:
            sh["name"] = sr.cstr(sh["name_off"]) if shstr else ""
            out.append(sh)
        return out

    def section(self, name):
        for sh in self.shdrs:
            if sh["name"] == name:
                return sh
        return None

    def section_bytes(self, name):
        sh = self.section(name)
        if not sh or sh["type"] == SHT_NOBITS:
            return b""
        return self.blob[sh["offset"]:sh["offset"] + sh["size"]]

    # -- address translation ------------------------------------------------

    def vaddr_to_offset(self, vaddr):
        """Map a link-time virtual address to a file offset via PT_LOAD.

        Section headers give this directly, but a stripped-of-sections file
        does not have them, and a hostile file may lie in them. PT_LOAD is what
        the linker itself uses, so it is the authority.
        """
        for ph in self.phdrs:
            if ph["type"] != PT_LOAD:
                continue
            if ph["vaddr"] <= vaddr < ph["vaddr"] + ph["filesz"]:
                return ph["offset"] + (vaddr - ph["vaddr"])
        return None

    # -- the dynamic array --------------------------------------------------

    def dynamic(self):
        """Return [(tag, value), ...] in file order, duplicates preserved.

        DT_NEEDED appears many times, so a dict would silently lose entries.
        """
        if self._dyn is not None:
            return self._dyn
        entries = []
        seg = self.phdr(PT_DYNAMIC)
        if seg is not None:
            off, end = seg["offset"], seg["offset"] + seg["filesz"]
        else:
            sh = self.section(".dynamic")
            if sh is None:
                self.warnings.append("no PT_DYNAMIC and no .dynamic section: "
                                     "this file is not dynamically linked.")
                self._dyn = entries
                return entries
            off, end = sh["offset"], sh["offset"] + sh["size"]
        width = 16 if self.is64 else 8
        while off + width <= min(end, len(self.blob)):
            try:
                tag = self.r.word(off)
                val = self.r.word(off + (8 if self.is64 else 4))
            except ElfError:
                break
            if tag == DT_NULL:
                break
            entries.append((tag, val))
            off += width
        self._dyn = entries
        return entries

    def dt_first(self, tag, default=None):
        for t, v in self.dynamic():
            if t == tag:
                return v
        return default

    def dt_all(self, tag):
        return [v for t, v in self.dynamic() if t == tag]

    def dt_present(self, tag):
        return any(t == tag for t, _ in self.dynamic())

    def dynstr(self):
        """The dynamic string table, located without trusting section headers."""
        if self._dynstr_cache is not None:
            return self._dynstr_cache
        va = self.dt_first(DT_STRTAB)
        size = self.dt_first(DT_STRSZ)
        blob = b""
        if va is not None:
            off = self.vaddr_to_offset(va)
            if off is None:
                # Some toolchains store a file offset here in unusual files.
                off = va if va < len(self.blob) else None
            if off is not None:
                if size is None:
                    size = 0x10000
                blob = self.blob[off:off + size]
        if not blob:
            blob = self.section_bytes(".dynstr")
        self._dynstr_cache = blob
        return blob

    def needed(self):
        s = Reader(self.dynstr(), self.little, self.is64)
        return [s.cstr(v) for v in self.dt_all(DT_NEEDED)]

    def soname(self):
        va = self.dt_first(DT_SONAME)
        if va is None:
            return None
        return Reader(self.dynstr(), self.little, self.is64).cstr(va)

    def runpaths(self):
        """(tag_name, value) for DT_RPATH and DT_RUNPATH, in that order."""
        s = Reader(self.dynstr(), self.little, self.is64)
        out = []
        for tag, name in ((DT_RPATH, "RPATH"), (DT_RUNPATH, "RUNPATH")):
            for v in self.dt_all(tag):
                out.append((name, s.cstr(v)))
        return out

    # -- symbols ------------------------------------------------------------

    def _symbols_from(self, symoff, count, strblob):
        s = Reader(strblob, self.little, self.is64)
        ent = 24 if self.is64 else 16
        out = []
        for i in range(count):
            base = symoff + i * ent
            try:
                if self.is64:
                    name_off = self.r.u32(base)
                    info = self.r.u8(base + 4)
                    other = self.r.u8(base + 5)
                    shndx = self.r.u16(base + 6)
                    value = self.r.u64(base + 8)
                    size = self.r.u64(base + 16)
                else:
                    name_off = self.r.u32(base)
                    value = self.r.u32(base + 4)
                    size = self.r.u32(base + 8)
                    info = self.r.u8(base + 12)
                    other = self.r.u8(base + 13)
                    shndx = self.r.u16(base + 14)
            except ElfError:
                break
            out.append({
                "name": s.cstr(name_off),
                "bind": info >> 4,
                "type": info & 0xF,
                "visibility": other & 0x3,
                "shndx": shndx,
                "value": value,
                "size": size,
                "defined": shndx != SHN_UNDEF,
            })
        return out

    def dynsyms(self):
        """.dynsym. Falls back to DT_HASH when section headers are gone."""
        sh = self.section(".dynsym")
        if sh is not None and sh["size"]:
            ent = sh["entsize"] or (24 if self.is64 else 16)
            strsh = None
            if sh["link"] < len(self.shdrs):
                strsh = self.shdrs[sh["link"]]
            strblob = (self.blob[strsh["offset"]:strsh["offset"] + strsh["size"]]
                       if strsh else self.dynstr())
            return self._symbols_from(sh["offset"], sh["size"] // ent, strblob)

        symva = self.dt_first(DT_SYMTAB)
        if symva is None:
            return []
        symoff = self.vaddr_to_offset(symva)
        if symoff is None:
            return []
        count = self._dynsym_count(symoff)
        if count is None:
            self.warnings.append(
                "section headers are absent and the file has no DT_HASH, so the "
                "dynamic symbol count cannot be derived exactly; GNU_HASH bucket "
                "chains were walked instead. Treat the symbol list as a lower bound.")
            return []
        return self._symbols_from(symoff, count, self.dynstr())

    def _dynsym_count(self, symoff):
        """nchain from DT_HASH is the exact count; GNU_HASH needs chain walking."""
        hva = self.dt_first(DT_HASH)
        if hva is not None:
            hoff = self.vaddr_to_offset(hva)
            if hoff is not None:
                try:
                    return self.r.u32(hoff + 4)   # nchain
                except ElfError:
                    pass
        gva = self.dt_first(DT_GNU_HASH)
        if gva is None:
            return None
        goff = self.vaddr_to_offset(gva)
        if goff is None:
            return None
        try:
            nbuckets = self.r.u32(goff)
            symndx = self.r.u32(goff + 4)
            maskwords = self.r.u32(goff + 8)
        except ElfError:
            return None
        bucket_off = goff + 16 + maskwords * (8 if self.is64 else 4)
        last = 0
        try:
            for i in range(nbuckets):
                b = self.r.u32(bucket_off + 4 * i)
                if b > last:
                    last = b
            if last < symndx:
                return symndx
            chain_off = bucket_off + 4 * nbuckets
            idx = last
            while True:
                h = self.r.u32(chain_off + 4 * (idx - symndx))
                idx += 1
                if h & 1:
                    break
        except ElfError:
            return None
        return idx

    def symtab(self):
        sh = self.section(".symtab")
        if sh is None or not sh["size"]:
            return []
        ent = sh["entsize"] or (24 if self.is64 else 16)
        strsh = self.shdrs[sh["link"]] if sh["link"] < len(self.shdrs) else None
        strblob = (self.blob[strsh["offset"]:strsh["offset"] + strsh["size"]]
                   if strsh else b"")
        return self._symbols_from(sh["offset"], sh["size"] // ent, strblob)

    # -- notes --------------------------------------------------------------

    def build_id(self):
        for sh in self.shdrs:
            if sh["type"] != SHT_NOTE:
                continue
            got = self._scan_note(self.blob[sh["offset"]:sh["offset"] + sh["size"]])
            if got:
                return got
        ph = self.phdr(PT_NOTE)
        if ph:
            return self._scan_note(self.blob[ph["offset"]:ph["offset"] + ph["filesz"]])
        return None

    @staticmethod
    def _scan_note(data):
        off = 0
        while off + 12 <= len(data):
            namesz, descsz, ntype = struct.unpack_from("<III", data, off)
            name_at = off + 12
            desc_at = name_at + ((namesz + 3) & ~3)
            if ntype == NT_GNU_BUILD_ID and data[name_at:name_at + 3] == b"GNU":
                blob = data[desc_at:desc_at + descsz]
                return "".join("%02x" % b for b in bytearray(blob))
            nxt = desc_at + ((descsz + 3) & ~3)
            if nxt <= off:
                break
            off = nxt
        return None

    def comment(self):
        raw = self.section_bytes(".comment")
        if not raw:
            return []
        parts = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if len(p) > 3]
        seen, out = set(), []
        for p in parts:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def android_ident(self):
        """.note.android.ident carries the minSdkVersion the NDK built against."""
        raw = self.section_bytes(".note.android.ident")
        if len(raw) < 20:
            return None
        namesz, descsz, ntype = struct.unpack_from("<III", raw, 0)
        desc_at = 12 + ((namesz + 3) & ~3)
        if descsz >= 4 and desc_at + 4 <= len(raw):
            return struct.unpack_from("<I", raw, desc_at)[0]
        return None


# ---------------------------------------------------------------------------
# The checklist
# ---------------------------------------------------------------------------

GOOD, BAD, WARN, INFO, UNKNOWN = "GOOD", "MISSING", "WARN", "INFO", "UNKNOWN"


class Check(object):
    __slots__ = ("key", "title", "state", "value", "evidence", "meaning")

    def __init__(self, key, title, state, value, evidence, meaning):
        self.key = key
        self.title = title
        self.state = state
        self.value = value
        self.evidence = evidence      # how the answer was derived, byte-level
        self.meaning = meaning        # what it does and does not imply

    def as_dict(self):
        return {"key": self.key, "title": self.title, "state": self.state,
                "value": self.value, "evidence": self.evidence,
                "meaning": self.meaning}


def analyse(elf):
    checks = []
    add = checks.append

    # -- identity ----------------------------------------------------------
    mach, abi = EM_NAMES.get(elf.e_machine, ("unknown(%d)" % elf.e_machine, "?"))
    add(Check("arch", "Architecture", INFO,
              "%s / %s / %s-bit" % (mach, abi, 64 if elf.is64 else 32),
              "e_machine=%d at file offset 18, EI_CLASS=%d at offset 4"
              % (elf.e_machine, elf.elfclass),
              "Decides which lib/<abi>/ directory this belongs in and which "
              "frida-server and gdbserver build can talk to it."))

    minsdk = elf.android_ident()
    if minsdk:
        add(Check("minsdk", "NDK target API", INFO, str(minsdk),
                  ".note.android.ident descriptor",
                  "The API level the NDK compiled against. Not the app's "
                  "minSdkVersion, but usually equal to it."))

    # -- PIE ---------------------------------------------------------------
    flags1 = elf.dt_first(DT_FLAGS_1, 0) or 0
    if elf.e_type == ET_DYN:
        if elf.e_entry and (flags1 & DF_1_PIE):
            v, st = "yes (PIE executable)", GOOD
        elif elf.e_entry:
            v, st = "yes (ET_DYN with an entry point -- PIE or a library with DT_INIT)", GOOD
        else:
            v, st = "yes (shared library, inherently relocatable)", GOOD
        ev = "e_type=3 (ET_DYN) at offset 16; DT_FLAGS_1=0x%x" % flags1
    elif elf.e_type == ET_EXEC:
        v, st = "NO -- ET_EXEC, fixed load address", BAD
        ev = "e_type=2 (ET_EXEC) at offset 16"
    else:
        v, st = ET_NAMES.get(elf.e_type, str(elf.e_type)), WARN
        ev = "e_type=%d at offset 16" % elf.e_type
    add(Check("pie", "PIE / position independence", st, v, ev,
              "ASLR can only randomise a base address the code does not depend "
              "on. An ET_EXEC file demands one address, so its code and data "
              "sit at a known location in every process. Android's linker has "
              "refused non-PIE executables since 5.0 (API 21), so ET_EXEC here "
              "means either a very old binary or something that is not going "
              "to run."))

    # -- NX ----------------------------------------------------------------
    gs = elf.phdr(PT_GNU_STACK)
    if gs is None:
        add(Check("nx", "NX / non-executable stack", WARN,
                  "no PT_GNU_STACK -- kernel default applies",
                  "no program header of type 0x6474E551",
                  "Without the marker the kernel falls back to its default. On "
                  "Android that default is a non-executable stack, so this is "
                  "usually harmless -- but the absence is worth a line in the "
                  "report because it means the toolchain was not asked."))
    elif gs["flags"] & PF_X:
        add(Check("nx", "NX / non-executable stack", BAD,
                  "EXECUTABLE STACK (RWE)",
                  "PT_GNU_STACK p_flags=0x%x, PF_X set" % gs["flags"],
                  "The stack is mapped with execute permission, so data written "
                  "there can be jumped to. This is the one item on the list that "
                  "is close to a finding on its own: no modern Android build "
                  "needs it, and it removes the single mitigation that made "
                  "classic stack shellcode obsolete."))
    else:
        add(Check("nx", "NX / non-executable stack", GOOD,
                  "yes (stack is RW, not X)",
                  "PT_GNU_STACK p_flags=0x%x" % gs["flags"],
                  "Data on the stack cannot be executed. It does not stop "
                  "return-oriented programming, which reuses existing code."))

    # -- W^X across loadable segments --------------------------------------
    wx = [ph for ph in elf.phdrs
          if ph["type"] == PT_LOAD and (ph["flags"] & PF_W) and (ph["flags"] & PF_X)]
    if wx:
        add(Check("wx", "W^X across PT_LOAD", BAD,
                  "%d segment(s) mapped writable AND executable" % len(wx),
                  "; ".join("PT_LOAD#%d vaddr=0x%x flags=0x%x"
                            % (p["index"], p["vaddr"], p["flags"]) for p in wx),
                  "A page that is both writable and executable lets a memory "
                  "write become code execution with no further work. Ordinary "
                  "NDK output never produces one; packers and self-modifying "
                  "obfuscators do."))
    else:
        add(Check("wx", "W^X across PT_LOAD", GOOD, "respected",
                  "%d PT_LOAD segments, none with PF_W|PF_X" % len(
                      [p for p in elf.phdrs if p["type"] == PT_LOAD]),
                  "No loadable segment is writable and executable at the same "
                  "time. The library may still call mprotect at runtime; that "
                  "is a dynamic question."))

    # -- RELRO -------------------------------------------------------------
    relro = elf.phdr(PT_GNU_RELRO)
    dflags = elf.dt_first(DT_FLAGS, 0) or 0
    bind_now = (elf.dt_present(DT_BIND_NOW) or bool(dflags & DF_BIND_NOW)
                or bool(flags1 & DF_1_NOW))
    if relro is None:
        st, v = BAD, "none"
        ev = "no PT_GNU_RELRO segment"
    elif bind_now:
        st, v = GOOD, "full"
        ev = ("PT_GNU_RELRO covers 0x%x..0x%x; %s"
              % (relro["vaddr"], relro["vaddr"] + relro["memsz"],
                 "DT_BIND_NOW present" if elf.dt_present(DT_BIND_NOW)
                 else ("DT_FLAGS&DF_BIND_NOW" if dflags & DF_BIND_NOW
                       else "DT_FLAGS_1&DF_1_NOW")))
    else:
        st, v = WARN, "partial"
        ev = ("PT_GNU_RELRO covers 0x%x..0x%x but no DT_BIND_NOW / DF_BIND_NOW "
              "/ DF_1_NOW, so .got.plt stays writable for lazy binding"
              % (relro["vaddr"], relro["vaddr"] + relro["memsz"]))
    add(Check("relro", "RELRO", st, v, ev,
              "RELRO asks the linker to make relocated data read-only once "
              "relocation is done. Partial RELRO protects .init_array, "
              ".fini_array, .data.rel.ro and .got, but leaves .got.plt "
              "writable so lazy binding can keep patching it. Full RELRO "
              "resolves every import at load time and then locks the whole "
              "region, which removes GOT overwrite as a primitive -- and, "
              "incidentally, makes GOT hooking harder for you as well. Since "
              "Android 5.0 the NDK links with -z relro -z now by default."))

    # -- canaries ----------------------------------------------------------
    dyn = elf.dynsyms()
    st_names = set(s["name"] for s in elf.symtab())
    dyn_names = set(s["name"] for s in dyn)
    all_names = dyn_names | st_names
    found_canary = sorted(n for n in all_names if n in CANARY_SYMBOLS)
    if found_canary:
        add(Check("canary", "Stack canaries", GOOD,
                  "referenced (%s)" % ", ".join(found_canary),
                  "symbol(s) %s appear in .dynsym/.symtab"
                  % ", ".join(found_canary),
                  "The compiler emitted a canary check in AT LEAST ONE "
                  "function. It does not mean every function is protected: "
                  "-fstack-protector-strong covers functions with arrays or "
                  "address-taken locals, and nothing else. Confirm the specific "
                  "function you care about in the disassembly."))
    else:
        add(Check("canary", "Stack canaries", BAD, "no reference found",
                  "none of %s in .dynsym or .symtab"
                  % ", ".join(CANARY_SYMBOLS),
                  "Compiled without -fstack-protector, OR with it but with no "
                  "function that qualified, OR statically linked against a libc "
                  "that resolves the symbol internally. THIS IS NOT A FINDING "
                  "ON ITS OWN. It is a missing mitigation: it raises the "
                  "exploitability of a stack overflow that already exists. With "
                  "no overflow, there is nothing for it to have stopped."))

    # -- FORTIFY -----------------------------------------------------------
    chk = sorted(n for n in dyn_names if n.startswith("__") and n.endswith("_chk"))
    chk = [n for n in chk if n not in CANARY_SYMBOLS]
    unfortified = sorted(n for n in dyn_names
                         if n in ("strcpy", "strcat", "memcpy", "sprintf",
                                  "vsprintf", "snprintf", "memmove", "strncpy"))
    if chk:
        add(Check("fortify", "_FORTIFY_SOURCE", GOOD,
                  "%d fortified import(s)" % len(chk),
                  ", ".join(chk[:12]) + (" ..." if len(chk) > 12 else ""),
                  "The __*_chk variants take a destination size and abort when "
                  "a copy would overflow a buffer whose size the compiler could "
                  "prove. It only helps where the size is known at compile time; "
                  "a heap buffer of computed size gets no protection. Unfortified "
                  "calls surviving alongside these: %s"
                  % (", ".join(unfortified) if unfortified else "none")))
    else:
        add(Check("fortify", "_FORTIFY_SOURCE", BAD, "no __*_chk imports",
                  "no symbol matching __*_chk in .dynsym",
                  "Built without _FORTIFY_SOURCE, or with it but with every "
                  "call inlined or unprovable. Same severity framing as the "
                  "canary: a missing mitigation, not a bug."))

    # -- TEXTREL -----------------------------------------------------------
    if elf.dt_present(DT_TEXTREL) or (dflags & DF_TEXTREL):
        add(Check("textrel", "Text relocations", BAD, "present",
                  "DT_TEXTREL present" if elf.dt_present(DT_TEXTREL)
                  else "DT_FLAGS & DF_TEXTREL",
                  "The library needs the loader to write into its own code "
                  "pages, which forces them writable during relocation. Android "
                  "has rejected text relocations outright for API 23 and above, "
                  "so a shipping library with this either targets something very "
                  "old or will fail to load."))
    else:
        add(Check("textrel", "Text relocations", GOOD, "none",
                  "no DT_TEXTREL and DF_TEXTREL clear in DT_FLAGS (0x%x)" % dflags,
                  "Code pages never need to be writable. Required on modern "
                  "Android."))

    # -- RPATH / RUNPATH ---------------------------------------------------
    rp = elf.runpaths()
    if rp:
        risky = [p for _, p in rp
                 if p.startswith("/data") or p.startswith("/sdcard")
                 or p.startswith("/storage") or p.startswith(".")
                 or "$ORIGIN" not in p and not p.startswith("/system")
                 and not p.startswith("/vendor") and not p.startswith("/apex")]
        add(Check("rpath", "RPATH / RUNPATH",
                  BAD if risky else WARN,
                  "; ".join("%s=%s" % (t, v) for t, v in rp),
                  "DT_RPATH/DT_RUNPATH string table entries",
                  "These are library search paths baked into the file. A path "
                  "that an attacker or another app can write to turns any "
                  "dependency load into arbitrary code execution in this "
                  "process. $ORIGIN-relative paths are the safe idiom. Note "
                  "that Android's linker restricts search paths heavily inside "
                  "an app process, so this is more often a smell than an "
                  "exploit -- but a writable absolute path deserves a finding."))
    else:
        add(Check("rpath", "RPATH / RUNPATH", GOOD, "none",
                  "no DT_RPATH or DT_RUNPATH entries",
                  "Dependency resolution follows the linker namespace rules "
                  "only. Nothing baked in."))

    # -- stripped ----------------------------------------------------------
    has_symtab = elf.section(".symtab") is not None
    debug_secs = [s["name"] for s in elf.shdrs if s["name"].startswith(".debug")]
    if debug_secs:
        add(Check("stripped", "Symbols and debug info", INFO,
                  "NOT stripped -- DWARF debug info present",
                  "sections: %s" % ", ".join(debug_secs[:6]),
                  "Local variable names, types, line numbers and often the "
                  "original source paths are in the file. This is a gift to an "
                  "analyst. Treat as a low-severity information disclosure and "
                  "a very high-value input to Ghidra."))
    elif has_symtab:
        add(Check("stripped", "Symbols and debug info", INFO,
                  "NOT stripped -- .symtab present (%d symbols)" % len(st_names),
                  ".symtab section exists",
                  "Internal, non-exported function names survive. Ghidra will "
                  "name functions instead of showing FUN_00001234 everywhere."))
    else:
        add(Check("stripped", "Symbols and debug info", INFO,
                  "stripped (.symtab absent, %d dynamic symbols remain)"
                  % len(dyn_names),
                  "no .symtab section; .dynsym has %d entries" % len(dyn_names),
                  "Stripping removes .symtab and .strtab. It CANNOT remove "
                  ".dynsym: the dynamic linker needs it to resolve imports and "
                  "exports at run time. So every exported function -- including "
                  "every statically registered Java_* JNI entry point -- still "
                  "has its name. 'Stripped' never means 'no symbols'."))

    # -- CFI ---------------------------------------------------------------
    cfi = sorted(n for n in all_names if n in CFI_SYMBOLS or n.startswith("__cfi"))
    if cfi:
        add(Check("cfi", "Control Flow Integrity", GOOD,
                  "evidence present (%s)" % ", ".join(cfi[:4]),
                  "symbols: %s" % ", ".join(cfi[:8]),
                  "LLVM CFI constrains indirect calls to a valid target set, "
                  "which removes many function-pointer-overwrite primitives. "
                  "Its presence says the build enabled it; it says nothing "
                  "about which call sites were covered."))
    else:
        add(Check("cfi", "Control Flow Integrity", INFO, "no evidence",
                  "no __cfi_* symbols",
                  "CFI is off, or it is on and fully inlined with no exported "
                  "trampoline. Not conclusive either way, and not a finding. "
                  "Shadow Call Stack cannot be detected here at all: it reserves "
                  "register x18 and leaves no symbol behind."))

    # -- code that runs at load time ---------------------------------------
    ia_sz = elf.dt_first(DT_INIT_ARRAYSZ, 0) or 0
    pre_sz = elf.dt_first(DT_PREINIT_ARRAYSZ, 0) or 0
    ptr = 8 if elf.is64 else 4
    n_init = ia_sz // ptr
    n_pre = pre_sz // ptr
    has_dt_init = elf.dt_present(DT_INIT)
    total = n_init + n_pre + (1 if has_dt_init else 0)
    add(Check("init", "Code that runs before JNI_OnLoad",
              WARN if total else GOOD,
              "%d constructor(s)" % total,
              "DT_INIT_ARRAYSZ=%d (%d entries), DT_PREINIT_ARRAYSZ=%d (%d), "
              "DT_INIT %s" % (ia_sz, n_init, pre_sz, n_pre,
                              "present" if has_dt_init else "absent"),
              "Every pointer in .init_array runs the moment the linker finishes "
              "relocating this library -- before JNI_OnLoad, before any Java "
              "code observes anything, and before most instrumentation is in "
              "place. C++ static constructors land here legitimately, which is "
              "why the count is rarely zero. Packers, licence checks and "
              "anti-debug code land here deliberately. Read them first."))

    # -- 16 KiB page readiness ---------------------------------------------
    loads = [p for p in elf.phdrs if p["type"] == PT_LOAD]
    if loads:
        min_align = min(p["align"] or 1 for p in loads)
        if min_align >= 0x4000:
            add(Check("page16k", "16 KiB page compatibility", GOOD,
                      "aligned to 0x%x" % min_align,
                      "smallest PT_LOAD p_align is 0x%x" % min_align,
                      "Devices with 16 KiB kernel pages can map the segments "
                      "directly. Google Play requires 16 KiB alignment for new "
                      "and updated apps targeting recent API levels."))
        else:
            add(Check("page16k", "16 KiB page compatibility", BAD,
                      "only 0x%x (4 KiB)" % min_align,
                      "smallest PT_LOAD p_align is 0x%x" % min_align,
                      "On a 16 KiB-page device the loader cannot honour these "
                      "segment boundaries. This is a compatibility defect, not "
                      "a security one -- but it is the kind of thing that makes "
                      "an app fail to start on new hardware, so report it. Fix: "
                      "link with -Wl,-z,max-page-size=16384."))

    # -- imports of interest ------------------------------------------------
    imports = sorted(s["name"] for s in dyn if not s["defined"] and s["name"])
    risky = [(n, DANGEROUS_IMPORTS[n]) for n in imports if n in DANGEROUS_IMPORTS]
    if risky:
        add(Check("imports", "Imports worth reading", WARN,
                  "%d of interest" % len(risky),
                  "; ".join("%s (%s)" % (n, why) for n, why in risky[:14]),
                  "These are not bugs. They are the call sites to read first. "
                  "An import proves the function is referenced somewhere in this "
                  "library; it says nothing about whether the call is reachable "
                  "or whether its arguments are attacker-influenced."))
    else:
        add(Check("imports", "Imports worth reading", GOOD, "none on the list",
                  "%d imported symbols, none in the watch list" % len(imports),
                  "No unbounded copies, no shell-out, no dynamic loading, no "
                  "anti-debug primitives among the imports."))

    # -- JNI surface --------------------------------------------------------
    jni = sorted(s["name"] for s in dyn if s["defined"] and s["name"].startswith("Java_"))
    onload = "JNI_OnLoad" in dyn_names
    if jni:
        v, st = "%d statically registered Java_* export(s)%s" % (
            len(jni), ", JNI_OnLoad present" if onload else ""), INFO
    elif onload:
        v, st = "no Java_* exports, but JNI_OnLoad is present", INFO
    else:
        v, st = "none", INFO
    add(Check("jni", "JNI surface", st, v,
              (", ".join(jni[:8]) + (" ..." if len(jni) > 8 else "")) if jni
              else ("JNI_OnLoad exported" if onload else "no JNI symbols"),
              "A Java_* export is a statically registered native method: the "
              "name encodes the Java class and method, so it maps straight back "
              "to the Java side. Zero Java_* exports plus a JNI_OnLoad means "
              "registration is dynamic via RegisterNatives, and the mapping "
              "only exists at run time. The mechanism is chapter 16's subject; "
              "recovering the table at run time is 57-Ghidra section 7.2."))

    # -- provenance ---------------------------------------------------------
    bid = elf.build_id()
    if bid:
        add(Check("buildid", "Build ID", INFO, bid,
                  ".note.gnu.build-id descriptor",
                  "Uniquely identifies this exact build. Use it to match a "
                  "stripped library against an unstripped copy, to spot the "
                  "same library shipped in two apps, and to detect that a "
                  "'new' release did not actually rebuild the native layer."))
    com = elf.comment()
    if com:
        add(Check("toolchain", "Toolchain banner", INFO, com[0],
                  " | ".join(com[:3]),
                  "The .comment section usually holds the exact clang and NDK "
                  "version. It dates the build and narrows which compiler "
                  "hardening defaults applied."))

    return checks


# ---------------------------------------------------------------------------
# APK mode: how the library is stored, which decides how it is loaded
# ---------------------------------------------------------------------------

def apk_entry_layout(zf, info):
    """Return (stored, data_offset, alignment) for one zip entry.

    zipfile does not expose the offset of the compressed data, only the local
    header offset, so the local header is parsed by hand: 30 fixed bytes, then
    the name, then the local extra field -- which is NOT always the same length
    as the central-directory extra field, and that is exactly where alignment
    padding is inserted by zipalign.
    """
    fh = zf.fp
    keep = fh.tell()
    try:
        fh.seek(info.header_offset)
        head = fh.read(30)
        if len(head) < 30 or head[:4] != b"PK\x03\x04":
            return None
        n_len, e_len = struct.unpack_from("<HH", head, 26)
        data_off = info.header_offset + 30 + n_len + e_len
    finally:
        fh.seek(keep)
    align = 1
    for a in (0x4000, 0x1000, 4):
        if data_off % a == 0:
            align = a
            break
    return {"stored": info.compress_type == zipfile.ZIP_STORED,
            "data_offset": data_off, "alignment": align}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

STATE_MARK = {GOOD: "[ ok ]", BAD: "[MISS]", WARN: "[warn]",
              INFO: "[info]", UNKNOWN: "[ ?? ]"}


def print_report(label, checks, warnings, verbose, out=sys.stdout):
    out.write("\n" + "=" * 78 + "\n")
    out.write("%s\n" % label)
    out.write("=" * 78 + "\n")
    for w in warnings:
        out.write("  ! %s\n" % w)
    if warnings:
        out.write("\n")
    for c in checks:
        out.write("%s %-34s %s\n" % (STATE_MARK[c.state], c.title, c.value))
        if verbose:
            out.write("        evidence: %s\n" % c.evidence)
            out.write("        %s\n\n" % _wrap(c.meaning, 8))
    if not verbose:
        out.write("\n  (run with --verbose for the byte-level evidence behind "
                  "each line\n   and what it does and does not imply)\n")


def _wrap(text, indent, width=70):
    words, line, lines = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = w
        else:
            line = (line + " " + w) if line else w
    if line:
        lines.append(line)
    pad = " " * indent
    return ("\n" + pad).join(lines)


def check_blob(blob, label):
    elf = Elf(blob, label)
    return elf, analyse(elf)


def main():
    ap = argparse.ArgumentParser(
        description="Chapter 15 ELF hardening checklist, without readelf.",
        epilog="Every line of output is a property of a file, not a finding. "
               "See README section 5.7 for how to write these up honestly.")
    ap.add_argument("targets", nargs="*", help=".so files, or directories")
    ap.add_argument("--apk", help="an APK; every lib/<abi>/*.so inside is checked")
    ap.add_argument("--abi", help="with --apk, restrict to one ABI directory")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="print the evidence and interpretation for every check")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any check is in the MISSING state (for CI)")
    args = ap.parse_args()

    if not args.targets and not args.apk:
        ap.error("give at least one .so, a directory, or --apk")

    results = []
    worst = False

    def handle(blob, label, extra=None):
        nonlocal worst
        try:
            elf, checks = check_blob(blob, label)
        except ElfError as exc:
            results.append({"target": label, "error": str(exc)})
            if not args.json:
                sys.stdout.write("\n%s\n  NOT AN ELF: %s\n" % (label, exc))
            return
        if any(c.state == BAD for c in checks):
            worst = True
        rec = {"target": label,
               "soname": elf.soname(),
               "needed": elf.needed(),
               "size": len(blob),
               "warnings": elf.warnings,
               "checks": [c.as_dict() for c in checks]}
        if extra:
            rec.update(extra)
            # An ABI directory that disagrees with e_machine means the device
            # will either skip the library or load the wrong one. Packers and
            # sloppy build scripts both produce this.
            declared = label.split("lib/", 1)[-1].split("/", 1)[0] \
                if "lib/" in label else None
            actual = EM_NAMES.get(elf.e_machine, (None, None))[1]
            if declared and actual and declared != actual:
                rec["abi_mismatch"] = {"directory": declared, "e_machine": actual}
                if not args.json:
                    sys.stdout.write(
                        "  ! ABI MISMATCH: stored under lib/%s/ but e_machine "
                        "says %s. The device picks the directory by ABI, so this\n"
                        "    library is either never loaded or loaded by a device "
                        "it was not built for.\n" % (declared, actual))
        results.append(rec)
        if not args.json:
            hdr = label
            if elf.soname():
                hdr += "   (SONAME %s)" % elf.soname()
            print_report(hdr, checks, elf.warnings, args.verbose)
            if elf.needed():
                sys.stdout.write("  DT_NEEDED: %s\n" % ", ".join(elf.needed()))
            if extra:
                sys.stdout.write("  in APK: %s, data at offset %d, %d-byte aligned\n"
                                 % ("STORED (uncompressed)" if extra["stored"]
                                    else "DEFLATED (compressed)",
                                    extra["data_offset"], extra["alignment"]))
                if not extra["stored"]:
                    sys.stdout.write(
                        "           -> compressed, so the library must be "
                        "extracted to /data/app/.../lib/ at install time\n"
                        "              rather than mapped straight out of the "
                        "APK. See README section 3.11.\n")
                elif extra["alignment"] < 0x1000:
                    # Uncompressed is only half the requirement. mmap needs a
                    # page-multiple file offset, so an unaligned STORED entry
                    # cannot be mapped in place either.
                    sys.stdout.write(
                        "           -> stored uncompressed BUT NOT page-aligned, "
                        "so it still cannot be mapped\n"
                        "              in place: mmap needs a page-multiple file "
                        "offset. Both conditions\n"
                        "              are required. Run zipalign. See README "
                        "section 3.11.\n")

    for t in args.targets:
        if os.path.isdir(t):
            for root, _, files in os.walk(t):
                for f in sorted(files):
                    if f.endswith(".so"):
                        p = os.path.join(root, f)
                        with open(p, "rb") as fh:
                            handle(fh.read(), p)
        else:
            with open(t, "rb") as fh:
                handle(fh.read(), t)

    if args.apk:
        with zipfile.ZipFile(args.apk) as zf:
            names = [n for n in zf.namelist()
                     if n.startswith("lib/") and n.endswith(".so")]
            if args.abi:
                names = [n for n in names if n.startswith("lib/%s/" % args.abi)]
            if not names:
                sys.stdout.write("no lib/**/*.so entries in %s\n" % args.apk)
            for n in sorted(names):
                info = zf.getinfo(n)
                layout = apk_entry_layout(zf, info)
                handle(zf.read(n), "%s!%s" % (os.path.basename(args.apk), n),
                       extra=layout)

    if args.json:
        json.dump(results, sys.stdout, indent=2)
        sys.stdout.write("\n")

    if args.strict and worst:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
