#!/usr/bin/env python3
"""
ctf-build-challenge.py -- synthesise libvault.so, the target for
                          labs/lab-05-ctf-the-honest-header.md.

WHAT IT DOES
    Writes a 64-bit little-endian AArch64 ELF shared object, byte by byte, from
    nothing but the System V gABI structure layouts. The resulting file has an
    honest program header table and a dynamic array -- the two things the
    dynamic linker actually reads -- and a SECTION HEADER TABLE THAT LIES about
    almost everything else.

    That is the whole lesson of the lab, and it is not a contrivance: a section
    header table is metadata for tools, is never consulted by the loader, and
    can therefore say anything at all without affecting whether the file runs.
    Real packers exploit this, usually by deleting the table; making it lie
    instead is the same idea with the volume turned up so that you can see
    which of your tools trusted it.

    Specifically, the generated file contains:

      HONEST                                LYING
      ------                                -----
      ELF header e_type / e_machine         .dynstr section header -> a decoy
      Program headers (4 PT_LOAD etc.)         string table saying "libinnocent.so"
      PT_DYNAMIC and the whole DT_* array    .dynsym section header -> a decoy
      .rela.dyn relocations                     symbol table with plausible,
      The real .dynsym / .dynstr contents        wrong names
      The real .rodata contents              .rodata section header -> size 0
                                             .text section header -> wrong address
                                             .comment -> a fabricated toolchain

    Four answers are recoverable from it, each needing a different technique.
    The lab states the format of each and gives a SHA-256 so a solver can check
    an answer without being shown it.

HOW TO RUN
    python3 ctf-build-challenge.py                       # writes ./libvault.so
    python3 ctf-build-challenge.py /tmp/ch15-fixtures    # writes there
    python3 ctf-build-challenge.py --answers             # prints the answers.
                                                         # Do not run this first.

REQUIREMENTS
    Python 3.6+. Standard library only. No NDK, no compiler, no device --
    which is deliberate, so that the CTF works for a reader who has none of
    those.

WHAT THIS WILL *NOT* PRODUCE
    - A runnable library. The .text section contains filler bytes, not
      instructions. The file is structurally valid for every PARSER in this
      chapter and would be rejected the moment a CPU tried to execute it. It is
      a parsing challenge and the lab says so plainly; do not push it to a
      device expecting it to load.
    - A realistic packer. Real packers delete section headers or encrypt
      segments. This one lies in place, because a lie is more instructive than
      an absence: an absence makes your tools complain, and a lie makes them
      answer confidently and wrongly.
    - Any obfuscation of the flags beyond a single-byte XOR. The difficulty is
      meant to be in knowing WHERE to look, not in cryptanalysis.
"""

import hashlib
import os
import struct
import sys

# ---------------------------------------------------------------------------
# The answers. Everything below is generated from these.
# ---------------------------------------------------------------------------

REAL_SONAME = "libvault.so"
DECOY_SONAME = "libinnocent.so"

CTOR_VADDR = 0x1180                     # where the constructor "is"

HIDDEN_METHODS = ["signRequest", "verifyLicense"]
HIDDEN_SIGS = ["([BJ)[B", "(Ljava/lang/String;)Z"]

XOR_KEY = 0xB7                          # == low byte of e_machine (183, AArch64)
SECRET_PLAIN = "CTF{segments_never_lie_sections_always_can}"

DECOY_STRING = "this string is in the decoy string table"


def answers():
    return [
        ("Flag 1 -- the real SONAME", "CTF{soname_%s}" % REAL_SONAME),
        ("Flag 2 -- the constructor address", "CTF{ctor_0x%x}" % CTOR_VADDR),
        ("Flag 3 -- the dynamically registered methods",
         "CTF{hidden_%s}" % "_".join(HIDDEN_METHODS)),
        ("Flag 4 -- the decoded secret", SECRET_PLAIN),
    ]


# ---------------------------------------------------------------------------
# ELF constants (gABI chapters 4 and 5)
# ---------------------------------------------------------------------------

ELFCLASS64, ELFDATA2LSB, EV_CURRENT = 2, 1, 1
ET_DYN, EM_AARCH64 = 3, 183

PT_LOAD, PT_DYNAMIC, PT_NOTE, PT_PHDR = 1, 2, 4, 6
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4

SHT_PROGBITS, SHT_STRTAB, SHT_DYNSYM, SHT_NOTE = 1, 3, 11, 7
SHT_DYNAMIC, SHT_RELA, SHT_HASH, SHT_INIT_ARRAY = 6, 4, 5, 14
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4

DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 1, 4, 5, 6
DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 7, 8, 9, 10, 11
DT_SONAME, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_FLAGS = 14, 25, 27, 30
DF_BIND_NOW = 0x8

STB_GLOBAL, STT_FUNC, STT_OBJECT, STV_DEFAULT = 1, 2, 1, 0
SHN_UNDEF = 0

R_AARCH64_RELATIVE = 1027
NT_GNU_BUILD_ID = 3

PAGE = 0x1000

# ---------------------------------------------------------------------------
# Fixed layout. file offset == virtual address throughout, which keeps the
# alignment requirement trivially satisfied and the arithmetic readable.
# ---------------------------------------------------------------------------

OFF_EHDR = 0x0000
OFF_PHDR = 0x0040
OFF_NOTE = 0x0200
OFF_DYNSYM = 0x0300           # the REAL one
OFF_DYNSTR = 0x0400           # the REAL one
OFF_HASH = 0x0500
OFF_RELA = 0x0580
OFF_RODATA = 0x0600           # flags live here
OFF_DECOY_SYM = 0x0900        # what the lying section header points at
OFF_DECOY_STR = 0x0A00
OFF_TEXT = 0x1000
OFF_DYNAMIC = 0x2000
OFF_INIT_ARRAY = 0x2100
OFF_GOT = 0x2110
OFF_SHSTRTAB = 0x2200
OFF_SHDR = 0x3000

TEXT_SIZE = 0x400
IMAGE_END = 0x4000


def cstrtab(names):
    """Build a string table and return (bytes, {name: offset})."""
    blob = bytearray(b"\x00")
    off = {"": 0}
    for n in names:
        if n in off:
            continue
        off[n] = len(blob)
        blob += n.encode("ascii") + b"\x00"
    return bytes(blob), off


def sym64(name_off, info, other, shndx, value, size):
    return struct.pack("<IBBHQQ", name_off, info, other, shndx, value, size)


def build():
    img = bytearray(IMAGE_END)

    # ---- .dynstr (REAL) ---------------------------------------------------
    real_names = [REAL_SONAME, "libc.so", "JNI_OnLoad",
                  "Java_com_ctf_vault_Vault_check", "malloc", "strcmp",
                  "g_vault_state"]
    dynstr, stroff = cstrtab(real_names)
    img[OFF_DYNSTR:OFF_DYNSTR + len(dynstr)] = dynstr

    # ---- .dynsym (REAL) ---------------------------------------------------
    syms = [sym64(0, 0, 0, SHN_UNDEF, 0, 0)]
    syms.append(sym64(stroff["malloc"], (STB_GLOBAL << 4) | STT_FUNC,
                      STV_DEFAULT, SHN_UNDEF, 0, 0))
    syms.append(sym64(stroff["strcmp"], (STB_GLOBAL << 4) | STT_FUNC,
                      STV_DEFAULT, SHN_UNDEF, 0, 0))
    syms.append(sym64(stroff["JNI_OnLoad"], (STB_GLOBAL << 4) | STT_FUNC,
                      STV_DEFAULT, 2, OFF_TEXT + 0x40, 0x30))
    syms.append(sym64(stroff["Java_com_ctf_vault_Vault_check"],
                      (STB_GLOBAL << 4) | STT_FUNC, STV_DEFAULT, 2,
                      OFF_TEXT + 0x80, 0x60))
    syms.append(sym64(stroff["g_vault_state"], (STB_GLOBAL << 4) | STT_OBJECT,
                      STV_DEFAULT, 4, OFF_GOT + 0x8, 8))
    dynsym = b"".join(syms)
    img[OFF_DYNSYM:OFF_DYNSYM + len(dynsym)] = dynsym
    nsyms = len(syms)

    # ---- .hash, so the symbol count is derivable without section headers --
    # Layout: nbucket, nchain, bucket[nbucket], chain[nchain].
    # Only nchain has to be right for a parser to size .dynsym; the buckets are
    # filled with a legal but unhelpful single-bucket arrangement.
    nbucket = 1
    hash_words = [nbucket, nsyms, 0] + [0] * nsyms
    hashblob = struct.pack("<%dI" % len(hash_words), *hash_words)
    img[OFF_HASH:OFF_HASH + len(hashblob)] = hashblob

    # ---- .rela.dyn --------------------------------------------------------
    # One RELATIVE relocation whose r_offset is the .init_array slot and whose
    # ADDEND carries the constructor's address. The slot itself stays zero,
    # exactly as a real AArch64 build leaves it.
    r_info = (0 << 32) | R_AARCH64_RELATIVE
    rela = struct.pack("<QQq", OFF_INIT_ARRAY, r_info, CTOR_VADDR)
    img[OFF_RELA:OFF_RELA + len(rela)] = rela

    # ---- .rodata ----------------------------------------------------------
    ro = bytearray()

    def put(b):
        start = len(ro)
        ro.extend(b)
        return OFF_RODATA + start

    put(b"vault: ready\x00")
    for name, sig in zip(HIDDEN_METHODS, HIDDEN_SIGS):
        put(name.encode() + b"\x00")
        put(sig.encode() + b"\x00")
    put(b"check\x00")
    put(b"(Ljava/lang/String;)Z\x00")
    put(b"CTF{soname_%s}\x00" % REAL_SONAME.encode())   # flag 1, plainly present
    # The terminator is encoded too, so that XORing the whole region yields a
    # properly NUL-terminated string rather than one ending in the key byte.
    put(bytes(bytearray(
        [(ord(c) ^ XOR_KEY) & 0xFF for c in SECRET_PLAIN] + [XOR_KEY])))
    put(b"E_NOKEY\x00")
    put(b"/data/local/tmp/vault.dat\x00")
    img[OFF_RODATA:OFF_RODATA + len(ro)] = bytes(ro)

    # ---- decoy string and symbol tables -----------------------------------
    decoy_names = [DECOY_SONAME, "libssl.so", "SSL_new", "SSL_free",
                   "EVP_EncryptInit_ex", DECOY_STRING]
    decoy_str, dstroff = cstrtab(decoy_names)
    img[OFF_DECOY_STR:OFF_DECOY_STR + len(decoy_str)] = decoy_str

    decoy_syms = [sym64(0, 0, 0, SHN_UNDEF, 0, 0)]
    for n in ("SSL_new", "SSL_free", "EVP_EncryptInit_ex"):
        decoy_syms.append(sym64(dstroff[n], (STB_GLOBAL << 4) | STT_FUNC,
                                STV_DEFAULT, SHN_UNDEF, 0, 0))
    decoy_sym = b"".join(decoy_syms)
    img[OFF_DECOY_SYM:OFF_DECOY_SYM + len(decoy_sym)] = decoy_sym

    # ---- .text filler -----------------------------------------------------
    # Not instructions. See the header: this is a parsing target.
    for i in range(TEXT_SIZE):
        img[OFF_TEXT + i] = (0x1F + i) & 0xFF

    # ---- .dynamic ---------------------------------------------------------
    dyn = [
        (DT_NEEDED, stroff["libc.so"]),
        (DT_SONAME, stroff[REAL_SONAME]),
        (DT_HASH, OFF_HASH),
        (DT_STRTAB, OFF_DYNSTR),
        (DT_STRSZ, len(dynstr)),
        (DT_SYMTAB, OFF_DYNSYM),
        (DT_SYMENT, 24),
        (DT_RELA, OFF_RELA),
        (DT_RELASZ, len(rela)),
        (DT_RELAENT, 24),
        (DT_INIT_ARRAY, OFF_INIT_ARRAY),
        (DT_INIT_ARRAYSZ, 8),
        (DT_FLAGS, DF_BIND_NOW),
        (DT_NULL, 0),
    ]
    blob = b"".join(struct.pack("<QQ", t, v) for t, v in dyn)
    img[OFF_DYNAMIC:OFF_DYNAMIC + len(blob)] = blob
    dynamic_size = len(blob)

    # .init_array slot: DELIBERATELY ZERO. The address is in the RELA addend.
    struct.pack_into("<Q", img, OFF_INIT_ARRAY, 0)

    # ---- .note.gnu.build-id ----------------------------------------------
    desc = bytes(bytearray(range(0x10)))
    note = struct.pack("<III", 4, len(desc), NT_GNU_BUILD_ID) + b"GNU\x00" + desc
    img[OFF_NOTE:OFF_NOTE + len(note)] = note

    # ---- section header string table (names for the LYING table) ---------
    shnames = ["", ".text", ".rodata", ".dynsym", ".dynstr", ".dynamic",
               ".note.gnu.build-id", ".comment", ".shstrtab", ".init_array"]
    shstr, shoff = cstrtab([n for n in shnames if n])
    img[OFF_SHSTRTAB:OFF_SHSTRTAB + len(shstr)] = shstr

    # a fabricated toolchain banner, immediately after shstrtab
    off_comment = OFF_SHSTRTAB + len(shstr)
    comment = b"GCC: (Debian 4.9.2-10) 4.9.2\x00"
    img[off_comment:off_comment + len(comment)] = comment

    # ---- program headers: HONEST -----------------------------------------
    phdrs = []

    def ph(ptype, flags, off, vaddr, filesz, memsz, align):
        phdrs.append(struct.pack("<IIQQQQQQ", ptype, flags, off, vaddr,
                                 vaddr, filesz, memsz, align))

    ph(PT_PHDR, PF_R, OFF_PHDR, OFF_PHDR, 7 * 56, 7 * 56, 8)
    ph(PT_LOAD, PF_R, 0x0000, 0x0000, 0x0C00, 0x0C00, PAGE)
    ph(PT_LOAD, PF_R | PF_X, OFF_TEXT, OFF_TEXT, TEXT_SIZE, TEXT_SIZE, PAGE)
    ph(PT_LOAD, PF_R | PF_W, OFF_DYNAMIC, OFF_DYNAMIC, 0x0120, 0x0120, PAGE)
    ph(PT_DYNAMIC, PF_R | PF_W, OFF_DYNAMIC, OFF_DYNAMIC,
       dynamic_size, dynamic_size, 8)
    ph(PT_GNU_RELRO, PF_R, OFF_DYNAMIC, OFF_DYNAMIC, 0x0120, 0x0120, 1)
    ph(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0)
    assert len(phdrs) == 7
    img[OFF_PHDR:OFF_PHDR + 7 * 56] = b"".join(phdrs)

    # ---- section headers: LYING ------------------------------------------
    shdrs = []

    def sh(name, stype, flags, addr, off, size, link=0, info=0,
           align=1, entsize=0):
        shdrs.append(struct.pack("<IIQQQQIIQQ", shoff.get(name, 0), stype,
                                 flags, addr, off, size, link, info,
                                 align, entsize))

    sh("", 0, 0, 0, 0, 0)                                            # 0 NULL
    # LIE 1: .text claims to be at the .rodata address.
    sh(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
       OFF_RODATA, OFF_RODATA, TEXT_SIZE, align=4)                   # 1
    # LIE 2: .rodata claims to be empty.
    sh(".rodata", SHT_PROGBITS, SHF_ALLOC, OFF_RODATA, OFF_RODATA, 0)  # 2
    # LIE 3: .dynsym points at the decoy symbol table.
    sh(".dynsym", SHT_DYNSYM, SHF_ALLOC, OFF_DECOY_SYM, OFF_DECOY_SYM,
       len(decoy_sym), link=4, info=1, align=8, entsize=24)          # 3
    # LIE 4: .dynstr points at the decoy string table.
    sh(".dynstr", SHT_STRTAB, SHF_ALLOC, OFF_DECOY_STR, OFF_DECOY_STR,
       len(decoy_str))                                               # 4
    # honest, because a lie here would stop the dynamic array being findable
    # by section-based tools and the point is that they disagree, not that they
    # fail
    sh(".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, OFF_DYNAMIC,
       OFF_DYNAMIC, dynamic_size, link=4, align=8, entsize=16)       # 5
    sh(".note.gnu.build-id", SHT_NOTE, SHF_ALLOC, OFF_NOTE, OFF_NOTE,
       len(note), align=4)                                           # 6
    # LIE 5: a fabricated toolchain banner
    sh(".comment", SHT_PROGBITS, 0, 0, off_comment, len(comment))    # 7
    sh(".init_array", SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE, OFF_INIT_ARRAY,
       OFF_INIT_ARRAY, 8, align=8, entsize=8)                        # 8
    sh(".shstrtab", SHT_STRTAB, 0, 0, OFF_SHSTRTAB, len(shstr))      # 9
    assert len(shdrs) == 10
    img[OFF_SHDR:OFF_SHDR + 10 * 64] = b"".join(shdrs)

    # ---- ELF header -------------------------------------------------------
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = ELFCLASS64
    ident[5] = ELFDATA2LSB
    ident[6] = EV_CURRENT
    img[0:16] = bytes(ident)
    struct.pack_into("<HHIQQQIHHHHHH", img, 16,
                     ET_DYN, EM_AARCH64, EV_CURRENT,
                     0,                 # e_entry
                     OFF_PHDR, OFF_SHDR,
                     0,                 # e_flags
                     64, 56, 7, 64, 10, 9)
    return bytes(img)


def main():
    args = [a for a in sys.argv[1:]]
    if "--answers" in args:
        print("Do not read this until you have tried the lab.\n")
        for label, value in answers():
            print("%-46s %s" % (label, value))
            print("%-46s sha256 %s"
                  % ("", hashlib.sha256(value.encode()).hexdigest()))
        return 0
    if "--hashes" in args:
        for label, value in answers():
            print("%-46s %s" % (label, hashlib.sha256(value.encode()).hexdigest()))
        return 0

    outdir = args[0] if args else "."
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    path = os.path.join(outdir, "libvault.so")
    blob = build()
    with open(path, "wb") as fh:
        fh.write(blob)
    print("wrote %s (%d bytes)" % (path, len(blob)))
    print("sha256 %s" % hashlib.sha256(blob).hexdigest())
    print()
    print("This file is a PARSING target, not a runnable library: its .text")
    print("holds filler bytes rather than instructions. Do not push it to a")
    print("device expecting it to load.")
    print()
    print("Start with:  python3 elf-inspect.py %s --sections" % path)
    print("Then ask yourself whether you believe any of it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
