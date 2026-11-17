#!/usr/bin/env python3
# =============================================================================
# hexdump-header.py -- annotated hex dump with automatic header field decoding
# Chapter 01 -- Computer Science Basics
# =============================================================================
#
# WHAT IT DOES
#   Reads the first N bytes of any file, prints a classic hex dump, and then
#   identifies the file format from its magic bytes and decodes the header
#   field by field. It understands:
#
#     ELF   -- .so shared libraries, executables, and PIE binaries.
#             Decodes magic, class (32/64-bit), endianness, OS ABI, type,
#             machine, entry point, program/section header table offsets.
#     DEX   -- classes.dex and every classesN.dex inside an APK.
#             Decodes magic + version, Adler-32 checksum, SHA-1 signature,
#             file_size, header_size, endian_tag, map_off and the id counts.
#     ZIP   -- .apk, .jar, .zip, and anything else beginning PK\x03\x04.
#             Decodes the local file header, including the first entry name.
#     ODEX / VDEX / ART / OAT -- recognised by magic and reported.
#     Anything else -- a generic dump with a printable-string summary and an
#             entropy estimate, which is usually enough to tell "encrypted
#             blob" from "text config" from "unknown container".
#
#   It also verifies the DEX Adler-32 checksum and SHA-1 signature when the
#   whole file is available, which is how you detect a deliberately corrupted
#   DEX shipped to break static analysis tools.
#
# HOW TO RUN
#   Python 3.7 or newer. Standard library only, no dependencies.
#
#     python3 hexdump-header.py <file> [<file> ...]
#     python3 hexdump-header.py --length 128 classes.dex
#     python3 hexdump-header.py --offset 0x20 --length 32 base.apk
#     python3 hexdump-header.py --no-verify libnative-lib.so
#     python3 hexdump-header.py --quiet /bin/ls          # fields only, no dump
#
#   Typical Android workflow:
#
#     unzip -o app.apk 'classes*.dex' 'lib/arm64-v8a/*' -d extracted/
#     python3 hexdump-header.py extracted/classes.dex
#     python3 hexdump-header.py extracted/lib/arm64-v8a/*.so
#     python3 hexdump-header.py app.apk
#
#   Pull a library straight off a device and inspect it:
#
#     adb pull /system/lib64/libc.so .
#     python3 hexdump-header.py libc.so
#
# REQUIREMENTS
#   Python >= 3.7. Runs on Linux, WSL, macOS and Windows. No third-party
#   packages. Works on files of any size (only the requested slice is read for
#   the dump; checksum verification streams the file in chunks).
#
# SEE ALSO
#   ../labs/lab-01-binary-hex-endianness.md -- do all of this by hand first
#   ../../12-DEX-Internals/README.md        -- the rest of the DEX format
#   ../../10-APK-Internals/README.md        -- the rest of the ZIP/APK format
#   ../../15-Native-Code/README.md          -- the rest of the ELF format
# =============================================================================

import argparse
import hashlib
import math
import os
import sys
import zlib

# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

PRINTABLE = set(range(0x20, 0x7F))


def u(data, off, size, little=True):
    """Read an unsigned integer of `size` bytes at `off`. Returns None if the
    slice is not fully present, so a truncated file degrades gracefully."""
    if off + size > len(data):
        return None
    return int.from_bytes(data[off:off + size], "little" if little else "big")


def hx(data, off, size):
    """Raw bytes at off..off+size as spaced hex, or '<truncated>'."""
    if off + size > len(data):
        return "<truncated>"
    return data[off:off + size].hex(" ")


def ascii_of(chunk):
    return "".join(chr(b) if b in PRINTABLE else "." for b in chunk)


def shannon_entropy(chunk):
    """Bits of entropy per byte, 0.0 (uniform) to 8.0 (random)."""
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    total = len(chunk)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


# -----------------------------------------------------------------------------
# Output formatting
# -----------------------------------------------------------------------------

RULE = "=" * 78
THIN = "-" * 78


def hexdump(data, base_offset=0, width=16):
    """Print a classic three-column hex dump: offset | hex | ascii."""
    print(f"{'offset':>8}  {'hex bytes':<{width * 3}} ascii")
    print(THIN)
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        print(f"{base_offset + i:08x}  {hexpart:<{width * 3}} |{ascii_of(chunk)}|")


def print_fields(fields):
    """fields is a list of (offset, size, name, raw_hex, decoded) tuples."""
    if not fields:
        return
    name_w = max(len(f[2]) for f in fields)
    raw_w = min(24, max(len(f[3]) for f in fields))
    print(f"{'off':>6} {'sz':>3}  {'field':<{name_w}}  "
          f"{'raw':<{raw_w}}  decoded")
    print(THIN)
    for off, size, name, raw, decoded in fields:
        raw_show = raw if len(raw) <= raw_w else raw[:raw_w - 3] + "..."
        print(f"0x{off:04x} {size:>3}  {name:<{name_w}}  "
              f"{raw_show:<{raw_w}}  {decoded}")


# -----------------------------------------------------------------------------
# ELF
# -----------------------------------------------------------------------------

ELF_CLASS = {0: "ELFCLASSNONE (invalid)", 1: "ELFCLASS32 (32-bit)",
             2: "ELFCLASS64 (64-bit)"}

ELF_DATA = {0: "ELFDATANONE (invalid)",
            1: "ELFDATA2LSB (little-endian)",
            2: "ELFDATA2MSB (big-endian)"}

ELF_OSABI = {0: "SYSV / None", 1: "HP-UX", 2: "NetBSD", 3: "Linux",
             6: "Solaris", 9: "FreeBSD", 12: "OpenBSD", 64: "ARM AEABI",
             97: "ARM", 255: "Standalone"}

ELF_TYPE = {0: "ET_NONE", 1: "ET_REL (relocatable object)",
            2: "ET_EXEC (fixed-address executable)",
            3: "ET_DYN (shared object or PIE)", 4: "ET_CORE (core dump)"}

ELF_MACHINE = {
    0x00: "EM_NONE", 0x02: "SPARC", 0x03: "x86 (i386)", 0x08: "MIPS",
    0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390", 0x28: "ARM (32-bit)",
    0x2A: "SuperH", 0x32: "IA-64", 0x3E: "x86-64 (AMD64)",
    0xB7: "AArch64 (ARM 64-bit)", 0xF3: "RISC-V",
}


def looks_like_elf(data):
    return data[:4] == b"\x7fELF"


def decode_elf(data):
    fields = []
    fields.append((0x00, 4, "e_ident[MAG]", hx(data, 0, 4),
                   "0x7F 'E' 'L' 'F' -- valid ELF magic"))

    ei_class = u(data, 4, 1)
    ei_data = u(data, 5, 1)
    ei_version = u(data, 6, 1)
    ei_osabi = u(data, 7, 1)
    ei_abiver = u(data, 8, 1)

    is64 = (ei_class == 2)
    little = (ei_data != 2)

    fields.append((0x04, 1, "e_ident[CLASS]", hx(data, 4, 1),
                   ELF_CLASS.get(ei_class, f"unknown ({ei_class})")))
    fields.append((0x05, 1, "e_ident[DATA]", hx(data, 5, 1),
                   ELF_DATA.get(ei_data, f"unknown ({ei_data})")))
    fields.append((0x06, 1, "e_ident[VERSION]", hx(data, 6, 1),
                   "1 (current)" if ei_version == 1 else f"unexpected ({ei_version})"))
    fields.append((0x07, 1, "e_ident[OSABI]", hx(data, 7, 1),
                   ELF_OSABI.get(ei_osabi, f"unknown ({ei_osabi})")))
    fields.append((0x08, 1, "e_ident[ABIVER]", hx(data, 8, 1), str(ei_abiver)))
    fields.append((0x09, 7, "e_ident[PAD]", hx(data, 9, 7), "reserved, should be zero"))

    e_type = u(data, 0x10, 2, little)
    e_machine = u(data, 0x12, 2, little)
    e_version = u(data, 0x14, 4, little)

    fields.append((0x10, 2, "e_type", hx(data, 0x10, 2),
                   ELF_TYPE.get(e_type, f"unknown ({e_type})")))
    if e_machine is None:
        machine_text = "<truncated>"
    else:
        machine_text = ELF_MACHINE.get(e_machine, f"unknown (0x{e_machine:04x})")
    fields.append((0x12, 2, "e_machine", hx(data, 0x12, 2), machine_text))
    fields.append((0x14, 4, "e_version", hx(data, 0x14, 4),
                   "1 (current)" if e_version == 1 else f"unexpected ({e_version})"))

    ptr = 8 if is64 else 4
    off = 0x18
    for name, note in (("e_entry", "entry point virtual address"),
                       ("e_phoff", "program header table file offset"),
                       ("e_shoff", "section header table file offset")):
        val = u(data, off, ptr, little)
        extra = ""
        if name == "e_entry" and e_type == 3:
            extra = "  (relative -- ET_DYN, real address = load_base + this)"
        fields.append((off, ptr, name, hx(data, off, ptr),
                       f"0x{val:x} -- {note}{extra}" if val is not None else "<truncated>"))
        off += ptr

    for name, size, note in (("e_flags", 4, "processor-specific flags"),
                             ("e_ehsize", 2, "size of this ELF header"),
                             ("e_phentsize", 2, "size of one program header entry"),
                             ("e_phnum", 2, "number of program headers"),
                             ("e_shentsize", 2, "size of one section header entry"),
                             ("e_shnum", 2, "number of section headers"),
                             ("e_shstrndx", 2, "index of the section-name string table")):
        val = u(data, off, size, little)
        fields.append((off, size, name, hx(data, off, size),
                       f"{val} (0x{val:x}) -- {note}" if val is not None else "<truncated>"))
        off += size

    notes = []
    if e_type == 3:
        notes.append(
            "ET_DYN means every address inside this file is an OFFSET from an\n"
            "  unknown load base chosen at runtime by ASLR. Android has required\n"
            "  position-independent executables since Android 5.0, so essentially\n"
            "  every .so and every native binary you meet will be ET_DYN.\n"
            "  runtime_address = Module.findBaseAddress(name) + file_offset")
    if e_type == 2:
        notes.append(
            "ET_EXEC means a FIXED load address, which defeats ASLR. On Android\n"
            "  this is either a very old binary or something built deliberately\n"
            "  outside the platform toolchain -- worth investigating.")
    if ei_data == 2:
        notes.append(
            "EI_DATA says BIG-ENDIAN. No Android ABI is big-endian, so this file\n"
            "  did not come from an Android build.")
    if e_machine == 0xB7:
        notes.append("AArch64 -- expect this under lib/arm64-v8a/ in an APK.")
    elif e_machine == 0x28:
        notes.append("ARM 32-bit -- expect this under lib/armeabi-v7a/ in an APK.")
    elif e_machine == 0x3E:
        notes.append("x86-64 -- an emulator build, or a desktop binary.")

    return "ELF", fields, notes


# -----------------------------------------------------------------------------
# DEX
# -----------------------------------------------------------------------------

def looks_like_dex(data):
    return data[:4] == b"dex\n" and len(data) >= 8 and data[7:8] == b"\x00"


def decode_dex(data, path=None, verify=True):
    fields = []
    magic = data[:8]
    version = magic[4:7].decode("ascii", "replace")
    fields.append((0x00, 8, "magic", hx(data, 0, 8),
                   f"'dex\\n{version}\\0' -- DEX format version {version}"))

    checksum = u(data, 0x08, 4)
    fields.append((0x08, 4, "checksum", hx(data, 8, 4),
                   f"0x{checksum:08x} -- Adler-32 of everything after this field"
                   if checksum is not None else "<truncated>"))

    sig = data[0x0C:0x20]
    fields.append((0x0C, 20, "signature", sig.hex(),
                   "SHA-1 of everything after this field"))

    layout = [
        (0x20, "file_size", "total size of the file in bytes"),
        (0x24, "header_size", "size of this header -- must be 0x70 (112)"),
        (0x28, "endian_tag", "0x12345678 little-endian, 0x78563412 byte-swapped"),
        (0x2C, "link_size", "size of the link section (0 in practice)"),
        (0x30, "link_off", "offset of the link section (0 in practice)"),
        (0x34, "map_off", "offset of the map_list -- the table of contents"),
        (0x38, "string_ids_size", "number of strings in the file"),
        (0x3C, "string_ids_off", "offset of the string id list"),
        (0x40, "type_ids_size", "number of distinct types"),
        (0x44, "type_ids_off", "offset of the type id list"),
        (0x48, "proto_ids_size", "number of method prototypes"),
        (0x4C, "proto_ids_off", "offset of the prototype id list"),
        (0x50, "field_ids_size", "number of field references"),
        (0x54, "field_ids_off", "offset of the field id list"),
        (0x58, "method_ids_size", "number of method references (the 64K limit)"),
        (0x5C, "method_ids_off", "offset of the method id list"),
        (0x60, "class_defs_size", "number of classes DEFINED in this file"),
        (0x64, "class_defs_off", "offset of the class definition list"),
        (0x68, "data_size", "size of the data section"),
        (0x6C, "data_off", "offset of the data section"),
    ]

    values = {}
    for off, name, note in layout:
        val = u(data, off, 4)
        values[name] = val
        if val is None:
            fields.append((off, 4, name, "<truncated>", "not present in the bytes read"))
            continue
        decoded = f"{val} (0x{val:x}) -- {note}"
        if name == "endian_tag":
            if val == 0x12345678:
                decoded = "0x12345678 -- ENDIAN_CONSTANT, little-endian (normal)"
            elif val == 0x78563412:
                decoded = "0x78563412 -- REVERSE_ENDIAN_CONSTANT, byte-swapped file"
            else:
                decoded = f"0x{val:08x} -- INVALID endian tag, header is corrupt or faked"
        if name == "header_size" and val != 0x70:
            decoded += "   <-- ANOMALY: the spec fixes this at 0x70"
        fields.append((off, 4, name, hx(data, off, 4), decoded))

    notes = []
    known_versions = {"035": "original / Android 1.0+",
                      "037": "Android 7.0, default methods and invoke-polymorphic",
                      "038": "Android 8.0, invoke-custom and const-method-handle",
                      "039": "Android 9.0, hidden API restrictions era"}
    if version in known_versions:
        notes.append(f"DEX version {version}: {known_versions[version]}")
    else:
        notes.append(f"DEX version {version} is not one of the usual "
                     f"035/037/038/039 -- inspect carefully.")

    if values.get("method_ids_size") is not None:
        n = values["method_ids_size"]
        if n > 60000:
            notes.append(
                f"method_ids_size is {n}. The DEX format indexes methods with a\n"
                "  16-bit value, so a single DEX cannot reference more than 65536\n"
                "  methods. This file is close to that limit, which is why large\n"
                "  apps ship classes2.dex, classes3.dex and so on (multidex).")

    # Verify checksum and signature against the real file when possible.
    if verify and path and os.path.isfile(path):
        try:
            real_size = os.path.getsize(path)
            if values.get("file_size") is not None:
                if values["file_size"] == real_size:
                    notes.append(f"file_size matches the real file size ({real_size}).")
                else:
                    notes.append(
                        f"file_size says {values['file_size']} but the file is\n"
                        f"  {real_size} bytes on disk. MISMATCH -- the header has been\n"
                        "  edited, the file is truncated, or it is a deliberately\n"
                        "  malformed DEX intended to break static analysis tools.")

            with open(path, "rb") as fh:
                fh.seek(0x0C)
                adler = 1
                sha = hashlib.sha1()
                first = True
                while True:
                    block = fh.read(1 << 20)
                    if not block:
                        break
                    adler = zlib.adler32(block, adler)
                    # Adler-32 covers bytes 0x0C onward; SHA-1 covers 0x20 onward.
                    # We are already positioned at 0x0C, so skip the first 20
                    # bytes (the signature field itself) for the SHA-1.
                    if first:
                        sha.update(block[20:])
                        first = False
                    else:
                        sha.update(block)
                adler &= 0xFFFFFFFF

            if checksum is not None:
                notes.append(
                    f"Adler-32 over bytes 0x0C.. is 0x{adler:08x}; header says "
                    f"0x{checksum:08x} -- {'MATCH' if adler == checksum else 'MISMATCH'}.")
            digest = sha.hexdigest()
            notes.append(
                f"SHA-1 over bytes 0x20.. is {digest[:16]}...; header says "
                f"{sig.hex()[:16]}... -- "
                f"{'MATCH' if digest == sig.hex() else 'MISMATCH'}.")
        except OSError as exc:
            notes.append(f"could not re-read the file to verify: {exc}")

    notes.append(
        "A checksum or signature MISMATCH is not necessarily a broken file. It is\n"
        "  a recognised anti-analysis technique: desktop parsers reject the file\n"
        "  while some runtime load paths accept it. Recompute both, patch them in,\n"
        "  and the file usually opens in jadx.")

    return "DEX", fields, notes


# -----------------------------------------------------------------------------
# ZIP / APK / JAR
# -----------------------------------------------------------------------------

ZIP_METHOD = {0: "stored (no compression)", 8: "deflate", 9: "deflate64",
              12: "bzip2", 14: "LZMA", 93: "zstd", 95: "XZ"}


def looks_like_zip(data):
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def decode_zip(data):
    sig = data[:4]
    if sig == b"PK\x05\x06":
        return "ZIP", [(0, 4, "signature", hx(data, 0, 4),
                        "end-of-central-directory record -- an EMPTY archive")], []
    if sig == b"PK\x07\x08":
        return "ZIP", [(0, 4, "signature", hx(data, 0, 4),
                        "spanned/split archive marker")], []

    fields = [(0x00, 4, "signature", hx(data, 0, 4),
               "'PK\\x03\\x04' -- ZIP local file header (P and K are Phil Katz)")]

    flags = u(data, 0x06, 2)
    method = u(data, 0x08, 2)
    name_len = u(data, 0x1A, 2)
    extra_len = u(data, 0x1C, 2)

    layout = [
        (0x04, 2, "version_needed", "minimum ZIP version required to extract"),
        (0x06, 2, "flags", "general purpose bit flags"),
        (0x08, 2, "compression", "compression method"),
        (0x0A, 2, "mod_time", "last modification time (MS-DOS format)"),
        (0x0C, 2, "mod_date", "last modification date (MS-DOS format)"),
        (0x0E, 4, "crc32", "CRC-32 of the uncompressed data"),
        (0x12, 4, "compressed_size", "size of the stored data"),
        (0x16, 4, "uncompressed_size", "size after decompression"),
        (0x1A, 2, "filename_len", "length of the name that follows"),
        (0x1C, 2, "extra_len", "length of the extra field"),
    ]
    for off, size, name, note in layout:
        val = u(data, off, size)
        if val is None:
            fields.append((off, size, name, "<truncated>", "not present"))
            continue
        decoded = f"{val} (0x{val:x}) -- {note}"
        if name == "compression":
            decoded = f"{val} -- {ZIP_METHOD.get(val, 'unknown method')}"
        if name == "flags":
            bits = []
            if val & 0x0001:
                bits.append("bit0 ENCRYPTED")
            if val & 0x0008:
                bits.append("bit3 sizes in a trailing data descriptor")
            if val & 0x0800:
                bits.append("bit11 filename is UTF-8")
            decoded = f"0x{val:04x} -- {', '.join(bits) if bits else 'none set'}"
        fields.append((off, size, name, hx(data, off, size), decoded))

    if name_len:
        start = 0x1E
        raw = data[start:start + name_len]
        if len(raw) == name_len:
            fields.append((start, name_len, "filename", raw.hex(" ")[:48],
                           repr(raw.decode("utf-8", "replace"))))

    notes = []
    if flags is not None and flags & 0x0001:
        notes.append("The encryption bit is set. Standard APKs are never encrypted "
                     "at the ZIP level; this is unusual.")
    if method not in (0, 8) and method is not None:
        notes.append(f"Compression method {method} is not stored or deflate. Android's "
                     "own loader only handles those two for entries it maps, so an "
                     "unusual method here is worth a second look.")
    notes.append(
        "A ZIP's real index is the CENTRAL DIRECTORY at the END of the file, not\n"
        "  these local headers. That redundancy is what makes ZIP tricks possible:\n"
        "  a file can be listed once in the central directory and appear differently\n"
        "  in its local header. The historical Android 'Master Key' family of bugs\n"
        "  all came from a verifier and a loader disagreeing about which copy of an\n"
        "  entry was authoritative. See ../../10-APK-Internals/README.md.")
    notes.append(
        "If this is an APK, the first entry is usually a stored (uncompressed),\n"
        "  4-byte-aligned resources.arsc, because zipalign arranges it so the\n"
        "  runtime can mmap it directly.")

    return "ZIP/APK", fields, notes


# -----------------------------------------------------------------------------
# Other Android magics worth recognising
# -----------------------------------------------------------------------------

OTHER_MAGIC = [
    (b"dey\n", "ODEX", "Optimised DEX (pre-ART / Dalvik era)."),
    (b"vdex", "VDEX", "Verified DEX container produced by dex2oat; holds the "
                      "original DEX plus verification results."),
    (b"oat\n", "OAT", "Ahead-of-time compiled ELF payload produced by dex2oat."),
    (b"art\n", "ART", "ART image file -- the pre-initialised boot heap that "
                      "zygote maps."),
    (b"\x03\x00\x08\x00", "AXML", "Binary AndroidManifest.xml or compiled "
                                  "layout resource."),
    (b"\x02\x00\x0c\x00", "ARSC", "resources.arsc -- the compiled resource table."),
    (b"\x1f\x8b", "GZIP", "gzip stream."),
    (b"\x89PNG", "PNG", "PNG image."),
    (b"\xff\xd8\xff", "JPEG", "JPEG image."),
    (b"BZh", "BZIP2", "bzip2 archive."),
    (b"\xfd7zXZ", "XZ", "XZ archive."),
    (b"ANDROID!", "BOOTIMG", "Android boot image (kernel + ramdisk)."),
    (b"SQLite format 3\x00", "SQLITE", "SQLite 3 database -- very often an app's "
                                       "local data store, worth dumping."),
]


def decode_other(data, path=None):
    for magic, name, note in OTHER_MAGIC:
        if data.startswith(magic):
            fields = [(0, len(magic), "magic", hx(data, 0, len(magic)), note)]
            return name, fields, []

    # Generic fallback.
    fields = [(0, min(8, len(data)), "magic", hx(data, 0, min(8, len(data))),
               "no known signature -- see the heuristics below")]

    notes = []
    # Entropy on 112 bytes is a poor estimate, so re-read a larger sample when
    # the file is still available.
    sample = data[:4096]
    if path:
        try:
            with open(path, "rb") as fh:
                bigger = fh.read(4096)
            if len(bigger) > len(sample):
                sample = bigger
        except OSError:
            pass
    ent = shannon_entropy(sample)
    printable = sum(1 for b in sample if b in PRINTABLE or b in (9, 10, 13))
    ratio = printable / len(sample) if sample else 0.0

    notes.append(f"Shannon entropy of the first {len(sample)} bytes: {ent:.2f} "
                 "bits/byte (8.00 = indistinguishable from random).")
    notes.append(f"Printable-character ratio: {ratio * 100:.1f}%.")

    if ent > 7.5:
        notes.append(
            "High entropy with no recognisable magic means compressed or\n"
            "  encrypted data. Inside an APK's assets/ or res/raw/, this is the\n"
            "  classic shape of a packed secondary DEX or an encrypted payload.\n"
            "  Next step: find the code that opens this file and work out the key.")
    elif ratio > 0.90:
        notes.append("Mostly printable -- this is probably text, JSON, XML or a "
                     "PEM-encoded key.")
    else:
        notes.append("Mixed binary content with no signature. Try searching the\n"
                     "  whole file for embedded magics: an inner 'dex\\n' or 'PK\\x03\\x04'\n"
                     "  at a non-zero offset is the standard way packed payloads hide.")

    if path:
        try:
            notes.append(f"File size on disk: {os.path.getsize(path)} bytes.")
        except OSError:
            pass

    return "UNKNOWN", fields, notes


# -----------------------------------------------------------------------------
# Driver
# -----------------------------------------------------------------------------

def analyse(path, dump_length, read_length, offset, quiet, verify):
    print()
    print(RULE)
    print(f" {path}")
    print(RULE)

    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(read_length)
    except OSError as exc:
        print(f" cannot read: {exc}")
        return 1

    if not data:
        print(" file is empty or the offset is past the end.")
        return 1

    try:
        size = os.path.getsize(path)
        print(f" size on disk: {size} bytes (0x{size:x})   "
              f"read {len(data)} bytes from offset 0x{offset:x}")
    except OSError:
        print(f" read {len(data)} bytes from offset 0x{offset:x}")

    if not quiet:
        print()
        hexdump(data[:dump_length], base_offset=offset)

    # Header decoding only makes sense when we started at the beginning.
    if offset != 0:
        print()
        print(" (offset is non-zero, so no header decoding was attempted)")
        return 0

    if looks_like_elf(data):
        kind, fields, notes = decode_elf(data)
    elif looks_like_dex(data):
        kind, fields, notes = decode_dex(data, path=path, verify=verify)
    elif looks_like_zip(data):
        kind, fields, notes = decode_zip(data)
    else:
        kind, fields, notes = decode_other(data, path=path)

    print()
    print(f" detected format: {kind}")
    print()
    print_fields(fields)

    if notes:
        print()
        print(" notes")
        print(THIN)
        for n in notes:
            print(f" * {n}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Annotated hex dump with automatic ELF / DEX / ZIP header "
                    "decoding. Chapter 01 of the Android Security Handbook.",
        epilog="Do lab-01-binary-hex-endianness.md by hand first; this script "
               "is for checking your answers, not replacing them.")
    parser.add_argument("files", nargs="+", help="one or more files to inspect")
    parser.add_argument("-n", "--length", type=lambda s: int(s, 0), default=64,
                        help="bytes to read and dump (default 64; accepts 0x hex)")
    parser.add_argument("-s", "--offset", type=lambda s: int(s, 0), default=0,
                        help="start offset (default 0; accepts 0x hex)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="skip the hex dump, print decoded fields only")
    parser.add_argument("--no-verify", dest="verify", action="store_false",
                        help="do not re-read the file to verify DEX checksums")
    args = parser.parse_args(argv)

    if args.length <= 0:
        parser.error("--length must be positive")
    # The dump shows exactly what was asked for, but a DEX header is 112 bytes
    # and a 64-bit ELF header is 64, so read at least 112 to decode fields.
    read_len = max(args.length, 112) if args.offset == 0 else args.length

    rc = 0
    for path in args.files:
        rc |= analyse(path, args.length, read_len, args.offset,
                      args.quiet, args.verify)
    print()
    return rc


if __name__ == "__main__":
    sys.exit(main())
