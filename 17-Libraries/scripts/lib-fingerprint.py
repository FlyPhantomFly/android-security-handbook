#!/usr/bin/env python3
"""
lib-fingerprint.py -- work out WHICH VERSION of a bundled library an APK
                      contains, from the shipped artifact alone, and print
                      the evidence that produced every answer.

WHAT IT DOES
    Chapter 17 section 3.7 says version identification is triangulation, not
    lookup: each technique yields a constraint, and you intersect the
    constraints. This script automates the constraints that can be computed
    from a file on disk, and refuses to pretend about the ones that cannot.

    Signals implemented (numbering follows README section 3.7):

      T1  Embedded version banners
          Byte-level search for the strings libraries carry so that they can
          report themselves: OPENSSL_VERSION_TEXT, "libcurl/7.x.y",
          "FFmpeg version ...", "libpng version ...", "inflate 1.2.11
          Copyright", "okhttp/4.9.3", SQLite's bare "3.NN.N" and its
          SQLITE_SOURCE_ID line.

      T2  Class-set comparison
          Lists the classes the APK actually DEFINES, by parsing the DEX
          header, class_defs, type_ids and string_ids -- not by scanning for
          printable runs. With --refs it compares that set against reference
          JAR/AAR files you downloaded from Maven and scores each one.

      T3  Native symbol sets
          Parses ELF .dynsym without readelf and matches symbol families
          (SSL_*, png_*, jpeg_*, sqlite3_*, curl_*, av_*) to say which
          third-party libraries were STATICALLY LINKED into a .so. Gradle can
          never tell you this; it is the biggest blind spot in mobile
          dependency scanning.

      T4  ELF build ID and .comment
          .note.gnu.build-id uniquely identifies one exact build. .comment
          usually holds the exact clang/NDK banner, which dates the build.

      T5  Resource and asset artefacts
          META-INF/<group>_<artifact>.version stamps -- when present these are
          literal, exact, and the single cheapest win in the whole chapter.

      T6  Behavioural signals
          NOT IMPLEMENTED, deliberately. Endpoints, User-Agent headers,
          SharedPreferences keys and thread names require a running process.
          The script reports T6 as "not attempted, requires runtime" instead
          of quietly leaving a gap. See labs/lab-03-sdk-audit.md.

    Every finding is printed with a confidence level, the byte-level evidence
    behind it, and a note on what would raise or lower that confidence.
    Findings that DISAGREE are printed as CONFLICTS rather than averaged --
    a stamp saying 4.9.3 and a banner saying 3.12.1 in the same APK is a real
    observation about shading or a second bundled copy, not noise to smooth
    over.

WHAT THIS WILL *NOT* TELL YOU
    - That a version is correct. A fingerprint is EVIDENCE, not proof. Every
      signal here can be forged, and several are trivially forgeable: a
      version banner is a string constant, a META-INF stamp is a text file,
      and both survive being edited by anyone who can repackage an APK. The
      script reports what the bytes say. Deciding whether the bytes are honest
      is your job, and labs/lab-05-ctf-library-that-lied.md is that job.
    - Whether the library is REACHED. A class in the DEX is not a class that
      runs; a .so in lib/ is not a .so that loads. Reachability is a runtime
      question -- README section 7.4.
    - Whether an old version is a finding. It is not, on its own. Reachability
      and the data handled decide that, and the rubric in README section 8.1
      Phase 4 is how you decide it defensibly. See faq.md.
    - Which CVEs affect the version it reports. No vulnerability database is
      consulted and none is bundled. Take the version to OSV or the NVD
      yourself, and read faq.md on their Android false-positive rate first.
    - Anything about code the app downloads later. Only the file you pass is
      read.
    - Anything about a split APK you did not pass. Run it on every path
      `adb shell pm path <pkg>` returned, or use scripts/lib-inventory.sh,
      which iterates them for you.
    - Anything about string-encrypted or packed code. Chapter 40 owns that.
      Here obfuscation is an obstacle to identification, and the script says
      so when a class set looks stripped rather than pretending it is small.

HOW TO RUN
    # Everything the file can be made to say, in one pass
    python3 lib-fingerprint.py app.apk

    # One managed library, scored against reference releases you downloaded
    #   curl -O https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.9.3/okhttp-4.9.3.jar
    python3 lib-fingerprint.py app.apk --prefix okhttp3 --refs ./refs

    # One native library only
    python3 lib-fingerprint.py app.apk --so lib/arm64-v8a/libfoo.so
    python3 lib-fingerprint.py libfoo.so

    # Class inventory, for scripts/lib-inventory.sh and for your own greps
    python3 lib-fingerprint.py app.apk --list-classes
    python3 lib-fingerprint.py app.apk --list-prefixes 3

    # Machine-readable, for diffing one build against the next
    python3 lib-fingerprint.py app.apk --json > build-1234.json

REQUIREMENTS
    Python 3.8 or newer. Standard library only -- nothing to install, no
    readelf, no baksmali, no network access. Runs identically on Windows,
    macOS and Linux, which is why the labs point Windows readers at it.

RELATED
    ../README.md section 3.7            the six techniques, in prose
    ../README.md section 8.1            the inventory-then-rate methodology
    ../scripts/lib-inventory.sh         the enumeration phase; calls this
                                        script as its last-resort fallback
    ../examples/fingerprint-signals.json the signal database this reads
    ../labs/lab-02-version-fingerprint.md the lab this was written for
    ../../12-DEX-Internals/README.md    the DEX structures parsed below
    ../../10-APK-Internals/README.md    the ZIP container they live in

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import os
import re
import struct
import sys
import zipfile
from collections import OrderedDict, defaultdict

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# DEX magic is "dex\n0NN\0". 035 is the baseline; 037-041 are later versions.
DEX_MAGIC_PREFIX = b"dex\n"
CDEX_MAGIC_PREFIX = b"cdex"
DEX_ENDIAN_CONSTANT = 0x12345678

# Header field offsets (see 12-DEX-Internals). Sizes are u32 little-endian.
OFF_ENDIAN_TAG = 0x28
OFF_STRING_IDS_SIZE = 0x38
OFF_STRING_IDS_OFF = 0x3C
OFF_TYPE_IDS_SIZE = 0x40
OFF_TYPE_IDS_OFF = 0x44
OFF_CLASS_DEFS_SIZE = 0x60
OFF_CLASS_DEFS_OFF = 0x64
CLASS_DEF_ITEM_SIZE = 32

# ELF
ELF_MAGIC = b"\x7fELF"
ELFCLASS32, ELFCLASS64 = 1, 2
SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOTE, SHT_DYNSYM = 2, 3, 6, 7, 11
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_HASH, DT_SONAME = 0, 1, 5, 6, 4, 14
NT_GNU_BUILD_ID = 3
E_MACHINE = {3: "x86", 40: "arm", 62: "x86_64", 183: "aarch64"}

CONF_ORDER = {"high": 3, "medium": 2, "low": 1}

# T1 -- version banners. Each entry is
#   (library id, human name, compiled regex, what the string actually is)
# The regexes are deliberately anchored on text the upstream project puts in
# its own binary for its own reporting, which is why they are stable.
BANNERS = [
    ("openssl", "OpenSSL",
     re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})"),
     "OPENSSL_VERSION_TEXT, compiled into every OpenSSL build"),
    ("boringssl", "BoringSSL",
     re.compile(rb"(BoringSSL)"),
     "BoringSSL carries no version; its presence is the finding"),
    ("libcurl", "libcurl",
     re.compile(rb"libcurl/(\d+\.\d+\.\d+)"),
     "the default curl User-Agent, built from LIBCURL_VERSION"),
    ("ffmpeg", "FFmpeg",
     re.compile(rb"FFmpeg version (n?[0-9][0-9a-zA-Z.\-]*)"),
     "FFmpeg's own version banner"),
    ("libpng", "libpng",
     re.compile(rb"libpng version (\d+\.\d+\.\d+)"),
     "the libpng copyright banner"),
    ("zlib", "zlib",
     re.compile(rb"inflate (\d+\.\d+\.\d+) Copyright"),
     "zlib's inflate copyright string, which embeds ZLIB_VERSION"),
    ("okhttp", "OkHttp",
     re.compile(rb"okhttp/(\d+\.\d+\.\d+)"),
     "the User-Agent fragment OkHttp sends"),
    ("sqlite-source-id", "SQLite",
     re.compile(rb"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [0-9a-f]{20,})"),
     "SQLITE_SOURCE_ID: build date plus source hash. It pins one exact "
     "upstream release, but you have to look the hash up -- it is not itself "
     "a version number, so it is recorded as corroboration"),
    ("libjpeg-turbo", "libjpeg-turbo",
     re.compile(rb"(libjpeg-turbo version \d+\.\d+\.\d+)"),
     "the libjpeg-turbo version banner"),
    ("bzip2", "bzip2",
     re.compile(rb"bzip2/libbzip2 version (\d+\.\d+\.\d+)"),
     "the bzip2 banner"),
    ("lua", "Lua",
     re.compile(rb"\$LuaVersion: (Lua \d+\.\d+[^ ]*)"),
     "Lua's embedded RCS-style version marker"),
]

# A bare "3.NN.N" is only meaningful once sqlite3_* symbols prove SQLite is
# present, so it is scored separately and only reported with corroboration.
SQLITE_BARE_VERSION = re.compile(rb"(?<![\d.])(3\.\d{1,2}\.\d{1,2})(?![\d.])")

# The compiler banner in .comment. Dates the build, which brackets everything
# else -- a library cannot be newer than the toolchain that compiled it.
COMPILER_BANNER = re.compile(
    rb"((?:Android|Debian|Ubuntu|FreeBSD)? ?\(?[^)\x00]{0,60}\)? ?"
    rb"(?:clang|GCC|GNU C\+?\+?) version [0-9][^\x00]{0,40})")

# T3 -- symbol families. Prefix -> (library id, human name, what it proves).
SYMBOL_FAMILIES = [
    (re.compile(r"^(SSL_|EVP_|X509_|OPENSSL_|CRYPTO_)"), "openssl-or-boringssl",
     "OpenSSL or BoringSSL",
     "TLS/crypto is statically linked into this .so, not taken from the platform"),
    (re.compile(r"^png_"), "libpng", "libpng",
     "a PNG parser is statically linked; adversary-chosen bytes reach it"),
    (re.compile(r"^(jpeg_|tj)"), "libjpeg", "libjpeg / libjpeg-turbo",
     "a JPEG parser is statically linked"),
    (re.compile(r"^sqlite3_"), "sqlite", "SQLite",
     "SQLite is statically linked rather than using the platform's libsqlite"),
    (re.compile(r"^curl_"), "libcurl", "libcurl",
     "HTTP is done in native code, outside every Java-level interception point"),
    (re.compile(r"^(av_|avcodec_|avformat_|avutil_|swscale_)"), "ffmpeg", "FFmpeg",
     "media demuxers and decoders are statically linked"),
    (re.compile(r"^(BZ2_|lzma_|ZSTD_|LZ4_)"), "compression", "a compression library",
     "an archive/compression parser is statically linked"),
    (re.compile(r"^(inflate|deflate|zlib|gz)"), "zlib", "zlib",
     "zlib is statically linked"),
    (re.compile(r"^(protobuf_|_ZN6google8protobuf)"), "protobuf", "Protocol Buffers",
     "protobuf is statically linked; payloads on the wire will be binary"),
    (re.compile(r"^(uv_|ares_)"), "libuv-or-cares", "libuv / c-ares",
     "an async I/O or DNS library is statically linked"),
]

# Symbols that describe the JNI shape of the library rather than its identity.
JNI_MARKERS = [
    (re.compile(r"^JNI_OnLoad$"),
     "JNI_OnLoad is exported: natives may be bound dynamically with "
     "RegisterNatives, so absent Java_* symbols do NOT mean absent JNI"),
    (re.compile(r"^Java_"),
     "statically named JNI entry points are exported; the Java class and "
     "method names in them survive R8, because JNI resolves by name"),
    (re.compile(r"^__stack_chk_fail$"),
     "stack protector is in use (a hardening observation, not a version one)"),
    (re.compile(r"^(_Znwm|_ZdlPv|__cxa_)"),
     "C++ runtime symbols: the library is C++, so expect mangled names"),
]

# T5 -- version stamp entries inside the APK.
VERSION_STAMP = re.compile(r"^META-INF/(.+)\.version$")

# Anything that is code but is not classes*.dex or lib/*.so.
EXTRA_CODE = re.compile(
    r"^(assets|res/raw)/.*\.(dex|jar|apk|zip|so|bundle|js|lua|wasm)$", re.I)

CLASSES_DEX = re.compile(r"^classes\d*\.dex$")

# Fallback descriptor scan, used only when the DEX header cannot be trusted.
DESCRIPTOR_SCAN = re.compile(rb"L([a-zA-Z][A-Za-z0-9_$/]{2,200});")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def read_uleb128(buf, off):
    """DEX unsigned LEB128. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated uleb128")
        byte = buf[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
        if shift > 35:
            raise ValueError("over-long uleb128")


def cstr(buf, off):
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", "replace")


def printable(raw):
    """Make arbitrary bytes (or an already-decoded string) safe to print.

    Every byte below 0x20 becomes a dot. Report lines must never carry raw
    control characters: they corrupt terminals, they break grep, and a file
    containing one registers as binary.
    """
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    return "".join(c if 0x20 <= ord(c) < 0x7F else "." for c in text)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Evidence(object):
    """One observation. Never a conclusion on its own.

    bound is what the observation constrains:
      exact     this is the version
      min       the version is at least this
      max       the version is at most this
      presence  the library is present; the version is not constrained
    """

    def __init__(self, technique, library, claim, bound, confidence,
                 where, why, raises=None):
        self.technique = technique
        self.library = library
        self.claim = claim
        self.bound = bound
        self.confidence = confidence
        self.where = where
        self.why = why
        self.raises = raises or ""

    def as_dict(self):
        return OrderedDict([
            ("technique", self.technique), ("library", self.library),
            ("claim", self.claim), ("bound", self.bound),
            ("confidence", self.confidence), ("where", self.where),
            ("why", self.why), ("would_raise_confidence", self.raises),
        ])


# ---------------------------------------------------------------------------
# DEX
# ---------------------------------------------------------------------------

class DexParseError(Exception):
    pass


def dex_defined_classes(blob, name="classes.dex"):
    """Return (set_of_class_names, how_it_was_read).

    Walks class_defs -> type_ids -> string_ids, which yields exactly the
    classes this DEX DEFINES. That is the right set: type_ids also contains
    every class merely REFERENCED, which would list platform classes the app
    never shipped and inflate every comparison.
    """
    if blob[:4] == CDEX_MAGIC_PREFIX:
        raise DexParseError(
            "CompactDex (cdex) container: this is a vdex-internal format, not "
            "a standalone DEX. Extract with a vdex tool first")
    if blob[:4] != DEX_MAGIC_PREFIX:
        raise DexParseError("not a DEX: magic is %r" % (blob[:8],))
    if len(blob) < 0x70:
        raise DexParseError("shorter than a DEX header")
    if u32(blob, OFF_ENDIAN_TAG) != DEX_ENDIAN_CONSTANT:
        raise DexParseError("endian_tag is not 0x12345678; byte-swapped DEX")

    string_ids_size = u32(blob, OFF_STRING_IDS_SIZE)
    string_ids_off = u32(blob, OFF_STRING_IDS_OFF)
    type_ids_size = u32(blob, OFF_TYPE_IDS_SIZE)
    type_ids_off = u32(blob, OFF_TYPE_IDS_OFF)
    class_defs_size = u32(blob, OFF_CLASS_DEFS_SIZE)
    class_defs_off = u32(blob, OFF_CLASS_DEFS_OFF)

    def bounded(off, count, width, what):
        if count and (off + count * width > len(blob) or off < 0x70):
            raise DexParseError("%s table runs past end of file" % what)

    bounded(string_ids_off, string_ids_size, 4, "string_ids")
    bounded(type_ids_off, type_ids_size, 4, "type_ids")
    bounded(class_defs_off, class_defs_size, CLASS_DEF_ITEM_SIZE, "class_defs")

    def string_at(idx):
        if idx >= string_ids_size:
            raise DexParseError("string index %d out of range" % idx)
        data_off = u32(blob, string_ids_off + idx * 4)
        _, after = read_uleb128(blob, data_off)      # utf16_size, unused here
        return cstr(blob, after)

    names = set()
    for i in range(class_defs_size):
        type_idx = u32(blob, class_defs_off + i * CLASS_DEF_ITEM_SIZE)
        if type_idx >= type_ids_size:
            continue
        desc_idx = u32(blob, type_ids_off + type_idx * 4)
        desc = string_at(desc_idx)
        if desc.startswith("L") and desc.endswith(";"):
            names.add(desc[1:-1])
    version = blob[4:7].decode("ascii", "replace")
    return names, "DEX %s header parse of %s (%d class_defs)" % (
        version, name, class_defs_size)


def dex_classes_fallback(blob, name="classes.dex"):
    """Last resort: scan for L...; descriptors anywhere in the file.

    Reports classes the DEX only REFERENCES as well as ones it defines, and
    will pick up descriptor-shaped bytes out of the bytecode. Lower quality,
    and the caller must say so in its output.
    """
    found = set()
    for m in DESCRIPTOR_SCAN.finditer(blob):
        found.add(m.group(1).decode("ascii", "replace"))
    return found, "byte-scan fallback on %s (references included, LOW quality)" % name


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

class Elf(object):
    """Just enough ELF to answer chapter 17's questions without readelf."""

    def __init__(self, blob, name="<elf>"):
        self.blob = blob
        self.name = name
        self.notes = []          # degradation messages for the report
        if blob[:4] != ELF_MAGIC:
            raise ValueError("not an ELF file")
        self.elfclass = blob[4]
        self.is64 = self.elfclass == ELFCLASS64
        if blob[5] != 1:
            self.notes.append("big-endian ELF; offsets below assume "
                              "little-endian and may be wrong")
        self.machine = u16(blob, 18)
        self.arch = E_MACHINE.get(self.machine, "machine=%d" % self.machine)
        if self.is64:
            self.shoff, self.shentsize = u64(blob, 0x28), u16(blob, 0x3A)
            self.shnum, self.shstrndx = u16(blob, 0x3C), u16(blob, 0x3E)
            self.phoff, self.phentsize = u64(blob, 0x20), u16(blob, 0x36)
            self.phnum = u16(blob, 0x38)
        else:
            self.shoff, self.shentsize = u32(blob, 0x20), u16(blob, 0x2E)
            self.shnum, self.shstrndx = u16(blob, 0x30), u16(blob, 0x32)
            self.phoff, self.phentsize = u32(blob, 0x1C), u16(blob, 0x2A)
            self.phnum = u16(blob, 0x2C)
        self.sections = self._sections()

    def _sections(self):
        out = []
        if not self.shoff or not self.shnum:
            self.notes.append(
                "no section headers: the file was stripped of them. Symbol "
                "enumeration falls back to PT_DYNAMIC and is less complete")
            return out
        raw = []
        for i in range(self.shnum):
            base = self.shoff + i * self.shentsize
            if base + self.shentsize > len(self.blob):
                self.notes.append("section header table truncated at index %d" % i)
                break
            if self.is64:
                name, stype = u32(self.blob, base), u32(self.blob, base + 4)
                off, size = u64(self.blob, base + 0x18), u64(self.blob, base + 0x20)
                link = u32(self.blob, base + 0x28)
                entsize = u64(self.blob, base + 0x38)
            else:
                name, stype = u32(self.blob, base), u32(self.blob, base + 4)
                off, size = u32(self.blob, base + 0x10), u32(self.blob, base + 0x14)
                link = u32(self.blob, base + 0x18)
                entsize = u32(self.blob, base + 0x24)
            raw.append({"name_off": name, "type": stype, "offset": off,
                        "size": size, "link": link, "entsize": entsize})
        strtab = b""
        if self.shstrndx < len(raw):
            s = raw[self.shstrndx]
            strtab = self.blob[s["offset"]:s["offset"] + s["size"]]
        for s in raw:
            s["name"] = cstr(strtab, s["name_off"]) if strtab else ""
            out.append(s)
        return out

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def section_bytes(self, name):
        s = self.section(name)
        if not s:
            return b""
        return self.blob[s["offset"]:s["offset"] + s["size"]]

    def dynamic_symbols(self):
        """Names in .dynsym. Empty set plus a note if it cannot be read."""
        sym = self.section(".dynsym")
        strt = self.section(".dynstr")
        if not sym or not strt:
            return self._symbols_via_pt_dynamic()
        strdata = self.blob[strt["offset"]:strt["offset"] + strt["size"]]
        entsize = sym["entsize"] or (24 if self.is64 else 16)
        names = set()
        count = sym["size"] // entsize if entsize else 0
        for i in range(count):
            base = sym["offset"] + i * entsize
            if base + 4 > len(self.blob):
                break
            nameoff = u32(self.blob, base)
            if nameoff:
                names.add(cstr(strdata, nameoff))
        names.discard("")
        return names

    def _symbols_via_pt_dynamic(self):
        """Without section headers, DT_HASH is the only portable symbol count.

        DT_GNU_HASH-only binaries cannot be sized this way without walking the
        bucket chains, and this script does not; it says so rather than
        guessing.
        """
        dyn = self._pt_dynamic_entries()
        if dyn is None:
            self.notes.append("no PT_DYNAMIC: cannot enumerate symbols. "
                              "Use `readelf --dyn-syms --wide` for this file")
            return set()
        strtab_va = dyn.get(DT_STRTAB)
        symtab_va = dyn.get(DT_SYMTAB)
        hash_va = dyn.get(DT_HASH)
        if strtab_va is None or symtab_va is None or hash_va is None:
            self.notes.append(
                "PT_DYNAMIC lacks DT_HASH, so the dynamic symbol count is not "
                "derivable here. DT_NEEDED was still read. For the full symbol "
                "list use `readelf --dyn-syms --wide`")
            return set()
        stroff = self._va_to_off(strtab_va)
        symoff = self._va_to_off(symtab_va)
        hashoff = self._va_to_off(hash_va)
        if None in (stroff, symoff, hashoff):
            return set()
        nchain = u32(self.blob, hashoff + 4)
        entsize = 24 if self.is64 else 16
        names = set()
        for i in range(nchain):
            base = symoff + i * entsize
            if base + 4 > len(self.blob):
                break
            nameoff = u32(self.blob, base)
            if nameoff:
                names.add(cstr(self.blob, stroff + nameoff))
        names.discard("")
        self.notes.append("symbols recovered via PT_DYNAMIC/DT_HASH "
                          "(%d entries), not section headers" % nchain)
        return names

    def _program_headers(self):
        out = []
        for i in range(self.phnum):
            base = self.phoff + i * self.phentsize
            if base + self.phentsize > len(self.blob):
                break
            if self.is64:
                out.append({"type": u32(self.blob, base),
                            "offset": u64(self.blob, base + 8),
                            "vaddr": u64(self.blob, base + 16),
                            "filesz": u64(self.blob, base + 32)})
            else:
                out.append({"type": u32(self.blob, base),
                            "offset": u32(self.blob, base + 4),
                            "vaddr": u32(self.blob, base + 8),
                            "filesz": u32(self.blob, base + 16)})
        return out

    def _va_to_off(self, vaddr):
        for ph in self._program_headers():
            if ph["type"] != PT_LOAD:
                continue
            if ph["vaddr"] <= vaddr < ph["vaddr"] + ph["filesz"]:
                return ph["offset"] + (vaddr - ph["vaddr"])
        return None

    def _pt_dynamic_entries(self):
        seg = None
        for ph in self._program_headers():
            if ph["type"] == PT_DYNAMIC:
                seg = ph
                break
        if seg is None:
            return None
        width = 16 if self.is64 else 8
        entries = {}
        self._dt_needed_offsets = []
        off = seg["offset"]
        end = off + seg["filesz"]
        while off + width <= min(end, len(self.blob)):
            if self.is64:
                tag, val = u64(self.blob, off), u64(self.blob, off + 8)
            else:
                tag, val = u32(self.blob, off), u32(self.blob, off + 4)
            if tag == DT_NULL:
                break
            if tag == DT_NEEDED:
                self._dt_needed_offsets.append(val)
            else:
                entries[tag] = val
            off += width
        return entries

    def needed(self):
        """DT_NEEDED list. Works with or without section headers."""
        dynsec = self.section(".dynamic")
        strsec = self.section(".dynstr")
        if dynsec and strsec:
            strdata = self.blob[strsec["offset"]:strsec["offset"] + strsec["size"]]
            width = 16 if self.is64 else 8
            out = []
            off = dynsec["offset"]
            end = off + dynsec["size"]
            while off + width <= min(end, len(self.blob)):
                if self.is64:
                    tag, val = u64(self.blob, off), u64(self.blob, off + 8)
                else:
                    tag, val = u32(self.blob, off), u32(self.blob, off + 4)
                if tag == DT_NULL:
                    break
                if tag == DT_NEEDED:
                    out.append(cstr(strdata, val))
                off += width
            return out
        dyn = self._pt_dynamic_entries()
        if dyn is None:
            return []
        stroff = self._va_to_off(dyn.get(DT_STRTAB, 0))
        if stroff is None:
            return []
        return [cstr(self.blob, stroff + v)
                for v in getattr(self, "_dt_needed_offsets", [])]

    def build_id(self):
        for s in self.sections:
            if s["type"] != SHT_NOTE:
                continue
            data = self.blob[s["offset"]:s["offset"] + s["size"]]
            off = 0
            while off + 12 <= len(data):
                namesz, descsz, ntype = (u32(data, off), u32(data, off + 4),
                                         u32(data, off + 8))
                name_at = off + 12
                desc_at = name_at + ((namesz + 3) & ~3)
                if ntype == NT_GNU_BUILD_ID and data[name_at:name_at + 3] == b"GNU":
                    return data[desc_at:desc_at + descsz].hex()
                off = desc_at + ((descsz + 3) & ~3)
                if descsz == 0 and namesz == 0:
                    break
        return None

    def comment(self):
        raw = self.section_bytes(".comment")
        if not raw:
            return []
        return [p.decode("utf-8", "replace")
                for p in raw.split(b"\x00") if len(p) > 3]

    def has_init_array(self):
        s = self.section(".init_array")
        if s:
            width = 8 if self.is64 else 4
            return s["size"] // width if width else 0
        return None


# ---------------------------------------------------------------------------
# Signal database
# ---------------------------------------------------------------------------

DEFAULT_DB_RELATIVE = os.path.join("..", "examples", "fingerprint-signals.json")


def load_db(path):
    """Load the class-prefix rule database. Missing file is not fatal."""
    if path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.normpath(os.path.join(here, DEFAULT_DB_RELATIVE))
    if not os.path.isfile(path):
        return {"libraries": []}, "no signal database at %s" % path
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), "signal database: %s" % path
    except (ValueError, OSError) as exc:
        return {"libraries": []}, "signal database unreadable (%s)" % exc


# ---------------------------------------------------------------------------
# Container reading
# ---------------------------------------------------------------------------

class Target(object):
    """Whatever the user passed: an APK, a bare DEX, or a bare .so."""

    def __init__(self, path):
        self.path = path
        self.kind = None
        self.entries = OrderedDict()   # name -> bytes, lazily filled
        self.zf = None
        self.names = []
        with open(path, "rb") as fh:
            head = fh.read(8)
        if head[:4] == ELF_MAGIC:
            self.kind = "elf"
            self.names = [os.path.basename(path)]
        elif head[:4] in (DEX_MAGIC_PREFIX, CDEX_MAGIC_PREFIX):
            self.kind = "dex"
            self.names = [os.path.basename(path)]
        elif zipfile.is_zipfile(path):
            self.kind = "zip"
            self.zf = zipfile.ZipFile(path)
            self.names = self.zf.namelist()
        else:
            raise ValueError(
                "%s is not an APK/ZIP, a DEX or an ELF. If it is an AAB or an "
                "XAPK, unzip it first and pass the APKs inside." % path)

    def read(self, name):
        if self.kind == "zip":
            return self.zf.read(name)
        with open(self.path, "rb") as fh:
            return fh.read()

    def dex_entries(self):
        if self.kind == "dex":
            return [os.path.basename(self.path)]
        return sorted(n for n in self.names if CLASSES_DEX.match(n))

    def so_entries(self):
        if self.kind == "elf":
            return [os.path.basename(self.path)]
        return sorted(n for n in self.names
                      if n.startswith("lib/") and n.endswith(".so"))

    def close(self):
        if self.zf:
            self.zf.close()


# ---------------------------------------------------------------------------
# The techniques
# ---------------------------------------------------------------------------

def t5_version_stamps(target, ev):
    """META-INF/<group>_<artifact>.version -- literal and exact."""
    found = 0
    if target.kind != "zip":
        return found
    for name in sorted(target.names):
        m = VERSION_STAMP.match(name)
        if not m:
            continue
        try:
            value = target.read(name).decode("utf-8", "replace").strip()
        except KeyError:
            continue
        if not value:
            continue
        found += 1
        ev.append(Evidence(
            "T5 version stamp", m.group(1), value, "exact", "high", name,
            "the build system wrote this file to record the artifact version; "
            "it is a literal string, not an inference",
            "corroborate with T2 (does the class set match that release?) -- "
            "a stamp is a text file and can be edited by a repackager"))
    return found


def t1_banners(blob, where, ev, sqlite_symbols_present=False):
    """Byte-level scan for self-reporting version strings."""
    hits = 0
    for lib_id, human, rx, what in BANNERS:
        for m in rx.finditer(blob):
            value = m.group(1).decode("utf-8", "replace")
            hits += 1
            # A source-hash line and a "BoringSSL" marker identify a build but
            # are not version numbers, so they corroborate rather than claim.
            bound = ("presence" if lib_id in ("boringssl", "sqlite-source-id")
                     else "exact")
            ev.append(Evidence(
                "T1 version banner", human, value, bound, "high", where,
                "%s (matched %r)" % (what, printable(m.group(0))[:80]),
                "confirm the same library also appears in T3 symbols; a lone "
                "string can be left over from a different component"))
            break     # one banner per library per file is enough
    if sqlite_symbols_present:
        m = SQLITE_BARE_VERSION.search(blob)
        if m:
            hits += 1
            ev.append(Evidence(
                "T1 version banner", "SQLite",
                m.group(1).decode("ascii"), "exact", "medium", where,
                "bare 3.x.y version string, reported only because sqlite3_* "
                "symbols prove SQLite is actually in this file",
                "match SQLITE_SOURCE_ID as well; that carries a source hash "
                "and cannot be confused with an unrelated 3.x.y string"))
    m = COMPILER_BANNER.search(blob)
    if m:
        ev.append(Evidence(
            "T4 .comment", "toolchain", printable(m.group(1)).strip(),
            "max", "medium", where,
            "the compiler banner in .comment; nothing in this file can predate "
            "the toolchain that built it, so this is an upper bound on age",
            "cross-check against the NDK release that shipped that clang"))
    return hits


def t3_symbols(elf, where, ev):
    """Symbol families -- what was statically linked into this .so."""
    syms = elf.dynamic_symbols()
    if not syms:
        return set(), 0
    matched = 0
    for rx, lib_id, human, meaning in SYMBOL_FAMILIES:
        examples = sorted(s for s in syms if rx.match(s))[:4]
        if not examples:
            continue
        matched += 1
        ev.append(Evidence(
            "T3 symbol family", human, "statically linked", "presence", "high",
            where,
            "%s -- exported symbols include %s" % (meaning, ", ".join(examples)),
            "read the T1 banner for this library to get its version; symbols "
            "prove presence, banners give the number"))
    for rx, meaning in JNI_MARKERS:
        if any(rx.match(s) for s in syms):
            ev.append(Evidence(
                "T3 structure", "(this .so)", "structural observation",
                "presence", "high", where, meaning, ""))
    if "av_register_all" in syms:
        ev.append(Evidence(
            "T3 symbol family", "FFmpeg", "older than 4.0", "max", "medium",
            where,
            "av_register_all is exported. That function was deprecated in "
            "FFmpeg 4.0 and later removed, so its presence brackets the build",
            "confirm with the FFmpeg version banner and the embedded "
            "configure line, which lists every codec compiled in"))
    return syms, matched


def t4_build_identity(elf, where, ev):
    bid = elf.build_id()
    if bid:
        ev.append(Evidence(
            "T4 build ID", "(this .so)", bid, "exact", "high", where,
            "the .note.gnu.build-id hash identifies this exact build. Two "
            "APKs carrying the same build ID ship byte-identical binaries",
            "download the vendor's published AAR and compare; a match proves "
            "provenance, a mismatch proves the binary is not theirs"))
    else:
        ev.append(Evidence(
            "T4 build ID", "(this .so)", "absent", "presence", "medium", where,
            "no .note.gnu.build-id. Absence is itself a signal: a non-standard "
            "build, or one deliberately stripped of identity",
            ""))
    n_init = elf.has_init_array()
    if n_init:
        ev.append(Evidence(
            "T3 structure", "(this .so)", "%d .init_array entries" % n_init,
            "presence", "high", where,
            "constructors run inside dlopen, BEFORE JNI_OnLoad and before any "
            "Java code. Anti-analysis lives here and never appears in a call "
            "graph rooted at JNI_OnLoad",
            "see labs/lab-04-constructor-hook.md"))
    needs = elf.needed()
    if needs:
        ev.append(Evidence(
            "T3 structure", "(this .so)", ", ".join(needs), "presence",
            "high", where,
            "DT_NEEDED list. A .so that needs libssl.so or libsqlite.so uses "
            "the platform's copy; one that needs neither but exports SSL_* "
            "symbols has its own, statically linked",
            ""))
    for c in elf.comment()[:3]:
        ev.append(Evidence(
            "T4 .comment", "toolchain", printable(c).strip(), "max", "medium",
            where, "compiler identification string left in .comment", ""))


def apply_db_rules(db, classes, ev, where):
    """Rules from the signal database.

    Two kinds:
      class_prefix     classes exist directly under this package
      class_relocated  the package appears as an inner SEGMENT of some other
                       package -- the signature of a shaded (relocated) copy,
                       which a prefix search alone would never find
    """
    for lib in db.get("libraries", []):
        name = lib.get("name", lib.get("id", "?"))
        for rule in lib.get("rules", []):
            kind = rule.get("kind")
            value = rule.get("value", "")
            if kind == "class_prefix":
                hits = [c for c in classes if c.startswith(value)]
                detail = "%d classes under %s. %s" % (
                    len(hits), value, rule.get("source", ""))
            elif kind == "class_relocated":
                seg = "/" + value.strip("/") + "/"
                hits = [c for c in classes
                        if seg in c and not c.startswith(value.strip("/") + "/")]
                if hits:
                    detail = ("%d classes carry '%s' as an inner package "
                              "segment, e.g. %s. That is SHADING: a build "
                              "relocated the library under another vendor's "
                              "namespace. It is still that library, it is "
                              "still that version's bugs, and no prefix "
                              "search for the original package would have "
                              "found it. %s" %
                              (len(hits), value, sorted(hits)[0].replace("/", "."),
                               rule.get("source", "")))
            else:
                continue
            if not hits:
                continue
            ev.append(Evidence(
                "T2 class prefix" if kind == "class_prefix" else "T2 shading",
                name, rule.get("implies", "present"),
                rule.get("bound", "presence"),
                rule.get("confidence", "medium"), where, detail,
                rule.get("raises", "")))


# ---------------------------------------------------------------------------
# Reference comparison (T2, the scored form)
# ---------------------------------------------------------------------------

VERSION_IN_FILENAME = re.compile(r"-(\d[\w.\-]*?)(?:-sources)?\.(?:jar|aar)$")


def ref_classes(path, prefix_slashed):
    names = set()
    try:
        with zipfile.ZipFile(path) as z:
            for entry in z.namelist():
                if entry.endswith(".class"):
                    name = entry[:-len(".class")]
                    if not prefix_slashed or name.startswith(prefix_slashed):
                        names.add(name)
                elif entry == "classes.jar":
                    import io
                    with zipfile.ZipFile(io.BytesIO(z.read(entry))) as inner:
                        for e2 in inner.namelist():
                            if not e2.endswith(".class"):
                                continue
                            n2 = e2[:-len(".class")]
                            if not prefix_slashed or n2.startswith(prefix_slashed):
                                names.add(n2)
    except (zipfile.BadZipFile, OSError):
        return set()
    return names


def compare_refs(apk_classes, refdir, prefix, out):
    prefix_slashed = prefix.replace(".", "/") if prefix else ""
    target = {c for c in apk_classes if c.startswith(prefix_slashed)}
    out.append("")
    out.append("=== T2  CLASS-SET COMPARISON AGAINST REFERENCE RELEASES ===")
    if not target:
        out.append("  The APK defines NO classes under '%s'." % prefix)
        out.append("  Three explanations, in order of likelihood:")
        out.append("    1. the library is genuinely absent;")
        out.append("    2. it was SHADED -- relocated under another package "
                   "name by the SDK that embeds it (see faq.md);")
        out.append("    3. R8 inlined or renamed it, which happens to small "
                   "libraries with no keep rules.")
        out.append("  Search the full class list for a distinctive class NAME "
                   "instead of the package: --list-classes | grep -i <name>")
        return
    files = sorted(f for f in os.listdir(refdir)
                   if f.lower().endswith((".jar", ".aar")))
    if not files:
        out.append("  %s contains no .jar or .aar files. Download candidate "
                   "releases from Maven first; the header of this script "
                   "shows the curl line." % refdir)
        return
    out.append("  APK defines %d classes under %s" % (len(target), prefix))
    out.append("")
    rows = []
    for fn in files:
        ref = ref_classes(os.path.join(refdir, fn), prefix_slashed)
        if not ref:
            continue
        inter = target & ref
        union = target | ref
        jaccard = len(inter) / float(len(union)) if union else 0.0
        containment = len(inter) / float(len(target))
        m = VERSION_IN_FILENAME.search(fn)
        rows.append({"file": fn, "version": m.group(1) if m else "?",
                     "ref_n": len(ref), "jaccard": jaccard,
                     "containment": containment,
                     "in_apk_not_ref": len(target - ref),
                     "in_ref_not_apk": len(ref - target),
                     "missing_examples": sorted(target - ref)[:5]})
    if not rows:
        out.append("  No reference archive contained classes under that "
                   "prefix. Check the prefix spelling and the artifact.")
        return
    rows.sort(key=lambda r: (-r["containment"], -r["jaccard"], r["ref_n"]))
    out.append("  %-38s %8s %8s %7s %7s" %
               ("reference", "contain", "jaccard", "-in-ref", "ref#"))
    out.append("  " + "-" * 72)
    for r in rows[:15]:
        out.append("  %-38s %8.3f %8.3f %7d %7d" %
                   (r["file"][:38], r["containment"], r["jaccard"],
                    r["in_apk_not_ref"], r["ref_n"]))
    out.append("")
    complete = [r for r in rows if r["containment"] >= 0.999]
    out.append("  HOW TO READ THIS -- and it is not 'take the top row'.")
    out.append("")
    out.append("  R8 deletes library classes the app never calls, so the APK's")
    out.append("  class set is a SUBSET of the real release. Jaccard therefore")
    out.append("  under-reports for every correct answer, and the column that")
    out.append("  matters is CONTAIN: the fraction of the APK's classes that")
    out.append("  the reference has. The version you want is the SMALLEST")
    out.append("  reference that contains ALL of them.")
    out.append("")
    if complete:
        smallest = min(complete, key=lambda r: r["ref_n"])
        out.append("  %d reference(s) contain every class the APK defines." %
                   len(complete))
        out.append("  Smallest such reference: %s  (version %s, %d classes)" %
                   (smallest["file"], smallest["version"], smallest["ref_n"]))
        out.append("  Defensible statement:")
        out.append("    \"%s is present. Its class set is fully contained in "
                   "release %s and in no smaller release tested; %d of the "
                   "APK's %d classes under %s matched.\"" %
                   (prefix, smallest["version"],
                    len(target) - smallest["in_apk_not_ref"], len(target),
                    prefix))
        if len(complete) > 1:
            out.append("  Several releases contain the set, so this is a "
                       "RANGE, not a point. Report the range, or add a")
            out.append("  discriminating class: find one that exists in only "
                       "part of the range and check for it directly.")
    else:
        best = rows[0]
        out.append("  NO reference contains every class the APK defines.")
        out.append("  Classes present in the APK but in no reference (sample):")
        for c in best["missing_examples"]:
            out.append("      %s" % c)
        out.append("  That means one of:")
        out.append("    - the APK is NEWER than every reference you "
                   "downloaded (get more);")
        out.append("    - the library is SHADED together with something else;")
        out.append("    - it is not that library at all, and the package name "
                   "is a lie. That case is lab 05.")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def conclusions(evidence, out):
    by_lib = defaultdict(list)
    for e in evidence:
        if e.library in ("(this .so)", "toolchain"):
            continue
        by_lib[e.library].append(e)

    out.append("")
    out.append("=== CONCLUSIONS ===")
    if not by_lib:
        out.append("  Nothing identified. That is a result, not a failure: see")
        out.append("  'SIGNALS NOT AVAILABLE' below for what could not be read.")
        return
    conflicts = []
    for lib in sorted(by_lib):
        items = by_lib[lib]
        exacts = sorted({e.claim for e in items if e.bound == "exact"})
        techs = sorted({e.technique for e in items})
        out.append("")
        out.append("  %s" % lib)
        # Only signals that CONSTRAIN the version corroborate the number.
        # A "presence" observation confirms the library is there; it says
        # nothing about which release, and counting it as corroboration would
        # be exactly the inflation this script exists to argue against.
        constraining = sorted({e.technique for e in items
                               if e.bound in ("exact", "min", "max")})
        presence_only = sorted({e.technique for e in items
                                if e.bound == "presence"} - set(constraining))
        if len(exacts) == 1:
            out.append("    version : %s" % exacts[0])
            out.append("    constrains the version : %s" %
                       (", ".join(constraining) or "(none)"))
            if presence_only:
                out.append("    confirms presence only : %s" %
                           ", ".join(presence_only))
            out.append("    confidence: %s" % (
                "high -- the version is constrained by more than one "
                "independent technique" if len(constraining) > 1 else
                "medium -- ONE technique constrains the version. A single "
                "signal is a lead, not an answer. Corroborate before you put "
                "a number in a report"))
        elif len(exacts) > 1:
            conflicts.append((lib, exacts))
            out.append("    version : CONFLICT -- %s" % ", ".join(exacts))
            out.append("    signals : %s" % ", ".join(techs))
        else:
            out.append("    version : not constrained by any signal here")
            out.append("    present : yes, on %s" % ", ".join(techs))
            out.append("    next    : download candidate releases and run "
                       "--prefix/--refs, or read the runtime signals in "
                       "README section 3.7 technique 6")
    if conflicts:
        out.append("")
        out.append("  *** CONFLICTING VERSION EVIDENCE ***")
        for lib, vals in conflicts:
            out.append("  %s: %s" % (lib, " vs ".join(vals)))
        out.append("")
        out.append("  Do not average these and do not pick the higher one.")
        out.append("  A disagreement usually means one of:")
        out.append("    - TWO COPIES are bundled, one of them shaded, and each")
        out.append("      is reporting itself honestly;")
        out.append("    - a stamp or banner is stale, because the build")
        out.append("      pipeline copied it forward;")
        out.append("    - a string was edited to mislead you.")
        out.append("  Each of those is worth more in a report than the version")
        out.append("  number you were originally after.")


def report(target, evidence, notes, out, examined):
    out.append("=" * 78)
    out.append("lib-fingerprint  --  %s" % target.path)
    out.append("=" * 78)
    out.append("")
    out.append("=== WHAT WAS EXAMINED ===")
    for line in examined:
        out.append("  %s" % line)
    out.append("")
    out.append("=== EVIDENCE ===")
    if not evidence:
        out.append("  (none)")
    else:
        ordered = sorted(evidence,
                         key=lambda e: (-CONF_ORDER.get(e.confidence, 0),
                                        e.technique, e.library))
        for e in ordered:
            out.append("")
            out.append("  [%s] %s" % (e.confidence.upper(), e.technique))
            out.append("    library : %s" % e.library)
            out.append("    claim   : %s   (%s)" % (e.claim, e.bound))
            out.append("    seen in : %s" % e.where)
            out.append("    why     : %s" % e.why)
            if e.raises:
                out.append("    raise it: %s" % e.raises)
    out.append("")
    out.append("=== SIGNALS NOT AVAILABLE, AND WHY ===")
    for n in notes:
        out.append("  - %s" % n)
    out.append("  - T6 behavioural signals (endpoints, User-Agent, "
               "SharedPreferences keys, thread names, log tags) were NOT")
    out.append("    attempted. They require a running process. This script "
               "reads a file. See labs/lab-03-sdk-audit.md.")
    out.append("  - No vulnerability database was consulted. A version is not "
               "a finding; see faq.md on why an outdated library is not")
    out.append("    automatically one.")
    conclusions(evidence, out)
    out.append("")
    out.append("=== WHAT THIS DOES NOT PROVE ===")
    out.append("  Every signal above is evidence, and evidence is forgeable.")
    out.append("  A version banner is a string constant. A META-INF stamp is a")
    out.append("  text file. A package prefix is a name anyone can choose. If")
    out.append("  the answer matters, corroborate across techniques that would")
    out.append("  have to be forged CONSISTENTLY, and say in the report which")
    out.append("  signals you actually matched.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def collect_classes(target, out_notes):
    """All defined classes across every classes*.dex, with how each was read."""
    classes = set()
    how = []
    for name in target.dex_entries():
        try:
            blob = target.read(name)
        except (KeyError, OSError) as exc:
            out_notes.append("could not read %s (%s)" % (name, exc))
            continue
        try:
            found, method = dex_defined_classes(blob, name)
        except (DexParseError, ValueError, struct.error) as exc:
            out_notes.append("%s: header parse failed (%s); used the byte-scan "
                             "fallback, which is lower quality" % (name, exc))
            try:
                found, method = dex_classes_fallback(blob, name)
            except Exception as exc2:            # noqa: BLE001 - report, do not die
                out_notes.append("%s: fallback also failed (%s)" % (name, exc2))
                continue
        classes |= found
        how.append(method)
    return classes, how


def main():
    ap = argparse.ArgumentParser(
        description="Version-fingerprint the libraries bundled in an APK, and "
                    "show the evidence behind every answer.",
        epilog="A fingerprint is evidence, not proof. Read the header of this "
               "file before you put a version number in a report.")
    ap.add_argument("path", help="an .apk (or any zip), a classes.dex, or a .so")
    ap.add_argument("--prefix", help="package prefix for the class-set "
                                     "comparison, e.g. okhttp3")
    ap.add_argument("--refs", help="directory of reference .jar/.aar releases "
                                   "downloaded from Maven")
    ap.add_argument("--so", help="restrict native analysis to this entry name")
    ap.add_argument("--db", help="signal database JSON (default: "
                                 "../examples/fingerprint-signals.json)")
    ap.add_argument("--list-classes", action="store_true",
                    help="print every class the APK defines, one per line, "
                         "and exit. Used by lib-inventory.sh")
    ap.add_argument("--list-prefixes", type=int, metavar="N",
                    help="print 'count package' collapsed to N components, "
                         "most common first, and exit")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable evidence, for build-to-build diffs")
    args = ap.parse_args()

    try:
        target = Target(args.path)
    except (OSError, ValueError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    evidence = []
    notes = []
    examined = []

    # --- managed side -------------------------------------------------------
    classes = set()
    if target.kind in ("zip", "dex"):
        classes, how = collect_classes(target, notes)
        for h in how:
            examined.append(h)
        if not classes and target.kind == "zip":
            notes.append("no classes*.dex at the archive root. If this is a "
                         "split APK, the code is in base.apk; run "
                         "lib-inventory.sh over every split")

    if args.list_classes:
        for c in sorted(classes):
            print(c.replace("/", "."))
        target.close()
        return 0

    if args.list_prefixes:
        counts = defaultdict(int)
        for c in classes:
            # Drop the class name first, then collapse the PACKAGE to N
            # components. Without the first step a top-level class such as
            # okhttp3/Call would be reported as if "Call" were a package.
            pkg = c.split("/")[:-1] or ["(default package)"]
            counts["/".join(pkg[:args.list_prefixes])] += 1
        for pkg, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            print("%7d %s" % (n, pkg.replace("/", ".")))
        target.close()
        return 0

    db, db_note = load_db(args.db)
    examined.append(db_note)
    if classes:
        apply_db_rules(db, classes, evidence, "classes*.dex")

    # --- T5 -----------------------------------------------------------------
    stamps = t5_version_stamps(target, evidence)
    if target.kind == "zip" and stamps == 0:
        notes.append("no META-INF/*.version stamps. AndroidX and several "
                     "Google artifacts write them; their absence means this "
                     "build strips them, or ships neither")

    # --- T1 on the DEX ------------------------------------------------------
    for name in target.dex_entries():
        try:
            t1_banners(target.read(name), name, evidence)
        except (KeyError, OSError):
            pass

    # --- native side --------------------------------------------------------
    sos = target.so_entries()
    if args.so:
        sos = [s for s in sos if s.endswith(args.so) or s == args.so]
        if not sos:
            notes.append("--so %s matched no entry in this file" % args.so)
    if target.kind == "zip" and not target.so_entries():
        notes.append("no lib/*/*.so entries. Either the app is pure managed "
                     "code, or the native libraries are in a split APK "
                     "(split_config.arm64_v8a.apk and friends)")
    for name in sos:
        try:
            blob = target.read(name)
        except (KeyError, OSError) as exc:
            notes.append("could not read %s (%s)" % (name, exc))
            continue
        try:
            elf = Elf(blob, name)
        except (ValueError, struct.error) as exc:
            notes.append("%s is not a parseable ELF (%s)" % (name, exc))
            continue
        examined.append("ELF %s: %s, %d sections" %
                        (name, elf.arch, len(elf.sections)))
        syms, _ = t3_symbols(elf, name, evidence)
        t4_build_identity(elf, name, evidence)
        t1_banners(blob, name, evidence,
                   sqlite_symbols_present=any(s.startswith("sqlite3_")
                                              for s in syms))
        for n in elf.notes:
            notes.append("%s: %s" % (name, n))

    # --- extra code ---------------------------------------------------------
    if target.kind == "zip":
        extra = [n for n in target.names if EXTRA_CODE.match(n)]
        if extra:
            evidence.append(Evidence(
                "T5 asset scan", "(runtime-loaded code)",
                "%d executable-looking asset(s)" % len(extra), "presence",
                "high", "assets/ and res/raw/",
                "code outside classes.dex and lib/: %s. Each one is a place "
                "to repeat this whole enumeration, and shipping code that is "
                "not in the DEX is a finding in its own right" %
                ", ".join(sorted(extra)[:6]),
                "unpack each and re-run this script on it"))

    if args.refs:
        if not args.prefix:
            sys.stderr.write("error: --refs needs --prefix\n")
            target.close()
            return 2
        if not os.path.isdir(args.refs):
            sys.stderr.write("error: %s is not a directory\n" % args.refs)
            target.close()
            return 2

    out = []
    report(target, evidence, notes, out, examined)
    if args.refs:
        compare_refs(classes, args.refs, args.prefix, out)
    elif args.prefix:
        hits = sorted(c for c in classes
                      if c.startswith(args.prefix.replace(".", "/")))
        out.append("")
        out.append("=== T2  CLASSES UNDER %s ===" % args.prefix)
        out.append("  %d classes. Pass --refs DIR to score them against "
                   "reference releases." % len(hits))
        for c in hits[:40]:
            out.append("    %s" % c.replace("/", "."))
        if len(hits) > 40:
            out.append("    ... and %d more" % (len(hits) - 40))

    if args.json:
        print(json.dumps(OrderedDict([
            ("target", target.path),
            ("examined", examined),
            ("evidence", [e.as_dict() for e in evidence]),
            ("signals_unavailable", notes),
            ("behavioural_signals", "not attempted; requires a running process"),
        ]), indent=2))
    else:
        print("\n".join(out))
    target.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
