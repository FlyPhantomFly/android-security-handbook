#!/usr/bin/env python3
"""
parse_axml.py — decode Android binary XML from the chunk layer up, and report
                every structural inconsistency on the way.

WHAT IT DOES
    Implements the structures documented in ../README.md section 6.3, using only
    the Python standard library:

      - ResChunk_header navigation by headerSize and size, never by a fixed
        offset guess                                              (README 6.3)
      - ResStringPool, both UTF-16 and UTF-8, including the UTF-8
        double-length encoding that tools disagree about          (README 6.3)
      - RES_XML_RESOURCE_MAP_TYPE                                  (README 6.3)
      - namespace, element, attribute and CDATA records            (README 6.3)
      - Res_value, with the full dataType table                    (README 6.3)

    It prints the document as an element tree, and then an ANOMALY REPORT: every
    place where the file is internally inconsistent, or where two reasonable
    implementations would read different things.

    The specification is AOSP's
        frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
    where every constant below is declared as a C++ struct or enum. Read it
    alongside this file.

WHY YOU WANT A PARSER YOU CONTROL
    apktool, jadx, aapt2, MobSF and PackageManager each read AXML with different
    code. When they disagree about a manifest, the disagreement IS the finding -
    but you can only see it if you have a fourth reading you understand. That is
    what this is for. It is deliberately strict and will complain about files
    the platform would happily accept, which is exactly what you want when you
    are hunting for a manifest built to mislead.

    Two divergences it is built to surface:

      rawValue vs typedValue    An attribute carries BOTH the original text
                                (a string-pool reference) and a parsed
                                Res_value. The platform reads typedValue. A
                                tool that displays rawValue for readability
                                shows you something the platform never
                                consulted. This parser prints both and flags
                                any disagreement.

      attributeSize             A START_ELEMENT declares the size of each
                                attribute record. Honour it and you stride
                                correctly; assume the usual 20 bytes and you
                                read the wrong bytes as soon as it is not 20.

WHAT THIS WILL *NOT* TELL YOU
    - What the platform actually parsed. This is a FOURTH opinion, not the
      authority. `adb shell dumpsys package <pkg>` is the authority, because it
      reports what PackageManagerService stored. When this tool and the device
      disagree, the device is right and the divergence is your finding.
    - Attribute semantics. It will tell you android:exported is typed boolean
      true; whether that matters for this component is chapter 32's subject,
      not this one's. See ../../32-Manifest/README.md.
    - Resource values. TYPE_REFERENCE data is a resource ID; resolving it needs
      resources.arsc, which this tool does not read. `aapt2 dump resources`
      does.
    - Whether an anomaly is deliberate. Build tools and obfuscators emit odd
      AXML by accident. Every flag here is a lead for a human.
    - resources.arsc. Same chunk grammar, different chunk types, not covered.

HOW TO RUN
    python3 parse_axml.py AndroidManifest.xml
    python3 parse_axml.py --extract app.apk
    python3 parse_axml.py --extract app.apk --entry res/xml/network_security_config.xml
    python3 parse_axml.py AndroidManifest.xml --chunks
    python3 parse_axml.py AndroidManifest.xml --strings
    python3 parse_axml.py AndroidManifest.xml --anomalies-only
    python3 parse_axml.py AndroidManifest.xml --json

    Run it from the chapter directory exactly as the chapter prints it:
        python3 examples/parse_axml.py --extract app.apk

REQUIREMENTS
    Python 3.8 or newer. Standard library only. Works on Windows, macOS, Linux.

RELATED
    ../README.md section 6.3              the chunk and string-pool layouts
    ../labs/lab-03-write-your-own-axml-parser.md   write your own first
    ../labs/lab-04-ctf-the-lying-manifest.md       then use it on a liar
    ./parse_apk_zip.py                    the container the manifest lives in
    ../../32-Manifest/README.md           what the attributes MEAN

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import struct
import sys
import zlib

# ResChunk_header types - ResourceTypes.h
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_LAST_CHUNK_TYPE = 0x017F
RES_XML_RESOURCE_MAP_TYPE = 0x0180

CHUNK_NAMES = {
    RES_NULL_TYPE: "RES_NULL_TYPE",
    RES_STRING_POOL_TYPE: "RES_STRING_POOL_TYPE",
    RES_TABLE_TYPE: "RES_TABLE_TYPE",
    RES_XML_TYPE: "RES_XML_TYPE",
    RES_XML_START_NAMESPACE_TYPE: "RES_XML_START_NAMESPACE_TYPE",
    RES_XML_END_NAMESPACE_TYPE: "RES_XML_END_NAMESPACE_TYPE",
    RES_XML_START_ELEMENT_TYPE: "RES_XML_START_ELEMENT_TYPE",
    RES_XML_END_ELEMENT_TYPE: "RES_XML_END_ELEMENT_TYPE",
    RES_XML_CDATA_TYPE: "RES_XML_CDATA_TYPE",
    RES_XML_RESOURCE_MAP_TYPE: "RES_XML_RESOURCE_MAP_TYPE",
}

# The headerSize each chunk type should declare. Anything else is navigable
# but worth saying out loud.
EXPECTED_HEADER_SIZE = {
    RES_XML_TYPE: 8,
    RES_STRING_POOL_TYPE: 28,
    RES_XML_RESOURCE_MAP_TYPE: 8,
    RES_XML_START_NAMESPACE_TYPE: 16,
    RES_XML_END_NAMESPACE_TYPE: 16,
    RES_XML_START_ELEMENT_TYPE: 16,
    RES_XML_END_ELEMENT_TYPE: 16,
    RES_XML_CDATA_TYPE: 16,
}

# ResStringPool_header flags
SORTED_FLAG = 0x0001
UTF8_FLAG = 0x0100

# Res_value dataType - ResourceTypes.h
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F

TYPE_NAMES = {
    TYPE_NULL: "TYPE_NULL",
    TYPE_REFERENCE: "TYPE_REFERENCE",
    TYPE_ATTRIBUTE: "TYPE_ATTRIBUTE",
    TYPE_STRING: "TYPE_STRING",
    TYPE_FLOAT: "TYPE_FLOAT",
    TYPE_DIMENSION: "TYPE_DIMENSION",
    TYPE_FRACTION: "TYPE_FRACTION",
    TYPE_DYNAMIC_REFERENCE: "TYPE_DYNAMIC_REFERENCE",
    TYPE_DYNAMIC_ATTRIBUTE: "TYPE_DYNAMIC_ATTRIBUTE",
    TYPE_INT_DEC: "TYPE_INT_DEC",
    TYPE_INT_HEX: "TYPE_INT_HEX",
    TYPE_INT_BOOLEAN: "TYPE_INT_BOOLEAN",
    TYPE_INT_COLOR_ARGB8: "TYPE_INT_COLOR_ARGB8",
    TYPE_INT_COLOR_RGB8: "TYPE_INT_COLOR_RGB8",
    TYPE_INT_COLOR_ARGB4: "TYPE_INT_COLOR_ARGB4",
    TYPE_INT_COLOR_RGB4: "TYPE_INT_COLOR_RGB4",
}

DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]

ATTR_RECORD_SIZE = 20      # ns, name, rawValue, Res_value{size,res0,type,data}

ALERT, WARN, INFO = "ALERT", "WARN", "INFO"
LEVEL_ORDER = {ALERT: 0, WARN: 1, INFO: 2}


class AxmlError(Exception):
    """Raised when the document cannot be walked at all."""


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def i32(d, o):
    return struct.unpack_from("<i", d, o)[0]


# ----------------------------------------------------------------------
# getting the manifest out of an APK, by hand
# ----------------------------------------------------------------------

def extract_from_apk(path, entry_name="AndroidManifest.xml"):
    """Pull one entry out of an APK without the zipfile module, so that the
    same code path works on a container zipfile refuses to open. See
    parse_apk_zip.py for why that matters."""
    with open(path, "rb") as fh:
        data = fh.read()

    eocd = -1
    window = max(0, len(data) - (22 + 0xFFFF))
    pos = data.find(b"PK\x05\x06", window)
    while pos != -1:
        if pos + 22 <= len(data) and pos + 22 + u16(data, pos + 20) == len(data):
            eocd = pos
        pos = data.find(b"PK\x05\x06", pos + 1)
    if eocd < 0:
        eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise AxmlError(f"{path}: no EOCD - not a ZIP")

    cd_off = u32(data, eocd + 16)
    cd_size = u32(data, eocd + 12)
    off, end = cd_off, min(cd_off + cd_size, len(data))
    matches = []
    while off + 46 <= end and data[off:off + 4] == b"PK\x01\x02":
        method = u16(data, off + 10)
        csize = u32(data, off + 20)
        n_len = u16(data, off + 28)
        m_len = u16(data, off + 30)
        k_len = u16(data, off + 32)
        lfh = u32(data, off + 42)
        name = data[off + 46:off + 46 + n_len].decode("utf-8", "replace")
        if name == entry_name:
            matches.append((lfh, method, csize))
        off += 46 + n_len + m_len + k_len

    if not matches:
        raise AxmlError(f"{path}: no entry named {entry_name!r}")
    if len(matches) > 1:
        print(f"warning: {len(matches)} entries named {entry_name!r} - a "
              f"duplicate-name archive. Reading the FIRST; run "
              f"parse_apk_zip.py to see them all.", file=sys.stderr)

    lfh, method, csize = matches[0]
    if data[lfh:lfh + 4] != b"PK\x03\x04":
        raise AxmlError(f"{path}: no local file header at 0x{lfh:x}")
    n_len = u16(data, lfh + 26)
    m_len = u16(data, lfh + 28)
    start = lfh + 30 + n_len + m_len
    payload = data[start:start + csize]
    if method == 0:
        return payload
    if method == 8:
        return zlib.decompressobj(-15).decompress(payload)
    raise AxmlError(f"{path}: entry uses compression method {method}, "
                    "which the platform installer rejects")


# ----------------------------------------------------------------------
# the string pool
# ----------------------------------------------------------------------

class StringPool:

    def __init__(self, data, start, header_size, chunk_size, report):
        self.report = report
        self.strings = []
        self.flags = 0
        self.utf8 = False
        self.count = 0
        self.style_count = 0

        if start + 28 > len(data):
            raise AxmlError("string pool header runs past the end of the file")

        self.count = u32(data, start + 8)
        self.style_count = u32(data, start + 12)
        self.flags = u32(data, start + 16)
        self.strings_start = u32(data, start + 20)
        self.styles_start = u32(data, start + 24)
        self.utf8 = bool(self.flags & UTF8_FLAG)

        # The offset array begins immediately after the header. Navigate by the
        # DECLARED headerSize, exactly as ResStringPool::setTo does - not by a
        # hardcoded 28.
        offsets_at = start + header_size
        needed = offsets_at + 4 * (self.count + self.style_count)
        if needed > start + chunk_size:
            report(ALERT, "pool-offsets-overrun",
                   f"the string pool declares {self.count} strings and "
                   f"{self.style_count} styles, whose offset arrays need "
                   f"{needed - start} bytes, but the chunk is {chunk_size}",
                   "The count is forged or the chunk is truncated. A parser "
                   "that trusts the count reads past the chunk; one that "
                   "bounds by size reads fewer strings. That is a divergence.")
            self.count = max(0, (start + chunk_size - offsets_at) // 4)

        data_base = start + self.strings_start
        if self.strings_start < header_size + 4 * self.count:
            report(WARN, "pool-strings-start",
                   f"stringsStart ({self.strings_start}) points inside or "
                   f"before the offset array (which ends at "
                   f"{header_size + 4 * self.count})",
                   "String data and offset data overlap. Decode by hand and "
                   "check what each of your tools makes of it.")

        for i in range(self.count):
            try:
                rel = u32(data, offsets_at + 4 * i)
            except struct.error:
                report(ALERT, "pool-offset-truncated",
                       f"string offset #{i} runs past the end of the file",
                       "Stop and read the chunk by hand with xxd.")
                break
            pos = data_base + rel
            if pos >= len(data) or pos >= start + chunk_size:
                report(ALERT, "pool-offset-out-of-range",
                       f"string #{i} has offset {rel}, which lands at "
                       f"0x{pos:x}, outside the pool chunk",
                       "An out-of-range offset is a crash primitive in a naive "
                       "parser and a divergence primitive in a careful one.")
                self.strings.append(None)
                continue
            try:
                self.strings.append(
                    self._read_utf8(data, pos, i) if self.utf8
                    else self._read_utf16(data, pos, i))
            except Exception as exc:                # noqa: BLE001
                report(ALERT, "pool-string-undecodable",
                       f"string #{i} at 0x{pos:x} would not decode: {exc}",
                       "Read the bytes: xxd -s <offset> -l 32 on the file.")
                self.strings.append(None)

    def _read_utf16(self, data, pos, index):
        """UTF-16: a 16-bit character count, high bit meaning 'the length is
        31 bits spread over two 16-bit values', then UTF-16 code units and a
        0x0000 terminator."""
        n = u16(data, pos)
        pos += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | u16(data, pos)
            pos += 2
        raw = data[pos:pos + n * 2]
        if len(raw) < n * 2:
            self.report(ALERT, "pool-utf16-truncated",
                        f"string #{index} declares {n} UTF-16 units but only "
                        f"{len(raw) // 2} are present",
                        "Truncated or forged length. Compare against "
                        "`aapt2 dump chunks`.")
        term = data[pos + n * 2:pos + n * 2 + 2]
        if term != b"\x00\x00":
            self.report(WARN, "pool-utf16-terminator",
                        f"string #{index} is not followed by a 0x0000 "
                        f"terminator (found {term.hex(' ')})",
                        "Parsers that read to the terminator rather than by "
                        "the declared length will read a longer string here.")
        return raw.decode("utf-16-le", "replace")

    def _read_utf8(self, data, pos, index):
        """UTF-8: TWO length values - the character count, then the byte count.
        Each is one byte, or two when the high bit of the first is set. Then
        the bytes, then a 0x00 terminator.

        The character count and the byte count are independent fields, and
        nothing forces them to agree. That is the single most reliable way to
        build a string pool that different tools read differently, which is why
        the mismatch below is an ALERT rather than a note."""
        char_len, pos = self._u8len(data, pos)
        byte_len, pos = self._u8len(data, pos)
        raw = data[pos:pos + byte_len]
        if len(raw) < byte_len:
            self.report(ALERT, "pool-utf8-truncated",
                        f"string #{index} declares {byte_len} bytes but only "
                        f"{len(raw)} are present",
                        "Truncated or forged. Read the pool by hand.")
        decoded = raw.decode("utf-8", "replace")
        if len(decoded) != char_len:
            self.report(
                ALERT, "pool-utf8-length-mismatch",
                f"string #{index} declares {char_len} characters and "
                f"{byte_len} bytes, but those bytes decode to "
                f"{len(decoded)} characters ({decoded!r})",
                "A parser that trusts the character count and one that trusts "
                "the byte count now hold different strings. This is a "
                "deliberate-looking construction; see README section 6.3.")
        term = data[pos + byte_len:pos + byte_len + 1]
        if term != b"\x00":
            self.report(WARN, "pool-utf8-terminator",
                        f"string #{index} is not followed by a 0x00 terminator "
                        f"(found {term.hex()})",
                        "A NUL-terminated reader will run into the next "
                        "string.")
        return decoded

    @staticmethod
    def _u8len(data, pos):
        n = data[pos]
        pos += 1
        if n & 0x80:
            n = ((n & 0x7F) << 8) | data[pos]
            pos += 1
        return n, pos

    def get(self, index):
        if index is None or index < 0:
            return None
        if index >= len(self.strings):
            return f"<out-of-range string #{index}>"
        return self.strings[index]


# ----------------------------------------------------------------------
# Res_value rendering
# ----------------------------------------------------------------------

def complex_to_float(data):
    mantissa = data & 0xFFFFFF00
    radix = (data >> 4) & 0x3
    shift = [23, 16, 8, 0][radix]
    return (mantissa * (1.0 / (1 << 8)) / (1 << shift))


def render_value(dtype, value, pool):
    if dtype == TYPE_NULL:
        return "@null" if value == 0 else "@empty"
    if dtype == TYPE_REFERENCE:
        return f"@0x{value:08x}"
    if dtype == TYPE_DYNAMIC_REFERENCE:
        return f"@dyn/0x{value:08x}"
    if dtype == TYPE_ATTRIBUTE:
        return f"?0x{value:08x}"
    if dtype == TYPE_DYNAMIC_ATTRIBUTE:
        return f"?dyn/0x{value:08x}"
    if dtype == TYPE_STRING:
        return repr(pool.get(value))
    if dtype == TYPE_FLOAT:
        return repr(struct.unpack("<f", struct.pack("<I", value))[0])
    if dtype == TYPE_DIMENSION:
        unit = DIMENSION_UNITS[value & 0xF] if (value & 0xF) < 6 else "?"
        return f"{complex_to_float(value):g}{unit}"
    if dtype == TYPE_FRACTION:
        unit = FRACTION_UNITS[value & 0xF] if (value & 0xF) < 2 else "?"
        return f"{complex_to_float(value) * 100:g}{unit}"
    if dtype == TYPE_INT_DEC:
        return str(value if value < 0x80000000 else value - (1 << 32))
    if dtype == TYPE_INT_HEX:
        return f"0x{value:x}"
    if dtype == TYPE_INT_BOOLEAN:
        # ResourceTypes.h: any non-zero value is true. aapt2 emits 0xffffffff.
        return "true" if value != 0 else "false"
    if TYPE_INT_COLOR_ARGB8 <= dtype <= TYPE_INT_COLOR_RGB4:
        return f"#{value:08x}"
    return f"0x{value:08x}"


# ----------------------------------------------------------------------
# the document
# ----------------------------------------------------------------------

class Axml:

    def __init__(self, data, path="<memory>"):
        self.data = data
        self.path = path
        self.findings = []
        self.chunks = []
        self.events = []
        self.pool = None
        self.resource_map = []
        self.namespaces = {}      # uri string index -> prefix string

        self._parse()

    # ------------------------------------------------------------------

    def report(self, level, code, message, next_step):
        self.findings.append({"level": level, "code": code,
                              "message": message, "next_step": next_step})

    def flagged(self):
        return [f for f in self.findings if f["level"] in (ALERT, WARN)]

    def string(self, index):
        if self.pool is None:
            return f"<no string pool: #{index}>"
        return self.pool.get(index)

    # ------------------------------------------------------------------

    def _parse(self):
        d = self.data
        if len(d) < 8:
            raise AxmlError(f"file is {len(d)} bytes; a chunk header is 8")

        ctype, header_size, size = struct.unpack_from("<HHI", d, 0)
        if ctype != RES_XML_TYPE:
            hint = ""
            if ctype == RES_TABLE_TYPE:
                hint = (" This looks like resources.arsc, not a binary XML "
                        "document. Use `aapt2 dump resources` for that.")
            elif d[:5] == b"<?xml" or d[:1] == b"<":
                hint = (" This is TEXT XML, already decoded - read it with a "
                        "text editor.")
            raise AxmlError(
                f"root chunk type is 0x{ctype:04x} "
                f"({CHUNK_NAMES.get(ctype, 'unknown')}), expected 0x0003 "
                f"RES_XML_TYPE.{hint}")

        self.root_size = size
        if size != len(d):
            level = ALERT if size > len(d) else WARN
            self.report(
                level, "root-size-mismatch",
                f"the root chunk declares size {size} but the file is "
                f"{len(d)} bytes ({len(d) - size:+d})",
                "A parser bounded by the root chunk's size stops at "
                f"0x{size:x}; one bounded by the file reads {len(d) - size} "
                "bytes more. Anything in that gap is seen by one and not the "
                "other. Dump it: xxd -s " + str(size) + " on the file.")

        if header_size != 8:
            self.report(
                WARN, "root-header-size",
                f"the root chunk declares headerSize {header_size}, not 8",
                "Chunk walking starts at chunkStart + headerSize. A parser "
                "that hardcodes 8 begins reading the child chunks at a "
                "different byte than one that honours the field.")

        limit = min(size, len(d)) if size <= len(d) else len(d)
        self._walk(header_size, limit, depth=0)
        self._check_balance()

        if limit < len(d):
            tail = d[limit:limit + 8]
            self.report(
                WARN, "trailing-chunks",
                f"{len(d) - limit} bytes follow the root chunk "
                f"(starting {tail.hex(' ')})",
                "Read them as chunks: if the first two bytes are a valid "
                "chunk type, someone appended a record that a "
                "root-size-bounded parser will never see.")

    def _walk(self, off, limit, depth):
        d = self.data
        while off + 8 <= limit:
            ctype, header_size, size = struct.unpack_from("<HHI", d, off)
            name = CHUNK_NAMES.get(ctype, f"UNKNOWN_0x{ctype:04x}")

            if size == 0:
                self.report(
                    ALERT, "chunk-zero-size",
                    f"{name} at 0x{off:x} declares size 0",
                    "A zero-size chunk is an infinite loop in a naive parser "
                    "and a stop condition in a careful one. The walk stops "
                    "here.")
                return
            if off + size > limit:
                self.report(
                    ALERT, "chunk-overruns",
                    f"{name} at 0x{off:x} declares size {size}, which runs "
                    f"past the end of its parent (0x{limit:x})",
                    "Either the size is forged or the document is truncated. "
                    "Compare with `aapt2 dump chunks`.")
                return
            if header_size < 8 or header_size > size:
                self.report(
                    ALERT, "chunk-header-size",
                    f"{name} at 0x{off:x} declares headerSize {header_size} "
                    f"with size {size} - impossible",
                    "headerSize must be at least 8 and no larger than size. "
                    "This is the classic AXML confusion primitive: a lenient "
                    "parser skips fields, a strict one refuses.")

            expected = EXPECTED_HEADER_SIZE.get(ctype)
            if expected is not None and header_size != expected:
                self.report(
                    ALERT, "chunk-header-size-unexpected",
                    f"{name} at 0x{off:x} declares headerSize {header_size}, "
                    f"but this chunk type's header is {expected} bytes",
                    "Payload parsing begins at chunkStart + headerSize. An "
                    "inflated value makes a parser skip the first fields of "
                    "the payload and read the rest at the wrong offsets, "
                    "which is how one tool is made to see a different "
                    "document from another. Diff against a clean build with "
                    "`aapt2 dump chunks`.")

            self.chunks.append({"offset": off, "type": ctype, "name": name,
                                "header_size": header_size, "size": size,
                                "depth": depth})

            if ctype == RES_STRING_POOL_TYPE:
                if self.pool is not None:
                    self.report(
                        ALERT, "pool-duplicate",
                        f"a second string pool at 0x{off:x}",
                        "A document has one pool. Which one a parser uses - "
                        "first or last - decides every string in the file.")
                else:
                    self.pool = StringPool(d, off, header_size, size,
                                           self.report)
            elif ctype == RES_XML_RESOURCE_MAP_TYPE:
                count = (size - header_size) // 4
                self.resource_map = [
                    u32(d, off + header_size + 4 * i) for i in range(count)]
            elif ctype == RES_XML_START_NAMESPACE_TYPE:
                self._namespace(off, header_size, start=True)
            elif ctype == RES_XML_END_NAMESPACE_TYPE:
                self._namespace(off, header_size, start=False)
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                self._start_element(off, header_size, size)
            elif ctype == RES_XML_END_ELEMENT_TYPE:
                self._end_element(off, header_size)
            elif ctype == RES_XML_CDATA_TYPE:
                self._cdata(off, header_size)
            elif ctype not in CHUNK_NAMES:
                self.report(
                    WARN, "chunk-unknown-type",
                    f"unknown chunk type 0x{ctype:04x} at 0x{off:x} "
                    f"({size} bytes)",
                    "Unknown chunks are skipped by size. That makes them a "
                    "container for data the document does not otherwise "
                    "describe. Dump the bytes and look.")

            off += size

        if off != limit:
            self.report(
                WARN, "chunk-walk-remainder",
                f"{limit - off} bytes left over after the chunk walk at "
                f"0x{off:x}",
                "The chunks do not tile their parent exactly. Look at the "
                "remainder.")

    # ------------------------------------------------------------------

    def _namespace(self, off, header_size, start):
        d = self.data
        base = off + header_size
        prefix_idx = i32(d, base)
        uri_idx = i32(d, base + 4)
        prefix = self.string(prefix_idx)
        uri = self.string(uri_idx)
        if start:
            self.namespaces[uri] = prefix
        self.events.append({
            "kind": "startNamespace" if start else "endNamespace",
            "offset": off, "prefix": prefix, "uri": uri})

    def _start_element(self, off, header_size, size):
        d = self.data
        base = off + header_size
        ns_idx = i32(d, base)
        name_idx = i32(d, base + 4)
        attr_start = u16(d, base + 8)
        attr_size = u16(d, base + 10)
        attr_count = u16(d, base + 12)
        id_index = u16(d, base + 14)
        class_index = u16(d, base + 16)
        style_index = u16(d, base + 18)

        name = self.string(name_idx)

        if attr_size != ATTR_RECORD_SIZE:
            self.report(
                ALERT, "attribute-size",
                f"<{name}> at 0x{off:x} declares attributeSize {attr_size}, "
                f"not {ATTR_RECORD_SIZE}",
                "Attribute records are addressed as attributeStart + "
                "index * attributeSize. A parser that honours the declared "
                "stride and one that assumes 20 read DIFFERENT BYTES as the "
                "attribute list from index 1 onwards. Decode both ways and "
                "compare; the platform honours the field.")

        if attr_start != 20:
            self.report(
                WARN, "attribute-start",
                f"<{name}> at 0x{off:x} declares attributeStart {attr_start}, "
                f"not the usual 20",
                "attributeStart is measured from the end of the chunk header. "
                "An unusual value moves the whole attribute list.")

        attrs = []
        for i in range(attr_count):
            rec = base + attr_start + i * attr_size
            if rec + ATTR_RECORD_SIZE > off + size:
                self.report(
                    ALERT, "attribute-overruns",
                    f"<{name}> attribute #{i} at 0x{rec:x} runs past the end "
                    f"of its chunk (0x{off + size:x})",
                    "attributeCount and the chunk size disagree. A parser "
                    "that trusts the count reads into the next chunk.")
                break
            attrs.append(self._attribute(rec, name, i))

        seen = {}
        for a in attrs:
            key = (a["ns"], a["name"])
            if key in seen:
                self.report(
                    ALERT, "attribute-duplicate",
                    f"<{name}> declares {a['qname']} more than once",
                    "The platform keeps one of them; which one is an "
                    "implementation detail. Two tools can easily disagree. "
                    "Confirm the effective value with `dumpsys package`.")
            seen[key] = a

        self.events.append({
            "kind": "startElement", "offset": off,
            "ns": self.string(ns_idx) if ns_idx >= 0 else None,
            "name": name, "attributes": attrs,
            "attribute_size": attr_size, "attribute_start": attr_start,
            "id_index": id_index, "class_index": class_index,
            "style_index": style_index})

    def _attribute(self, rec, element, index):
        d = self.data
        ns_idx = i32(d, rec)
        name_idx = i32(d, rec + 4)
        raw_idx = i32(d, rec + 8)
        val_size = u16(d, rec + 12)
        res0 = d[rec + 14]
        dtype = d[rec + 15]
        data = u32(d, rec + 16)

        ns_uri = self.string(ns_idx) if ns_idx >= 0 else None
        name = self.string(name_idx)
        prefix = self.namespaces.get(ns_uri) if ns_uri else None
        qname = f"{prefix}:{name}" if prefix else str(name)

        raw = self.string(raw_idx) if raw_idx >= 0 else None
        typed = render_value(dtype, data, self.pool) if self.pool else str(data)

        if val_size != 8:
            self.report(
                ALERT, "res-value-size",
                f"<{element}> {qname}: Res_value.size is {val_size}, not 8",
                "Res_value is 8 bytes by definition. A parser that strides by "
                "the declared size lands somewhere else on the next read.")
        if res0 != 0:
            self.report(
                WARN, "res-value-res0",
                f"<{element}> {qname}: Res_value.res0 is 0x{res0:02x}, not 0",
                "A reserved field with a value in it is either a new platform "
                "feature or someone signalling to their own loader.")
        if dtype not in TYPE_NAMES:
            self.report(
                WARN, "res-value-type",
                f"<{element}> {qname}: unknown dataType 0x{dtype:02x}",
                "Look it up in ResourceTypes.h. An unrecognised type is "
                "rendered differently by every tool.")

        # THE divergence: rawValue text against the typed value the platform
        # actually consults.
        if raw is not None and dtype != TYPE_STRING:
            if str(raw).strip().lower() != str(typed).strip().lower():
                self.report(
                    ALERT, "raw-vs-typed",
                    f"<{element}> {qname}: rawValue is {raw!r} but typedValue "
                    f"is {typed} ({TYPE_NAMES.get(dtype, hex(dtype))}, "
                    f"data=0x{data:08x})",
                    "The platform reads typedValue. Any tool that renders "
                    "rawValue for readability is showing you a value the "
                    "platform never consulted. Confirm on a device with "
                    "`adb shell dumpsys package <pkg>`; see "
                    "../labs/lab-04-ctf-the-lying-manifest.md.")

        return {"ns": ns_uri, "name": name, "qname": qname, "raw": raw,
                "raw_index": raw_idx, "type": dtype,
                "type_name": TYPE_NAMES.get(dtype, f"0x{dtype:02x}"),
                "data": data, "typed": typed, "offset": rec}

    def _end_element(self, off, header_size):
        d = self.data
        base = off + header_size
        ns_idx = i32(d, base)
        name_idx = i32(d, base + 4)
        self.events.append({
            "kind": "endElement", "offset": off,
            "ns": self.string(ns_idx) if ns_idx >= 0 else None,
            "name": self.string(name_idx)})

    def _cdata(self, off, header_size):
        d = self.data
        base = off + header_size
        data_idx = i32(d, base)
        self.events.append({
            "kind": "cdata", "offset": off,
            "text": self.string(data_idx)})

    def _check_balance(self):
        stack = []
        for ev in self.events:
            if ev["kind"] == "startElement":
                stack.append(ev["name"])
            elif ev["kind"] == "endElement":
                if not stack:
                    self.report(
                        ALERT, "unbalanced-close",
                        f"</{ev['name']}> at 0x{ev['offset']:x} closes an "
                        "element that was never opened",
                        "The event stream is not a tree. Tools that build a "
                        "DOM will either throw or silently reparent; either "
                        "way they no longer agree with a streaming parser.")
                elif stack[-1] != ev["name"]:
                    self.report(
                        ALERT, "mismatched-close",
                        f"</{ev['name']}> at 0x{ev['offset']:x} closes "
                        f"<{stack[-1]}>",
                        "Mismatched nesting. See above - the disagreement "
                        "between a DOM builder and a streaming reader is the "
                        "point of the construction.")
                    stack.pop()
                else:
                    stack.pop()
        if stack:
            self.report(
                ALERT, "unclosed-elements",
                f"{len(stack)} element(s) never closed: {stack}",
                "A truncated or deliberately unterminated document. Some "
                "parsers accept it and keep whatever they have.")

    # ------------------------------------------------------------------

    def to_xml(self):
        out = []
        depth = 0
        for ev in self.events:
            if ev["kind"] == "startElement":
                pad = "  " * depth
                if not ev["attributes"]:
                    out.append(f"{pad}<{ev['name']}>")
                else:
                    out.append(f"{pad}<{ev['name']}")
                    for a in ev["attributes"]:
                        note = ""
                        if a["raw"] is not None and a["type"] != TYPE_STRING:
                            note = f"   <-- rawValue={a['raw']!r}"
                        out.append(
                            f"{pad}    {a['qname']}={a['typed']}"
                            f"   ({a['type_name']}, data=0x{a['data']:08x})"
                            f"{note}")
                    out.append(f"{pad}>")
                depth += 1
            elif ev["kind"] == "endElement":
                depth = max(0, depth - 1)
                out.append(f"{'  ' * depth}</{ev['name']}>")
            elif ev["kind"] == "cdata":
                out.append(f"{'  ' * depth}{ev['text']!r}")
            elif ev["kind"] == "startNamespace":
                out.append(f"xmlns:{ev['prefix']}=\"{ev['uri']}\"")
        return out

    def summary(self):
        return {
            "path": self.path,
            "size": len(self.data),
            "root_size": self.root_size,
            "string_pool": {
                "count": self.pool.count if self.pool else 0,
                "encoding": ("UTF-8" if self.pool and self.pool.utf8
                             else "UTF-16"),
                "flags": self.pool.flags if self.pool else None,
            },
            "resource_map_entries": len(self.resource_map),
            "chunks": self.chunks,
            "elements": [
                {"name": ev["name"],
                 "attributes": [
                     {k: v for k, v in a.items() if k != "offset"}
                     for a in ev["attributes"]]}
                for ev in self.events if ev["kind"] == "startElement"],
            "findings": self.findings,
        }


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def print_report(doc, args):
    print(f"\n=== {doc.path} ({len(doc.data):,} bytes) ===\n")

    if not args.anomalies_only:
        print("-- document --")
        print(f"  {'root chunk size':<22} {doc.root_size}")
        if doc.pool:
            print(f"  {'string pool':<22} {doc.pool.count} strings, "
                  f"{'UTF-8' if doc.pool.utf8 else 'UTF-16'}, "
                  f"flags=0x{doc.pool.flags:x}")
        else:
            print(f"  {'string pool':<22} MISSING")
        print(f"  {'resource map':<22} {len(doc.resource_map)} entries")
        print(f"  {'chunks':<22} {len(doc.chunks)}")
        print(f"  {'elements':<22} "
              f"{sum(1 for e in doc.events if e['kind'] == 'startElement')}")

        if args.chunks:
            print("\n-- chunk map --")
            for c in doc.chunks:
                print(f"  0x{c['offset']:08x}  {c['name']:<32} "
                      f"headerSize={c['header_size']:<5} size={c['size']}")

        if args.strings and doc.pool:
            print(f"\n-- string pool ({doc.pool.count}) --")
            for i, s in enumerate(doc.pool.strings):
                print(f"  [{i:>4}] {s!r}")

        print("\n-- document tree --")
        for line in doc.to_xml():
            print(f"  {line}")

    print(f"\n-- anomaly report ({len(doc.findings)}) --")
    if not doc.findings:
        print("  none - every chunk, every offset and every length is "
              "self-consistent,")
        print("  and no attribute's rawValue contradicts its typedValue.")
    else:
        for f in sorted(doc.findings, key=lambda x: LEVEL_ORDER[x["level"]]):
            marker = {"ALERT": "!!", "WARN": " !", "INFO": "  "}[f["level"]]
            print(f"  {marker} [{f['level']:<5}] {f['code']}")
            print(f"       {f['message']}")
            print(f"       next step: {f['next_step']}")

    print("\n-- reminder --")
    print("  This is a FOURTH reading, not the authority. If it disagrees with")
    print("  apktool or aapt2, that is a lead. If it disagrees with "
          "`dumpsys package`,")
    print("  the device is right and you have found something.")
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Decode Android binary XML and report structural anomalies")
    ap.add_argument("path", nargs="?",
                    help="an AXML file (omit when using --extract)")
    ap.add_argument("--extract", metavar="APK",
                    help="read the AXML entry out of this APK instead")
    ap.add_argument("--entry", default="AndroidManifest.xml",
                    help="which entry --extract should read "
                         "(default: AndroidManifest.xml)")
    ap.add_argument("--chunks", action="store_true",
                    help="print the chunk map with offsets and sizes")
    ap.add_argument("--strings", action="store_true",
                    help="dump the string pool")
    ap.add_argument("--anomalies-only", action="store_true",
                    help="skip the tree; print only the anomaly report")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if anything is flagged ALERT or WARN")
    args = ap.parse_args()

    if not args.path and not args.extract:
        ap.error("give an AXML file, or --extract app.apk")

    try:
        if args.extract:
            data = extract_from_apk(args.extract, args.entry)
            label = f"{args.extract}!{args.entry}"
        else:
            with open(args.path, "rb") as fh:
                data = fh.read()
            label = args.path
    except (OSError, AxmlError, zlib.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        doc = Axml(data, label)
    except AxmlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(doc.summary(), indent=2, default=str))
    else:
        print_report(doc, args)

    if args.strict and doc.flagged():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
