#!/usr/bin/env python3
"""
dex_parser.py — parse an Android DEX file from first principles.

WHAT IT DOES
    Implements the structures documented in ../README.md section 3, using only
    the Python standard library:

      - header_item, field by field                        (README 3.2)
      - checksum and SHA-1 signature verification          (README 3.4)
      - LEB128 / ULEB128 / ULEB128p1 decoding              (README 3.5)
      - MUTF-8 decoding                                    (README 3.6)
      - string_ids / string_data_item                      (README 3.8)
      - type_ids, proto_ids, field_ids, method_ids         (README 3.9-3.12)
      - class_defs                                         (README 3.13)
      - map_list with full TYPE_* decoding                 (README 3.22)
      - MAP COVERAGE ANALYSIS                              (README 3.22 note)

WHY WRITE YOUR OWN PARSER
    Two reasons. First, you learn the format properly — reading the spec is not
    the same as making the offsets work. Second, and more practically, when a
    crafted DEX makes apktool and jadx disagree with the runtime, a parser you
    control and understand is the tiebreaker.

    The --map-coverage check is the payoff. In a legitimate d8 output, every
    byte of the file is accounted for by exactly one map entry. Uncovered
    regions mean a packer parked something there, a second DEX was appended, or
    data is being smuggled past scanners that only read the map.

HOW TO RUN
    python3 dex_parser.py classes.dex
    python3 dex_parser.py classes.dex --strings | head -50
    python3 dex_parser.py classes.dex --strings --filter "http"
    python3 dex_parser.py classes.dex --classes
    python3 dex_parser.py classes.dex --methods
    python3 dex_parser.py classes.dex --map
    python3 dex_parser.py classes.dex --map-coverage
    python3 dex_parser.py classes.dex --verify-header
    python3 dex_parser.py classes.dex --json

    # Extract straight from an APK
    unzip -o app.apk 'classes*.dex' -d /tmp/dex
    for f in /tmp/dex/classes*.dex; do python3 dex_parser.py "$f" --verify-header; done

REQUIREMENTS
    Python 3.8+. No third-party modules.

CAVEAT
    This is a teaching parser. It is deliberately strict and will complain about
    files the runtime would accept, which is exactly what you want when hunting
    for deliberately malformed DEX. For production tooling use libdexfile or a
    maintained library. Ground truth for opcodes is
    libdexfile/dex/dex_instruction_list.h in AOSP.
"""

import argparse
import hashlib
import json
import struct
import sys
import zlib

HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412
NO_INDEX = 0xFFFFFFFF

# README 3.22 — the complete TYPE_* table.
MAP_TYPES = {
    0x0000: ("TYPE_HEADER_ITEM", 112),
    0x0001: ("TYPE_STRING_ID_ITEM", 4),
    0x0002: ("TYPE_TYPE_ID_ITEM", 4),
    0x0003: ("TYPE_PROTO_ID_ITEM", 12),
    0x0004: ("TYPE_FIELD_ID_ITEM", 8),
    0x0005: ("TYPE_METHOD_ID_ITEM", 8),
    0x0006: ("TYPE_CLASS_DEF_ITEM", 32),
    0x0007: ("TYPE_CALL_SITE_ID_ITEM", 4),
    0x0008: ("TYPE_METHOD_HANDLE_ITEM", 8),
    0x1000: ("TYPE_MAP_LIST", None),
    0x1001: ("TYPE_TYPE_LIST", None),
    0x1002: ("TYPE_ANNOTATION_SET_REF_LIST", None),
    0x1003: ("TYPE_ANNOTATION_SET_ITEM", None),
    0x2000: ("TYPE_CLASS_DATA_ITEM", None),
    0x2001: ("TYPE_CODE_ITEM", None),
    0x2002: ("TYPE_STRING_DATA_ITEM", None),
    0x2003: ("TYPE_DEBUG_INFO_ITEM", None),
    0x2004: ("TYPE_ANNOTATION_ITEM", None),
    0x2005: ("TYPE_ENCODED_ARRAY_ITEM", None),
    0x2006: ("TYPE_ANNOTATIONS_DIRECTORY_ITEM", None),
    0xF000: ("TYPE_HIDDENAPI_CLASS_DATA_ITEM", None),
}

# README 3.23 — access flags, class/field/method meanings differ for some bits.
ACCESS_FLAGS = [
    (0x00001, "PUBLIC"), (0x00002, "PRIVATE"), (0x00004, "PROTECTED"),
    (0x00008, "STATIC"), (0x00010, "FINAL"), (0x00020, "SYNCHRONIZED"),
    (0x00040, "VOLATILE/BRIDGE"), (0x00080, "TRANSIENT/VARARGS"),
    (0x00100, "NATIVE"), (0x00200, "INTERFACE"), (0x00400, "ABSTRACT"),
    (0x00800, "STRICT"), (0x01000, "SYNTHETIC"), (0x02000, "ANNOTATION"),
    (0x04000, "ENUM"), (0x10000, "CONSTRUCTOR"),
    (0x20000, "DECLARED_SYNCHRONIZED"),
]


class DexError(Exception):
    pass


# --------------------------------------------------------------------------
# Primitive decoders — README 3.5 and 3.6
# --------------------------------------------------------------------------

def read_uleb128(data, off):
    """Unsigned LEB128. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise DexError(f"ULEB128 ran off the end at offset {off}")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 28:
            raise DexError("ULEB128 longer than 5 bytes")
    return result, off


def read_uleb128p1(data, off):
    """ULEB128p1: the encoded value minus one, so 0x00 means -1."""
    value, off = read_uleb128(data, off)
    return value - 1, off


def read_sleb128(data, off):
    """Signed LEB128. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise DexError(f"SLEB128 ran off the end at offset {off}")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            # sign-extend if the sign bit of the final group is set
            if b & 0x40:
                result |= -(1 << shift)
            break
        if shift > 35:
            raise DexError("SLEB128 too long")
    return result, off


def decode_mutf8(raw):
    """
    Decode Modified UTF-8 (README 3.6).

    Differs from standard UTF-8 in two ways that matter:
      - U+0000 is encoded as the two bytes C0 80, never as a single 00
      - supplementary characters are encoded as a CESU-8 surrogate PAIR
        (two 3-byte sequences), not as one 4-byte sequence
    """
    out = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0:
            break
        if b < 0x80:
            out.append(chr(b)); i += 1
        elif (b & 0xE0) == 0xC0:
            if i + 1 >= n:
                raise DexError("truncated 2-byte MUTF-8 sequence")
            cp = ((b & 0x1F) << 6) | (raw[i + 1] & 0x3F)
            out.append(chr(cp)); i += 2
        elif (b & 0xF0) == 0xE0:
            if i + 2 >= n:
                raise DexError("truncated 3-byte MUTF-8 sequence")
            cp = ((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F)
            out.append(chr(cp)); i += 3
        else:
            # A 4-byte sequence is INVALID in MUTF-8. Recover rather than abort,
            # but say so — a real one is a strong sign of a hand-crafted file.
            out.append("\ufffd"); i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# The parser
# --------------------------------------------------------------------------

class DexFile:

    def __init__(self, data):
        self.data = data
        self.warnings = []
        self.header = {}
        self._parse_header()

    # ---------------------------------------------------------- header ---

    def _parse_header(self):
        d = self.data
        if len(d) < HEADER_SIZE:
            raise DexError(f"file is only {len(d)} bytes; a header is {HEADER_SIZE}")

        magic = d[0:8]
        if magic[0:4] == b"dey\n":
            raise DexError(
                "this is a Dalvik-era ODEX (magic 'dey\\n'), not a DEX. "
                "See README section 3.1.")
        if magic[0:4] != b"dex\n":
            raise DexError(f"bad magic {magic[0:4]!r} — expected b'dex\\n'")

        version = magic[4:7].decode("ascii", "replace")

        (checksum,) = struct.unpack_from("<I", d, 8)
        signature = d[12:32]
        fields = struct.unpack_from("<20I", d, 32)

        (file_size, header_size, endian_tag, link_size, link_off, map_off,
         string_ids_size, string_ids_off, type_ids_size, type_ids_off,
         proto_ids_size, proto_ids_off, field_ids_size, field_ids_off,
         method_ids_size, method_ids_off, class_defs_size, class_defs_off,
         data_size, data_off) = fields

        self.header = dict(
            magic=magic.decode("ascii", "replace").rstrip("\x00"),
            version=version,
            checksum=checksum,
            signature=signature.hex(),
            file_size=file_size, header_size=header_size, endian_tag=endian_tag,
            link_size=link_size, link_off=link_off, map_off=map_off,
            string_ids_size=string_ids_size, string_ids_off=string_ids_off,
            type_ids_size=type_ids_size, type_ids_off=type_ids_off,
            proto_ids_size=proto_ids_size, proto_ids_off=proto_ids_off,
            field_ids_size=field_ids_size, field_ids_off=field_ids_off,
            method_ids_size=method_ids_size, method_ids_off=method_ids_off,
            class_defs_size=class_defs_size, class_defs_off=class_defs_off,
            data_size=data_size, data_off=data_off,
        )

        if endian_tag == REVERSE_ENDIAN_CONSTANT:
            raise DexError("byte-swapped DEX (REVERSE_ENDIAN_CONSTANT) — unsupported")
        if endian_tag != ENDIAN_CONSTANT:
            self.warnings.append(
                f"endian_tag is 0x{endian_tag:08x}, expected 0x{ENDIAN_CONSTANT:08x}")
        if header_size != HEADER_SIZE:
            self.warnings.append(
                f"header_size is 0x{header_size:x}, expected 0x{HEADER_SIZE:x} "
                "— fields may be skipped by a lenient parser (README 5.2)")
        if file_size != len(d):
            self.warnings.append(
                f"header.file_size={file_size} but the file is {len(d)} bytes "
                f"({len(d) - file_size:+d}) — trailing data?")

    # -------------------------------------------------------- integrity ---

    def verify_checksum(self):
        """Adler-32 over everything after the checksum field itself."""
        actual = zlib.adler32(self.data[12:]) & 0xFFFFFFFF
        return actual == self.header["checksum"], actual

    def verify_signature(self):
        """SHA-1 over everything after the signature field."""
        actual = hashlib.sha1(self.data[32:]).hexdigest()
        return actual == self.header["signature"], actual

    # ----------------------------------------------------------- tables ---

    def string(self, idx):
        """Resolve a string_ids index to its decoded value (README 3.8)."""
        h = self.header
        if idx == NO_INDEX or idx >= h["string_ids_size"]:
            return None
        off_of_off = h["string_ids_off"] + idx * 4
        (data_off,) = struct.unpack_from("<I", self.data, off_of_off)
        utf16_size, p = read_uleb128(self.data, data_off)
        end = self.data.find(b"\x00", p)
        if end == -1:
            end = len(self.data)
        s = decode_mutf8(self.data[p:end])
        if len(s) != utf16_size:
            # Not always an error (surrogate pairs count as 2 UTF-16 units),
            # but a large discrepancy is a parser-divergence signal.
            pass
        return s

    def type_name(self, idx):
        h = self.header
        if idx == NO_INDEX or idx >= h["type_ids_size"]:
            return None
        (desc_idx,) = struct.unpack_from("<I", self.data, h["type_ids_off"] + idx * 4)
        return self.string(desc_idx)

    def method_ref(self, idx):
        """Return (class, name, shorty-ish proto) for a method_ids index."""
        h = self.header
        if idx >= h["method_ids_size"]:
            return None
        base = h["method_ids_off"] + idx * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, base)
        proto_base = h["proto_ids_off"] + proto_idx * 12
        shorty_idx, return_type_idx, _params_off = struct.unpack_from(
            "<III", self.data, proto_base)
        return dict(
            cls=self.type_name(class_idx),
            name=self.string(name_idx),
            shorty=self.string(shorty_idx),
            ret=self.type_name(return_type_idx),
        )

    def field_ref(self, idx):
        h = self.header
        if idx >= h["field_ids_size"]:
            return None
        base = h["field_ids_off"] + idx * 8
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.data, base)
        return dict(cls=self.type_name(class_idx),
                    name=self.string(name_idx),
                    type=self.type_name(type_idx))

    def class_defs(self):
        """Yield each class_def_item (README 3.13)."""
        h = self.header
        for i in range(h["class_defs_size"]):
            base = h["class_defs_off"] + i * 32
            (class_idx, access_flags, superclass_idx, interfaces_off,
             source_file_idx, annotations_off, class_data_off,
             static_values_off) = struct.unpack_from("<8I", self.data, base)
            yield dict(
                index=i,
                name=self.type_name(class_idx),
                access_flags=access_flags,
                access=decode_access(access_flags),
                superclass=self.type_name(superclass_idx),
                source_file=self.string(source_file_idx)
                if source_file_idx != NO_INDEX else None,
                has_data=class_data_off != 0,
                annotations_off=annotations_off,
            )

    def strings(self):
        for i in range(self.header["string_ids_size"]):
            try:
                yield i, self.string(i)
            except DexError as e:
                self.warnings.append(f"string #{i}: {e}")

    # -------------------------------------------------------- map_list ---

    def map_list(self):
        """Parse the map_list (README 3.22)."""
        off = self.header["map_off"]
        if off == 0 or off + 4 > len(self.data):
            raise DexError("map_off is 0 or out of bounds")
        (size,) = struct.unpack_from("<I", self.data, off)
        entries = []
        for i in range(size):
            base = off + 4 + i * 12
            if base + 12 > len(self.data):
                raise DexError("map_list runs off the end of the file")
            mtype, _unused, count, moff = struct.unpack_from("<HHII", self.data, base)
            name, item_size = MAP_TYPES.get(mtype, (f"UNKNOWN_0x{mtype:04x}", None))
            entries.append(dict(type=mtype, name=name, count=count,
                                offset=moff, item_size=item_size))
        return entries

    def map_coverage(self):
        """
        THE PACKER DETECTOR (README 3.22, 5.2).

        In a legitimate d8 output every byte is covered by exactly one map
        entry. Report gaps and overlaps.
        """
        entries = self.map_list()
        ranges = []

        for e in entries:
            start = e["offset"]
            if e["item_size"] is not None:
                length = e["count"] * e["item_size"]
            elif e["type"] == 0x1000:               # the map itself
                length = 4 + e["count"] * 12
            else:
                length = None                        # variable — bounded below
            ranges.append((start, length, e["name"], e["count"]))

        # For variable-size sections, bound each by the next section's start.
        starts = sorted({r[0] for r in ranges} | {len(self.data)})
        resolved = []
        for start, length, name, count in ranges:
            if length is None:
                nxt = next((s for s in starts if s > start), len(self.data))
                length = nxt - start
                approx = True
            else:
                approx = False
            resolved.append(dict(start=start, end=start + length,
                                 name=name, count=count, approx=approx))

        resolved.sort(key=lambda r: r["start"])

        gaps, overlaps = [], []
        cursor = 0
        for r in resolved:
            if r["start"] > cursor:
                gaps.append((cursor, r["start"], r["start"] - cursor))
            elif r["start"] < cursor:
                overlaps.append((r["start"], cursor, r["name"]))
            cursor = max(cursor, r["end"])
        if cursor < len(self.data):
            gaps.append((cursor, len(self.data), len(self.data) - cursor))

        return resolved, gaps, overlaps


def decode_access(flags):
    return [name for bit, name in ACCESS_FLAGS if flags & bit]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Parse an Android DEX file")
    ap.add_argument("path")
    ap.add_argument("--strings", action="store_true", help="dump the string pool")
    ap.add_argument("--filter", help="only strings containing this substring")
    ap.add_argument("--classes", action="store_true", help="list class_defs")
    ap.add_argument("--methods", action="store_true", help="list method_ids")
    ap.add_argument("--map", action="store_true", help="dump the map_list")
    ap.add_argument("--map-coverage", action="store_true",
                    help="check that every byte is covered — the packer detector")
    ap.add_argument("--verify-header", action="store_true",
                    help="checksum, signature and structural sanity")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        with open(args.path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        dex = DexFile(data)
    except DexError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        out = {"header": dex.header, "warnings": dex.warnings}
        if args.map:
            out["map"] = dex.map_list()
        print(json.dumps(out, indent=2))
        return 0

    # --- header ---------------------------------------------------------
    print(f"\n=== {args.path} ({len(data):,} bytes) ===\n")
    print("-- header --")
    h = dex.header
    print(f"  {'magic':<22} {h['magic']!r}")
    print(f"  {'version':<22} {h['version']}")
    print(f"  {'checksum':<22} 0x{h['checksum']:08x}")
    print(f"  {'signature':<22} {h['signature']}")
    for k in ("file_size", "header_size", "link_size", "link_off", "map_off",
              "string_ids_size", "type_ids_size", "proto_ids_size",
              "field_ids_size", "method_ids_size", "class_defs_size",
              "data_size", "data_off"):
        v = h[k]
        print(f"  {k:<22} {v:<12} (0x{v:x})")
    print(f"  {'endian_tag':<22} 0x{h['endian_tag']:08x}")

    # 64K reference limit — README 3.28
    for tbl in ("method_ids_size", "field_ids_size", "type_ids_size"):
        if h[tbl] > 60000:
            print(f"  !! {tbl} = {h[tbl]} — close to the 65,536 limit")

    if dex.warnings:
        print("\n-- warnings --")
        for w in dex.warnings:
            print(f"  ! {w}")

    # --- integrity ------------------------------------------------------
    if args.verify_header:
        print("\n-- integrity --")
        ok_c, actual_c = dex.verify_checksum()
        ok_s, actual_s = dex.verify_signature()
        print(f"  adler32   {'OK' if ok_c else 'MISMATCH'}  "
              f"(computed 0x{actual_c:08x})")
        print(f"  sha1      {'OK' if ok_s else 'MISMATCH'}")
        if not ok_s:
            print(f"            computed {actual_s}")
        print("\n  NOTE: these fields are UNKEYED. Anyone who edits the file")
        print("        recomputes them — apktool does it automatically. They")
        print("        detect corruption, not tampering. See README 5.2.")

    # --- map ------------------------------------------------------------
    if args.map:
        print("\n-- map_list --")
        try:
            for e in dex.map_list():
                sz = e["item_size"] if e["item_size"] is not None else "var"
                print(f"  0x{e['type']:04x}  {e['name']:<34} "
                      f"count={e['count']:<8} off=0x{e['offset']:<8x} item={sz}")
        except DexError as e:
            print(f"  error: {e}")

    if args.map_coverage:
        print("\n-- map coverage --")
        try:
            resolved, gaps, overlaps = dex.map_coverage()
            for r in resolved:
                flag = " ~" if r["approx"] else "  "
                print(f" {flag} 0x{r['start']:08x}-0x{r['end']:08x}  {r['name']}")
            print("\n  (~ = size inferred from the next section's start)")

            if overlaps:
                print("\n  !! OVERLAPPING SECTIONS:")
                for s, e, n in overlaps:
                    print(f"     0x{s:x}-0x{e:x}  {n}")

            if gaps:
                total = sum(g[2] for g in gaps)
                print(f"\n  !! {len(gaps)} UNCOVERED REGION(S), {total} bytes total:")
                for s, e, n in gaps:
                    print(f"     0x{s:08x}-0x{e:08x}  ({n} bytes)")
                    blob = data[s:min(e, s + 16)]
                    print(f"       first bytes: {blob.hex(' ')}")
                    if blob[:4] == b"dex\n":
                        print("       ^^ ANOTHER DEX FILE IS EMBEDDED HERE")
                    elif blob[:2] == b"PK":
                        print("       ^^ a ZIP/APK is embedded here")
                print("\n  A legitimate d8 output has NO uncovered regions.")
                print("  Investigate: packer payload, appended DEX, or smuggled data.")
                print("  See README section 3.22 and 5.2.")
            else:
                print("\n  OK — every byte is accounted for by the map.")
        except DexError as e:
            print(f"  error: {e}")

    # --- strings --------------------------------------------------------
    if args.strings:
        print(f"\n-- strings ({h['string_ids_size']}) --")
        for i, s in dex.strings():
            if s is None:
                continue
            if args.filter and args.filter.lower() not in s.lower():
                continue
            printable = s.replace("\n", "\\n").replace("\r", "\\r")
            print(f"  [{i:>6}] {printable}")

    # --- classes --------------------------------------------------------
    if args.classes:
        print(f"\n-- classes ({h['class_defs_size']}) --")
        for c in dex.class_defs():
            acc = " ".join(c["access"])
            src = f"  ({c['source_file']})" if c["source_file"] else ""
            print(f"  {c['name']}{src}")
            print(f"      extends {c['superclass']}   [{acc}]")

    # --- methods --------------------------------------------------------
    if args.methods:
        print(f"\n-- method_ids ({h['method_ids_size']}) --")
        native = 0
        for i in range(h["method_ids_size"]):
            m = dex.method_ref(i)
            if m is None:
                continue
            print(f"  [{i:>6}] {m['cls']}->{m['name']} : {m['shorty']}")
        print(f"\n  (access flags live in encoded_method, not method_ids; "
              f"use --classes with a full walk for native counts)")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
