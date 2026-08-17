#!/usr/bin/env python3
"""
dex-strings.py — parse the string pool out of a DEX file, by hand, with no dependencies.

WHY THIS SCRIPT EXISTS
  Chapter 03 argues that a file format is a data structure written to disk. This script proves it:
  in about a hundred lines of plain Python it reads the same table that `dexdump`, `jadx`,
  `baksmali` and ART all read, using nothing but the array indexing and offset arithmetic from
  section 3.9 and the ULEB128 encoding from section 3.5.

  Once you have written this, the DEX format stops being a specification to memorise and becomes
  a set of choices you can predict. That transition is the point.

WHAT IT DOES
  * Reads the DEX header and reports the fields that matter.
  * Walks string_ids -> string_data_item and decodes every string (MUTF-8).
  * Verifies that the pool is SORTED, which is why the format needs no on-disk hash table.
  * Optionally computes Java's String.hashCode for each string, so you can compare against
    ART's intern table.
  * Filters, so you can answer real questions about an app without decompiling it.

USAGE
  python3 dex-strings.py classes.dex                       # every string
  python3 dex-strings.py classes.dex --header              # header fields only
  python3 dex-strings.py classes.dex --verify-sorted       # is the pool really sorted?
  python3 dex-strings.py classes.dex --grep 'http|api|key' # regex filter
  python3 dex-strings.py classes.dex --classes             # class descriptors only (L...;)
  python3 dex-strings.py classes.dex --urls                # URLs and endpoints
  python3 dex-strings.py classes.dex --interesting         # the security-relevant triage view
  python3 dex-strings.py classes.dex --hash onCreate       # Java hashCode for one string
  python3 dex-strings.py app.apk                           # reads classes*.dex from an APK

DEPENDENCIES
  Python 3.8+, standard library only.

Chapter 03 — Programming Fundamentals, sections 3.5, 3.9, 3.10 and 9.3; labs/lab-02
Next chapter: 12-DEX-Internals, which parses the rest of the format the same way.
"""

import argparse
import re
import struct
import sys
import zipfile

# -------------------------------------------------------------------------------------------------
# DEX header layout. Every offset here is a fact from the format specification; nothing is guessed.
# The header is always 0x70 bytes, which is itself a useful sanity check.
# -------------------------------------------------------------------------------------------------
HEADER_FIELDS = [
    # (name, offset, format, description)
    ("magic",            0x00, "8s", "dex\\n + version, e.g. dex\\n039"),
    ("checksum",         0x08, "I",  "Adler-32 of everything after this field"),
    # signature is 20 bytes at 0x0C — handled separately
    ("file_size",        0x20, "I",  "total file size; MUST match the real length"),
    ("header_size",      0x24, "I",  "always 0x70"),
    ("endian_tag",       0x28, "I",  "0x12345678 little-endian"),
    ("link_size",        0x2C, "I",  ""),
    ("link_off",         0x30, "I",  ""),
    ("map_off",          0x34, "I",  "the map_list — every section, described"),
    ("string_ids_size",  0x38, "I",  "how many strings"),
    ("string_ids_off",   0x3C, "I",  "where the string_ids table starts"),
    ("type_ids_size",    0x40, "I",  ""),
    ("type_ids_off",     0x44, "I",  ""),
    ("proto_ids_size",   0x48, "I",  ""),
    ("proto_ids_off",    0x4C, "I",  ""),
    ("field_ids_size",   0x50, "I",  ""),
    ("field_ids_off",    0x54, "I",  ""),
    ("method_ids_size",  0x58, "I",  ""),
    ("method_ids_off",   0x5C, "I",  ""),
    ("class_defs_size",  0x60, "I",  "how many classes this DEX defines"),
    ("class_defs_off",   0x64, "I",  ""),
    ("data_size",        0x68, "I",  ""),
    ("data_off",         0x6C, "I",  ""),
]


def read_uleb128(buf: bytes, pos: int):
    """Decode an unsigned LEB128 integer.

    Seven bits of payload per byte; the high bit means 'another byte follows'. It exists so that
    small numbers — which most lengths are — cost one byte instead of four. That is the same
    space-versus-simplicity trade the whole DEX format is built on.

    Returns (value, new_position).
    """
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated ULEB128")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 28:
            raise ValueError("ULEB128 too long")


def decode_mutf8(raw: bytes) -> str:
    """Decode Modified UTF-8, the encoding DEX actually uses.

    It differs from real UTF-8 in exactly two ways, and both exist for the same reason — so that a
    string can be NUL-terminated in C while still being able to contain a NUL character:

      1. U+0000 is encoded as the two bytes C0 80 rather than as 00.
      2. Characters above U+FFFF are encoded as a SURROGATE PAIR of three-byte sequences
         (six bytes total) rather than as one four-byte sequence.

    Python's standard UTF-8 decoder handles neither, so we fix them up. This is chapter 03
    section 3.5.5, and it is a real source of bugs in tools that assume plain UTF-8.
    """
    # Fix 1: C0 80 -> U+0000
    raw = raw.replace(b"\xc0\x80", b"\x00")
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Fix 2: surrogate pairs arrive as two separate three-byte sequences. Decoding with
        # 'surrogatepass' accepts them, and then we recombine.
        try:
            s = raw.decode("utf-8", errors="surrogatepass")
            s = s.encode("utf-16", "surrogatepass").decode("utf-16")
        except Exception:
            s = raw.decode("utf-8", errors="replace")
    return s


def java_string_hash(s: str) -> int:
    """Bit-exact java.lang.String.hashCode(). See examples/hashmap_from_scratch.py."""
    h = 0
    for ch in s:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return h - 0x100000000 if h >= 0x80000000 else h


class Dex:
    def __init__(self, data: bytes):
        if data[:4] != b"dex\n":
            raise ValueError("not a DEX file (bad magic)")
        self.data = data
        self.header = {}
        for name, off, fmt, _desc in HEADER_FIELDS:
            (value,) = struct.unpack_from("<" + fmt, data, off)
            self.header[name] = value
        self.header["signature"] = data[0x0C:0x20].hex()

    # ---- header ---------------------------------------------------------------------------------

    def print_header(self):
        h = self.header
        print(f"  {'magic':<20} {h['magic'].decode('latin-1')!r}")
        print(f"  {'signature':<20} {h['signature']}")
        print(f"  {'checksum':<20} 0x{h['checksum']:08x}")
        print(f"  {'file_size':<20} {h['file_size']:,}   (actual: {len(self.data):,})")
        if h["file_size"] != len(self.data):
            print("      >>> MISMATCH. Data exists that the header does not describe.")
            print("      >>> See 12-DEX-Internals lab 04 — this is how payloads are hidden.")
        print(f"  {'header_size':<20} 0x{h['header_size']:x}"
              f"{'   (expected 0x70)' if h['header_size'] != 0x70 else ''}")
        print(f"  {'endian_tag':<20} 0x{h['endian_tag']:08x}")
        print()
        for label in ("string_ids", "type_ids", "proto_ids", "field_ids",
                      "method_ids", "class_defs"):
            size = h[f"{label}_size"]
            off = h[f"{label}_off"]
            print(f"  {label:<20} {size:>8,} entries at 0x{off:08x}")

    # ---- the string pool ------------------------------------------------------------------------

    def strings(self):
        """Yield every string in the pool, in table order.

        The table is an array of 4-byte offsets. Element i lives at
        string_ids_off + i*4 — which is exactly `base + index * element_size` from section 3.9.1,
        and is why array indexing starts at zero.
        """
        count = self.header["string_ids_size"]
        table = self.header["string_ids_off"]
        for i in range(count):
            (data_off,) = struct.unpack_from("<I", self.data, table + i * 4)
            # A string_data_item is: ULEB128 length (in UTF-16 code units), then MUTF-8 bytes,
            # then a NUL. Note that the length is in CODE UNITS, not bytes — so you cannot use
            # it to skip forwards. You must find the NUL. That is section 3.5.4's trap, on disk.
            _utf16_len, pos = read_uleb128(self.data, data_off)
            end = self.data.index(b"\x00", pos)
            yield decode_mutf8(self.data[pos:end])

    def verify_sorted(self) -> bool:
        """The pool must be sorted by UTF-16 code point order. Check it."""
        prev = None
        prev_i = -1
        ok = True
        for i, s in enumerate(self.strings()):
            if prev is not None and s < prev:
                if ok:
                    print("  NOT SORTED. First violation:")
                    print(f"    [{prev_i}] {prev!r}")
                    print(f"    [{i}] {s!r}")
                ok = False
            prev, prev_i = s, i
        return ok


# -------------------------------------------------------------------------------------------------
# Triage filters — the questions you actually ask of a string pool on an engagement.
# -------------------------------------------------------------------------------------------------

INTERESTING = [
    ("URLs and endpoints",   r"^https?://|^ws://|^wss://"),
    ("File paths",           r"^/(data|sdcard|storage|system|proc)/"),
    ("Crypto",               r"AES|RSA|HMAC|SHA-?\d|PBKDF2|Cipher|KeyStore|ECB|CBC/|GCM"),
    ("Auth and tokens",      r"(?i)token|bearer|oauth|jwt|session|credential|password|passwd"),
    ("Keys and secrets",     r"(?i)secret|api[_-]?key|private[_-]?key|BEGIN [A-Z ]*PRIVATE"),
    ("Native libraries",     r"^lib[a-z0-9_]+$|\.so$"),
    ("Reflection",           r"getDeclaredMethod|setAccessible|forName|getMethod"),
    ("Dynamic loading",      r"DexClassLoader|InMemoryDexClassLoader|loadLibrary|System\.load"),
    ("Command execution",    r"Runtime|ProcessBuilder|/system/bin/sh|exec"),
    ("Root and debug checks", r"(?i)su\b|superuser|magisk|xposed|frida|/proc/self/maps|ro\.debuggable"),
    ("WebView",              r"addJavascriptInterface|setJavaScriptEnabled|shouldOverrideUrl"),
    ("Debug leftovers",      r"(?i)^(TODO|FIXME|HACK|XXX|test[_-]|debug[_-]|staging)"),
]


def load_dex_blobs(path: str):
    """Accept either a .dex file or an .apk, yielding (name, bytes)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head == b"dex\n":
        with open(path, "rb") as fh:
            yield path, fh.read()
        return
    if head[:2] == b"PK":
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist()
                     if n.startswith("classes") and n.endswith(".dex")]
            if not names:
                raise ValueError("no classes*.dex inside this archive")
            for n in sorted(names):
                yield n, z.read(n)
        return
    raise ValueError("not a DEX file and not a zip/APK")


def main():
    ap = argparse.ArgumentParser(
        description="Parse the string pool out of a DEX file or an APK.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("path", help="a .dex file or an .apk")
    ap.add_argument("--header", action="store_true", help="print header fields and stop")
    ap.add_argument("--verify-sorted", action="store_true", help="check that the pool is sorted")
    ap.add_argument("--grep", metavar="REGEX", help="only strings matching this regex")
    ap.add_argument("--classes", action="store_true", help="only class descriptors (Lfoo/Bar;)")
    ap.add_argument("--urls", action="store_true", help="only URLs")
    ap.add_argument("--interesting", action="store_true",
                    help="security triage view, grouped by category")
    ap.add_argument("--with-hash", action="store_true",
                    help="also print each string's Java hashCode")
    ap.add_argument("--hash", metavar="STRING",
                    help="compute Java hashCode for one string and exit")
    ap.add_argument("--min-length", type=int, default=0)
    ap.add_argument("--limit", type=int, default=0, help="stop after N matches (0 = no limit)")
    args = ap.parse_args()

    if args.hash is not None:
        print(java_string_hash(args.hash))
        return 0

    for name, blob in load_dex_blobs(args.path):
        try:
            dex = Dex(blob)
        except ValueError as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            continue

        print(f"\n=== {name} ===")

        if args.header:
            dex.print_header()
            continue

        print(f"  {dex.header['string_ids_size']:,} strings at "
              f"0x{dex.header['string_ids_off']:08x}\n")

        if args.verify_sorted:
            ok = dex.verify_sorted()
            print("  SORTED" if ok else "  NOT SORTED")
            print("\n  Why sorted rather than hashed? Three constraints:")
            print("    1. The file is memory-mapped, so no structure can be built at load time.")
            print("    2. It is read-only, so nothing can be rehashed or resized.")
            print("    3. It must be small, and a hash table needs spare capacity to stay fast.")
            print("  A sorted array needs zero extra bytes and gives O(log n) binary search.")
            print("  ART then builds a HASH TABLE over it at load time — the intern table —")
            print("  because it performs millions of lookups and O(log n) is not good enough.")
            print("  Two structures, two constraints, one correct answer each. See labs/lab-02.")
            continue

        if args.interesting:
            all_strings = list(dex.strings())
            for label, pattern in INTERESTING:
                rx = re.compile(pattern)
                hits = [s for s in all_strings if rx.search(s)]
                if not hits:
                    continue
                print(f"  --- {label} ({len(hits)}) ---")
                for s in sorted(set(hits))[:25]:
                    print(f"      {s!r}")
                if len(set(hits)) > 25:
                    print(f"      ... {len(set(hits)) - 25} more")
                print()
            print("  NOTE: a string pool contains every class name, method name, field name and")
            print("  literal in the app, exactly once. Obfuscation RENAMES entries here; it")
            print("  cannot remove the table, because the runtime needs it. Anything that must")
            print("  be exact on the wire or across a boundary survives verbatim — which is why")
            print("  this view still works on an obfuscated app.")
            continue

        rx = None
        if args.grep:
            rx = re.compile(args.grep)
        elif args.classes:
            rx = re.compile(r"^L[a-zA-Z0-9_$/]+;$")
        elif args.urls:
            rx = re.compile(r"^https?://")

        shown = 0
        for s in dex.strings():
            if len(s) < args.min_length:
                continue
            if rx and not rx.search(s):
                continue
            if args.with_hash:
                print(f"  {java_string_hash(s):>12}  {s!r}")
            else:
                print(f"  {s!r}")
            shown += 1
            if args.limit and shown >= args.limit:
                print(f"  ... stopped at --limit {args.limit}")
                break

        if rx and shown == 0:
            print("  (no matches)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
