#!/usr/bin/env python3
"""
dex-diff.py -- structural diff of two DEX files (or two APKs).

PURPOSE
    Answer the question "what did they add?" for a repackaged application.

    You have an original APK and a suspect one -- a trojanised build from a
    third-party store, a modded game, a competitor's rebrand of your SDK, or the
    same app before and after an update. Comparing file hashes tells you they
    differ. Comparing decompiled source is thousands of lines of noise, most of
    it caused by the compiler renaming things. What you actually want is the
    short list: which classes, methods, fields and strings exist in one and not
    the other.

    This diffs the DEX *index tables* rather than the bytecode. Those tables are
    the app's declared vocabulary -- every type it names, every method it can
    call, every string constant it holds. An injected payload has to appear
    there, because there is nowhere else for its class name, its method names or
    its command-and-control URL to live. That makes the index diff a reliable
    first pass even when the bytecode has been reordered or the build is
    otherwise non-reproducible.

WHAT IT WILL NOT TELL YOU
    A method whose *body* changed but whose signature did not is invisible here
    -- the index entry is identical. Reflection and runtime-loaded DEX are
    likewise invisible, because the whole point of those techniques is to keep
    names out of the static tables. Treat a clean diff as "no new declared
    surface", not as "no change". Chapter 40 covers what hides from this.

    Comparing two builds from different toolchain versions produces noise:
    d8/R8 changes synthetic class naming (lambdas, `$$ExternalSyntheticLambda`)
    between releases. Use --ignore-synthetic to suppress the common shapes.

USAGE
    python3 dex-diff.py <old> <new>                 # .dex or .apk, either side
    python3 dex-diff.py old.apk new.apk --strings   # include the string diff
    python3 dex-diff.py old.apk new.apk --ignore-synthetic
    python3 dex-diff.py old.apk new.apk --json report.json

    Exit status is 0 when the two sides declare the same surface, 1 when they
    differ, 2 on a parse error -- so it can gate a CI check.

REQUIREMENTS
    Python 3.7+. Standard library only.
"""

import argparse
import json
import os
import re
import struct
import sys
import zipfile

DEX_MAGIC = b"dex\n"
HEADER_SIZE = 0x70

# Offsets of the size/offset pairs inside the DEX header. See chapter 12 section 3.
HDR = {
    "string_ids": (0x38, 0x3C),
    "type_ids":   (0x40, 0x44),
    "proto_ids":  (0x48, 0x4C),
    "field_ids":  (0x50, 0x54),
    "method_ids": (0x58, 0x5C),
    "class_defs": (0x60, 0x64),
}

CLASS_DEF_ITEM_SIZE = 32

# Shapes the compiler generates, which differ between toolchain versions for
# reasons that have nothing to do with what the developer wrote.
SYNTHETIC_PATTERNS = [
    re.compile(r"\$\$ExternalSyntheticLambda\d+"),
    re.compile(r"\$\$ExternalSynthetic\w+"),
    re.compile(r"\$\$Lambda\$"),
    re.compile(r"^L.*/R\$\w+;$"),          # resource inner classes
    re.compile(r"^L.*/BuildConfig;$"),
    re.compile(r"-\$\$Nest\$"),
]


class DexError(Exception):
    pass


def uleb128(data, off):
    """Read an unsigned LEB128. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise DexError("truncated uleb128")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
        if shift > 28:
            raise DexError("oversized uleb128")


def decode_mutf8(raw):
    """
    Decode Modified UTF-8 as used by DEX string data.

    Differs from standard UTF-8 in two ways that matter: U+0000 is encoded as
    the two bytes C0 80 so that no string contains an embedded NUL, and
    characters above the BMP are stored as a surrogate pair, each surrogate
    encoded separately in three bytes (CESU-8). Python's utf-8 codec rejects
    both, so decode by hand and fall back to a lossy repr for anything invalid
    -- a deliberately malformed string should not stop the diff.
    """
    out = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0:
            break
        if b < 0x80:
            out.append(chr(b))
            i += 1
        elif b & 0xE0 == 0xC0:
            if i + 1 >= n:
                out.append("�"); break
            out.append(chr(((b & 0x1F) << 6) | (raw[i + 1] & 0x3F)))
            i += 2
        elif b & 0xF0 == 0xE0:
            if i + 2 >= n:
                out.append("�"); break
            out.append(chr(((b & 0x0F) << 12) |
                           ((raw[i + 1] & 0x3F) << 6) |
                           (raw[i + 2] & 0x3F)))
            i += 3
        else:
            out.append("�")
            i += 1
    return "".join(out)


class Dex:
    """Index-table view of one DEX file. Bytecode is not parsed."""

    def __init__(self, data, label="<dex>"):
        self.data = data
        self.label = label
        if len(data) < HEADER_SIZE:
            raise DexError("file shorter than a DEX header")
        if data[:4] != DEX_MAGIC:
            raise DexError("bad magic (not a DEX file)")

        hdr_size = struct.unpack_from("<I", data, 0x24)[0]
        if hdr_size != HEADER_SIZE:
            raise DexError("header_size is 0x%X, expected 0x70" % hdr_size)

        self.counts = {}
        self.offsets = {}
        for name, (soff, ooff) in HDR.items():
            self.counts[name] = struct.unpack_from("<I", data, soff)[0]
            self.offsets[name] = struct.unpack_from("<I", data, ooff)[0]

        self.strings = self._strings()
        self.types = self._types()
        self.protos = self._protos()
        self.methods = self._methods()
        self.fields = self._fields()
        self.classes = self._classes()

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _strings(self):
        out = []
        base = self.offsets["string_ids"]
        for i in range(self.counts["string_ids"]):
            data_off = self._u32(base + i * 4)
            try:
                _, p = uleb128(self.data, data_off)      # utf16_size, unused
                end = self.data.find(b"\x00", p)
                if end < 0:
                    end = len(self.data)
                out.append(decode_mutf8(self.data[p:end]))
            except DexError:
                out.append("<malformed:%d>" % i)
        return out

    def _str(self, idx):
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return "<oob:%d>" % idx

    def _types(self):
        base = self.offsets["type_ids"]
        return [self._str(self._u32(base + i * 4))
                for i in range(self.counts["type_ids"])]

    def _type(self, idx):
        if 0 <= idx < len(self.types):
            return self.types[idx]
        return "<oob:%d>" % idx

    def _protos(self):
        """Return each prototype as a readable '(params)ret' shorthand."""
        out = []
        base = self.offsets["proto_ids"]
        for i in range(self.counts["proto_ids"]):
            off = base + i * 12
            ret_idx = self._u32(off + 4)
            params_off = self._u32(off + 8)
            params = []
            if params_off:
                size = self._u32(params_off)
                for k in range(size):
                    params.append(self._type(self._u16(params_off + 4 + k * 2)))
            out.append("(%s)%s" % ("".join(params), self._type(ret_idx)))
        return out

    def _proto(self, idx):
        if 0 <= idx < len(self.protos):
            return self.protos[idx]
        return "<oob:%d>" % idx

    def _methods(self):
        out = []
        base = self.offsets["method_ids"]
        for i in range(self.counts["method_ids"]):
            off = base + i * 8
            cls = self._type(self._u16(off))
            proto = self._proto(self._u16(off + 2))
            name = self._str(self._u32(off + 4))
            out.append("%s->%s%s" % (cls, name, proto))
        return out

    def _fields(self):
        out = []
        base = self.offsets["field_ids"]
        for i in range(self.counts["field_ids"]):
            off = base + i * 8
            cls = self._type(self._u16(off))
            typ = self._type(self._u16(off + 2))
            name = self._str(self._u32(off + 4))
            out.append("%s->%s:%s" % (cls, name, typ))
        return out

    def _classes(self):
        """Defined classes only -- a type_id can name a class this DEX merely references."""
        out = []
        base = self.offsets["class_defs"]
        for i in range(self.counts["class_defs"]):
            out.append(self._type(self._u32(base + i * CLASS_DEF_ITEM_SIZE)))
        return out


def load(path):
    """Load every DEX in an APK, or a single bare .dex. Returns a merged Dex-like view."""
    dexes = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            names = sorted(n for n in z.namelist()
                           if n.startswith("classes") and n.endswith(".dex") and "/" not in n)
            if not names:
                raise DexError("APK contains no classes*.dex at the archive root")
            for n in names:
                dexes.append(Dex(z.read(n), "%s!%s" % (os.path.basename(path), n)))
    else:
        with open(path, "rb") as f:
            dexes.append(Dex(f.read(), os.path.basename(path)))
    return dexes


def merge(dexes, attr):
    out = set()
    for d in dexes:
        out.update(getattr(d, attr))
    return out


def is_synthetic(name):
    return any(p.search(name) for p in SYNTHETIC_PATTERNS)


def report(title, added, removed, limit, out):
    if not added and not removed:
        return
    out.append("")
    out.append("=" * 72)
    out.append("%s   +%d  -%d" % (title, len(added), len(removed)))
    out.append("=" * 72)
    for tag, items in (("+", sorted(added)), ("-", sorted(removed))):
        shown = items[:limit]
        for it in shown:
            out.append("  %s %s" % (tag, it))
        if len(items) > limit:
            out.append("  %s ... and %d more (raise --limit to see them)"
                       % (tag, len(items) - limit))


def main():
    ap = argparse.ArgumentParser(
        description="Structural diff of two DEX files or APKs.")
    ap.add_argument("old", help="baseline .dex or .apk")
    ap.add_argument("new", help="suspect .dex or .apk")
    ap.add_argument("--strings", action="store_true",
                    help="also diff the string pool (noisy but where URLs and keys show up)")
    ap.add_argument("--ignore-synthetic", action="store_true",
                    help="suppress compiler-generated names that differ across toolchain versions")
    ap.add_argument("--limit", type=int, default=60,
                    help="max entries printed per section (default 60)")
    ap.add_argument("--json", metavar="FILE", help="also write the full diff as JSON")
    args = ap.parse_args()

    try:
        old = load(args.old)
        new = load(args.new)
    except (DexError, OSError, zipfile.BadZipFile) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    out = []
    out.append("old: %s  (%d dex, %d classes)"
               % (args.old, len(old), sum(len(d.classes) for d in old)))
    out.append("new: %s  (%d dex, %d classes)"
               % (args.new, len(new), sum(len(d.classes) for d in new)))

    sections = [("CLASSES", "classes"), ("METHODS", "methods"), ("FIELDS", "fields")]
    if args.strings:
        sections.append(("STRINGS", "strings"))

    result = {}
    differ = False
    for title, attr in sections:
        a = merge(old, attr)
        b = merge(new, attr)
        added = b - a
        removed = a - b
        if args.ignore_synthetic and attr != "strings":
            added = {x for x in added if not is_synthetic(x)}
            removed = {x for x in removed if not is_synthetic(x)}
        if added or removed:
            differ = True
        result[attr] = {"added": sorted(added), "removed": sorted(removed)}
        report(title, added, removed, args.limit, out)

    if not differ:
        out.append("")
        out.append("No difference in declared surface.")
        out.append("Note this does not mean the code is identical -- a method body can change")
        out.append("without its signature changing. See the header comment.")

    print("\n".join(out))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print("\nJSON written to %s" % args.json, file=sys.stderr)

    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
