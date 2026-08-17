#!/usr/bin/env python3
"""
kotlin-metadata-recover.py -- recover ORIGINAL Kotlin names from a renamed APK.

PURPOSE
    R8 renames `com.example.LicenceVault` to `a.b`. The `@kotlin.Metadata`
    annotation that kotlinc attached to that class is a *separate* record of the
    same declaration, written as a protobuf, and R8 does not always remove or
    rewrite it. When it survives intact it hands back the original class name,
    every function name, every property name and every JVM signature -- for free,
    with no mapping.txt and no dynamic analysis.

    This script reads DEX directly (no Android tooling, no jadx, no Java), finds
    every `Lkotlin/Metadata;` class annotation, decodes the `d1` protobuf and the
    `d2` string table exactly the way the Kotlin runtime does, and prints

        <renamed DEX name>  ->  <original Kotlin name>

    plus the members. It also reports whether R8 *rewrote* the metadata, which is
    the difference between a total recovery and a wasted afternoon.

USAGE
    python3 -B kotlin-metadata-recover.py <app.apk | classes.dex> [options]

    Options:
      --summary            One line per class: renamed -> original. (default)
      --members            Also print functions, properties and JVM signatures.
      --json               Emit machine-readable JSON instead of text.
      --rewrite-check      Only print the rewrite verdict and the evidence.
      --filter SUBSTR      Only classes whose original name contains SUBSTR.
      --limit N            Stop after N classes (default: no limit).
      --raw-d2             Dump the d2 string table verbatim, undecoded.

    Examples:
      python3 -B kotlin-metadata-recover.py target.apk --members
      python3 -B kotlin-metadata-recover.py target.apk --rewrite-check
      python3 -B kotlin-metadata-recover.py classes.dex --json > names.json

REQUIREMENTS
    Python 3.8+. Standard library only -- `zipfile`, `struct`, `json`.
    No Android SDK, no JDK, no kotlinx-metadata, no network. It is deliberately
    dependency-free so it runs on a jump box with nothing installed.

WHAT THIS WILL *NOT* TELL YOU
    - It will not recover names for Java classes. `@kotlin.Metadata` is emitted
      by kotlinc only. A Java-only app yields nothing, and that is not a bug.
    - It will not recover names that R8 REWROTE. If `kotlin.Metadata` was kept by
      a keep rule, R8 rewrites the payload to match the renamed program, and the
      "original" names you get back are the obfuscated ones. Use --rewrite-check
      before you trust a single name. The script tells you; it cannot undo it.
    - It will not recover local variable names, parameter *values*, string
      constants, or anything about method bodies. Metadata describes the
      declaration surface only -- there is no code in it.
    - It will not tell you what a method DOES. Recovering `verifyLicence()` tells
      you where to look, not what you will find. This is a triage accelerator.
    - It does not decode every field of the Kotlin metadata protobuf. Type
      information, type parameters, contracts, annotations on types and version
      requirements are parsed past and discarded. Names and JVM signatures are
      what an analyst needs; the rest is noise at this altitude.
    - It cannot see classes that R8 deleted. A name absent here may simply have
      been shrunk away rather than hidden.
    - It reads only `classes*.dex` at the APK root. Code loaded at runtime from
      assets, a packer's encrypted payload, or a dynamic feature module is out of
      scope -- see the dynamic-loading material in chapter 40-Obfuscation.

REFERENCES (the algorithms below are ports, not guesses)
    Kotlin compiler sources, all under org/jetbrains/kotlin/metadata/jvm/deserialization/:
      BitEncoding.java        -- decodeBytes, decode7to8, addModuloByte
      utfEncoding.kt          -- UTF8_MODE_MARKER, stringsToBytes
      JvmNameResolverBase.kt  -- getString, PREDEFINED_STRINGS, the three Operations
      metadata.proto          -- Class.fq_name = 3, Function.name = 2, Property.name = 2
      jvm_metadata.proto      -- StringTableTypes, JvmMethodSignature, extensions 100/101
    DEX format: Android "Dalvik Executable format" -- annotations_directory_item,
    annotation_set_item, annotation_item, encoded_annotation, encoded_array.
"""

import sys
import json
import zipfile
import argparse

# --------------------------------------------------------------------------
# DEX primitives
# --------------------------------------------------------------------------

DEX_MAGICS = (b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00",
              b"dex\n038\x00", b"dex\n039\x00", b"dex\n040\x00")


def u4(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def u2(buf, off):
    return int.from_bytes(buf[off:off + 2], "little")


def uleb128(buf, off):
    """Return (value, new_offset). DEX unsigned LEB128."""
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 too long")


def mutf8_code_units(buf, off):
    """
    Decode a DEX string_data_item body (Modified UTF-8, NUL-terminated) into a
    list of UTF-16 code units.

    This must return CODE UNITS, not a Python str, because Kotlin's UTF8 mode
    stores raw bytes 0x00..0xFF as individual code units and a naive utf-8
    decode destroys them. A real 0x00 byte is the terminator; the code point
    U+0000 is encoded as C0 80 and is NOT a terminator.
    """
    units = []
    while True:
        b = buf[off]
        off += 1
        if b == 0:
            return units, off
        if b < 0x80:
            units.append(b)
        elif (b & 0xE0) == 0xC0:
            b2 = buf[off]
            off += 1
            units.append(((b & 0x1F) << 6) | (b2 & 0x3F))
        elif (b & 0xF0) == 0xE0:
            b2 = buf[off]
            b3 = buf[off + 1]
            off += 2
            units.append(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F))
        else:
            # Not valid MUTF-8. Keep the byte rather than aborting the whole DEX.
            units.append(b)


def units_to_text(units):
    """Best-effort display string from UTF-16 code units, surrogates combined."""
    out = []
    i = 0
    n = len(units)
    while i < n:
        c = units[i]
        if 0xD800 <= c <= 0xDBFF and i + 1 < n and 0xDC00 <= units[i + 1] <= 0xDFFF:
            hi, lo = c, units[i + 1]
            out.append(chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)))
            i += 2
            continue
        out.append(chr(c))
        i += 1
    return "".join(out)


class Dex:
    """A read-only DEX view exposing only what metadata recovery needs."""

    def __init__(self, data, origin="<dex>"):
        if data[:8] not in DEX_MAGICS:
            raise ValueError("not a DEX file (bad magic %r)" % data[:8])
        self.d = data
        self.origin = origin
        self.string_ids_size = u4(data, 0x38)
        self.string_ids_off = u4(data, 0x3C)
        self.type_ids_size = u4(data, 0x40)
        self.type_ids_off = u4(data, 0x44)
        self.proto_ids_size = u4(data, 0x48)
        self.proto_ids_off = u4(data, 0x4C)
        self.field_ids_size = u4(data, 0x50)
        self.field_ids_off = u4(data, 0x54)
        self.method_ids_size = u4(data, 0x58)
        self.method_ids_off = u4(data, 0x5C)
        self.class_defs_size = u4(data, 0x60)
        self.class_defs_off = u4(data, 0x64)
        self._str_cache = {}

    def string_units(self, idx):
        cached = self._str_cache.get(idx)
        if cached is not None:
            return cached
        off = u4(self.d, self.string_ids_off + idx * 4)
        _, off = uleb128(self.d, off)          # utf16_size, unused
        units, _ = mutf8_code_units(self.d, off)
        self._str_cache[idx] = units
        return units

    def string(self, idx):
        return units_to_text(self.string_units(idx))

    def type_name(self, type_idx):
        return self.string(u4(self.d, self.type_ids_off + type_idx * 4))

    def class_defs(self):
        for i in range(self.class_defs_size):
            base = self.class_defs_off + i * 32
            yield {
                "class_idx": u4(self.d, base + 0x00),
                "access_flags": u4(self.d, base + 0x04),
                "source_file_idx": u4(self.d, base + 0x10),
                "annotations_off": u4(self.d, base + 0x14),
            }


# --------------------------------------------------------------------------
# DEX encoded_value / encoded_annotation
# --------------------------------------------------------------------------

VALUE_BYTE, VALUE_SHORT, VALUE_CHAR, VALUE_INT = 0x00, 0x02, 0x03, 0x04
VALUE_LONG, VALUE_FLOAT, VALUE_DOUBLE = 0x06, 0x10, 0x11
VALUE_METHOD_TYPE, VALUE_METHOD_HANDLE = 0x15, 0x16
VALUE_STRING, VALUE_TYPE, VALUE_FIELD = 0x17, 0x18, 0x19
VALUE_METHOD, VALUE_ENUM, VALUE_ARRAY = 0x1A, 0x1B, 0x1C
VALUE_ANNOTATION, VALUE_NULL, VALUE_BOOLEAN = 0x1D, 0x1E, 0x1F


def read_encoded_value(dex, off):
    """Return (python_value, new_offset). Strings come back as StrRef objects."""
    b = dex.d[off]
    off += 1
    vtype = b & 0x1F
    varg = (b >> 5) & 0x07

    def sized_uint(n):
        nonlocal off
        v = int.from_bytes(dex.d[off:off + n], "little")
        off += n
        return v

    if vtype in (VALUE_BYTE, VALUE_SHORT, VALUE_CHAR, VALUE_INT, VALUE_LONG):
        return sized_uint(varg + 1), off
    if vtype in (VALUE_FLOAT, VALUE_DOUBLE):
        sized_uint(varg + 1)
        return None, off
    if vtype in (VALUE_STRING, VALUE_TYPE, VALUE_FIELD, VALUE_METHOD,
                 VALUE_ENUM, VALUE_METHOD_TYPE, VALUE_METHOD_HANDLE):
        idx = sized_uint(varg + 1)
        if vtype == VALUE_STRING:
            return StrRef(dex, idx), off
        return idx, off
    if vtype == VALUE_NULL:
        return None, off
    if vtype == VALUE_BOOLEAN:
        return bool(varg), off
    if vtype == VALUE_ARRAY:
        size, off = uleb128(dex.d, off)
        items = []
        for _ in range(size):
            v, off = read_encoded_value(dex, off)
            items.append(v)
        return items, off
    if vtype == VALUE_ANNOTATION:
        ann, off = read_encoded_annotation(dex, off)
        return ann, off
    raise ValueError("unknown encoded_value type 0x%02x" % vtype)


class StrRef:
    """Lazy reference to a DEX string, so d1 can be read as code units."""

    __slots__ = ("dex", "idx")

    def __init__(self, dex, idx):
        self.dex = dex
        self.idx = idx

    def units(self):
        return self.dex.string_units(self.idx)

    def text(self):
        return self.dex.string(self.idx)

    def __repr__(self):
        return "StrRef(%s)" % self.text()


def read_encoded_annotation(dex, off):
    type_idx, off = uleb128(dex.d, off)
    size, off = uleb128(dex.d, off)
    elements = {}
    for _ in range(size):
        name_idx, off = uleb128(dex.d, off)
        value, off = read_encoded_value(dex, off)
        elements[dex.string(name_idx)] = value
    return {"type": dex.type_name(type_idx), "elements": elements}, off


def class_annotations(dex, annotations_off):
    """Yield decoded class-level annotations for one class_def."""
    if annotations_off == 0:
        return
    class_annotations_off = u4(dex.d, annotations_off)
    if class_annotations_off == 0:
        return
    size = u4(dex.d, class_annotations_off)
    for i in range(size):
        item_off = u4(dex.d, class_annotations_off + 4 + i * 4)
        # annotation_item: visibility u1, then encoded_annotation
        ann, _ = read_encoded_annotation(dex, item_off + 1)
        yield ann


# --------------------------------------------------------------------------
# BitEncoding -- port of org.jetbrains.kotlin.metadata.jvm.deserialization
# --------------------------------------------------------------------------

UTF8_MODE_MARKER = 0x0000
_8TO7_MODE_MARKER = 0xFFFF          # (char) -1


def decode_bytes(d1_units_list):
    """
    Port of BitEncoding.decodeBytes(String[]).

    `d1_units_list` is a list of UTF-16 code-unit lists, one per d1 entry.
    Returns the serialized protobuf as bytes.
    """
    data = [list(x) for x in d1_units_list]
    if data and data[0]:
        marker = data[0][0]
        if marker == UTF8_MODE_MARKER:
            data[0] = data[0][1:]
            return strings_to_bytes(data)
        if marker == _8TO7_MODE_MARKER:
            data[0] = data[0][1:]

    raw = strings_to_bytes(data)
    # "Adding 0x7f modulo max byte value is equivalent to subtracting 1"
    shifted = bytes((b + 0x7F) & 0x7F for b in raw)
    return decode_7to8(shifted)


def strings_to_bytes(data):
    """Port of utfEncoding.kt stringsToBytes: take the low byte of each unit."""
    out = bytearray()
    for s in data:
        for c in s:
            out.append(c & 0xFF)
    return bytes(out)


def decode_7to8(data):
    """Port of BitEncoding.decode7to8. Seven usable bits per input byte."""
    result_length = 7 * len(data) // 8
    result = bytearray(result_length)
    byte_index = 0
    bit = 0
    for i in range(result_length):
        first = (data[byte_index] & 0xFF) >> bit
        byte_index += 1
        second = (data[byte_index] & ((1 << (bit + 1)) - 1)) << (7 - bit)
        result[i] = (first + second) & 0xFF
        if bit == 6:
            byte_index += 1
            bit = 0
        else:
            bit += 1
    return bytes(result)


# --------------------------------------------------------------------------
# Minimal protobuf wire-format reader
# --------------------------------------------------------------------------

def pb_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError("protobuf varint too long")


def pb_parse(buf, start=0, end=None):
    """
    Parse a protobuf message into {field_number: [values...]}.
    Varints and fixed fields become ints; length-delimited fields become bytes.
    """
    if end is None:
        end = len(buf)
    fields = {}
    pos = start
    while pos < end:
        key, pos = pb_varint(buf, pos)
        fno = key >> 3
        wire = key & 0x07
        if wire == 0:
            val, pos = pb_varint(buf, pos)
        elif wire == 1:
            val = int.from_bytes(buf[pos:pos + 8], "little")
            pos += 8
        elif wire == 2:
            ln, pos = pb_varint(buf, pos)
            val = buf[pos:pos + ln]
            pos += ln
        elif wire == 5:
            val = int.from_bytes(buf[pos:pos + 4], "little")
            pos += 4
        elif wire in (3, 4):
            # Deprecated groups. Kotlin metadata does not use them.
            raise ValueError("protobuf group wire type in Kotlin metadata")
        else:
            raise ValueError("bad protobuf wire type %d" % wire)
        fields.setdefault(fno, []).append(val)
    return fields


def pb_packed_varints(raw):
    out = []
    pos = 0
    while pos < len(raw):
        v, pos = pb_varint(raw, pos)
        out.append(v)
    return out


def pb_first(fields, fno, default=None):
    v = fields.get(fno)
    return v[0] if v else default


# --------------------------------------------------------------------------
# JvmNameResolver -- port of JvmNameResolverBase.getString
# --------------------------------------------------------------------------

_K = "kotlin"

PREDEFINED_STRINGS = [
    _K + "/Any", _K + "/Nothing", _K + "/Unit", _K + "/Throwable", _K + "/Number",
    _K + "/Byte", _K + "/Double", _K + "/Float", _K + "/Int",
    _K + "/Long", _K + "/Short", _K + "/Boolean", _K + "/Char",
    _K + "/CharSequence", _K + "/String", _K + "/Comparable", _K + "/Enum",
    _K + "/Array", _K + "/ByteArray", _K + "/DoubleArray", _K + "/FloatArray",
    _K + "/IntArray", _K + "/LongArray", _K + "/ShortArray",
    _K + "/BooleanArray", _K + "/CharArray",
    _K + "/Cloneable", _K + "/Annotation",
    _K + "/collections/Iterable", _K + "/collections/MutableIterable",
    _K + "/collections/Collection", _K + "/collections/MutableCollection",
    _K + "/collections/List", _K + "/collections/MutableList",
    _K + "/collections/Set", _K + "/collections/MutableSet",
    _K + "/collections/Map", _K + "/collections/MutableMap",
    _K + "/collections/Map.Entry", _K + "/collections/MutableMap.MutableEntry",
    _K + "/collections/Iterator", _K + "/collections/MutableIterator",
    _K + "/collections/ListIterator", _K + "/collections/MutableListIterator",
]

OP_NONE, OP_INTERNAL_TO_CLASS_ID, OP_DESC_TO_CLASS_ID = 0, 1, 2

# StringTableTypes.Record field numbers (jvm_metadata.proto)
REC_RANGE, REC_PREDEFINED_INDEX, REC_OPERATION = 1, 2, 3
REC_SUBSTRING_INDEX, REC_REPLACE_CHAR, REC_STRING = 4, 5, 6


class NameResolver:
    """Resolves a metadata name index to its string, applying record ops."""

    def __init__(self, string_table_types_bytes, strings):
        self.strings = strings
        self.records = []
        self.local_name_indices = set()
        if string_table_types_bytes is None:
            return
        stt = pb_parse(string_table_types_bytes)
        for raw in stt.get(1, []):                  # repeated Record record = 1
            rec = pb_parse(raw)
            rng = pb_first(rec, REC_RANGE, 1)
            # "range" collapses identical subsequent records; expand them.
            for _ in range(max(1, rng)):
                self.records.append(rec)
        for raw in stt.get(5, []):                  # repeated int32 local_name = 5
            if isinstance(raw, (bytes, bytearray)):
                self.local_name_indices.update(pb_packed_varints(raw))
            else:
                self.local_name_indices.add(raw)

    def get_string(self, index):
        if not isinstance(index, int):
            # A length-delimited field was read where a name index was expected.
            # That means the payload is not the message shape we assumed --
            # report it rather than crashing the whole DEX.
            return "<not-a-name-index>"
        if index < 0:
            return "<bad-index:%d>" % index
        rec = self.records[index] if index < len(self.records) else None

        if rec is not None and REC_STRING in rec:
            s = rec[REC_STRING][0].decode("utf-8", "replace")
        elif rec is not None and REC_PREDEFINED_INDEX in rec:
            pi = rec[REC_PREDEFINED_INDEX][0]
            s = PREDEFINED_STRINGS[pi] if 0 <= pi < len(PREDEFINED_STRINGS) \
                else "<predefined:%d>" % pi
        elif index < len(self.strings):
            s = self.strings[index]
        else:
            return "<oob:%d>" % index

        if rec is not None:
            sub = rec.get(REC_SUBSTRING_INDEX)
            if sub:
                vals = pb_packed_varints(sub[0]) if isinstance(sub[0], (bytes, bytearray)) \
                    else [v for v in sub]
                if len(vals) >= 2:
                    begin, end = vals[0], vals[1]
                    if 0 <= begin <= end <= len(s):
                        s = s[begin:end]
            rep = rec.get(REC_REPLACE_CHAR)
            if rep:
                vals = pb_packed_varints(rep[0]) if isinstance(rep[0], (bytes, bytearray)) \
                    else [v for v in rep]
                if len(vals) >= 2:
                    s = s.replace(chr(vals[0]), chr(vals[1]))
            op = pb_first(rec, REC_OPERATION, OP_NONE)
            if op == OP_INTERNAL_TO_CLASS_ID:
                s = s.replace("$", ".")
            elif op == OP_DESC_TO_CLASS_ID:
                if len(s) >= 2:
                    s = s[1:-1]
                s = s.replace("$", ".")
        return s

    def is_local(self, index):
        return index in self.local_name_indices


# --------------------------------------------------------------------------
# metadata.proto field numbers
# --------------------------------------------------------------------------

CLASS_FLAGS, CLASS_FQ_NAME, CLASS_COMPANION_NAME = 1, 3, 4
CLASS_NESTED_CLASS_NAME, CLASS_CONSTRUCTOR = 7, 8
CLASS_FUNCTION, CLASS_PROPERTY, CLASS_TYPE_ALIAS = 9, 10, 11
CLASS_ENUM_ENTRY, CLASS_SEALED_SUBCLASS_FQ_NAME = 13, 16
CLASS_MODULE_NAME_EXT = 101            # jvm extension: class_module_name

PACKAGE_FUNCTION, PACKAGE_PROPERTY, PACKAGE_TYPE_ALIAS = 3, 4, 5

FUNCTION_NAME = 2
FUNCTION_SIGNATURE_EXT = 100           # jvm extension: method_signature
PROPERTY_NAME = 2
PROPERTY_SIGNATURE_EXT = 100           # jvm extension: property_signature
CONSTRUCTOR_SIGNATURE_EXT = 100
ENUM_ENTRY_NAME = 1
TYPE_ALIAS_NAME = 1

JVM_SIG_NAME, JVM_SIG_DESC = 1, 2
JVM_PROP_FIELD, JVM_PROP_SYNTHETIC, JVM_PROP_GETTER, JVM_PROP_SETTER = 1, 2, 3, 4


def read_jvm_signature(raw, nr):
    """JvmMethodSignature / JvmFieldSignature -> 'name desc' or None."""
    if raw is None:
        return None
    m = pb_parse(raw)
    ni = pb_first(m, JVM_SIG_NAME)
    di = pb_first(m, JVM_SIG_DESC)
    name = nr.get_string(ni) if ni is not None else None
    desc = nr.get_string(di) if di is not None else None
    if name is None and desc is None:
        return None
    return "%s%s" % (name or "?", desc or "")


def parse_class(payload, nr):
    """ProtoBuf.Class -> a plain dict of recovered names."""
    c = pb_parse(payload)
    out = {"kind": "class"}
    fq = pb_first(c, CLASS_FQ_NAME)
    out["original_name"] = nr.get_string(fq) if fq is not None else "<no fq_name>"
    out["is_local"] = nr.is_local(fq) if fq is not None else False

    comp = pb_first(c, CLASS_COMPANION_NAME)
    if comp is not None:
        out["companion"] = nr.get_string(comp)

    mod = pb_first(c, CLASS_MODULE_NAME_EXT)
    if mod is not None:
        out["module_name"] = nr.get_string(mod)

    nested = []
    for raw in c.get(CLASS_NESTED_CLASS_NAME, []):
        vals = pb_packed_varints(raw) if isinstance(raw, (bytes, bytearray)) else [raw]
        nested.extend(nr.get_string(v) for v in vals)
    if nested:
        out["nested"] = nested

    sealed = []
    for raw in c.get(CLASS_SEALED_SUBCLASS_FQ_NAME, []):
        vals = pb_packed_varints(raw) if isinstance(raw, (bytes, bytearray)) else [raw]
        sealed.extend(nr.get_string(v) for v in vals)
    if sealed:
        out["sealed_subclasses"] = sealed

    out["enum_entries"] = [
        nr.get_string(pb_first(pb_parse(raw), ENUM_ENTRY_NAME))
        for raw in c.get(CLASS_ENUM_ENTRY, [])
        if pb_first(pb_parse(raw), ENUM_ENTRY_NAME) is not None
    ]
    out["functions"] = _functions(c.get(CLASS_FUNCTION, []), nr)
    out["properties"] = _properties(c.get(CLASS_PROPERTY, []), nr)
    out["constructors"] = [
        read_jvm_signature(pb_first(pb_parse(raw), CONSTRUCTOR_SIGNATURE_EXT), nr)
        for raw in c.get(CLASS_CONSTRUCTOR, [])
    ]
    out["constructors"] = [x for x in out["constructors"] if x]
    return out


def parse_synthetic(payload, nr):
    """
    k=3 SYNTHETIC_CLASS. The payload is a bare ProtoBuf.Function describing the
    lambda, not a Class. This is where a lambda's ORIGINAL name can survive even
    though the class holding it is called `a$b$1`.
    """
    fns = _functions([payload], nr)
    name = fns[0]["name"] if fns else "?"
    return {
        "kind": "synthetic",
        "original_name": "<lambda %s>" % name if name not in ("?", "<oob:0>") else "<synthetic>",
        "functions": fns,
        "properties": [],
        "enum_entries": [],
        "constructors": [],
    }


def parse_package(payload, nr):
    p = pb_parse(payload)
    return {
        "kind": "package",
        "original_name": "<file facade>",
        "functions": _functions(p.get(PACKAGE_FUNCTION, []), nr),
        "properties": _properties(p.get(PACKAGE_PROPERTY, []), nr),
        "enum_entries": [],
        "constructors": [],
    }


def _functions(raws, nr):
    out = []
    for raw in raws:
        f = pb_parse(raw)
        ni = pb_first(f, FUNCTION_NAME)
        out.append({
            "name": nr.get_string(ni) if ni is not None else "?",
            "jvm": read_jvm_signature(pb_first(f, FUNCTION_SIGNATURE_EXT), nr),
        })
    return out


def _properties(raws, nr):
    out = []
    for raw in raws:
        p = pb_parse(raw)
        ni = pb_first(p, PROPERTY_NAME)
        entry = {"name": nr.get_string(ni) if ni is not None else "?"}
        sig_raw = pb_first(p, PROPERTY_SIGNATURE_EXT)
        if sig_raw is not None:
            sig = pb_parse(sig_raw)
            entry["field"] = read_jvm_signature(pb_first(sig, JVM_PROP_FIELD), nr)
            entry["getter"] = read_jvm_signature(pb_first(sig, JVM_PROP_GETTER), nr)
            entry["setter"] = read_jvm_signature(pb_first(sig, JVM_PROP_SETTER), nr)
        out.append(entry)
    return out


# --------------------------------------------------------------------------
# Driving it from a DEX
# --------------------------------------------------------------------------

KIND_NAMES = {
    1: "class", 2: "file-facade", 3: "synthetic-class",
    4: "multifile-facade", 5: "multifile-part",
}


def descriptor_to_dotted(desc):
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc


def recover_from_dex(dex):
    """Yield one record per class carrying a decodable @kotlin.Metadata."""
    for cd in dex.class_defs():
        if cd["annotations_off"] == 0:
            continue
        for ann in class_annotations(dex, cd["annotations_off"]):
            if ann["type"] != "Lkotlin/Metadata;":
                continue
            el = ann["elements"]
            kind = el.get("k", 1)
            d1 = el.get("d1") or []
            d2 = el.get("d2") or []
            mv = el.get("mv") or []
            xs = el.get("xs")
            xi = el.get("xi")
            pn = el.get("pn")

            strings = [s.text() if isinstance(s, StrRef) else str(s) for s in d2]
            rec = {
                "dex": dex.origin,
                "renamed_name": descriptor_to_dotted(dex.type_name(cd["class_idx"])),
                "renamed_descriptor": dex.type_name(cd["class_idx"]),
                "source_file": dex.string(cd["source_file_idx"])
                if cd["source_file_idx"] != 0xFFFFFFFF else None,
                "k": kind,
                "kind_name": KIND_NAMES.get(kind, "unknown(%s)" % kind),
                "mv": [v for v in mv if isinstance(v, int)],
                "xs": xs.text() if isinstance(xs, StrRef) else xs,
                "xi": xi,
                "pn": pn.text() if isinstance(pn, StrRef) else pn,
                "d1_entries": len(d1),
                "d2": strings,
                "error": None,
            }

            if not d1:
                # k=3 synthetic classes and some facades legitimately have no d1.
                rec["original_name"] = rec["xs"] or "<no d1 payload>"
                rec["functions"] = []
                rec["properties"] = []
                rec["enum_entries"] = []
                rec["constructors"] = []
                yield rec
                continue

            if kind == 4:
                # MULTIFILE_CLASS_FACADE. d1 is NOT a BitEncoding'd protobuf --
                # it is a plain array of the JVM internal names of the parts this
                # facade delegates to. Those part names are frequently original
                # even when everything around them is renamed.
                parts = [s.text() if isinstance(s, StrRef) else str(s) for s in d1]
                rec["original_name"] = (rec["xs"] or rec["renamed_name"]).replace("/", ".")
                rec["multifile_parts"] = [p.replace("/", ".") for p in parts]
                rec["functions"] = []
                rec["properties"] = []
                rec["enum_entries"] = []
                rec["constructors"] = []
                yield rec
                continue

            try:
                units = [s.units() if isinstance(s, StrRef) else [] for s in d1]
                payload = decode_bytes(units)
                # readClassDataFrom: a length-delimited StringTableTypes, then
                # the Class (or Package) message, back to back.
                stt_len, pos = pb_varint(payload, 0)
                stt = payload[pos:pos + stt_len]
                body = payload[pos + stt_len:]
                nr = NameResolver(stt, strings)
                if kind in (2, 5):
                    parsed = parse_package(body, nr)
                    if rec["xs"]:
                        parsed["original_name"] = rec["xs"].replace("/", ".")
                elif kind == 3:
                    parsed = parse_synthetic(body, nr)
                else:
                    parsed = parse_class(body, nr)
                rec.update(parsed)
            except Exception as exc:                    # noqa: BLE001
                rec["error"] = "%s: %s" % (type(exc).__name__, exc)
                rec["original_name"] = "<decode failed>"
                rec.setdefault("functions", [])
                rec.setdefault("properties", [])
                rec.setdefault("enum_entries", [])
                rec.setdefault("constructors", [])
            yield rec


def load_dexes(path):
    """Yield Dex objects from an APK, a JAR, or a bare .dex."""
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:8] in DEX_MAGICS:
        with open(path, "rb") as fh:
            yield Dex(fh.read(), origin=path)
        return
    if head[:2] != b"PK":
        raise SystemExit("%s is neither a DEX nor a zip/APK" % path)
    with zipfile.ZipFile(path) as z:
        names = sorted(n for n in z.namelist()
                       if n.startswith("classes") and n.endswith(".dex")
                       and "/" not in n)
        if not names:
            raise SystemExit("no classes*.dex at the root of %s" % path)
        for n in names:
            yield Dex(z.read(n), origin=n)


# --------------------------------------------------------------------------
# The rewrite verdict
# --------------------------------------------------------------------------

def rewrite_verdict(records):
    """
    Decide whether R8 rewrote the metadata, by comparing what the metadata
    CLAIMS the class is called against what the DEX actually calls it, and by
    checking whether recovered names look obfuscated.

    The reasoning: if metadata is intact, `original_name` is a real,
    human-authored name while `renamed_name` is `a.b`. If R8 rewrote it, the two
    agree -- because R8 rewrote the metadata to describe the renamed program.
    """
    total = agree = short = decoded = 0
    empty_shell = sum(1 for r in records if r["d1_entries"] == 0 and not r.get("d2"))
    prop_names = 0
    for r in records:
        prop_names += len(r.get("properties") or [])
        if r.get("error") or r["k"] not in (1,):
            continue
        orig = r.get("original_name") or ""
        if orig.startswith("<"):
            continue
        decoded += 1
        dotted_orig = orig.replace("/", ".")
        total += 1
        if dotted_orig == r["renamed_name"]:
            agree += 1
        simple = dotted_orig.rsplit(".", 1)[-1].split("$")[-1]
        if len(simple) <= 2:
            short += 1

    if decoded == 0:
        if empty_shell and empty_shell == len(records):
            return {
                "verdict": "payload-stripped",
                "detail": ("%d classes carry an @kotlin.Metadata annotation whose "
                           "elements are ALL absent -- no k, no d1, no d2. The "
                           "annotation is a marker only. Grepping for "
                           "'Lkotlin/Metadata;' would have called this a leak; it "
                           "is not one." % empty_shell),
                "classes_decoded": 0,
                "empty_shells": empty_shell,
            }
        return {
            "verdict": "no-metadata",
            "detail": "No decodable @kotlin.Metadata class records were found.",
            "classes_decoded": 0,
            "empty_shells": empty_shell,
        }
    agree_pct = 100.0 * agree / total if total else 0.0
    short_pct = 100.0 * short / total if total else 0.0
    if short_pct > 60.0:
        verdict = "rewritten"
        detail = ("%.0f%% of recovered simple names are 1-2 characters. R8 kept "
                  "kotlin.Metadata and rewrote its payload to match the renamed "
                  "program, so class, function and enum-entry names are NOT the "
                  "originals. Kotlin PROPERTY names are rewritten far less "
                  "reliably -- %d were recovered here; read them with --members "
                  "before concluding nothing leaked." % (short_pct, prop_names))
    elif agree_pct > 80.0:
        verdict = "not-obfuscated-or-rewritten"
        detail = ("%.0f%% of metadata names equal the DEX names. Either the app "
                  "was not name-obfuscated at all, or R8 rewrote the metadata "
                  "consistently." % agree_pct)
    else:
        verdict = "intact"
        detail = ("%.0f%% of metadata names differ from the DEX names and only "
                  "%.0f%% are 1-2 characters. The metadata describes the "
                  "PRE-obfuscation program: these are original names."
                  % (100.0 - agree_pct, short_pct))
    return {
        "verdict": verdict,
        "detail": detail,
        "classes_decoded": decoded,
        "agree_with_dex_pct": round(agree_pct, 1),
        "short_name_pct": round(short_pct, 1),
        "empty_shells": empty_shell,
        "recovered_property_names": prop_names,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Recover original Kotlin names from a renamed APK or DEX.")
    ap.add_argument("target", help="APK, JAR or classes.dex")
    ap.add_argument("--summary", action="store_true", help="renamed -> original only")
    ap.add_argument("--members", action="store_true", help="also print members")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--rewrite-check", action="store_true",
                    help="print only the rewrite verdict")
    ap.add_argument("--filter", default=None, help="substring filter on original name")
    ap.add_argument("--limit", type=int, default=0, help="stop after N classes")
    ap.add_argument("--raw-d2", action="store_true", help="dump the d2 table verbatim")
    args = ap.parse_args(argv)

    records = []
    for dex in load_dexes(args.target):
        for rec in recover_from_dex(dex):
            if args.filter and args.filter not in (rec.get("original_name") or ""):
                continue
            records.append(rec)
            if args.limit and len(records) >= args.limit:
                break
        if args.limit and len(records) >= args.limit:
            break

    verdict = rewrite_verdict(records)

    if args.json:
        json.dump({"target": args.target, "verdict": verdict,
                   "classes": records}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.rewrite_check:
        print("target   : %s" % args.target)
        print("classes  : %d with @kotlin.Metadata" % len(records))
        print("decoded  : %d" % verdict.get("classes_decoded", 0))
        print("verdict  : %s" % verdict["verdict"])
        print("detail   : %s" % verdict["detail"])
        return 0

    if not records:
        print("No @kotlin.Metadata annotations found in %s." % args.target)
        print("Either the app has no Kotlin, or R8 stripped the annotation "
              "(full mode does this by default).")
        return 0

    failures = sum(1 for r in records if r.get("error"))
    print("# %s" % args.target)
    print("# %d classes carry @kotlin.Metadata; %d decoded, %d failed"
          % (len(records), len(records) - failures, failures))
    print("# verdict: %s -- %s" % (verdict["verdict"], verdict["detail"]))
    print()

    for r in records:
        orig = (r.get("original_name") or "?").replace("/", ".")
        print("%-46s -> %s   [k=%s %s]"
              % (r["renamed_name"], orig, r["k"], r["kind_name"]))
        if r.get("error"):
            print("      !! %s" % r["error"])
        if r.get("source_file"):
            print("      SourceFile: %s" % r["source_file"])
        if args.raw_d2:
            for s in r.get("d2", []):
                print("      d2: %r" % s)
        if args.members:
            for e in r.get("enum_entries", []):
                print("      enum   %s" % e)
            for f in r.get("functions", []):
                jvm = (" [jvm %s]" % f["jvm"]) if f.get("jvm") else ""
                print("      fun    %s%s" % (f["name"], jvm))
            for p in r.get("properties", []):
                bits = []
                for key in ("field", "getter", "setter"):
                    if p.get(key):
                        bits.append("%s %s" % (key, p[key]))
                extra = ("  [%s]" % "; ".join(bits)) if bits else ""
                print("      val    %s%s" % (p["name"], extra))
            for c in r.get("constructors", []):
                print("      ctor   %s" % c)
            for p in r.get("multifile_parts", []):
                print("      part   %s" % p)
            if r.get("companion"):
                print("      companion %s" % r["companion"])
            if r.get("module_name"):
                print("      module %s" % r["module_name"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
