#!/usr/bin/env python3
"""
parcel-decode.py -- turn a raw Binder parcel into fields you can read.

WHAT IT DOES
    A parcel is a flat byte buffer with NO type tags and NO schema. `service
    call` prints it as 32-bit words and leaves you to work it out. This script
    does the working out:

        - accepts the three dump formats you actually encounter:
            * `service call` output           0x00000000: 0000001c 006e0061 ...
            * examples/binder-probe.c output  00000000: 00000000 ffffffff ...
            * a bare hex string or a file of hex bytes
        - decodes the interface-token header (strict-mode policy, work-source
          uid, the 'SYST' magic, and the descriptor String16)
        - decodes the reply exception header, naming the exception and
          extracting the message AND the remote stack trace, which is the most
          under-used piece of reconnaissance in Android
        - decodes String16, String8, int32, int64 and byte arrays, checking
          the length arithmetic and the 4-byte padding so a malformed parcel
          is reported as malformed rather than silently misread
        - finds and decodes embedded flat_binder_object structures --
          BINDER_TYPE_HANDLE, BINDER_TYPE_BINDER, BINDER_TYPE_FD,
          BINDER_TYPE_PTR -- by their 4-byte magic, and prints the flags
        - guesses the layout when you do not tell it, and says clearly that it
          is guessing

HOW TO RUN
    # straight off a device
    adb shell service call activity 1598968902 | python3 -B parcel-decode.py -

    # a saved dump
    python3 -B parcel-decode.py dump.txt

    # paste a dump interactively, then Ctrl-D (Ctrl-Z Enter on Windows)
    python3 -B parcel-decode.py --paste

    # tell it what the parcel is, instead of letting it guess
    python3 -B parcel-decode.py dump.txt --as token      # a request: token first
    python3 -B parcel-decode.py dump.txt --as reply      # a reply: exception header first
    python3 -B parcel-decode.py dump.txt --as raw        # no assumptions

    # a bare hex string
    python3 -B parcel-decode.py --hex "1c000000 61006e00 64007200"

    # spell out the field types yourself, in order
    python3 -B parcel-decode.py dump.txt --layout token,str16,i32,i64

    # the worked examples that ship with this chapter
    python3 -B parcel-decode.py ../examples/measured-binder-probe.txt --as token

REQUIREMENTS
    Python 3.6+, standard library only. No adb, no device, no network. Runs
    anywhere.

WHAT THIS WILL *NOT* TELL YOU
    - What the fields MEAN. A parcel carries no schema, so this script can
      tell you "int32 = 3" and never that 3 is a user id. The meaning lives in
      the .aidl file, which is not on the device. Get it from AOSP source or
      from the decompiled Stub -- see README section 6.
    - Whether your reading is the RIGHT one. Because there are no type tags,
      a run of bytes is a valid String16 length AND a valid int32 AND half of
      an int64 at the same time. When --layout is not given the script uses
      heuristics and labels every guess. Two different layouts can both parse
      cleanly and only one can be correct. If the field walk looks plausible
      but the last field runs off the end, your layout is wrong.
    - Anything about Parcelables. A Parcelable has NO framing whatsoever --
      writeToParcel() just writes fields. Decoding one requires its source.
      The script will show you the raw bytes and stop.
    - Whether a parcel is malicious. It reports structure, not intent.
    - Where one parcel ends and the next begins. A file containing SEVERAL
      dumps is concatenated into one byte string, because nothing in a hex
      dump marks a boundary. Feed it one dump at a time, or expect the field
      walk to run straight from the end of the first parcel into the start of
      the second. The byte count printed in the banner is your check: if it is
      larger than the data_size the tool reported, you have more than one.
    - The offsets array. `service call` does not print it and a hex dump does
      not contain it. The script locates embedded objects by scanning for
      their type magic instead, which finds real ones but could in principle
      match coincidental bytes; every such hit is labelled "scanned", not
      "declared". examples/binder-probe.c prints the real offsets array.
"""

import argparse
import re
import struct
import sys

# --------------------------------------------------------------------------
# Constants -- see README sections 3.7 and 3.8
# --------------------------------------------------------------------------

HEADER_SYST = 0x53595354          # B_PACK_CHARS('S','Y','S','T')
UNSET_WORK_SOURCE = -1

EXCEPTIONS = {
    0:    "no exception",
    -1:   "SecurityException",
    -2:   "BadParcelableException",
    -3:   "IllegalArgumentException",
    -4:   "NullPointerException",
    -5:   "IllegalStateException",
    -6:   "NetworkOnMainThreadException",
    -7:   "UnsupportedOperationException",
    -8:   "ServiceSpecificException",
    -9:   "a Parcelable exception",
    -129: "the transaction itself failed",
}

OBJECT_TYPES = {
    0x73622a85: ("BINDER_TYPE_BINDER",      "'sb*' -- a LOCAL object in the sender"),
    0x77622a85: ("BINDER_TYPE_WEAK_BINDER", "'wb*' -- a local object, weak ref"),
    0x73682a85: ("BINDER_TYPE_HANDLE",      "'sh*' -- a REMOTE reference"),
    0x77682a85: ("BINDER_TYPE_WEAK_HANDLE", "'wh*' -- a remote reference, weak"),
    0x66642a85: ("BINDER_TYPE_FD",          "'fd*' -- a REAL open file descriptor"),
    0x66646185: ("BINDER_TYPE_FDA",         "'fda' -- an array of descriptors"),
    0x70742a85: ("BINDER_TYPE_PTR",         "'pt*' -- a scatter-gather buffer"),
}

FLAT_FLAG_PRIORITY_MASK = 0xff
FLAT_FLAG_ACCEPTS_FDS = 0x100
FLAT_FLAG_TXN_SECURITY_CTX = 0x1000

WELL_KNOWN_CODES = {
    0x5f4e5446: ("INTERFACE_TRANSACTION", "'_NTF'"),
    0x5f444d50: ("DUMP_TRANSACTION", "'_DMP'"),
    0x5f434d44: ("SHELL_COMMAND_TRANSACTION", "'_CMD'"),
    0x5f504e47: ("PING_TRANSACTION", "'_PNG'"),
    0x5f535052: ("SYSPROPS_TRANSACTION", "'_SPR'"),
    0x5f545754: ("TWEET_TRANSACTION", "'_TWT'"),
    0x5f4c494b: ("LIKE_TRANSACTION", "'_LIK'"),
}


# --------------------------------------------------------------------------
# Input parsing
#
# THE TWO DUMP FORMATS DISAGREE ABOUT BYTE ORDER, and this is the single
# easiest way to decode a parcel into confident nonsense.
#
#   `service call` prints 32-bit WORDS in host order. The group "0000001c" is
#   the four bytes  1c 00 00 00  in memory. Read it left to right and you get
#   0x1c000000 = 469762048 instead of 28.
#
#   examples/binder-probe.c prints raw BYTES, four to a group. The group
#   "852a6873" is the four bytes  85 2a 68 73  in memory, which as a
#   little-endian u32 is 0x73682a85 -- BINDER_TYPE_HANDLE.
#
# Both look identical: eight hex digits, four groups to a line. They are
# distinguished by the "0x" on the offset (service call has it, binder-probe
# does not) and by the ASCII column delimiter ('...' versus |...|). Applying
# the wrong rule produces a parcel that still parses, still looks structured,
# and is wrong in every field -- which is exactly the failure mode this whole
# script exists to prevent, so it is handled explicitly and per line.
# --------------------------------------------------------------------------

# `  0x00000000: 0000001c 006e0061 00720064 0069006f '....a.n.d.r.o.i.'`
RE_SERVICE_LINE = re.compile(
    r"^\s*0x[0-9a-fA-F]{8}:\s+((?:[0-9a-fA-F]{8}\s+)*[0-9a-fA-F]{8})")

# `      00000000: 00000000 ffffffff 54535953 1a000000  |........TSYS....|`
RE_PROBE_LINE = re.compile(
    r"^\s*[0-9a-fA-F]{8}:\s+((?:[0-9a-fA-F]{8}\s+)*[0-9a-fA-F]{8})")

# `Result: Parcel(00000000 00000001   '........')` -- the one-line form
RE_INLINE = re.compile(r"Parcel\(((?:[0-9a-fA-F]{8}\s*)+)")


def _words_to_bytes(words, swap):
    """
    swap=True  : each group is a host-order 32-bit WORD (service call).
    swap=False : each group is four raw BYTES in order (binder-probe).
    """
    out = bytearray()
    for w in words:
        v = int(w, 16)
        if swap:
            out += struct.pack("<I", v)      # word -> little-endian bytes
        else:
            out += struct.pack(">I", v)      # digits already ARE the byte order
    return bytes(out)


def parse_dump(text):
    """-> (bytes, how) where `how` names the format detected."""
    chunks = []          # list of (words, swap)
    how = None

    for line in text.splitlines():
        if "Parcel(Error:" in line:
            # e.g. Parcel(Error: 0xffffffffffffffb6 "Not a data message")
            continue

        m = RE_SERVICE_LINE.match(line)
        if m:
            how = how or "service call hex dump (host-order words)"
            chunks.append((m.group(1).split(), True))
            continue

        m = RE_PROBE_LINE.match(line)
        if m:
            how = how or "binder-probe hex dump (raw bytes)"
            chunks.append((m.group(1).split(), False))
            continue

        m = RE_INLINE.search(line)
        if m:
            # `Result: Parcel(00000000 00000001   '........')` -- this is
            # `service call`'s one-line form, so it is host-order words.
            how = how or "inline Parcel(...) (host-order words)"
            chunks.append((m.group(1).split(), True))
            continue

    if not chunks:
        # Fall back: any bare 8-hex-digit tokens anywhere in the input. We
        # cannot know the convention, so we assume raw bytes and say so.
        loose = re.findall(r"\b[0-9a-fA-F]{8}\b", text)
        if loose:
            return _words_to_bytes(loose, False), \
                   "loose hex words (ASSUMED raw byte order -- use --hex to be sure)"
        return b"", "none"

    out = bytearray()
    for words, swap in chunks:
        out += _words_to_bytes(words, swap)
    return bytes(out), (how or "none")


def parse_hex_string(s):
    """A bare byte string: '1c 00 00 00' or '1c000000'."""
    s = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(s) % 2:
        raise ValueError("odd number of hex digits")
    return bytes(int(s[i:i + 2], 16) for i in range(0, len(s), 2))


# --------------------------------------------------------------------------
# The reader
# --------------------------------------------------------------------------

class Reader(object):
    def __init__(self, data):
        self.d = data
        self.pos = 0
        self.notes = []

    def remaining(self):
        return len(self.d) - self.pos

    def i32(self):
        if self.remaining() < 4:
            raise EOFError("wanted int32 at %d, only %d bytes left"
                           % (self.pos, self.remaining()))
        v = struct.unpack_from("<i", self.d, self.pos)[0]
        self.pos += 4
        return v

    def u32(self):
        if self.remaining() < 4:
            raise EOFError("wanted uint32 at %d, only %d bytes left"
                           % (self.pos, self.remaining()))
        v = struct.unpack_from("<I", self.d, self.pos)[0]
        self.pos += 4
        return v

    def i64(self):
        # int64 and double are 8-BYTE ALIGNED inside a parcel.
        if self.pos % 8:
            self.pos += 8 - (self.pos % 8)
        if self.remaining() < 8:
            raise EOFError("wanted int64 at %d, only %d bytes left"
                           % (self.pos, self.remaining()))
        v = struct.unpack_from("<q", self.d, self.pos)[0]
        self.pos += 8
        return v

    def f32(self):
        if self.remaining() < 4:
            raise EOFError("wanted float at %d" % self.pos)
        v = struct.unpack_from("<f", self.d, self.pos)[0]
        self.pos += 4
        return v

    def f64(self):
        if self.pos % 8:
            self.pos += 8 - (self.pos % 8)
        if self.remaining() < 8:
            raise EOFError("wanted double at %d" % self.pos)
        v = struct.unpack_from("<d", self.d, self.pos)[0]
        self.pos += 8
        return v

    def str16(self):
        """
        int32 CHARACTER count, then that many UTF-16LE units, then a UTF-16
        NUL, padded to 4.

        -1 is NULL, and 0 is the EMPTY string. Those are different on the
        wire and conflating them is the most common hand-rolled-parcel bug
        there is.
        """
        start = self.pos
        n = self.i32()
        if n == -1:
            return None, (start, self.pos)
        if n < 0:
            raise ValueError("negative String16 length %d at offset %d" % (n, start))
        need = (n + 1) * 2
        if self.remaining() < need:
            raise EOFError("String16 of %d chars needs %d bytes, %d left (offset %d)"
                           % (n, need, self.remaining(), start))
        raw = self.d[self.pos:self.pos + n * 2]
        self.pos += need                      # includes the NUL
        while self.pos % 4:
            self.pos += 1
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            s = raw.decode("utf-16-le", "replace")
            self.notes.append("String16 at %d had undecodable units" % start)
        return s, (start, self.pos)

    def str8(self):
        start = self.pos
        n = self.i32()
        if n == -1:
            return None, (start, self.pos)
        need = n + 1
        if self.remaining() < need:
            raise EOFError("String8 of %d bytes, only %d left" % (n, self.remaining()))
        raw = self.d[self.pos:self.pos + n]
        self.pos += need
        while self.pos % 4:
            self.pos += 1
        return raw.decode("utf-8", "replace"), (start, self.pos)

    def bytearr(self):
        start = self.pos
        n = self.i32()
        if n == -1:
            return None, (start, self.pos)
        if n < 0 or n > self.remaining():
            raise ValueError("byte array length %d is not sane at offset %d" % (n, start))
        raw = self.d[self.pos:self.pos + n]
        self.pos += n
        while self.pos % 4:
            self.pos += 1
        return raw, (start, self.pos)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def hexdump(data, indent="  "):
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        out.append("%s%08x  %-47s  |%s|" % (indent, i, hexpart, asc))
    return "\n".join(out)


def field(offset, kind, value, note=""):
    if isinstance(value, str) and len(value) > 96:
        value = value[:93] + "..."
    line = "  [0x%04x] %-10s %s" % (offset, kind, value)
    if note:
        line += "   <- " + note
    return line


# --------------------------------------------------------------------------
# Decoders
# --------------------------------------------------------------------------

def decode_token(r, out):
    """
    The four-field interface-token header, in order:
      int32 strict-mode policy
      int32 work-source uid   (-1 = unset)
      int32 'SYST' magic
      String16 descriptor
    Returns the descriptor, or None if this does not look like a token.
    """
    save = r.pos
    try:
        p0 = r.pos; policy = r.i32()
        p1 = r.pos; ws = r.i32()
        p2 = r.pos; magic = r.u32()
    except EOFError:
        r.pos = save
        return None

    if magic != HEADER_SYST:
        r.pos = save
        return None

    out.append("INTERFACE TOKEN")
    out.append(field(p0, "int32", "0x%08x" % (policy & 0xffffffff),
                     "strict-mode thread policy"))
    out.append(field(p1, "int32", ws,
                     "work-source uid -- CALLER-WRITTEN, never trust it"
                     if ws != UNSET_WORK_SOURCE else "work-source uid, unset"))
    out.append(field(p2, "int32", "0x%08x 'SYST'" % magic, "the parcel magic"))
    try:
        desc, (a, b) = r.str16()
    except (EOFError, ValueError) as e:
        out.append("  !! token magic matched but the descriptor is malformed: %s" % e)
        r.pos = save
        return None
    out.append(field(a, "String16", repr(desc), "the interface descriptor"))
    out.append("")
    return desc


def decode_exception(r, out):
    """
    int32 exception code; if non-zero, a String16 message; and possibly a
    remote stack trace written by Parcel.writeStackTrace():
        int32 header size (bytes from the size field to the end of the trace)
        String16 trace
    Returns the code, or None if this could not be an exception header.
    """
    save = r.pos
    try:
        p0 = r.pos
        code = r.i32()
    except EOFError:
        return None

    if code == 0:
        out.append("EXCEPTION HEADER")
        out.append(field(p0, "int32", 0, "writeNoException() -- the call succeeded"))
        out.append("")
        return 0

    if code not in EXCEPTIONS:
        r.pos = save
        return None

    out.append("EXCEPTION HEADER")
    out.append(field(p0, "int32", code, EXCEPTIONS[code]))
    try:
        msg, (a, _) = r.str16()
        out.append(field(a, "String16", repr(msg), "the exception message"))
    except (EOFError, ValueError):
        out.append("  (no message followed)")
        out.append("")
        return code

    # Optional remote stack trace.
    if r.remaining() >= 8:
        save2 = r.pos
        try:
            hp = r.pos
            hdr_size = r.i32()
            tp = r.pos
            trace, (ta, tb) = r.str16()
            # Sanity: the header size must account for itself, the length
            # field, the UTF-16 payload and its NUL.
            expect = 4 + 4 + (len(trace) * 2) + 2 if trace is not None else None
            ok = expect is not None and abs(hdr_size - expect) <= 4
            out.append(field(hp, "int32", hdr_size,
                             "stack-trace header size%s"
                             % ("" if ok else " -- DOES NOT MATCH, layout is probably wrong")))
            out.append(field(ta, "String16", "%d chars of remote stack trace"
                             % (len(trace) if trace else 0),
                             "FREE RECONNAISSANCE -- see below"))
            if trace:
                out.append("")
                out.append("  REMOTE STACK TRACE")
                for ln in trace.splitlines():
                    if ln.strip():
                        out.append("    " + ln.strip())
                out.append("")
                out.append("  That names the guard method, its class and the line in the")
                out.append("  generated stub. A refused call tells you more than a")
                out.append("  successful one. See README section 3.7.5.")
        except (EOFError, ValueError):
            r.pos = save2
    out.append("")
    return code


def scan_objects(data, out):
    """
    Locate flat_binder_object structures by their 4-byte type magic.

    LABELLED AS SCANNED, NOT DECLARED. The authoritative list is the offsets
    array, which a hex dump does not contain. A coincidental 4-byte match is
    possible; treat a hit whose flags and handle look absurd with suspicion.
    """
    hits = []
    for off in range(0, max(0, len(data) - 3), 4):
        t = struct.unpack_from("<I", data, off)[0]
        if t in OBJECT_TYPES:
            hits.append(off)
    if not hits:
        return

    out.append("EMBEDDED OBJECTS (found by scanning for the type magic)")
    for off in hits:
        name, why = OBJECT_TYPES[struct.unpack_from("<I", data, off)[0]]
        out.append("  at offset 0x%04x: %s" % (off, name))
        out.append("      %s" % why)
        if off + 24 <= len(data):
            flags = struct.unpack_from("<I", data, off + 4)[0]
            handle = struct.unpack_from("<I", data, off + 8)[0]
            cookie = struct.unpack_from("<Q", data, off + 16)[0]
            bits = []
            if flags & FLAT_FLAG_ACCEPTS_FDS:
                bits.append("ACCEPTS_FDS")
            if flags & FLAT_FLAG_TXN_SECURITY_CTX:
                bits.append("TXN_SECURITY_CTX")
            out.append("      flags  = 0x%08x  min-priority=%d%s"
                       % (flags, flags & FLAT_FLAG_PRIORITY_MASK,
                          ("  " + " ".join(bits)) if bits else ""))
            if name in ("BINDER_TYPE_HANDLE", "BINDER_TYPE_WEAK_HANDLE"):
                out.append("      handle = %d   (meaningful ONLY in the receiving process)"
                           % handle)
            elif name == "BINDER_TYPE_FD":
                out.append("      fd     = %d   (a real open descriptor, dup'ed in by the "
                           "kernel; no permission is re-checked on use)" % handle)
            out.append("      cookie = 0x%016x" % cookie)
            # Parcel::writeStrongBinder appends a stability int32 after the object.
            if off + 28 <= len(data):
                stab = struct.unpack_from("<i", data, off + 24)[0]
                if 0 <= stab <= 0x3f:
                    out.append("      then int32 %d -- the stability category "
                               "writeStrongBinder() appends" % stab)
        else:
            out.append("      (truncated -- fewer than 24 bytes remain)")
    out.append("")


def decode_layout(r, spec, out):
    """Decode an explicit --layout list. No guessing at all."""
    out.append("FIELDS (explicit layout)")
    for kind in spec:
        kind = kind.strip().lower()
        try:
            if kind == "token":
                d = decode_token(r, out)
                if d is None:
                    out.append("  !! no interface token here")
            elif kind in ("i32", "int", "int32", "bool"):
                p = r.pos; v = r.i32()
                out.append(field(p, "int32", v,
                                 "boolean" if kind == "bool" else ""))
            elif kind in ("i64", "long", "int64"):
                p = r.pos; v = r.i64()
                out.append(field(p, "int64", v, "8-byte aligned"))
            elif kind in ("f", "float"):
                p = r.pos; out.append(field(p, "float", r.f32()))
            elif kind in ("d", "double"):
                p = r.pos; out.append(field(p, "double", r.f64(), "8-byte aligned"))
            elif kind in ("str16", "string", "s16"):
                v, (a, _) = r.str16()
                out.append(field(a, "String16",
                                 "<null>" if v is None else repr(v)))
            elif kind in ("str8", "s8"):
                v, (a, _) = r.str8()
                out.append(field(a, "String8", "<null>" if v is None else repr(v)))
            elif kind in ("bytes", "bytearray"):
                v, (a, _) = r.bytearr()
                out.append(field(a, "byte[]",
                                 "<null>" if v is None else "%d bytes" % len(v)))
            elif kind in ("exc", "exception"):
                decode_exception(r, out)
            else:
                out.append("  !! unknown layout element %r" % kind)
                return
        except (EOFError, ValueError) as e:
            out.append("  !! %s" % e)
            out.append("  The layout you gave does not match these bytes. "
                       "Because a parcel has no type tags, that failure is the "
                       "ONLY signal you get.")
            return
    if r.remaining():
        out.append("  %d bytes left over -- your layout is incomplete" % r.remaining())


def decode_auto(r, out):
    """
    Best-effort. Try a token, then an exception header, then read what looks
    like plausible fields. Everything after the header is labelled a guess.
    """
    desc = decode_token(r, out)
    if desc is None:
        decode_exception(r, out)

    if r.remaining() == 0:
        return

    out.append("REMAINING FIELDS (GUESSED -- a parcel has no type tags)")
    guard = 0
    while r.remaining() >= 4 and guard < 64:
        guard += 1
        save = r.pos
        # Does a String16 read cleanly and land on a boundary?
        try:
            v, (a, b) = r.str16()
            if v is not None and len(v) > 0 and all(
                    ch == "\t" or ch == "\n" or ord(ch) >= 0x20 for ch in v):
                out.append(field(a, "String16", repr(v), "guess"))
                continue
            r.pos = save
        except (EOFError, ValueError):
            r.pos = save

        p = r.pos
        v = r.i32()
        note = "guess"
        if v in WELL_KNOWN_CODES:
            note = "%s %s" % WELL_KNOWN_CODES[v]
        elif v == -1:
            note = "guess -- -1 is also 'null string' and 'null array'"
        out.append(field(p, "int32", "%d (0x%08x)" % (v, v & 0xffffffff), note))

    if r.remaining():
        out.append("  ... %d bytes not decoded" % r.remaining())
    out.append("")
    out.append("  Everything above marked 'guess' is a guess. Two different")
    out.append("  layouts can both parse cleanly and only one is correct. Get")
    out.append("  the real layout from the .aidl or the decompiled Stub, then")
    out.append("  re-run with --layout.")


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Decode a Binder parcel hex dump into fields.")
    ap.add_argument("file", nargs="?",
                    help="dump file, or '-' for stdin")
    ap.add_argument("--paste", action="store_true",
                    help="read a pasted dump from stdin until EOF")
    ap.add_argument("--hex", metavar="BYTES",
                    help="decode a bare hex byte string instead of a dump")
    ap.add_argument("--as", dest="mode", choices=("auto", "token", "reply", "raw"),
                    default="auto",
                    help="what this parcel is (default: auto)")
    ap.add_argument("--layout",
                    help="comma-separated field types, e.g. token,str16,i32")
    ap.add_argument("--no-hexdump", action="store_true")
    args = ap.parse_args()

    if args.hex:
        data = parse_hex_string(args.hex)
        how = "--hex"
    else:
        if args.paste or args.file == "-" or args.file is None:
            if sys.stdin.isatty() and not args.paste:
                ap.print_help()
                return 2
            if args.paste:
                sys.stderr.write("paste the dump, then EOF "
                                 "(Ctrl-D, or Ctrl-Z then Enter on Windows)\n")
            text = sys.stdin.read()
        else:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        data, how = parse_dump(text)

    if not data:
        sys.stderr.write("no hex found in the input.\n"
                         "Expected `service call` output, binder-probe output, "
                         "or bare 8-digit hex words.\n")
        return 1

    print("PARCEL -- %d bytes, from %s" % (len(data), how))
    print("")
    if not args.no_hexdump:
        print(hexdump(data))
        print("")

    r = Reader(data)
    out = []

    if args.layout:
        decode_layout(r, args.layout.split(","), out)
    elif args.mode == "token":
        d = decode_token(r, out)
        if d is None:
            out.append("  !! no interface token: the 'SYST' magic is not at offset 8")
        decode_auto(r, out)
    elif args.mode == "reply":
        decode_exception(r, out)
        decode_auto(r, out)
    elif args.mode == "raw":
        pass
    else:
        decode_auto(r, out)

    print("\n".join(out))
    scan_objects(data, [])  # placeholder to keep signature symmetrical
    obj_out = []
    scan_objects(data, obj_out)
    if obj_out:
        print("\n".join(obj_out))

    for n in r.notes:
        print("note: %s" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
