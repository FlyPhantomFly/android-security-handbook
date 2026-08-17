#!/usr/bin/env python3
"""
dump-strings.py — recover an application's string literals by parsing the DEX
                  string_ids table, not by scanning for printable byte runs.

WHAT IT DOES
    Reads the DEX header, seeks to string_ids_off, walks string_ids_size
    four-byte offsets, and decodes each string_data_item as Modified UTF-8.
    The result is exactly the set of strings the application declared, in the
    order the table stores them, with no false positives from compiled code
    bytes that happen to look like text.

    Input may be:
      - a raw classes.dex file, or
      - an .apk (or any ZIP), in which case every classes*.dex entry at the
        archive root is processed in order. Multidex is normal: a large app is
        classes.dex, classes2.dex, classes3.dex and so on, and each one has its
        OWN independent string table.

WHY NOT JUST USE `strings`
    `strings -a -n 8 classes.dex` works and is one keystroke, but it scans for
    runs of printable bytes. That means it reports fragments of bytecode,
    fragments of the type table, and pieces of adjacent strings glued together,
    while missing any string containing a byte it considers non-printable. It
    also cannot tell you a string's index, which is the number you need when
    you go looking for the matching `const-string vX, "..."` in Smali.

    On Windows the problem is worse: `strings` there is the Sysinternals tool,
    which has different defaults and different flags from the Unix one. This
    script behaves identically on Windows, macOS and Linux, which is why the
    labs in this chapter point Windows readers at it instead.

WHAT THIS WILL *NOT* TELL YOU
    - WHERE a string is used. The string table is global to the DEX; it has no
      back-pointer to the method that references it. Knowing `hunter2` exists
      is a note; knowing which method holds the `const-string` is a finding.
      For that, baksmali the DEX and grep the Smali, or use jadx.
    - Anything the app never stored as a literal. Strings built at runtime by
      Base64 decoding, XOR, character arithmetic, AES, or native code are not
      in this table by construction. Their absence is itself a signal — see
      ../labs/lab-03-reflection-hunt.md.
    - Strings inside native libraries (lib/*/*.so), inside assets, inside
      resources.arsc, or inside a DEX that a packer decrypts at runtime.
    - Whether a flagged string is actually a vulnerability. --heuristic
      produces LEADS, not findings. Every one needs a human to confirm what it
      is for and whether it is reachable.

HOW TO RUN
    # Whole APK, every classes*.dex, everything in the table
    python3 dump-strings.py target.apk

    # A single DEX, only strings of 6 characters or more
    python3 dump-strings.py classes.dex --min-len 6

    # First-pass triage: flag the strings worth reading first
    python3 dump-strings.py target.apk --min-len 8 --heuristics
    python3 dump-strings.py classes.dex --min-len 4 --heuristic

    # Just the triage worksheet, no full dump
    python3 dump-strings.py target.apk --heuristic --only-flagged

    # Drop class, method, field and type names; keep what is likely a literal
    python3 dump-strings.py classes.dex --literals-only

    # Piping works normally
    python3 dump-strings.py classes.dex --min-len 6 | grep -i hunter

    --heuristic and --heuristics are the same flag. Both spellings are accepted
    so that every command printed in chapter 04 runs verbatim.

REQUIREMENTS
    Python 3.8 or newer. Standard library only — nothing to install.
    Works on Windows, macOS and Linux.

RELATED
    ../README.md section 3.2          why the string table leaks secrets
    ../labs/lab-02-string-and-equals.md   the lab this script was written for
    ../../12-DEX-Internals/README.md  the DEX format, byte by byte
    ../../12-DEX-Internals/examples/dex_parser.py
                                      a full DEX parser; this script is the
                                      focused string-table tool, not a
                                      replacement for it

AUTHORISED TESTING ONLY.
"""

import argparse
import base64
import binascii
import os
import re
import struct
import sys
import textwrap
import zipfile

# ---------------------------------------------------------------------------
# DEX constants. See ../../12-DEX-Internals/README.md and the AOSP reference at
# https://source.android.com/docs/core/runtime/dex-format
# ---------------------------------------------------------------------------

DEX_MAGIC = b"dex\n"
HEADER_SIZE = 0x70

# Byte offsets of the header fields this script needs. The full header is 20
# consecutive uint32 values starting at 0x20; we name only the ones we use.
OFF_STRING_IDS_SIZE = 0x38
OFF_STRING_IDS_OFF = 0x3C
OFF_TYPE_IDS_SIZE = 0x40
OFF_TYPE_IDS_OFF = 0x44
OFF_PROTO_IDS_SIZE = 0x48
OFF_PROTO_IDS_OFF = 0x4C
OFF_FIELD_IDS_SIZE = 0x50
OFF_FIELD_IDS_OFF = 0x54
OFF_METHOD_IDS_SIZE = 0x58
OFF_METHOD_IDS_OFF = 0x5C


class DexError(Exception):
    """Raised when the bytes we were handed are not a DEX we can walk."""


# ---------------------------------------------------------------------------
# Primitive decoders
# ---------------------------------------------------------------------------

def read_uleb128(data, off):
    """
    Unsigned LEB128: a variable-length integer, seven bits per byte, low group
    first, high bit set on every byte except the last. Returns (value, offset
    just past the encoded value).
    """
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise DexError("ULEB128 ran off the end of the file at offset %d" % off)
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
        if shift > 28:
            raise DexError("ULEB128 longer than five bytes — corrupt or crafted file")


def decode_mutf8(raw):
    """
    Decode Modified UTF-8, the encoding DEX uses for every string.

    It differs from standard UTF-8 in exactly two ways, and Python's built-in
    'utf-8' codec rejects both of them, which is why this function exists:

      1. U+0000 is encoded as the two bytes C0 80, never as a single 00 byte.
         That lets a NUL terminate the string data without a NUL ever appearing
         inside the string's own content.
      2. Characters above U+FFFF are encoded CESU-8 style, as a SURROGATE PAIR
         of two three-byte sequences, rather than as one four-byte sequence.
         An emoji in an app's string table therefore occupies six bytes here
         and four bytes in a normal UTF-8 file.

    A genuine four-byte sequence is invalid in MUTF-8. We substitute U+FFFD and
    keep going rather than aborting, because a hand-crafted DEX that contains
    one is exactly the kind of file you still want to read.
    """
    out = []
    i = 0
    n = len(raw)
    pending_high = None  # an unpaired high surrogate we have seen but not used

    def flush_high():
        # A high surrogate with no low surrogate after it is malformed. Emit a
        # replacement character so the result stays printable on every console.
        nonlocal pending_high
        if pending_high is not None:
            out.append("�")
            pending_high = None

    while i < n:
        b = raw[i]
        if b == 0:
            break  # the string_data_item's terminating NUL
        if b < 0x80:
            flush_high()
            out.append(chr(b))
            i += 1
        elif (b & 0xE0) == 0xC0:
            if i + 1 >= n:
                raise DexError("truncated two-byte MUTF-8 sequence")
            cp = ((b & 0x1F) << 6) | (raw[i + 1] & 0x3F)
            flush_high()
            out.append(chr(cp))  # cp == 0 here is the legitimate C0 80 case
            i += 2
        elif (b & 0xF0) == 0xE0:
            if i + 2 >= n:
                raise DexError("truncated three-byte MUTF-8 sequence")
            cp = ((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F)
            i += 3
            if 0xD800 <= cp <= 0xDBFF:
                flush_high()
                pending_high = cp
            elif 0xDC00 <= cp <= 0xDFFF:
                if pending_high is None:
                    out.append("�")
                else:
                    astral = 0x10000 + ((pending_high - 0xD800) << 10) + (cp - 0xDC00)
                    out.append(chr(astral))
                    pending_high = None
            else:
                flush_high()
                out.append(chr(cp))
        else:
            flush_high()
            out.append("�")
            i += 1

    flush_high()
    return "".join(out)


# ---------------------------------------------------------------------------
# The string table reader
# ---------------------------------------------------------------------------

class DexStringTable(object):
    """
    A deliberately narrow view of a DEX: the header fields needed to find the
    string table, plus the index tables needed to tell a class or method name
    apart from an ordinary literal.
    """

    def __init__(self, data, label):
        self.data = data
        self.label = label
        self.warnings = []
        self._parse_header()

    # ------------------------------------------------------------- header --

    def _parse_header(self):
        d = self.data
        if len(d) < HEADER_SIZE:
            raise DexError(
                "file is only %d bytes; a DEX header alone is %d bytes"
                % (len(d), HEADER_SIZE))

        if d[0:4] != DEX_MAGIC:
            raise DexError(describe_not_dex(d))

        self.version = d[4:7].decode("ascii", "replace")

        def u32(off):
            return struct.unpack_from("<I", d, off)[0]

        self.string_ids_size = u32(OFF_STRING_IDS_SIZE)
        self.string_ids_off = u32(OFF_STRING_IDS_OFF)
        self.type_ids_size = u32(OFF_TYPE_IDS_SIZE)
        self.type_ids_off = u32(OFF_TYPE_IDS_OFF)
        self.proto_ids_size = u32(OFF_PROTO_IDS_SIZE)
        self.proto_ids_off = u32(OFF_PROTO_IDS_OFF)
        self.field_ids_size = u32(OFF_FIELD_IDS_SIZE)
        self.field_ids_off = u32(OFF_FIELD_IDS_OFF)
        self.method_ids_size = u32(OFF_METHOD_IDS_SIZE)
        self.method_ids_off = u32(OFF_METHOD_IDS_OFF)

        end = self.string_ids_off + self.string_ids_size * 4
        if self.string_ids_size and end > len(d):
            raise DexError(
                "string_ids table claims %d entries at offset 0x%x, which runs "
                "past the end of a %d-byte file. The header is lying — this is "
                "either a truncated download or a deliberately malformed DEX."
                % (self.string_ids_size, self.string_ids_off, len(d)))

        file_size = u32(0x20)
        if file_size != len(d):
            self.warnings.append(
                "header.file_size is %d but the file is %d bytes (%+d). "
                "Trailing data after a DEX is a packer fingerprint; see "
                "dex_parser.py --map-coverage in chapter 12."
                % (file_size, len(d), len(d) - file_size))

    # ------------------------------------------------------------ strings --

    def string_at(self, idx):
        """
        Resolve one string_ids index.

        The table at string_ids_off is an array of uint32 file offsets. Each
        one points at a string_data_item: a ULEB128 giving the length in UTF-16
        code units, then the MUTF-8 bytes, then a NUL.
        """
        (data_off,) = struct.unpack_from("<I", self.data, self.string_ids_off + idx * 4)
        utf16_size, p = read_uleb128(self.data, data_off)
        end = self.data.find(b"\x00", p)
        if end == -1:
            raise DexError("string #%d is not NUL-terminated before EOF" % idx)
        text = decode_mutf8(self.data[p:end])

        # utf16_size counts UTF-16 code units, so an astral character counts as
        # two while Python's len() counts it as one. A mismatch beyond that is
        # a parser-divergence signal: the runtime and your tools will disagree
        # about this string, which packers exploit.
        units = sum(2 if ord(c) > 0xFFFF else 1 for c in text)
        if units != utf16_size:
            self.warnings.append(
                "string #%d declares %d UTF-16 units but decodes to %d"
                % (idx, utf16_size, units))
        return text

    def strings(self):
        """Yield (index, text) in table order. Unreadable entries are skipped."""
        for i in range(self.string_ids_size):
            try:
                yield i, self.string_at(i)
            except DexError as exc:
                self.warnings.append("string #%d: %s" % (i, exc))

    # --------------------------------------------------------- structural --

    def structural_indices(self):
        """
        Return the set of string indices referenced by the type, prototype,
        field and method tables — that is, every string that exists because it
        names something rather than because a developer typed it in quotes.

        This is an approximation and it is deliberately conservative. The
        string table is deduplicated, so a literal that happens to equal a
        method name shares one entry and will be classified as structural. Use
        --literals-only to cut noise, never to prove absence.
        """
        used = set()
        d = self.data

        for i in range(self.type_ids_size):
            (descriptor_idx,) = struct.unpack_from("<I", d, self.type_ids_off + i * 4)
            used.add(descriptor_idx)

        for i in range(self.proto_ids_size):
            (shorty_idx,) = struct.unpack_from("<I", d, self.proto_ids_off + i * 12)
            used.add(shorty_idx)

        # field_id_item: class_idx u16, type_idx u16, name_idx u32
        for i in range(self.field_ids_size):
            (name_idx,) = struct.unpack_from("<I", d, self.field_ids_off + i * 8 + 4)
            used.add(name_idx)

        # method_id_item: class_idx u16, proto_idx u16, name_idx u32
        for i in range(self.method_ids_size):
            (name_idx,) = struct.unpack_from("<I", d, self.method_ids_off + i * 8 + 4)
            used.add(name_idx)

        return used


def describe_not_dex(head):
    """
    Build an error message that tells the reader what they actually handed us
    and what to do next. "bad magic" on its own has cost more people more time
    than any other message in reverse engineering.
    """
    prefix = "this is not a DEX file: the first four bytes are %s, expected %r" % (
        " ".join("%02x" % b for b in head[:4]), DEX_MAGIC)

    known = [
        (b"\xca\xfe\xba\xbe", "a Java .class file (magic 0xCAFEBABE). A .class holds "
                              "ONE class in JVM bytecode; a .dex holds many in Dalvik "
                              "bytecode. Convert it first:\n"
                              "        d8 --min-api 21 Your.class --output .\n"
                              "    then point this script at the classes.dex that "
                              "produces."),
        (b"PK\x03\x04", "a ZIP archive — an APK, AAB, JAR or plain ZIP. Pass the "
                        "archive path directly and this script will read every "
                        "classes*.dex inside it."),
        (b"dey\n", "a Dalvik-era ODEX (magic 'dey\\n'), not a DEX."),
        (b"cdex", "a CompactDex (magic 'cdex'), the layout ART uses inside .vdex "
                  "files. Extract the standard DEX first, for example with "
                  "vdexExtractor, or pull classes.dex from the APK instead."),
        (b"vdex", "a .vdex file. The DEX payload is inside it; extract it first."),
        (b"\x7fELF", "an ELF binary — a native .so or executable, not Java at all. "
                     "Strings there live in .rodata; use a native tool."),
        (b"\x1f\x8b", "a gzip stream. Decompress it first."),
        (b"\x03\x00\x08\x00", "a binary AndroidManifest.xml or compiled resource. "
                              "Use apktool or aapt2 to decode it."),
    ]
    for magic, explanation in known:
        if head[:len(magic)] == magic:
            return prefix + "\n\n    That looks like " + explanation + _apk_name_hint()

    return prefix + (
        "\n\n    Nothing recognised. Check the first eight bytes yourself:\n"
        "        od -A d -t x1 -N 8 classes.dex        # any Unix\n"
        "        Format-Hex -Path classes.dex -Count 8 # Windows PowerShell\n"
        "    A real DEX starts 64 65 78 0a followed by three version digits and "
        "a NUL,\n    for example 64 65 78 0a 30 33 35 00 for version 035."
        + _apk_name_hint())


def _apk_name_hint():
    return (
        "\n\n    If you passed an APK and got here, its DEX may be stored under a "
        "name\n    other than classes*.dex — packers and some obfuscators do that. "
        "List the\n    archive with `unzip -l app.apk | grep -i dex` and pass the "
        "extracted file\n    directly.")


# ---------------------------------------------------------------------------
# Heuristics — leads, not findings
# ---------------------------------------------------------------------------

# Framework and specification URLs that appear in essentially every APK. They
# are excluded from flagging so the worksheet stays readable; the count of
# suppressed strings is always reported so nothing disappears silently.
KNOWN_NOISE = (
    "schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
    "java.sun.com",
    "xml.org/sax",
    "apache.org/xml",
    "docs.oracle.com",
    "kotlinlang.org",
    "developer.android.com",
)

_RE_URL = re.compile(r"(?i)\b(?:https?|ftps?|wss?|file|content|market|intent)://")
_RE_CLOUD = re.compile(
    r"(?i)\.(?:amazonaws|firebaseio|appspot|cloudfront|herokuapp|blob\.core\.windows)"
    r"\.(?:com|net)\b")

_RE_VENDOR_KEY = re.compile(
    r"(AKIA[0-9A-Z]{16})"                       # AWS access key id
    r"|(AIza[0-9A-Za-z_\-]{35})"                # Google API key
    r"|([sr]k_(?:live|test)_[0-9A-Za-z]{10,})"  # Stripe
    r"|(xox[abprs]-[0-9A-Za-z\-]{10,})"         # Slack
    r"|(gh[pousr]_[0-9A-Za-z]{20,})"            # GitHub
)
_RE_KEY_WORD = re.compile(
    r"(?i)\b(api[_\-]?key|apikey|client[_\-]?secret|access[_\-]?key|"
    r"consumer[_\-]?key|x-api-key)\b")

_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.")
_RE_TOKEN_WORD = re.compile(
    r"(?i)(\bbearer\b|auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|"
    r"session[_\-]?token|id[_\-]?token|\btoken\b)")

_RE_PASSWORD = re.compile(r"(?i)(password|passwd|passphrase|\bpwd\b)")
_RE_SECRET = re.compile(r"(?i)(secret|credential|keystore|\bpin\b|private[_\-]?key)")

_RE_PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE|RSA|EC)")

_RE_DBCONN = re.compile(
    r"(?i)(^jdbc:|^mongodb(\+srv)?://|^postgres(ql)?://|^mysql://|^redis://|"
    r"^amqp://|data source=|initial catalog=|integrated security=|;password=|;pwd=)")

_RE_IP = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b(?!\.\d)")

_RE_B64 = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")
_RE_PATHISH = re.compile(r"^[A-Za-z0-9_$]+(?:/[A-Za-z0-9_$]+)+$")


def _looks_like_text(raw):
    if not raw:
        return False
    printable = sum(1 for c in raw if 0x20 <= c < 0x7F or c in (9, 10, 13))
    return printable / float(len(raw)) >= 0.85


def _m_privkey(s):
    return "PEM header present" if _RE_PRIVKEY.search(s) else None


def _m_dbconn(s):
    m = _RE_DBCONN.search(s)
    return "matches %r" % m.group(0) if m else None


def _m_apikey(s):
    m = _RE_VENDOR_KEY.search(s)
    if m:
        return "vendor key format: %s" % m.group(0)[:24]
    m = _RE_KEY_WORD.search(s)
    return "names a key: %r" % m.group(0) if m else None


def _m_token(s):
    if _RE_JWT.search(s):
        return "looks like a JWT (three dot-separated base64url segments)"
    m = _RE_TOKEN_WORD.search(s)
    return "names a token: %r" % m.group(0) if m else None


def _m_url(s):
    m = _RE_URL.search(s)
    if m:
        return "scheme %r" % m.group(0)
    m = _RE_CLOUD.search(s)
    return "cloud host %r" % m.group(0) if m else None


def _m_password(s):
    m = _RE_PASSWORD.search(s)
    return "mentions %r" % m.group(0) if m else None


def _m_secret(s):
    m = _RE_SECRET.search(s)
    return "mentions %r" % m.group(0) if m else None


def _m_base64(s):
    if _RE_PATHISH.match(s):
        return None  # java/lang/String and friends are not base64
    if not _RE_B64.match(s) or len(s) % 4:
        return None
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    if (has_upper + has_lower + has_digit) < 2:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    if _looks_like_text(raw):
        return "decodes to text: %r" % raw.decode("utf-8", "replace")[:60]
    if len(s) >= 24 and has_upper and has_lower and has_digit:
        return "high-entropy blob, %d bytes when decoded" % len(raw)
    return None


def _m_ip(s):
    for match in _RE_IP.finditer(s):
        octets = match.group(1).split(".")
        if all(o and len(o) <= 3 and int(o) <= 255 for o in octets):
            if match.group(1) in ("0.0.0.0", "255.255.255.255"):
                continue
            return "literal address %s" % match.group(1)
    return None


# (key, heading, why it matters, matcher). Order is triage order: the things
# that are almost always real come first.
HEURISTICS = [
    ("PRIVKEY", "Private key or certificate material",
     "A PEM header in a shipped artefact means the private half of a key pair, "
     "or a pinned certificate, is in the hands of anyone who downloads the app.",
     _m_privkey),
    ("DBCONN", "Database / message-broker connection string",
     "A client that talks to a database directly has published the credentials "
     "and usually bypasses every server-side authorisation check.",
     _m_dbconn),
    ("APIKEY", "API key",
     "Vendor key formats are unambiguous. Generic key words need one look to "
     "decide whether the value is next to them or fetched at runtime.",
     _m_apikey),
    ("TOKEN", "Token / bearer credential",
     "A JWT baked into the DEX is a static credential. Decode the payload and "
     "read its claims and expiry before deciding severity.",
     _m_token),
    ("URL", "URL, endpoint or non-HTTP scheme",
     "Endpoints map the backend attack surface. content:// and intent:// "
     "schemes map the app's own IPC surface.",
     _m_url),
    ("PASSWORD", "Mentions a password",
     "Usually a field name, a log message or a JSON key. Occasionally the "
     "value itself is the very next entry in the table.",
     _m_password),
    ("SECRET", "Mentions a secret, credential, keystore or PIN",
     "Same reasoning as PASSWORD. Cheap to read, occasionally decisive.",
     _m_secret),
    ("BASE64", "Base64-looking blob",
     "Encoding is not encryption. If it decodes to text you have just defeated "
     "the obfuscation; if it decodes to bytes, note the length and look for the "
     "decrypt routine.",
     _m_base64),
    ("IP", "Hardcoded IP address",
     "Hardcoded addresses skip DNS and often skip certificate validation with "
     "it. 10.0.2.2 is the Android emulator's view of the host, which means "
     "debug configuration shipped to production.",
     _m_ip),
]


def classify(s):
    """Return a list of (key, detail) for every heuristic that matched."""
    if any(noise in s for noise in KNOWN_NOISE):
        return []
    hits = []
    for key, _heading, _why, matcher in HEURISTICS:
        detail = matcher(s)
        if detail:
            hits.append((key, detail))
    return hits


def is_known_noise(s):
    return any(noise in s for noise in KNOWN_NOISE)


# ---------------------------------------------------------------------------
# Input handling: a raw DEX, or every classes*.dex in an archive
# ---------------------------------------------------------------------------

_RE_CLASSES_DEX = re.compile(r"^classes(\d*)\.dex$")


def _dex_sort_key(name):
    """classes.dex, classes2.dex, classes10.dex — numeric, not lexicographic."""
    match = _RE_CLASSES_DEX.match(name)
    digits = match.group(1) if match else ""
    return int(digits) if digits else 1


def load_dex_blobs(path):
    """
    Yield (label, bytes) for each DEX to process.

    Dispatch is by content, not by file extension, so a DEX named `payload.bin`
    and an APK named `target.zip` both work.
    """
    if os.path.isdir(path):
        raise DexError(
            "%s is a directory. Pass a .dex file or an .apk, not a folder. If "
            "you have an unpacked APK, its DEX files are at the top level of "
            "that folder." % path)

    with open(path, "rb") as handle:
        head = handle.read(8)

    if head[:4] == DEX_MAGIC:
        with open(path, "rb") as handle:
            yield os.path.basename(path), handle.read()
        return

    if head[:2] != b"PK":
        with open(path, "rb") as handle:
            raise DexError(describe_not_dex(handle.read(8)))

    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise DexError("%s starts like a ZIP but will not open: %s" % (path, exc))

    with archive:
        names = [n for n in archive.namelist() if _RE_CLASSES_DEX.match(n)]
        if not names:
            other = [n for n in archive.namelist() if n.lower().endswith(".dex")]
            message = (
                "%s is a ZIP archive but contains no classes*.dex at its root.\n\n"
                "    An ordinary APK has classes.dex, and for multidex also "
                "classes2.dex,\n    classes3.dex and so on, all at the top level "
                "of the archive." % path)
            if other:
                message += (
                    "\n\n    It does contain these .dex entries elsewhere, which is "
                    "what a packer\n    or a plugin architecture looks like. Extract "
                    "one and pass it directly:\n"
                    + "".join("        %s\n" % n for n in other[:20]))
            else:
                message += (
                    "\n\n    No .dex entry anywhere in the archive. Likely causes: it "
                    "is a JAR or an\n    AAB rather than an APK, it is a split APK "
                    "that carries only resources, or\n    a packer stores the real "
                    "DEX encrypted under assets/ or lib/.")
            raise DexError(message)

        for name in sorted(names, key=_dex_sort_key):
            yield "%s :: %s" % (os.path.basename(path), name), archive.read(name)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_CONTROL = {ord("\n"): "\\n", ord("\r"): "\\r", ord("\t"): "\\t"}


def escape(s):
    """Make a string safe to print on one line, on any console."""
    out = []
    for ch in s:
        code = ord(ch)
        if code in _CONTROL:
            out.append(_CONTROL[code])
        elif code < 0x20 or code == 0x7F:
            out.append("\\x%02x" % code)
        else:
            out.append(ch)
    return "".join(out)


def rule(char="-", width=78):
    return char * width


def main():
    # Windows consoles default to a legacy code page and will raise on the
    # first non-ASCII string in the table. UTF-8 with replacement keeps the
    # tool usable everywhere, including when piped into grep or a file. Do this
    # before argparse runs, so --help renders correctly too.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

    parser = argparse.ArgumentParser(
        prog="dump-strings.py",
        description="Dump the DEX string_ids table from a .dex or an .apk. "
                    "Parses the table directly; does not scan for printable runs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "notes:\n"
            "  --heuristic and --heuristics are aliases for the same flag. Both\n"
            "  spellings work so that every command printed in chapter 04 runs\n"
            "  verbatim.\n\n"
            "  Output is in string_ids table order by default. That table is\n"
            "  sorted by UTF-16 code point, which is why the order looks strange\n"
            "  but is perfectly consistent between runs. Use --sorted for a\n"
            "  human reading order; use table order when you need indices to\n"
            "  line up with another tool.\n\n"
            "  Heuristic hits are LEADS. Confirm each one against the Smali\n"
            "  before it goes anywhere near a report.\n"))

    parser.add_argument("path", help="a .dex file, or an .apk (every classes*.dex "
                                     "at the archive root is processed)")
    parser.add_argument("--min-len", type=int, default=1, metavar="N",
                        help="hide strings shorter than N characters "
                             "(default: 1, i.e. show everything; 8 is a good "
                             "first-pass value on a real APK)")
    parser.add_argument("--heuristic", "--heuristics", action="store_true",
                        dest="heuristic",
                        help="flag likely-interesting strings and print a grouped "
                             "triage worksheet at the end (both spellings accepted)")
    parser.add_argument("--only-flagged", action="store_true",
                        help="with --heuristic, print only the worksheet and skip "
                             "the full dump")
    parser.add_argument("--literals-only", action="store_true",
                        help="hide strings that the type, prototype, field or "
                             "method tables reference, leaving what is most likely "
                             "a developer-written literal (approximate — see the "
                             "header comment)")
    parser.add_argument("--sorted", action="store_true",
                        help="sort output alphabetically instead of preserving "
                             "string_ids table order")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress per-DEX headers and parser warnings")

    args = parser.parse_args()

    if args.only_flagged and not args.heuristic:
        parser.error("--only-flagged needs --heuristic (or --heuristics)")
    if args.min_len < 0:
        parser.error("--min-len cannot be negative")

    try:
        blobs = list(load_dex_blobs(args.path))
    except DexError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except OSError as exc:
        sys.stderr.write("error: cannot read %s: %s\n" % (args.path, exc))
        return 1

    grand_total = 0
    grand_shown = 0
    grand_noise = 0
    flagged = {}          # key -> list of (label, index, text, detail)
    exit_code = 0

    for label, data in blobs:
        try:
            dex = DexStringTable(data, label)
        except DexError as exc:
            sys.stderr.write("error: %s: %s\n" % (label, exc))
            exit_code = 2
            continue

        structural = dex.structural_indices() if args.literals_only else set()

        rows = []
        for index, text in dex.strings():
            grand_total += 1
            if len(text) < args.min_len:
                continue
            if index in structural:
                continue
            rows.append((index, text))

        if args.sorted:
            rows.sort(key=lambda r: (r[1].lower(), r[0]))

        show_dump = not args.only_flagged
        if show_dump and not args.quiet:
            print("")
            print(rule("="))
            print(" %s" % label)
            print(" DEX version %s   string_ids_size=%d   table at 0x%x"
                  % (dex.version, dex.string_ids_size, dex.string_ids_off))
            print(rule("="))

        for index, text in rows:
            grand_shown += 1
            hits = []
            if args.heuristic:
                if is_known_noise(text):
                    grand_noise += 1
                else:
                    hits = classify(text)
                    for key, detail in hits:
                        flagged.setdefault(key, []).append((label, index, text, detail))
            if args.only_flagged:
                continue
            marker = ("   << " + ",".join(k for k, _ in hits)) if hits else ""
            print("  [%6d]  %s%s" % (index, escape(text), marker))

        if show_dump and not args.quiet:
            hidden = dex.string_ids_size - len(rows)
            print(rule())
            print("  %d strings in the table, %d shown, %d hidden by filters"
                  % (dex.string_ids_size, len(rows), hidden))
            if dex.warnings:
                print("")
                print("  parser warnings:")
                for warning in dex.warnings[:20]:
                    print("    ! %s" % warning)
                if len(dex.warnings) > 20:
                    print("    ! ... and %d more" % (len(dex.warnings) - 20))

    # --------------------------------------------------------- worksheet ---

    if args.heuristic:
        total_hits = sum(len(v) for v in flagged.values())
        print("")
        print(rule("="))
        print(" HEURISTIC TRIAGE — %d hit(s) across %d categor%s"
              % (total_hits, len(flagged), "y" if len(flagged) == 1 else "ies"))
        print(rule("="))

        if not flagged:
            print("")
            print("  Nothing matched. That is a result, not a clean bill of health.")
            print("  Read ../labs/lab-03-reflection-hunt.md: an app whose string")
            print("  table contains no interesting strings at all is either very")
            print("  small or is building its strings at runtime, and the second")
            print("  case is the more interesting one.")
        else:
            for key, heading, why, _matcher in HEURISTICS:
                entries = flagged.get(key)
                if not entries:
                    continue
                print("")
                print(" %s — %s (%d)" % (key, heading, len(entries)))
                print(textwrap.fill(why, width=76,
                                    initial_indent="   why it matters: ",
                                    subsequent_indent="   "))
                print("")
                for label, index, text, detail in entries:
                    print("   [%6d] %s" % (index, escape(text)))
                    print("            %s   (%s)" % (detail, label))

        if grand_noise:
            print("")
            print("  %d string(s) were skipped as known framework constants "
                  "(schemas.android.com," % grand_noise)
            print("  w3.org and similar). Drop --heuristic to see them in the "
                  "full dump.")

        print("")
        print(rule())
        print("  These are LEADS. A hit tells you a string exists, not that it is")
        print("  reachable, not that it is used, and not that it is a finding. The")
        print("  next step is always the same: baksmali the DEX and grep the Smali")
        print("  for the string to learn which method holds the const-string.")
        print(rule())

    if not args.quiet and len(blobs) > 1:
        print("")
        print("  Across %d DEX files: %d strings in total, %d printed."
              % (len(blobs), grand_total, grand_shown))
        print("  Each DEX has its own independent string table, so indices repeat.")

    print("")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
