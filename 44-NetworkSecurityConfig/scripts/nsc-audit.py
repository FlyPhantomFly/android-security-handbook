#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nsc-audit.py — pull the Network Security Config out of an APK, resolve the
               `@xml/...` reference, decode the binary XML, and report every
               trust decision it makes with a verdict and a next step.

WHAT IT DOES
    An app's network trust policy is not in the manifest. The manifest holds a
    32-bit resource ID:

        android:networkSecurityConfig=@0x7f0b0000

    That number means nothing until you resolve it against resources.arsc, which
    turns it into a path — `res/xml/alt_network_security_config.xml` — and that
    file is stored as Android binary XML (AXML), not text. Three steps stand
    between a tester and the file that decides whether their proxy works. This
    script does all three, and then reads the result:

      1. Extract AndroidManifest.xml from the APK and decode it.
      2. Read `android:networkSecurityConfig`, `android:usesCleartextTraffic`,
         `android:debuggable` and `targetSdkVersion` from <application>/<uses-sdk>.
      3. Resolve the resource ID through a minimal resources.arsc reader to a
         `res/xml/...` path, extract that entry, decode it, and model the
         document as the platform models it: <base-config>, <domain-config>
         (nested, with inheritance), <trust-anchors>, <certificates>, <pin-set>
         and <debug-overrides>.

    It then applies the rules in ../README.md sections 3 and 5 and prints
    findings with a severity, the evidence, and what to do next.

    Where a <certificates src="@raw/..."> entry points at a bundled certificate,
    the script extracts the DER, computes its SHA-256 SubjectPublicKeyInfo pin
    (the same value <pin digest="SHA-256"> holds) and tells you whether any pin
    in the document actually matches it.

WHY THIS EXISTS AND WHAT IT DELIBERATELY DOES NOT DO
    Chapter 32 owns the manifest audit; ../../32-Manifest/scripts/manifest-audit.py
    is the manifest scanner and this is NOT a second one. It reads exactly four
    manifest attributes, and only because they change what the config MEANS.

    Chapter 10 owns Android binary XML at the byte level. The AXML decoding here
    is done by importing ../../10-APK-Internals/examples/parse_axml.py, not by
    reimplementing it. If that file is missing, this script says so and stops
    rather than guessing.

    Chapter 36 owns defeating a pin at runtime. This script reads a pin-set as a
    DECLARATION: how many pins, when they expire, whether they can still bite.

WHAT THIS WILL *NOT* TELL YOU
    - What the platform actually built. This is a host-side read of a file. The
      authority is the running app, because inheritance, resource overlays, split
      APKs and OEM patches all happen after this file is written. Run
      ./nsc-runtime.js under Frida and compare. Where they differ, the device is
      right and the difference is the finding.
    - Whether the app honours its own config. Nothing here is enforced on raw
      sockets, on a bundled BoringSSL, on Flutter's Dart:io stack, or inside a
      custom TrustManager the app installs itself. `cleartextTrafficPermitted="false"`
      is a promise made by cooperating libraries, not a firewall. Capture packets.
    - Whether the app pins in code as well. OkHttp CertificatePinner, TrustKit and
      a hand-written X509TrustManager are invisible here. An app with no <pin-set>
      may still pin. See chapter 36, 36-CertificatePinning.
    - Resource overlays and RRO. A device-side overlay can replace res/xml/*
      after install. This reads the APK only.
    - Split APKs. Pass every split you have; a config can live in any of them.
    - Whether a finding matters. Severity here is the SHAPE of the defect. Impact
      needs the endpoint, the data on it, and a capture proving traffic flows.

HOW TO RUN
    # host - the normal case, everything from the APK
    python3 -B nsc-audit.py base.apk

    # host - print the decoded config as XML as well
    python3 -B nsc-audit.py base.apk --xml

    # host - a config you already have as text (apktool output, or app source)
    python3 -B nsc-audit.py work/res/xml/network_security_config.xml \\
            --target-sdk 30 --debuggable false

    # host - machine readable, and CI gating
    python3 -B nsc-audit.py base.apk --json
    python3 -B nsc-audit.py base.apk --fail-on HIGH

    # host - pull the APK off the device first
    adb shell pm path com.example.app
    adb pull /data/app/.../base.apk
    python3 -B nsc-audit.py base.apk

    Run it with `python3 -B`. This script imports parse_axml.py by path, and an
    import writes a __pycache__ next to the imported file unless bytecode is
    disabled. The script sets sys.dont_write_bytecode itself before importing,
    but -B is the belt to that braces: a module loaded through
    importlib.util.module_from_spec writes bytecode even when
    PYTHONDONTWRITEBYTECODE is set in the environment, and a __pycache__ has
    twice appeared under a scripts/ directory in this repository from exactly
    that pattern.

    On Windows, if a config contains non-ASCII text (they do - one real config
    in this chapter's README carries a Chinese comment), set PYTHONIOENCODING=utf-8
    or the console codec will raise UnicodeEncodeError halfway through the tree.

REQUIREMENTS
    Python 3.8+. Standard library only.
    ../../10-APK-Internals/examples/parse_axml.py must be present. Override its
    location with --parse-axml PATH or the NSC_PARSE_AXML environment variable.

EXIT CODES
    0  ran, and nothing at or above --fail-on
    1  a finding at or above --fail-on (default: nothing fails)
    2  input could not be read or decoded

AUTHORISED TESTING ONLY. Reading an APK you were given is fine. Reading one you
pulled off someone else's phone is not.
"""

import sys

# Set BEFORE the parse_axml import below. importlib's SourceLoader consults this
# flag when it decides whether to cache bytecode, so setting it here is what
# stops a __pycache__ appearing next to 10-APK-Internals/examples/.
sys.dont_write_bytecode = True

import argparse           # noqa: E402
import base64             # noqa: E402
import datetime           # noqa: E402
import hashlib            # noqa: E402
import importlib.util     # noqa: E402
import json               # noqa: E402
import os                 # noqa: E402
import re                 # noqa: E402
import struct             # noqa: E402
import zlib               # noqa: E402

# ----------------------------------------------------------------------------
# severity model - same ladder as 32-Manifest/scripts/manifest-audit.py so that
# findings from the two tools can be merged into one report without rescaling.
# ----------------------------------------------------------------------------

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "POSITIVE"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# resources.arsc chunk types - ResourceTypes.h
RES_TABLE_TYPE = 0x0002
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203

# ResTable_type.flags
FLAG_SPARSE = 0x01
FLAG_OFFSET16 = 0x02

# ResTable_entry.flags
ENTRY_FLAG_COMPLEX = 0x0001
ENTRY_FLAG_COMPACT = 0x0008

TYPE_STRING = 0x03
TYPE_REFERENCE = 0x01
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_DEC = 0x10

NO_ENTRY = 0xFFFFFFFF

# Digest algorithms the platform accepts in <pin digest="...">. Pin.java has the
# authoritative list; on every release this chapter has checked it is SHA-256
# only, and SHA-1 support was removed long before it.
SUPPORTED_DIGESTS = {"SHA-256": 32}

# Elements and attributes the platform's XmlConfigSource knows about. Anything
# else is not "ignored" - see finding NSC-020.
KNOWN_ELEMENTS = {
    "network-security-config", "base-config", "domain-config", "domain",
    "trust-anchors", "certificates", "pin-set", "pin", "debug-overrides",
}
KNOWN_ATTRS = {
    "network-security-config": set(),
    "base-config": {"cleartextTrafficPermitted", "hstsEnforced"},
    "domain-config": {"cleartextTrafficPermitted", "hstsEnforced"},
    "domain": {"includeSubdomains"},
    "trust-anchors": set(),
    "certificates": {"src", "overridePins"},
    "pin-set": {"expiration"},
    "pin": {"digest"},
    "debug-overrides": set(),
}


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


class AuditError(Exception):
    """Something we cannot recover from - bad input, missing dependency."""


def parse_expiration(text):
    """Parse a <pin-set expiration> the way the PLATFORM does, not the way a
    strict parser would.

    XmlConfigSource uses `new SimpleDateFormat("yyyy-MM-dd")`, and
    SimpleDateFormat is LENIENT unless setLenient(false) is called. A lenient
    parse does not reject an out-of-range field - it carries it into the next
    unit, exactly as java.util.Calendar does. So:

        2021-07-1    -> 2021-07-01     (an un-padded day is simply fine)
        2023-02-29   -> 2023-03-01     (2023 is not a leap year; the day rolls)
        2024-02-29   -> 2024-02-29     (2024 IS a leap year; no rollover)
        2025-13-01   -> 2026-01-01     (the month rolls into the next year)

    Returns (datetime or None, rolled_over_from or None). The second element is
    non-None only when the written value is not a real calendar date and the
    platform's leniency changed it, which is a finding in its own right: the
    date a linter reports and the date the device uses are different.
    """
    if not text:
        return None, None
    m = re.match(r"^\s*(\d{4})-(\d{1,2})-(\d{1,2})\s*$", text)
    if not m:
        return None, None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        return datetime.datetime(y, mo, d), None
    except ValueError:
        pass
    # Lenient: month-1 months after January of that year, then day-1 days.
    total = mo - 1
    y += total // 12
    mo = total % 12 + 1
    try:
        base = datetime.datetime(y, mo, 1)
    except ValueError:
        return None, None
    return base + datetime.timedelta(days=d - 1), text.strip()


# ----------------------------------------------------------------------------
# 1. borrow chapter 10's AXML parser rather than writing a fourth one
# ----------------------------------------------------------------------------

def load_parse_axml(explicit=None):
    """Import 10-APK-Internals/examples/parse_axml.py by path.

    The chapter's whole argument about tool divergence rests on there being ONE
    parser in this repository whose behaviour is understood. Importing it is
    deliberate. Copying it would create a second implementation that drifts."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("NSC_PARSE_AXML")
    if env:
        candidates.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(
        here, "..", "..", "10-APK-Internals", "examples", "parse_axml.py"))
    candidates.append(os.path.join(os.getcwd(), "parse_axml.py"))

    for cand in candidates:
        cand = os.path.normpath(cand)
        if not os.path.isfile(cand):
            continue
        spec = importlib.util.spec_from_file_location("parse_axml_for_nsc", cand)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod, cand

    raise AuditError(
        "could not find parse_axml.py. This script decodes Android binary XML "
        "with chapter 10's parser rather than shipping a second copy.\n"
        "Looked in:\n  " + "\n  ".join(os.path.normpath(c) for c in candidates) +
        "\nPass --parse-axml PATH or set NSC_PARSE_AXML.")


# ----------------------------------------------------------------------------
# 2. resources.arsc: turn 0x7f0b0000 into "res/xml/alt_network_security_config.xml"
# ----------------------------------------------------------------------------

class ResourceTable:
    """A deliberately small resources.arsc reader.

    It answers exactly one question - "what file does this resource ID name?" -
    because that is the only question this chapter needs. `aapt2 dump resources`
    answers it too and is a good cross-check; this exists so the script has no
    dependency on the Android SDK being installed.

    A resource ID is three fields packed into 32 bits:

        0x7f      0b       0000
        package   type     entry index

    Resolution walks: the package chunk whose id matches, then every
    RES_TABLE_TYPE_TYPE chunk carrying that type id (one per resource
    qualifier - one for default, one for -v21, one for -xhdpi and so on), then
    the entry at that index inside each. A file resource's value is a
    TYPE_STRING whose data indexes the table's GLOBAL value string pool, and the
    string there is the archive path."""

    def __init__(self, data, string_pool_cls, report):
        self.data = data
        self.report = report
        self.value_pool = None
        self.packages = {}          # package id -> {"name":…, "types":{id:[chunks]}}
        self._parse(string_pool_cls)

    def _parse(self, string_pool_cls):
        d = self.data
        if len(d) < 12:
            raise AuditError("resources.arsc is too small to hold a table header")
        ctype, header_size, size = struct.unpack_from("<HHI", d, 0)
        if ctype != RES_TABLE_TYPE:
            raise AuditError(
                "resources.arsc root chunk is 0x%04x, expected 0x0002 "
                "RES_TABLE_TYPE" % ctype)
        limit = min(size, len(d))
        off = header_size
        while off + 8 <= limit:
            ct, hs, sz = struct.unpack_from("<HHI", d, off)
            if sz == 0 or off + sz > limit:
                self.report(
                    "arsc-chunk", "a chunk at 0x%x declares size %d, which is "
                    "zero or runs past the table" % (off, sz))
                break
            if ct == RES_STRING_POOL_TYPE and self.value_pool is None:
                self.value_pool = string_pool_cls(
                    d, off, hs, sz,
                    lambda lvl, code, msg, nxt: self.report(code, msg))
            elif ct == RES_TABLE_PACKAGE_TYPE:
                self._package(off, hs, sz, string_pool_cls)
            off += sz

    def _package(self, start, header_size, size, string_pool_cls):
        d = self.data
        pkg_id = u32(d, start + 8)
        raw_name = d[start + 12:start + 12 + 256]
        name = raw_name.decode("utf-16-le", "replace").split("\x00", 1)[0]
        type_strings_off = u32(d, start + 268)
        key_strings_off = u32(d, start + 276)

        entry = {"name": name, "types": {}, "type_names": None}

        if type_strings_off:
            p = start + type_strings_off
            if p + 8 <= len(d):
                _, ths, tsz = struct.unpack_from("<HHI", d, p)
                try:
                    entry["type_names"] = string_pool_cls(
                        d, p, ths, tsz,
                        lambda lvl, code, msg, nxt: self.report(code, msg))
                except Exception as exc:                       # noqa: BLE001
                    self.report("arsc-typepool",
                                "type string pool would not decode: %s" % exc)

        # walk the package's own child chunks
        off = start + header_size
        limit = start + size
        while off + 8 <= limit:
            ct, hs, sz = struct.unpack_from("<HHI", d, off)
            if sz == 0 or off + sz > limit:
                break
            if ct == RES_TABLE_TYPE_TYPE:
                tid = d[off + 8]
                entry["types"].setdefault(tid, []).append((off, hs, sz))
            off += sz

        # A package id of 0 is a dynamic/shared-library package; keep it, but a
        # later lookup that matches it should say so.
        self.packages[pkg_id] = entry

    # ------------------------------------------------------------------

    def type_name(self, pkg_id, type_id):
        pkg = self.packages.get(pkg_id)
        if not pkg or not pkg["type_names"]:
            return None
        return pkg["type_names"].get(type_id - 1)

    def resolve(self, res_id):
        """Return (list_of_distinct_string_values, notes)."""
        notes = []
        pkg_id = (res_id >> 24) & 0xFF
        type_id = (res_id >> 16) & 0xFF
        index = res_id & 0xFFFF

        pkg = self.packages.get(pkg_id)
        if pkg is None:
            if pkg_id == 0x01:
                notes.append(
                    "package id 0x01 is `android` - this resource lives in "
                    "framework-res.apk, not in this APK. That is unusual for a "
                    "network security config and worth a second look.")
            else:
                notes.append(
                    "no package with id 0x%02x in this resources.arsc. If the "
                    "APK is one of a split set, the resource may live in "
                    "another split - pass that one instead." % pkg_id)
            return [], notes

        chunks = pkg["types"].get(type_id, [])
        if not chunks:
            notes.append("package 0x%02x declares no type id 0x%02x" %
                         (pkg_id, type_id))
            return [], notes

        values = []
        for (off, hs, sz) in chunks:
            v = self._entry_value(off, hs, sz, index, notes)
            if v is not None and v not in values:
                values.append(v)
        if len(values) > 1:
            notes.append(
                "this resource has %d different values across configuration "
                "qualifiers: %s. The one the device uses depends on its locale, "
                "density and API level. Read them all." %
                (len(values), ", ".join(repr(v) for v in values)))
        return values, notes

    def _entry_value(self, off, header_size, size, index, notes):
        d = self.data
        flags = d[off + 9]
        entry_count = u32(d, off + 12)
        entries_start = u32(d, off + 16)

        idx_base = off + header_size
        offset = None

        if flags & FLAG_SPARSE:
            # ResTable_sparseTypeEntry { uint16 idx; uint16 offset/4 }
            for i in range(entry_count):
                p = idx_base + 4 * i
                if p + 4 > off + size:
                    break
                if u16(d, p) == index:
                    offset = u16(d, p + 2) * 4
                    break
            if offset is None:
                return None
        elif flags & FLAG_OFFSET16:
            if index >= entry_count:
                return None
            p = idx_base + 2 * index
            if p + 2 > off + size:
                return None
            raw = u16(d, p)
            if raw == 0xFFFF:
                return None
            offset = raw * 4
        else:
            if index >= entry_count:
                return None
            p = idx_base + 4 * index
            if p + 4 > off + size:
                return None
            raw = u32(d, p)
            if raw == NO_ENTRY:
                return None
            offset = raw

        e = off + entries_start + offset
        if e + 8 > off + size:
            notes.append("entry offset 0x%x lands outside its type chunk" % e)
            return None

        e_size = u16(d, e)
        e_flags = u16(d, e + 2)

        if e_flags & ENTRY_FLAG_COMPACT:
            notes.append(
                "this entry uses the COMPACT layout introduced with Android 14's "
                "aapt2. This reader does not decode it; cross-check with "
                "`aapt2 dump resources`.")
            return None
        if e_flags & ENTRY_FLAG_COMPLEX:
            notes.append(
                "resource is a bag/map, not a simple value - a network security "
                "config reference should never be one")
            return None

        v = e + e_size
        if v + 8 > off + size:
            return None
        # Res_value { uint16 size; uint8 res0; uint8 dataType; uint32 data }
        dtype = d[v + 3]
        data = u32(d, v + 4)
        if dtype != TYPE_STRING:
            notes.append(
                "resource value has dataType 0x%02x, not TYPE_STRING - it does "
                "not name a file" % dtype)
            return None
        if self.value_pool is None:
            notes.append("no global value string pool in resources.arsc")
            return None
        return self.value_pool.get(data)


# ----------------------------------------------------------------------------
# 3. the config document model
# ----------------------------------------------------------------------------

class Node:
    """One element of the config, with its attributes, text and children."""

    __slots__ = ("name", "attrs", "text", "children", "parent", "line_hint")

    def __init__(self, name, attrs=None, parent=None):
        self.name = name
        self.attrs = attrs or {}
        self.text = ""
        self.children = []
        self.parent = parent
        self.line_hint = None

    def kids(self, name):
        return [c for c in self.children if c.name == name]

    def kid(self, name):
        k = self.kids(name)
        return k[0] if k else None

    def attr(self, name, default=None):
        return self.attrs.get(name, default)

    def bool_attr(self, name):
        v = self.attrs.get(name)
        if v is None:
            return None
        if isinstance(v, bool):
            return v
        return str(v).strip().lower() in ("true", "1", "yes")

    def path(self):
        parts = []
        n = self
        while n is not None and n.name:
            label = n.name
            if n.name == "domain-config":
                doms = [d.text for d in n.kids("domain")]
                if doms:
                    label += "[" + ",".join(doms[:3]) + \
                             ("…" if len(doms) > 3 else "") + "]"
            parts.append(label)
            n = n.parent
        return "/".join(reversed(parts))

    def to_xml(self, indent=0):
        pad = "  " * indent
        a = "".join(' %s="%s"' % (k, v) for k, v in sorted(self.attrs.items()))
        if not self.children and not self.text:
            return ["%s<%s%s />" % (pad, self.name, a)]
        out = ["%s<%s%s>" % (pad, self.name, a)]
        if self.text:
            out.append("%s  %s" % (pad, self.text))
        for c in self.children:
            out.extend(c.to_xml(indent + 1))
        out.append("%s</%s>" % (pad, self.name))
        return out


def tree_from_axml(doc):
    """Rebuild a tree from parse_axml's flat event stream.

    parse_axml deliberately emits events rather than a DOM, because a document
    whose start and end tags do not balance is itself a finding and a DOM
    builder would hide it. Nesting matters here - <domain-config> inheritance is
    the whole point - so we rebuild, and shout if the stream will not nest."""
    root = Node("")
    stack = [root]
    problems = []
    for ev in doc.events:
        if ev["kind"] == "startElement":
            attrs = {}
            for a in ev["attributes"]:
                # The platform reads the TYPED value. parse_axml gives us both,
                # and flags the disagreement itself; we take the typed one and
                # strip the quoting it adds for strings.
                val = a["typed"]
                if isinstance(val, str) and len(val) >= 2 and \
                        val[0] == val[-1] == "'":
                    val = val[1:-1]
                attrs[a["name"]] = val
            n = Node(ev["name"], attrs, stack[-1])
            n.line_hint = "0x%x" % ev["offset"]
            stack[-1].children.append(n)
            stack.append(n)
        elif ev["kind"] == "endElement":
            if len(stack) > 1:
                stack.pop()
            else:
                problems.append("</%s> closes nothing" % ev["name"])
        elif ev["kind"] == "cdata":
            txt = (ev["text"] or "").strip()
            if txt:
                if stack[-1].text:
                    stack[-1].text += " " + txt
                else:
                    stack[-1].text = txt
    if len(stack) > 1:
        problems.append("%d element(s) never closed" % (len(stack) - 1))
    return root, problems


def tree_from_text(path):
    """Parse a decoded, text XML config - apktool output, or app source."""
    import xml.etree.ElementTree as ET
    try:
        et_root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise AuditError("%s: not well-formed XML: %s" % (path, exc))

    def strip_ns(tag):
        return tag.split("}", 1)[-1] if "}" in tag else tag

    def conv(el, parent):
        n = Node(strip_ns(el.tag), {}, parent)
        for k, v in el.attrib.items():
            n.attrs[strip_ns(k)] = v
        n.text = (el.text or "").strip()
        for c in el:
            n.children.append(conv(c, n))
        return n

    root = Node("")
    root.children.append(conv(et_root, root))
    return root, []


# ----------------------------------------------------------------------------
# 4. minimal DER walk - enough to pin a bundled certificate
# ----------------------------------------------------------------------------

def der_children(buf, start, end):
    """Yield (tag, header_len, content_start, content_end) for each TLV."""
    i = start
    while i < end:
        if i + 2 > end:
            return
        tag = buf[i]
        ln = buf[i + 1]
        j = i + 2
        if ln & 0x80:
            nbytes = ln & 0x7F
            if nbytes == 0 or j + nbytes > end:
                return
            ln = int.from_bytes(buf[j:j + nbytes], "big")
            j += nbytes
        if j + ln > end:
            return
        yield tag, j - i, j, j + ln
        i = j + ln


def spki_pin(der):
    """SHA-256 of the DER SubjectPublicKeyInfo, base64 - exactly what goes in
    <pin digest="SHA-256">.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    TBSCertificate ::= SEQUENCE { [0] version, serial, signature, issuer,
                                  validity, subject, subjectPublicKeyInfo, … }

    So: descend into the outer SEQUENCE, take its first child (tbsCertificate),
    then count fields. Version is a context tag [0] and is optional, which is
    why the index is computed rather than hardcoded."""
    outer = list(der_children(der, 0, len(der)))
    if not outer or outer[0][0] != 0x30:
        return None
    _, _, cs, ce = outer[0]
    tbs = list(der_children(der, cs, ce))
    if not tbs or tbs[0][0] != 0x30:
        return None
    _, _, ts, te = tbs[0]
    fields = list(der_children(der, ts, te))
    # skip the optional [0] EXPLICIT version
    idx = 1 if fields and fields[0][0] == 0xA0 else 0
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    want = idx + 5
    if want >= len(fields):
        return None
    tag, hdr, s, e = fields[want]
    if tag != 0x30:
        return None
    spki = der[s - hdr:e]
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def cert_subject(der):
    """Best-effort printable subject - concatenate the PrintableString/UTF8String
    values found in the subject RDN sequence. Good enough to recognise a CA."""
    try:
        outer = list(der_children(der, 0, len(der)))
        _, _, cs, ce = outer[0]
        tbs = list(der_children(der, cs, ce))
        _, _, ts, te = tbs[0]
        fields = list(der_children(der, ts, te))
        idx = 1 if fields and fields[0][0] == 0xA0 else 0
        tag, hdr, s, e = fields[idx + 4]      # subject
        out = []

        def walk(a, b, depth=0):
            if depth > 6:
                return
            for t, h, cs2, ce2 in der_children(der, a, b):
                if t in (0x13, 0x0C, 0x16, 0x14):
                    try:
                        out.append(der[cs2:ce2].decode("utf-8", "replace"))
                    except Exception:                          # noqa: BLE001
                        pass
                elif t in (0x30, 0x31):
                    walk(cs2, ce2, depth + 1)
        walk(s, e)
        return ", ".join(out) if out else None
    except Exception:                                          # noqa: BLE001
        return None


def pem_or_der_to_ders(blob):
    """Return every certificate in a blob, whether it is DER or PEM."""
    if blob[:1] == b"\x30":
        return [blob]
    text = blob.decode("ascii", "replace")
    out = []
    for m in re.finditer(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            text, re.S):
        try:
            out.append(base64.b64decode(re.sub(r"\s+", "", m.group(1))))
        except Exception:                                      # noqa: BLE001
            pass
    return out


# ----------------------------------------------------------------------------
# 5. the audit
# ----------------------------------------------------------------------------

class Finding:
    def __init__(self, code, severity, title, evidence, why, next_step):
        self.code = code
        self.severity = severity
        self.title = title
        self.evidence = evidence
        self.why = why
        self.next_step = next_step

    def as_dict(self):
        return {"code": self.code, "severity": self.severity,
                "title": self.title, "evidence": self.evidence,
                "why": self.why, "next_step": self.next_step}


class Auditor:

    def __init__(self, root, meta, now=None):
        self.root = root
        self.meta = meta                 # dict with target_sdk, debuggable, …
        self.findings = []
        self.now = now or datetime.datetime.now()
        self.raw_certs = {}              # entry path -> [der, …]

    # -------------------------------------------------------------- helpers

    def add(self, code, severity, title, evidence, why, next_step):
        self.findings.append(
            Finding(code, severity, title, evidence, why, next_step))

    @property
    def nsc(self):
        return self.root.kid("network-security-config")

    def worst(self):
        if not self.findings:
            return "POSITIVE"
        return min((f.severity for f in self.findings), key=lambda s: SEV_RANK[s])

    # ------------------------------------------------------------ inheritance

    def effective(self, node):
        """Walk up to compute the values that actually apply at `node`.

        The platform's inheritance rule, from NetworkSecurityConfig.Builder:
        a <domain-config> that omits a property takes its PARENT's value, where
        the parent is the enclosing <domain-config> if there is one and
        <base-config> otherwise, and <base-config> itself falls back to the
        platform default for the app's targetSdkVersion. Properties are
        inherited INDIVIDUALLY - declaring <trust-anchors> does not stop
        cleartextTrafficPermitted being inherited."""
        cleartext = None
        anchors = None
        pins = None
        pin_owner = None
        chain = []
        n = node
        while n is not None and n.name in ("domain-config", "base-config",
                                           "debug-overrides"):
            chain.append(n)
            if cleartext is None and n.bool_attr("cleartextTrafficPermitted") is not None:
                cleartext = (n.bool_attr("cleartextTrafficPermitted"), n)
            ta = n.kid("trust-anchors")
            if anchors is None and ta is not None:
                anchors = ([(c.attr("src"), c.bool_attr("overridePins") or False)
                            for c in ta.kids("certificates")], n)
            ps = n.kid("pin-set")
            if pins is None and ps is not None:
                pins = ps
                pin_owner = n
            n = n.parent if n.parent is not None and n.parent.name in (
                "domain-config", "base-config") else None

        # fall back to <base-config> for a top-level <domain-config>
        base = self.nsc.kid("base-config") if self.nsc else None
        if base is not None and base not in chain:
            if cleartext is None and base.bool_attr("cleartextTrafficPermitted") is not None:
                cleartext = (base.bool_attr("cleartextTrafficPermitted"), base)
            ta = base.kid("trust-anchors")
            if anchors is None and ta is not None:
                anchors = ([(c.attr("src"), c.bool_attr("overridePins") or False)
                            for c in ta.kids("certificates")], base)

        if cleartext is None:
            default = self.meta["target_sdk"] is not None and \
                self.meta["target_sdk"] < 28
            cleartext = (default, None)
        if anchors is None:
            anchors = ([("system", False)], None)
        return {"cleartext": cleartext, "anchors": anchors,
                "pins": pins, "pin_owner": pin_owner}

    def domains_of(self, node):
        out = []
        for d in node.kids("domain"):
            out.append((d.text or "?", d.bool_attr("includeSubdomains") or False))
        return out

    def all_domain_configs(self, node=None, acc=None):
        if acc is None:
            acc = []
        node = node if node is not None else self.nsc
        if node is None:
            return acc
        for c in node.children:
            if c.name == "domain-config":
                acc.append(c)
                self.all_domain_configs(c, acc)
            elif c.name in ("base-config", "debug-overrides"):
                continue
        return acc

    # ------------------------------------------------------------------ rules

    def run(self):
        if self.nsc is None:
            self.add(
                "NSC-000", "CRITICAL",
                "the document's root element is not <network-security-config>",
                "root child is %r" % ([c.name for c in self.root.children] or None),
                "XmlConfigSource requires the root tag to be "
                "<network-security-config>. Anything else throws a "
                "ParserException the first time the config is used, which the "
                "app sees as a RuntimeException on its first network call.",
                "Confirm you extracted the right resource. If this really is "
                "what shipped, the app cannot be making TLS calls through the "
                "platform stack at all - find out what it IS using.")
            return self.findings

        self._check_structure()
        self._check_cleartext()
        self._check_trust_anchors()
        self._check_debug_overrides()
        self._check_pin_sets()
        self._check_manifest_agreement()
        self._check_domains()
        if not self.findings:
            self.add(
                "NSC-999", "POSITIVE",
                "no declarative defect found in this config",
                "base-config and every domain-config reviewed",
                "The document denies cleartext, trusts only the system store "
                "outside <debug-overrides>, and any pin-set is live and has a "
                "backup pin.",
                "This says nothing about the app's runtime behaviour. Run "
                "./nsc-runtime.js and capture traffic before you write "
                "'transport security is correctly configured'.")
        return self.findings

    # ..................................................................

    def _check_structure(self):
        def walk(n):
            for c in n.children:
                if c.name not in KNOWN_ELEMENTS:
                    self.add(
                        "NSC-020", "MEDIUM",
                        "element <%s> is not part of the schema" % c.name,
                        "at %s (offset %s)" % (c.path(), c.line_hint),
                        "XmlConfigSource does not skip tags it does not "
                        "recognise - it raises a ParserException. That is "
                        "thrown lazily, when the config is first consulted, so "
                        "an app can install and launch and then fail on its "
                        "first HTTPS request. A typo here is not a cosmetic "
                        "defect.",
                        "Launch the app with logcat open and make it talk to "
                        "the network. Either you see the exception, in which "
                        "case the app is broken, or you do not, in which case "
                        "the file you read is not the file the app loaded - "
                        "find out why.")
                else:
                    known = KNOWN_ATTRS.get(c.name, set())
                    for a in c.attrs:
                        if a not in known:
                            self.add(
                                "NSC-021", "LOW",
                                "attribute %s is not defined on <%s>" % (a, c.name),
                                "at %s" % c.path(),
                                "Unknown attributes are read from the "
                                "AttributeSet, so a misspelt "
                                "`cleartextTrafficPermited` is simply absent "
                                "and the value is inherited instead. The "
                                "developer believes they set a policy; the "
                                "platform never saw one.",
                                "Compute what the inherited value actually is "
                                "and report THAT, not the attribute they "
                                "meant to write.")
                walk(c)
        walk(self.nsc)

        if self.nsc.kid("base-config") is None:
            self.add(
                "NSC-022", "INFO",
                "no <base-config>",
                "only %s present" % ([c.name for c in self.nsc.children] or "nothing"),
                "Without a <base-config> every host that no <domain-config> "
                "matches falls back to the platform default for this app's "
                "targetSdkVersion: system trust anchors only, and cleartext "
                "denied at targetSdk >= 28.",
                "That is usually the right answer. State the default you "
                "computed in the report so the reader does not assume you "
                "found nothing.")

        for dc in self.all_domain_configs():
            if not dc.kids("domain"):
                self.add(
                    "NSC-023", "MEDIUM",
                    "<domain-config> with no <domain> child",
                    "at %s (offset %s)" % (dc.path(), dc.line_hint),
                    "A domain-config must name at least one domain. The parser "
                    "rejects one that does not, so this file did not ship in "
                    "this form - or your extraction lost an element.",
                    "Re-extract and decode with a second tool. If both agree, "
                    "the app is broken.")

    def _check_cleartext(self):
        base = self.nsc.kid("base-config")
        if base is not None and base.bool_attr("cleartextTrafficPermitted") is True:
            self.add(
                "NSC-001", "HIGH",
                "cleartextTrafficPermitted=\"true\" in <base-config>",
                "at %s (offset %s)" % (base.path(), base.line_hint),
                "This re-enables plaintext HTTP for EVERY host the app talks "
                "to that no <domain-config> narrows. On targetSdk 28 and above "
                "the platform default is to refuse cleartext, so this is a "
                "deliberate opt-out of the default, applied globally. Any "
                "request that is not HTTPS is readable and modifiable by "
                "anything on the path.",
                "Do not report the flag on its own. Capture traffic and find "
                "the actual http:// requests. A global permit with no cleartext "
                "endpoint in use is a LOW; one carrying a session token is a "
                "HIGH.")

        permissive = []
        for dc in self.all_domain_configs():
            if dc.bool_attr("cleartextTrafficPermitted") is True:
                permissive.append(dc)
        if permissive:
            doms = []
            for dc in permissive:
                doms.extend("%s%s" % ("*." if sub else "", h)
                            for h, sub in self.domains_of(dc))
            base_true = base is not None and \
                base.bool_attr("cleartextTrafficPermitted") is True
            self.add(
                "NSC-002", "LOW" if base_true else "MEDIUM",
                "cleartext permitted for %d specific domain(s)" % len(doms),
                ", ".join(doms[:12]) + ("…" if len(doms) > 12 else ""),
                "Scoped cleartext is a different finding from global cleartext "
                "and must be reported as one. The question is what travels over "
                "those hosts. An analytics beacon leaking a device identifier "
                "over HTTP is real but bounded; an auth endpoint is not.",
                "Resolve each host, capture its traffic, and write the finding "
                "against the DATA you saw, naming the host. If the host is an "
                "ad or analytics SDK's, say which SDK - the app's developer "
                "often does not know it is there." +
                (" Note that <base-config> already permits cleartext "
                 "globally, so these entries change nothing." if base_true else ""))

        # the inverted pattern: permit globally, then deny per TLD
        denies = [dc for dc in self.all_domain_configs()
                  if dc.bool_attr("cleartextTrafficPermitted") is False]
        if base is not None and base.bool_attr("cleartextTrafficPermitted") is True \
                and denies:
            covered = []
            for dc in denies:
                covered.extend("%s%s" % ("*." if sub else "", h)
                               for h, sub in self.domains_of(dc))
            self.add(
                "NSC-003", "INFO",
                "inverted policy: cleartext allowed by default, denied per domain",
                "denied for: %s" % (", ".join(covered[:12]) +
                                    ("…" if len(covered) > 12 else "")),
                "This is a real pattern in shipping apps - permit cleartext in "
                "<base-config>, then deny it for a list of top-level domains "
                "with includeSubdomains=\"true\". It leaves cleartext permitted "
                "for everything the deny list misses: bare IP addresses, "
                "localhost, and every TLD not enumerated.",
                "Enumerate what is NOT covered. Test a host under a TLD absent "
                "from the list, and test a literal IP address. That is where "
                "the policy still permits HTTP.")

    def _check_trust_anchors(self):
        for owner in [self.nsc.kid("base-config")] + self.all_domain_configs():
            if owner is None:
                continue
            ta = owner.kid("trust-anchors")
            if ta is None:
                continue
            for c in ta.kids("certificates"):
                src = (c.attr("src") or "").strip()
                override = c.bool_attr("overridePins") or False
                where = owner.path()
                if src == "user":
                    self.add(
                        "NSC-004", "HIGH",
                        "<certificates src=\"user\"/> outside <debug-overrides>",
                        "at %s (offset %s), overridePins=%s" %
                        (where, c.line_hint, str(override).lower()),
                        "From API 24 the platform stopped trusting "
                        "user-installed certificate authorities by default. "
                        "This puts them back. Anything that can get a CA into "
                        "the user store - a malicious profile, a social "
                        "engineering prompt, an MDM enrolment, or simply a "
                        "tester - can then terminate this app's TLS for the "
                        "hosts this block covers. This is the classic "
                        "MASVS-NETWORK-1 defect, and unlike <debug-overrides> "
                        "it applies in a release build.",
                        "Confirm on a device: install a CA into the user store "
                        "only (Settings > Security > Install from storage), "
                        "point the app at a proxy and see the traffic. Then "
                        "state exactly which hosts it covers - a scoped entry "
                        "over an ad SDK's domains is not the same finding as "
                        "one in <base-config>." +
                        (" overridePins=\"true\" here means these certificates "
                         "also defeat any <pin-set>." if override else ""))
                elif src == "system":
                    pass
                elif src.startswith("@raw/") or src.startswith("@"):
                    self.add(
                        "NSC-005", "INFO",
                        "bundled certificate trust anchor %s" % src,
                        "at %s (offset %s), overridePins=%s" %
                        (where, c.line_hint, str(override).lower()),
                        "The app ships its own CA and trusts it. That is how a "
                        "private PKI is done properly, and it is also how an "
                        "app is made to trust a corporate interception "
                        "appliance. Which one it is depends entirely on whose "
                        "certificate it is.",
                        "Extract the certificate and read its subject and "
                        "issuer. This script does that below where it can "
                        "resolve the resource. If it is a public CA rather "
                        "than a private root, ask why.")
                elif src:
                    self.add(
                        "NSC-006", "MEDIUM",
                        "unrecognised trust anchor source %r" % src,
                        "at %s" % where,
                        "src accepts \"system\", \"user\" or a resource "
                        "reference. Anything else is a parse error.",
                        "Decode the file again with a second tool. A value "
                        "that survives both readings but is not one of the "
                        "three is a broken build.")
                if override and src != "user":
                    self.add(
                        "NSC-007", "HIGH",
                        "overridePins=\"true\" on a non-debug trust anchor",
                        "at %s, src=%r" % (where, src),
                        "overridePins means: a chain that terminates in one of "
                        "THESE certificates is exempt from the <pin-set>. In a "
                        "release configuration it turns pinning into a "
                        "suggestion for anyone holding one of those anchors.",
                        "Establish who controls the anchor. If it is the "
                        "system store, pinning provides no protection against "
                        "an attacker who can get a CA installed - which "
                        "includes every MDM.")

            if not ta.kids("certificates"):
                self.add(
                    "NSC-008", "MEDIUM",
                    "<trust-anchors> with no <certificates>",
                    "at %s" % owner.path(),
                    "An empty trust-anchor set means NO certificate chain "
                    "validates for the hosts this covers. Every TLS connection "
                    "to them fails.",
                    "Launch the app and watch for handshake failures against "
                    "those hosts. If they work anyway, the app is not using "
                    "the platform trust manager - find the one it is using.")

    def _check_debug_overrides(self):
        do = self.nsc.kid("debug-overrides")
        if do is None:
            return
        srcs = []
        for ta in do.kids("trust-anchors"):
            for c in ta.kids("certificates"):
                srcs.append((c.attr("src"), c.bool_attr("overridePins") or False))
        debuggable = self.meta.get("debuggable")

        if debuggable is True:
            self.add(
                "NSC-009", "CRITICAL",
                "<debug-overrides> IS ACTIVE - the app is debuggable",
                "android:debuggable=\"true\" and <debug-overrides> declares %s"
                % (srcs or "no certificates"),
                "<debug-overrides> is applied only when the ApplicationInfo "
                "carries FLAG_DEBUGGABLE. Here it does. Every anchor in this "
                "block is live in the build you are holding, in addition to "
                "whatever <base-config> says, and overridePins inside "
                "<debug-overrides> defaults to TRUE - so any pin-set is "
                "bypassable too. A debuggable release build is separately a "
                "critical finding; this compounds it.",
                "Prove it: install your own CA in the user store, proxy the "
                "app, and show pinned traffic decrypting. Report the "
                "debuggable flag as the root cause and this as the impact.")
        elif debuggable is False:
            self.add(
                "NSC-010", "INFO",
                "<debug-overrides> present but INERT - the app is not debuggable",
                "android:debuggable is false/absent; block declares %s"
                % (srcs or "no certificates"),
                "This is the single most over-reported item in mobile reports. "
                "<debug-overrides> is consulted only when FLAG_DEBUGGABLE is "
                "set on the app. In a normal release build it is not, so this "
                "block is parsed and then discarded - the platform builds no "
                "trust anchors from it at all. It is not a vulnerability, and "
                "reporting it as one costs you credibility on the findings "
                "that are real.",
                "Do not raise this as a finding. If you want to mention it, "
                "mention it as a note: the block exists, it is inert in this "
                "build, and it WOULD become live if a debuggable build ever "
                "shipped. Prove inertness by dumping the platform's own "
                "ApplicationConfig with ./nsc-runtime.js - the anchors it "
                "reports will not include the user store.")
        else:
            self.add(
                "NSC-011", "LOW",
                "<debug-overrides> present, debuggable state unknown",
                "block declares %s" % (srcs or "no certificates"),
                "Whether this block does anything depends entirely on "
                "android:debuggable in the manifest, which was not supplied.",
                "Re-run against the APK rather than the bare XML, or pass "
                "--debuggable true/false. Until then this is unresolved, not "
                "benign.")

        # a debug-overrides that does not trust the user store is unusual
        if srcs and all(s != "user" for s, _ in srcs):
            self.add(
                "NSC-012", "INFO",
                "<debug-overrides> does not trust the user store",
                "sources: %s" % srcs,
                "The overwhelmingly common content of this block is "
                "<certificates src=\"user\"/>, so a developer can proxy their "
                "own debug build. Something else here is worth reading.",
                "Extract whatever it does trust and identify it.")

    def _check_pin_sets(self):
        owners = [self.nsc.kid("base-config")] + self.all_domain_configs()
        found_any = False
        for owner in owners:
            if owner is None:
                continue
            ps = owner.kid("pin-set")
            if ps is None:
                continue
            found_any = True
            pins = ps.kids("pin")
            doms = ["%s%s" % ("*." if sub else "", h)
                    for h, sub in self.domains_of(owner)] or ["<base-config>"]
            label = ", ".join(doms[:8]) + ("…" if len(doms) > 8 else "")

            exp = ps.attr("expiration")
            if exp:
                parsed, lenient_from = parse_expiration(exp)
                if lenient_from is not None:
                    self.add(
                        "NSC-030", "MEDIUM",
                        "expiration %r is not a real date; the platform rolls it "
                        "over to %s" % (exp, parsed.date().isoformat()),
                        "pin-set for %s" % label,
                        "XmlConfigSource parses this with a SimpleDateFormat of "
                        "\"yyyy-MM-dd\", and SimpleDateFormat is LENIENT by "
                        "default: an out-of-range field is carried into the next "
                        "unit rather than rejected. %s therefore becomes %s. A "
                        "strict parser - including this script's first attempt, "
                        "and most linters - reports the value as invalid and "
                        "stops, which is a different answer from the one the "
                        "device will use." % (exp, parsed.date().isoformat()),
                        "Use the rolled-over date for every conclusion below. "
                        "Confirm on a device by reading PinSet.expirationTime "
                        "with ../scripts/nsc-runtime.js - it prints the real "
                        "epoch milliseconds the platform stored.")
                if parsed is None:
                    self.add(
                        "NSC-013", "HIGH",
                        "pin-set expiration %r does not parse as yyyy-MM-dd" % exp,
                        "pin-set for %s" % label,
                        "XmlConfigSource parses this with a SimpleDateFormat of "
                        "\"yyyy-MM-dd\". A value it cannot parse is a "
                        "ParserException, thrown when the config is first used.",
                        "Launch the app and watch logcat on its first HTTPS "
                        "request. Either it throws, or the file you read is "
                        "not the file it loaded.")
                else:
                    days = (parsed - self.now).days
                    if days < 0:
                        self.add(
                            "NSC-014", "HIGH",
                            "PIN-SET EXPIRED %d days ago - pinning is off" % -days,
                            "expiration=\"%s\" on the pin-set for %s; %d pin(s) "
                            "declared" % (exp, label, len(pins)),
                            "An expired pin-set does not fail closed and does "
                            "not log. NetworkSecurityTrustManager checks the "
                            "expiry before it checks the pins, and if the date "
                            "has passed it simply does not enforce them. Every "
                            "pin in the document is dead weight from that "
                            "moment on: the app validates the chain normally "
                            "and accepts any certificate from any trusted CA. "
                            "The developers almost certainly believe they are "
                            "still pinned, because nothing broke.",
                            "This is a real finding and it is under-reported "
                            "precisely because the app keeps working. Prove it: "
                            "get a CA the app trusts into play, proxy the "
                            "pinned host, and show the traffic. Then show the "
                            "same interception failing against a host whose "
                            "pin-set is still live, if there is one. Report the "
                            "date and the number of days.")
                    elif days < 90:
                        self.add(
                            "NSC-015", "MEDIUM",
                            "pin-set expires in %d days" % days,
                            "expiration=\"%s\" for %s" % (exp, label),
                            "When it passes, pinning stops silently. Nothing "
                            "in the app will report it and nothing will break, "
                            "so it will not be noticed until someone audits "
                            "the file again.",
                            "Raise it now, with the date. The fix is a release "
                            "before that date, or removing the attribute and "
                            "accepting that an unpinned failure mode is worse "
                            "than a bricked app.")
                    else:
                        self.add(
                            "NSC-016", "INFO",
                            "pin-set expires %s (%d days away)" %
                            (parsed.date().isoformat(), days),
                            "for %s" % label,
                            "The attribute is a deliberate safety valve: it "
                            "guarantees the app cannot brick itself against a "
                            "certificate rotation it did not anticipate. The "
                            "price is that after that date there is no pinning.",
                            "Record the date in the report. It is the date the "
                            "control ends.")
            else:
                self.add(
                    "NSC-017", "LOW",
                    "pin-set with no expiration",
                    "for %s; %d pin(s)" % (label, len(pins)),
                    "Without an expiration the pins never lapse. That is "
                    "stronger security and a real availability risk: if every "
                    "pinned key is rotated or revoked before users update, the "
                    "installed base cannot reach the host at all and cannot be "
                    "fixed remotely.",
                    "Check that at least one pin is a long-lived intermediate "
                    "or root rather than all leaves, and that a backup pin "
                    "exists. Report it as a resilience observation, not a "
                    "vulnerability.")

            if len(pins) < 2:
                self.add(
                    "NSC-018", "MEDIUM",
                    "pin-set has %d pin(s) - no backup pin" % len(pins),
                    "for %s" % label,
                    "RFC 7469 section 4.3 requires a backup pin for exactly "
                    "one reason: a single pinned key that has to be replaced in "
                    "a hurry leaves every installed copy of the app unable to "
                    "connect. This is the failure mode that makes teams rip "
                    "pinning out entirely.",
                    "Report as a resilience defect. The fix is a second pin "
                    "over a key held offline and not yet in use.")

            for p in pins:
                digest = (p.attr("digest") or "").strip()
                val = (p.text or "").strip()
                if digest not in SUPPORTED_DIGESTS:
                    self.add(
                        "NSC-019", "HIGH",
                        "unsupported pin digest %r" % digest,
                        "pin %r for %s" % (val[:16] + "…", label),
                        "Pin.isSupportedDigestAlgorithm accepts SHA-256 only. "
                        "An unsupported algorithm is a ParserException, not a "
                        "silently ignored pin.",
                        "If this shipped, the app throws on its first use of "
                        "the config. Verify on a device.")
                else:
                    try:
                        raw = base64.b64decode(val, validate=True)
                    except Exception:                          # noqa: BLE001
                        raw = b""
                    if len(raw) != SUPPORTED_DIGESTS[digest]:
                        self.add(
                            "NSC-024", "MEDIUM",
                            "pin value is %d bytes, not %d" %
                            (len(raw), SUPPORTED_DIGESTS[digest]),
                            "pin %r for %s" % (val, label),
                            "A SHA-256 pin is 32 bytes base64-encoded. A "
                            "different length is either a truncated copy-paste "
                            "or a hash of the wrong thing - people pin the "
                            "whole certificate instead of its "
                            "SubjectPublicKeyInfo surprisingly often.",
                            "Recompute the correct value: "
                            "`openssl x509 -in cert.pem -pubkey -noout | "
                            "openssl pkey -pubin -outform der | "
                            "openssl dgst -sha256 -binary | openssl enc -base64`")

        if not found_any:
            self.add(
                "NSC-025", "INFO",
                "no <pin-set> anywhere in this config",
                "checked base-config and %d domain-config(s)" %
                len(self.all_domain_configs()),
                "The app declares no certificate pinning through this "
                "mechanism. That is the norm and is not by itself a finding. "
                "It does mean any CA the app trusts can terminate its TLS.",
                "Before you write 'the app does not pin', check for pinning in "
                "CODE - OkHttp's CertificatePinner, TrustKit, or a custom "
                "X509TrustManager. See chapter 36, 36-CertificatePinning. "
                "This file cannot see any of them.")

    def _check_manifest_agreement(self):
        m_clear = self.meta.get("uses_cleartext")
        base = self.nsc.kid("base-config")
        eff = base.bool_attr("cleartextTrafficPermitted") if base is not None else None
        if m_clear is None or eff is None:
            return
        if m_clear != eff:
            self.add(
                "NSC-026", "INFO",
                "manifest and config disagree about cleartext; the CONFIG wins",
                "android:usesCleartextTraffic=%s but <base-config "
                "cleartextTrafficPermitted=%s>" %
                (str(m_clear).lower(), str(eff).lower()),
                "ActivityThread.handleBindApplication sets the boolean from "
                "the manifest flag, and then NetworkSecurityConfigProvider "
                "installs the parsed config over the top. Once a config is "
                "present, the manifest attribute is dead. A grep-based tool "
                "that reads only the manifest reports the wrong answer here in "
                "both directions.",
                "Report the effective value, %s, and say where it came from. "
                "Confirm with ./nsc-runtime.js, which asks the platform." %
                str(eff).lower())

    def _check_domains(self):
        seen = {}
        for dc in self.all_domain_configs():
            for h, sub in self.domains_of(dc):
                key = (h.lower(), sub)
                if key in seen and seen[key] is not dc:
                    self.add(
                        "NSC-027", "MEDIUM",
                        "domain %r appears in two different <domain-config>s" % h,
                        "at %s and %s" % (seen[key].path(), dc.path()),
                        "The platform builds a map keyed by Domain, so one of "
                        "the two configurations wins and which one is not "
                        "something you should predict from the file. Two "
                        "readers of this file will reach different conclusions.",
                        "Ask the device. ./nsc-runtime.js prints the platform's "
                        "own per-domain table; that is the answer.")
                seen[key] = dc

                if h and "." not in h and sub:
                    self.add(
                        "NSC-028", "INFO",
                        "<domain>%s</domain> is a bare label with "
                        "includeSubdomains" % h,
                        "includeSubdomains=%s, at %s" % (str(sub).lower(),
                                                         dc.path()),
                        "With includeSubdomains this matches every host under "
                        "that top-level domain. It is a legitimate way to "
                        "write a policy that covers the public internet while "
                        "leaving bare IP addresses and internal names outside "
                        "it - and that gap is usually the interesting part.",
                        "Work out what falls OUTSIDE the set of labels used "
                        "here and test a host there.")
                if h and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
                    self.add(
                        "NSC-029", "INFO",
                        "<domain> is a literal IP address: %s" % h,
                        "at %s" % dc.path(),
                        "Domain matching is on the hostname string. An entry "
                        "for an IP address only applies when the app connects "
                        "to that literal address, not when DNS resolves a name "
                        "to it.",
                        "Check whether the app connects by name or by address. "
                        "If by name, this entry never applies.")


# ----------------------------------------------------------------------------
# 6. driving it
# ----------------------------------------------------------------------------

def read_manifest_meta(pa, apk_path):
    """Four attributes, and only four. Chapter 32 audits the manifest."""
    data = pa.extract_from_apk(apk_path, "AndroidManifest.xml")
    doc = pa.Axml(data, "%s!AndroidManifest.xml" % apk_path)
    meta = {"target_sdk": None, "min_sdk": None, "debuggable": None,
            "uses_cleartext": None, "nsc_ref": None, "package": None,
            "axml_findings": [f for f in doc.findings
                              if f["level"] in ("ALERT", "WARN")]}
    for ev in doc.events:
        if ev["kind"] != "startElement":
            continue
        by_name = {a["name"]: a for a in ev["attributes"]}
        if ev["name"] == "manifest" and "package" in by_name:
            meta["package"] = by_name["package"]["typed"].strip("'")
        if ev["name"] == "uses-sdk":
            if "targetSdkVersion" in by_name:
                meta["target_sdk"] = by_name["targetSdkVersion"]["data"]
            if "minSdkVersion" in by_name:
                meta["min_sdk"] = by_name["minSdkVersion"]["data"]
        if ev["name"] == "application":
            if "debuggable" in by_name:
                meta["debuggable"] = by_name["debuggable"]["data"] != 0
            else:
                meta["debuggable"] = False
            if "usesCleartextTraffic" in by_name:
                meta["uses_cleartext"] = \
                    by_name["usesCleartextTraffic"]["data"] != 0
            if "networkSecurityConfig" in by_name:
                a = by_name["networkSecurityConfig"]
                meta["nsc_ref"] = a["data"]
                meta["nsc_ref_type"] = a["type_name"]
    return meta, doc


def resolve_config_entry(pa, apk_path, res_id, notes):
    try:
        arsc = pa.extract_from_apk(apk_path, "resources.arsc")
    except Exception as exc:                                   # noqa: BLE001
        notes.append("could not read resources.arsc: %s" % exc)
        return None
    table = ResourceTable(arsc, pa.StringPool,
                          lambda code, msg: notes.append("%s: %s" % (code, msg)))
    values, more = table.resolve(res_id)
    notes.extend(more)
    if not values:
        return None
    return values[0]


def resolve_raw_cert(pa, apk_path, src, notes):
    """src is `@raw/name` or a numeric reference; return the DER blobs."""
    if not src.startswith("@"):
        return []
    m = re.match(r"^@(?:0x)?([0-9a-fA-F]{8})$", src[1:]) or \
        re.match(r"^@0x([0-9a-fA-F]{8})$", src)
    res_id = None
    if src.startswith("@0x"):
        try:
            res_id = int(src[3:], 16)
        except ValueError:
            res_id = None
    if res_id is None:
        notes.append(
            "trust anchor %r is a symbolic reference; this script resolves "
            "numeric ids only. `aapt2 dump resources %s | grep %s` gives the "
            "path." % (src, os.path.basename(apk_path), src.lstrip("@")))
        return []
    path = resolve_config_entry(pa, apk_path, res_id, notes)
    if not path:
        return []
    try:
        blob = pa.extract_from_apk(apk_path, path)
    except Exception as exc:                                   # noqa: BLE001
        notes.append("could not read %s: %s" % (path, exc))
        return []
    return pem_or_der_to_ders(blob)


def print_report(result, args):
    w = sys.stdout.write
    w("\n" + "=" * 78 + "\n")
    w("  Network Security Config audit - %s\n" % result["input"])
    w("=" * 78 + "\n\n")

    m = result["manifest"]
    if m:
        w("-- manifest facts that change what the config MEANS --\n")
        w("   %-28s %s\n" % ("package", m.get("package")))
        w("   %-28s %s\n" % ("targetSdkVersion", m.get("target_sdk")))
        w("   %-28s %s\n" % ("android:debuggable", m.get("debuggable")))
        w("   %-28s %s\n" % ("android:usesCleartextTraffic",
                             m.get("uses_cleartext")))
        ref = m.get("nsc_ref")
        w("   %-28s %s\n" % ("android:networkSecurityConfig",
                             ("0x%08x" % ref) if ref else "(absent)"))
        w("   %-28s %s\n" % ("resolved to", result.get("entry") or "(unresolved)"))
        w("\n")
        if m.get("axml_findings"):
            w("   the manifest's own AXML has %d structural anomaly(ies) - run\n"
              "   ../../10-APK-Internals/examples/parse_axml.py on it.\n\n"
              % len(m["axml_findings"]))

    if result["notes"]:
        w("-- resolution notes --\n")
        for n in result["notes"]:
            w("   * %s\n" % n)
        w("\n")

    if result.get("default_only"):
        w("-- no config: what the platform applies instead --\n")
        for line in result["default_only"]:
            w("   %s\n" % line)
        w("\n")

    if args.xml and result.get("xml"):
        w("-- decoded configuration --\n")
        for line in result["xml"]:
            w("   %s\n" % line)
        w("\n")

    if result.get("effective"):
        w("-- effective policy, per scope --\n")
        for row in result["effective"]:
            w("   %s\n" % row["scope"])
            w("       cleartext permitted : %s   (%s)\n" %
              (row["cleartext"], row["cleartext_from"]))
            w("       trust anchors       : %s   (%s)\n" %
              (row["anchors"], row["anchors_from"]))
            w("       pin-set             : %s\n" % row["pins"])
        w("\n")

    if result.get("bundled_certs"):
        w("-- bundled trust anchors --\n")
        for c in result["bundled_certs"]:
            w("   %s\n" % c["src"])
            w("       subject : %s\n" % c.get("subject"))
            w("       SPKI pin: %s\n" % c.get("pin"))
            w("       matches a declared <pin>: %s\n" % c.get("matches_pin"))
        w("\n")

    w("-- findings (%d) --\n\n" % len(result["findings"]))
    for f in sorted(result["findings"], key=lambda x: SEV_RANK[x["severity"]]):
        w("   [%-8s] %s  %s\n" % (f["severity"], f["code"], f["title"]))
        w("       evidence  : %s\n" % f["evidence"])
        for i, chunk in enumerate(_wrap(f["why"], 66)):
            w("       %s%s\n" % ("why       : " if i == 0 else "            ", chunk))
        for i, chunk in enumerate(_wrap(f["next_step"], 66)):
            w("       %s%s\n" % ("next step : " if i == 0 else "            ", chunk))
        w("\n")

    w("-- reminder --\n")
    w("   This is a host-side read of a file. The platform is the authority.\n")
    w("   Run ./nsc-runtime.js under Frida and compare; where they differ, the\n")
    w("   device is right and the difference is your finding.\n\n")


def _wrap(text, width):
    import textwrap
    return textwrap.wrap(text, width) or [""]


def main():
    ap = argparse.ArgumentParser(
        description="Extract, resolve, decode and audit an Android Network "
                    "Security Config.")
    ap.add_argument("path", help="an APK, or a decoded/text config XML")
    ap.add_argument("--xml", action="store_true",
                    help="also print the decoded configuration")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--entry", default=None,
                    help="skip resolution and read this APK entry directly")
    ap.add_argument("--target-sdk", type=int, default=None,
                    help="override targetSdkVersion (needed for a bare XML file)")
    ap.add_argument("--debuggable", choices=["true", "false"], default=None,
                    help="override android:debuggable (needed for a bare XML file)")
    ap.add_argument("--parse-axml", default=None,
                    help="path to 10-APK-Internals/examples/parse_axml.py")
    ap.add_argument("--fail-on", choices=SEVERITIES, default=None,
                    help="exit 1 if any finding is at or above this severity")
    ap.add_argument("--now", default=None,
                    help="treat this yyyy-mm-dd as today (pin expiry testing)")
    args = ap.parse_args()

    try:
        pa, pa_path = load_parse_axml(args.parse_axml)
    except AuditError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    now = datetime.datetime.now()
    if args.now:
        try:
            now = datetime.datetime.strptime(args.now, "%Y-%m-%d")
        except ValueError:
            sys.stderr.write("error: --now wants yyyy-mm-dd\n")
            return 2

    notes = ["AXML decoding by %s" % pa_path]
    result = {"input": args.path, "manifest": None, "entry": None,
              "notes": notes, "findings": [], "xml": None,
              "effective": None, "bundled_certs": []}

    is_apk = args.path.lower().endswith((".apk", ".zip", ".apks"))
    meta = {"target_sdk": args.target_sdk,
            "debuggable": (None if args.debuggable is None
                           else args.debuggable == "true"),
            "uses_cleartext": None}
    root = None

    try:
        if is_apk:
            mmeta, _mdoc = read_manifest_meta(pa, args.path)
            if args.target_sdk is not None:
                mmeta["target_sdk"] = args.target_sdk
            if args.debuggable is not None:
                mmeta["debuggable"] = args.debuggable == "true"
            meta = mmeta
            result["manifest"] = mmeta

            entry = args.entry
            if entry is None:
                if not mmeta.get("nsc_ref"):
                    result["default_only"] = default_policy_lines(mmeta)
                    result["findings"] = [f.as_dict() for f in
                                          no_config_findings(mmeta)]
                    _emit(result, args)
                    return _exit_code(result, args)
                entry = resolve_config_entry(pa, args.path,
                                             mmeta["nsc_ref"], notes)
                if entry is None:
                    notes.append(
                        "the manifest names a config but the resource id would "
                        "not resolve. Cross-check: `aapt2 dump resources %s`"
                        % os.path.basename(args.path))
                    raise AuditError(
                        "could not resolve resource 0x%08x to a file"
                        % mmeta["nsc_ref"])
            result["entry"] = entry
            blob = pa.extract_from_apk(args.path, entry)
            doc = pa.Axml(blob, "%s!%s" % (args.path, entry))
            root, problems = tree_from_axml(doc)
            for p in problems:
                notes.append("document structure: %s" % p)
            for f in doc.findings:
                if f["level"] in ("ALERT", "WARN"):
                    notes.append("AXML %s: %s" % (f["code"], f["message"]))
        else:
            with open(args.path, "rb") as fh:
                head = fh.read(4)
            if head[:2] == b"\x03\x00":
                blob = open(args.path, "rb").read()
                doc = pa.Axml(blob, args.path)
                root, problems = tree_from_axml(doc)
                for p in problems:
                    notes.append("document structure: %s" % p)
            else:
                root, _ = tree_from_text(args.path)
            notes.append(
                "read as a standalone file: targetSdkVersion and "
                "android:debuggable are NOT known unless you passed them, and "
                "both change the verdict. Prefer running against the APK.")
    except (AuditError, OSError, zlib.error) as exc:
        sys.stderr.write("error: %s\n" % exc)
        for n in notes:
            sys.stderr.write("  note: %s\n" % n)
        return 2
    except Exception as exc:                                   # noqa: BLE001
        sys.stderr.write("error: %s: %s\n" % (type(exc).__name__, exc))
        return 2

    auditor = Auditor(root, meta, now=now)
    findings = auditor.run()
    result["findings"] = [f.as_dict() for f in findings]

    nsc = root.kid("network-security-config")
    if nsc is not None:
        result["xml"] = nsc.to_xml()
        result["effective"] = effective_rows(auditor)

        if is_apk:
            declared = set()
            for owner in [nsc.kid("base-config")] + auditor.all_domain_configs():
                if owner is None:
                    continue
                ps = owner.kid("pin-set")
                if ps is not None:
                    for p in ps.kids("pin"):
                        declared.add((p.text or "").strip())
            for owner in [nsc.kid("base-config"), nsc.kid("debug-overrides")] + \
                    auditor.all_domain_configs():
                if owner is None:
                    continue
                for ta in owner.kids("trust-anchors"):
                    for c in ta.kids("certificates"):
                        src = (c.attr("src") or "")
                        if not src.startswith("@"):
                            continue
                        for der in resolve_raw_cert(pa, args.path, src, notes):
                            pin = spki_pin(der)
                            result["bundled_certs"].append({
                                "src": "%s (in %s)" % (src, owner.path()),
                                "subject": cert_subject(der),
                                "pin": pin,
                                "matches_pin": (pin in declared) if pin else None,
                            })

    _emit(result, args)
    return _exit_code(result, args)


def effective_rows(auditor):
    rows = []
    scopes = []
    base = auditor.nsc.kid("base-config")
    scopes.append(("<base-config> / every host no domain-config matches",
                   base if base is not None else auditor.nsc))
    for dc in auditor.all_domain_configs():
        doms = ", ".join("%s%s" % ("*." if sub else "", h)
                         for h, sub in auditor.domains_of(dc))
        scopes.append((doms or "<domain-config with no domain>", dc))
    for label, node in scopes:
        if node.name not in ("base-config", "domain-config"):
            eff = {"cleartext": (auditor.meta["target_sdk"] is not None and
                                 auditor.meta["target_sdk"] < 28, None),
                   "anchors": ([("system", False)], None), "pins": None}
        else:
            eff = auditor.effective(node)
        ct, ct_from = eff["cleartext"]
        anchors, an_from = eff["anchors"]
        ps = eff["pins"]
        if ps is None:
            pin_desc = "none"
        else:
            pin_desc = "%d pin(s), expiration=%s" % (
                len(ps.kids("pin")), ps.attr("expiration") or "never")
        rows.append({
            "scope": label,
            "cleartext": str(ct).lower(),
            "cleartext_from": ("declared on <%s>" % ct_from.name) if ct_from
                              else "platform default for targetSdk %s"
                                   % auditor.meta["target_sdk"],
            "anchors": ", ".join("%s%s" % (s, "+overridePins" if o else "")
                                 for s, o in anchors),
            "anchors_from": ("declared on <%s>" % an_from.name) if an_from
                            else "platform default",
            "pins": pin_desc,
        })
    return rows


def default_policy_lines(meta):
    t = meta.get("target_sdk")
    lines = [
        "This APK has no android:networkSecurityConfig. The platform builds "
        "the default configuration from targetSdkVersion alone:",
        "",
        "   trust anchors      : the system CA store only "
        "(SystemCertificateSource)",
    ]
    if t is None:
        lines.append("   cleartext          : depends on targetSdkVersion, "
                     "which was not readable")
    elif t >= 28:
        lines.append("   cleartext          : DENIED (targetSdk %d >= 28)" % t)
    else:
        lines.append("   cleartext          : PERMITTED (targetSdk %d < 28)" % t)
    if meta.get("uses_cleartext") is not None:
        lines.append("   android:usesCleartextTraffic=%s overrides that boolean"
                     % str(meta["uses_cleartext"]).lower())
    if t is not None and t < 24:
        lines.append("   user-added CAs     : TRUSTED (targetSdk %d < 24)" % t)
    else:
        lines.append("   user-added CAs     : NOT trusted")
    lines.append("   pinning            : none")
    return lines


def no_config_findings(meta):
    out = []
    t = meta.get("target_sdk")
    if t is not None and t < 24:
        out.append(Finding(
            "NSC-030", "HIGH",
            "targetSdkVersion %d is below 24 - user CAs are trusted by default" % t,
            "no networkSecurityConfig, targetSdk=%d" % t,
            "Before API 24 the default trust store included user-installed "
            "certificate authorities. An app targeting below 24 gets that old "
            "default no matter what version of Android it runs on, because the "
            "default configuration is selected by targetSdkVersion. Any CA in "
            "the user store terminates this app's TLS.",
            "Install a CA in the user store only and proxy the app; it should "
            "work with no repackaging and no root. That is the proof."))
    if t is not None and t < 28:
        out.append(Finding(
            "NSC-031", "MEDIUM",
            "targetSdkVersion %d is below 28 - cleartext HTTP is permitted "
            "by default" % t,
            "no networkSecurityConfig, targetSdk=%d, "
            "android:usesCleartextTraffic=%s" % (t, meta.get("uses_cleartext")),
            "The cleartext default flipped at API 28. Below it, the platform "
            "permits plaintext HTTP unless the app opts out.",
            "Capture traffic and look for http:// requests. Report what you "
            "found travelling in the clear, not the default itself."))
    if meta.get("uses_cleartext") is True:
        out.append(Finding(
            "NSC-032", "HIGH",
            "android:usesCleartextTraffic=\"true\" with no config to narrow it",
            "manifest attribute set, no networkSecurityConfig",
            "This is the blunt instrument version of "
            "cleartextTrafficPermitted=\"true\" in <base-config>: it applies "
            "to every host, with no way to scope it. With no config present "
            "there is nothing to override it.",
            "Capture traffic. Then check whether the app needs it at all - "
            "very often it was added to make one legacy endpoint work and "
            "never narrowed to a <domain-config>."))
    if meta.get("debuggable") is True:
        out.append(Finding(
            "NSC-033", "HIGH",
            "android:debuggable=\"true\" in a build you were given",
            "no networkSecurityConfig, but the app is debuggable",
            "There is no <debug-overrides> here to activate, but debuggable "
            "means `run-as` works, the app is attachable, and any future "
            "config's debug block would be live.",
            "Report the debuggable flag on its own merits; see "
            "../../32-Manifest/README.md."))
    if not out:
        out.append(Finding(
            "NSC-034", "INFO",
            "no config, and the defaults are the safe ones",
            "targetSdk=%s, no networkSecurityConfig, "
            "android:usesCleartextTraffic=%s" % (t, meta.get("uses_cleartext")),
            "System trust anchors only, cleartext denied, no pinning. The "
            "absence of the file is not a finding - it is the modern default "
            "and it is a good one.",
            "Do not raise 'no network security config found' as a finding. If "
            "you want pinning, that is a hardening recommendation, and it "
            "belongs in the recommendations section with its availability "
            "cost stated."))
    return out


def _emit(result, args):
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result, args)


def _exit_code(result, args):
    if args.fail_on:
        threshold = SEV_RANK[args.fail_on]
        for f in result["findings"]:
            if SEV_RANK[f["severity"]] <= threshold and f["severity"] != "POSITIVE":
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
