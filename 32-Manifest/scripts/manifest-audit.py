#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manifest-audit.py — mechanical application of the Chapter 32 manifest audit checklist.

WHAT IT DOES
    Reads an AndroidManifest.xml in EITHER of the two forms you actually have on a
    real engagement:

      1. Decoded text XML, as produced by `apktool d target.apk -o work/`
         (work/AndroidManifest.xml), or the source manifest of a Gradle project.

      2. The output of `aapt2 dump xmltree --file AndroidManifest.xml target.apk`,
         which is the closest host-side approximation of what the *platform*
         parses, because aapt2 and the platform share libandroidfw.

    It then walks every element and produces a severity-rated findings report
    covering the checklist in README.md section 5.6 — application flags,
    every exported component, provider read/write/grant posture, custom
    permission protection levels, intent filters and deep links, <meta-data>
    that looks like a credential, <queries>, and the two elements that live
    OUTSIDE <application> and are missed constantly: <instrumentation> and
    <profileable android:shell="true">.

    Crucially it applies the targetSdk Version Matrix (README section 3.4).
    The same attribute means different things at different targetSdk levels:
    exported defaults change at 17 (providers) and 31 (everything else),
    cleartext HTTP flips to off-by-default at 28, context-registered receivers
    must declare their export state at 33, and PendingIntent mutability becomes
    mandatory at 31. A manifest auditor who ignores targetSdk will produce both
    false positives and false negatives.

WHY IT MATTERS
    The checklist is long, it is boring, and a human running it by hand at 17:40
    on the last day of an engagement will skip rows. Machines do not skip rows.
    What the machine cannot do is judge impact: every finding this script emits
    is a LEAD, not a vulnerability. An exported Activity is a vulnerability only
    when you have proven what it does and proven that an unprivileged app can
    reach it. See labs/lab-03-proving-reachability.md.

    Reachability discipline, restated because it is the single most common
    reason a manifest finding is rejected: `adb shell` runs as UID 2000 and
    holds privileges an ordinary app does not. Reaching a component from
    `adb shell` does NOT prove an attacker can reach it. This script marks every
    reachability-dependent finding as UNPROVEN for exactly that reason.

HOW TO RUN
    # host — decoded text XML (apktool)
    apktool d -f target.apk -o work/
    python3 manifest-audit.py work/AndroidManifest.xml

    # host — aapt2 xmltree (closest to the platform's own parser)
    aapt2 dump xmltree --file AndroidManifest.xml target.apk > tree.txt
    python3 manifest-audit.py --format xmltree tree.txt

    # host — read from stdin
    aapt2 dump xmltree --file AndroidManifest.xml target.apk \
        | python3 manifest-audit.py --format xmltree -

    # host — useful options
    python3 manifest-audit.py work/AndroidManifest.xml --markdown  > findings.md
    python3 manifest-audit.py work/AndroidManifest.xml --json      > findings.json
    python3 manifest-audit.py work/AndroidManifest.xml --min-severity HIGH
    python3 manifest-audit.py work/AndroidManifest.xml --target-sdk 30   # override

    # host — the three-way read this chapter insists on (lab 01)
    python3 manifest-audit.py work/AndroidManifest.xml       > a.txt
    python3 manifest-audit.py --format xmltree tree.txt      > b.txt
    diff a.txt b.txt     # any difference is itself a finding

REQUIREMENTS
    Python 3.7+. Standard library only — no pip install, so it runs on a locked
    down assessment laptop and inside a jump host. `aapt2` and `apktool` are
    needed only to produce the input, not to run this script.

    The script never writes files next to itself and never imports anything that
    would produce a __pycache__ next to the repository source. Run it as a script.

EXIT CODES
    0  no finding at or above --fail-on (default: never fail)
    1  at least one finding at or above --fail-on   (use in CI: --fail-on HIGH)
    2  input could not be parsed

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import os
import re
import sys
import textwrap
import xml.etree.ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"
TOOLS_NS = "http://schemas.android.com/tools"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "POSITIVE"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


# --------------------------------------------------------------------------- #
#  Reference data
# --------------------------------------------------------------------------- #

# Platform permissions whose protectionLevel is stable and widely known.
# Anything not in this table must be resolved on a device:
#     adb shell pm list permissions -f | grep -A6 <permission>
# The script says so rather than guessing.
KNOWN_PROTECTION_LEVELS = {
    "android.permission.INTERNET": "normal",
    "android.permission.ACCESS_NETWORK_STATE": "normal",
    "android.permission.ACCESS_WIFI_STATE": "normal",
    "android.permission.VIBRATE": "normal",
    "android.permission.WAKE_LOCK": "normal",
    "android.permission.FOREGROUND_SERVICE": "normal",
    "android.permission.RECEIVE_BOOT_COMPLETED": "normal",
    "android.permission.QUERY_ALL_PACKAGES": "normal",
    "android.permission.REQUEST_INSTALL_PACKAGES": "signature|appop",
    "android.permission.SYSTEM_ALERT_WINDOW": "signature|preinstalled|appop",
    "android.permission.READ_CONTACTS": "dangerous",
    "android.permission.WRITE_CONTACTS": "dangerous",
    "android.permission.READ_SMS": "dangerous",
    "android.permission.RECEIVE_SMS": "dangerous",
    "android.permission.SEND_SMS": "dangerous",
    "android.permission.CAMERA": "dangerous",
    "android.permission.RECORD_AUDIO": "dangerous",
    "android.permission.ACCESS_FINE_LOCATION": "dangerous",
    "android.permission.ACCESS_COARSE_LOCATION": "dangerous",
    "android.permission.READ_EXTERNAL_STORAGE": "dangerous",
    "android.permission.WRITE_EXTERNAL_STORAGE": "dangerous",
    "android.permission.READ_PHONE_STATE": "dangerous",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "signature|appop|preinstalled",
    "android.permission.WRITE_SECURE_SETTINGS": "signature|privileged|development",
    "android.permission.INSTALL_PACKAGES": "signature|privileged",
    "android.permission.PACKAGE_USAGE_STATS": "signature|privileged|development|appop",
}

# Permissions only the system holds. An exported component guarded by one of
# these is CORRECT, not a finding — see README section 9.5.
SYSTEM_BIND_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_JOB_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.BIND_QUICK_SETTINGS_TILE",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_CARRIER_SERVICES",
    "android.permission.BIND_CHOOSER_TARGET_SERVICE",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_APPWIDGET",
    "android.permission.BIND_REMOTEVIEWS",
    "android.permission.BIND_COMPANION_DEVICE_SERVICE",
    "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE",
}

# High-signal permissions from README section 3.11.
HIGH_SIGNAL_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES":
        "Dropper capability: the app can trigger installation of other APKs.",
    "android.permission.QUERY_ALL_PACKAGES":
        "Defeats package-visibility filtering. Fingerprinting and targeting capability; "
        "Play-restricted to specific use cases.",
    "android.permission.SYSTEM_ALERT_WINDOW":
        "Draw over other apps — the basis of overlay and tapjacking attacks.",
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        "Read and act on every screen. The most abused capability in Android malware.",
    "android.permission.BIND_DEVICE_ADMIN":
        "Device administration: lock, wipe, resist uninstall.",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
        "Read every notification, including OTP codes.",
    "android.permission.READ_SMS":
        "OTP interception.",
    "android.permission.RECEIVE_SMS":
        "OTP interception.",
    "android.permission.MANAGE_EXTERNAL_STORAGE":
        "All-files access across shared storage.",
    "android.permission.PACKAGE_USAGE_STATS":
        "Which apps the user runs and when.",
    "android.permission.WRITE_SECURE_SETTINGS":
        "Not grantable to third-party apps, but a strong intent signal.",
    "android.permission.RECORD_AUDIO":
        "Microphone. Check for a matching foregroundServiceType.",
    "android.permission.CAMERA":
        "Camera. Check for a matching foregroundServiceType.",
    "android.permission.ACCESS_FINE_LOCATION":
        "Precise location. Check for a matching foregroundServiceType.",
    "android.permission.ACCESS_BACKGROUND_LOCATION":
        "Location while the app is not in use.",
    "android.permission.READ_LOGS":
        "Not grantable to third-party apps on modern Android; an intent signal.",
}

# Package names whose presence in <queries> reveals what the app looks for.
ROOT_DETECTION_QUERY_TARGETS = {
    "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
    "de.robv.android.xposed.installer", "com.saurik.substrate",
    "com.koushikdutta.superuser", "com.thirdparty.superuser",
    "com.yellowes.su", "com.zachspong.temprootremovejb",
    "com.ramdroid.appquarantine", "com.formyhm.hideroot",
    "io.github.huskydg.magisk", "me.weishu.kernelsu",
}

# <meta-data> names that look like credentials.
SECRETISH_NAME_RE = re.compile(
    r"(secret|password|passwd|passphrase|private[_.-]?key|api[_.-]?key|apikey|"
    r"access[_.-]?token|auth[_.-]?token|client[_.-]?secret|signing[_.-]?key|"
    r"credential|bearer)",
    re.IGNORECASE,
)

# <meta-data> values that look like credentials by shape.
SECRETISH_VALUE_RES = [
    (re.compile(r"^AIza[0-9A-Za-z_\-]{35}$"), "Google API key shape"),
    (re.compile(r"^sk_(live|test)_[0-9A-Za-z]{16,}$"), "Stripe secret key shape"),
    (re.compile(r"^pk_live_[0-9A-Za-z]{16,}$"), "Stripe live publishable key shape"),
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "AWS access key id shape"),
    (re.compile(r"^gh[pousr]_[0-9A-Za-z]{30,}$"), "GitHub token shape"),
    (re.compile(r"^xox[baprs]-[0-9A-Za-z\-]{10,}$"), "Slack token shape"),
    (re.compile(r"^ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}$"),
     "JWT shape"),
    (re.compile(r"^[0-9a-fA-F]{32,}$"), "long hex string — possible key or hash"),
]

# <meta-data> names that are public by design and should NOT be reported as secrets.
KNOWN_PUBLIC_METADATA = {
    "com.google.android.gms.ads.APPLICATION_ID",
    "com.google.android.gms.version",
    "com.facebook.sdk.ApplicationId",
    "io.sentry.dsn",
    "com.google.firebase.messaging.default_notification_icon",
    "com.google.firebase.messaging.default_notification_color",
}

FOREGROUND_SERVICE_TYPES = {
    "camera", "connectedDevice", "dataSync", "health", "location",
    "mediaPlayback", "mediaProjection", "microphone", "phoneCall",
    "remoteMessaging", "shortService", "specialUse", "systemExempted",
}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


# --------------------------------------------------------------------------- #
#  Model
# --------------------------------------------------------------------------- #

class Value(object):
    """One attribute value, carrying enough type information to spot AXML tricks."""

    __slots__ = ("raw", "vtype", "resid", "data", "anomaly")

    def __init__(self, raw, vtype="string", resid=None, data=None, anomaly=None):
        self.raw = raw            # printable form
        self.vtype = vtype        # 'string' | 'bool' | 'int' | 'ref' | 'unknown'
        self.resid = resid        # attribute resource id, when the source gives one
        self.data = data          # numeric payload for bool/int
        self.anomaly = anomaly    # note about a suspicious encoding

    def as_bool(self):
        """Platform semantics: getAttributeBooleanValue returns data != 0."""
        if self.vtype == "bool":
            return self.data != 0
        s = (self.raw or "").strip().lower()
        if s in ("true", "1", "yes"):
            return True
        if s in ("false", "0", "no", ""):
            return False
        # A reference, or a non-boolean string in a boolean slot. Unknown, but the
        # platform will coerce it, so treat a non-empty non-false value as true and
        # say so loudly.
        return True

    def as_int(self, default=None):
        if self.vtype in ("int", "bool") and self.data is not None:
            return self.data
        try:
            return int((self.raw or "").strip(), 0)
        except (ValueError, TypeError):
            return default

    def is_ref(self):
        return self.vtype == "ref"

    def __str__(self):
        return self.raw if self.raw is not None else ""


class Node(object):
    """One manifest element."""

    __slots__ = ("tag", "attrs", "children", "parent", "line", "dup_attrs")

    def __init__(self, tag, line=None, parent=None):
        self.tag = tag
        self.attrs = {}       # normalised name -> Value
        self.children = []
        self.parent = parent
        self.line = line
        self.dup_attrs = []   # names seen more than once on this element

    def add(self, name, value):
        if name in self.attrs:
            self.dup_attrs.append(name)
        else:
            self.attrs[name] = value

    def get(self, name):
        return self.attrs.get(name)

    def gets(self, name, default=None):
        v = self.attrs.get(name)
        return v.raw if v is not None else default

    def has(self, name):
        return name in self.attrs

    def kids(self, tag):
        return [c for c in self.children if c.tag == tag]

    def descendants(self, tag=None):
        for c in self.children:
            if tag is None or c.tag == tag:
                yield c
            for g in c.descendants(tag):
                yield g

    def name(self, pkg=None):
        n = self.gets("android:name")
        if n and n.startswith(".") and pkg:
            return pkg + n
        return n or "<unnamed>"


class Finding(object):
    __slots__ = ("check", "severity", "title", "where", "evidence",
                 "why", "fix", "proven")

    def __init__(self, check, severity, title, where="", evidence="",
                 why="", fix="", proven=True):
        self.check = check
        self.severity = severity
        self.title = title
        self.where = where
        self.evidence = evidence
        self.why = why
        self.fix = fix
        # proven=False means "this depends on reachability or on data you have not
        # inspected yet". Printed as UNPROVEN so it never leaks into a report as fact.
        self.proven = proven

    def to_dict(self):
        return {
            "check": self.check,
            "severity": self.severity,
            "title": self.title,
            "where": self.where,
            "evidence": self.evidence,
            "why": self.why,
            "fix": self.fix,
            "proven": self.proven,
        }


# --------------------------------------------------------------------------- #
#  Parser 1 — decoded text XML (apktool / Gradle source)
# --------------------------------------------------------------------------- #

def _normalise_attr_name(key):
    if key.startswith("{"):
        uri, _, local = key[1:].partition("}")
        if uri == ANDROID_NS:
            return "android:" + local
        if uri == TOOLS_NS:
            return "tools:" + local
        return uri.rsplit("/", 1)[-1] + ":" + local
    return key


def _classify_text_value(raw):
    s = (raw or "").strip()
    low = s.lower()
    if low in ("true", "false"):
        return Value(s, "bool", data=(1 if low == "true" else 0))
    if s.startswith("@") or s.startswith("?"):
        return Value(s, "ref")
    if re.match(r"^-?\d+$", s):
        return Value(s, "int", data=int(s))
    if re.match(r"^0x[0-9a-fA-F]+$", s):
        return Value(s, "int", data=int(s, 16))
    return Value(s, "string")


def parse_text_xml(text):
    """Parse decoded text XML into the Node model."""
    try:
        root_el = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("not parseable as text XML: %s" % exc)

    def build(el, parent=None):
        tag = el.tag
        if tag.startswith("{"):
            tag = tag.split("}", 1)[1]
        node = Node(tag, parent=parent)
        for k, v in el.attrib.items():
            node.add(_normalise_attr_name(k), _classify_text_value(v))
        for child in list(el):
            if not isinstance(child.tag, str):
                continue  # comment / PI
            node.children.append(build(child, node))
        return node

    return build(root_el)


# --------------------------------------------------------------------------- #
#  Parser 2 — `aapt2 dump xmltree` output
# --------------------------------------------------------------------------- #

_E_RE = re.compile(r"^(?P<indent>\s*)E:\s*(?P<tag>[^\s(]+)(?:\s*\(line=(?P<line>\d+)\))?")
_N_RE = re.compile(r"^(?P<indent>\s*)N:\s*(?P<prefix>[^=]+)=(?P<uri>\S+)")
_A_RE = re.compile(
    r"^(?P<indent>\s*)A:\s*(?P<name>[^(=]+?)"
    r"(?:\((?P<resid>0x[0-9a-fA-F]+)\))?"
    r"=(?P<value>.*)$"
)

_TYPED_RE = re.compile(r"^\(type\s+(?P<t>0x[0-9a-fA-F]+)\)(?P<d>[-0-9a-fA-Fx]+)")
_STRING_RE = re.compile(r'^"(?P<s>.*?)"(?:\s*\(Raw:\s*"(?P<raw>.*)"\s*\))?\s*$')


def _classify_xmltree_value(text, attr_name):
    text = text.strip()

    m = _STRING_RE.match(text)
    if m:
        return Value(m.group("raw") if m.group("raw") is not None else m.group("s"),
                     "string")

    if text.startswith("@"):
        return Value(text, "ref")

    m = _TYPED_RE.match(text)
    if m:
        try:
            t = int(m.group("t"), 16)
        except ValueError:
            return Value(text, "unknown")
        d_raw = m.group("d")
        try:
            d = int(d_raw, 16) if d_raw.lower().startswith("0x") else int(d_raw, 0)
        except ValueError:
            d = None
        if d is not None and d > 0x7FFFFFFF:
            signed = d - 0x100000000
        else:
            signed = d

        if t == 0x12:  # TYPE_INT_BOOLEAN
            anomaly = None
            if d not in (0, 1, 0xFFFFFFFF):
                anomaly = ("boolean encoded as 0x%x — the platform reads data != 0, "
                           "so this is TRUE; decoders that expect 0/1 may print "
                           "otherwise" % d)
            elif d == 0xFFFFFFFF:
                anomaly = ("boolean encoded as 0xffffffff (-1) — TRUE to the platform. "
                           "Some decoders print '-1' or '4294967295' and fail to flag it")
            return Value("true" if d else "false", "bool", data=(1 if d else 0),
                         anomaly=anomaly)
        if t == 0x01:  # TYPE_REFERENCE
            return Value("@0x%08x" % (d or 0), "ref")
        if t in (0x10, 0x11):  # INT_DEC / INT_HEX
            return Value(str(signed), "int", data=signed)
        if t == 0x03:  # TYPE_STRING as a raw index (older aapt2)
            return Value(text, "string")
        return Value(text, "unknown")

    return Value(text, "unknown")


def parse_xmltree(text):
    """Parse `aapt2 dump xmltree` output into the Node model."""
    prefixes = {}
    root = None
    stack = []  # list of (indent, Node)
    saw_element = False

    for line in text.splitlines():
        if not line.strip():
            continue

        m = _N_RE.match(line)
        if m:
            prefixes[m.group("prefix").strip()] = m.group("uri").strip()
            continue

        m = _E_RE.match(line)
        if m:
            saw_element = True
            indent = len(m.group("indent"))
            tag = m.group("tag").strip()
            line_no = int(m.group("line")) if m.group("line") else None
            node = Node(tag, line=line_no)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                node.parent = stack[-1][1]
                stack[-1][1].children.append(node)
            elif root is None:
                root = node
            else:
                # Two roots should not happen; keep the first, attach the rest.
                node.parent = root
                root.children.append(node)
            stack.append((indent, node))
            continue

        m = _A_RE.match(line)
        if m and stack:
            name = m.group("name").strip()
            # aapt2 emits either "android:exported" or the full URI form.
            if name.startswith(ANDROID_NS + ":"):
                name = "android:" + name[len(ANDROID_NS) + 1:]
            elif name.startswith(TOOLS_NS + ":"):
                name = "tools:" + name[len(TOOLS_NS) + 1:]
            elif ":" in name:
                pfx, _, local = name.partition(":")
                uri = prefixes.get(pfx)
                if uri == ANDROID_NS:
                    name = "android:" + local
                elif uri == TOOLS_NS:
                    name = "tools:" + local
            val = _classify_xmltree_value(m.group("value"), name)
            val.resid = m.group("resid")
            stack[-1][1].add(name, val)
            continue

    if root is None or not saw_element:
        raise ValueError("no elements found — is this really `aapt2 dump xmltree` output?")
    return root


def parse_auto(text, forced=None):
    """Choose a parser. `forced` is 'xml', 'xmltree' or None for autodetect."""
    if forced == "xml":
        return parse_text_xml(text), "xml"
    if forced == "xmltree":
        return parse_xmltree(text), "xmltree"

    stripped = text.lstrip()
    if stripped.startswith("<?xml") or stripped.startswith("<manifest"):
        return parse_text_xml(text), "xml"
    if re.search(r"^\s*E:\s*manifest", text, re.M):
        return parse_xmltree(text), "xmltree"
    # Last resort: try both.
    try:
        return parse_text_xml(text), "xml"
    except ValueError:
        return parse_xmltree(text), "xmltree"


# --------------------------------------------------------------------------- #
#  Audit
# --------------------------------------------------------------------------- #

class Auditor(object):

    def __init__(self, root, source_format, target_sdk_override=None):
        self.root = root
        self.source_format = source_format
        self.findings = []
        self.notes = []

        self.package = root.gets("package") or "<unknown>"
        self.application = None
        for c in root.children:
            if c.tag == "application":
                self.application = c
                break

        self.min_sdk, self.target_sdk = self._read_sdk_levels()
        if target_sdk_override is not None:
            self.target_sdk = target_sdk_override
            self.notes.append("targetSdk overridden on the command line: %d"
                              % target_sdk_override)

        self.declared_permissions = self._read_declared_permissions()
        self.stats = {}

    # ---------------------------------------------------------------- helpers

    def add(self, check, severity, title, where="", evidence="", why="", fix="",
            proven=True):
        self.findings.append(Finding(check, severity, title, where, evidence,
                                     why, fix, proven))

    def _read_sdk_levels(self):
        min_sdk = target_sdk = None
        for u in self.root.kids("uses-sdk"):
            v = u.get("android:minSdkVersion")
            if v is not None:
                min_sdk = v.as_int(min_sdk)
            v = u.get("android:targetSdkVersion")
            if v is not None:
                target_sdk = v.as_int(target_sdk)
        return min_sdk, target_sdk

    def _read_declared_permissions(self):
        """name -> (protectionLevel string, explicit?)"""
        out = {}
        for p in self.root.descendants("permission"):
            name = p.gets("android:name")
            if not name:
                continue
            lvl = p.gets("android:protectionLevel")
            out[name] = (lvl if lvl else "normal", lvl is not None)
        return out

    def resolve_protection(self, perm):
        """
        Return (level, source) where source is 'declared', 'platform' or 'unknown'.
        'unknown' means: go and resolve it on a device. The script refuses to guess.
        """
        if perm in self.declared_permissions:
            lvl, explicit = self.declared_permissions[perm]
            return lvl, ("declared" if explicit else "declared-default")
        if perm in KNOWN_PROTECTION_LEVELS:
            return KNOWN_PROTECTION_LEVELS[perm], "platform"
        if perm in SYSTEM_BIND_PERMISSIONS:
            return "signature|privileged", "platform"
        return None, "unknown"

    def effective_exported(self, node):
        """
        Return (exported: bool, basis: str, confident: bool).
        Implements the Version Matrix in README section 3.4.
        """
        attr = node.get("android:exported")
        has_filter = bool(node.kids("intent-filter"))

        if attr is not None:
            if attr.is_ref():
                return True, "explicit but a RESOURCE REFERENCE — resolve it", False
            return attr.as_bool(), "explicit", True

        if node.tag == "provider":
            if self.target_sdk is None:
                return False, ("no attribute; targetSdk unknown — default is true at "
                               "targetSdk<=16 and false from 17"), False
            if self.target_sdk <= 16:
                return True, "no attribute; targetSdk<=16 so providers default to TRUE", True
            return False, "no attribute; targetSdk>=17 so providers default to false", True

        if has_filter:
            if self.target_sdk is not None and self.target_sdk >= 31:
                return True, ("no attribute but an intent-filter is present, and the "
                              "attribute is MANDATORY from targetSdk 31 — this manifest "
                              "as read would fail to install; the shipped APK almost "
                              "certainly has the attribute and your decoder lost it"), False
            return True, ("no attribute; intent-filter present and targetSdk<31 so the "
                          "component is IMPLICITLY EXPORTED"), True

        return False, "no attribute and no intent-filter; defaults to false", True

    def component_permission(self, node):
        """
        The permission a caller must hold. Component-level attribute wins over the
        application-level one; note that it OVERRIDES rather than adds.
        """
        v = node.gets("android:permission")
        if v is not None:
            return v, "component"
        if self.application is not None:
            av = self.application.gets("android:permission")
            if av is not None:
                return av, "application"
        return None, None

    # ------------------------------------------------------------------ B/C

    def audit_manifest_root(self):
        self.add("CTX", "INFO", "Package identity",
                 where=self.package,
                 evidence="versionCode=%s versionName=%s" % (
                     self.root.gets("android:versionCode", "?"),
                     self.root.gets("android:versionName", "?")),
                 why="versionName is cosmetic and is frequently stale or falsified. "
                     "Correlate findings to versionCode and to the signing certificate.")

        # B1 / B2 — SDK levels and the Version Matrix.
        if self.target_sdk is None:
            self.add("B1", "MEDIUM", "targetSdkVersion not present in this manifest",
                     evidence="no <uses-sdk android:targetSdkVersion>",
                     why="In a Gradle project targetSdk lives in build.gradle and is "
                         "injected by the manifest merger, so a SOURCE manifest legitimately "
                         "omits it. In a decoded APK its absence is abnormal and every "
                         "default in this report is therefore unreliable. Confirm with "
                         "`aapt2 dump badging target.apk | grep targetSdk`.",
                     fix="Audit the built artefact, not the source manifest.",
                     proven=False)
        else:
            self._version_matrix()

        if self.min_sdk is not None and self.min_sdk < 24:
            self.add("B2", "MEDIUM", "Low minSdkVersion widens the threat model",
                     evidence="minSdkVersion=%d" % self.min_sdk,
                     why="Every finding must now be assessed on the oldest supported "
                         "platform too: below 23 all permissions are granted at install "
                         "and MODE_WORLD_READABLE still works; below 24 user-added CA "
                         "certificates are trusted by default and file:// URIs cross app "
                         "boundaries freely.",
                     fix="Raise minSdk, or document the compensating controls that apply "
                         "on old platforms.")

        # B3 — sharedUserId.
        suid = self.root.gets("android:sharedUserId")
        if suid:
            sev = "CRITICAL" if suid == "android.uid.system" else "HIGH"
            self.add("B3", sev, "sharedUserId dissolves the app sandbox between siblings",
                     evidence='android:sharedUserId="%s"' % suid,
                     why="Apps sharing a UID share a data directory namespace, can read "
                         "each other's files directly, and hold the union of each other's "
                         "granted permissions. The sandbox is a UID boundary, and inside a "
                         "shared UID group there is no boundary. One weak sibling app "
                         "compromises every member."
                         + (" android.uid.system additionally requires the platform signing "
                            "key — if this APK installs on a stock device, that key has "
                            "leaked or the build is permissive."
                            if suid == "android.uid.system" else ""),
                     fix="Removing sharedUserId from a published app changes its UID and is "
                         "not supported without uninstall/reinstall, so the recommendation "
                         "must include a data-migration plan. On API 33+ "
                         "android:sharedUserMaxSdkVersion lets an app stop using the shared "
                         "UID on new platforms while preserving it on old ones.")
            if not self.root.has("android:sharedUserMaxSdkVersion"):
                self.add("B3b", "LOW", "sharedUserId with no migration path declared",
                         evidence="android:sharedUserMaxSdkVersion absent",
                         why="Deprecated since API 29 with no declared migration.",
                         fix='Add android:sharedUserMaxSdkVersion="32" and plan the move.')

        # B4 — installLocation.
        loc = self.root.gets("android:installLocation")
        if loc in ("auto", "preferExternal"):
            self.add("B4", "LOW", "App may install to external/adoptable storage",
                     evidence='android:installLocation="%s"' % loc,
                     why="Historically this placed the APK on a volume with no UNIX "
                         "permissions. Modern adoptable storage is encrypted, so this is a "
                         "note rather than a finding on current devices — but it still "
                         "matters on an app handling sensitive data with a low minSdk.",
                     fix='Use android:installLocation="internalOnly".')

        # <permission-tree>
        for t in self.root.descendants("permission-tree"):
            self.add("F6", "INFO", "<permission-tree> — the manifest under-describes the surface",
                     where=t.gets("android:name", "?"),
                     why="A permission tree reserves a namespace so the app may add "
                         "permissions at runtime via PackageManager.addPermission(). "
                         "Permissions can therefore appear that are not in this file.",
                     fix="Hook addPermission at runtime, or enumerate with "
                         "`adb shell pm list permissions -f` after exercising the app.")

        # <instrumentation> — sibling of <application>, bottom of the file.
        for inst in self.root.kids("instrumentation"):
            self.add("H3", "HIGH", "<instrumentation> shipped in the manifest",
                     where=inst.gets("android:name", "?"),
                     evidence='targetPackage="%s"' % inst.gets("android:targetPackage", "?"),
                     why="A declared instrumentation runner can be launched with "
                         "`am instrument` and executes INSIDE the target app's process with "
                         "the target app's UID and permissions. If the runner class is "
                         "actually present in the DEX, anyone with adb runs code in the "
                         "app's sandbox. Even when the class is absent, its presence proves "
                         "a test artefact reached the shipped build. This element sits "
                         "outside <application> at the bottom of the file, which is why it "
                         "is missed constantly.",
                     fix="Remove the <instrumentation> element from release variants; keep "
                         "test runners in androidTest sources so they are only merged into "
                         "the test APK.")

        # <original-package>, <protected-broadcast> etc.
        for op in self.root.kids("original-package"):
            self.add("MISC", "INFO", "<original-package> present",
                     where=op.gets("android:name", "?"),
                     why="The package was renamed. Affects identity, and therefore affects "
                         "which data directory and which authority conventions apply.")
        if self.root.kids("protected-broadcast"):
            self.add("MISC", "INFO", "<protected-broadcast> in a non-system manifest",
                     why="Only the platform manifest can define protected broadcasts. In a "
                         "third-party APK it has no effect, but it tells you the developer "
                         "copied from a system manifest.")

    def _version_matrix(self):
        t = self.target_sdk
        rows = []
        if t < 31:
            rows.append(("31", "android:exported is not mandatory, so components with an "
                               "intent-filter are exported by DEFAULT; PendingIntent "
                               "mutability is unchecked, so a mutable PendingIntent handed "
                               "to another app can be filled in by the recipient and fired "
                               "with this app's identity"))
        if t < 33:
            rows.append(("33", "context-registered receivers do not have to declare "
                               "RECEIVER_EXPORTED / RECEIVER_NOT_EXPORTED, so a "
                               "dynamically registered receiver is effectively EXPORTED and "
                               "is completely invisible in this file"))
        if t < 28:
            rows.append(("28", "cleartext HTTP is permitted by default "
                               "(usesCleartextTraffic defaults to true)"))
        if t < 30:
            rows.append(("30", "package visibility filtering does not apply — the app can "
                               "enumerate every installed package with no declaration"))
        if t < 29:
            rows.append(("29", "scoped storage does not apply"))
        if t < 24:
            rows.append(("24", "user-added CA certificates are trusted by default, and "
                               "file:// URIs may be passed across app boundaries"))
        if t < 23:
            rows.append(("23", "install-time permissions and functional "
                               "MODE_WORLD_READABLE/WRITEABLE file modes"))
        if t < 34:
            rows.append(("34", "foregroundServiceType is not mandatory, so a foreground "
                               "service need not declare what it is doing"))

        if not rows:
            self.add("B1", "POSITIVE", "targetSdkVersion is current",
                     evidence="targetSdkVersion=%d" % t,
                     why="Every platform hardening in the Version Matrix is active.")
            return

        sev = "MEDIUM"
        if t < 28:
            sev = "HIGH"
        if t < 23:
            sev = "HIGH"

        body = "\n".join("  - below %s: %s" % (lvl, txt) for lvl, txt in rows)
        self.add("B1", sev, "Low targetSdkVersion re-enables a CLUSTER of insecure defaults",
                 evidence="targetSdkVersion=%d" % t,
                 why="A targetSdk finding is never one finding. Every protection below "
                     "applies only from the stated level, and this app has opted out of "
                     "all of them:\n" + body,
                 fix="Raise targetSdkVersion and re-test. Each row above becomes a separate "
                     "regression test.")

    # -------------------------------------------------------------------- C

    def audit_application(self):
        app = self.application
        if app is None:
            self.add("C0", "INFO", "No <application> element",
                     why="A manifest with no <application> is a library manifest, a split, "
                         "or a stub. Nothing below applies.")
            return

        # C13 — the Application class is the first app code that runs.
        appname = app.gets("android:name")
        if appname:
            self.add("C13", "INFO", "Application class — read this first in JADX",
                     where=appname,
                     why="Application.onCreate runs before any Activity. Root detection, "
                         "SSL pinning setup, native library loading and anti-instrumentation "
                         "checks live here. Note also that a <provider> with a high "
                         "initOrder runs EARLIER still.")

        # C1 — debuggable.
        dbg = app.get("android:debuggable")
        if dbg is not None and dbg.as_bool():
            self.add("C1", "CRITICAL", "android:debuggable=\"true\"",
                     evidence=self._ev(dbg),
                     why="`adb shell run-as <pkg>` gives a shell as the app's UID with full "
                         "read/write of its private data, JDWP debugging attaches to the "
                         "process, and Frida/Objection need no root. USB access alone is "
                         "enough. In a release build this is never intentional.",
                     fix="Remove android:debuggable from the manifest entirely and let the "
                         "build type control it. Confirm on the shipped artefact with "
                         "`aapt2 dump badging target.apk | grep -i debug`.")
        elif dbg is None:
            self.add("C1", "INFO", "android:debuggable absent from this file",
                     why="ABSENCE PROVES NOTHING. Gradle's debug build type sets debuggable "
                         "during the merge, so the source manifest is clean while the "
                         "shipped APK is debuggable. This check is only meaningful against "
                         "a decoded APK.",
                     fix="Verify on the artefact: `aapt2 dump badging target.apk | grep -i "
                         "debug`, or on-device: "
                         "`adb shell dumpsys package <pkg> | grep -E 'flags='` and look for "
                         "DEBUGGABLE.",
                     proven=False)

        # C2 — testOnly.
        t = app.get("android:testOnly")
        if t is not None and t.as_bool():
            self.add("C2", "HIGH", "android:testOnly=\"true\"",
                     evidence=self._ev(t),
                     why="A testOnly APK can only be installed with `pm install -t`. Android "
                         "Studio's Run button sets this. Its presence in a distributed build "
                         "means the pipeline shipped a debug artefact — and testOnly very "
                         "often travels with debuggable.",
                     fix="Ship the assembleRelease output, not the IDE's install artefact.")

        # C4/C5/C6 — backup.
        self._audit_backup(app)

        # C7/C8 — network.
        self._audit_network(app)

        # C11 — legacy storage.
        for attr, sev in (("android:requestLegacyExternalStorage", "MEDIUM"),
                          ("android:preserveLegacyExternalStorage", "LOW")):
            v = app.get(attr)
            if v is not None and v.as_bool():
                self.add("C11", sev, "%s=\"true\"" % attr.split(":")[1],
                         evidence=self._ev(v),
                         why="The app opts out of scoped storage where the platform still "
                             "honours it (ignored from targetSdk 30 for "
                             "requestLegacyExternalStorage). Its presence means the code "
                             "was written against the pre-scoped-storage model and probably "
                             "still contains that path.",
                         fix="Migrate to MediaStore / SAF and remove the attribute.")

        # C12 — appComponentFactory.
        acf = app.gets("android:appComponentFactory")
        if acf and not acf.startswith("androidx.core.app.CoreComponentFactory"):
            self.add("C12", "MEDIUM", "Custom android:appComponentFactory",
                     where=acf,
                     why="This class instantiates every Activity, Service, Receiver, "
                         "Provider, Application and ClassLoader in the app. It is the "
                         "earliest app-controlled hook point in the process. Packers and "
                         "malware use it; so can you. If the app has no obvious reason for "
                         "one, read this class before anything else.",
                     fix="None required if legitimate — this is an investigation lead.")

        # C9/C10 and the rest.
        v = app.get("android:allowClearUserData")
        if v is not None and not v.as_bool():
            self.add("C9", "LOW", 'android:allowClearUserData="false"',
                     why="Where it takes effect (system/privileged apps), the user cannot "
                         "clear the app's data from Settings, so leaked secrets on the "
                         "device cannot be removed by the user.")
        v = app.get("android:hasFragileUserData")
        if v is not None and v.as_bool():
            self.add("C10", "LOW", 'android:hasFragileUserData="true"',
                     why="Data survives uninstall and is handed to a reinstalled app with "
                         "the same package name. Worth noting on an app holding secrets.")
        v = app.get("android:hasCode")
        if v is not None and not v.as_bool():
            self.add("C14", "MEDIUM", 'android:hasCode="false"',
                     why="The app declares it contains no DEX. If classes.dex is present "
                         "anyway, code is being loaded another way — check for a packer, "
                         "assets/*.dex, or a native loader.",
                     fix="Investigate; not a defect on its own for a pure-resource split.")
        v = app.get("android:process")
        if v is not None and not str(v).startswith(":"):
            self.add("C15", "LOW", "Global (non-private) process name on <application>",
                     evidence=self._ev(v),
                     why="A process name without a leading ':' can be shared with apps "
                         "signed by the same key. A private process name starts with ':'.",
                     fix="Prefix the process name with ':' unless sharing is intended.")
        v = app.get("android:vmSafeMode")
        if v is not None and v.as_bool():
            self.add("C16", "INFO", 'android:vmSafeMode="true"',
                     why="Disables JIT/AOT optimisation. Occasionally used by packers, and "
                         "it makes every method interpreted, which is convenient for "
                         "hooking.")
        for attr in ("android:memtagMode", "android:gwpAsanMode"):
            if app.has(attr):
                self.add("HARDEN", "POSITIVE", "%s declared" % attr.split(":")[1],
                         evidence=self._ev(app.get(attr)),
                         why="Opt-in native memory-safety hardening. Its presence means the "
                             "developer is doing something right — say so in the report.")

        # <profileable> lives inside <application>.
        for p in app.kids("profileable"):
            shell = p.get("android:shell")
            enabled = p.get("android:enabled")
            if shell is not None and shell.as_bool() and \
                    (enabled is None or enabled.as_bool()):
                self.add("C3", "MEDIUM", '<profileable android:shell="true"> in the build',
                         why="Allows UID 2000 (shell) to profile the app with simpleperf, "
                             "perfetto and heap dumps on a NON-debuggable production build. "
                             "You do not get run-as or JDWP, but you do get memory profiling "
                             "and native stack sampling from an unprivileged shell, which can "
                             "expose secrets held in memory.",
                         fix="Restrict <profileable> to debug variants unless field "
                             "profiling is an explicit product requirement.")

    def _audit_backup(self, app):
        allow = app.get("android:allowBackup")
        # Default is true when the attribute is absent.
        allowed = True if allow is None else allow.as_bool()
        has_full = app.has("android:fullBackupContent")
        has_der = app.has("android:dataExtractionRules")
        agent = app.gets("android:backupAgent")

        if not allowed:
            self.add("C4", "POSITIVE", 'android:allowBackup="false"',
                     why="Auto Backup and adb backup are both disabled. This branch of the "
                         "audit closes here.")
        else:
            basis = "explicit" if allow is not None else "DEFAULT (attribute absent)"
            if not has_full and not has_der:
                self.add("C5", "HIGH",
                         "Backup enabled with NO rules file — everything is backed up",
                         evidence="allowBackup=%s (%s); no fullBackupContent, no "
                                  "dataExtractionRules" % (allowed, basis),
                         why="Every file in the private data directory except no_backup/ "
                             "and cache/ leaves the device: shared_prefs (session tokens, "
                             "refresh tokens, PII), databases, and files/. On platforms "
                             "where `adb backup` still functions this is extractable over "
                             "USB with no root.",
                         fix='android:allowBackup="false", or a dataExtractionRules XML '
                             'that excludes every credential store from BOTH <cloud-backup> '
                             'and <device-transfer>.',
                         proven=False)
            else:
                self.add("C5", "MEDIUM", "Backup enabled with a rules file — read the rules",
                         evidence="allowBackup=%s (%s); fullBackupContent=%s "
                                  "dataExtractionRules=%s" % (
                                      allowed, basis,
                                      app.gets("android:fullBackupContent", "-"),
                                      app.gets("android:dataExtractionRules", "-")),
                         why="Anything not explicitly excluded is backed up. "
                             "dataExtractionRules has TWO independent rule sets — "
                             "<cloud-backup> and <device-transfer>. An app that excluded a "
                             "secret from cloud backup but not from device transfer has an "
                             "incomplete fix.",
                         fix="Resolve the referenced XML from res/xml/, enumerate the actual "
                             "files in the data directory, and list what would leave.",
                         proven=False)

            if allow is None:
                self.add("C4b", "INFO", "allowBackup relies on the platform default",
                         why="Absent means true. Relying on a default for a security-relevant "
                             "switch is fragile; state it explicitly.",
                         fix='Declare android:allowBackup explicitly either way.')

        if agent:
            self.add("C4c", "INFO", "Custom BackupAgent declared",
                     where=agent,
                     why="Key-value backup implemented by hand. Read the agent: developers "
                         "frequently serialise tokens into the backup stream themselves, "
                         "bypassing whatever the rules file excludes.")

        v = app.get("android:restoreAnyVersion")
        if v is not None and v.as_bool():
            self.add("C4d", "LOW", 'android:restoreAnyVersion="true"',
                     why="A backup produced by a NEWER version of the app may be restored. "
                         "Combined with a weak deserialiser, a crafted backup becomes an "
                         "attacker-controlled input channel.")

    def _audit_network(self, app):
        nsc = app.gets("android:networkSecurityConfig")
        clear = app.get("android:usesCleartextTraffic")

        if clear is not None and clear.as_bool():
            self.add("C7", "HIGH", 'android:usesCleartextTraffic="true"',
                     evidence=self._ev(clear),
                     why="The platform's network stacks will permit plaintext HTTP. "
                         "Combined with real HTTP endpoints this is a straightforward "
                         "machine-in-the-middle finding. Note that a networkSecurityConfig, "
                         "when present, SUPERSEDES this attribute.",
                     fix='Remove the attribute (or set it to false) and add a Network '
                         'Security Config with cleartextTrafficPermitted="false".',
                     proven=False)
        elif clear is None and self.target_sdk is not None and self.target_sdk <= 27:
            self.add("C7", "HIGH",
                     "Cleartext HTTP permitted by DEFAULT (targetSdk<=27)",
                     evidence="targetSdkVersion=%d, no usesCleartextTraffic attribute"
                              % self.target_sdk,
                     why="usesCleartextTraffic only defaults to false from targetSdk 28. "
                         "Below that, plain HTTP works with no configuration and no warning. "
                         "This is the invisible version of the finding above.",
                     fix="Raise targetSdk to 28+ AND ship a Network Security Config.",
                     proven=False)

        if not nsc:
            sev = "MEDIUM"
            self.add("C8", sev, "No android:networkSecurityConfig",
                     why="Without an explicit config the app inherits the platform defaults "
                         "for its targetSdk. There is no pinning, no per-domain policy, and "
                         "no explicit statement of which domains may use cleartext.",
                     fix="Add a Network Security Config. See "
                         "../../44-NetworkSecurityConfig/README.md.")
        else:
            self.add("C8", "INFO", "networkSecurityConfig present — you MUST read it",
                     where=nsc,
                     why="This referenced file is frequently the highest-value single file "
                         "in the APK. It can re-enable cleartext for named domains, add a "
                         "user-trust anchor (making a Burp CA trusted), ship "
                         "<debug-overrides> into production, or pin certificates.",
                     fix="Resolve it: apktool output res/xml/, then read every "
                         "<domain-config>, every <trust-anchors>, and check for "
                         "<debug-overrides>.",
                     proven=False)

    # -------------------------------------------------------------------- D

    def audit_components(self):
        if self.application is None:
            return

        counts = {t: [0, 0] for t in COMPONENT_TAGS}  # [total, exported]

        for tag in COMPONENT_TAGS:
            for comp in self.application.descendants(tag):
                node_marker = comp.gets("tools:node", "")
                if node_marker in ("remove", "removeAll"):
                    # A merger directive, not a shipped component. Its presence is
                    # informative in the opposite direction: it names something a
                    # library WOULD have injected.
                    self.add("MERGE", "POSITIVE",
                             'tools:node="%s" removes a library-injected component'
                             % node_marker,
                             where="%s %s" % (tag, comp.name(self.package)),
                             why="The developer read the merged manifest and deliberately "
                                 "deleted a component contributed by a dependency. That is "
                                 "the correct remediation pattern for SDK injection.")
                    continue
                counts[tag][0] += 1
                exported, basis, confident = self.effective_exported(comp)
                if exported:
                    counts[tag][1] += 1
                self._audit_one_component(comp, exported, basis, confident)

        self.stats["components"] = counts

    def _audit_one_component(self, comp, exported, basis, confident):
        tag = comp.tag
        cname = comp.name(self.package)
        perm, perm_src = self.component_permission(comp)

        # activity-alias needs its own treatment first.
        if tag == "activity-alias":
            self._audit_alias(comp, exported, perm)

        # A provider's access control is readPermission/writePermission (each
        # falling back to android:permission), not android:permission alone.
        # Handling that in _audit_provider avoids a duplicate, wrongly-worded D3.
        if exported and tag != "provider":
            self._audit_exported_component(comp, cname, basis, confident, perm, perm_src)

        # Attributes that matter regardless of export state.
        if tag in ("activity", "activity-alias"):
            self._audit_activity_attrs(comp, cname, exported)
        elif tag == "service":
            self._audit_service_attrs(comp, cname, exported, perm)
        elif tag == "receiver":
            self._audit_receiver_attrs(comp, cname, exported)
        elif tag == "provider":
            self._audit_provider(comp, cname, exported, basis)

        if comp.get("android:directBootAware") is not None and \
                comp.get("android:directBootAware").as_bool():
            self.add("D11", "LOW", "directBootAware component runs before first unlock",
                     where="%s %s" % (tag, cname),
                     why="The component can execute in the window before the user has ever "
                         "unlocked the device, when only device-encrypted storage is "
                         "available and the lock screen is not yet an obstacle. It must not "
                         "touch credential-encrypted storage — verify that it does not.")

        v = comp.get("android:enabled")
        if v is not None and not v.as_bool():
            self.add("D18", "INFO", "Component declared disabled",
                     where="%s %s" % (tag, cname),
                     why="`enabled=\"false\"` is NOT permanent unreachability. The app can "
                         "flip it at runtime with "
                         "PackageManager.setComponentEnabledSetting, and aliases are "
                         "routinely toggled to change the launcher icon. Grep the DEX for "
                         "setComponentEnabledSetting, and check the live state with "
                         "`adb shell dumpsys package <pkg>`.")

        for md in comp.kids("meta-data"):
            self._audit_metadata(md, "%s %s" % (tag, cname))

        for f in comp.kids("intent-filter"):
            self._audit_intent_filter(f, comp, cname, exported)

    def _audit_exported_component(self, comp, cname, basis, confident, perm, perm_src):
        tag = comp.tag

        if perm is None:
            self.add("D3", "MEDIUM",
                     "Exported %s with NO permission" % tag,
                     where=cname,
                     evidence="exported=true (%s)" % basis,
                     why="Any application on the device may reach this component with a "
                         "fully attacker-controlled Intent (or ContentResolver call). "
                         "Severity escalates to High or Critical once you establish what the "
                         "component DOES — a state change, a data read, a WebView load, a "
                         "credential handoff.",
                     fix='android:exported="false" if it does not need to be reachable; '
                         'otherwise a signature-level permission plus an in-code check on '
                         'Binder.getCallingUid().',
                     proven=False)
            if not confident:
                self.add("D2", "INFO", "Export state inferred, not read",
                         where=cname,
                         evidence=basis,
                         why="Confirm against the device before reporting: "
                             "`adb shell dumpsys package <pkg>` is authoritative.",
                         proven=False)
            return

        level, source = self.resolve_protection(perm)

        if perm in SYSTEM_BIND_PERMISSIONS:
            self.add("D6b", "POSITIVE",
                     "Exported %s guarded by a system BIND_ permission" % tag,
                     where=cname,
                     evidence='android:permission="%s"' % perm,
                     why="This is the CORRECT configuration for a system-bound component: "
                         "the component must be exported because the platform binds to it, "
                         "and only the system holds this permission. Do not report it as an "
                         "exported-component finding. The finding would be its ABSENCE.")
            return

        if source == "unknown":
            self.add("D4", "MEDIUM",
                     "Exported %s guarded by a permission of UNKNOWN level" % tag,
                     where=cname,
                     evidence='android:permission="%s" (declared %s)'
                              % (perm, "in this manifest" if perm in self.declared_permissions
                                 else "elsewhere — not in this manifest"),
                     why="A permission is only a control if its protectionLevel is signature "
                         "or (with caveats) dangerous. A normal-level permission is granted "
                         "automatically to any app that declares <uses-permission>, so it "
                         "provides zero access control. This script will not guess.",
                     fix="Resolve it on a device: "
                         "`adb shell pm list permissions -f | grep -A6 %s`" % perm,
                     proven=False)
            return

        base = level.split("|")[0].strip() if level else "normal"

        if base == "normal":
            self.add("D4", "HIGH",
                     "Exported %s guarded by a NORMAL-level permission (no protection)" % tag,
                     where=cname,
                     evidence='android:permission="%s" -> protectionLevel="%s" (%s)'
                              % (perm, level, source)
                              + ("; the attribute was OMITTED, and omitted means normal"
                                 if source == "declared-default" else ""),
                     why="A normal permission is granted automatically, with no user prompt "
                         "and no signature check, to any app that simply declares "
                         "<uses-permission>. The component is therefore reachable by every "
                         "app on the device, exactly as if no permission were set. This is "
                         "one of the most common real findings and developers dispute it "
                         "until you show them the attacker manifest that acquires it.",
                     fix='android:protectionLevel="signature" on the <permission>, plus an '
                         'in-code caller check. If third-party apps genuinely need access, '
                         'use "dangerous" with a clear description and still check the '
                         'caller in code.',
                     proven=False)
        elif base == "dangerous":
            self.add("D4b", "MEDIUM",
                     "Exported %s guarded by a DANGEROUS permission" % tag,
                     where=cname,
                     evidence='android:permission="%s" -> "%s" (%s)' % (perm, level, source),
                     why="The user is the control. A custom dangerous permission produces an "
                         "app-authored runtime prompt that users routinely accept. Better "
                         "than normal, weaker than signature.",
                     fix="Prefer signature for intra-vendor IPC.")
        elif "signature" in (level or ""):
            self.add("D4c", "POSITIVE",
                     "Exported %s guarded by a signature-level permission" % tag,
                     where=cname,
                     evidence='android:permission="%s" -> "%s" (%s)' % (perm, level, source),
                     why="Only apps signed with the same certificate can be granted this. "
                         "For a third-party attacker that means unreachable. Verify the "
                         "sibling apps really are same-signed with `apksigner verify "
                         "--print-certs` on both APKs.")

        if perm_src == "application":
            self.add("D3b", "INFO",
                     "Permission inherited from <application android:permission>",
                     where=cname,
                     why="A per-component android:permission OVERRIDES the application-level "
                         "one rather than adding to it. Any component that sets its own "
                         "permission — including an empty string — escapes the app-wide "
                         "requirement.")

    def _audit_alias(self, comp, exported, perm):
        cname = comp.name(self.package)
        target = comp.gets("android:targetActivity", "?")
        # Find the target Activity to compare posture.
        tnode = None
        for a in self.application.descendants("activity"):
            if a.name(self.package) == (self.package + target if target.startswith(".")
                                        else target):
                tnode = a
                break

        pv = comp.get("android:permission")
        if pv is not None and str(pv) == "":
            self.add("D5", "HIGH", 'activity-alias with android:permission=""',
                     where=cname,
                     why="An empty permission string REMOVES the application-level permission "
                         "requirement for this entry point. It is not 'no opinion'; it is an "
                         "explicit opt-out.",
                     fix="Delete the attribute, or set a real permission.")

        if tnode is not None:
            t_exported, _, _ = self.effective_exported(tnode)
            t_perm, _ = self.component_permission(tnode)
            weaker = (exported and not t_exported) or \
                     (exported and t_perm and not perm)
            if weaker:
                self.add("D5", "HIGH",
                         "activity-alias is WEAKER than the Activity it targets",
                         where="%s -> %s" % (cname, target),
                         evidence="alias exported=%s permission=%s | target exported=%s "
                                  "permission=%s" % (exported, perm, t_exported, t_perm),
                         why="An <activity-alias> is a second, independently configured entry "
                             "point to an existing Activity. Its exported and permission "
                             "attributes are its own and do NOT inherit from the target. An "
                             "Activity declared exported=\"false\" with a strong permission "
                             "is fully reachable through an alias that declares neither. "
                             "Auditors who grep only for '<activity' miss this entirely.",
                         fix="Give the alias the same posture as its target, or delete it.")
        else:
            self.add("D5b", "INFO", "activity-alias targetActivity not resolvable here",
                     where="%s -> %s" % (cname, target),
                     why="Resolve the target manually and compare exported/permission. The "
                         "alias's posture is independent of the target's.")

    def _audit_activity_attrs(self, comp, cname, exported):
        lm = comp.gets("android:launchMode")
        aff = comp.get("android:taskAffinity")
        app_aff = self.application.get("android:taskAffinity") if self.application else None

        affinity_is_default = (aff is None and (app_aff is None or str(app_aff) != ""))
        affinity_is_empty = (aff is not None and str(aff) == "") or \
                            (aff is None and app_aff is not None and str(app_aff) == "")

        if lm in ("singleTask", "singleInstance") and affinity_is_default:
            self.add("D13", "MEDIUM",
                     "Task hijacking configuration: %s with a default taskAffinity" % lm,
                     where=cname,
                     evidence='launchMode="%s", taskAffinity not set (defaults to the '
                              'package name)' % lm,
                     why="A malicious app can declare an Activity with "
                         "taskAffinity=\"<this package>\" and launchMode=\"singleTask\". "
                         "Once its task exists, launching the victim from the launcher can "
                         "bring the ATTACKER'S task forward, so the user sees the attacker's "
                         "UI believing it is this app. This is the StrandHogg family.",
                     fix='android:taskAffinity="" on the launcher Activity, or better, '
                         'on <application> app-wide.',
                     proven=False)

        if affinity_is_empty:
            self.add("D14", "POSITIVE", 'taskAffinity="" — task hijacking closed',
                     where=cname,
                     why="An Activity with no affinity has no task identity for another app "
                         "to adopt.")

        v = comp.get("android:allowTaskReparenting")
        if v is not None and v.as_bool():
            self.add("D15", "MEDIUM", 'allowTaskReparenting="true"',
                     where=cname,
                     why="The Activity may move into another task whose affinity matches "
                         "when that task comes to the foreground. Combined with affinity "
                         "manipulation, a malicious app can adopt this Activity into its own "
                         "task.",
                     fix="Remove the attribute.")

        for attr, sev, note in (
            ("android:showWhenLocked", "MEDIUM",
             "The Activity displays OVER the lock screen. An attacker with physical access "
             "to a locked device reaches this UI; if the Activity is also exported, any app "
             "can force it to appear."),
            ("android:turnScreenOn", "MEDIUM",
             "Starting the Activity wakes the screen. Combined with showWhenLocked and "
             "exported, any app can light up a locked phone with an attacker-chosen screen."),
            ("android:allowEmbedded", "MEDIUM",
             "The Activity may be launched as an embedded child of another Activity, which "
             "invites UI-embedding and clickjacking scenarios on a sensitive screen."),
        ):
            v = comp.get(attr)
            if v is not None and v.as_bool():
                self.add("D12", sev if exported else "LOW",
                         '%s="true"' % attr.split(":")[1], where=cname, why=note,
                         fix="Remove unless the screen genuinely needs it, and never combine "
                             "with exported on a sensitive Activity.",
                         proven=False)

        v = comp.get("android:multiprocess")
        if v is not None and v.as_bool():
            self.add("D19", "MEDIUM", 'android:multiprocess="true"',
                     where=cname,
                     why="Legacy attribute: an instance of this Activity can run in the "
                         "CALLER'S process. Very rare and worth reading the code for.")

        v = comp.get("android:lockTaskMode")
        if v is not None and str(v) in ("always", "if_whitelisted"):
            self.add("D20", "INFO", "lockTaskMode set (kiosk-relevant)",
                     where=cname, evidence=self._ev(v),
                     why="On a kiosk assessment this is a primary attribute: it governs "
                         "whether the user can escape the pinned app.")

        if comp.has("android:requireContentUriPermissionFromCaller"):
            self.add("HARDEN", "POSITIVE",
                     "requireContentUriPermissionFromCaller declared (API 35+)",
                     where=cname,
                     why="The caller must already hold read/write permission on any "
                         "content:// URI it passes in the Intent. A genuinely useful modern "
                         "hardening attribute.")

    def _audit_service_attrs(self, comp, cname, exported, perm):
        # A service guarded by a system BIND_ permission is exported because the
        # PLATFORM binds to it, and only the platform holds that permission.
        # Reporting it as an RPC surface is the classic tool-operator mistake —
        # see README section 9.5. The finding there would be its ABSENCE.
        if exported and perm in SYSTEM_BIND_PERMISSIONS:
            exported = False

        if exported:
            lvl, _src = self.resolve_protection(perm) if perm else (None, "unknown")
            gated = bool(lvl) and "signature" in lvl
            self.add("D6", "MEDIUM" if gated else "HIGH",
                     "Exported Service — treat as a full RPC endpoint"
                     + (" (gated to same-signed callers)" if gated else ""),
                     where=cname,
                     evidence="permission=%s%s" % (perm or "NONE",
                                                   " -> %s" % lvl if lvl else ""),
                     why="If this Service returns an IBinder from onBind, an attacker gets "
                         "the interface and can call EVERY method on it, with arbitrary "
                         "arguments, repeatedly, with no UI. That is strictly worse than an "
                         "exported Activity. Open the class in JADX, find onBind, find the "
                         "Stub it returns, and enumerate the TRANSACTION_* constants — each "
                         "one is a callable method.",
                     fix='android:exported="false", or a signature permission plus a '
                         'per-method caller check using Binder.getCallingUid().',
                     proven=False)

        v = comp.get("android:isolatedProcess")
        if v is not None and v.as_bool():
            self.add("D7", "POSITIVE", 'android:isolatedProcess="true"',
                     where=cname,
                     why="The service runs in a special process with no permissions of its "
                         "own, no access to the app's data directory, and essentially no "
                         "Binder access to system services. This is Android's built-in "
                         "sandbox for parsing untrusted input, and using it is a sign of a "
                         "mature threat model.")

        fst = comp.gets("android:foregroundServiceType")
        if fst:
            types = [t.strip() for t in fst.split("|") if t.strip()]
            unknown = [t for t in types if t not in FOREGROUND_SERVICE_TYPES]
            self.add("D8", "INFO", "foregroundServiceType declared",
                     where=cname, evidence=fst,
                     why="This is a declaration of capability you can audit against "
                         "behaviour. camera / microphone / location here means the app runs "
                         "those sensors in the BACKGROUND. Verify each declared type is "
                         "actually used.")
            if "specialUse" in types:
                self.add("D8b", "MEDIUM", 'foregroundServiceType="specialUse"',
                         where=cname,
                         why="specialUse is the 'we did not fit a category' escape hatch and "
                             "requires a <property> justification string. Read that "
                             "justification: it is the developer's own account of what the "
                             "background service does, and on a malware assessment it is a "
                             "plausible-sounding cover story.",
                         fix="Check for PROPERTY_SPECIAL_USE_FGS_SUBTYPE and compare it "
                             "against observed behaviour.")
            if unknown:
                self.add("D8c", "LOW", "Unrecognised foregroundServiceType value",
                         where=cname, evidence=", ".join(unknown),
                         why="Either a newer platform type than this script knows, or a "
                             "typo that will fail at runtime.")
        elif self.target_sdk is not None and self.target_sdk >= 34:
            self.add("D8", "LOW", "No foregroundServiceType on targetSdk>=34",
                     where=cname,
                     why="Mandatory from targetSdk 34 for foreground services. If this "
                         "service never calls startForeground the attribute is not needed — "
                         "confirm from the code rather than assuming.",
                     proven=False)

        v = comp.get("android:externalService")
        if v is not None and v.as_bool():
            self.add("D21", "INFO", 'android:externalService="true"',
                     where=cname,
                     why="Only meaningful with isolatedProcess. The isolated service runs "
                         "under the CALLING app's UID, letting the caller supply the sandbox. "
                         "Rare and interesting — read the code.")

    def _audit_receiver_attrs(self, comp, cname, exported):
        if exported:
            self.add("D9", "MEDIUM", "Exported BroadcastReceiver",
                     where=cname,
                     why="Any app can deliver an Intent with attacker-controlled extras. The "
                         "classic finding is a receiver that reads an extra and acts on it: "
                         "starting a download from an attacker URL, changing a server "
                         "endpoint, clearing data, logging the user out, or forwarding a "
                         "token. Read onReceive and trace every getStringExtra.",
                     fix='android:exported="false" plus LocalBroadcastManager or an explicit '
                         'Intent, or a signature permission.',
                     proven=False)

        for f in comp.kids("intent-filter"):
            pv = f.get("android:priority")
            pri = pv.as_int() if pv is not None else None
            if pri is not None and pri >= 100:
                self.add("D10", "MEDIUM", "Receiver intent-filter with high priority",
                         where=cname, evidence="priority=%d" % pri,
                         why="For ORDERED broadcasts the highest-priority receiver runs "
                             "first and may call abortBroadcast() so no later receiver sees "
                             "the message. That is the historical SMS-interception pattern, "
                             "and it still works between apps on custom ordered broadcasts. "
                             "Values above 1000 are documented as reserved for the system.",
                         proven=False)

    # -------------------------------------------------------------------- E

    def _audit_provider(self, comp, cname, exported, basis):
        auth = comp.gets("android:authorities", "")
        authorities = [a.strip() for a in auth.split(";") if a.strip()]

        self.add("E1", "INFO", "Provider authority inventory",
                 where=cname,
                 evidence=", ".join(authorities) or "<none declared>",
                 why="Each authority is an address an attacker types. Every one of them is "
                     "an endpoint to enumerate with `content query --uri content://<auth>/…`.")

        for a in authorities:
            if "${" in a:
                continue  # a build-time placeholder, resolved by the merger
            if not a.startswith(self.package) and self.package not in a:
                self.add("E9", "LOW", "Authority not namespaced under the package",
                         where=cname, evidence=a,
                         why="A non-unique authority can collide with another app's. On "
                             "install the SECOND app to claim an authority fails to install, "
                             "which is a denial of service, and on a device where install "
                             "order is controllable it is an authority-squatting "
                             "opportunity.",
                         fix='Use "${applicationId}.something".')

        gen = comp.gets("android:permission")
        rp = comp.gets("android:readPermission") or gen
        wp = comp.gets("android:writePermission") or gen
        grants = comp.get("android:grantUriPermissions")
        grants_on = grants is not None and grants.as_bool()
        grant_children = comp.kids("grant-uri-permission")
        path_perms = comp.kids("path-permission")

        if exported:
            if not rp:
                self.add("E2", "HIGH", "Exported provider with NO read permission",
                         where=cname, evidence="exported=true (%s)" % basis,
                         why="Every app on the device can call query() and openFile() in read "
                             "mode against every URI under this authority. If the provider is "
                             "backed by the app's database, this is direct data disclosure.",
                         fix="Set readPermission (signature level) or set exported=\"false\".",
                         proven=False)
            if not wp:
                self.add("E3", "HIGH", "Exported provider with NO write permission",
                         where=cname,
                         evidence="readPermission=%s, writePermission=absent" % (rp or "absent"),
                         why="insert(), update() and delete() are unprotected. This is "
                             "startlingly common because developers set readPermission and "
                             "assume it covers both directions. Write access to an app's own "
                             "database is frequently a privilege escalation: flip an "
                             "is_premium column, inject a row the app later trusts, or "
                             "overwrite a stored server URL.",
                         fix="Set writePermission explicitly, always, even when it is the "
                             "same value as readPermission.",
                         proven=False)

            for label, p in (("readPermission", rp), ("writePermission", wp)):
                if not p:
                    continue
                level, source = self.resolve_protection(p)
                if source == "unknown":
                    self.add("E4", "MEDIUM",
                             "Provider %s has an UNKNOWN protection level" % label,
                             where=cname, evidence=p,
                             fix="`adb shell pm list permissions -f | grep -A6 %s`" % p,
                             why="Resolve it before deciding whether the provider is "
                                 "protected.",
                             proven=False)
                elif level and level.split("|")[0] == "normal":
                    self.add("E4", "HIGH",
                             "Provider %s is a NORMAL-level permission" % label,
                             where=cname,
                             evidence='%s="%s" -> protectionLevel="%s" (%s)'
                                      % (label, p, level, source),
                             why="Granted automatically to any app that declares it. The "
                                 "provider is effectively unprotected in that direction.",
                             fix='protectionLevel="signature".')

        if grants_on and not grant_children and not exported:
            self.add("E5", "INFO",
                     'grantUriPermissions="true" on a NON-exported provider',
                     where=cname,
                     why="This is the FileProvider pattern and it is correct: the component "
                         "is closed, and access comes exclusively from per-URI grants attached "
                         "to an Intent. The risk moves entirely into (a) which paths the "
                         "<paths> resource exposes and (b) which URIs the app chooses to grant "
                         "— read both, but do not report the attribute itself.",
                     proven=False)
        elif grants_on and not grant_children:
            self.add("E5", "MEDIUM",
                     'grantUriPermissions="true" with no <grant-uri-permission> child',
                     where=cname,
                     why="ANY URI under this authority can be granted with "
                         "FLAG_GRANT_READ_URI_PERMISSION / FLAG_GRANT_WRITE_URI_PERMISSION, "
                         "bypassing readPermission and writePermission for the granted URI. "
                         "Now find an exported Activity that returns a result, or a "
                         "PendingIntent handed to another app, and this becomes 'temporary "
                         "access to one image' turning into 'read any file the app can read'.",
                     fix="Set grantUriPermissions=\"false\" and add narrow "
                         "<grant-uri-permission android:pathPrefix=\"/shared/\"/> children.",
                     proven=False)
        elif grants_on and grant_children:
            self.add("E5", "INFO", "grantUriPermissions restricted by child elements",
                     where=cname,
                     evidence="; ".join(self._path_desc(g) for g in grant_children),
                     why="Narrow grant paths are good design. Verify the paths cannot be "
                         "escaped by a non-normalised URI (see E6/E10).")

        for pp in path_perms:
            self.add("E6", "MEDIUM", "<path-permission> present — it usually WIDENS access",
                     where=cname,
                     evidence=self._path_desc(pp) + " read=%s write=%s" % (
                         pp.gets("android:readPermission", "-"),
                         pp.gets("android:writePermission", "-")),
                     why="path-permission is an OR, not an AND. A caller who satisfies EITHER "
                         "the component permission OR a matching path permission is allowed. "
                         "So adding a path-permission with a weaker permission to a "
                         "strongly protected provider OPENS that path. Worse: if the provider "
                         "declares no component-level permission, any path that matches NO "
                         "path-permission rule is allowed by default — the developer's mental "
                         "model of 'I locked down the sensitive paths' is exactly backwards.",
                     fix="Enforce authorisation in code inside query/insert/update/delete/"
                         "call/openFile, using Binder.getCallingUid(), rather than trying to "
                         "express it with path-permission.",
                     proven=False)
            perm_here = pp.gets("android:readPermission")
            if perm_here:
                lvl, src = self.resolve_protection(perm_here)
                if lvl and lvl.split("|")[0] == "normal":
                    self.add("E6b", "HIGH",
                             "<path-permission> grants a path to EVERY app",
                             where=cname,
                             evidence='%s readPermission="%s" -> "%s" (%s)'
                                      % (self._path_desc(pp), perm_here, lvl, src),
                             why="The path permission names a normal-level permission, which "
                                 "every app can obtain by declaring it. This path is public. "
                                 "The canonical example is "
                                 'readPermission="android.permission.INTERNET".',
                             fix="Delete the <path-permission> and check the caller in code.")

        if grants_on or path_perms:
            self.add("E10", "INFO",
                     "URI path matching is NOT normalised — test for traversal",
                     where=cname,
                     why="path / pathPrefix / pathPattern match the raw uri.getPath(). "
                         "content://auth/public/../secret/token.txt still has a path "
                         "beginning /public/, so it matches pathPrefix=\"/public/\", while a "
                         "provider that does new File(baseDir, segment) resolves it to "
                         "/secret/token.txt. Note pathPattern is a GLOB, not a regex: '*' "
                         "means zero-or-more of the PRECEDING character.",
                     fix="In openFile, resolve with getCanonicalPath() and verify the result "
                         "is still inside the intended directory before returning a "
                         "descriptor.",
                     proven=False)

        # FileProvider paths meta-data.
        for md in comp.kids("meta-data"):
            n = md.gets("android:name", "")
            if n in ("android.support.FILE_PROVIDER_PATHS",
                     "androidx.core.content.FileProvider.PATHS"):
                self.add("E7", "MEDIUM", "FileProvider <paths> configuration referenced",
                         where=cname,
                         evidence=md.gets("android:resource", "?"),
                         why="You must open this file. A <root-path name=\"root\" path=\"/\"/> "
                             "or <external-path path=\".\"/> entry exposes everything the app "
                             "can read through a provider that other apps are handed URIs "
                             "for. This is the single most common FileProvider defect.",
                         fix="Restrict to the narrowest subdirectory that works, never "
                             "root-path, never path=\".\" .",
                         proven=False)

        v = comp.get("android:forceUriPermissions")
        if v is not None and v.as_bool():
            self.add("HARDEN", "POSITIVE", 'forceUriPermissions="true"',
                     where=cname,
                     why="Requires a URI permission grant even for the app's own components.")

        io = comp.get("android:initOrder")
        if io is not None:
            self.add("E11", "INFO", "Provider initOrder set — early execution",
                     where=cname, evidence=self._ev(io),
                     why="Providers are created BEFORE Application.onCreate(). A provider is "
                         "therefore the earliest app code that runs, ahead of any anti-tamper "
                         "or pinning setup installed in Application.onCreate. Libraries use "
                         "this deliberately (AndroidX Startup, FirebaseInitProvider); so do "
                         "packers.")

        self.add("E8", "INFO", "Provider call() is not visible in the manifest",
                 where=cname,
                 why="ContentProvider.call() is an untyped RPC entry point — a method name, "
                     "an arg string, and a Bundle. It is gated by the same read/write "
                     "permissions only if the implementation checks them, and most do not. "
                     "You cannot audit it from the manifest. Decompile the provider and "
                     "enumerate the method strings, then fuzz it. See "
                     "../../27-ContentProviders/scripts/provider-call-fuzz.py.",
                 proven=False)

    @staticmethod
    def _path_desc(node):
        for a in ("android:path", "android:pathPrefix", "android:pathPattern",
                  "android:pathSuffix", "android:pathAdvancedPattern"):
            if node.has(a):
                return "%s=%s" % (a.split(":")[1], node.gets(a))
        return "<no path attribute>"

    # -------------------------------------------------------------------- F

    def audit_permissions(self):
        # Declared custom permissions.
        for p in self.root.descendants("permission"):
            name = p.gets("android:name", "?")
            lvl = p.gets("android:protectionLevel")
            if lvl is None:
                self.add("F1", "HIGH",
                         "Custom permission with NO protectionLevel (defaults to normal)",
                         where=name,
                         why="When the attribute is omitted the level is 'normal', which "
                             "means the permission is granted automatically to any app that "
                             "declares <uses-permission>. If this permission guards a "
                             "component, it guards nothing. Developers omit the attribute "
                             "believing the default is restrictive.",
                         fix='android:protectionLevel="signature"')
            else:
                base = lvl.split("|")[0].strip()
                if base == "normal":
                    self.add("F2", "HIGH", 'Custom permission at protectionLevel="normal"',
                             where=name, evidence=lvl,
                             why="Access control that grants itself. Any app obtains it by "
                                 "declaring <uses-permission android:name=\"%s\"/>." % name,
                             fix='protectionLevel="signature" for intra-vendor IPC.')
                elif base == "dangerous":
                    self.add("F2b", "MEDIUM", 'Custom permission at "dangerous"',
                             where=name, evidence=lvl,
                             why="An app-authored runtime prompt that users routinely accept "
                                 "is the only control.")
                elif "signature" in lvl:
                    self.add("F2c", "POSITIVE", "Custom permission at signature level",
                             where=name, evidence=lvl,
                             why="The correct level for inter-app IPC within one vendor's "
                                 "suite.")
                if "knownSigner" in lvl:
                    self.add("F2d", "INFO", "protectionLevel includes knownSigner",
                             where=name, evidence=lvl,
                             why="Grantable to apps signed by any certificate in the "
                                 "declaring app's android:knownCerts resource. Read that "
                                 "resource — it names the trusted signing identities.")
                if "development" in lvl:
                    self.add("F2e", "INFO", "protectionLevel includes 'development'",
                             where=name, evidence=lvl,
                             why="A development permission can be granted from the shell with "
                                 "`pm grant`, which means YOU can grant it during testing "
                                 "even though a real attacker could not. A frequent source of "
                                 "false positives.",
                             proven=False)

            self.add("F0", "INFO", "Custom permission name — squatting consideration",
                     where=name,
                     why="If two apps declare the same permission name, the FIRST installed "
                         "wins and its protectionLevel is the one that applies. A malicious "
                         "app installed before the victim can define this name as 'normal'. "
                         "Modern platforms have hardened this, but a custom permission is "
                         "only as strong as the guarantee that your app defines it.")

        # Requested permissions.
        requested = []
        for u in self.root.descendants("uses-permission"):
            n = u.gets("android:name")
            if n:
                requested.append((n, u))
        for u in self.root.descendants("uses-permission-sdk-23"):
            n = u.gets("android:name")
            if n:
                requested.append((n, u))

        self.stats["permissions_requested"] = len(requested)

        for name, node in requested:
            if name in HIGH_SIGNAL_PERMISSIONS:
                sev = "MEDIUM" if name in (
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_SMS",
                ) else "LOW"
                self.add("F4", sev, "High-signal permission requested",
                         where=name, evidence=HIGH_SIGNAL_PERMISSIONS[name],
                         why="Cross-check against observed functionality. A requested but "
                             "unused permission is over-privilege (MASVS-PLATFORM and a Play "
                             "policy issue); a requested and used one tells you where to look "
                             "next.",
                         proven=False)
            if not name.startswith("android.permission.") and \
                    not name.startswith("com.android.") and \
                    not name.startswith("android.") and \
                    name not in self.declared_permissions:
                self.add("F8", "INFO", "Custom permission requested but not declared here",
                         where=name,
                         why="Some OTHER app on the device declares this permission and "
                             "therefore sets its protectionLevel. Find out which app, and "
                             "what level it chose — if it is normal, this app is relying on "
                             "a control that does not exist.",
                         fix="`adb shell pm list permissions -f | grep -A6 %s`" % name,
                         proven=False)

        # <queries>
        for q in self.root.descendants("queries"):
            pkgs = [p.gets("android:name") for p in q.kids("package")]
            pkgs = [p for p in pkgs if p]
            if pkgs:
                self.add("F9", "INFO", "<queries> declares which packages the app looks for",
                         evidence=", ".join(pkgs[:25]) + (" …" if len(pkgs) > 25 else ""),
                         why="This is a statement of intent you can compare against "
                             "behaviour. A list of competitor apps, banking apps, or "
                             "root-management tools tells you what the app checks for before "
                             "you have read a line of code.")
                hits = sorted(set(p for p in pkgs
                                  if p.lower() in ROOT_DETECTION_QUERY_TARGETS))
                if hits:
                    self.add("F9b", "INFO", "<queries> lists root/hooking tool packages",
                             evidence=", ".join(hits),
                             why="The app performs package-name-based root or hooking "
                                 "detection. You now know exactly which checks to defeat. "
                                 "See ../../37-RootDetection/README.md.")
            if len(pkgs) > 30:
                self.add("F9c", "LOW", "<queries> enumerates a very large package list",
                         evidence="%d packages" % len(pkgs),
                         why="A long target list is characteristic of banking malware and of "
                             "aggressive anti-fraud SDKs. Read the whole list.")

        # uses-library
        for lib in self.root.descendants("uses-library"):
            n = lib.gets("android:name", "")
            if n == "org.apache.http.legacy":
                self.add("H4", "LOW", "<uses-library org.apache.http.legacy>",
                         why="Restores the removed Apache HTTP client, which has weaker TLS "
                             "defaults and does not honour the Network Security Config in the "
                             "same way as the modern stack. Its presence is a hint that some "
                             "HTTP handling bypasses your network hardening review.",
                         fix="Migrate to OkHttp/HttpURLConnection.")
        for lib in self.root.descendants("uses-static-library"):
            if lib.has("android:certDigest"):
                self.add("HARDEN", "POSITIVE",
                         "Static library dependency pinned by certificate digest",
                         where=lib.gets("android:name", "?"),
                         why="Certificate pinning on a library APK is a genuine integrity "
                             "control.")

    # -------------------------------------------------------------------- G

    def _audit_intent_filter(self, f, comp, cname, exported):
        actions = [a.gets("android:name") for a in f.kids("action")]
        cats = [c.gets("android:name") for c in f.kids("category")]
        datas = f.kids("data")
        browsable = "android.intent.category.BROWSABLE" in cats
        auto = f.get("android:autoVerify")
        auto_on = auto is not None and auto.as_bool()

        schemes = [d.gets("android:scheme") for d in datas if d.has("android:scheme")]
        hosts = [d.gets("android:host") for d in datas if d.has("android:host")]
        mimes = [d.gets("android:mimeType") for d in datas if d.has("android:mimeType")]

        if browsable:
            web = any(s in ("http", "https") for s in schemes if s)
            custom = [s for s in schemes if s and s not in ("http", "https")]

            if custom:
                self.add("G4", "HIGH", "BROWSABLE filter on a CUSTOM scheme",
                         where=cname,
                         evidence="scheme(s): " + ", ".join(custom),
                         why="A custom scheme is unowned and unverifiable: any other app may "
                             "declare the identical filter, and the user is shown a "
                             "disambiguation dialog — or, if the malicious app is the only "
                             "handler at that moment, nothing at all. BROWSABLE additionally "
                             "means a web page can reach this component: a link, an iframe or "
                             "a window.location in the mobile browser delivers "
                             "attacker-controlled data to it. That converts a local finding "
                             "into a remote one. If the scheme carries an OAuth redirect, the "
                             "authorisation code is interceptable.",
                         fix="Use https App Links with autoVerify=\"true\" and a hosted "
                             "assetlinks.json. For OAuth, use Custom Tabs with PKCE and an "
                             "https redirect.",
                         proven=False)

            if web and not auto_on:
                self.add("G2", "MEDIUM", "https/http BROWSABLE filter WITHOUT autoVerify",
                         where=cname,
                         evidence="hosts: " + (", ".join(h for h in hosts if h) or "-"),
                         why="Without autoVerify this is an ordinary deep link, not an App "
                             "Link. Another app can declare the same filter and compete for "
                             "the URL.",
                         fix='android:autoVerify="true" plus a hosted '
                             'https://<host>/.well-known/assetlinks.json listing the package '
                             'and the SHA-256 of the signing certificate.',
                         proven=False)
            if web and auto_on:
                self.add("G3", "INFO", "autoVerify declared — verify it actually verifies",
                         where=cname,
                         evidence="hosts: " + (", ".join(h for h in hosts if h) or "-"),
                         why="Declaring autoVerify does not mean verification succeeded. A "
                             "missing, malformed or wrong-fingerprint assetlinks.json leaves "
                             "the link unverified and interceptable.",
                         fix="`adb shell pm get-app-links <pkg>` and check every domain "
                             "reports verified; fetch the assetlinks.json and compare the "
                             "digest against `apksigner verify --print-certs`.",
                         proven=False)

            self.add("G1", "INFO", "BROWSABLE entry point — trace the data",
                     where=cname,
                     evidence="actions: %s | schemes: %s | hosts: %s" % (
                         ", ".join(a for a in actions if a) or "-",
                         ", ".join(s for s in schemes if s) or "-",
                         ", ".join(h for h in hosts if h) or "-"),
                     why="Follow getIntent().getData() through the Activity. If it reaches "
                         "WebView.loadUrl you likely have arbitrary URL loading in the app's "
                         "WebView context; if it reaches a token exchange you may have an "
                         "OAuth redirect interception.")

        for h in hosts:
            if h == "*":
                self.add("G5", "MEDIUM", 'android:host="*" matches every host',
                         where=cname,
                         why="A deep-link handler that trusts the host will trust any host. "
                             "Combined with a WebView load this is arbitrary-origin loading.",
                         fix="Enumerate the exact hosts.")
        for d in datas:
            pat = d.gets("android:pathPattern")
            if pat in (".*", "/.*", "*"):
                self.add("G5b", "MEDIUM", "Overly broad pathPattern",
                         where=cname, evidence=pat,
                         why="Every path under the host reaches this component.")

        for m in mimes:
            if m == "*/*":
                self.add("G6", "LOW", 'android:mimeType="*/*" on a filter',
                         where=cname,
                         why="The component accepts any content an attacker offers, which "
                             "makes it a sink for hostile files. Check what the code does "
                             "with the received Uri — especially whether it opens it with a "
                             "parser." if exported else
                             "Not exported, so lower impact — confirm the export state.",
                         proven=False)

        if f.has("android:mimeGroup") or any(d.has("android:mimeGroup") for d in datas):
            self.add("G7", "INFO", "mimeGroup used — the manifest understates the surface",
                     where=cname,
                     why="The app can change the group's MIME types at runtime with "
                         "PackageManager.setMimeGroup. Read the code.")

    # -------------------------------------------------------------------- H

    def audit_metadata(self):
        if self.application is None:
            return
        for md in self.application.kids("meta-data"):
            self._audit_metadata(md, "<application>")

    def _audit_metadata(self, md, where):
        name = md.gets("android:name", "")
        value = md.gets("android:value")
        resource = md.gets("android:resource")

        if resource:
            interesting = any(k in name for k in (
                "FILE_PROVIDER_PATHS", "accessibilityservice", "device_admin",
                "APP_RESTRICTIONS", "searchable", "appwidget",
                "AccountAuthenticator", "network_security", "sync_adapter",
                "job", "PATHS"))
            self.add("H5", "MEDIUM" if interesting else "INFO",
                     "meta-data references an XML resource — read it",
                     where="%s :: %s" % (where, name),
                     evidence=resource,
                     why="The manifest entry is a pointer. The referenced file is where the "
                         "real configuration lives: FileProvider <paths>, accessibility "
                         "service capabilities, device-admin policies, managed-configuration "
                         "schemas and account-authenticator descriptions are all far more "
                         "informative than the manifest line that points at them.",
                     fix="apktool decodes them into res/xml/. Read every one.",
                     proven=False)
            return

        if value is None:
            return

        if name in KNOWN_PUBLIC_METADATA:
            self.add("H2b", "INFO", "meta-data value is public by design",
                     where="%s :: %s" % (where, name),
                     why="Do not report this as a leaked secret. Reporting public identifiers "
                         "as critical costs you credibility on everything else in the "
                         "document.")
            return

        shape_hit = None
        for rx, label in SECRETISH_VALUE_RES:
            if rx.match(value.strip()):
                shape_hit = label
                break
        name_hit = bool(SECRETISH_NAME_RE.search(name))

        if name_hit or shape_hit:
            redacted = value if len(value) <= 12 else value[:6] + "…" + value[-4:]
            self.add("H2", "HIGH", "meta-data looks like a credential",
                     where="%s :: %s" % (where, name),
                     evidence="value=%s%s" % (redacted,
                                              (" [%s]" % shape_hit) if shape_hit else ""),
                     why="SDK integration guides tell developers to paste keys into the "
                         "manifest, so they do, and the key ships in every copy of the APK in "
                         "plaintext. This is a CANDIDATE, not a finding: a Google Maps key "
                         "restricted to the package name plus signing digest is not "
                         "exploitable, and an AdMob application id is public by design.",
                     fix="Validate before reporting. If it is genuinely usable, demonstrate "
                         "the usage. If you cannot validate, say so explicitly and recommend "
                         "the client verify the server-side restriction.",
                     proven=False)
        elif name.startswith("com.google.android.geo.API_KEY"):
            self.add("H2c", "MEDIUM", "Google Maps API key in meta-data",
                     where="%s :: %s" % (where, name),
                     why="Only a finding if unrestricted. A key restricted to this package "
                         "name plus the SHA-1 signing digest is largely fine, and you cannot "
                         "check that from outside.",
                     fix='Report as "verify the API key restrictions in the Google Cloud '
                         'console".',
                     proven=False)

    # ------------------------------------------------------------- AXML tricks

    def audit_axml_anomalies(self):
        if self.source_format != "xmltree":
            self.add("A1", "INFO", "Single-source read",
                     evidence="parsed as decoded text XML",
                     why="This report reflects ONE decoder. AXML attributes are matched by "
                         "resource ID rather than by name, booleans are 'non-zero is true', "
                         "and independent decoders can be made to disagree with the platform. "
                         "Malware has used exactly that to make analysis tools print a benign "
                         "manifest.",
                     fix="Run the three-way read: `aapt2 dump xmltree` (closest to the "
                         "platform), an independent decoder (apktool), and the device itself "
                         "(`adb shell dumpsys package <pkg>`). See "
                         "labs/lab-01-three-way-read.md.",
                     proven=False)

        # Boolean encoding anomalies (only visible in xmltree mode).
        for node in self._walk(self.root):
            for aname, v in node.attrs.items():
                if v.anomaly:
                    self.add("A2", "HIGH", "Suspicious boolean encoding in AXML",
                             where="%s %s :: %s" % (node.tag, node.name(self.package), aname),
                             evidence=v.anomaly,
                             why="The platform's getAttributeBooleanValue returns data != 0. "
                                 "A crafted APK can store 0xffffffff for android:exported or "
                                 "android:debuggable; some third-party decoders print 'false' "
                                 "or a raw number while the platform reads TRUE. Deliberate "
                                 "malformation is itself a finding.",
                             fix="Confirm the effective value on-device with "
                                 "`adb shell dumpsys package <pkg>`.")
            if node.dup_attrs:
                self.add("A2b", "HIGH", "Duplicate attribute on one element",
                         where="%s %s" % (node.tag, node.name(self.package)),
                         evidence=", ".join(sorted(set(node.dup_attrs))),
                         why="A compiler never emits duplicate attributes. The platform's "
                             "indexOfAttribute finds the FIRST match by resource ID; some "
                             "decoders show the last. This is a parser-differential setup.",
                         fix="Read the raw bytes and determine which value the platform sees.")
            for aname, v in node.attrs.items():
                if aname.startswith("android:") and self.source_format == "xmltree" \
                        and v.resid is None and aname != "android:name":
                    self.add("A2c", "MEDIUM",
                             "android-namespaced attribute with NO resource ID",
                             where="%s %s :: %s" % (node.tag, node.name(self.package), aname),
                             why="The platform matches manifest attributes by resource ID. An "
                                 "attribute that carries the android: prefix but no resource "
                                 "ID is invisible to the platform while a name-based decoder "
                                 "displays it — the inverse trick is an attribute with the "
                                 "correct resource ID and a garbage name string, which the "
                                 "platform honours and a name-based decoder drops.",
                             fix="Cross-check with `adb shell dumpsys package <pkg>`.")

    @staticmethod
    def _walk(node):
        yield node
        for c in node.children:
            for g in Auditor._walk(c):
                yield g

    # ---------------------------------------------------------------- driver

    def run(self):
        self.audit_axml_anomalies()
        self.audit_manifest_root()
        self.audit_application()
        self.audit_components()
        self.audit_permissions()
        self.audit_metadata()
        self._reachability_reminder()
        return self.findings

    def _reachability_reminder(self):
        self.add("PROOF", "INFO",
                 "Nothing in this report is proven until you reach it from an app",
                 why="Every export-related finding above is derived from a declaration. "
                     "`adb shell` runs as UID 2000 and holds privileges an ordinary "
                     "application does not, so reaching a component from `adb shell` does not "
                     "prove an attacker can reach it. Build the unprivileged probe app in "
                     "labs/lab-03-proving-reachability.md, or use Drozer (whose agent IS an "
                     "ordinary app), and record for every component whether it was reachable "
                     "from shell, from an app, or from both.",
                 fix="Report shell evidence and app evidence as separate claims. A report "
                     "that conflates them is not defensible.",
                 proven=False)

    @staticmethod
    def _ev(v):
        if v is None:
            return ""
        s = str(v)
        if v.anomaly:
            s += "  [%s]" % v.anomaly
        return s


# --------------------------------------------------------------------------- #
#  Output
# --------------------------------------------------------------------------- #

def _wrap(text, width, indent=""):
    if not text:
        return []
    out = []
    for para in str(text).split("\n"):
        if not para.strip():
            out.append("")
            continue
        out.extend(textwrap.wrap(para, width=width,
                                 initial_indent=indent,
                                 subsequent_indent=indent) or [indent])
    return out


def render_text(findings, auditor, width=96, color=False):
    order = sorted(findings, key=lambda f: (SEV_RANK[f.severity], f.check))
    lines = []
    bar = "=" * width

    lines.append(bar)
    lines.append("  ANDROID MANIFEST AUDIT — %s" % auditor.package)
    lines.append(bar)
    lines.append("  source format : %s" % auditor.source_format)
    lines.append("  minSdk        : %s" % (auditor.min_sdk if auditor.min_sdk is not None
                                           else "not declared here"))
    lines.append("  targetSdk     : %s" % (auditor.target_sdk if auditor.target_sdk is not None
                                           else "not declared here"))
    comps = auditor.stats.get("components", {})
    if comps:
        lines.append("  components    : " + ", ".join(
            "%s %d/%d exported" % (t, comps[t][1], comps[t][0])
            for t in COMPONENT_TAGS if comps[t][0]))
    for n in auditor.notes:
        lines.append("  note          : %s" % n)
    lines.append("")

    counts = {}
    for f in order:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append("  " + " | ".join("%s: %d" % (s, counts.get(s, 0))
                                   for s in SEVERITIES))
    lines.append("")

    # Compact table first — this is what goes at the top of a report.
    lines.append("-" * width)
    lines.append("  %-9s %-6s %-34s %s" % ("SEVERITY", "CHECK", "WHERE", "FINDING"))
    lines.append("-" * width)
    for f in order:
        where = (f.where or "-")
        if len(where) > 34:
            where = "…" + where[-33:]
        title = f.title
        avail = width - 9 - 6 - 34 - 5
        if len(title) > avail:
            title = title[:avail - 1] + "…"
        flag = "" if f.proven else " *"
        lines.append("  %-9s %-6s %-34s %s%s"
                     % (f.severity, f.check, where, title, flag))
    lines.append("-" * width)
    lines.append("  * = UNPROVEN: depends on reachability, on data you have not inspected,")
    lines.append("      or on a referenced file you have not yet opened.")
    lines.append("")

    # Detail.
    for f in order:
        lines.append(bar)
        lines.append("[%s] %s  (%s)%s" % (f.severity, f.title, f.check,
                                          "" if f.proven else "  — UNPROVEN"))
        if f.where:
            lines.append("  where    : %s" % f.where)
        if f.evidence:
            for i, l in enumerate(_wrap(f.evidence, width - 13, "")):
                lines.append(("  evidence : " if i == 0 else "             ") + l)
        if f.why:
            for i, l in enumerate(_wrap(f.why, width - 13, "")):
                lines.append(("  why      : " if i == 0 else "             ") + l)
        if f.fix:
            for i, l in enumerate(_wrap(f.fix, width - 13, "")):
                lines.append(("  fix      : " if i == 0 else "             ") + l)
        lines.append("")

    return "\n".join(lines)


def render_markdown(findings, auditor):
    order = sorted(findings, key=lambda f: (SEV_RANK[f.severity], f.check))
    out = []
    out.append("# Manifest audit — `%s`" % auditor.package)
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Source format | `%s` |" % auditor.source_format)
    out.append("| minSdkVersion | %s |" % (auditor.min_sdk if auditor.min_sdk is not None
                                           else "not declared here"))
    out.append("| targetSdkVersion | %s |" % (auditor.target_sdk
                                              if auditor.target_sdk is not None
                                              else "not declared here"))
    comps = auditor.stats.get("components", {})
    for t in COMPONENT_TAGS:
        if comps.get(t, [0, 0])[0]:
            out.append("| %s | %d total, **%d exported** |"
                       % (t, comps[t][0], comps[t][1]))
    out.append("")
    out.append("## Findings")
    out.append("")
    out.append("| Severity | Check | Where | Finding | Proven |")
    out.append("|---|---|---|---|---|")
    for f in order:
        out.append("| **%s** | %s | `%s` | %s | %s |" % (
            f.severity, f.check, f.where or "-",
            f.title.replace("|", "\\|"),
            "yes" if f.proven else "**no**"))
    out.append("")
    out.append("## Detail")
    out.append("")
    for f in order:
        out.append("### [%s] %s" % (f.severity, f.title))
        out.append("")
        out.append("- **Check:** %s" % f.check)
        if f.where:
            out.append("- **Where:** `%s`" % f.where)
        if f.evidence:
            out.append("- **Evidence:** %s" % f.evidence.replace("\n", " "))
        if f.why:
            out.append("- **Why it matters:** %s" % f.why.replace("\n", "\n  "))
        if f.fix:
            out.append("- **Fix:** %s" % f.fix)
        if not f.proven:
            out.append("- **Proven:** no — reachability or referenced data still to verify.")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Severity-rated AndroidManifest.xml audit "
                    "(Chapter 32 checklist, section 5.6).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Every finding is a LEAD. Impact and reachability are your job.")
    ap.add_argument("manifest",
                    help="Path to a decoded AndroidManifest.xml, or to a file containing "
                         "`aapt2 dump xmltree` output. Use '-' for stdin.")
    ap.add_argument("--format", choices=("auto", "xml", "xmltree"), default="auto",
                    help="Input format (default: autodetect).")
    ap.add_argument("--target-sdk", type=int, default=None,
                    help="Override targetSdkVersion, e.g. when the value comes from "
                         "build.gradle rather than the manifest.")
    ap.add_argument("--min-severity", choices=SEVERITIES, default=None,
                    help="Only show findings at or above this severity.")
    ap.add_argument("--fail-on", choices=SEVERITIES, default=None,
                    help="Exit 1 if any finding is at or above this severity (for CI).")
    ap.add_argument("--markdown", action="store_true", help="Emit Markdown.")
    ap.add_argument("--json", action="store_true", help="Emit JSON.")
    ap.add_argument("--width", type=int, default=96, help="Text output width.")
    args = ap.parse_args(argv)

    if args.manifest == "-":
        data = sys.stdin.read()
    else:
        if not os.path.isfile(args.manifest):
            sys.stderr.write("[-] no such file: %s\n" % args.manifest)
            return 2
        with open(args.manifest, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()

    forced = None if args.format == "auto" else args.format
    try:
        root, fmt = parse_auto(data, forced)
    except ValueError as exc:
        sys.stderr.write("[-] could not parse input: %s\n" % exc)
        sys.stderr.write("    Try --format xml or --format xmltree explicitly.\n")
        return 2

    if root.tag != "manifest":
        sys.stderr.write("[-] root element is <%s>, expected <manifest>\n" % root.tag)
        return 2

    auditor = Auditor(root, fmt, target_sdk_override=args.target_sdk)
    findings = auditor.run()

    if args.min_severity:
        limit = SEV_RANK[args.min_severity]
        findings = [f for f in findings if SEV_RANK[f.severity] <= limit]

    if args.json:
        print(json.dumps({
            "package": auditor.package,
            "source_format": auditor.source_format,
            "minSdkVersion": auditor.min_sdk,
            "targetSdkVersion": auditor.target_sdk,
            "components": auditor.stats.get("components", {}),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    elif args.markdown:
        print(render_markdown(findings, auditor))
    else:
        print(render_text(findings, auditor, width=args.width))

    if args.fail_on:
        limit = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] <= limit and f.severity != "POSITIVE"
               for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
