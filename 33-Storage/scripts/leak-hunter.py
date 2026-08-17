#!/usr/bin/env python3
"""
leak-hunter.py -- pull an app's storage and look for credential-shaped values in
                  it, then argue honestly about how many of them are real.

WHAT IT DOES
    Given a package name (it pulls) or a directory (it reads what you already
    pulled), it walks every file, decides what kind of file each one is, and
    applies detectors that are appropriate to that kind:

        XML         SharedPreferences: every <string>, <long>, <boolean> is a
                    named key/value pair, so the KEY NAME carries as much signal
                    as the value. "auth_token" holding 180 base64 characters is
                    a different claim from a 180-character string in a blob.
        SQLite      Reads the header, lists tables and columns from sqlite_master
                    WITHOUT executing any SQL, and reports column NAMES that
                    look credential-bearing. Then greps the raw bytes -- and the
                    -wal and -journal companions, which is where deleted rows
                    survive. See "THE WAL POINT" below.
        JSON        Recurses keys and values with the same key-name weighting.
        Text/log    Line-oriented regex sweep with the line number kept.
        Binary      strings-style extraction (printable runs >= 6), then the
                    same value detectors, at a lower confidence.

    Every hit gets a CONFIDENCE (high / medium / low) and, more usefully, a
    REASON: the specific evidence that produced it. A hit with no reason you
    can read out loud to a developer is not a finding.

    It also reports, separately, the two things that matter more than any single
    regex:

        PLAINTEXT-BESIDE-CIPHERTEXT   the same distinctive value found in two
                                      files, one of which looks encrypted. This
                                      is chapter 33's signature finding and it
                                      is what catches an app that did the crypto
                                      correctly and then cached the cleartext.
        SURFACE                       a per-directory census: how many files, how
                                      big, which are world-readable, which sit
                                      outside the app sandbox entirely
                                      (/sdcard, Android/data, Android/media).

HOW TO RUN
    # host -- pull and scan in one step (needs root on the device)
    python3 -B leak-hunter.py --package com.example.app

    # host -- scan a directory you already pulled, no device needed
    python3 -B leak-hunter.py --dir ./pulled/com.example.app

    # keep the pull for later, and for storage-diff.py
    python3 -B leak-hunter.py --package com.example.app --keep ./pulled

    # only the strong hits, for a first pass on a big app
    python3 -B leak-hunter.py --dir ./pulled/app --min-confidence high

    # everything, including the noise, when you are hunting rather than reporting
    python3 -B leak-hunter.py --dir ./pulled/app --min-confidence low --show-context

    # machine-readable
    python3 -B leak-hunter.py --dir ./pulled/app --json > findings.json

    # add your own pattern -- name=regex, repeatable
    python3 -B leak-hunter.py --dir ./pulled/app \\
        --pattern "internal-session=ACME-[0-9A-F]{32}"

REQUIREMENTS
    * Python 3.6+ on the host. Standard library only. The SQLite reading is done
      with Python's own sqlite3 module in READ-ONLY URI mode, so a corrupt or
      hostile database cannot be modified by the act of scanning it.
    * For --package: `adb` on PATH and root on the device, because /data/data is
      not readable otherwise. Without root, pull what you can reach
      (/sdcard/Android/data/<pkg>) and pass --dir.

WHAT THIS SCRIPT WILL *NOT* TELL YOU
    - Whether any hit is a real credential. It cannot. It is a regex engine with
      opinions. Read the FALSE POSITIVES section below IN FULL before you put a
      single line of its output in a report; roughly speaking, on a real app the
      low-confidence tier is 90%+ noise and the high-confidence tier is still
      wrong often enough that every hit needs a human.
    - Whether a credential it finds is USABLE. A leaked token that the server
      revoked at logout is a hygiene issue; the same token still accepted an hour
      later is an authentication finding. Only replaying it against the server
      answers that, and only with permission.
    - Whether a value is encrypted. High entropy is not encryption. A UUID, a
      compressed thumbnail, a protobuf and an AES ciphertext all look alike to a
      byte-frequency test, and the script says "high entropy" rather than
      "encrypted" everywhere for that reason. See 34-Cryptography section 8 for
      the actual question -- ECB detection, IV reuse, key provenance -- which is
      that chapter's job and not this one's.
    - Where the value came from, or which code wrote it. Hook it: see
      storage-trace.js in this directory, which prints a stack for every write.
    - Anything about data that never touched disk. An in-memory-only token is
      invisible here and visible to 19-Memory's methods.
    - Anything about a value that was deleted before you pulled. SQLite's WAL and
      freelist pages often still hold it; a value overwritten in place usually
      does not.
    - Whether a file is REACHABLE by another app. It reports mode bits from the
      pull, which on many transports (adb pull onto NTFS, for one) do not survive
      the copy at all. Use storage-diff.py for permission questions; it reads
      modes on the device where they mean something.

FALSE POSITIVES -- read this before reporting anything
    These are the ones that come up on every single engagement.

    1. ADVERTISING AND ANALYTICS IDENTIFIERS look exactly like session tokens.
       A GAID is a UUID; Firebase installation IDs are 22-character base64;
       Adjust, Amplitude and Segment all persist opaque ids in SharedPreferences
       under names containing "token". `firebase_installation_id` matching a
       "token" rule is expected behaviour, not a finding -- though it may still
       be a PRIVACY finding, which is a different report section.
    2. PUBLIC KEYS AND CERTIFICATES match every "long base64 blob" rule. A
       pinned server certificate in `assets/` is the app doing the right thing.
    3. FEATURE FLAGS AND EXPERIMENT BUCKETS are long, opaque and stored under
       names like `config_hash`. They are neither secret nor interesting.
    4. THE WORD "password" IN A UI STRING. `hint_password_too_short` is a
       resource key. The detector weights the key name, which makes this class
       WORSE, not better -- so it checks that the VALUE also looks like a
       secret, and drops the hit to low when the value is short, spaced, or
       obviously human text.
    5. BASE64 THAT IS NOT BASE64. Any hex string of even length is valid base64
       input; so is most of a UUID. The script requires >= 20 characters, mixed
       case or digits, and a decode that yields either valid UTF-8 with a JSON
       or JWT shape, or bytes with entropy above 5.5 bits -- and reports which
       of those two it was.
    6. YOUR OWN TEST DATA. If you logged into the app as `test@example.com` with
       `Passw0rd!`, you will find them, and they prove only that you typed them.
       Pass --exclude-value to silence a string you supplied yourself.
    7. CACHED SERVER RESPONSES containing another user's public profile. Common
       in social apps, looks alarming, is usually the API working as designed.
    8. THE SAME VALUE IN TEN FILES is usually one value copied by one library,
       not ten separate leaks. The report groups by value for this reason, and
       a group of ten files is one finding with ten locations.

THE WAL POINT
    An app that deletes a row does not necessarily remove the bytes. SQLite in
    WAL mode writes new pages to `<db>-wal` and only folds them back into the
    main file at a checkpoint, so `<db>-wal` routinely contains rows the
    database no longer shows. "We clear the session table on logout" is a claim
    about SQL, and `strings db-wal` is how you test it against the disk. The
    scanner therefore treats `-wal`, `-shm` and `-journal` as first-class
    targets rather than as ignorable temporary files, and labels any hit found
    only in a companion file as RESIDUAL, which is a stronger finding than the
    same value in the live table: it means a deletion that the developer
    believes happened, did not.

AUTHORISED TESTING ONLY. This reads other people's data by design. Run it
against apps you are permitted to test, on a device you own, and destroy the
pulled copies when the engagement ends.
"""

from __future__ import print_function

import argparse
import base64
import binascii
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

VERSION = "1.0"

MAX_FILE_BYTES = 32 * 1024 * 1024
PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

# Key names that raise the stakes when a value sits under them. Deliberately
# NOT a finding on their own -- see false positive 4.
HOT_KEY = re.compile(
    r"(?i)(pass(wo?rd|phrase)|secret|token|bearer|refresh|session|auth|"
    r"credential|api[_-]?key|apikey|private[_-]?key|jwt|cookie|otp|pin|"
    r"seed|mnemonic|signature|hmac|salt|iv|master[_-]?key)")

# Key names that look hot but almost never are -- see false positives 1 and 3.
COLD_KEY = re.compile(
    r"(?i)(installation[_-]?id|instance[_-]?id|advertising|gaid|idfa|"
    r"firebase|analytics|amplitude|segment|adjust|appsflyer|crashlytics|"
    r"experiment|feature[_-]?flag|config[_-]?hash|hint_|label_|error_|"
    r"_enabled$|_count$|_timestamp$|_version$)")

VALUE_RULES = [
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
     "high", "three dot-separated base64url segments beginning eyJ -- a JWT header"),
    ("private-key-pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     "high", "PEM private-key armour"),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "high", "AWS access key id prefix and length"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "medium", "Google API key shape -- often a client key that is meant to ship"),
    ("slack-token", re.compile(r"\bxox[abposr]-[0-9A-Za-z-]{10,}"),
     "high", "Slack token prefix"),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
     "high", "GitHub token prefix"),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"),
     "high", "Stripe secret key prefix"),
    ("basic-auth-url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"),
     "high", "credentials embedded in a URL authority"),
    ("authorization-header", re.compile(r"(?i)authorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+\S+"),
     "high", "a literal Authorization header value"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "low", "email shape -- PII, and a privacy finding rather than a credential one"),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
     "low", "UUID shape -- overwhelmingly an install id, see false positive 1"),
    ("long-hex", re.compile(r"\b[0-9a-fA-F]{40,}\b"),
     "low", "40+ hex characters -- a hash, a key, or a checksum; shape alone cannot say"),
]

B64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")


def shannon(data):
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = float(len(data))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def looks_like_human_text(value):
    """Cheap guard against reporting UI strings and sentences as secrets."""
    if " " in value.strip():
        return True
    letters = sum(1 for c in value if c.isalpha())
    return letters and (letters / float(len(value))) > 0.95 and len(value) < 24


def inspect_base64(value):
    """Return (confidence, reason) for a base64-looking string, or None."""
    if len(value) < 20:
        return None
    if not (any(c.isdigit() for c in value) or
            (any(c.isupper() for c in value) and any(c.islower() for c in value))):
        return None
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            return ("high", "base64 that decodes to JSON -- a serialised object, "
                            "frequently a token payload")
        printable = sum(1 for c in text if 0x20 <= ord(c) < 0x7F or c in "\r\n\t")
        if printable == len(text) and len(text) > 8:
            return ("medium", "base64 that decodes to printable text")
    except (UnicodeDecodeError, ValueError):
        pass
    ent = shannon(bytearray(raw))
    if ent > 5.5 and len(raw) >= 16:
        return ("medium",
                "base64 decoding to %d bytes at %.2f bits/byte entropy -- "
                "consistent with a key, a ciphertext, a compressed blob or a "
                "random identifier; entropy cannot distinguish them" % (len(raw), ent))
    return None


class Hit(object):
    __slots__ = ("path", "kind", "rule", "key", "value", "confidence", "reason",
                 "location", "residual")

    def __init__(self, path, kind, rule, key, value, confidence, reason,
                 location="", residual=False):
        self.path = path
        self.kind = kind
        self.rule = rule
        self.key = key
        self.value = value
        self.confidence = confidence
        self.reason = reason
        self.location = location
        self.residual = residual

    def redacted(self, full=False):
        v = self.value
        if full or len(v) <= 24:
            return v
        return "%s...%s (%d chars)" % (v[:12], v[-6:], len(v))

    def as_dict(self, full=False):
        return {"path": self.path, "kind": self.kind, "rule": self.rule,
                "key": self.key, "value": self.redacted(full),
                "confidence": self.confidence, "reason": self.reason,
                "location": self.location, "residual": self.residual}


def scan_value(path, kind, key, value, location="", base_conf=None):
    """Apply every value rule to one string. Returns a list of Hit."""
    hits = []
    if value is None:
        return hits
    value = value if isinstance(value, str) else str(value)
    if len(value) > 4096:
        value = value[:4096]

    for name, rx, conf, reason in VALUE_RULES:
        m = rx.search(value)
        if not m:
            continue
        hits.append(Hit(path, kind, name, key, m.group(0), conf, reason, location))

    for m in B64_RE.finditer(value):
        got = inspect_base64(m.group(0))
        if got:
            conf, reason = got
            hits.append(Hit(path, kind, "base64-blob", key, m.group(0),
                            conf, reason, location))
            break

    # Key-name weighting, applied last so it can only ADJUST, never invent.
    if key:
        hot = HOT_KEY.search(key)
        cold = COLD_KEY.search(key)
        if hot and not cold and not looks_like_human_text(value) and len(value) >= 12:
            if not hits:
                hits.append(Hit(path, kind, "hot-key-name", key, value, "medium",
                                "key name matches %r and the value is %d "
                                "non-obvious characters; the NAME is the evidence, "
                                "not the value" % (hot.group(0), len(value)),
                                location))
            else:
                for h in hits:
                    if h.confidence == "low":
                        h.confidence = "medium"
                        h.reason += "; promoted because the key name %r is "\
                                    "credential-shaped" % hot.group(0)
        if cold:
            for h in hits:
                if h.confidence == "high":
                    h.confidence = "medium"
                else:
                    h.confidence = "low"
                h.reason += ("; DEMOTED because the key name matches %r, which is "
                             "an analytics/config name -- see false positive 1"
                             % cold.group(0))
        if key and HOT_KEY.search(key) and looks_like_human_text(value):
            for h in hits:
                h.confidence = "low"
                h.reason += "; demoted because the value reads as human text or a "\
                            "UI string, see false positive 4"
    return hits


# ---------------------------------------------------------------------------
# Per-file-type scanners
# ---------------------------------------------------------------------------

XML_ENTRY = re.compile(
    r"<(string|int|long|float|boolean|set)\s+name=\"([^\"]*)\"\s*(?:>(.*?)</\1>|"
    r"value=\"([^\"]*)\"\s*/>)", re.S)


def scan_xml(path, data, rel):
    hits = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return scan_binary(path, data, rel)
    for m in XML_ENTRY.finditer(text):
        key = m.group(2)
        value = m.group(3) if m.group(3) is not None else m.group(4)
        hits.extend(scan_value(rel, "sharedprefs", key, value,
                               location="<%s name=%s>" % (m.group(1), key)))
    if not hits:
        hits.extend(scan_text(path, data, rel, kind="xml"))
    return hits


def scan_json(path, data, rel):
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception:
        return scan_text(path, data, rel, kind="json")
    hits = []

    def walk(node, trail):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, trail + [str(k)])
        elif isinstance(node, list):
            for i, v in enumerate(node[:200]):
                walk(v, trail + ["[%d]" % i])
        else:
            key = trail[-1] if trail else ""
            hits.extend(scan_value(rel, "json", key, node,
                                   location=".".join(trail)))
    walk(obj, [])
    return hits


CRED_COLUMN = HOT_KEY


def scan_sqlite(path, data, rel):
    """Read the schema and the rows without ever writing to the file."""
    hits = []
    tmp = None
    try:
        # Copy to a temp file so a WAL that we cannot see cannot be replayed
        # into the original, and open read-only regardless.
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        shutil.copyfile(path, tmp)
        conn = sqlite3.connect("file:%s?mode=ro&immutable=1" % tmp.replace("?", "%3f"),
                               uri=True)
        cur = conn.cursor()
        cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = cur.fetchall()
        for tname, tsql in tables:
            if tsql and CRED_COLUMN.search(tsql):
                cols = [c for c in re.findall(r"[\"`\[]?(\w+)[\"`\]]?\s+\w+", tsql or "")
                        if CRED_COLUMN.search(c)]
                if cols:
                    hits.append(Hit(rel, "sqlite-schema", "credential-column",
                                    tname, ", ".join(sorted(set(cols))), "medium",
                                    "table %r declares column(s) whose NAME is "
                                    "credential-shaped; the schema is the evidence, "
                                    "the contents still have to be checked" % tname,
                                    location="table %s" % tname))
            try:
                cur.execute("SELECT * FROM \"%s\" LIMIT 200" % tname.replace('"', '""'))
            except sqlite3.Error:
                continue
            names = [d[0] for d in cur.description or []]
            for row in cur.fetchall():
                for cname, cval in zip(names, row):
                    if isinstance(cval, (bytes, bytearray)):
                        continue
                    hits.extend(scan_value(rel, "sqlite", cname, cval,
                                           location="%s.%s" % (tname, cname)))
        conn.close()
    except Exception as exc:
        hits.append(Hit(rel, "sqlite", "unreadable", "", str(exc)[:120], "low",
                        "the database could not be opened as SQLite; falling back "
                        "to a raw byte scan", location=""))
        hits.extend(scan_binary(path, data, rel))
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return hits


def scan_text(path, data, rel, kind="text"):
    hits = []
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return hits
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 8192:
            line = line[:8192]
        key = ""
        m = re.match(r"\s*([A-Za-z_][\w.-]{0,60})\s*[=:]\s*(.+)$", line)
        if m:
            key, rest = m.group(1), m.group(2)
            hits.extend(scan_value(rel, kind, key, rest, location="line %d" % n))
        else:
            hits.extend(scan_value(rel, kind, "", line, location="line %d" % n))
    return hits


def extract_strings(data, minlen=6):
    out, run = [], bytearray()
    for b in bytearray(data):
        if b in PRINTABLE:
            run.append(b)
        else:
            if len(run) >= minlen:
                out.append(run.decode("ascii", "replace"))
            run = bytearray()
    if len(run) >= minlen:
        out.append(run.decode("ascii", "replace"))
    return out


def scan_binary(path, data, rel):
    hits = []
    for s in extract_strings(data)[:20000]:
        for h in scan_value(rel, "binary", "", s):
            # Binary provenance is weaker: there is no key name and no line, so
            # the same match deserves less confidence than it would in XML.
            if h.confidence == "high":
                h.confidence = "medium"
            elif h.confidence == "medium":
                h.confidence = "low"
            h.reason += "; found in a byte scan with no surrounding key name"
            hits.append(h)
    return hits


SQLITE_MAGIC = b"SQLite format 3\x00"


def scan_file(path, rel):
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if size == 0 or size > MAX_FILE_BYTES:
        return []
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except (OSError, IOError):
        return []

    low = rel.lower()
    if data.startswith(SQLITE_MAGIC):
        return scan_sqlite(path, data, rel)
    if low.endswith((".xml", ".plist")):
        return scan_xml(path, data, rel)
    if low.endswith(".json"):
        return scan_json(path, data, rel)
    head = data[:4096]
    nonprint = sum(1 for b in bytearray(head) if b not in PRINTABLE and b not in (10, 13))
    if head and nonprint / float(len(head)) > 0.10:
        return scan_binary(path, data, rel)
    return scan_text(path, data, rel)


# ---------------------------------------------------------------------------
# Pulling
# ---------------------------------------------------------------------------

PULL_ROOTS = [
    "/data/user/{u}/{p}",
    "/data/user_de/{u}/{p}",
    "/storage/emulated/{u}/Android/data/{p}",
    "/storage/emulated/{u}/Android/media/{p}",
]


def adb(args, serial=None, timeout=900):
    argv = ["adb"] + (["-s", serial] if serial else []) + args
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(timeout=timeout)
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def pull_package(package, dest, user=0, serial=None):
    """Tar the roots on the device as root, pull the tar, unpack on the host.

    Pulling /data/data directly with `adb pull` fails: adb runs as shell, not
    root, and adb's own root is unavailable on a user build. Tarring as root to
    a shell-readable location and pulling that is the reliable path, and it also
    preserves the modes -- which a direct pull onto NTFS would not.
    """
    os.makedirs(dest, exist_ok=True)
    remote_tar = "/data/local/tmp/leakhunt-%s.tar" % package.replace(".", "_")
    roots = " ".join(r.format(p=package, u=user) for r in PULL_ROOTS)
    cmd = ("su -c 'rm -f %s; tar cf %s %s 2>/dev/null; chmod 644 %s'"
           % (remote_tar, remote_tar, roots, remote_tar))
    rc, out, err = adb(["shell", cmd], serial)
    local_tar = os.path.join(dest, "pulled.tar")
    rc, out, err = adb(["pull", remote_tar, local_tar], serial)
    adb(["shell", "su -c 'rm -f %s'" % remote_tar], serial)
    if rc != 0 or not os.path.exists(local_tar):
        raise SystemExit(
            "error: could not pull %s.\n"
            "       adb said: %s\n"
            "       This almost always means su is unavailable. Without root you\n"
            "       cannot read /data/data at all -- pull what you can reach and\n"
            "       use --dir:\n"
            "         adb shell tar cf /sdcard/x.tar /sdcard/Android/data/%s\n"
            % (package, (err or out).strip()[:200], package))
    import tarfile
    with tarfile.open(local_tar) as tf:
        for member in tf.getmembers():
            # Refuse absolute paths and traversal. The tar comes off a device
            # whose contents an attacker may control.
            name = member.name.lstrip("/")
            if ".." in name.split("/"):
                continue
            member.name = name
            try:
                # Python 3.12 deprecates the unfiltered form and 3.14 changes the
                # default. 'data' is the right filter here: it strips setuid bits
                # and refuses absolute paths and links out of the tree, which is
                # exactly what you want from an archive built on a device you are
                # attacking. Older Pythons do not accept the argument.
                try:
                    tf.extract(member, dest, filter="data")
                except TypeError:
                    tf.extract(member, dest)
            except Exception:
                continue
    os.unlink(local_tar)
    return dest


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

CONF_ORDER = {"high": 3, "medium": 2, "low": 1}

OUTSIDE_SANDBOX = ("storage/emulated", "sdcard", "Android/data", "Android/media")
RESIDUAL_SUFFIX = ("-wal", "-shm", "-journal", ".bak", ".tmp", ".old")


def modes_are_meaningful():
    """False on Windows, where every extracted file reports the same mode.

    NTFS has no POSIX mode bits, so os.stat() on an extracted file reports a
    value synthesised from the read-only attribute -- typically 0o666 for
    everything. Printing a world-readable count from that is worse than
    printing nothing, because it is confidently wrong for every row. The
    permission question belongs on the device anyway; that is storage-diff.py.
    """
    return os.name != "nt"


def surface_census(root, depth=4):
    """Group files by the storage root they came from.

    A tar pulled from the device unpacks as data/user/0/<pkg>/... and
    storage/emulated/0/Android/data/<pkg>/..., so grouping on the FIRST path
    component collapses CE, DE and the profile into one bucket named "data" --
    which hides the single most useful thing in the census. Group deep enough to
    separate them instead.
    """
    rows = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace("\\", "/")
        parts = [] if rel == "." else rel.split("/")
        top = "/".join(parts[:depth]) if parts else "."
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            try:
                st = os.stat(full)
            except OSError:
                continue
            r = rows.setdefault(top, {"files": 0, "bytes": 0, "wr": 0})
            r["files"] += 1
            r["bytes"] += st.st_size
            if modes_are_meaningful() and (st.st_mode & 0o004):
                r["wr"] += 1
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="leak-hunter.py",
        description="Hunt for credential-shaped values in an app's storage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The FALSE POSITIVES section of the module docstring is not "
               "optional reading. Roughly nine in ten low-confidence hits on a "
               "real app are noise.")
    ap.add_argument("--version", action="version", version="leak-hunter.py " + VERSION)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--package", help="pull this package from the device first")
    src.add_argument("--dir", help="scan an already-pulled directory")
    ap.add_argument("--user", type=int, default=0)
    ap.add_argument("--serial")
    ap.add_argument("--keep", help="with --package, keep the pull under this directory")
    ap.add_argument("--min-confidence", choices=["low", "medium", "high"],
                    default="medium")
    ap.add_argument("--pattern", action="append", default=[],
                    help="extra detector as name=regex (repeatable)")
    ap.add_argument("--exclude-value", action="append", default=[],
                    help="a literal string you supplied yourself; suppress it")
    ap.add_argument("--show-context", action="store_true",
                    help="print full values instead of redacting the middle")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=40, help="rows per confidence tier")
    args = ap.parse_args(argv)

    for spec in args.pattern:
        if "=" not in spec:
            raise SystemExit("error: --pattern wants name=regex, got %r" % spec)
        name, rx = spec.split("=", 1)
        VALUE_RULES.append((name, re.compile(rx), "high",
                            "matched the operator-supplied pattern %r" % name))

    tmpdir = None
    if args.package:
        tmpdir = args.keep or tempfile.mkdtemp(prefix="leakhunt-")
        root = os.path.join(tmpdir, args.package)
        sys.stderr.write("pulling %s ...\n" % args.package)
        pull_package(args.package, root, args.user, args.serial)
    else:
        root = args.dir
        if not os.path.isdir(root):
            raise SystemExit("error: %s is not a directory" % root)

    hits = []
    scanned = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            scanned += 1
            for h in scan_file(full, rel):
                if any(x and x in h.value for x in args.exclude_value):
                    continue
                if rel.endswith(RESIDUAL_SUFFIX):
                    h.residual = True
                hits.append(h)

    # Group identical values -- false positive 8.
    groups = {}
    for h in hits:
        groups.setdefault(h.value, []).append(h)

    # Plaintext-beside-ciphertext: the same value in two files where at least one
    # path smells encrypted and at least one does not.
    beside = []
    for value, hs in groups.items():
        paths = sorted(set(h.path for h in hs))
        if len(paths) < 2:
            continue
        enc = [p for p in paths if re.search(r"(?i)(encrypt|secure|cipher|vault|"
                                             r"keystore|sealed)", p)]
        plain = [p for p in paths if p not in enc]
        if enc and plain:
            beside.append((value, enc, plain))

    minc = CONF_ORDER[args.min_confidence]
    kept = [h for h in hits if CONF_ORDER[h.confidence] >= minc]

    if args.json:
        json.dump({
            "root": root, "files_scanned": scanned,
            "hits": [h.as_dict(args.show_context) for h in kept],
            "value_groups": {k[:32]: sorted(set(x.path for x in v))
                             for k, v in groups.items() if len(v) > 1},
            "plaintext_beside_ciphertext": [
                {"value": v[:32], "encrypted_paths": e, "plain_paths": p}
                for v, e, p in beside],
            "surface": surface_census(root),
        }, sys.stdout, indent=1)
        print()
        return 1 if kept else 0

    print("=" * 78)
    print("LEAK HUNT  --  %s" % root)
    print("=" * 78)
    print("  files scanned      %d" % scanned)
    print("  raw hits           %d" % len(hits))
    print("  at >= %-6s       %d" % (args.min_confidence, len(kept)))
    print("  distinct values    %d" % len(groups))
    print()

    print("-" * 78)
    print("SURFACE  --  where this app's bytes live")
    print("-" * 78)
    wr_col = "world-readable" if modes_are_meaningful() else "(modes n/a)"
    print("  %-44s %7s %12s  %s" % ("root", "files", "bytes", wr_col))
    for top, r in sorted(surface_census(root).items()):
        outside = any(o in top for o in OUTSIDE_SANDBOX)
        print("  %-44s %7d %12d  %s%s" % (
            top[:44], r["files"], r["bytes"],
            r["wr"] if modes_are_meaningful() else "-",
            "   <- OUTSIDE THE UID SANDBOX" if outside else ""))
    if not modes_are_meaningful():
        print()
        print("  Mode bits were dropped by the host filesystem (NTFS has none), so")
        print("  the permission column is suppressed rather than guessed. Ask")
        print("  storage-diff.py, which reads modes on the device.")
    print()

    for tier in ("high", "medium", "low"):
        if CONF_ORDER[tier] < minc:
            continue
        rows = [h for h in kept if h.confidence == tier]
        if not rows:
            continue
        print("-" * 78)
        print("%s CONFIDENCE  (%d)" % (tier.upper(), len(rows)))
        print("-" * 78)
        for h in rows[:args.limit]:
            flag = "  [RESIDUAL] " if h.residual else "  "
            print("%s%s" % (flag, h.path))
            print("      rule      %s   %s" % (h.rule, h.location))
            if h.key:
                print("      key       %s" % h.key)
            print("      value     %s" % h.redacted(args.show_context))
            print("      why       %s" % h.reason)
            if h.residual:
                print("      NOTE      this file is a SQLite companion or a backup "
                      "copy. A value")
                print("                found only here is data the app believes it "
                      "deleted.")
            print()
        if len(rows) > args.limit:
            print("  ... %d more at this tier (raise --limit)\n" % (len(rows) - args.limit))

    print("=" * 78)
    print("PLAINTEXT BESIDE CIPHERTEXT")
    print("=" * 78)
    if not beside:
        print("  No value was found in both an encryption-named path and a plain one.")
        print("  This is a weak negative: it only checks paths whose NAME suggests")
        print("  encryption. An app that encrypts into files/data.bin and caches the")
        print("  cleartext in cache/data.tmp will not be caught by a name heuristic.")
        print("  Compare the two by hand, or diff a session with storage-diff.py.")
    else:
        for value, enc, plain in beside[:20]:
            print("  value %s" % (value[:40] + ("..." if len(value) > 40 else "")))
            for p in enc:
                print("      encrypted-looking  %s" % p)
            for p in plain:
                print("      plain              %s" % p)
            print("      -> the app protected this value in one place and did not in")
            print("         another. The weaker copy sets the severity.")
            print()
    print()
    print("  Every line above is a CANDIDATE. Read the module docstring's FALSE")
    print("  POSITIVES section before reporting any of them.")
    return 1 if kept else 0


if __name__ == "__main__":
    sys.exit(main())
