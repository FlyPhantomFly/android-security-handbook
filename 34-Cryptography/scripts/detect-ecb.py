#!/usr/bin/env python3
"""
detect-ecb.py - find ECB mode and the rest of the crypto smell catalogue, both in
                an app's code and in the data it has already written to disk.

WHAT IT DOES
  Two complementary scans, over any directory you point it at.

  1. CODE SCAN (a decoded APK: apktool output, jadx output, or a source tree)
     Applies the static rules from README.md section 5.2 to .smali, .java, .kt,
     .xml, .json, .gradle and .properties files:

       F-02  Cipher.getInstance("AES")   - no mode given, silently ECB/PKCS5
       F-02  explicit AES/ECB/*
       F-03  hardcoded or all-zero IVs feeding IvParameterSpec
       F-05  SHA1PRNG + setSeed, keys derived from ANDROID_ID or a constant
       F-06  java.util.Random used near key/IV/token generation
       F-07  MD5 / SHA-1 used for integrity, signing or key derivation
       F-01  SecretKeySpec built from a string or array literal
       F-09  key-looking constants in strings.xml / BuildConfig / gradle
       F-14  RSA with NoPadding or PKCS1Padding
       F-15  Arrays.equals / String.equals on MAC-shaped values
       plus PBKDF2 iteration counts and GCM tag lengths where they are literals

  2. DATA SCAN (a pulled /data/data/<pkg> tree, a database, a preferences file)
     Reads bytes rather than code, and proves things the code cannot hide:

       - repeated 16-byte blocks inside a single value  -> ECB, no code needed
       - identical leading 16 bytes across records      -> fixed or absent IV
       - identical leading 12 bytes under GCM           -> nonce reuse
       - Shannon entropy per file and per Base64 value  -> what is really encrypted
       - Base64 values that decode to readable text     -> F-10, not encrypted at all
       - 16/24/32-byte high-entropy blobs stored next to ciphertext -> F-13, the key

WHY IT MATTERS
  A grep tells you what the code says. The data tells you what the code did. The
  second is the evidence you put in a report, because it survives obfuscation, it
  survives a decompiler that produced garbage, and it does not require the reader
  to trust your reading of someone else's Smali.

  Repeated ciphertext blocks are the cleanest crypto finding in mobile testing:
  identical 16-byte plaintext blocks can only produce identical 16-byte ciphertext
  blocks under ECB. There is no argument to be had about it.

HOW TO RUN
  # host - unpack the app first
  apktool d target.apk -o unpacked/
  jadx -d jadx-out/ target.apk

  # host - code scan (auto-detected from the directory contents)
  python3 detect-ecb.py unpacked/
  python3 detect-ecb.py jadx-out/sources/ --code

  # host - pull the app's data and scan the bytes
  adb shell "su -c 'tar czf /sdcard/appdata.tgz /data/data/com.example.target'"
  adb pull /sdcard/appdata.tgz && tar xzf appdata.tgz
  python3 detect-ecb.py ./data/data/com.example.target
  python3 detect-ecb.py --entropy ./data/data/com.example.target

  # host - machine-readable, for a pipeline
  python3 detect-ecb.py unpacked/ --json > findings.json

  Useful flags:
    --code / --data     force one scan instead of auto-detecting
    --entropy           entropy report for every file and every Base64 value
    --block-size N      block size for the repetition test (default 16)
    --min-len N         ignore values shorter than N bytes (default 32)
    --context N         lines of context around a code hit (default 0)
    --json              JSON output
    --quiet             findings only, no progress
    -x, --exclude GLOB  skip paths matching GLOB (repeatable)

REQUIREMENTS
  Python 3.7+. Standard library only - no pip install, so it runs on a locked-down
  analysis host or inside a container with no network.

  Nothing here executes app code, so it is safe to run against malware samples.

AUTHORISED TESTING ONLY.
"""

import argparse
import base64
import binascii
import fnmatch
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict

# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Finding:
    """One observation. `evidence` must be something you can paste into a report."""

    def __init__(self, fid, severity, title, path, line, evidence, note):
        self.fid = fid
        self.severity = severity
        self.title = title
        self.path = path
        self.line = line
        self.evidence = evidence
        self.note = note

    def as_dict(self):
        return {
            "id": self.fid,
            "severity": self.severity,
            "title": self.title,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "note": self.note,
        }

    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 9), self.fid, self.path, self.line)


# --------------------------------------------------------------------------- #
# Code rules
# --------------------------------------------------------------------------- #
#
# Each rule is (id, severity, title, compiled regex, note, file-extension filter).
#
# The notes are deliberately long. A rule that fires without explaining what the
# developer was probably thinking produces a report the developer ignores.

CODE_EXTS = {".java", ".kt", ".smali", ".xml", ".json", ".gradle", ".kts",
             ".properties", ".txt", ".cfg", ".pro", ".js", ".ts", ".c", ".cpp",
             ".h", ".m", ".mm", ".dart"}

# Java/Kotlin source form: Cipher.getInstance("AES") with a single token.
RE_NO_MODE_JAVA = re.compile(
    r'getInstance\s*\(\s*"(?P<t>AES|DES|DESede|Blowfish|RC2|AES_128|AES_192|AES_256)"'
)

# Smali form. The transformation is a const-string; the call follows within a few
# instructions. We match the const-string and confirm the call nearby in code.
RE_SMALI_CONST_STRING = re.compile(r'const-string(?:/jumbo)?\s+[vp]\d+,\s*"(?P<t>[^"]*)"')
RE_SMALI_GETINSTANCE = re.compile(r'Ljavax/crypto/Cipher;->getInstance')

RE_EXPLICIT_ECB = re.compile(r'"(?P<t>[A-Za-z0-9_]+/ECB/[A-Za-z0-9]+)"')

CODE_RULES = [
    (
        "F-02", "HIGH", "Transformation string with no mode - resolves to ECB",
        RE_NO_MODE_JAVA,
        "Cipher.getInstance(\"AES\") is legal JCA and resolves to AES/ECB/PKCS5Padding. "
        "The developer did not choose ECB; they chose nothing, and the default chose "
        "for them. ECB encrypts every 16-byte block independently, so identical "
        "plaintext blocks give identical ciphertext blocks and blocks can be cut and "
        "pasted between records. Fix: AES/GCM/NoPadding with a provider-generated nonce.",
        None,
    ),
    (
        "F-02", "HIGH", "Explicit ECB mode",
        RE_EXPLICIT_ECB,
        "ECB chosen deliberately. The usual reason given is 'CBC needs an IV and I do "
        "not want to change the storage format'. The answer is that the format has to "
        "change: store nonce || ciphertext || tag and use GCM.",
        None,
    ),
    (
        "F-07", "MEDIUM", "MD5 in use",
        re.compile(r'getInstance\s*\(\s*"MD5"|MessageDigest\.getInstance\("MD5"\)|"MD5"'),
        "MD5 is collision-broken. It is a finding when used for integrity, signatures, "
        "password hashing or key derivation. It is NOT a finding when used as a cache "
        "key, an ETag or a de-duplication hash. Determine which before you report it - "
        "reporting a cache key as a crypto vulnerability costs you credibility.",
        None,
    ),
    (
        "F-07", "MEDIUM", "SHA-1 in use",
        re.compile(r'"SHA-?1"|SHA1withRSA|SHA1WithRSA|HmacSHA1(?!\w)'),
        "SHA-1 has a public collision (SHAttered, 2017). Fatal for signatures and "
        "certificates. HMAC-SHA1 is not broken by the collision but signals an "
        "unreviewed codebase. PBKDF2WithHmacSHA1 is still acceptable; note and move on.",
        None,
    ),
    (
        "F-06", "HIGH", "java.util.Random",
        re.compile(r'new\s+Random\s*\(|java\.util\.Random|Ljava/util/Random;|Random\(\)\.next'),
        "java.util.Random is a 48-bit linear congruential generator. Two consecutive "
        "outputs are enough to recover its state and predict every future value. Any "
        "use for a key, IV, nonce, token, session id, OTP or reset code is a finding. "
        "Fix: java.security.SecureRandom with no explicit seed.",
        None,
    ),
    (
        "F-05", "HIGH", "SHA1PRNG / setSeed key derivation",
        re.compile(r'SHA1PRNG|setSeed\s*\('),
        "The 'deterministic key' anti-pattern: SecureRandom.getInstance(\"SHA1PRNG\"), "
        "setSeed(secret), nextBytes(key). It was never a KDF, and from Android 7 "
        "setSeed supplements rather than replaces the seed, so the same code produces "
        "DIFFERENT keys on different releases - which is how apps discover this bug: "
        "as a data-loss incident, not as a security review finding. "
        "Fix: PBKDF2WithHmacSHA256 or HKDF.",
        None,
    ),
    (
        "F-01", "HIGH", "SecretKeySpec constructed in code",
        re.compile(r'new\s+SecretKeySpec\s*\(|Ljavax/crypto/spec/SecretKeySpec;-><init>'),
        "Every software symmetric key passes through this constructor. Trace the first "
        "argument backwards: if it reaches a String literal, a byte-array literal, a "
        "BuildConfig field or a resource, the key is hardcoded and identical for every "
        "installation of the app. Confirm at runtime with "
        "scripts/frida-jca-universal-hook.js, which prints the bytes.",
        None,
    ),
    (
        "F-03", "MEDIUM", "IvParameterSpec built from a literal or a zero array",
        re.compile(r'new\s+IvParameterSpec\s*\(|Ljavax/crypto/spec/IvParameterSpec;-><init>'),
        "Check what feeds it. new byte[16] is an all-zero IV. A string literal is a "
        "constant IV. key.getEncoded() means IV == key. All three make CBC "
        "deterministic: identical plaintexts produce identical ciphertexts, which "
        "enables equality detection and dictionary attacks over small plaintext spaces "
        "such as PINs. Fix: omit the IV on encrypt and read cipher.getIV() afterwards.",
        None,
    ),
    (
        "F-03", "MEDIUM", "Zero-filled byte array of block size",
        re.compile(r'new\s+byte\s*\[\s*(?:16|12|8)\s*\]'),
        "A zero-filled array of exactly one block (or one GCM nonce) is almost always "
        "an IV that nobody filled in. Follow it to its use.",
        None,
    ),
    (
        "F-14", "HIGH", "Textbook RSA (NoPadding)",
        re.compile(r'"RSA/(?:ECB|None)/NoPadding"|"RSA"'),
        "RSA with no padding is deterministic and malleable, and small plaintexts can "
        "be recovered by taking an integer root. Note that \"RSA\" alone resolves to "
        "RSA/ECB/PKCS1Padding on Android - the 'ECB' there is a JCA naming artefact, "
        "RSA has no mode. Fix: RSA/ECB/OAEPWithSHA-256AndMGF1Padding with an explicit "
        "OAEPParameterSpec.",
        None,
    ),
    (
        "F-14", "MEDIUM", "RSA PKCS#1 v1.5 encryption padding",
        re.compile(r'"RSA/(?:ECB|None)/PKCS1Padding"'),
        "PKCS#1 v1.5 encryption padding is the Bleichenbacher / ROBOT oracle class. If "
        "any error path distinguishes 'bad padding' from other failures, the private "
        "key operation becomes a decryption oracle. Fix: OAEP.",
        None,
    ),
    (
        "F-15", "LOW", "Non-constant-time comparison of a secret",
        re.compile(r'Arrays\.equals\s*\(|\.equals\s*\(\s*(?:mac|tag|hmac|signature|digest|hash)\b',
                   re.IGNORECASE),
        "Arrays.equals and String.equals return at the first differing byte, leaking "
        "how many leading bytes matched. Exploitability on-device is usually poor "
        "(timing noise dominates), so report it honestly as Low unless the comparison "
        "is server-side or the attacker can time it precisely. "
        "Fix: MessageDigest.isEqual, which is constant-time.",
        None,
    ),
    (
        "F-05", "MEDIUM", "Key derived from a device identifier",
        re.compile(r'ANDROID_ID|getDeviceId\s*\(|Settings\.Secure\.getString|SERIAL\b|getImei'),
        "Device identifiers are not secrets: other apps, the OS, backups and support "
        "logs see them, and on modern Android they are per-app but still not "
        "unpredictable to code running on the device. A key derived from one is "
        "recoverable by anyone with the device. Fix: AndroidKeyStore.",
        None,
    ),
    (
        "F-08", "INFO", "Home-grown byte manipulation near crypto",
        re.compile(r'\^\s*(?:key|k|secret|s)\s*\[|\bxor\b', re.IGNORECASE),
        "An XOR loop over a constant array is obfuscation, not encryption. Decide "
        "which claim the app makes: if it is presented to the user as encryption, it "
        "is a finding; if it is string obfuscation inside a packer, it is context, not "
        "a vulnerability. See README section 5.2 F-11 and ../40-Obfuscation.",
        None,
    ),
    (
        "F-12", "MEDIUM", "GCM tag length given in bytes instead of bits",
        re.compile(r'GCMParameterSpec\s*\(\s*(?:8|12|16|32)\s*,'),
        "GCMParameterSpec takes the tag length in BITS. Passing 16 asks for a 16-bit "
        "tag, forgeable in roughly 2^15 attempts. Passing 128 is correct. This is one "
        "of the few genuine 'off by a factor of eight' security bugs.",
        None,
    ),
    (
        "F-09", "MEDIUM", "Secret-looking name in a resource or build config",
        re.compile(r'(?i)\b(?:api[_-]?key|secret|password|passwd|private[_-]?key|'
                   r'client[_-]?secret|token|aes[_-]?key|enc[_-]?key)\b\s*[=:>]'),
        "strings.xml, BuildConfig fields and gradle.properties values ship in the APK "
        "in cleartext. aapt2 dump strings recovers them without any decompilation. "
        "Anything here is public.",
        None,
    ),
]

# PBKDF2 iteration counts appear as an integer literal in a PBEKeySpec call.
RE_PBE_ITER = re.compile(r'PBEKeySpec\s*\([^)]*?,\s*(\d{2,9})\s*,')
RE_SMALI_PBE = re.compile(r'const(?:/16|/high16|/4)?\s+[vp]\d+,\s*(0x[0-9a-fA-F]+|\d+)')

# Literal byte arrays of key-ish length in Smali: fill-array-data payloads.
RE_SMALI_FILL_ARRAY = re.compile(r'\.array-data\s+1\b')


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, UnicodeError):
        return None


def scan_code_file(path, text, ctx_lines=0):
    findings = []
    lines = text.splitlines()

    for fid, sev, title, rx, note, _ext in CODE_RULES:
        for m in rx.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            evidence = lines[line_no - 1].strip() if line_no - 1 < len(lines) else m.group(0)
            if ctx_lines:
                lo = max(0, line_no - 1 - ctx_lines)
                hi = min(len(lines), line_no + ctx_lines)
                evidence = "\n".join(l.rstrip() for l in lines[lo:hi])
            findings.append(Finding(fid, sev, title, path, line_no, evidence[:400], note))

    # PBKDF2 iteration counts (Java/Kotlin literal form).
    for m in RE_PBE_ITER.finditer(text):
        iters = int(m.group(1))
        line_no = text.count("\n", 0, m.start()) + 1
        if iters < 100000:
            sev = "HIGH" if iters <= 10000 else "MEDIUM"
            findings.append(Finding(
                "F-05", sev, "PBKDF2 iteration count too low", path, line_no,
                m.group(0)[:200],
                "The count is %d. Current guidance (OWASP Password Storage Cheat Sheet) "
                "is 600,000 for PBKDF2-HMAC-SHA256. Calibrate on the slowest device you "
                "support and store the count inside the record so it can be raised later "
                "without invalidating existing data - and authenticate the stored count "
                "as associated data so an attacker cannot edit it downwards." % iters))

    return findings


def scan_smali_file(path, text):
    """
    Smali needs its own pass, because the transformation string and the call that
    consumes it are separate instructions. We look for a const-string holding a
    transformation, then confirm a Cipher.getInstance within the next few lines.
    """
    findings = []
    lines = text.splitlines()

    for i, line in enumerate(lines):
        m = RE_SMALI_CONST_STRING.search(line)
        if not m:
            continue
        t = m.group("t")
        # Does a getInstance follow within a short window?
        window = "\n".join(lines[i:i + 8])
        if not RE_SMALI_GETINSTANCE.search(window):
            continue

        up = t.upper()
        if "/" not in t and up.split("_")[0] in {"AES", "DES", "DESEDE", "BLOWFISH", "RC2"}:
            findings.append(Finding(
                "F-02", "HIGH", "Smali: transformation with no mode (silent ECB)",
                path, i + 1, line.strip(),
                "const-string \"%s\" feeding Cipher.getInstance. With no mode token the "
                "JCA resolves this to %s/ECB/PKCS5Padding. This is the highest-yield "
                "single grep in an Android crypto review, and it survives R8 renaming "
                "because the string constant is not renamed." % (t, up)))
        elif "/ECB/" in up:
            findings.append(Finding(
                "F-02", "HIGH", "Smali: explicit ECB", path, i + 1, line.strip(),
                "const-string \"%s\" feeding Cipher.getInstance." % t))
        elif up.startswith("RSA") and "OAEP" not in up:
            findings.append(Finding(
                "F-14", "MEDIUM", "Smali: RSA without OAEP", path, i + 1, line.strip(),
                "const-string \"%s\". PKCS#1 v1.5 or no padding." % t))

    # fill-array-data blocks of exactly 16/24/32 bytes next to a SecretKeySpec.
    if "Ljavax/crypto/spec/SecretKeySpec;-><init>" in text:
        for m in re.finditer(r'\.array-data\s+1\n(?P<body>(?:\s+-?0x[0-9a-fA-F]+t\s*\n)+)\s*\.end array-data',
                             text):
            count = len(re.findall(r'0x[0-9a-fA-F]+t', m.group("body")))
            if count in (8, 16, 24, 32):
                line_no = text.count("\n", 0, m.start()) + 1
                raw = re.findall(r'(-?0x[0-9a-fA-F]+)t', m.group("body"))
                try:
                    vals = [int(v, 16) & 0xFF for v in raw]
                    as_hex = "".join("%02x" % v for v in vals)
                    as_txt = "".join(chr(v) if 32 <= v < 127 else "." for v in vals)
                except ValueError:
                    as_hex, as_txt = "?", "?"
                findings.append(Finding(
                    "F-01", "HIGH", "Literal byte array of key length in a class that "
                                    "builds a SecretKeySpec",
                    path, line_no, "%d bytes: %s  ascii=\"%s\"" % (count, as_hex, as_txt),
                    "A fill-array-data payload of exactly %d bytes in a class that "
                    "constructs a SecretKeySpec is a hardcoded key until proven "
                    "otherwise. Confirm at runtime; do not report on the static "
                    "evidence alone, because it might be a lookup table." % count))

    return findings


# --------------------------------------------------------------------------- #
# Data rules
# --------------------------------------------------------------------------- #

BASE64_RE = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
HEX_RE = re.compile(rb'\b(?:[0-9a-fA-F]{2}){16,}\b')

TEXTUAL_EXTS = {".xml", ".json", ".txt", ".properties", ".html", ".js", ".css"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", "build", ".gradle", ".idea"}


def shannon_entropy(data):
    """Bits per byte. 8.0 is maximal. Ciphertext and compressed data sit above 7.5."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def repeated_blocks(data, block=16):
    """Return (repeat_count, total_blocks, the most repeated block)."""
    if len(data) < block * 2:
        return 0, 0, None
    blocks = [data[i:i + block] for i in range(0, len(data) - len(data) % block, block)]
    counts = Counter(blocks)
    repeats = sum(c - 1 for c in counts.values() if c > 1)
    worst = counts.most_common(1)[0] if counts else (None, 0)
    return repeats, len(blocks), worst


def try_b64(raw):
    """Decode a Base64 candidate strictly enough to avoid nonsense matches."""
    try:
        if len(raw) % 4 != 0:
            raw = raw + b"=" * (-len(raw) % 4)
        out = base64.b64decode(raw, validate=True)
        return out if out else None
    except (binascii.Error, ValueError):
        return None


def printable_ratio(data):
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def scan_data_file(path, data, block=16, min_len=32, want_entropy=False):
    findings = []

    # ---- whole-file block repetition -------------------------------------- #
    if len(data) >= min_len:
        repeats, total, worst = repeated_blocks(data, block)
        if repeats > 0 and total >= 4:
            findings.append(Finding(
                "F-02", "HIGH", "Repeated %d-byte blocks in stored data" % block,
                path, 0,
                "%d repeated blocks out of %d. Most repeated: %s (x%d)"
                % (repeats, total, worst[0].hex() if worst[0] else "?", worst[1]),
                "Identical ciphertext blocks can only arise from ECB mode (or from a "
                "reused CTR/GCM keystream). This is proof of ECB that does not depend "
                "on reading the code at all, which makes it the strongest form of the "
                "finding. Caveat: a file of mostly zero bytes or a bitmap will also "
                "show repeats - confirm the region is actually ciphertext with the "
                "entropy figure before reporting."))

    # ---- embedded Base64 values ------------------------------------------- #
    values = []
    for m in BASE64_RE.finditer(data):
        raw = m.group(0)
        dec = try_b64(raw)
        if dec is None or len(dec) < 8:
            continue
        values.append((m.start(), raw, dec))

    for off, raw, dec in values:
        ratio = printable_ratio(dec)
        ent = shannon_entropy(dec)

        if ratio > 0.9 and len(dec) >= 8:
            findings.append(Finding(
                "F-10", "HIGH", "Base64 value decodes to readable text",
                path, 0,
                "offset %d: %s -> %r" % (off, raw[:48].decode("ascii", "replace"),
                                         dec[:96]),
                "Base64 is an encoding, not a cipher. Anyone can decode it. If this "
                "field is presented as 'encrypted' - in the code, in a data-flow "
                "diagram or to the client - the finding is that the data is stored in "
                "cleartext. Fix: encrypt with AES-GCM under an AndroidKeyStore key."))
            continue

        if len(dec) >= block * 2:
            repeats, total, worst = repeated_blocks(dec, block)
            if repeats > 0:
                findings.append(Finding(
                    "F-02", "HIGH", "Repeated blocks inside one Base64 value",
                    path, 0,
                    "offset %d: %d/%d blocks repeat; block %s"
                    % (off, repeats, total, worst[0].hex() if worst[0] else "?"),
                    "A single stored record containing two identical 16-byte ciphertext "
                    "blocks is ECB. Decode the value, split it into blocks, and put the "
                    "hex in the report."))

        if len(dec) in (16, 24, 32) and ent > 7.0:
            findings.append(Finding(
                "F-13", "MEDIUM", "High-entropy %d-byte value stored with app data" % len(dec),
                path, 0,
                "offset %d: %s (entropy %.2f)" % (off, dec.hex(), ent),
                "A 16, 24 or 32-byte value with near-maximal entropy sitting in the same "
                "file as ciphertext is very often the key. Try it: decrypt an adjacent "
                "ciphertext with it. Storing the key beside the data it protects "
                "reduces the scheme to obfuscation."))

        if want_entropy:
            findings.append(Finding(
                "INFO", "INFO", "Base64 value", path, 0,
                "offset %d len=%d entropy=%.2f printable=%.0f%%"
                % (off, len(dec), ent, ratio * 100),
                "Entropy near 8.0 means ciphertext or compressed data. Between 4 and 6 "
                "usually means structured binary. Below 4 with high printable ratio "
                "means text."))

    # ---- fixed-IV / nonce-reuse across records ---------------------------- #
    # (Cross-record comparison happens in the caller, which has all the values.)
    return findings, [dec for _off, _raw, dec in values]


def cross_record_analysis(all_values, block=16):
    """
    all_values: list of (path, decoded_bytes).

    Two records that share their leading 16 bytes were encrypted with the same IV.
    Two records that share their leading 12 bytes under GCM shared a nonce, which
    is the catastrophic case: the XOR of the plaintexts falls out, and the GCM
    authentication subkey H becomes recoverable, permitting universal forgery.
    """
    findings = []
    by_prefix16 = defaultdict(list)
    by_prefix12 = defaultdict(list)

    for path, dec in all_values:
        if len(dec) >= block + 8:
            by_prefix16[dec[:block]].append((path, dec))
        if len(dec) >= 12 + 16 + 1:
            by_prefix12[dec[:12]].append((path, dec))

    for prefix, group in by_prefix16.items():
        distinct_tails = {d[block:] for _p, d in group}
        if len(group) > 1 and len(distinct_tails) > 1:
            findings.append(Finding(
                "F-03", "HIGH", "Multiple records share the same leading %d bytes" % block,
                group[0][0], 0,
                "prefix %s shared by %d records with different bodies"
                % (prefix.hex(), len(group)),
                "If the format is iv || ciphertext, this is a fixed IV: CBC becomes "
                "deterministic, so equal plaintexts give equal ciphertexts and a small "
                "plaintext space (a PIN, a boolean, an enum) can be brute-forced by "
                "encrypting every candidate and matching. If the format is not "
                "iv || ciphertext then the first block is a header - check before "
                "reporting."))

    for prefix, group in by_prefix12.items():
        distinct_tails = {d[12:] for _p, d in group}
        if len(group) > 1 and len(distinct_tails) > 1:
            findings.append(Finding(
                "F-04", "CRITICAL", "Multiple records share the same leading 12 bytes",
                group[0][0], 0,
                "12-byte prefix %s shared by %d records" % (prefix.hex(), len(group)),
                "Twelve bytes is the GCM nonce length, and the conventional layout is "
                "nonce || ciphertext || tag. If these are GCM records, the same nonce "
                "was used for different messages under the same key. Consequences: the "
                "XOR of the two plaintexts is immediately recoverable, and the GCM "
                "authentication subkey H can be solved for, after which an attacker "
                "forges a valid tag for ANY message under that key. This is the "
                "'forbidden attack' (Joux). Confirm the layout before reporting - a "
                "12-byte constant header would look identical here."))

    return findings


# --------------------------------------------------------------------------- #
# Walking
# --------------------------------------------------------------------------- #

def looks_like_code_tree(root):
    """apktool output has smali*/ and AndroidManifest.xml; jadx output has sources/."""
    try:
        entries = os.listdir(root)
    except OSError:
        return False
    if any(e.startswith("smali") for e in entries):
        return True
    if "AndroidManifest.xml" in entries:
        return True
    if "sources" in entries or "resources" in entries:
        return True
    for dirpath, _dirs, files in os.walk(root):
        for f in files[:50]:
            if f.endswith((".smali", ".java", ".kt")):
                return True
        break
    return False


def excluded(path, patterns):
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def walk(root, excludes):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and
                   not excluded(os.path.join(dirpath, d), excludes)]
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            if excluded(full, excludes):
                continue
            yield full


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

BANNER = r"""
  detect-ecb.py - ECB and crypto-smell detector
  Chapter 34 - Cryptography.  Findings map to README.md section 5.2 (F-01..F-16).
"""


def print_report(findings, root, mode, quiet):
    if not quiet:
        print(BANNER)
        print("  target : %s" % os.path.abspath(root))
        print("  mode   : %s" % mode)
        print("  " + "-" * 68)

    real = [f for f in findings if f.severity != "INFO" or f.fid != "INFO"]
    info = [f for f in findings if f.severity == "INFO" and f.fid == "INFO"]

    real.sort(key=lambda f: f.sort_key())

    if not real:
        print("\n  No crypto smells matched. That is a starting point, not a clean "
              "bill of health:")
        print("    - the app may do its crypto in native code (check libcrypto.so usage)")
        print("    - strings may be encrypted by a commercial obfuscator")
        print("    - confirm dynamically with scripts/frida-jca-universal-hook.js")
    else:
        by_sev = defaultdict(list)
        for f in real:
            by_sev[f.severity].append(f)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            group = by_sev.get(sev)
            if not group:
                continue
            print("\n  === %s (%d) ===" % (sev, len(group)))
            seen_note = set()
            for f in group:
                loc = f.path if not f.line else "%s:%d" % (f.path, f.line)
                print("\n  [%s] %s" % (f.fid, f.title))
                print("      %s" % loc)
                for ln in f.evidence.splitlines():
                    print("      | %s" % ln)
                key = (f.fid, f.title)
                if key not in seen_note:
                    seen_note.add(key)
                    print("      why: %s" % _wrap(f.note, 6))

    if info:
        print("\n  === entropy detail (%d values) ===" % len(info))
        for f in info:
            print("      %s  %s" % (f.path, f.evidence))

    print("\n  " + "-" * 68)
    counts = Counter(f.severity for f in real)
    print("  totals: " + ", ".join("%s=%d" % (s, counts[s])
                                   for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                                   if counts.get(s)))
    print("""
  NEXT STEPS
    1. Confirm every static hit at runtime. A grep hit in dead code is not a
       finding, and a report full of unconfirmed greps is why clients stop
       reading mobile reports.
         frida -U -f <pkg> -l scripts/frida-jca-universal-hook.js

    2. Turn each confirmed hit into impact. "The key is hardcoded" is an
       observation; "here is the decrypted session token database" is a finding.

    3. Write the fix as code. See examples/02-correct-aes-gcm.java and
       examples/04-keystore-backed-vault.kt.
""")


def _wrap(text, indent, width=88):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width - indent:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    pad = "\n" + " " * (indent + 5)
    return pad.join(lines)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Detect ECB and related crypto smells in a decoded APK or in an "
                    "app's stored data.",
        epilog="Findings map to the catalogue in 34-Cryptography/README.md section 5.2.")
    ap.add_argument("path", help="directory or file to scan")
    ap.add_argument("--code", action="store_true", help="force the code scan")
    ap.add_argument("--data", action="store_true", help="force the data scan")
    ap.add_argument("--entropy", action="store_true",
                    help="report entropy for every file and Base64 value")
    ap.add_argument("--block-size", type=int, default=16,
                    help="block size for the repetition test (default 16)")
    ap.add_argument("--min-len", type=int, default=32,
                    help="ignore values shorter than this many bytes (default 32)")
    ap.add_argument("--context", type=int, default=0,
                    help="lines of context around a code hit")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--quiet", action="store_true", help="findings only")
    ap.add_argument("-x", "--exclude", action="append", default=[],
                    help="skip paths matching this glob (repeatable)")
    args = ap.parse_args(argv)

    root = args.path
    if not os.path.exists(root):
        print("error: no such path: %s" % root, file=sys.stderr)
        return 2

    if args.code:
        mode = "code"
    elif args.data or args.entropy:
        mode = "data"
    else:
        mode = "code" if looks_like_code_tree(root) else "data"

    findings = []
    all_values = []
    scanned = 0

    for path in walk(root, args.exclude):
        ext = os.path.splitext(path)[1].lower()

        if mode == "code":
            if ext not in CODE_EXTS:
                continue
            text = _read_text(path)
            if text is None:
                continue
            scanned += 1
            if ext == ".smali":
                findings.extend(scan_smali_file(path, text))
            findings.extend(scan_code_file(path, text, args.context))
        else:
            try:
                size = os.path.getsize(path)
                if size == 0 or size > 64 * 1024 * 1024:
                    continue
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            scanned += 1

            if args.entropy:
                ent = shannon_entropy(data)
                findings.append(Finding(
                    "INFO", "INFO", "file entropy", path, 0,
                    "%d bytes, entropy %.2f bits/byte%s"
                    % (len(data), ent,
                       "   <- looks like ciphertext or compressed data" if ent > 7.5 else ""),
                    "Values above ~7.5 are ciphertext, compressed data or already-"
                    "compressed media. Values around 4-6 are structured binary "
                    "(SQLite, protobuf). A 'protected' file below 6.0 is worth opening."))

            f, values = scan_data_file(path, data, args.block_size,
                                       args.min_len, args.entropy)
            findings.extend(f)
            for v in values:
                all_values.append((path, v))

    if mode == "data":
        findings.extend(cross_record_analysis(all_values, args.block_size))

    if args.json:
        print(json.dumps({
            "target": os.path.abspath(root),
            "mode": mode,
            "files_scanned": scanned,
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
    else:
        if not args.quiet:
            print("\n  files scanned: %d" % scanned)
        print_report(findings, root, mode, args.quiet)

    # Exit code 1 when anything of HIGH or CRITICAL severity was found, so this
    # can gate a CI job without parsing the output.
    return 1 if any(f.severity in ("HIGH", "CRITICAL") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
