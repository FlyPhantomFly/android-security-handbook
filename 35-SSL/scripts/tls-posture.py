#!/usr/bin/env python3
"""
tls-posture.py -- report what an endpoint's TLS actually is, and flag what is weak.

WHAT IT DOES
    Connects to a host:port and answers, with evidence rather than a grade:

        PROTOCOLS   which of SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3 the server will
                    actually complete a ServerHello for
        CIPHERS     which cipher suites it accepts, per protocol version, in
                    the server's own preference order, decoded into their four
                    parts (key exchange, authentication, encryption, MAC)
        CHAIN       every certificate the server sent: subject, issuer,
                    validity window, public key type and size, signature
                    algorithm, SANs, and whether it is a CA
        FINDINGS    each weakness, with an honest severity and a one-line
                    statement of what an attacker actually gets

    Two probing engines are used, deliberately:

      * A RAW ClientHello engine for SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2 and
        TLS 1.3. It builds the handshake bytes by hand and parses the
        ServerHello or Alert that comes back. This exists because your local
        OpenSSL will refuse to *offer* SSL 3.0, RC4, 3DES or export ciphers at
        its default security level -- so a tool built only on Python's `ssl`
        module reports "not supported" for a server that supports them
        perfectly well. That is a false negative on exactly the finding you
        were looking for.

      * Python's `ssl` module for retrieving the certificate chain, where
        being a real TLS client is worth more than being a byte-level one.

    Where the raw engine and the local library disagree, the raw engine wins,
    and the report says which one produced each line.

HOW TO RUN
    # the common case
    python3 tls-posture.py api.example.com

    # explicit port, e.g. an app's non-standard API port
    python3 tls-posture.py api.example.com:8443

    # several endpoints from an app's extracted domain list
    python3 tls-posture.py --targets domains.txt

    # machine readable, for diffing two test runs
    python3 tls-posture.py api.example.com --json > before.json

    # skip the slow part (per-version cipher enumeration)
    python3 tls-posture.py api.example.com --no-ciphers

    # go through Burp or any HTTP CONNECT proxy
    python3 tls-posture.py api.example.com --proxy 127.0.0.1:8080

    # be patient with a slow or rate-limited host
    python3 tls-posture.py api.example.com --timeout 15 --delay 0.2

REQUIREMENTS
    Python 3.7 or newer. Standard library only -- no `cryptography`, no
    `requests`, no `nmap`, no `sslyze`, no network tooling beyond a TCP socket.
    Runs on Windows, on a locked-down laptop, and in a container with nothing
    installed. No root, no device, no adb.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the APP you are testing trusts this endpoint. That is the whole
      point of chapter 35 and this script cannot answer it. A server can be
      configured perfectly and the app can still accept any certificate on
      earth, because validation happens in the CLIENT. Run
      trace-tls-validation.js against the app; a green report here means
      nothing about the app.
    - Whether the app PINS this endpoint. Pinning is client-side and invisible
      from here. See 36-CertificatePinning.
    - Whether the chain is TRUSTED. This script reports what the server sent
      and parses it. It deliberately does NOT verify against a trust store,
      because the question that matters is "what does the Android device's
      store make of this", not "what does this laptop's store make of it".
      The chain summary tells you enough to decide; `openssl verify` will do
      the arithmetic if you want it.
    - Whether a weak cipher is REACHABLE. A server can accept TLS 1.0 while
      every client that matters negotiates 1.3. That is still a finding, but a
      much smaller one than the report's severity column implies on its own --
      severity here is about the option existing, not about it being used.
    - Certificate TRANSPARENCY, OCSP stapling, CRL status, or revocation of
      any kind. Revocation needs a separate live fetch and a policy decision
      about soft-fail; it is out of scope and its absence is not an omission.
    - Anything about HTTP. No request is ever sent. The tool completes a
      handshake and hangs up, so it will not appear in application logs as a
      request and will not trip a WAF rule that matches on paths.
    - Whether you are allowed to point it at this host. Scanning
      infrastructure you do not own may be unlawful where you are. This tool
      makes one TCP connection per probe and can make dozens; that is not
      stealthy and is not meant to be.

ACCURACY NOTES
    Cipher-suite identifiers and names are IANA registry values. Where a suite
    is not in the table the report prints the raw two-byte identifier rather
    than guessing a name, in the same spirit as avc-decode.py's "no gloss
    available".

    Cipher enumeration works by repeatedly offering the set of suites not yet
    seen and recording which one the server picks. That yields the server's
    OWN preference order when the server enforces its order, and an arbitrary
    but complete set when it honours the client's. The report says which case
    it believes it is in, and why.

AUTHORISED TESTING ONLY.
"""

from __future__ import print_function

import argparse
import binascii
import json
import os
import socket
import ssl
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Protocol version identifiers, as they appear on the wire.
# ---------------------------------------------------------------------------

SSL_3_0 = 0x0300
TLS_1_0 = 0x0301
TLS_1_1 = 0x0302
TLS_1_2 = 0x0303
TLS_1_3 = 0x0304

VERSION_NAME = {
    0x0002: "SSL 2.0",
    SSL_3_0: "SSL 3.0",
    TLS_1_0: "TLS 1.0",
    TLS_1_1: "TLS 1.1",
    TLS_1_2: "TLS 1.2",
    TLS_1_3: "TLS 1.3",
}

# Probing order matters: oldest first, so that a server which drops the
# connection on a modern hello (some middleboxes do) still yields data.
PROBE_VERSIONS = [SSL_3_0, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3]

# Which Android releases shipped a client that would negotiate each version by
# default. Used only to annotate the report -- an app can always override.
ANDROID_DEFAULT_CLIENT = {
    SSL_3_0: "disabled by default since Android 5.0 (API 21), removed later",
    TLS_1_0: "client default through Android 9; disabled by default from Android 10 (API 29)",
    TLS_1_1: "client default through Android 9; disabled by default from Android 10 (API 29)",
    TLS_1_2: "enabled by default from Android 5.0 (API 21)",
    TLS_1_3: "enabled by default from Android 10 (API 29); Conscrypt supports it earlier",
}

# ---------------------------------------------------------------------------
# Cipher suites.
#
# Each entry is (name, kex, auth, enc, mac, notes). `kex` NONE means the suite
# is a TLS 1.3 suite, where key exchange is negotiated separately and every
# suite is AEAD and forward-secret by construction.
# ---------------------------------------------------------------------------

CIPHER_SUITES = {
    # --- TLS 1.3 ---------------------------------------------------------
    0x1301: ("TLS_AES_128_GCM_SHA256", None, None, "AES-128-GCM", "AEAD", ""),
    0x1302: ("TLS_AES_256_GCM_SHA384", None, None, "AES-256-GCM", "AEAD", ""),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", None, None, "ChaCha20-Poly1305", "AEAD", ""),
    0x1304: ("TLS_AES_128_CCM_SHA256", None, None, "AES-128-CCM", "AEAD", ""),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", None, None, "AES-128-CCM-8", "AEAD",
             "8-byte tag: a shorter authentication tag than usual"),

    # --- ECDHE, AEAD -- the modern TLS 1.2 suites ------------------------
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AES-128-GCM", "AEAD", ""),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AES-256-GCM", "AEAD", ""),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES-128-GCM", "AEAD", ""),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AES-256-GCM", "AEAD", ""),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA",
             "ChaCha20-Poly1305", "AEAD", ""),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA",
             "ChaCha20-Poly1305", "AEAD", ""),
    0xCCAA: ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE", "RSA",
             "ChaCha20-Poly1305", "AEAD", ""),

    # --- ECDHE, CBC ------------------------------------------------------
    0xC023: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "ECDSA", "AES-128-CBC", "SHA256", ""),
    0xC024: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "ECDSA", "AES-256-CBC", "SHA384", ""),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "AES-128-CBC", "SHA256", ""),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "AES-256-CBC", "SHA384", ""),
    0xC009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", "AES-128-CBC", "SHA-1", ""),
    0xC00A: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", "AES-256-CBC", "SHA-1", ""),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", "AES-128-CBC", "SHA-1", ""),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", "AES-256-CBC", "SHA-1", ""),
    0xC007: ("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", "ECDSA", "RC4-128", "SHA-1", ""),
    0xC011: ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", "RSA", "RC4-128", "SHA-1", ""),
    0xC008: ("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "ECDSA", "3DES-EDE-CBC", "SHA-1", ""),
    0xC012: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "RSA", "3DES-EDE-CBC", "SHA-1", ""),

    # --- DHE -------------------------------------------------------------
    0x009E: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", "AES-128-GCM", "AEAD", ""),
    0x009F: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", "AES-256-GCM", "AEAD", ""),
    0x0067: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", "AES-128-CBC", "SHA256", ""),
    0x006B: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", "AES-256-CBC", "SHA256", ""),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "AES-128-CBC", "SHA-1", ""),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", "AES-256-CBC", "SHA-1", ""),
    0x0016: ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "RSA", "3DES-EDE-CBC", "SHA-1", ""),
    0x0015: ("TLS_DHE_RSA_WITH_DES_CBC_SHA", "DHE", "RSA", "DES-CBC", "SHA-1", ""),
    0x0014: ("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "DHE", "RSA", "DES40-CBC", "SHA-1", "EXPORT"),

    # --- static RSA key exchange: no forward secrecy ---------------------
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "RSA", "AES-128-GCM", "AEAD", ""),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "RSA", "AES-256-GCM", "AEAD", ""),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", "AES-128-CBC", "SHA256", ""),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", "AES-256-CBC", "SHA256", ""),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES-128-CBC", "SHA-1", ""),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", "AES-256-CBC", "SHA-1", ""),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES-EDE-CBC", "SHA-1", ""),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4-128", "SHA-1", ""),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RSA", "RC4-128", "MD5", ""),
    0x0009: ("TLS_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", "DES-CBC", "SHA-1", ""),
    0x0003: ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", "RSA", "RC4-40", "MD5", "EXPORT"),
    0x0006: ("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RSA", "RSA", "RC2-40-CBC", "MD5", "EXPORT"),
    0x0008: ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "RSA", "RSA", "DES40-CBC", "SHA-1", "EXPORT"),
    0x0001: ("TLS_RSA_WITH_NULL_MD5", "RSA", "RSA", "NULL", "MD5", "NULL"),
    0x0002: ("TLS_RSA_WITH_NULL_SHA", "RSA", "RSA", "NULL", "SHA-1", "NULL"),
    0x003B: ("TLS_RSA_WITH_NULL_SHA256", "RSA", "RSA", "NULL", "SHA256", "NULL"),

    # --- anonymous: no server authentication at all ----------------------
    0x0018: ("TLS_DH_anon_WITH_RC4_128_MD5", "DH", "anon", "RC4-128", "MD5", "ANON"),
    0x001B: ("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "DH", "anon", "3DES-EDE-CBC", "SHA-1", "ANON"),
    0x0034: ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "DH", "anon", "AES-128-CBC", "SHA-1", "ANON"),
    0x003A: ("TLS_DH_anon_WITH_AES_256_CBC_SHA", "DH", "anon", "AES-256-CBC", "SHA-1", "ANON"),
    0xC018: ("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "ECDH", "anon", "AES-128-CBC", "SHA-1", "ANON"),
    0xC019: ("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "ECDH", "anon", "AES-256-CBC", "SHA-1", "ANON"),

    # --- signalling values, never negotiated -----------------------------
    0x00FF: ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", None, None, None, None, "SCSV"),
    0x5600: ("TLS_FALLBACK_SCSV", None, None, None, None, "SCSV"),
}

# Suites offered when enumerating a pre-1.3 version. Deliberately includes the
# broken ones: finding them is the point.
LEGACY_OFFER = [c for c in CIPHER_SUITES
                if c not in (0x00FF, 0x5600) and CIPHER_SUITES[c][1] is not None]

TLS13_OFFER = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]

# ---------------------------------------------------------------------------
# Alert descriptions, so a refusal says WHY.
# ---------------------------------------------------------------------------

ALERT_DESC = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure -- no cipher suite or parameter in common",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca -- the server did not recognise a CA we offered",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version -- the server refuses this protocol version",
    71: "insufficient_security -- server requires stronger parameters",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name -- SNI names a host this server does not serve",
    116: "certificate_required",
    120: "no_application_protocol",
}

# ---------------------------------------------------------------------------
# Named elliptic curve groups, for the supported_groups extension and for
# decoding an EC certificate's curve.
# ---------------------------------------------------------------------------

NAMED_GROUPS = [
    (0x001D, "x25519"),
    (0x0017, "secp256r1"),
    (0x0018, "secp384r1"),
    (0x0019, "secp521r1"),
    (0x001E, "x448"),
]

# signature_algorithms values we advertise. Broad, so that an old server does
# not refuse us for reasons unrelated to what we are measuring.
SIG_ALGS = [
    0x0403,  # ecdsa_secp256r1_sha256
    0x0503,  # ecdsa_secp384r1_sha384
    0x0603,  # ecdsa_secp521r1_sha512
    0x0807,  # ed25519
    0x0804,  # rsa_pss_rsae_sha256
    0x0805,  # rsa_pss_rsae_sha384
    0x0806,  # rsa_pss_rsae_sha512
    0x0401,  # rsa_pkcs1_sha256
    0x0501,  # rsa_pkcs1_sha384
    0x0601,  # rsa_pkcs1_sha512
    0x0201,  # rsa_pkcs1_sha1
    0x0203,  # ecdsa_sha1
]


# ===========================================================================
# Minimal DER / X.509 reader.
#
# Written by hand rather than pulled from `cryptography` so that this script
# has no dependencies. It reads only the fields the report needs and refuses
# to guess about anything else.
# ===========================================================================

class DerError(Exception):
    pass


def der_read_tlv(buf, off):
    """Read one DER Tag-Length-Value at `off`.

    Returns (tag, header_len, length, value_offset, next_offset).
    """
    if off >= len(buf):
        raise DerError("truncated at %d" % off)
    tag = buf[off]
    if (tag & 0x1F) == 0x1F:
        raise DerError("multi-byte tags are not supported (tag=0x%02x)" % tag)
    p = off + 1
    if p >= len(buf):
        raise DerError("truncated length at %d" % p)
    first = buf[p]
    p += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0:
            raise DerError("indefinite length is not valid DER")
        if p + n > len(buf):
            raise DerError("truncated long length at %d" % p)
        length = int.from_bytes(buf[p:p + n], "big")
        p += n
    else:
        length = first
    if p + length > len(buf):
        raise DerError("value overruns buffer at %d" % p)
    return tag, p - off, length, p, p + length


def der_children(buf, off):
    """Iterate the children of the constructed element at `off`."""
    tag, _hl, length, vo, nxt = der_read_tlv(buf, off)
    if not (tag & 0x20):
        raise DerError("element at %d is primitive, not constructed" % off)
    p = vo
    while p < vo + length:
        t, hl, ln, v, n = der_read_tlv(buf, p)
        yield (t, p, v, ln)
        p = n


def der_oid_to_string(buf, vo, length):
    """Decode an OBJECT IDENTIFIER value into dotted-decimal."""
    if length == 0:
        return ""
    data = buf[vo:vo + length]
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for b in data[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


OID_NAMES = {
    # Relative distinguished name components
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.4.15": "businessCategory",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
    # Public key algorithms
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.3.101.112": "Ed25519",
    "1.2.840.10040.4.1": "id-dsa",
    # Signature algorithms
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    # Curves
    "1.2.840.10045.3.1.7": "prime256v1 (P-256)",
    "1.3.132.0.34": "secp384r1 (P-384)",
    "1.3.132.0.35": "secp521r1 (P-521)",
    "1.3.132.0.10": "secp256k1",
    # Extensions
    "2.5.29.15": "keyUsage",
    "2.5.29.17": "subjectAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.37": "extKeyUsage",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.31": "cRLDistributionPoints",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList",
}

# Signature algorithms whose hash is broken or deprecated for certificates.
WEAK_SIG_OIDS = {
    "1.2.840.113549.1.1.5": ("SHA-1", "SHA-1 collisions are practical (SHAttered, 2017)"),
    "1.2.840.10045.4.1": ("SHA-1", "SHA-1 collisions are practical (SHAttered, 2017)"),
    "1.2.840.113549.1.1.4": ("MD5", "MD5 collisions are trivial; a rogue CA was built this way in 2008"),
    "1.2.840.113549.1.1.2": ("MD2", "MD2 is comprehensively broken"),
}


def parse_name(buf, off):
    """Render an X.501 Name as a comma-joined RDN string."""
    out = []
    try:
        for _t, rdn_off, _v, _l in der_children(buf, off):
            for _t2, atv_off, _v2, _l2 in der_children(buf, rdn_off):
                kids = list(der_children(buf, atv_off))
                if len(kids) < 2:
                    continue
                oid = der_oid_to_string(buf, kids[0][2], kids[0][3])
                val = buf[kids[1][2]:kids[1][2] + kids[1][3]]
                try:
                    text = val.decode("utf-8")
                except UnicodeDecodeError:
                    text = val.decode("latin-1", "replace")
                out.append("%s=%s" % (OID_NAMES.get(oid, oid), text))
    except DerError:
        pass
    return ", ".join(out) if out else "(unparsable)"


def parse_time(buf, vo, length, tag):
    """UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) into ISO-ish text."""
    raw = buf[vo:vo + length].decode("ascii", "replace")
    try:
        if tag == 0x17:              # YYMMDDHHMMSSZ
            yy = int(raw[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = raw[2:]
        else:                        # YYYYMMDDHHMMSSZ
            year = int(raw[0:4])
            rest = raw[4:]
        return "%04d-%s-%s %s:%s:%s UTC" % (
            year, rest[0:2], rest[2:4], rest[4:6], rest[6:8], rest[8:10])
    except (ValueError, IndexError):
        return raw


def parse_time_epoch(buf, vo, length, tag):
    """Same value as parse_time, but as a UNIX timestamp for comparisons."""
    import calendar
    raw = buf[vo:vo + length].decode("ascii", "replace")
    try:
        if tag == 0x17:
            yy = int(raw[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = raw[2:]
        else:
            year = int(raw[0:4])
            rest = raw[4:]
        return calendar.timegm((
            year, int(rest[0:2]), int(rest[2:4]),
            int(rest[4:6]), int(rest[6:8]), int(rest[8:10]), 0, 0, 0))
    except (ValueError, IndexError):
        return None


def parse_san(buf, off):
    """SubjectAltName -> list of strings, tagged by kind."""
    names = []
    try:
        for tag, item_off, vo, ln in der_children(buf, off):
            kind = tag & 0x1F
            raw = buf[vo:vo + ln]
            if kind == 2:
                names.append("DNS:" + raw.decode("utf-8", "replace"))
            elif kind == 1:
                names.append("email:" + raw.decode("utf-8", "replace"))
            elif kind == 6:
                names.append("URI:" + raw.decode("utf-8", "replace"))
            elif kind == 7:
                if ln == 4:
                    names.append("IP:" + ".".join(str(b) for b in raw))
                elif ln == 16:
                    names.append("IP:" + ":".join(
                        "%02x%02x" % (raw[i], raw[i + 1]) for i in range(0, 16, 2)))
                else:
                    names.append("IP:(%d bytes)" % ln)
            else:
                names.append("othername[%d]" % kind)
    except DerError:
        pass
    return names


def rsa_modulus_bits(buf, vo, length):
    """SubjectPublicKey BIT STRING -> RSAPublicKey -> modulus bit length."""
    # BIT STRING value starts with an "unused bits" octet, always 0 here.
    inner = vo + 1
    try:
        kids = list(der_children(buf, inner))
        if not kids:
            return None
        _t, _o, mvo, mln = kids[0]
        m = buf[mvo:mvo + mln]
        # DER integers are signed, so a leading 0x00 is padding.
        i = 0
        while i < len(m) and m[i] == 0:
            i += 1
        if i >= len(m):
            return 0
        return (len(m) - i - 1) * 8 + m[i].bit_length()
    except DerError:
        return None


class Certificate(object):
    """The subset of an X.509 certificate this report needs."""

    def __init__(self, der):
        self.der = der
        self.subject = "(unparsed)"
        self.issuer = "(unparsed)"
        self.not_before = None
        self.not_after = None
        self.not_before_epoch = None
        self.not_after_epoch = None
        self.serial = None
        self.sig_alg_oid = None
        self.sig_alg = None
        self.key_alg = None
        self.key_bits = None
        self.key_curve = None
        self.san = []
        self.is_ca = None
        self.path_len = None
        self.self_signed = None
        self.version = None
        self.parse_error = None
        try:
            self._parse()
        except (DerError, IndexError, ValueError) as exc:
            self.parse_error = str(exc)

    def _parse(self):
        b = self.der
        top = list(der_children(b, 0))
        if len(top) < 3:
            raise DerError("certificate has fewer than 3 top-level elements")
        tbs_off = top[0][1]
        sigalg_off = top[1][1]

        # outer signatureAlgorithm
        sk = list(der_children(b, sigalg_off))
        if sk:
            self.sig_alg_oid = der_oid_to_string(b, sk[0][2], sk[0][3])
            self.sig_alg = OID_NAMES.get(self.sig_alg_oid, self.sig_alg_oid)

        tbs = list(der_children(b, tbs_off))
        idx = 0
        # [0] EXPLICIT version, optional, default v1.
        #
        # The test below must be `& 0xE0`, not `& 0xC0`. A context-specific
        # constructed tag is 0b10_1_xxxxx: class bits 10, constructed bit 1.
        # `(t & 0xC0) == 0xA0` masks the constructed bit away and can never be
        # true, so the version element is silently skipped, every subsequent
        # field is read one position early, and the certificate parses into
        # convincing nonsense rather than failing. That bug shipped in this
        # script's first draft and was caught only by running it.
        if tbs and (tbs[0][0] & 0xE0) == 0xA0 and (tbs[0][0] & 0x1F) == 0:
            vkids = list(der_children(b, tbs[0][1]))
            if vkids:
                self.version = int.from_bytes(
                    b[vkids[0][2]:vkids[0][2] + vkids[0][3]], "big") + 1
            idx = 1
        else:
            self.version = 1

        # serialNumber
        self.serial = binascii.hexlify(
            b[tbs[idx][2]:tbs[idx][2] + tbs[idx][3]]).decode("ascii")
        idx += 1
        idx += 1                                    # inner signature AlgorithmIdentifier
        self.issuer = parse_name(b, tbs[idx][1]); issuer_off = tbs[idx][1]; idx += 1

        # validity
        vk = list(der_children(b, tbs[idx][1]))
        if len(vk) >= 2:
            self.not_before = parse_time(b, vk[0][2], vk[0][3], vk[0][0])
            self.not_after = parse_time(b, vk[1][2], vk[1][3], vk[1][0])
            self.not_before_epoch = parse_time_epoch(b, vk[0][2], vk[0][3], vk[0][0])
            self.not_after_epoch = parse_time_epoch(b, vk[1][2], vk[1][3], vk[1][0])
        idx += 1

        self.subject = parse_name(b, tbs[idx][1]); subject_off = tbs[idx][1]; idx += 1

        # A certificate is self-issued when the two Name encodings are equal.
        _it, _ihl, _iln, _ivo, inx = der_read_tlv(b, issuer_off)
        _st, _shl, _sln, _svo, snx = der_read_tlv(b, subject_off)
        self.self_signed = (b[issuer_off:inx] == b[subject_off:snx])

        # SubjectPublicKeyInfo
        spki_off = tbs[idx][1]
        spki = list(der_children(b, spki_off))
        if spki:
            alg = list(der_children(b, spki[0][1]))
            if alg:
                oid = der_oid_to_string(b, alg[0][2], alg[0][3])
                self.key_alg = OID_NAMES.get(oid, oid)
                if oid == "1.2.840.10045.2.1" and len(alg) > 1:
                    curve_oid = der_oid_to_string(b, alg[1][2], alg[1][3])
                    self.key_curve = OID_NAMES.get(curve_oid, curve_oid)
                    if "P-256" in (self.key_curve or ""):
                        self.key_bits = 256
                    elif "P-384" in (self.key_curve or ""):
                        self.key_bits = 384
                    elif "P-521" in (self.key_curve or ""):
                        self.key_bits = 521
                elif oid == "1.2.840.113549.1.1.1" and len(spki) > 1:
                    self.key_bits = rsa_modulus_bits(b, spki[1][2], spki[1][3])
                elif oid == "1.3.101.112":
                    self.key_bits = 255
        idx += 1

        # optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions
        for t, o, vo, ln in tbs[idx:]:
            if (t & 0xE0) == 0xA0 and (t & 0x1F) == 3:
                ext_seq = list(der_children(b, o))
                if not ext_seq:
                    continue
                for _et, ext_off, _evo, _eln in der_children(b, ext_seq[0][1]):
                    self._parse_extension(b, ext_off)

    def _parse_extension(self, b, ext_off):
        kids = list(der_children(b, ext_off))
        if not kids:
            return
        oid = der_oid_to_string(b, kids[0][2], kids[0][3])
        octets = None
        for t, o, vo, ln in kids[1:]:
            if t == 0x04:
                octets = (vo, ln)
        if octets is None:
            return
        vo, ln = octets
        if oid == "2.5.29.17":
            self.san = parse_san(b, vo)
        elif oid == "2.5.29.19":
            self.is_ca = False
            try:
                for t, o, cvo, cln in der_children(b, vo):
                    if t == 0x01:                    # BOOLEAN cA
                        self.is_ca = b[cvo] != 0
                    elif t == 0x02:                  # INTEGER pathLenConstraint
                        self.path_len = int.from_bytes(b[cvo:cvo + cln], "big")
            except DerError:
                pass

    def summary_key(self):
        if self.key_alg is None:
            return "unknown"
        if self.key_curve:
            return "%s %s" % (self.key_alg, self.key_curve)
        if self.key_bits:
            return "%s %d-bit" % (self.key_alg, self.key_bits)
        return self.key_alg

    def to_dict(self):
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "version": self.version,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature_algorithm": self.sig_alg,
            "public_key": self.summary_key(),
            "key_bits": self.key_bits,
            "san": self.san,
            "is_ca": self.is_ca,
            "path_len": self.path_len,
            "self_signed": self.self_signed,
            "sha256_fingerprint": self.fingerprint(),
            "parse_error": self.parse_error,
        }

    def fingerprint(self):
        import hashlib
        return hashlib.sha256(self.der).hexdigest()

    def spki_pin(self):
        """The base64 SHA-256 of the SubjectPublicKeyInfo -- the value that goes
        in an HPKP header, an OkHttp CertificatePinner, or a
        network_security_config <pin>. Computed here purely so you can compare
        it against what an app has configured. Pinning itself is chapter 36."""
        import base64
        import hashlib
        try:
            tbs_off = list(der_children(self.der, 0))[0][1]
            tbs = list(der_children(self.der, tbs_off))
            idx = 0
            if tbs and (tbs[0][0] & 0xE0) == 0xA0 and (tbs[0][0] & 0x1F) == 0:
                idx = 1
            idx += 5                                 # serial, sigalg, issuer, validity, subject
            spki_off = tbs[idx][1]
            _t, _hl, _ln, _vo, nxt = der_read_tlv(self.der, spki_off)
            return base64.b64encode(
                hashlib.sha256(self.der[spki_off:nxt]).digest()).decode("ascii")
        except (DerError, IndexError):
            return None


# ===========================================================================
# Raw TLS ClientHello engine.
# ===========================================================================

def build_extension(ext_type, body):
    return struct.pack(">HH", ext_type, len(body)) + body


def build_client_hello(host, version, suites, tls13=False):
    """Build a complete TLS record containing one ClientHello.

    `version` is the legacy client_version. For TLS 1.3 the real version lives
    in the supported_versions extension and client_version stays at 0x0303,
    which is what `tls13=True` arranges.
    """
    legacy_version = TLS_1_2 if tls13 else version

    client_random = os.urandom(32)
    session_id = b""

    body = struct.pack(">H", legacy_version)
    body += client_random
    body += struct.pack(">B", len(session_id)) + session_id

    suite_bytes = b"".join(struct.pack(">H", s) for s in suites)
    # TLS_EMPTY_RENEGOTIATION_INFO_SCSV: some old servers refuse a hello
    # without either this or the renegotiation_info extension.
    suite_bytes += struct.pack(">H", 0x00FF)
    body += struct.pack(">H", len(suite_bytes)) + suite_bytes

    body += b"\x01\x00"                       # one compression method: null

    exts = b""

    # server_name (0) -- omitted for a literal IP, which is illegal in SNI.
    if host and not _is_ip_literal(host):
        name = host.encode("idna") if _is_ascii(host) else host.encode("utf-8")
        sni = struct.pack(">B", 0) + struct.pack(">H", len(name)) + name
        exts += build_extension(0, struct.pack(">H", len(sni)) + sni)

    # supported_groups (10)
    groups = b"".join(struct.pack(">H", g) for g, _n in NAMED_GROUPS)
    exts += build_extension(10, struct.pack(">H", len(groups)) + groups)

    # ec_point_formats (11): uncompressed only
    exts += build_extension(11, b"\x01\x00")

    # signature_algorithms (13) -- required from TLS 1.2 onward
    if version >= TLS_1_2 or tls13:
        sa = b"".join(struct.pack(">H", s) for s in SIG_ALGS)
        exts += build_extension(13, struct.pack(">H", len(sa)) + sa)

    # renegotiation_info (65281), empty
    exts += build_extension(65281, b"\x00")

    if tls13:
        # supported_versions (43): TLS 1.3 only, so the answer is unambiguous.
        exts += build_extension(43, b"\x02" + struct.pack(">H", TLS_1_3))
        # key_share (51) with an EMPTY client_shares list. This is legal and
        # makes the server reply with a HelloRetryRequest -- which still names
        # the cipher suite it chose, which is all we need. Sending a real
        # key share would mean implementing X25519, for no extra information.
        exts += build_extension(51, struct.pack(">H", 0))

    body += struct.pack(">H", len(exts)) + exts

    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16" + struct.pack(">H", legacy_version) + \
             struct.pack(">H", len(handshake)) + handshake
    return record


def _is_ascii(s):
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _is_ip_literal(host):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except (OSError, ValueError):
            continue
    return False


class HelloResult(object):
    def __init__(self):
        self.ok = False
        self.version = None          # negotiated version, as an int
        self.cipher = None           # negotiated cipher suite id
        self.alert_level = None
        self.alert_desc = None
        self.error = None
        self.hrr = False             # HelloRetryRequest (TLS 1.3 only)

    def why(self):
        if self.ok:
            return "ServerHello"
        if self.alert_desc is not None:
            return "alert %d: %s" % (
                self.alert_desc, ALERT_DESC.get(self.alert_desc, "unknown"))
        return self.error or "no response"


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _open_socket(host, port, timeout, proxy=None):
    if proxy:
        phost, pport = proxy
        s = socket.create_connection((phost, pport), timeout=timeout)
        s.settimeout(timeout)
        req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
               % (host, port, host, port)).encode("ascii")
        s.sendall(req)
        # Read until the blank line ending the proxy's response headers.
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                s.close()
                raise OSError("proxy closed the connection during CONNECT")
            data += chunk
            if len(data) > 65536:
                s.close()
                raise OSError("proxy response headers are implausibly large")
        status = data.split(b"\r\n", 1)[0].decode("latin-1")
        if " 200" not in status:
            s.close()
            raise OSError("proxy refused CONNECT: %s" % status)
        return s
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def send_hello(host, port, version, suites, timeout, tls13=False, proxy=None,
               sni=None):
    """Send one ClientHello and classify the answer."""
    r = HelloResult()
    sock = None
    try:
        sock = _open_socket(host, port, timeout, proxy)
        hello = build_client_hello(sni if sni is not None else host,
                                   version, suites, tls13=tls13)
        sock.sendall(hello)

        header = _recv_exact(sock, 5)
        if header is None:
            r.error = "server closed the connection without replying"
            return r
        rtype, rver, rlen = struct.unpack(">BHH", header)
        if rlen == 0 or rlen > 65535:
            r.error = "implausible record length %d" % rlen
            return r
        payload = _recv_exact(sock, rlen)
        if payload is None:
            r.error = "truncated record"
            return r

        if rtype == 21:                                   # alert
            if len(payload) >= 2:
                r.alert_level = payload[0]
                r.alert_desc = payload[1]
            else:
                r.error = "malformed alert"
            return r

        if rtype != 22:                                   # not a handshake
            r.error = "unexpected record type %d" % rtype
            return r

        if len(payload) < 4 or payload[0] != 0x02:        # not a ServerHello
            r.error = "handshake message %d, expected ServerHello" % payload[0]
            return r

        sh = payload[4:]
        if len(sh) < 35:
            r.error = "ServerHello too short"
            return r
        legacy = struct.unpack(">H", sh[0:2])[0]
        server_random = sh[2:34]
        p = 34
        sid_len = sh[p]; p += 1 + sid_len
        if p + 2 > len(sh):
            r.error = "ServerHello truncated before cipher suite"
            return r
        r.cipher = struct.unpack(">H", sh[p:p + 2])[0]; p += 2
        p += 1                                            # compression method

        negotiated = legacy
        if p + 2 <= len(sh):
            ext_total = struct.unpack(">H", sh[p:p + 2])[0]; p += 2
            end = min(p + ext_total, len(sh))
            while p + 4 <= end:
                etype, elen = struct.unpack(">HH", sh[p:p + 4]); p += 4
                if p + elen > end:
                    break
                if etype == 43 and elen >= 2:             # supported_versions
                    negotiated = struct.unpack(">H", sh[p:p + 2])[0]
                p += elen

        # HelloRetryRequest carries this exact server_random (RFC 8446 4.1.3).
        HRR_RANDOM = binascii.unhexlify(
            "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
        r.hrr = (server_random == HRR_RANDOM)

        r.ok = True
        r.version = negotiated
        return r

    except (OSError, socket.timeout, struct.error) as exc:
        r.error = "%s: %s" % (type(exc).__name__, exc)
        return r
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_version(host, port, version, timeout, proxy=None, sni=None):
    """Does the server complete a ServerHello for this protocol version?"""
    tls13 = (version == TLS_1_3)
    suites = TLS13_OFFER if tls13 else LEGACY_OFFER
    r = send_hello(host, port, version, suites, timeout, tls13=tls13,
                   proxy=proxy, sni=sni)
    if r.ok and r.version is not None and r.version != version:
        # The server answered, but downgraded. That is a "no" for this version
        # and worth recording, because it is NOT the same as a refusal.
        r.ok = False
        r.error = "server negotiated %s instead" % VERSION_NAME.get(
            r.version, "0x%04x" % r.version)
    return r


def enumerate_ciphers(host, port, version, timeout, proxy=None, sni=None,
                      delay=0.0, limit=64):
    """Repeatedly offer the not-yet-seen suites and record the server's pick.

    Returns (accepted, server_ordered, note). `server_ordered` is a best-effort
    judgement, explained in `note`.
    """
    tls13 = (version == TLS_1_3)
    remaining = list(TLS13_OFFER if tls13 else LEGACY_OFFER)
    accepted = []
    rounds = 0

    while remaining and rounds < limit:
        rounds += 1
        r = send_hello(host, port, version, remaining, timeout, tls13=tls13,
                       proxy=proxy, sni=sni)
        if delay:
            time.sleep(delay)
        if not r.ok or r.cipher is None:
            break
        if r.version is not None and r.version != version:
            break
        if r.cipher not in remaining:
            # A server that picks something we did not offer is broken or is a
            # middlebox. Record it and stop rather than looping forever.
            accepted.append(r.cipher)
            break
        accepted.append(r.cipher)
        remaining.remove(r.cipher)

    note = ""
    server_ordered = None
    if len(accepted) >= 2:
        # Offer the first two accepted suites in the reverse of the order we
        # saw them. If the server still picks the first one it picked before,
        # it is enforcing its own preference.
        rev = [accepted[1], accepted[0]]
        r = send_hello(host, port, version, rev, timeout, tls13=tls13,
                       proxy=proxy, sni=sni)
        if r.ok and r.cipher == accepted[0]:
            server_ordered = True
            note = ("server enforces its own preference order, so the list "
                    "below is that order, strongest-preferred first")
        elif r.ok and r.cipher == accepted[1]:
            server_ordered = False
            note = ("server honours the CLIENT's order, so the list below is "
                    "a complete set in no meaningful order")
        else:
            note = "preference order could not be determined"
    elif len(accepted) == 1:
        note = "only one suite accepted, so there is no order to determine"

    return accepted, server_ordered, note


# ===========================================================================
# Certificate chain retrieval, via the ssl module.
# ===========================================================================

def fetch_chain(host, port, timeout, proxy=None, sni=None):
    """Return (list_of_Certificate, negotiated_info_dict, error_or_None).

    Verification is deliberately disabled. This tool reports what the server
    sent; it does not adjudicate trust, because the trust store that matters is
    the Android device's, not this laptop's.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (AttributeError, ValueError):
        pass
    # Ask OpenSSL for everything it is willing to offer at a relaxed security
    # level, so that an endpoint with only legacy suites still yields a chain.
    for spec in ("ALL:@SECLEVEL=0", "ALL:@SECLEVEL=1", "DEFAULT"):
        try:
            ctx.set_ciphers(spec)
            break
        except ssl.SSLError:
            continue

    raw = None
    info = {}
    try:
        raw = _open_socket(host, port, timeout, proxy)
        server_hostname = None if _is_ip_literal(host) else (sni if sni is not None else host)
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as s:
            raw = None                       # ownership passed to the wrapper
            info["negotiated_version"] = s.version()
            c = s.cipher()
            if c:
                info["negotiated_cipher"] = c[0]
                info["negotiated_cipher_bits"] = c[2]
            info["compression"] = s.compression()
            info["alpn"] = s.selected_alpn_protocol()

            chain_der = []
            if hasattr(s, "get_unverified_chain"):
                try:
                    chain = s.get_unverified_chain() or []
                    for cert in chain:
                        chain_der.append(cert.public_bytes(ssl.ENCODING_DER)
                                         if hasattr(cert, "public_bytes")
                                         else bytes(cert))
                except (AttributeError, ssl.SSLError, TypeError, ValueError):
                    chain_der = []
            if not chain_der:
                leaf = s.getpeercert(binary_form=True)
                if leaf:
                    chain_der = [leaf]
            return [Certificate(d) for d in chain_der], info, None
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return [], info, "%s: %s" % (type(exc).__name__, exc)
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


# ===========================================================================
# Findings.
# ===========================================================================

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Finding(object):
    def __init__(self, severity, title, detail, impact):
        self.severity = severity
        self.title = title
        self.detail = detail
        self.impact = impact

    def to_dict(self):
        return {"severity": self.severity, "title": self.title,
                "detail": self.detail, "impact": self.impact}


def assess(result):
    """Turn measurements into findings, with severities that are defensible."""
    f = []
    versions = result["protocols"]

    if versions.get("SSL 3.0", {}).get("supported"):
        f.append(Finding(
            "HIGH", "SSL 3.0 accepted",
            "The server completed a ServerHello for SSL 3.0.",
            "POODLE (CVE-2014-3566) recovers plaintext a byte at a time from "
            "any CBC suite under SSL 3.0. Android clients have not negotiated "
            "SSL 3.0 by default for a decade, so exploitation needs a client "
            "that will downgrade -- but the option should not exist."))

    for v in ("TLS 1.0", "TLS 1.1"):
        if versions.get(v, {}).get("supported"):
            f.append(Finding(
                "MEDIUM", "%s accepted" % v,
                "The server completed a ServerHello for %s." % v,
                "Deprecated by RFC 8996. Its CBC construction is the root of "
                "BEAST and Lucky 13, and it forbids modern AEAD suites. "
                "Android disables it client-side by default from API 29, so "
                "the practical risk is to older clients and to anything that "
                "explicitly re-enables it."))

    if not versions.get("TLS 1.2", {}).get("supported") and \
       not versions.get("TLS 1.3", {}).get("supported"):
        f.append(Finding(
            "HIGH", "Neither TLS 1.2 nor TLS 1.3 is available",
            "Only deprecated protocol versions completed a handshake.",
            "A current Android client with default settings cannot reach this "
            "endpoint at all, and any client that can has disabled its own "
            "protections to do so."))

    if not versions.get("TLS 1.3", {}).get("supported"):
        f.append(Finding(
            "INFO", "TLS 1.3 not offered",
            "The server did not complete a TLS 1.3 handshake.",
            "Not a vulnerability. TLS 1.3 removes whole classes of "
            "misconfiguration (static RSA, CBC, renegotiation) by deleting "
            "them from the protocol; its absence means those classes remain "
            "possible here."))

    seen_suites = set()
    for vname, vdata in versions.items():
        for cid in vdata.get("ciphers", []):
            seen_suites.add(cid)

    def suite_name(cid):
        e = CIPHER_SUITES.get(cid)
        return e[0] if e else "unknown suite 0x%04X" % cid

    weak_enc = {
        "RC4-128": ("HIGH", "RC4 keystream biases allow plaintext recovery "
                            "(RFC 7465 prohibits RC4 outright)"),
        "RC4-40": ("CRITICAL", "40-bit export-grade RC4 is breakable by brute force"),
        "RC2-40-CBC": ("CRITICAL", "40-bit export-grade RC2 is breakable by brute force"),
        "DES-CBC": ("CRITICAL", "56-bit DES is breakable by brute force"),
        "DES40-CBC": ("CRITICAL", "40-bit export-grade DES is trivially breakable"),
        "3DES-EDE-CBC": ("MEDIUM", "64-bit block size makes Sweet32 collision "
                                   "attacks feasible on long-lived connections"),
        "NULL": ("CRITICAL", "NULL encryption means the record layer is plaintext"),
    }

    for cid in sorted(seen_suites):
        e = CIPHER_SUITES.get(cid)
        if not e:
            f.append(Finding(
                "INFO", "Unrecognised cipher suite 0x%04X accepted" % cid,
                "This identifier is not in the script's table.",
                "Look it up in the IANA TLS registry before drawing a "
                "conclusion. The script refuses to guess."))
            continue
        name, kex, auth, enc, mac, notes = e
        if auth == "anon":
            f.append(Finding(
                "CRITICAL", "Anonymous cipher suite accepted: %s" % name,
                "This suite performs no server authentication.",
                "Any machine on the path can complete the handshake as the "
                "server. There is no certificate to validate, so no client "
                "check can help. This is TLS with the authentication removed."))
        if enc in weak_enc:
            sev, why = weak_enc[enc]
            f.append(Finding(
                sev, "Weak encryption accepted: %s" % name,
                "Record encryption is %s." % enc, why))
        if "EXPORT" in (notes or ""):
            f.append(Finding(
                "CRITICAL", "Export-grade suite accepted: %s" % name,
                "Deliberately weakened 1990s-era cryptography.",
                "Export suites are the precondition for FREAK and Logjam-class "
                "downgrade attacks. There is no legitimate reason to offer one."))
        if mac == "MD5":
            f.append(Finding(
                "HIGH", "MD5 record MAC accepted: %s" % name,
                "Record integrity uses HMAC-MD5.",
                "HMAC-MD5 is not as broken as bare MD5, but no current client "
                "needs it and its presence indicates an unmaintained profile."))
        if kex == "RSA" and auth == "RSA":
            f.append(Finding(
                "LOW", "Static RSA key exchange accepted: %s" % name,
                "The premaster secret is encrypted to the server's long-term "
                "RSA key, so there is no forward secrecy.",
                "Anyone who records traffic today and later obtains the "
                "server's private key can decrypt all of it retroactively. "
                "That includes a future compromise, a subpoena, or a backup "
                "leak. It also keeps the ROBOT/Bleichenbacher oracle surface "
                "alive."))

    # ---- certificate findings ------------------------------------------
    chain = result.get("chain", [])
    now = time.time()
    for i, cd in enumerate(chain):
        where = "leaf certificate" if i == 0 else "intermediate #%d" % i
        if cd.get("parse_error"):
            f.append(Finding(
                "INFO", "Could not fully parse the %s" % where,
                cd["parse_error"],
                "Not necessarily a problem with the certificate -- this "
                "script's DER reader is deliberately minimal."))
            continue

        oid = cd.get("_sig_oid")
        if oid in WEAK_SIG_OIDS:
            algname, why = WEAK_SIG_OIDS[oid]
            sev = "HIGH" if i == 0 else "MEDIUM"
            f.append(Finding(
                sev, "%s is signed with %s" % (where.capitalize(), algname),
                "signatureAlgorithm = %s" % cd.get("signature_algorithm"),
                why + ". A self-signed ROOT's own signature does not matter "
                      "(nothing verifies it), but a signature over any other "
                      "certificate does."))

        bits = cd.get("key_bits")
        keyalg = cd.get("public_key", "")
        if bits and "rsa" in keyalg.lower():
            if bits < 1024:
                f.append(Finding("CRITICAL", "%s has a %d-bit RSA key" % (where.capitalize(), bits),
                                 "Public key is RSA %d-bit." % bits,
                                 "Factorable with modest resources."))
            elif bits < 2048:
                f.append(Finding("HIGH", "%s has a %d-bit RSA key" % (where.capitalize(), bits),
                                 "Public key is RSA %d-bit." % bits,
                                 "Below the 2048-bit floor every public CA has "
                                 "enforced since 2014."))

        nae = cd.get("_not_after_epoch")
        nbe = cd.get("_not_before_epoch")
        if nae is not None:
            if nae < now:
                f.append(Finding(
                    "HIGH", "%s has expired" % where.capitalize(),
                    "notAfter = %s" % cd.get("not_after"),
                    "Every correctly-configured client will refuse this "
                    "connection. If the app you are testing does NOT refuse "
                    "it, that is the finding -- see this chapter's Lab 02."))
            elif nae - now < 21 * 86400:
                f.append(Finding(
                    "LOW", "%s expires in under 21 days" % where.capitalize(),
                    "notAfter = %s" % cd.get("not_after"),
                    "Operational, not a vulnerability."))
        if nbe is not None and nbe > now:
            f.append(Finding(
                "HIGH", "%s is not yet valid" % where.capitalize(),
                "notBefore = %s" % cd.get("not_before"),
                "Clock skew on either end, or a certificate issued ahead of time."))

        if i == 0:
            if not cd.get("san"):
                f.append(Finding(
                    "MEDIUM", "Leaf certificate has no subjectAltName",
                    "No SAN extension was found.",
                    "Since Chrome 58 and Android's own verifier, CN is no "
                    "longer consulted for hostname matching. A certificate "
                    "with only a CN will fail hostname verification on any "
                    "current client -- and an app that accepts it anyway has "
                    "a broken HostnameVerifier."))
            if cd.get("self_signed") and cd.get("is_ca") is not True:
                f.append(Finding(
                    "INFO", "Leaf certificate is self-signed",
                    "issuer == subject.",
                    "Expected for a development endpoint or an interception "
                    "proxy. On production it means no CA vouches for this key."))
            wild = [n for n in cd.get("san", []) if n.startswith("DNS:*.")]
            for w in wild:
                labels = w[len("DNS:*."):].split(".")
                if len(labels) <= 2:
                    f.append(Finding(
                        "MEDIUM", "Very broad wildcard SAN: %s" % w,
                        "The wildcard covers every host under a "
                        "second-level domain.",
                        "One compromised host anywhere under that domain "
                        "yields a certificate valid for all of them."))

    if len(chain) == 1:
        f.append(Finding(
            "LOW", "Server sent only one certificate",
            "No intermediate was supplied.",
            "If the leaf is not self-signed, clients must find the "
            "intermediate themselves. Desktop browsers often cache or fetch "
            "it via authorityInfoAccess; Android's verifier is less "
            "forgiving, so this shows up as an app-only failure that 'works "
            "in the browser'."))

    f.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.title))
    return f


# ===========================================================================
# Reporting.
# ===========================================================================

BAR = "=" * 78
SUB = "-" * 78


def describe_suite(cid):
    e = CIPHER_SUITES.get(cid)
    if not e:
        return "0x%04X  (not in this script's table -- look it up in the IANA registry)" % cid
    name, kex, auth, enc, mac, notes = e
    if kex is None:
        parts = "AEAD %s, key exchange negotiated separately (TLS 1.3)" % enc
    else:
        parts = "kex=%s auth=%s enc=%s mac=%s" % (kex, auth, enc, mac)
    tail = ("  [%s]" % notes) if notes else ""
    return "0x%04X  %-52s %s%s" % (cid, name, parts, tail)


def render(result):
    out = []
    out.append(BAR)
    out.append("TLS POSTURE  %s:%d" % (result["host"], result["port"]))
    out.append("probed %s" % result["timestamp"])
    out.append(BAR)

    # ---- protocols ----
    out.append("")
    out.append("PROTOCOL VERSIONS   (raw ClientHello engine -- independent of "
               "local OpenSSL policy)")
    out.append(SUB)
    for vname in ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
        d = result["protocols"].get(vname)
        if d is None:
            continue
        mark = "ACCEPTED" if d["supported"] else "refused "
        out.append("  %-9s %s   %s" % (vname, mark, d["why"]))
        note = ANDROID_DEFAULT_CLIENT.get(
            [k for k, v in VERSION_NAME.items() if v == vname][0])
        if note:
            out.append("            android client default: %s" % note)

    # ---- ciphers ----
    for vname in ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
        d = result["protocols"].get(vname)
        if not d or not d["supported"]:
            continue
        ciphers = d.get("ciphers") or []
        if not ciphers:
            continue
        out.append("")
        out.append("CIPHER SUITES accepted under %s   (%d)" % (vname, len(ciphers)))
        out.append(SUB)
        if d.get("cipher_note"):
            out.append("  note: %s" % d["cipher_note"])
        for cid in ciphers:
            out.append("  " + describe_suite(cid))

    # ---- chain ----
    out.append("")
    out.append("CERTIFICATE CHAIN AS SENT   (not verified against any trust store)")
    out.append(SUB)
    if result.get("chain_error"):
        out.append("  could not retrieve: %s" % result["chain_error"])
    if not result.get("chain"):
        out.append("  (no certificates retrieved)")
    for i, c in enumerate(result.get("chain", [])):
        role = "LEAF" if i == 0 else "CA #%d" % i
        out.append("  [%s]" % role)
        out.append("    subject   : %s" % c["subject"])
        out.append("    issuer    : %s" % c["issuer"])
        out.append("    valid     : %s  ->  %s" % (c["not_before"], c["not_after"]))
        out.append("    key       : %s" % c["public_key"])
        out.append("    signature : %s" % c["signature_algorithm"])
        out.append("    is CA     : %s%s" % (
            c["is_ca"],
            ("  pathLen=%s" % c["path_len"]) if c["path_len"] is not None else ""))
        out.append("    self-signed: %s" % c["self_signed"])
        if c["san"]:
            shown = c["san"][:12]
            out.append("    SAN       : %s%s" % (
                ", ".join(shown),
                ("  (+%d more)" % (len(c["san"]) - 12)) if len(c["san"]) > 12 else ""))
        else:
            out.append("    SAN       : (none)")
        out.append("    SHA-256   : %s" % c["sha256_fingerprint"])
        if c.get("spki_pin"):
            out.append("    SPKI pin  : sha256/%s   (for comparison against an "
                       "app's configured pin -- see 36-CertificatePinning)"
                       % c["spki_pin"])
        out.append("")

    # ---- what the ssl module negotiated ----
    info = result.get("negotiated") or {}
    if info:
        out.append("WHAT A DEFAULT PYTHON CLIENT ACTUALLY NEGOTIATED "
                   "(ssl module, this machine)")
        out.append(SUB)
        for k in ("negotiated_version", "negotiated_cipher",
                  "negotiated_cipher_bits", "alpn", "compression"):
            if k in info:
                out.append("  %-24s %s" % (k, info[k]))

    # ---- findings ----
    out.append("")
    out.append("FINDINGS")
    out.append(SUB)
    if not result["findings"]:
        out.append("  Nothing flagged. That means this SERVER's TLS profile is "
                   "unremarkable.")
        out.append("  It says nothing whatsoever about the APP. Read the "
                   "header of this file.")
    for fd in result["findings"]:
        out.append("  [%-8s] %s" % (fd["severity"], fd["title"]))
        out.append("             %s" % fd["detail"])
        out.append("             impact: %s" % fd["impact"])
        out.append("")

    out.append(BAR)
    counts = {}
    for fd in result["findings"]:
        counts[fd["severity"]] = counts.get(fd["severity"], 0) + 1
    out.append("  " + "   ".join(
        "%s=%d" % (s, counts.get(s, 0))
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
    out.append("  Server-side posture only. Client-side trust is chapter 35 "
               "section 3; pinning is chapter 36.")
    out.append(BAR)
    return "\n".join(out)


# ===========================================================================
# Driver
# ===========================================================================

def probe_target(host, port, args):
    result = {
        "host": host,
        "port": port,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "protocols": {},
        "chain": [],
        "chain_error": None,
        "negotiated": {},
        "findings": [],
    }
    proxy = args._proxy
    sni = args.sni

    for v in PROBE_VERSIONS:
        vname = VERSION_NAME[v]
        r = probe_version(host, port, v, args.timeout, proxy=proxy, sni=sni)
        entry = {"supported": r.ok, "why": r.why(), "ciphers": [],
                 "cipher_note": "", "server_ordered": None}
        if r.ok and not args.no_ciphers:
            acc, ordered, note = enumerate_ciphers(
                host, port, v, args.timeout, proxy=proxy, sni=sni,
                delay=args.delay)
            entry["ciphers"] = acc
            entry["cipher_note"] = note
            entry["server_ordered"] = ordered
        elif r.ok and r.cipher is not None:
            entry["ciphers"] = [r.cipher]
            entry["cipher_note"] = ("cipher enumeration disabled; this is only "
                                    "the suite chosen for the probe hello")
        result["protocols"][vname] = entry
        if args.delay:
            time.sleep(args.delay)

    certs, info, err = fetch_chain(host, port, args.timeout, proxy=proxy, sni=sni)
    result["negotiated"] = info
    result["chain_error"] = err
    for c in certs:
        d = c.to_dict()
        d["spki_pin"] = c.spki_pin()
        d["_sig_oid"] = c.sig_alg_oid
        d["_not_after_epoch"] = c.not_after_epoch
        d["_not_before_epoch"] = c.not_before_epoch
        result["chain"].append(d)

    result["findings"] = [f.to_dict() for f in assess(result)]

    # Strip the private helper keys before anything is serialised.
    for d in result["chain"]:
        for k in ("_sig_oid", "_not_after_epoch", "_not_before_epoch"):
            d.pop(k, None)
    return result


def parse_target(text, default_port=443):
    text = text.strip()
    if not text or text.startswith("#"):
        return None
    if text.startswith("["):                       # [v6addr]:port
        close = text.find("]")
        if close == -1:
            return None
        host = text[1:close]
        rest = text[close + 1:]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if text.count(":") == 1:
        host, _, p = text.partition(":")
        try:
            return host, int(p)
        except ValueError:
            return text, default_port
    return text, default_port


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Report an endpoint's TLS protocols, cipher suites and "
                    "certificate chain, and flag what is weak.",
        epilog="Read the WHAT THIS WILL NOT TELL YOU block at the top of this "
               "file before putting any output in a report. In particular: a "
               "clean result here says nothing about the app.")
    ap.add_argument("target", nargs="?",
                    help="host or host:port (default port 443)")
    ap.add_argument("--targets", metavar="FILE",
                    help="file of host[:port] lines, one per target")
    ap.add_argument("--port", type=int, default=443,
                    help="default port when the target does not name one")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="per-connection timeout in seconds (default 8)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to sleep between probes; use against a "
                         "rate-limited host")
    ap.add_argument("--no-ciphers", action="store_true",
                    help="skip per-version cipher enumeration (much faster)")
    ap.add_argument("--proxy", metavar="HOST:PORT",
                    help="route every probe through an HTTP CONNECT proxy")
    ap.add_argument("--sni", metavar="NAME",
                    help="send this name in SNI instead of the target host")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable output")
    args = ap.parse_args(argv)

    args._proxy = None
    if args.proxy:
        h, _, p = args.proxy.partition(":")
        if not p.isdigit():
            sys.stderr.write("tls-posture: --proxy needs HOST:PORT\n")
            return 2
        args._proxy = (h, int(p))

    targets = []
    if args.targets:
        if not os.path.exists(args.targets):
            sys.stderr.write("tls-posture: no such file: %s\n" % args.targets)
            return 2
        with open(args.targets, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                t = parse_target(line, args.port)
                if t:
                    targets.append(t)
    if args.target:
        t = parse_target(args.target, args.port)
        if t:
            targets.append(t)

    if not targets:
        ap.print_usage()
        sys.stderr.write("tls-posture: give a target, or --targets FILE\n")
        return 2

    results = []
    for host, port in targets:
        try:
            results.append(probe_target(host, port, args))
        except KeyboardInterrupt:
            sys.stderr.write("\ninterrupted\n")
            return 130
        except Exception as exc:                     # keep going across a list
            results.append({
                "host": host, "port": port, "error": "%s: %s"
                % (type(exc).__name__, exc),
                "protocols": {}, "chain": [], "findings": [],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            })

    if args.as_json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
        return 0

    for i, r in enumerate(results):
        if i:
            print("")
        if r.get("error"):
            print("%s:%d -- probe failed: %s" % (r["host"], r["port"], r["error"]))
            continue
        print(render(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
