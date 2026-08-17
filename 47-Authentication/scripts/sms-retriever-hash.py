#!/usr/bin/env python3
# 47-Authentication/scripts/sms-retriever-hash.py
#
# PURPOSE
#   Compute the 11-character SMS Retriever app hash for an Android application,
#   directly from its APK.
#
#   The SMS Retriever API lets an app read exactly ONE incoming SMS - the one
#   whose body ends with this hash - with NO SMS PERMISSION AT ALL. The hash is
#   derived from the package name AND the app's signing certificate, so a
#   repackaged clone gets a different hash and never receives the code.
#
#   You need this number when you are:
#
#     * TESTING an app's OTP flow and want to know whether the server is
#       appending the RIGHT hash. A mismatch presents to the developer as "SMS
#       autofill never works", and the usual developer "fix" is to add READ_SMS -
#       which is the origin of a large share of the over-permissioned OTP apps
#       measured in README section 8.6 (9 of 17 apps carried full-inbox SMS
#       markers while 12 of 17 already had the permissionless API).
#
#     * REVIEWING an app and want to confirm its debug and release builds differ,
#       which they always do, because they are signed with different keys.
#
# USAGE
#   python3 -B sms-retriever-hash.py app.apk
#   python3 -B sms-retriever-hash.py app.apk --package com.example.override
#   python3 -B sms-retriever-hash.py *.apk
#
#   Pull an APK from a device first:
#     adb shell pm path com.example.app
#     adb pull /data/app/~~xxx/com.example.app-1/base.apk
#
# THE ALGORITHM (Google's published AppSignatureHelper)
#
#     appInfo = "<package name> <hex of the signing certificate DER>"
#     digest  = SHA-256(appInfo, UTF-8)
#     hash    = base64(digest[0:9], no padding)[0:11]
#
#   Nine bytes is chosen because it encodes to exactly twelve base64 characters
#   with no padding, of which the first eleven are used. The hex encoding of the
#   certificate is lower-case and is the DER of the signer certificate - the same
#   bytes `keytool`/`apksigner` fingerprint.
#
# LIMITS, STATED HONESTLY
#   * v1 signature blocks (META-INF/*.RSA|DSA|EC) are parsed directly. For an
#     APK signed ONLY with v2/v3/v4 and no v1 block, this script says so rather
#     than guessing; use `apksigner verify --print-certs` and pass the DER with
#     --cert-der. Most real apps still carry a v1 block.
#   * The SMS Retriever API itself is a Google Play services component and is NOT
#     in AOSP, so there is no source to check this against. The algorithm here is
#     the published one; the way to VERIFY it is empirical - send a message with
#     the computed hash and see whether it is delivered.
#   * A multi-signer APK produces one hash per signer. All are printed.
#
# DEPENDENCIES
#   Standard library only, if the APK carries a v1 signature block. No
#   cryptography package is required: the certificate DER is extracted from the
#   PKCS#7 structure by locating the certificate SEQUENCE, which needs only a
#   minimal DER walker (included).
#
# AUTHORISED TESTING ONLY. This reads a local file and computes a hash. It
# sends nothing and talks to nothing.

import argparse
import base64
import hashlib
import re
import subprocess
import sys
import zipfile


# ---------------------------------------------------------------------------
# Minimal DER reader - just enough to find X.509 certificates inside a PKCS#7
# SignedData blob. Writing this out is more honest than pulling in a dependency
# for what is fundamentally a tag-length-value walk.
# ---------------------------------------------------------------------------

def der_read_tlv(buf, pos):
    """Return (tag, header_len, length, value_start, value_end) at `pos`."""
    if pos >= len(buf):
        raise ValueError("truncated DER at %d" % pos)
    tag = buf[pos]
    p = pos + 1
    if p >= len(buf):
        raise ValueError("truncated DER length at %d" % p)
    first = buf[p]
    p += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise ValueError("unsupported DER length form (%d bytes)" % n)
        if p + n > len(buf):
            raise ValueError("truncated DER long length")
        length = int.from_bytes(buf[p:p + n], "big")
        p += n
    return tag, p - pos, length, p, p + length


def find_certificates(der):
    """Yield the DER bytes of each X.509 certificate found in a PKCS#7 blob.

    THE SHAPE TEST MATTERS, AND A LOOSER ONE PRODUCES THE WRONG ANSWER SILENTLY.

    RFC 5280 defines:

        Certificate ::= SEQUENCE {
            tbsCertificate      TBSCertificate,      -- SEQUENCE
            signatureAlgorithm  AlgorithmIdentifier, -- SEQUENCE
            signatureValue      BIT STRING           -- tag 0x03
        }

    So a certificate is a SEQUENCE with EXACTLY THREE children, of tags
    SEQUENCE, SEQUENCE, BIT STRING, and the three must exactly fill the parent.

    An earlier revision of this function tested only "SEQUENCE whose first child
    is 0xA0 or 0x02". That matched an inner sub-structure of the certificate
    rather than the certificate itself: it produced a plausible-looking 425-byte
    blob and a confident SHA-256 fingerprint that DID NOT MATCH `apksigner
    verify --print-certs` for the same APK. The failure was silent - there was no
    error, just a wrong hash - which is exactly the kind of bug that ships. The
    lesson is the one this chapter repeats: if the output looks reasonable, check
    it against an independent tool before believing it.
    """
    out = []
    seen = set()
    i = 0
    n = len(der)
    while i < n:
        if der[i] != 0x30:
            i += 1
            continue
        try:
            _, _, length, vstart, vend = der_read_tlv(der, i)
        except ValueError:
            i += 1
            continue
        if length < 200 or vend > n:
            i += 1
            continue

        try:
            # child 1: tbsCertificate, a SEQUENCE
            t1, _, _, _, e1 = der_read_tlv(der, vstart)
            if t1 != 0x30:
                i += 1
                continue
            # child 2: signatureAlgorithm, a SEQUENCE
            t2, _, _, _, e2 = der_read_tlv(der, e1)
            if t2 != 0x30:
                i += 1
                continue
            # child 3: signatureValue, a BIT STRING, and it must end the parent
            t3, _, _, _, e3 = der_read_tlv(der, e2)
            if t3 != 0x03 or e3 != vend:
                i += 1
                continue
            # the tbsCertificate itself must begin with [0] version or INTEGER serial
            t4, _, _, _, _ = der_read_tlv(der, vstart + (der_read_tlv(der, vstart)[1]))
            if t4 not in (0xA0, 0x02):
                i += 1
                continue
        except ValueError:
            i += 1
            continue

        cert = der[i:vend]
        key = hashlib.sha256(cert).hexdigest()
        if key not in seen:
            seen.add(key)
            out.append(cert)
        i = vend
    return out


# ---------------------------------------------------------------------------
# APK inspection
# ---------------------------------------------------------------------------

def package_name_from_apk(apk_path):
    """Determine the package name, preferring a real parser over a guess.

    Order of preference:

      1. `aapt2 dump packagename` - authoritative, ships with the Android SDK
         build-tools, and is almost always on PATH on a machine that does
         Android work.
      2. `aapt dump badging` - the legacy equivalent.
      3. Return None and make the caller demand --package.

    An earlier revision guessed by regexing the UTF-16 string pool for the
    first dotted identifier. On a real APK that returned
    `Nandroidx.work.impl.background.systemalarm.ConstraintProxy` - a string-pool
    fragment with a stray leading character, not a package name at all - and it
    did so WITHOUT ANY WARNING. Since the package name is an input to the hash,
    a wrong guess silently produces a wrong hash, which is worse than refusing.
    Guessing was removed rather than improved.
    """
    for cmd in (["aapt2", "dump", "packagename", apk_path],
                ["aapt", "dump", "badging", apk_path]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
        if out.returncode != 0:
            continue
        text = out.stdout.strip()
        if cmd[1] == "dump" and cmd[2] == "packagename":
            first = text.splitlines()[0].strip() if text else ""
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+", first):
                return first
        else:
            m = re.search(r"package: name='([^']+)'", text)
            if m:
                return m.group(1)
    return None


def signer_certs_from_apk(apk_path):
    """Extract signer certificate DERs from the v1 (JAR) signature block."""
    certs = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            for name in z.namelist():
                if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", name, re.IGNORECASE):
                    certs.extend(find_certificates(z.read(name)))
    except (zipfile.BadZipFile, OSError) as exc:
        raise RuntimeError("cannot read %s: %s" % (apk_path, exc))
    return certs


# ---------------------------------------------------------------------------
# The hash itself
# ---------------------------------------------------------------------------

NUM_HASHED_BYTES = 9
NUM_BASE64_CHARS = 11


def app_hash(package_name, cert_der):
    """The published SMS Retriever app-hash computation."""
    cert_hex = cert_der.hex()                       # lower-case hex of the DER
    app_info = "%s %s" % (package_name, cert_hex)
    digest = hashlib.sha256(app_info.encode("utf-8")).digest()
    truncated = digest[:NUM_HASHED_BYTES]
    b64 = base64.b64encode(truncated).decode("ascii").rstrip("=")
    return b64[:NUM_BASE64_CHARS]


def sha256_fingerprint(cert_der):
    h = hashlib.sha256(cert_der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


# ---------------------------------------------------------------------------

def process(apk_path, override_package, cert_der_path):
    print("=" * 74)
    print("APK     : %s" % apk_path)

    package = override_package or package_name_from_apk(apk_path)
    if not package:
        print("  ERROR: could not determine the package name.")
        print("  Neither aapt2 nor aapt is on PATH, so there is nothing")
        print("  authoritative to ask. Pass it explicitly:")
        print("      --package com.example.app")
        print("  This script does NOT guess: the package name is an input to")
        print("  the hash, so a wrong guess yields a wrong hash silently.")
        return 1
    print("Package : %s%s" % (package, "  (from --package)" if override_package else
                              "  (from aapt/aapt2)"))

    if cert_der_path:
        with open(cert_der_path, "rb") as fh:
            certs = [fh.read()]
        print("Cert    : %s  (from --cert-der)" % cert_der_path)
    else:
        certs = signer_certs_from_apk(apk_path)

    if not certs:
        print()
        print("  No v1 (JAR) signature block found.")
        print("  This APK is signed with v2/v3/v4 only. Extract the signer")
        print("  certificate and pass it back in:")
        print()
        print("    apksigner verify --print-certs-pem %s > signer.pem" % apk_path)
        print("    openssl x509 -in signer.pem -outform DER -out signer.der")
        print("    python3 -B %s %s --cert-der signer.der" % (sys.argv[0], apk_path))
        return 1

    print("Signers : %d" % len(certs))
    for idx, der in enumerate(certs):
        print()
        print("  signer[%d]" % idx)
        print("    SHA-256 fingerprint : %s" % sha256_fingerprint(der))
        print("    DER length          : %d bytes" % len(der))
        h = app_hash(package, der)
        print("    SMS RETRIEVER HASH  : %s" % h)
        print()
        print("    The server must append this to the message:")
        print()
        print("        <#> Your code is 481203")
        print("        %s" % h)
        print()
        print("    Constraints: message begins with <#>, ends with the hash, and")
        print("    is at most 140 bytes. Get any of the three wrong and delivery")
        print("    silently does not happen - there is no error anywhere.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Compute the SMS Retriever 11-character app hash from an APK.")
    ap.add_argument("apks", nargs="+", help="one or more .apk files")
    ap.add_argument("--package", help="override the package name")
    ap.add_argument("--cert-der",
                    help="signer certificate in DER form, for v2/v3-only APKs")
    args = ap.parse_args(argv)

    if args.cert_der and len(args.apks) > 1:
        ap.error("--cert-der applies to a single APK")

    rc = 0
    for path in args.apks:
        try:
            rc |= process(path, args.package, args.cert_der)
        except RuntimeError as exc:
            print("SKIP %s (%s)" % (path, exc), file=sys.stderr)
            rc = 1

    print()
    print("=" * 74)
    print("VERIFYING THIS NUMBER")
    print("  There is no offline oracle: SMS Retriever is a Play services")
    print("  component with no public source. The empirical check is to send a")
    print("  message in the format above to a device running the app with the")
    print("  retriever started, and observe whether it arrives. If it does not,")
    print("  the two things to check first are the signing key (debug builds")
    print("  differ from release) and the 140-byte limit.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
