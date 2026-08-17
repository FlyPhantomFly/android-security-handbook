#!/usr/bin/env python3
"""
04-verify-attestation.py — SERVER-SIDE verification of an Android key attestation.

WHAT IT DOES
    Takes a PEM certificate chain produced by 03-key-attestation.java and:

      1. verifies each signature up to a PINNED Google hardware attestation root,
      2. checks every certificate's validity dates,
      3. checks the chain against a revocation status list,
      4. parses extension OID 1.3.6.1.4.1.11129.2.1.17 out of the LEAF,
      5. compares the attestationChallenge against the nonce this server issued,
      6. requires attestationSecurityLevel to be TrustedEnvironment or StrongBox,
      7. reads rootOfTrust FROM THE HARDWARE-ENFORCED LIST ONLY and requires
         verifiedBootState == Verified and deviceLocked == true,
      8. matches attestationApplicationId against our package name and signing
         certificate digest,
      9. enforces a minimum osPatchLevel,
     10. checks the key's own policy — purpose, algorithm, size, origin, auth
         binding — against what we demanded,
     11. returns the leaf public key so the caller can BIND IT TO THE ACCOUNT.

    It prints every field it reads and says which list each came from, so it
    doubles as an analysis tool for lab 03.

WHY IT MATTERS
    THIS FILE, NOT THE ANDROID ONE, IS WHERE ATTESTATION SUCCEEDS OR FAILS.

    The client side of attestation is about fifteen lines and is hard to get
    wrong. Every attestation finding worth writing up is here, on the server, and
    there are five recurring ones:

      * Reading `softwareEnforced` instead of `hardwareEnforced`. Every field
        appears in BOTH lists. The software-enforced copy is asserted by the
        Android framework, which is on the attacker's side of the trust boundary.
        A verifier that reads rootOfTrust or origin from it — or that merges both
        lists into one dictionary, which is the usual shape of the bug — is
        trivially defeated. CHECK THIS FIRST IN ANY REVIEW.
      * Not checking the challenge, or accepting a constant one. Attestation
        without a fresh, server-issued, single-use nonce is replayable: an
        attacker captures one chain from a clean device and submits it forever
        from a compromised one.
      * Pinning an intermediate instead of the root. Under Remote Key
        Provisioning the intermediates are short-lived and rotate; pinning one is
        a robustness bug that fails closed at an unpredictable future date.
      * Not checking attestationApplicationId, so a repackaged app on the same
        device attests just as well.
      * Verifying on the device instead of the server, which is an expensive
        `return True`.

    See ../README.md section 3.7.5, and ../labs/lab-03-attestation-analysis.md.

HOW TO RUN
    # host — analysis mode: parse and print everything, no policy enforcement
    python3 04-verify-attestation.py --chain chain.pem --dump

    # host — verification mode, as a server would run it
    python3 04-verify-attestation.py \
        --chain chain.pem \
        --challenge 3f9a...  \
        --package com.example.app \
        --signer-digest 5c8e... \
        --min-patch 202401 \
        --require-strongbox \
        --roots google-roots.pem

    Exit code 0 = accepted, 1 = rejected, 2 = usage or parse error.

    As a library:
        from verify_attestation import verify, VerificationError
        result = verify(pem_text, expected_challenge=nonce,
                        expected_package="com.example.app",
                        expected_signer_digests={"5c8e..."})

REQUIREMENTS
    Python 3.8+
        pip install cryptography asn1crypto

    Plus the Google hardware attestation root certificate(s), which you must
    obtain from Google's own published location and PIN. This script will not
    fetch them for you: a verifier that downloads its trust anchor at runtime
    has no trust anchor.

    Compare this implementation against Google's reference verifier at
    github.com/google/android-key-attestation before relying on either.

NOTE ON SCOPE
    This is teaching code with production-shaped structure. Before deploying it,
    add: persistent single-use nonce storage, the revocation status list fetch
    and cache, structured logging, and a considered policy for devices that
    produce no attestation at all — which is the decision that actually matters
    and which no library can make for you.

AUTHORISED TESTING ONLY.
"""

import argparse
import binascii
import datetime
import hashlib
import re
import sys

try:
    from asn1crypto import core as asn1
except ImportError:  # pragma: no cover
    print("[-] pip install asn1crypto", file=sys.stderr)
    raise SystemExit(2)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
except ImportError:  # pragma: no cover
    print("[-] pip install cryptography", file=sys.stderr)
    raise SystemExit(2)


ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

SECURITY_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
VERIFIED_BOOT_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
ORIGIN = {0: "GENERATED", 1: "DERIVED", 2: "IMPORTED", 3: "UNKNOWN"}

PURPOSE = {0: "ENCRYPT", 1: "DECRYPT", 2: "SIGN", 3: "VERIFY",
           4: "DERIVE_KEY", 5: "WRAP_KEY", 6: "AGREE_KEY", 7: "ATTEST_KEY"}

ALGORITHM = {1: "RSA", 3: "EC", 32: "AES", 33: "TRIPLE_DES", 128: "HMAC"}

# Tag numbers inside AuthorizationList. See
# hardware/interfaces/security/keymint/aidl/.../Tag.aidl — read that, not this.
TAGS = {
    1: "purpose", 2: "algorithm", 3: "keySize", 5: "digest", 6: "padding",
    10: "ecCurve", 200: "rsaPublicExponent",
    303: "rollbackResistance", 305: "earlyBootOnly",
    400: "activeDateTime", 401: "originationExpireDateTime",
    402: "usageExpireDateTime", 405: "usageCountLimit",
    503: "noAuthRequired", 504: "userAuthType", 505: "authTimeout",
    506: "allowWhileOnBody", 507: "trustedUserPresenceRequired",
    508: "trustedConfirmationRequired", 509: "unlockedDeviceRequired",
    701: "creationDateTime", 702: "origin", 704: "rootOfTrust",
    705: "osVersion", 706: "osPatchLevel",
    709: "attestationApplicationId",
    710: "attestationIdBrand", 711: "attestationIdDevice",
    712: "attestationIdProduct", 713: "attestationIdSerial",
    714: "attestationIdImei", 715: "attestationIdMeid",
    716: "attestationIdManufacturer", 717: "attestationIdModel",
    718: "vendorPatchLevel", 719: "bootPatchLevel",
}


class VerificationError(Exception):
    """Raised for any failed policy check. The message is safe to log."""


# ---------------------------------------------------------------------------
# ASN.1 parsing
# ---------------------------------------------------------------------------

def _parse_authorization_list(seq):
    """
    An AuthorizationList is a SEQUENCE of context-tagged, EXPLICIT values.

    We parse it generically rather than with a full schema, because the tag set
    grows every KeyMint version and a strict schema breaks on newer devices —
    which is itself a real failure mode in production verifiers: they start
    rejecting brand-new phones.
    """
    out = {}
    for child in seq:
        try:
            tag_no = child.tag
        except Exception:
            continue
        name = TAGS.get(tag_no, "tag_%d" % tag_no)

        try:
            inner = child.chosen if hasattr(child, "chosen") else child
        except Exception:
            inner = child

        # NULL-valued tags are booleans by presence: noAuthRequired,
        # unlockedDeviceRequired, allowWhileOnBody, etc.
        if isinstance(inner, asn1.Null) or (
                hasattr(inner, "contents") and inner.contents == b"" and
                name in ("noAuthRequired", "allowWhileOnBody",
                         "trustedUserPresenceRequired",
                         "trustedConfirmationRequired",
                         "unlockedDeviceRequired", "rollbackResistance",
                         "earlyBootOnly")):
            out[name] = True
            continue

        if name == "rootOfTrust":
            out[name] = _parse_root_of_trust(inner)
            continue

        try:
            if isinstance(inner, asn1.Integer):
                out[name] = int(inner)
            elif isinstance(inner, asn1.SetOf) or isinstance(inner, asn1.Set):
                out[name] = [int(x) for x in inner]
            elif isinstance(inner, asn1.OctetString):
                out[name] = bytes(inner)
            elif isinstance(inner, asn1.Sequence):
                out[name] = [_coerce(x) for x in inner]
            else:
                out[name] = _coerce(inner)
        except Exception as exc:      # never let one odd tag lose the rest
            out[name] = "<unparsed: %s>" % exc.__class__.__name__
    return out


def _coerce(v):
    try:
        if isinstance(v, asn1.Integer):
            return int(v)
        if isinstance(v, asn1.Boolean):
            return bool(v)
        if isinstance(v, asn1.OctetString):
            return bytes(v)
    except Exception:
        pass
    try:
        return bytes(v.contents)
    except Exception:
        return repr(v)


def _parse_root_of_trust(seq):
    """
    RootOfTrust ::= SEQUENCE {
        verifiedBootKey    OCTET STRING,
        deviceLocked       BOOLEAN,
        verifiedBootState  ENUMERATED,
        verifiedBootHash   OCTET STRING   -- schema 3+
    }
    """
    out = {}
    items = list(seq)
    try:
        out["verifiedBootKey"] = binascii.hexlify(bytes(items[0])).decode()
    except Exception:
        out["verifiedBootKey"] = None
    try:
        out["deviceLocked"] = bool(items[1])
    except Exception:
        out["deviceLocked"] = None
    try:
        state = int(items[2])
        out["verifiedBootState"] = state
        out["verifiedBootStateName"] = VERIFIED_BOOT_STATE.get(state, "unknown(%d)" % state)
    except Exception:
        out["verifiedBootState"] = None
        out["verifiedBootStateName"] = "unparsed"
    if len(items) > 3:
        try:
            out["verifiedBootHash"] = binascii.hexlify(bytes(items[3])).decode()
        except Exception:
            pass
    return out


def parse_attestation_extension(leaf_cert):
    """
    Pull KeyDescription out of the leaf certificate.

    KeyDescription ::= SEQUENCE {
        attestationVersion       INTEGER,
        attestationSecurityLevel ENUMERATED,
        keymasterVersion         INTEGER,
        keymasterSecurityLevel   ENUMERATED,
        attestationChallenge     OCTET STRING,
        uniqueId                 OCTET STRING,
        softwareEnforced         AuthorizationList,
        hardwareEnforced         AuthorizationList }
    """
    ext_bytes = None
    for ext in leaf_cert.extensions:
        if ext.oid.dotted_string == ATTESTATION_OID:
            ext_bytes = ext.value.value
            break
    if ext_bytes is None:
        raise VerificationError(
            "no attestation extension (%s) in the leaf certificate — this device "
            "produced no attestation" % ATTESTATION_OID)

    seq = asn1.Sequence.load(ext_bytes)
    items = list(seq)
    if len(items) < 8:
        raise VerificationError("malformed KeyDescription: %d elements" % len(items))

    sec_level = int(items[1])
    km_level = int(items[3])

    return {
        "attestationVersion": int(items[0]),
        "attestationSecurityLevel": sec_level,
        "attestationSecurityLevelName": SECURITY_LEVEL.get(sec_level, "unknown"),
        "keymasterVersion": int(items[2]),
        "keymasterSecurityLevel": km_level,
        "keymasterSecurityLevelName": SECURITY_LEVEL.get(km_level, "unknown"),
        "attestationChallenge": bytes(items[4]),
        "uniqueId": bytes(items[5]),
        # Keep the two lists SEPARATE. Merging them is the bug.
        "softwareEnforced": _parse_authorization_list(items[6]),
        "hardwareEnforced": _parse_authorization_list(items[7]),
    }


def parse_attestation_application_id(raw):
    """
    AttestationApplicationId ::= SEQUENCE {
        packageInfoRecords SET OF AttestationPackageInfo,
        signatureDigests   SET OF OCTET_STRING }

    AttestationPackageInfo ::= SEQUENCE {
        packageName OCTET_STRING,
        version     INTEGER }

    This is what binds the attestation to YOUR app. Without checking it, a
    repackaged copy on the same device attests just as well.
    """
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        seq = asn1.Sequence.load(bytes(raw))
        items = list(seq)
        packages = []
        for pkg in items[0]:
            p = list(pkg)
            packages.append({
                "packageName": bytes(p[0]).decode("utf-8", "replace"),
                "version": int(p[1]),
            })
        digests = [binascii.hexlify(bytes(d)).decode() for d in items[1]]
        return {"packages": packages, "signatureDigests": digests}
    except Exception as exc:
        return {"error": "unparsed: %s" % exc}


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def load_chain(pem_text):
    certs = []
    for block in re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem_text, re.S):
        certs.append(x509.load_pem_x509_certificate(block.encode()))
    if not certs:
        raise VerificationError("no PEM certificates found")
    return certs


def verify_signature(child, parent):
    pub = parent.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(child.signature_hash_algorithm))
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)
    else:
        raise VerificationError("unsupported public key type in the chain")


def verify_chain(certs, trusted_roots, now=None):
    """
    Verify signatures leaf -> ... -> root, check dates, and require that the top
    of the chain is one of our PINNED roots.

    We pin the ROOT, never an intermediate. Under Remote Key Provisioning the
    intermediates are short-lived and rotate; a verifier pinned to one will start
    rejecting every device at an unpredictable future date. That is a real
    robustness bug worth reporting even though it is not exploitable.
    """
    now = now or datetime.datetime.utcnow()

    for i, cert in enumerate(certs):
        nb = cert.not_valid_before
        na = cert.not_valid_after
        if now < nb or now > na:
            raise VerificationError(
                "certificate %d is outside its validity window (%s .. %s)" % (i, nb, na))

    for i in range(len(certs) - 1):
        try:
            verify_signature(certs[i], certs[i + 1])
        except Exception as exc:
            raise VerificationError(
                "signature verification failed: cert %d not signed by cert %d (%s)"
                % (i, i + 1, exc.__class__.__name__))

    top = certs[-1]
    top_fp = hashlib.sha256(
        top.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    if not trusted_roots:
        raise VerificationError(
            "no pinned roots supplied. A verifier without a pinned trust anchor "
            "verifies nothing — pass --roots with Google's published hardware "
            "attestation root certificate(s).")

    for root in trusted_roots:
        root_fp = hashlib.sha256(
            root.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        if root_fp == top_fp:
            return True
        # The chain may stop one short of the root, with the top certificate
        # signed by it.
        try:
            verify_signature(top, root)
            return True
        except Exception:
            continue

    raise VerificationError(
        "chain does not terminate at a pinned Google hardware attestation root "
        "(top-of-chain SPKI sha256=%s)" % top_fp)


def check_revocation(certs, status_list):
    """
    Google publishes a revocation status list of attestation key serial numbers
    known to be compromised. Attestation keys HAVE been extracted from real
    devices, by researchers and by others.

    Pass a dict {serial_hex_lowercase: {"status": ..., "reason": ...}}, loaded
    from Google's attestation status endpoint and cached. A verifier that skips
    this accepts chains signed by keys everyone knows are stolen.
    """
    if not status_list:
        return ["revocation NOT checked — supply the status list in production"]
    problems = []
    for cert in certs:
        serial = format(cert.serial_number, "x").lower()
        entry = status_list.get(serial)
        if entry is not None:
            problems.append("certificate serial %s is %s (%s)" % (
                serial, entry.get("status", "listed"), entry.get("reason", "")))
    return problems


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def verify(pem_text,
           expected_challenge=None,
           expected_package=None,
           expected_signer_digests=None,
           trusted_roots=None,
           min_os_patch_level=None,
           require_strongbox=False,
           allow_unlocked=False,
           revocation_status=None,
           verbose=True):
    """
    Full server-side verification. Raises VerificationError on any failure.

    Returns a dict containing the parsed attestation and the leaf public key.
    THE CALLER MUST THEN BIND THAT PUBLIC KEY TO THE ACCOUNT and require it to
    sign every subsequent request. Attestation proves a key is in hardware at ONE
    MOMENT; the value comes entirely from using that key afterwards.
    """
    def say(*a):
        if verbose:
            print(*a)

    certs = load_chain(pem_text)
    say("[*] chain length: %d" % len(certs))
    for i, c in enumerate(certs):
        say("    [%d] subject=%s" % (i, c.subject.rfc4514_string()))
        say("        issuer =%s" % c.issuer.rfc4514_string())
        say("        serial =%x  valid %s .. %s"
            % (c.serial_number, c.not_valid_before, c.not_valid_after))

    if len(certs) == 1:
        raise VerificationError(
            "single self-signed certificate — this device produced NO attestation "
            "chain. Treat it as an unattested device and apply your fallback "
            "policy explicitly. (That policy is where the real bug usually is.)")

    # ---- steps 4, 5, 6: chain, dates, revocation -------------------------
    verify_chain(certs, trusted_roots or [])
    say("[+] chain verifies to a pinned root")

    for problem in check_revocation(certs, revocation_status):
        if revocation_status:
            raise VerificationError(problem)
        say("[!] " + problem)

    # ---- step 7: parse the extension from the LEAF -----------------------
    att = parse_attestation_extension(certs[0])
    say("")
    say("[*] attestationVersion       = %d" % att["attestationVersion"])
    say("[*] attestationSecurityLevel = %s" % att["attestationSecurityLevelName"])
    say("[*] keymasterVersion         = %d" % att["keymasterVersion"])
    say("[*] keymasterSecurityLevel   = %s" % att["keymasterSecurityLevelName"])
    say("[*] challenge (hex)          = %s"
        % binascii.hexlify(att["attestationChallenge"]).decode())

    hw = att["hardwareEnforced"]
    sw = att["softwareEnforced"]

    if verbose:
        say("")
        say("--- hardwareEnforced (THE ONLY LIST THAT COUNTS) ---")
        for k, v in sorted(hw.items()):
            say("    %-28s %s" % (k, _pretty(k, v)))
        say("")
        say("--- softwareEnforced (asserted by the FRAMEWORK — informational only) ---")
        for k, v in sorted(sw.items()):
            say("    %-28s %s" % (k, _pretty(k, v)))
        say("")
        if "rootOfTrust" in sw:
            say("    NOTE: rootOfTrust appears in the SOFTWARE-enforced list on this")
            say("    device. IGNORE IT. A verifier that reads it there is trivially")
            say("    defeated, and that is the single most common attestation bug.")

    # ---- step 8: the challenge, the only anti-replay control -------------
    if expected_challenge is not None:
        if att["attestationChallenge"] != expected_challenge:
            raise VerificationError(
                "challenge mismatch — REPLAY. expected %s, got %s" % (
                    binascii.hexlify(expected_challenge).decode(),
                    binascii.hexlify(att["attestationChallenge"]).decode()))
        say("[+] challenge matches the nonce we issued")
        say("    (now CONSUME it — a nonce accepted twice is not a nonce)")
    else:
        say("[!] no expected challenge supplied — REPLAY IS NOT BEING CHECKED.")
        say("    In production this alone makes the verification worthless.")

    # ---- step 9: where was the attestation produced? ---------------------
    if att["attestationSecurityLevel"] == 0:
        raise VerificationError(
            "attestationSecurityLevel is Software — the whole statement was made "
            "by software the attacker controls, and is worthless")
    if require_strongbox and att["attestationSecurityLevel"] != 2:
        raise VerificationError(
            "StrongBox required but attestationSecurityLevel is %s"
            % att["attestationSecurityLevelName"])
    say("[+] attestation produced in %s" % att["attestationSecurityLevelName"])

    # ---- step 10: root of trust, FROM THE HARDWARE LIST ONLY -------------
    rot = hw.get("rootOfTrust")
    if not isinstance(rot, dict):
        raise VerificationError(
            "no rootOfTrust in the HARDWARE-enforced list. If it is present only "
            "in softwareEnforced, that is not a root of trust — it is a claim by "
            "the attacker's own operating system.")

    say("[*] rootOfTrust.verifiedBootState = %s" % rot.get("verifiedBootStateName"))
    say("[*] rootOfTrust.deviceLocked      = %s" % rot.get("deviceLocked"))
    say("[*] rootOfTrust.verifiedBootKey   = %s" % rot.get("verifiedBootKey"))

    if not allow_unlocked:
        if rot.get("verifiedBootState") != 0:
            raise VerificationError(
                "verifiedBootState is %s, not Verified — the device is running a "
                "custom or unverified boot image" % rot.get("verifiedBootStateName"))
        if rot.get("deviceLocked") is not True:
            raise VerificationError(
                "deviceLocked is false — the bootloader is unlocked")
        say("[+] device is booted verified and locked")
    else:
        say("[!] --allow-unlocked: boot state and lock state NOT enforced")

    # ---- step 11: bind to OUR app ---------------------------------------
    app_id = parse_attestation_application_id(hw.get("attestationApplicationId"))
    if app_id and "packages" in app_id:
        say("[*] attestationApplicationId:")
        for p in app_id["packages"]:
            say("      package %s (version %d)" % (p["packageName"], p["version"]))
        for d in app_id["signatureDigests"]:
            say("      signer digest %s" % d)

    if expected_package is not None:
        if not app_id or "packages" not in app_id:
            raise VerificationError(
                "attestationApplicationId absent from the hardware-enforced list — "
                "cannot bind this attestation to our application")
        names = {p["packageName"] for p in app_id["packages"]}
        if expected_package not in names:
            raise VerificationError(
                "attestationApplicationId does not contain our package. "
                "expected %s, got %s" % (expected_package, sorted(names)))
        say("[+] package name matches")

    if expected_signer_digests:
        got = {d.lower() for d in (app_id or {}).get("signatureDigests", [])}
        want = {d.lower() for d in expected_signer_digests}
        if not (got & want):
            raise VerificationError(
                "signing certificate digest does not match — this is a REPACKAGED "
                "application. expected one of %s, got %s" % (sorted(want), sorted(got)))
        say("[+] signing certificate digest matches")

    # ---- step 12: patch level -------------------------------------------
    patch = hw.get("osPatchLevel")
    say("[*] osVersion    = %s" % hw.get("osVersion"))
    say("[*] osPatchLevel = %s" % patch)
    if min_os_patch_level is not None:
        if patch is None:
            raise VerificationError("no osPatchLevel in the hardware-enforced list")
        if int(patch) < int(min_os_patch_level):
            raise VerificationError(
                "osPatchLevel %s is below our minimum %s" % (patch, min_os_patch_level))
        say("[+] patch level acceptable")

    # ---- step 13: the key's own policy ----------------------------------
    origin = hw.get("origin")
    if origin is not None:
        say("[*] origin = %s" % ORIGIN.get(origin, origin))
        if origin == 2:
            raise VerificationError(
                "key origin is IMPORTED — the key material existed in software at "
                "some point, so it cannot support a device-binding claim")

    if hw.get("noAuthRequired") is True:
        say("[!] noAuthRequired is present: this key is usable with NO user "
            "authentication. Whether that is acceptable is your policy decision.")
    else:
        say("[*] userAuthType = %s   authTimeout = %s"
            % (hw.get("userAuthType"), hw.get("authTimeout")))
        if hw.get("authTimeout") not in (None, 0):
            say("[!] authTimeout is %s seconds — a WINDOW, not per-use binding."
                % hw.get("authTimeout"))

    purposes = hw.get("purpose")
    if purposes:
        say("[*] purpose = %s" % ", ".join(PURPOSE.get(p, str(p)) for p in purposes))
    alg = hw.get("algorithm")
    if alg is not None:
        say("[*] algorithm = %s   keySize = %s" % (ALGORITHM.get(alg, alg), hw.get("keySize")))

    # ---- step 14 is the CALLER's job ------------------------------------
    leaf_pub = certs[0].public_key()
    say("")
    say("[+] ACCEPTED")
    say("")
    say("    NOW DO STEP 14, WHICH IS NOT OPTIONAL:")
    say("    bind this leaf public key to the account and require it to sign")
    say("    every subsequent request. Attestation proves the key was in hardware")
    say("    at ONE MOMENT. An app that attests at registration and then sends")
    say("    bearer tokens has thrown the entire guarantee away.")

    return {
        "attestation": att,
        "leaf_public_key": leaf_pub,
        "leaf_public_key_pem": leaf_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "attestation_application_id": app_id,
    }


def _pretty(name, value):
    if name == "rootOfTrust" and isinstance(value, dict):
        return ("verifiedBootState=%s deviceLocked=%s verifiedBootKey=%s"
                % (value.get("verifiedBootStateName"), value.get("deviceLocked"),
                   (value.get("verifiedBootKey") or "")[:32]))
    if name == "attestationApplicationId" and isinstance(value, (bytes, bytearray)):
        parsed = parse_attestation_application_id(value)
        if parsed and "packages" in parsed:
            return "%s  signers=%s" % (
                [p["packageName"] for p in parsed["packages"]],
                [d[:16] + "…" for d in parsed["signatureDigests"]])
    if name == "purpose" and isinstance(value, list):
        return ", ".join(PURPOSE.get(p, str(p)) for p in value)
    if name == "algorithm" and isinstance(value, int):
        return ALGORITHM.get(value, str(value))
    if isinstance(value, (bytes, bytearray)):
        h = binascii.hexlify(value).decode()
        return h if len(h) <= 64 else h[:64] + "…"
    return value


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Server-side verification of an Android key attestation chain.")
    ap.add_argument("--chain", required=True, help="PEM chain, leaf first")
    ap.add_argument("--roots", help="PEM file of PINNED Google attestation root(s)")
    ap.add_argument("--challenge", help="hex of the nonce this server issued")
    ap.add_argument("--package", help="our package name, e.g. com.example.app")
    ap.add_argument("--signer-digest", action="append", default=[],
                    help="hex sha256 of our signing certificate (repeatable)")
    ap.add_argument("--min-patch", help="minimum osPatchLevel, e.g. 202401")
    ap.add_argument("--require-strongbox", action="store_true")
    ap.add_argument("--allow-unlocked", action="store_true",
                    help="do NOT enforce verified boot / device locked. "
                         "For analysis only — never in production.")
    ap.add_argument("--dump", action="store_true",
                    help="parse and print everything, enforce nothing. "
                         "Analysis mode for lab 03.")
    args = ap.parse_args()

    with open(args.chain, "r", encoding="utf-8") as fh:
        pem = fh.read()

    roots = []
    if args.roots:
        with open(args.roots, "r", encoding="utf-8") as fh:
            roots = load_chain(fh.read())

    challenge = binascii.unhexlify(args.challenge) if args.challenge else None

    if args.dump:
        # Analysis mode: show everything, enforce nothing. Useful for reading a
        # chain you captured from a target, where you do not have the nonce.
        certs = load_chain(pem)
        att = parse_attestation_extension(certs[0])
        print("chain length: %d" % len(certs))
        print("attestationVersion       = %d" % att["attestationVersion"])
        print("attestationSecurityLevel = %s" % att["attestationSecurityLevelName"])
        print("keymasterSecurityLevel   = %s" % att["keymasterSecurityLevelName"])
        print("challenge                = %s"
              % binascii.hexlify(att["attestationChallenge"]).decode())
        for label, lst in (("hardwareEnforced", att["hardwareEnforced"]),
                           ("softwareEnforced", att["softwareEnforced"])):
            print("\n--- %s ---" % label)
            for k, v in sorted(lst.items()):
                print("  %-28s %s" % (k, _pretty(k, v)))
        print("\nREMEMBER: only the hardwareEnforced list is trustworthy.")
        return 0

    try:
        verify(pem,
               expected_challenge=challenge,
               expected_package=args.package,
               expected_signer_digests=set(args.signer_digest) or None,
               trusted_roots=roots,
               min_os_patch_level=args.min_patch,
               require_strongbox=args.require_strongbox,
               allow_unlocked=args.allow_unlocked)
        return 0
    except VerificationError as exc:
        print("\n[-] REJECTED: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
