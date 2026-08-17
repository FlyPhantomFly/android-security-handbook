#!/usr/bin/env python3
# parse-attestation.py — read an Android key attestation chain OFFLINE, with no network at all.
#
# PURPOSE
#   Takes a PEM or DER key attestation certificate chain and tells you, without contacting Google
#   or anybody else:
#
#     * the security level of the attestation itself   (Software / TrustedEnvironment / StrongBox)
#     * the security level of the attested KEY          (they can differ, and the difference matters)
#     * the RootOfTrust: verified boot state, bootloader lock state, verified boot key hash
#     * which authorisations are HARDWARE-enforced and which are merely SOFTWARE-enforced
#     * the attestationApplicationId — the packages and signing-cert digests that may use the key
#     * whether each certificate is actually signed by the next one up (ECDSA and RSA, in pure
#       Python, no third-party modules)
#     * the SHA-256 of the root certificate's public key, so you can compare it yourself against
#       Google's published hardware attestation root
#
#   The point of doing this offline is that key attestation is a *self-contained* cryptographic
#   claim. Everything except revocation can be checked with the chain in your hand. Tools that
#   require an online service teach the opposite lesson and hide the mechanism.
#
# HOW THIS DIFFERS FROM 49-KeyStore/examples/04-verify-attestation.py
#   That file is a SERVER-SIDE POLICY VERIFIER: it pins the Google root, checks revocation, and
#   returns accept/reject for a production backend. This file is an ANALYST'S PARSER: it pins
#   nothing, decides nothing, has no dependencies and no network, and prints what the chain says
#   including the parts a verifier would reject. Use 49's when you are building the backend; use
#   this one when you are holding a chain and want to know what is in it.
#
# USAGE
#   python3 -B parse-attestation.py chain.pem                 # PEM, concatenated leaf-first
#   python3 -B parse-attestation.py leaf.der ca1.der root.der # one DER file per certificate
#   python3 -B parse-attestation.py chain.pem --expect-challenge <hex>
#   python3 -B parse-attestation.py chain.pem --json          # machine-readable
#
#   Produce a chain to feed it with:
#     ./probe-security-levels.sh --attest | sed -n '/BEGIN CHAIN/,/END CHAIN/p' > chain.pem
#
# REQUIREMENTS
#   Python 3.7+. Standard library only — no cryptography, no pyasn1, no openssl. Use `python3 -B`
#   so no __pycache__ is written next to the script.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - It will NOT check revocation. Attestation keys do get revoked, and the revocation list is
#     published by Google and served over the network. An offline verdict is therefore always
#     "valid unless revoked". Fetch the status list separately for a production verifier.
#   - It will NOT decide, by itself, that the chain is trustworthy. It prints the root's public-key
#     fingerprint; comparing that against the Google hardware attestation root you obtained through
#     a trusted channel is YOUR step and cannot be delegated to this script. A chain that verifies
#     internally but ends at an attacker's own root verifies perfectly and proves nothing.
#   - It will NOT tell you the app holding the key is honest. A valid chain says a key lives in
#     secure hardware. It says nothing about the code calling that key one second later. See
#     ../../49-KeyStore/README.md section 1.3 for the extraction-versus-use distinction.
#   - It will NOT validate certificate dates against a trusted clock, only against your host clock.
#   - It does not implement every historic attestation schema quirk. Unknown tags are printed with
#     their raw number rather than silently dropped, so you can see what it did not understand.
#
# SAFETY
#   Reads only. Writes nothing. Certificates are public data; this script never sees, asks for or
#   emits private key material.

import sys
import json
import hashlib
import base64
import datetime

ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

# --------------------------------------------------------------------------- DER


class DerError(Exception):
    pass


class Node:
    """One parsed DER TLV. `content` is the raw value bytes; `children` is lazily filled."""

    __slots__ = ("cls", "constructed", "tag", "content", "raw", "children")

    def __init__(self, cls, constructed, tag, content, raw):
        self.cls = cls                  # 0 universal, 1 application, 2 context, 3 private
        self.constructed = constructed
        self.tag = tag
        self.content = content
        self.raw = raw                  # full TLV, needed for signature verification
        self.children = None

    def kids(self):
        if self.children is None:
            self.children = parse_all(self.content) if self.constructed else []
        return self.children

    def __repr__(self):
        return "Node(cls=%d,tag=%d,len=%d)" % (self.cls, self.tag, len(self.content))


def parse_one(buf, off):
    if off >= len(buf):
        raise DerError("truncated at %d" % off)
    start = off
    b0 = buf[off]
    off += 1
    cls = (b0 & 0xC0) >> 6
    constructed = bool(b0 & 0x20)
    tag = b0 & 0x1F
    if tag == 0x1F:                      # high-tag-number form
        tag = 0
        while True:
            if off >= len(buf):
                raise DerError("truncated tag")
            b = buf[off]
            off += 1
            tag = (tag << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    if off >= len(buf):
        raise DerError("truncated length")
    l0 = buf[off]
    off += 1
    if l0 & 0x80:
        n = l0 & 0x7F
        if n == 0:
            raise DerError("indefinite length not allowed in DER")
        length = int.from_bytes(buf[off:off + n], "big")
        off += n
    else:
        length = l0
    content = buf[off:off + length]
    if len(content) != length:
        raise DerError("truncated content: want %d got %d" % (length, len(content)))
    off += length
    return Node(cls, constructed, tag, content, buf[start:off]), off


def parse_all(buf):
    out, off = [], 0
    while off < len(buf):
        node, off = parse_one(buf, off)
        out.append(node)
    return out


def der_int(node):
    return int.from_bytes(node.content, "big", signed=True) if node.content else 0


def der_uint(node):
    return int.from_bytes(node.content, "big")


def der_oid(node):
    b = node.content
    if not b:
        return ""
    first = b[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def der_time(node):
    s = node.content.decode("ascii", "replace")
    try:
        if node.tag == 23:               # UTCTime YYMMDDHHMMSSZ
            yy = int(s[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return datetime.datetime(year, int(s[2:4]), int(s[4:6]),
                                     int(s[6:8]), int(s[8:10]), int(s[10:12]))
        return datetime.datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]),
                                 int(s[8:10]), int(s[10:12]), int(s[12:14]))
    except Exception:
        return s


OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.12": "title", "2.5.4.13": "description",
}

SIG_ALG_NAMES = {
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.113549.1.1.5": ("rsa", "sha1"),
}


def rdn_to_str(node):
    out = []
    for rdn in node.kids():
        for atv in rdn.kids():
            kids = atv.kids()
            if len(kids) >= 2:
                oid = der_oid(kids[0])
                val = kids[1].content.decode("utf-8", "replace")
                out.append("%s=%s" % (OID_NAMES.get(oid, oid), val))
    return ", ".join(out)


# --------------------------------------------------------------------------- X.509


class Cert:
    def __init__(self, der):
        self.der = der
        top = parse_all(der)[0]
        tbs, sigalg, sigval = top.kids()[0], top.kids()[1], top.kids()[2]
        self.tbs_raw = tbs.raw
        self.sig_alg_oid = der_oid(sigalg.kids()[0])
        # BIT STRING: first content byte is the count of unused bits
        self.sig_value = sigval.content[1:]

        k = tbs.kids()
        i = 0
        if k[0].cls == 2 and k[0].tag == 0:     # [0] EXPLICIT version
            self.version = der_int(k[0].kids()[0]) + 1
            i = 1
        else:
            self.version = 1
        self.serial = der_uint(k[i]); i += 1
        i += 1                                   # signature algorithm (repeat)
        self.issuer = rdn_to_str(k[i]); i += 1
        validity = k[i]; i += 1
        vk = validity.kids()
        self.not_before, self.not_after = der_time(vk[0]), der_time(vk[1])
        self.subject = rdn_to_str(k[i]); i += 1
        self.spki_node = k[i]; i += 1
        self.spki_der = self.spki_node.raw

        self.extensions = {}
        while i < len(k):
            node = k[i]; i += 1
            if node.cls == 2 and node.tag == 3:  # [3] EXPLICIT extensions
                for ext in node.kids()[0].kids():
                    ek = ext.kids()
                    oid = der_oid(ek[0])
                    critical = len(ek) == 3 and ek[1].content == b"\xff"
                    value = ek[-1].content
                    self.extensions[oid] = (critical, value)

    # -- public key ---------------------------------------------------------

    def key_info(self):
        alg_oid = der_oid(self.spki_node.kids()[0].kids()[0])
        bits = self.spki_node.kids()[1].content[1:]
        if alg_oid == "1.2.840.10045.2.1":       # id-ecPublicKey
            curve = der_oid(self.spki_node.kids()[0].kids()[1])
            return ("ec", curve, bits)
        if alg_oid == "1.2.840.113549.1.1.1":    # rsaEncryption
            seq = parse_all(bits)[0].kids()
            return ("rsa", der_uint(seq[0]), der_uint(seq[1]))
        return ("unknown:" + alg_oid, None, bits)

    def spki_sha256(self):
        return hashlib.sha256(self.spki_der).hexdigest()


# --------------------------------------------------------------------------- signature verification
#
# Implemented here rather than shelling out to openssl so that the whole verification is visible
# and has no dependency. This is textbook ECDSA over the NIST prime curves and textbook PKCS#1
# v1.5 RSA verification.

CURVES = {
    # name: (p, a, b, Gx, Gy, n)
    "1.2.840.10045.3.1.7": (  # P-256 / prime256v1 / secp256r1
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        -3,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    "1.3.132.0.34": (         # P-384 / secp384r1
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        -3,
        0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
        0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973),
}


def _inv(a, m):
    return pow(a, -1, m)


def _pt_add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + a) * _inv(2 * P[1], p) % p
    else:
        lam = (Q[1] - P[1]) * _inv(Q[0] - P[0], p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def _pt_mul(k, P, p, a):
    R = None
    while k:
        if k & 1:
            R = _pt_add(R, P, p, a)
        P = _pt_add(P, P, p, a)
        k >>= 1
    return R


def ecdsa_verify(curve_oid, pubkey_bytes, digest, r, s):
    if curve_oid not in CURVES:
        return None, "unsupported curve " + curve_oid
    p, a, b, gx, gy, n = CURVES[curve_oid]
    a = a % p
    if pubkey_bytes[0] != 0x04:
        return None, "only uncompressed points supported"
    size = (len(pubkey_bytes) - 1) // 2
    Q = (int.from_bytes(pubkey_bytes[1:1 + size], "big"),
         int.from_bytes(pubkey_bytes[1 + size:], "big"))
    if not (0 < r < n and 0 < s < n):
        return False, "r or s out of range"
    e = int.from_bytes(digest, "big")
    if len(digest) * 8 > n.bit_length():
        e >>= (len(digest) * 8 - n.bit_length())
    w = _inv(s, n)
    P = _pt_add(_pt_mul(e * w % n, (gx, gy), p, a), _pt_mul(r * w % n, Q, p, a), p, a)
    if P is None:
        return False, "point at infinity"
    return (P[0] % n) == r, None


DIGEST_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    "sha1":   bytes.fromhex("3021300906052b0e03021a05000414"),
}


def rsa_verify(n, e, digest, hashname, sig):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False, "signature length %d != modulus length %d" % (len(sig), k)
    m = pow(int.from_bytes(sig, "big"), e, n)
    em = m.to_bytes(k, "big")
    expect = b"\x00\x01" + b"\xff" * (k - 3 - len(DIGEST_PREFIX[hashname]) - len(digest)) \
             + b"\x00" + DIGEST_PREFIX[hashname] + digest
    return em == expect, None


def verify_signed_by(child, parent):
    """Is `child` really signed by `parent`'s key? Returns (True/False/None, note)."""
    if child.sig_alg_oid not in SIG_ALG_NAMES:
        return None, "unsupported signature algorithm " + child.sig_alg_oid
    kind, hashname = SIG_ALG_NAMES[child.sig_alg_oid]
    digest = hashlib.new(hashname, child.tbs_raw).digest()
    ktype, p1, p2 = parent.key_info()
    if kind == "ecdsa" and ktype == "ec":
        seq = parse_all(child.sig_value)[0].kids()
        return ecdsa_verify(p1, p2, digest, der_uint(seq[0]), der_uint(seq[1]))
    if kind == "rsa" and ktype == "rsa":
        return rsa_verify(p1, p2, digest, hashname, child.sig_value)
    return None, "signature algorithm %s does not match parent key type %s" % (kind, ktype)


# --------------------------------------------------------------------------- attestation extension

SECURITY_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
BOOT_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
ORIGIN = {0: "GENERATED", 1: "DERIVED", 2: "IMPORTED", 3: "UNKNOWN", 4: "SECURELY_IMPORTED"}
ALGORITHM = {1: "RSA", 3: "EC", 32: "AES", 33: "TRIPLE_DES", 128: "HMAC"}
DIGEST = {0: "NONE", 1: "MD5", 2: "SHA1", 3: "SHA-224", 4: "SHA-256", 5: "SHA-384", 6: "SHA-512"}
PADDING = {1: "NONE", 2: "RSA_OAEP", 3: "RSA_PSS", 4: "RSA_PKCS1_1_5_ENCRYPT",
           5: "RSA_PKCS1_1_5_SIGN", 64: "PKCS7"}
# NOTE: these are KeyMint KeyPurpose enum values, NOT the Java KeyProperties.PURPOSE_* bitmask.
# PURPOSE_ENCRYPT is 1 in Java and 0 here. Confusing the two is a classic verifier bug.
PURPOSE = {0: "ENCRYPT", 1: "DECRYPT", 2: "SIGN", 3: "VERIFY", 4: "DERIVE_KEY",
           5: "AGREE_KEY", 6: "ATTEST_KEY"}
EC_CURVE = {0: "P-224", 1: "P-256", 2: "P-384", 3: "P-521", 4: "CURVE_25519"}
AUTH_TYPE = {1: "PASSWORD", 2: "FINGERPRINT", 0xFFFFFFFF: "ANY"}

TAGS = {
    1: "purpose", 2: "algorithm", 3: "keySize", 5: "digest", 6: "padding",
    10: "ecCurve", 200: "rsaPublicExponent", 203: "mgfDigest",
    303: "rollbackResistance", 305: "earlyBootOnly",
    400: "activeDateTime", 401: "originationExpireDateTime", 402: "usageExpireDateTime",
    405: "usageCountLimit", 503: "noAuthRequired", 504: "userAuthType", 505: "authTimeout",
    506: "allowWhileOnBody", 507: "trustedUserPresenceRequired",
    508: "trustedConfirmationRequired", 509: "unlockedDeviceRequired",
    701: "creationDateTime", 702: "origin", 703: "rollbackResistant", 704: "rootOfTrust",
    705: "osVersion", 706: "osPatchLevel", 709: "attestationApplicationId",
    710: "attestationIdBrand", 711: "attestationIdDevice", 712: "attestationIdProduct",
    713: "attestationIdSerial", 714: "attestationIdImei", 715: "attestationIdMeid",
    716: "attestationIdManufacturer", 717: "attestationIdModel",
    718: "vendorPatchLevel", 719: "bootPatchLevel", 720: "deviceUniqueAttestation",
    723: "attestationIdSecondImei", 1004: "identityCredentialKey", 1006: "moduleHash",
}

# Tags whose presence alone is the statement (ASN.1 NULL); the value carries no information.
NULL_TAGS = {303, 305, 503, 506, 507, 508, 509, 720, 1004}
SET_OF_INT_TAGS = {1, 5, 6}


def decode_app_id(blob):
    """attestationApplicationId is a DER structure hidden inside an OCTET STRING."""
    try:
        seq = parse_all(blob)[0].kids()
        packages = []
        for pkg in seq[0].kids():
            pk = pkg.kids()
            packages.append({"package": pk[0].content.decode("utf-8", "replace"),
                             "version": der_uint(pk[1])})
        digests = [d.content.hex() for d in seq[1].kids()]
        return {"packages": packages, "signature_digests": digests}
    except Exception as exc:
        return {"raw": blob.hex(), "error": str(exc)}


def decode_auth_list(node):
    out = {}
    for child in node.kids():
        if child.cls != 2:
            continue
        tag = child.tag
        name = TAGS.get(tag, "tag_%d" % tag)
        inner = child.kids()
        if tag in NULL_TAGS:
            out[name] = True
            continue
        if not inner:
            out[name] = True
            continue
        v = inner[0]
        if tag in SET_OF_INT_TAGS:
            vals = [der_uint(x) for x in child.kids()[0].kids()] if v.constructed else [der_uint(v)]
            table = {1: PURPOSE, 5: DIGEST, 6: PADDING}[tag]
            out[name] = [table.get(x, x) for x in vals]
        elif tag == 2:
            out[name] = ALGORITHM.get(der_uint(v), der_uint(v))
        elif tag == 10:
            out[name] = EC_CURVE.get(der_uint(v), der_uint(v))
        elif tag == 702:
            out[name] = ORIGIN.get(der_uint(v), der_uint(v))
        elif tag == 504:
            out[name] = AUTH_TYPE.get(der_uint(v), der_uint(v))
        elif tag == 704:
            rk = v.kids()
            out[name] = {
                "verifiedBootKey": rk[0].content.hex(),
                "deviceLocked": rk[1].content == b"\xff",
                "verifiedBootState": BOOT_STATE.get(der_uint(rk[2]), der_uint(rk[2])),
                "verifiedBootHash": rk[3].content.hex() if len(rk) > 3 else None,
            }
        elif tag == 709:
            out[name] = decode_app_id(v.content)
        elif tag in (710, 711, 712, 713, 714, 715, 716, 717):
            out[name] = v.content.decode("utf-8", "replace")
        elif v.tag == 2 or not v.constructed:
            try:
                out[name] = der_uint(v)
            except Exception:
                out[name] = v.content.hex()
        else:
            out[name] = v.content.hex()
    return out


def decode_attestation(ext_value):
    # The extension value is an OCTET STRING wrapping the KeyDescription SEQUENCE.
    inner = parse_all(ext_value)[0]
    kd = (inner if inner.tag == 16 else parse_all(inner.content)[0]).kids()
    return {
        "attestationVersion": der_uint(kd[0]),
        "attestationSecurityLevel": SECURITY_LEVEL.get(der_uint(kd[1]), der_uint(kd[1])),
        "keymasterVersion": der_uint(kd[2]),
        "keymasterSecurityLevel": SECURITY_LEVEL.get(der_uint(kd[3]), der_uint(kd[3])),
        "attestationChallenge": kd[4].content.hex(),
        "attestationChallengeAscii": kd[4].content.decode("ascii", "replace"),
        "uniqueId": kd[5].content.hex(),
        "softwareEnforced": decode_auth_list(kd[6]),
        "hardwareEnforced": decode_auth_list(kd[7]),
    }


# --------------------------------------------------------------------------- input


def load_certs(paths):
    certs = []
    for path in paths:
        with open(path, "rb") as fh:
            data = fh.read()
        if b"-----BEGIN CERTIFICATE-----" in data:
            text = data.decode("ascii", "replace")
            for chunk in text.split("-----BEGIN CERTIFICATE-----")[1:]:
                body = chunk.split("-----END CERTIFICATE-----")[0]
                certs.append(Cert(base64.b64decode("".join(body.split()))))
        else:
            certs.append(Cert(data))
    return certs


# --------------------------------------------------------------------------- report


def main(argv):
    paths, expect_challenge, as_json = [], None, False
    i = 0
    while i < len(argv):
        if argv[i] == "--expect-challenge":
            expect_challenge = argv[i + 1].lower().replace(" ", "")
            i += 2
        elif argv[i] == "--json":
            as_json = True
            i += 1
        else:
            paths.append(argv[i])
            i += 1
    if not paths:
        print(__doc__ if __doc__ else "usage: parse-attestation.py chain.pem", file=sys.stderr)
        print("usage: parse-attestation.py <chain.pem | leaf.der ...> "
              "[--expect-challenge HEX] [--json]", file=sys.stderr)
        return 2

    certs = load_certs(paths)
    result = {"chain_length": len(certs), "certificates": [], "attestation": None, "checks": []}

    for idx, cert in enumerate(certs):
        ktype, p1, p2 = cert.key_info()
        entry = {
            "index": idx,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "serial": hex(cert.serial),
            "not_before": str(cert.not_before),
            "not_after": str(cert.not_after),
            "key": ktype if ktype != "ec" else "ec(%s)" % p1,
            "spki_sha256": cert.spki_sha256(),
            "self_signed": cert.subject == cert.issuer,
            "has_attestation_extension": ATTESTATION_OID in cert.extensions,
        }
        if ktype == "rsa":
            entry["key"] = "rsa-%d" % p1.bit_length()
        result["certificates"].append(entry)
        if ATTESTATION_OID in cert.extensions and result["attestation"] is None:
            result["attestation"] = decode_attestation(cert.extensions[ATTESTATION_OID][1])
            result["attestation"]["found_in_cert_index"] = idx

    # chain linkage and real signature verification
    for idx in range(len(certs) - 1):
        child, parent = certs[idx], certs[idx + 1]
        ok, note = verify_signed_by(child, parent)
        result["checks"].append({
            "check": "cert[%d] signed by cert[%d]" % (idx, idx + 1),
            "names_match": child.issuer == parent.subject,
            "signature_valid": ok,
            "note": note,
        })
    if certs:
        root = certs[-1]
        ok, note = verify_signed_by(root, root)
        result["checks"].append({
            "check": "root cert[%d] self-signature" % (len(certs) - 1),
            "names_match": root.issuer == root.subject,
            "signature_valid": ok,
            "note": note,
        })

    att = result["attestation"]
    if att and expect_challenge is not None:
        result["checks"].append({
            "check": "attestation challenge equals the one we issued",
            "expected": expect_challenge,
            "actual": att["attestationChallenge"],
            "signature_valid": att["attestationChallenge"] == expect_challenge,
        })

    if as_json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    print("=" * 78)
    print("CHAIN - %d certificate(s)" % len(certs))
    print("=" * 78)
    for e in result["certificates"]:
        print("[%d] subject : %s" % (e["index"], e["subject"]))
        print("    issuer  : %s" % e["issuer"])
        print("    serial  : %s" % e["serial"])
        print("    key     : %s" % e["key"])
        print("    valid   : %s .. %s" % (e["not_before"], e["not_after"]))
        print("    spki-sha256 : %s" % e["spki_sha256"])
        print("    attestation extension: %s%s" % (
            "YES" if e["has_attestation_extension"] else "no",
            "   (self-signed root)" if e["self_signed"] else ""))
        print()

    print("-" * 78)
    print("SIGNATURE / LINKAGE CHECKS")
    print("-" * 78)
    for c in result["checks"]:
        state = {True: "PASS", False: "FAIL", None: "SKIP"}[c.get("signature_valid")]
        extra = ""
        if "names_match" in c:
            extra = "   names_match=%s" % c["names_match"]
        if c.get("note"):
            extra += "   [%s]" % c["note"]
        print("  %-4s %s%s" % (state, c["check"], extra))
    print()
    print("  The root above is trusted ONLY if its spki-sha256 matches the Google hardware")
    print("  attestation root you obtained through a channel you trust. This script does not,")
    print("  and cannot, decide that for you.")
    print()

    if not att:
        print("No attestation extension (%s) in any certificate." % ATTESTATION_OID)
        print("Either this is not a key attestation chain, or the key was generated without")
        print("setAttestationChallenge(). A self-signed 'CN=Android Keystore Key' certificate with")
        print("no extension proves nothing whatsoever about the hardware.")
        return 0

    print("=" * 78)
    print("KEY ATTESTATION  (from cert[%d], extension %s)" % (att["found_in_cert_index"], ATTESTATION_OID))
    print("=" * 78)
    print("  attestationVersion       : %s" % att["attestationVersion"])
    print("  attestationSecurityLevel : %s      <- where the STATEMENT was made" % att["attestationSecurityLevel"])
    print("  keymasterVersion         : %s" % att["keymasterVersion"])
    print("  keymasterSecurityLevel   : %s      <- where the KEY lives" % att["keymasterSecurityLevel"])
    print("  attestationChallenge     : %s" % att["attestationChallenge"])
    print("  uniqueId                 : %s" % (att["uniqueId"] or "(empty)"))
    print()

    for which in ("hardwareEnforced", "softwareEnforced"):
        label = "HARDWARE-ENFORCED (trustworthy)" if which == "hardwareEnforced" \
                else "SOFTWARE-ENFORCED (asserted by Android, NOT trustworthy)"
        print("-" * 78)
        print("  %s" % label)
        print("-" * 78)
        entries = att[which]
        if not entries:
            print("    (empty)")
        for key, value in entries.items():
            if isinstance(value, dict) and key == "rootOfTrust":
                print("    rootOfTrust:")
                print("      verifiedBootState : %s" % value["verifiedBootState"])
                print("      deviceLocked      : %s" % value["deviceLocked"])
                print("      verifiedBootKey   : %s" % value["verifiedBootKey"])
                print("      verifiedBootHash  : %s" % value["verifiedBootHash"])
            elif isinstance(value, dict) and key == "attestationApplicationId":
                print("    attestationApplicationId:")
                for p in value.get("packages", []):
                    print("      package : %s (version %s)" % (p["package"], p["version"]))
                for d in value.get("signature_digests", []):
                    print("      signer  : %s" % d)
                if "error" in value:
                    print("      undecoded: %s" % value["raw"][:80])
            else:
                print("    %-28s: %s" % (key, value))
        print()

    # The verdicts that actually decide a report.
    print("=" * 78)
    print("VERDICTS")
    print("=" * 78)
    hw = att["hardwareEnforced"]
    sw = att["softwareEnforced"]
    rot = hw.get("rootOfTrust")

    if att["attestationSecurityLevel"] == "Software":
        print("  [CRITICAL] attestationSecurityLevel is Software. The whole statement was made by")
        print("             the Android framework, which an attacker with root owns. Worthless.")
    else:
        print("  [ok]  Attestation was produced in %s." % att["attestationSecurityLevel"])

    print("  [--]  The attested key lives in: %s" % att["keymasterSecurityLevel"])

    if rot is None:
        if "rootOfTrust" in sw:
            print("  [CRITICAL] rootOfTrust appears ONLY in the software-enforced list. A verifier")
            print("             that reads it from there is reading an attacker-controlled value.")
        else:
            print("  [warn] No rootOfTrust present. Boot integrity is unattested.")
    else:
        good = rot["verifiedBootState"] == "Verified" and rot["deviceLocked"]
        print("  [%s]  Boot: verifiedBootState=%s deviceLocked=%s"
              % ("ok" if good else "FAIL", rot["verifiedBootState"], rot["deviceLocked"]))
        if not good:
            print("        This device is NOT in a stock, locked, verified state. Compare that")
            print("        against whatever ro.boot.verifiedbootstate claims - the property lives")
            print("        in the normal world and is trivially rewritten; this field does not.")

    # Read origin from the hardware list FIRST, and say which list it came from. A GENERATED
    # sitting only in softwareEnforced is the framework's word for it, which is worth nothing.
    if "origin" in hw:
        origin, where = hw["origin"], "hardware-enforced"
    elif "origin" in sw:
        origin, where = sw["origin"], "SOFTWARE-enforced"
    else:
        origin, where = None, None
    if origin and origin != "GENERATED":
        print("  [warn] origin=%s (%s) - the key material existed outside the secure hardware."
              % (origin, where))
    elif origin and where == "hardware-enforced":
        print("  [ok]  origin=GENERATED (hardware-enforced) - the key was born inside the")
        print("        secure hardware and the hardware is the one saying so.")
    elif origin:
        print("  [warn] origin=GENERATED but only in the SOFTWARE-enforced list. That is the")
        print("        framework's claim about itself, not the hardware's. It proves nothing.")

    if "noAuthRequired" in hw:
        print("  [--]  noAuthRequired is set: this key can be used with no user authentication.")
    elif "userAuthType" in hw:
        print("  [ok]  Key is auth-bound: userAuthType=%s authTimeout=%s"
              % (hw.get("userAuthType"), hw.get("authTimeout", "per-use")))

    appid = hw.get("attestationApplicationId", sw.get("attestationApplicationId"))
    if appid is None:
        print("  [warn] No attestationApplicationId — nothing ties this key to a package.")
    elif "attestationApplicationId" in sw and "attestationApplicationId" not in hw:
        print("  [note] attestationApplicationId is SOFTWARE-enforced. That is normal - the")
        print("         framework supplies it - but it means a verifier must still check the")
        print("         chain and the challenge, since this field alone is not hardware-backed.")

    for tag in ("rollbackResistance", "rollbackResistant"):
        if tag in hw:
            print("  [ok]  %s is hardware-enforced: deleting this key really destroys it." % tag)
            break
    else:
        print("  [--]  No rollback resistance. A restored flash image could resurrect this key")
        print("        blob; deletion is not guaranteed to be permanent.")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
