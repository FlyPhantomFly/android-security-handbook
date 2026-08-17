#!/usr/bin/env python3
"""
04-reimplement-signing.py — reproduce a native request signature in Python.

WHAT IT IS
    A worked example of the deliverable that ends most native reverse
    engineering engagements: a standalone reimplementation of the algorithm you
    read in the decompiler, verified against the real implementation.

WHY THIS IS THE DELIVERABLE
    Reading a function tells you how it works. Reimplementing it proves you were
    right, and — more importantly — lets you exercise the server without the app.
    Once you can produce valid signatures yourself, you can test the API directly:
    fuzz parameters, replay with modifications, check authorisation on every
    endpoint. That is where the real findings are, and none of it is reachable
    while you still need the app in the loop.

    The verification step is not optional. A reimplementation that has never been
    checked against ground truth is a hypothesis, and hypotheses about sign
    extension and integer width are wrong startlingly often.

THE TARGET, as read in Ghidra
    The library exports a function that, given a request body and a timestamp,
    produces a hex signature. The decompiled C reduced to:

        1. Derive a 32-byte key by SHA-256 over a device-independent seed
           embedded in .rodata (found via a cross-reference from the derive
           function; see ../labs/lab-04-ctf-three-routes.md for the technique).
        2. Build a canonical string:  METHOD + "\\n" + PATH + "\\n" + timestamp
                                      + "\\n" + sha256hex(body)
        3. HMAC-SHA256 that canonical string under the derived key.
        4. Return it lowercase hex.

    Every one of those four steps is a decision the analyst had to make from the
    decompilation, and each is annotated below with what it looked like in
    Ghidra. That annotation is the point of this file.

USAGE
    # Reproduce a signature
    python3 04-reimplement-signing.py \\
        --method POST --path /v3/transfer \\
        --timestamp 1735689600 \\
        --body '{"to":"acct-42","amount":100}'

    # Verify against a signature captured from the app
    python3 04-reimplement-signing.py --method POST --path /v3/transfer \\
        --timestamp 1735689600 --body '{"to":"acct-42","amount":100}' \\
        --expect 3f2a...c1

    # Run the self-test vectors
    python3 04-reimplement-signing.py --selftest

REQUIREMENTS
    Python 3.8+. Standard library only — hashlib and hmac are enough, and using
    only the standard library means this file runs anywhere, including on a
    locked-down engagement laptop.

AUTHORISED TESTING ONLY. Producing valid signatures for a service you are not
contracted to test is unauthorised access in most jurisdictions.
"""

import argparse
import binascii
import hashlib
import hmac
import json
import sys

# --------------------------------------------------------------------------- #
# STEP 1 — the seed, recovered from .rodata
#
# IN GHIDRA
#   The derive function referenced a 24-byte array in .rodata. It was not a
#   printable string, because it had been XOR-obfuscated with a single byte that
#   appeared as an immediate in the decode loop:
#
#       for (i = 0; i < 0x18; i = i + 1) {
#           local_38[i] = *(byte *)(&DAT_00102080 + i) ^ 0x5c;
#       }
#
#   Recovering it: select the bytes at DAT_00102080, Copy Special -> Byte String,
#   then XOR with 0x5c.
#
# WHAT THIS TELLS YOU ABOUT THE DESIGN
#   The seed is a build-time constant, identical on every device and every
#   install. It is therefore not a secret in any meaningful sense: it is
#   available to anyone who reads the binary, which is everyone. Note that
#   distinction in the report — "obfuscated build-time constant", not "key".
# --------------------------------------------------------------------------- #

SEED_XOR_KEY = 0x5C

SEED_ENCRYPTED = bytes([
    0x3d, 0x39, 0x2b, 0x33, 0x3d, 0x71, 0x2f, 0x33, 0x3e, 0x38, 0x33, 0x38,
    0x3d, 0x71, 0x2f, 0x39, 0x39, 0x3a, 0x71, 0x2b, 0x6e, 0x71, 0x6e, 0x6c,
])


def recover_seed() -> bytes:
    """Undo the single-byte XOR the library applies in its decode loop."""
    return bytes(b ^ SEED_XOR_KEY for b in SEED_ENCRYPTED)


# --------------------------------------------------------------------------- #
# STEP 2 — key derivation
#
# IN GHIDRA
#   A call to SHA256_Init / SHA256_Update / SHA256_Final, all three exported by
#   libcrypto.so and therefore named even though the app's own functions were
#   stripped. That asymmetry is the single most useful fact in native crypto
#   analysis: the app can hide its code but not the library it calls.
#
#   The result was memcpy'd into a 32-byte global that every later use read from.
#   Recovering that global's address and hooking the memcpy is the runtime route
#   to the same answer.
# --------------------------------------------------------------------------- #

def derive_key(seed: bytes) -> bytes:
    """SHA-256 over the recovered seed. 32 bytes out."""
    return hashlib.sha256(seed).digest()


# --------------------------------------------------------------------------- #
# STEP 3 — the canonical string
#
# IN GHIDRA
#   A snprintf with the format string "%s\n%s\n%llu\n%s", which appeared
#   verbatim in .rodata. Format strings are the single most generous thing a
#   developer leaves an analyst: this one gave the field count, the field order,
#   the separator, and the type of each field, without reading a line of logic.
#
#   THE TRAPS, and how each was resolved:
#
#     - Is the separator "\n" or "\r\n"? The format string settles it: 0x0a.
#     - Is the timestamp seconds or milliseconds? %llu with values around
#       1.7e9 in the observed traffic says seconds.
#     - Is the body hashed or included raw? The fourth argument came from a
#       function that called SHA256_* and then a hex-encoding loop, so: hashed,
#       then hex.
#     - Is the hex upper or lower case? The encoding loop indexed a 16-byte
#       .rodata string. Reading it showed "0123456789abcdef": lower case.
#
#   Each of those is a coin flip you cannot guess, and each is why the
#   verification step at the bottom of this file exists.
# --------------------------------------------------------------------------- #

HEX_ALPHABET = "0123456789abcdef"     # read directly out of .rodata


def hex_lower(data: bytes) -> str:
    """The library's own hex encoder, reproduced exactly (lower case)."""
    return "".join(HEX_ALPHABET[b >> 4] + HEX_ALPHABET[b & 0x0F] for b in data)


def canonical_string(method: str, path: str, timestamp: int, body: bytes) -> str:
    """
    METHOD \n PATH \n TIMESTAMP \n sha256hex(body)

    Note that `method` is upper-cased and `path` is used verbatim including its
    leading slash and any query string. Both facts came from reading how the
    arguments were prepared before the snprintf call.
    """
    body_hash = hex_lower(hashlib.sha256(body).digest())
    return "%s\n%s\n%d\n%s" % (method.upper(), path, timestamp, body_hash)


# --------------------------------------------------------------------------- #
# STEP 4 — the HMAC
#
# IN GHIDRA
#   HMAC_Init_ex(ctx, key, 0x20, EVP_sha256(), NULL), then HMAC_Update over the
#   canonical string, then HMAC_Final.
#
#   The digest algorithm was identified without guessing: EVP_sha256() is an
#   exported symbol, and hooking EVP_MD_get0_name at runtime prints "SHA256"
#   directly. See ../../53-Frida/examples/03-native-key-recovery.js.
# --------------------------------------------------------------------------- #

def sign(method: str, path: str, timestamp: int, body: bytes,
         key: bytes = None) -> str:
    """Produce the signature the library would produce for these inputs."""
    if key is None:
        key = derive_key(recover_seed())
    canonical = canonical_string(method, path, timestamp, body)
    mac = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).digest()
    return hex_lower(mac)


# --------------------------------------------------------------------------- #
# Verification
#
# THIS IS THE PART THAT MAKES THE REST TRUSTWORTHY.
#
# Capture a real (input, signature) pair from the app — the easy way is to hook
# the native function with Frida, print its arguments and its return value, and
# copy both. Then check that this implementation produces the same output.
#
#   frida -U -f com.example.app -l ../examples/03-ghidra-to-frida-bridge.js \\
#         --no-pause
#   g.setup("libsign.so")
#   g.hookJni(0x00103a10, "sign", 3)
#
# If the signatures do not match, the mismatch is almost always one of the four
# traps listed under STEP 3. Work through them in order.
# --------------------------------------------------------------------------- #

# Vectors captured from a running app. Replace with your own.
SELF_TEST_VECTORS = [
    {
        "method": "POST",
        "path": "/v3/transfer",
        "timestamp": 1735689600,
        "body": b'{"to":"acct-42","amount":100}',
        # Expected value: replace with a signature you captured. The placeholder
        # below is deliberately not a real signature, so the self-test FAILS
        # until you supply ground truth. A self-test that passes against a
        # made-up constant is worse than no self-test.
        "expected": None,
    },
]


def selftest() -> int:
    seed = recover_seed()
    key = derive_key(seed)

    print("Recovered seed  : %r" % seed)
    print("                  (%s)" % hex_lower(seed))
    try:
        print("  as ASCII      : %s" % seed.decode("ascii"))
    except UnicodeDecodeError:
        print("  as ASCII      : <not printable - check the XOR key>")
    print("Derived key     : %s" % hex_lower(key))
    print()

    failures = 0
    for i, v in enumerate(SELF_TEST_VECTORS):
        canonical = canonical_string(v["method"], v["path"],
                                     v["timestamp"], v["body"])
        got = sign(v["method"], v["path"], v["timestamp"], v["body"], key)

        print("Vector %d" % i)
        print("  canonical string (repr, so \\n is visible):")
        print("    %r" % canonical)
        print("  computed signature: %s" % got)

        if v["expected"] is None:
            print("  expected         : <NOT SET>")
            print()
            print("  This vector has no ground truth, so it proves nothing.")
            print("  Capture a real (input, signature) pair from the app and put")
            print("  the signature in SELF_TEST_VECTORS[%d]['expected'].", i)
            print("  Until then this implementation is a HYPOTHESIS.")
            failures += 1
        elif got == v["expected"]:
            print("  expected         : %s" % v["expected"])
            print("  MATCH")
        else:
            print("  expected         : %s" % v["expected"])
            print("  MISMATCH")
            print()
            print("  Work through the four traps from STEP 3, in this order:")
            print("    1. separator: is it \\n or \\r\\n?")
            print("    2. timestamp: seconds or milliseconds?")
            print("    3. body: raw, or hashed-then-hex?")
            print("    4. hex case: lower or upper?")
            print("  Also check: is the method upper-cased? Does the path include")
            print("  the query string? Is there a trailing newline?")
            failures += 1
        print()

    return failures


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Reproduce a native request signature outside the app.")
    ap.add_argument("--method", default="POST")
    ap.add_argument("--path", default="/v3/transfer")
    ap.add_argument("--timestamp", type=int, default=1735689600)
    ap.add_argument("--body", default="{}")
    ap.add_argument("--body-file", help="read the body from a file instead")
    ap.add_argument("--key-hex", help="override the derived key (32 bytes hex)")
    ap.add_argument("--expect", help="verify against a captured signature")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--show-work", action="store_true",
                    help="print every intermediate value")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(1 if selftest() else 0)

    if args.body_file:
        with open(args.body_file, "rb") as fh:
            body = fh.read()
    else:
        body = args.body.encode("utf-8")

    if args.key_hex:
        try:
            key = binascii.unhexlify(args.key_hex)
        except binascii.Error as e:
            sys.exit("bad --key-hex: %s" % e)
        if len(key) != 32:
            sys.exit("--key-hex must be 32 bytes (64 hex characters)")
    else:
        key = derive_key(recover_seed())

    canonical = canonical_string(args.method, args.path, args.timestamp, body)
    signature = sign(args.method, args.path, args.timestamp, body, key)

    if args.show_work:
        print("seed      : %r" % recover_seed())
        print("key       : %s" % hex_lower(key))
        print("body      : %r" % body)
        print("body sha  : %s" % hex_lower(hashlib.sha256(body).digest()))
        print("canonical : %r" % canonical)
        print()

    print(signature)

    if args.expect:
        if signature.lower() == args.expect.lower().strip():
            print("MATCH", file=sys.stderr)
            sys.exit(0)
        print("MISMATCH — expected %s" % args.expect, file=sys.stderr)
        print("See the STEP 3 traps in this file's comments.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

# --------------------------------------------------------------------------- #
# WHAT TO DO ONCE THIS VERIFIES
#
# You can now talk to the API without the app. That unlocks the tests that
# actually find things:
#
#   - Replay a captured request with a modified amount, re-signed. Does the
#     server check anything beyond the signature?
#   - Sign a request for a resource belonging to another account. Is there any
#     server-side authorisation, or is the signature the whole control?
#   - Reuse a timestamp from an hour ago. Is there replay protection?
#   - Omit the signature entirely. Is it enforced, or merely expected?
#   - Sign a request for an endpoint the app never calls. Is the surface larger
#     than the client suggests?
#
# THE FINDING is not "the signing key is recoverable from the binary" — that is
# true of every client-side key and is barely worth writing down on its own. The
# finding is whatever the four questions above reveal, because that is where the
# server's assumptions turn out to be wrong.
#
# And the remediation is correspondingly not "obfuscate the key better". It is
# that a signature produced by a key the client holds authenticates the CLIENT
# BUILD, not the user and not the request's legitimacy, and the server must not
# treat it as if it did.
# --------------------------------------------------------------------------- #
