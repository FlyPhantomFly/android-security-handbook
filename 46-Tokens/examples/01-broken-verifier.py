#!/usr/bin/env python3
"""
examples/01-broken-verifier.py — a DELIBERATELY BROKEN JWT verifier.

PURPOSE
  This is the negative half of the highest-value pair in chapter 46. It is a compact,
  faithful reproduction of how token verification is written when somebody reads the JWT
  structure, understands base64url, and never reads RFC 8725. Every flaw below has been
  found in shipping production code; none of them is a strawman.

  It is written to be *readable*, not to be sneaky. Each flaw is numbered, and each number
  matches a row in the chapter's failure-class table (README section 5) and a stage in
  labs/lab-02-the-jwt-attack-gauntlet.md.

  The seven planted flaws:
    FLAW 1  alg is read from the token and obeyed  -> "none" is accepted
    FLAW 2  one key blob serves every algorithm    -> HS/RS confusion
    FLAW 3  the HMAC secret is a human-chosen word -> offline cracking
    FLAW 4  kid is used as a filesystem path       -> key-file traversal
    FLAW 5  exp / nbf / iat are never examined     -> tokens never die
    FLAW 6  iss is never compared                  -> any issuer will do
    FLAW 7  aud is never compared                  -> any audience will do
  Plus a bonus, FLAW 8: the signature comparison uses `==` rather than a constant-time
  compare, which is a timing side channel on a network-reachable endpoint.

USAGE
  As a library, which is how run-gauntlet.py drives it:
      import importlib.util, pathlib
      spec = importlib.util.spec_from_file_location("bv", "01-broken-verifier.py")
      ...
      bv.verify(token, keydir="/path/to/lab/keys")

  As a command-line tool, for poking at one token by hand:
      python3 -B 01-broken-verifier.py --keydir /path/to/lab/keys --token "eyJ..."
      python3 -B 01-broken-verifier.py --keydir ... --token-file tok.txt

  Run it with `python3 -B`. Without -B, Python may write a __pycache__ directory into
  this repository, which is on the artefact blocklist.

REQUIREMENTS
  Python 3.8+. Standard library only for the HMAC and `none` paths. The RS256 path uses
  `cryptography` (pip install cryptography); if it is absent, RS256 verification reports
  an honest error instead of silently passing.

WHAT THIS WILL NOT TELL YOU
  * It will not tell you whether a real application under test is vulnerable. This file is
    a teaching fixture. Read the target's own verifier, or test it from the outside with
    the attacks in the gauntlet lab — never assume a target shares these flaws.
  * It will not tell you that a token is safe. Its whole job is to say "accepted" when it
    should have said "rejected". Never use it to triage anything.
  * It does not implement JWE (encrypted JWTs) at all. A five-segment token is refused.
  * It is not a complete JWT library. Compression (`zip: DEF`), nested JWTs, JWKS fetching
    and `crit` handling are all absent. Their absence is not one of the flaws; it is scope.

SAFETY
  Only ever feed this tokens you minted yourself. Chapter 46's standing rule is that every
  token you handle in this chapter is one you created. Do not paste a token belonging to a
  real account into any tool, including this one.

Chapter 46 — Tokens
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys

# --------------------------------------------------------------------------- #
# FLAW 3: the HMAC secret is a word a human chose.
#
# "Passw0rd!" satisfies most corporate password policies -- upper, lower, digit,
# symbol, nine characters -- and is in every wordlist ever published. An HMAC key
# is not a password. It is 256 bits of output from a CSPRNG, and no human should
# ever see it, type it, or be able to remember it.
# --------------------------------------------------------------------------- #
LEGACY_HMAC_SECRET = b"Passw0rd!"

# --------------------------------------------------------------------------- #
# FLAW 2: ONE key blob, used for every algorithm family.
#
# The developer's reasoning was: "we have one signing key, so we load it once."
# For RS256 that variable holds the issuer's PUBLIC key, which is published at the
# JWKS endpoint for anybody to download. When the same variable is then handed to
# an HMAC function, a public value becomes a symmetric secret, and anybody who can
# read the JWKS can mint tokens. This is the algorithm-confusion attack, and it is
# a *code-structure* bug rather than a cryptographic one: the primitives are fine.
# --------------------------------------------------------------------------- #
DEFAULT_PUBLIC_KEY_FILE = "issuer-public.pem"


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring the padding JWT strips.

    base64url is NOT base64. Two characters differ: '+' becomes '-' and '/' becomes
    '_', so the value survives being placed in a URL or an HTTP header without further
    escaping. RFC 7515 also strips the '=' padding, so the length is rarely a multiple
    of four and a plain b64decode() raises. This function is correct; it is not one of
    the flaws.
    """
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _load_key_by_kid(kid, keydir):
    """FLAW 4: `kid` is attacker-controlled data used to build a filesystem path.

    `kid` (key ID) is a hint in the JOSE header telling the verifier which key to use.
    It arrives inside the token, which means it is written by whoever wrote the token,
    which means an attacker writes it. Here it is concatenated onto a directory and
    opened. Two consequences follow immediately:

      * Traversal. `kid = "../public/jwks.json"` escapes the key directory and reads a
        file the attacker can also download, so the attacker knows the exact key bytes
        and can compute a matching HMAC.
      * The classic form, on POSIX systems, is `kid = "../../../../dev/null"`, which
        yields a zero-length key. Signing with an empty key is trivial.

    The correct design has no filesystem in it at all: `kid` selects from a small,
    in-memory map of keys the verifier already trusts, and an unknown `kid` is a
    rejection rather than a lookup.
    """
    if not kid:
        return None
    path = os.path.join(keydir, kid)          # no normalisation, no allow-list
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def verify(token: str, keydir: str = ".", public_key_file: str = None):
    """Return (accepted: bool, claims_or_none: dict, reason: str).

    This function is the bug. Read it as evidence, not as a template.
    """
    parts = token.split(".")

    if len(parts) == 5:
        return False, None, "five segments: this is a JWE, unsupported"
    if len(parts) != 3:
        return False, None, f"expected 3 segments, got {len(parts)}"

    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(payload_b64))
    except Exception as exc:                                   # noqa: BLE001
        return False, None, f"malformed segment: {exc}"

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # ----------------------------------------------------------------------- #
    # FLAW 1: the algorithm is taken from the token.
    #
    # The token says how to check the token. Stated that plainly it is obviously
    # circular, and yet it is what the JOSE header invites you to do -- the field
    # exists, it names an algorithm, and dispatching on it feels like reading a
    # protocol correctly. RFC 8725 section 3.1 is explicit that the verifier must
    # decide the acceptable algorithms in advance and treat `alg` as, at most, a
    # cross-check.
    #
    # The `.lower()` here is a second-order flaw. A verifier that special-cases the
    # exact string "none" but not "NoNe" has been bypassed in real libraries; this
    # one lowercases first, which makes every case variant reach the same branch --
    # and that branch accepts. Both spellings are tested in the gauntlet.
    # ----------------------------------------------------------------------- #
    alg = str(header.get("alg", "")).lower()

    # FLAW 1, exploited: alg=none means "this token is unsigned", and the verifier
    # says fine. RFC 7519 defines the "none" algorithm for the case where integrity
    # is provided by some *other* mechanism. Almost nobody who accepts it has one.
    if alg == "none":
        return True, claims, "accepted: alg=none, signature not required"

    # FLAW 4, exploited: kid picks the key, from the filesystem.
    kid_key = _load_key_by_kid(header.get("kid"), keydir)

    if alg.startswith("hs"):
        # FLAW 2 + FLAW 3 exploited together.
        #
        # The key is whichever of these is available: the file `kid` pointed at, or
        # the legacy shared secret. Note what is missing -- nothing here checks that
        # the chosen key was ever *intended* for HMAC. The RSA public key, fetched by
        # a traversing `kid`, lands in `key` and is used as an HMAC secret.
        key = kid_key if kid_key is not None else LEGACY_HMAC_SECRET
        digestmod = {"hs256": hashlib.sha256,
                     "hs384": hashlib.sha384,
                     "hs512": hashlib.sha512}.get(alg, hashlib.sha256)
        expected = b64url_encode(hmac.new(key, signing_input, digestmod).digest())

        # FLAW 8: `==` on a secret-dependent comparison. Python's str.__eq__ short
        # circuits on the first differing byte, so the time taken leaks how many
        # leading bytes were correct. Over a network this is usually unexploitable
        # noise; on a local socket, or against a service that signs a response, it
        # is not. `hmac.compare_digest` exists for exactly this and costs nothing.
        if expected == signature_b64:
            return True, claims, f"accepted: {alg} signature matched"
        return False, None, f"rejected: {alg} signature mismatch"

    if alg.startswith("rs") or alg.startswith("ps") or alg.startswith("es"):
        pub_pem = kid_key
        if pub_pem is None:
            pkf = public_key_file or os.path.join(keydir, DEFAULT_PUBLIC_KEY_FILE)
            try:
                with open(pkf, "rb") as fh:
                    pub_pem = fh.read()
            except OSError as exc:                             # noqa: BLE001
                return False, None, f"rejected: no public key available ({exc})"
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            pub = serialization.load_pem_public_key(pub_pem)
            pub.verify(b64url_decode(signature_b64), signing_input,
                       padding.PKCS1v15(), hashes.SHA256())
            return True, claims, f"accepted: {alg} signature verified"
        except ImportError:
            return False, None, "rejected: `cryptography` not installed, cannot check RS256"
        except Exception:                                      # noqa: BLE001
            return False, None, f"rejected: {alg} signature invalid"

    return False, None, f"rejected: unknown alg {alg!r}"


# --------------------------------------------------------------------------- #
# FLAWS 5, 6 and 7 live here -- in what this function does NOT do.
#
# A verifier's job does not end at the signature. A signature answers exactly one
# question: "was this token produced by somebody holding the key?" It says nothing
# about *when* it was produced, *who* produced it, or *who it was for*. Those are
# the exp, iss and aud claims, and every one of them must be compared against a
# value the verifier holds independently.
#
#   exp missing or unchecked -> a token minted once works forever. The most common
#                               real form is a token with a valid exp that the
#                               verifier simply never reads.
#   iss unchecked            -> a token from any issuer, including one the attacker
#                               operates, is accepted as if it came from yours.
#   aud unchecked            -> a token minted for a different relying party is
#                               accepted here. This is the "Sign in with X" flaw;
#                               see 45-OAuth section 5.1, Attack 6.
#
# There is no code below because there is no code in the original. That absence is
# the vulnerability, and it is invisible to anyone reviewing by asking "does it
# verify the signature?" -- because it does.
# --------------------------------------------------------------------------- #


def main():
    ap = argparse.ArgumentParser(
        description="Deliberately broken JWT verifier -- teaching fixture, chapter 46.")
    ap.add_argument("--token", help="the token to check")
    ap.add_argument("--token-file", help="read the token from a file instead")
    ap.add_argument("--keydir", default=".", help="directory the broken kid lookup uses")
    ap.add_argument("--public-key-file", help="PEM public key for the RS256 path")
    args = ap.parse_args()

    if args.token_file:
        with open(args.token_file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
    elif args.token:
        token = args.token.strip()
    else:
        ap.error("give --token or --token-file")
        return 2

    ok, claims, reason = verify(token, args.keydir, args.public_key_file)
    print(f"verdict : {'ACCEPTED' if ok else 'REJECTED'}")
    print(f"reason  : {reason}")
    if claims is not None:
        print("claims  : " + json.dumps(claims, indent=2, sort_keys=True))
    print()
    print("Reminder: this verifier is broken on purpose. ACCEPTED here means nothing.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
