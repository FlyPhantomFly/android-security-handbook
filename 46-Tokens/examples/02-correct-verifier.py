#!/usr/bin/env python3
"""
examples/02-correct-verifier.py — the correct counterpart to 01-broken-verifier.py.

PURPOSE
  Same input, same output shape, same twenty-odd lines of structure -- and none of the
  seven flaws. This file exists so that the diff between it and 01-broken-verifier.py is
  the chapter's argument in executable form: JWT verification failures are not exotic
  cryptography, they are a handful of comparisons that were never written.

  It is also the CONTROL in labs/lab-02-the-jwt-attack-gauntlet.md. Every attack that the
  broken verifier accepts, this one must reject, and it must still accept the one genuine
  token. A control that rejects everything proves nothing, so the gauntlet checks both
  directions.

  The five rules it implements, in the order they matter:
    RULE 1  The verifier decides the algorithm. `alg` from the token is a cross-check
            at most, and anything outside the allow-list is a rejection.
    RULE 2  Each key knows its own algorithm. A public key can never be used as an
            HMAC secret, because keys are typed, not bytes.
    RULE 3  `kid` selects from an in-memory map of already-trusted keys. It never
            reaches a filesystem, a URL, a database, or a string concatenation.
    RULE 4  exp / nbf / iat are compared against the clock, with a bounded skew.
    RULE 5  iss and aud are compared, with `==` on a value this verifier holds and
            the token does not influence.
  Plus: signature comparison is constant time, and the token's own header is never
  allowed to change which key, algorithm, or issuer is used.

USAGE
  As a library, which is how run-gauntlet.py drives it:
      trust = TrustStore(
          issuer="https://issuer.lab.local",
          audience="com.pentest.ch46.client",
          rsa_public_pems={"rsa-2026-08": pem_bytes},
          hmac_secrets={"hs-legacy": secret_bytes},
      )
      ok, claims, reason = verify(token, trust)

  As a command-line tool:
      python3 -B 02-correct-verifier.py --token "eyJ..." \\
          --issuer https://issuer.lab.local --audience com.pentest.ch46.client \\
          --rsa-key rsa-2026-08=/path/issuer-public.pem

  Run it with `python3 -B` so no __pycache__ is written into the repository.

REQUIREMENTS
  Python 3.8+ and `cryptography` (pip install cryptography) for the RS256 path.
  No network access is used or needed: keys are supplied by the caller.

WHAT THIS WILL NOT TELL YOU
  * It will not tell you the token's holder is who they claim to be. It tells you the
    token is intact, current, from your issuer, and minted for you. Whether `sub` maps
    to the right account, and whether that account may perform the requested action, is
    authorisation and lives above this function.
  * It will not detect a stolen token. Every check here passes for a token an attacker
    copied out of a phone's SharedPreferences. That is what "bearer" means, and it is
    why sender-constraining (DPoP, mTLS) exists -- see README section 3.11.
  * It will not detect a compromised issuer. If the signing key leaked, every forged
    token verifies perfectly. Key compromise is answered by rotation and revocation.
  * It does not fetch JWKS. Key retrieval and rotation are deliberately outside the
    verifier, because a verifier that fetches a key named by the token it is verifying
    has reintroduced flaw 4 with extra steps.
  * It does not implement JWE, nested JWTs, or `crit`. Those are scope, not oversight.

SAFETY
  Only feed this tokens you minted yourself.

Chapter 46 — Tokens
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time

# Algorithms this verifier will ever consider. Everything else -- "none", "HS1",
# a typo, a future algorithm nobody has reviewed -- is rejected before any key is
# touched. The allow-list is short on purpose: an application that needs both RSA
# and HMAC verification usually has two token families and should have two
# verifiers, not one verifier with a wider list.
ALLOWED_ALGS = frozenset({"RS256", "HS256"})

# Maximum clock skew tolerated, in seconds. 60 is generous for a server whose clock
# is disciplined by NTP and mean for one that is not. Making it large to "fix" a
# flaky test is how an exp check becomes decorative.
MAX_SKEW_SECONDS = 60

# Refuse absurd tokens before parsing them. A JWT is a header, some claims and a
# signature; anything past a few kilobytes is either a mistake or an attempt to
# make the parser do work. This is the cheapest check in the file.
MAX_TOKEN_BYTES = 8 * 1024


class TrustStore:
    """Everything the verifier trusts, supplied from outside the token.

    Not one field here can be influenced by the token being verified. That property
    is the whole design: the token is data, and data does not get to choose the rules
    it will be judged by.
    """

    def __init__(self, issuer, audience, rsa_public_pems=None, hmac_secrets=None):
        if not issuer or not audience:
            raise ValueError("a verifier with no expected issuer or audience is not a verifier")
        self.issuer = issuer
        self.audience = audience
        # RULE 2 + RULE 3: keys are held in typed maps, keyed by kid. A kid that is
        # not a key of one of these dicts does not resolve to anything. There is no
        # fallback, no default key, and no path.
        self.rsa_public_pems = dict(rsa_public_pems or {})
        self.hmac_secrets = dict(hmac_secrets or {})

    def key_for(self, alg, kid):
        """Return (key_object_or_bytes, error). The algorithm chooses the map."""
        if kid is None:
            return None, "header has no kid, and this verifier does not guess"
        if alg == "RS256":
            pem = self.rsa_public_pems.get(kid)
            if pem is None:
                return None, f"unknown RSA kid {kid!r}"
            return pem, None
        if alg == "HS256":
            secret = self.hmac_secrets.get(kid)
            if secret is None:
                return None, f"unknown HMAC kid {kid!r}"
            # RULE 2, made mechanical: an HMAC secret must have come from a CSPRNG,
            # so a short one is a configuration error, not an input to be validated
            # away quietly. 32 bytes is the floor for HS256; RFC 7518 section 3.2
            # requires a key at least as long as the hash output.
            if len(secret) < 32:
                return None, ("HMAC key shorter than the 32-byte minimum for HS256 "
                              "(RFC 7518 section 3.2) -- this is a deployment fault, "
                              "not a token fault")
            return secret, None
        return None, f"no key type defined for alg {alg!r}"


def b64url_decode(segment: str) -> bytes:
    """Strict base64url decode.

    Two details that matter. First, base64url is not base64: '-' and '_' replace '+'
    and '/'. Second, `validate=True` makes a segment containing a '+' or '/' -- which
    a naive forgery tool emits when it uses standard base64 -- an error rather than
    something quietly tolerated. RFC 8725 section 3.11 asks for exactly this
    strictness, because two parsers that disagree about what a segment means is how
    parser-differential attacks start.
    """
    if any(ch in segment for ch in "+/= \n\r\t"):
        raise ValueError("segment is not strict base64url")
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment.encode("ascii") + pad.encode("ascii"))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify(token, trust, now=None, max_skew=MAX_SKEW_SECONDS, required_claims=("sub",)):
    """Return (accepted: bool, claims_or_none: dict, reason: str).

    The order of the checks is deliberate and is itself a security property: nothing
    that costs real CPU happens before the cheap structural checks, and no claim is
    read as meaningful before the signature has been verified. Reading `sub` from an
    unverified token to look up a user is a full authentication bypass even if the
    signature is checked one line later, because the lookup already happened.
    """
    now = int(time.time()) if now is None else int(now)

    # --- structure, before anything expensive ------------------------------- #
    if not isinstance(token, str):
        return False, None, "token is not a string"
    if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        return False, None, f"token exceeds {MAX_TOKEN_BYTES} bytes"

    parts = token.split(".")
    if len(parts) == 5:
        return False, None, "five segments: JWE is not supported by this verifier"
    if len(parts) != 3:
        return False, None, f"expected 3 segments, got {len(parts)}"
    header_b64, payload_b64, signature_b64 = parts
    if not signature_b64:
        # An empty third segment is the shape of an alg=none token. It is caught
        # again by the allow-list below; catching it twice is not redundancy, it is
        # depth. The cheap check also means a stripped-signature token never reaches
        # the key lookup.
        return False, None, "empty signature segment (unsigned token)"

    try:
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(signature_b64)
    except Exception as exc:                                   # noqa: BLE001
        return False, None, f"malformed segment: {exc}"
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return False, None, "header and payload must both be JSON objects"

    # --- RULE 1: the algorithm is ours, not the token's --------------------- #
    #
    # `alg` is read only to confirm it is one we already decided to accept. If this
    # application only ever issues RS256, ALLOWED_ALGS should contain only RS256 and
    # this becomes an equality test. The failure mode this prevents is the whole
    # algorithm-confusion family, including alg=none, in one comparison.
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALLOWED_ALGS:
        return False, None, f"alg {alg!r} is not in the allow-list {sorted(ALLOWED_ALGS)}"

    # RFC 8725 section 3.10: a `crit` header names extensions the verifier MUST
    # understand. This verifier understands none, so any crit is a rejection. Ignoring
    # crit is how a verifier silently skips a control the issuer thought was mandatory.
    if "crit" in header:
        return False, None, "crit header present and this verifier implements no extensions"

    # --- RULES 2 and 3: the key comes from the trust store ------------------ #
    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        return False, None, "kid must be a string"
    key, err = trust.key_for(alg, kid)
    if err:
        # Note what did NOT happen: no file was opened, no URL was fetched, no string
        # was concatenated. `kid` was a dictionary lookup and nothing else, so a kid
        # of "../../dev/null" is simply a miss.
        return False, None, f"key selection failed: {err}"

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # --- signature ---------------------------------------------------------- #
    if alg == "HS256":
        expected = hmac.new(key, signing_input, hashlib.sha256).digest()
        # Constant time. `compare_digest` takes the same time whether the first byte
        # differs or the last one does.
        if not hmac.compare_digest(expected, signature):
            return False, None, "HS256 signature mismatch"
    else:  # RS256 -- guaranteed by the allow-list above
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
            pub = serialization.load_pem_public_key(key)
            # Belt and braces: confirm the key really is RSA before using it as one.
            # A trust store misconfigured with an EC key under an "RS256" kid should
            # fail loudly here rather than raise something ambiguous later.
            if not isinstance(pub, rsa.RSAPublicKey):
                return False, None, "kid resolved to a non-RSA key for RS256"
            pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except ImportError:
            return False, None, "`cryptography` is required for RS256 verification"
        except Exception:                                      # noqa: BLE001
            return False, None, "RS256 signature invalid"

    # Everything below this line runs only on a token whose integrity is now proven.
    # Everything below this line is still mandatory.

    # --- RULE 5: issuer ----------------------------------------------------- #
    #
    # A valid signature from key K proves the token came from whoever holds K. It does
    # not prove K belongs to your issuer, unless you also insist the token says so and
    # you pinned that kid to that issuer. Compare with `!=` on an exact string. Do not
    # use startswith, do not use "contains", and do not normalise -- `https://evil/
    # ?x=https://issuer.lab.local` contains your issuer.
    if claims.get("iss") != trust.issuer:
        return False, None, f"iss {claims.get('iss')!r} != expected {trust.issuer!r}"

    # --- RULE 5: audience --------------------------------------------------- #
    #
    # `aud` is a string or an array of strings (RFC 7519 section 4.1.3). Handle both.
    # This is the check whose absence is the "Sign in with X" account-takeover flaw:
    # a genuinely signed token minted for a different relying party is accepted here
    # if you skip it. See 45-OAuth section 5.1 Attack 6.
    aud = claims.get("aud")
    aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if trust.audience not in aud_list:
        return False, None, f"aud {aud!r} does not contain {trust.audience!r}"
    if len(aud_list) > 1 and claims.get("azp") not in (None, trust.audience):
        # Multiple audiences means the issuer minted one token for several parties.
        # OIDC then requires azp ("authorized party") to name the client the token was
        # actually issued to. If it names somebody else, this token is not ours.
        return False, None, f"multi-audience token whose azp is {claims.get('azp')!r}"

    # --- RULE 4: time ------------------------------------------------------- #
    #
    # exp is REQUIRED here, not merely checked if present. "Validate exp if the token
    # has one" is the same bug shape as "validate the code_verifier if one was sent"
    # -- the attacker simply omits the field. A token with no expiry is a permanent
    # credential and must be refused by policy.
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return False, None, "no numeric exp claim -- a token without an expiry is refused"
    if now > exp + max_skew:
        return False, None, f"expired {int(now - exp)}s ago"

    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and now + max_skew < nbf:
        return False, None, f"not valid for another {int(nbf - now)}s (nbf)"

    iat = claims.get("iat")
    if isinstance(iat, (int, float)) and iat > now + max_skew:
        return False, None, "iat is in the future -- clock skew or forgery"

    for name in required_claims:
        if name not in claims:
            return False, None, f"required claim {name!r} is absent"

    return True, claims, f"accepted: {alg}, kid={kid}, {int(exp - now)}s of life remaining"


def main():
    ap = argparse.ArgumentParser(
        description="A correct JWT verifier -- the control for chapter 46's gauntlet.")
    ap.add_argument("--token", help="the token to check")
    ap.add_argument("--token-file", help="read the token from a file instead")
    ap.add_argument("--issuer", required=True, help="the exact iss value you expect")
    ap.add_argument("--audience", required=True, help="the exact aud value you expect")
    ap.add_argument("--rsa-key", action="append", default=[], metavar="KID=PATH",
                    help="an RSA public key PEM to trust, as kid=path (repeatable)")
    ap.add_argument("--hmac-key", action="append", default=[], metavar="KID=PATH",
                    help="an HMAC secret file to trust, as kid=path (repeatable)")
    args = ap.parse_args()

    if args.token_file:
        with open(args.token_file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
    elif args.token:
        token = args.token.strip()
    else:
        ap.error("give --token or --token-file")
        return 2

    def load(pairs):
        out = {}
        for pair in pairs:
            if "=" not in pair:
                ap.error(f"expected kid=path, got {pair!r}")
            kid, path = pair.split("=", 1)
            with open(path, "rb") as fh:
                out[kid] = fh.read()
        return out

    trust = TrustStore(args.issuer, args.audience, load(args.rsa_key), load(args.hmac_key))
    ok, claims, reason = verify(token, trust)
    print(f"verdict : {'ACCEPTED' if ok else 'REJECTED'}")
    print(f"reason  : {reason}")
    if claims is not None:
        print("claims  : " + json.dumps(claims, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
