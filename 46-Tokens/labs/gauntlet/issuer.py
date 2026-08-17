#!/usr/bin/env python3
"""
labs/gauntlet/issuer.py — a minimal, LOCAL token issuer for chapter 46's gauntlet.

PURPOSE
  Every token used anywhere in chapter 46 must be one you minted yourself. This file is
  how you mint them. It is a stand-in for an authorisation server's signing half: it
  generates a throwaway RSA keypair, publishes the public half as a JWKS, keeps a legacy
  HMAC secret around (deliberately a weak one), and issues tokens of both families.

  It is intentionally NOT a server. There is no Flask app, no port, and no network. A
  token issuer that listens on a socket invites you to point it at something real; this
  one cannot be pointed at anything. 45-OAuth's CTF already ships a mock authorisation
  server for flow work -- see 45-OAuth/labs/ctf/mock_as.py. This chapter needs only the
  minting, because this chapter is about the token, not the flow that carried it.

  Two token families are issued, because a real estate almost always has more than one:

    Family A -- "the modern one".  RS256, kid `rsa-2026-08`, signed by a 2048-bit RSA
                key generated fresh on every run. The public half is published.
    Family B -- "the legacy one".  HS256, kid `hs-legacy`, signed with a shared secret
                that a human chose in 2019 and nobody has rotated since.

USAGE
  # generate key material and mint the standard set of lab tokens
  python3 -B issuer.py --workdir /tmp/ch46-lab --init

  # mint one token with claims you choose
  python3 -B issuer.py --workdir /tmp/ch46-lab --mint \\
      --sub alice --role user --ttl 900

  # mint the legacy HS256 family instead
  python3 -B issuer.py --workdir /tmp/ch46-lab --mint --family hs --sub alice

  # print what is on disk
  python3 -B issuer.py --workdir /tmp/ch46-lab --show

  Always run with `python3 -B`; without it Python may leave a __pycache__ directory,
  which is on this repository's artefact blocklist.

REQUIREMENTS
  Python 3.8+ and `cryptography` (pip install cryptography). No PyJWT: the whole point
  of a chapter on token internals is that you assemble the three segments yourself and
  see that there is no magic in them.

OUTPUT LAYOUT (all inside --workdir, which must be OUTSIDE this repository)
  keys/rsa-2026-08        the RSA PUBLIC key, PEM. This is what a verifier needs.
  keys/hs-legacy          the legacy HMAC secret, raw bytes.
  keys/issuer-public.pem  a second copy, under the name a naive verifier defaults to.
  private/issuer.pem      the RSA PRIVATE key. Never leaves the workdir.
  public/jwks.json        the published key set -- treat these bytes as world-readable.
  tokens/*.jwt            the minted tokens.

WHAT THIS WILL NOT TELL YOU
  * Nothing here tells you anything about a real authorisation server. Its behaviour is
    whatever this file says it is, which is why the gauntlet's conclusions are about
    VERIFIERS, not about issuers.
  * The RSA key is 2048-bit and generated in software with no hardware backing. It is a
    lab key and it is thrown away. Do not reuse it, do not commit it, and do not draw
    conclusions about key management from it -- that is 49-KeyStore's subject.
  * The weak HMAC secret is weak ON PURPOSE. Its crackability is a fact about this lab,
    not evidence about any product.

SAFETY
  --workdir must be outside the repository. The script refuses to run inside a directory
  that contains a `.git` folder or a `STYLE-GUIDE.md`, because committing a private key
  is the one mistake this chapter cannot recover from. Every byte it writes is throwaway.

Chapter 46 — Tokens
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time

RSA_KID = "rsa-2026-08"
HS_KID = "hs-legacy"

# The secret a human chose. Nine characters, one capital, one digit, one symbol --
# it passes a corporate password policy and it is in rockyou.txt. An HMAC key is
# not a password; see README section 5.4.
LEGACY_SECRET = b"Passw0rd!"

ISSUER = "https://issuer.lab.local"
AUDIENCE = "com.pentest.ch46.client"
OTHER_AUDIENCE = "com.pentest.ch46.otherapp"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def json_segment(obj) -> str:
    """Serialise compactly, exactly as a real issuer does.

    separators=(",", ":") removes the spaces json.dumps inserts by default. This is not
    cosmetic: the signature covers the exact bytes of the base64url segments, so a
    verifier that re-serialises the parsed JSON and signs that will produce a different
    signature over semantically identical claims. Never re-serialise a JWT you intend to
    verify; sign and verify the bytes you received.
    """
    return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def guard_workdir(workdir):
    """Refuse to write key material into anything that looks like a repository."""
    probe = os.path.abspath(workdir)
    for _ in range(6):
        if os.path.isdir(os.path.join(probe, ".git")) or \
           os.path.isfile(os.path.join(probe, "STYLE-GUIDE.md")):
            sys.exit(f"refusing to write key material inside a repository: {probe}\n"
                     f"choose a --workdir outside it, for example your system temp dir.")
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent


def init(workdir):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    for sub in ("keys", "private", "public", "tokens"):
        os.makedirs(os.path.join(workdir, sub), exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)

    write(os.path.join(workdir, "private", "issuer.pem"), priv_pem)
    write(os.path.join(workdir, "keys", RSA_KID), pub_pem)
    write(os.path.join(workdir, "keys", "issuer-public.pem"), pub_pem)
    write(os.path.join(workdir, "keys", HS_KID), LEGACY_SECRET)

    # The published key set. In a real deployment this is served over HTTPS from
    # the issuer's /jwks endpoint and anybody at all may fetch it. Treat these bytes
    # as public knowledge in every threat model -- that assumption is what makes the
    # HS/RS confusion attack work.
    numbers = key.public_key().public_numbers()

    def uint_b64(value):
        length = (value.bit_length() + 7) // 8
        return b64url(value.to_bytes(length, "big"))

    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": RSA_KID,
                      "n": uint_b64(numbers.n), "e": uint_b64(numbers.e)}]}
    write(os.path.join(workdir, "public", "jwks.json"),
          json.dumps(jwks, indent=2, sort_keys=True).encode("utf-8"))

    print(f"[+] workdir      {os.path.abspath(workdir)}")
    print(f"[+] RSA keypair  2048-bit, kid={RSA_KID}, thrown away when you delete the workdir")
    print(f"[+] HMAC secret  kid={HS_KID}, {len(LEGACY_SECRET)} bytes -- deliberately weak")
    print(f"[+] JWKS         public/jwks.json ({os.path.getsize(os.path.join(workdir, 'public', 'jwks.json'))} bytes)")
    print("[!] Every token minted from this workdir is yours. Do not put any other "
          "token near these tools.")


def write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def sign_rs256(workdir, header, claims):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    with open(os.path.join(workdir, "private", "issuer.pem"), "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    signing_input = f"{json_segment(header)}.{json_segment(claims)}".encode("ascii")
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{b64url(sig)}"


def sign_hs256(header, claims, secret=LEGACY_SECRET):
    signing_input = f"{json_segment(header)}.{json_segment(claims)}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{signing_input.decode('ascii')}.{b64url(sig)}"


def mint(workdir, family="rs", sub="alice", role="user", ttl=900,
         audience=AUDIENCE, issuer=ISSUER, issued_at=None, extra=None):
    """Mint one token. Returns the compact serialisation."""
    now = int(time.time()) if issued_at is None else int(issued_at)
    claims = {
        "iss": issuer,
        "sub": sub,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + int(ttl),
        "jti": b64url(os.urandom(12)),
        "role": role,
        "scope": "notes.read" if role == "user" else "notes.read notes.write admin",
    }
    if extra:
        claims.update(extra)
    if family == "rs":
        header = {"alg": "RS256", "typ": "JWT", "kid": RSA_KID}
        return sign_rs256(workdir, header, claims)
    header = {"alg": "HS256", "typ": "JWT", "kid": HS_KID}
    return sign_hs256(header, claims)


def show(workdir):
    for root, _dirs, files in os.walk(workdir):
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, workdir)
            print(f"{os.path.getsize(path):>7}  {rel}")


def main():
    ap = argparse.ArgumentParser(description="Local JWT issuer for chapter 46's gauntlet.")
    ap.add_argument("--workdir", required=True, help="throwaway directory, OUTSIDE the repo")
    ap.add_argument("--init", action="store_true", help="generate key material")
    ap.add_argument("--mint", action="store_true", help="mint one token to stdout")
    ap.add_argument("--show", action="store_true", help="list the workdir")
    ap.add_argument("--family", choices=("rs", "hs"), default="rs")
    ap.add_argument("--sub", default="alice")
    ap.add_argument("--role", default="user")
    ap.add_argument("--ttl", type=int, default=900, help="seconds until exp")
    ap.add_argument("--audience", default=AUDIENCE)
    ap.add_argument("--issuer", default=ISSUER)
    ap.add_argument("--out", help="also write the token to this file")
    args = ap.parse_args()

    guard_workdir(args.workdir)

    if args.init:
        init(args.workdir)
    if args.mint:
        token = mint(args.workdir, args.family, args.sub, args.role,
                     args.ttl, args.audience, args.issuer)
        print(token)
        if args.out:
            write(args.out, token.encode("ascii"))
    if args.show:
        show(args.workdir)
    if not (args.init or args.mint or args.show):
        ap.error("give at least one of --init, --mint, --show")
    return 0


if __name__ == "__main__":
    sys.exit(main())
