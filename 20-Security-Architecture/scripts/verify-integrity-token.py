#!/usr/bin/env python3
"""
verify-integrity-token.py
===============================================================================
PURPOSE
  Demonstrate, as running code, the *server side* of an integrity verdict --
  the half that chapter 20 argues is the only half that carries security
  weight. It implements the five checks a backend must perform on a
  Play-Integrity-style token, in the order it must perform them, and it fails
  loudly and specifically when one of them is skipped.

  It exists because the difference between a sound and an unsound integrity
  design is not visible in the app. It is visible here, in about 200 lines,
  and reading those lines is faster than reading the argument.

  Two audiences:
    - Developers: this is the shape your backend must have. Compare it with
      what yours actually does.
    - Pentesters: use `decode` to see exactly what an attacker sees in a
      captured token, and `selftest` to rehearse the four attacks you will run
      against a client's backend (replay, cross-app token, stale token,
      forged signature).

USAGE
  # host -- issue a single-use nonce, the way your server must
  ./verify-integrity-token.py issue-nonce --session s-1001 --operation transfer

  # host -- look inside a captured token WITHOUT verifying it (recon)
  ./verify-integrity-token.py decode --token-file captured.jwt

  # host -- the full server-side check chain
  ./verify-integrity-token.py verify --token-file captured.jwt \\
      --session s-1001 --operation transfer \\
      --package com.example.app --secret-file hs256.key --max-age 300

  # host -- asymmetric verification (the correct direction; see NOTES)
  ./verify-integrity-token.py verify --token-file captured.jwt \\
      --session s-1001 --operation transfer \\
      --package com.example.app --pubkey-file server-verify.pem

  # host -- prove each check catches its attack, offline, no device needed
  ./verify-integrity-token.py selftest

REQUIREMENTS
  Python 3.8+. No dependencies for HS256 (stdlib hmac/hashlib only).
  ES256/RS256/EdDSA verification additionally needs `pip install cryptography`;
  without it, those algorithms are refused rather than silently skipped.
  EdDSA is the algorithm ../examples/integrity-backend.js uses, so the two
  tools verify each other's tokens.
  A writable nonce store (default ./nonce-store.json).

WHAT THIS WILL *NOT* TELL YOU
  - It does not talk to Google. A genuine Play Integrity token is encrypted and
    signed by Google and is decoded by the server-to-server
    `playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken` call.
    This script models the *checks around* that call -- nonce, package,
    freshness, verdict policy -- which is where real implementations fail.
    It cannot decrypt or validate a real Play token, and pretending otherwise
    would teach the wrong lesson.
  - It cannot tell you whether the device was honest. No software can. It can
    only tell you whether the *statement about* the device was produced by a
    party you trust, bound to a request you made, recently.
  - A PASS here says your verification logic is well formed. It says nothing
    about the strength of the underlying attestation, which depends on
    hardware you do not control and on keys that have, historically, leaked.
  - It does not test your backend over the network. Point it at a token you
    captured; it will not exercise your endpoints for you.
===============================================================================
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

DEFAULT_STORE = "nonce-store.json"

# Verdicts a typical backend accepts for a high-value operation. Policy, not
# gospel: a browse-only operation may reasonably accept MEETS_BASIC_INTEGRITY.
ACCEPTABLE_DEVICE_VERDICTS = {"MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"}


# ---------------------------------------------------------------------------
# base64url helpers -- JWS uses unpadded base64url, which trips people up
# ---------------------------------------------------------------------------

def b64u_decode(s):
    if isinstance(s, str):
        s = s.encode("ascii")
    pad = b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Nonce store -- the single-use property lives here, not in the token
# ---------------------------------------------------------------------------

class NonceStore(object):
    """A deliberately boring single-use nonce store.

    The security property is 'consume', not 'lookup'. A store that only checks
    membership without deleting the entry gives you replay for free, which is
    the single most common way this design is got wrong.
    """

    def __init__(self, path):
        self.path = path
        self.data = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)

    def _flush(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def issue(self, session, operation, ttl_seconds=300):
        nonce = b64u_encode(secrets.token_bytes(32))
        self.data[nonce] = {
            "session": session,
            "operation": operation,
            "issued_at": int(time.time()),
            "expires_at": int(time.time()) + ttl_seconds,
        }
        self._flush()
        return nonce

    def consume(self, nonce):
        """Returns the record and REMOVES it. Second call for the same nonce
        returns None, which is what makes replay fail."""
        rec = self.data.pop(nonce, None)
        if rec is not None:
            self._flush()
        return rec


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def verify_signature(header, signing_input, signature, secret=None, pubkey_pem=None):
    """Return (ok, detail). Refuses anything it cannot check properly."""
    alg = header.get("alg")

    if alg is None:
        return False, "token header has no 'alg'"

    if alg.lower() == "none":
        # The classic JWT bug. Refuse explicitly rather than falling through.
        return False, "alg=none: unsigned token offered as if it were signed"

    if alg == "HS256":
        if secret is None:
            return False, "HS256 token but no --secret-file given"
        expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            return False, "HS256 signature mismatch"
        return True, ("HS256 signature valid -- but see NOTES: a symmetric key "
                      "the client also holds proves nothing about the client")

    if alg in ("ES256", "RS256", "EdDSA"):
        if pubkey_pem is None:
            return False, "%s token but no --pubkey-file given" % alg
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            return False, ("%s requires `pip install cryptography`; refusing to "
                           "skip the check" % alg)
        key = serialization.load_pem_public_key(pubkey_pem)
        try:
            if alg == "ES256":
                # JWS ES256 is raw r||s; the library wants DER.
                half = len(signature) // 2
                r = int.from_bytes(signature[:half], "big")
                s = int.from_bytes(signature[half:], "big")
                der = utils.encode_dss_signature(r, s)
                key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            elif alg == "EdDSA":
                # Ed25519: raw 64-byte signature, no hash parameter. This is
                # what ../examples/integrity-backend.js produces.
                key.verify(signature, signing_input)
            else:
                key.verify(signature, signing_input,
                           padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return False, "%s signature mismatch" % alg
        return True, "%s signature valid" % alg

    return False, "unsupported alg %r -- refusing rather than guessing" % alg


# ---------------------------------------------------------------------------
# The check chain
# ---------------------------------------------------------------------------

class Result(object):
    def __init__(self):
        self.checks = []
        self.allowed = False

    def add(self, name, ok, detail):
        self.checks.append((name, ok, detail))
        return ok

    def render(self):
        width = max(len(n) for n, _, _ in self.checks)
        for name, ok, detail in self.checks:
            print("  [%s] %-*s  %s" % ("PASS" if ok else "FAIL", width, name, detail))
        print()
        print("  VERDICT: %s" % ("ALLOW" if self.allowed else "DENY"))


def split_token(token):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("expected three dot-separated parts, got %d" % len(parts))
    header = json.loads(b64u_decode(parts[0]))
    payload = json.loads(b64u_decode(parts[1]))
    signature = b64u_decode(parts[2])
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    return header, payload, signature, signing_input


def verify(token, store, session, operation, package, secret, pubkey_pem,
           max_age, require_verdict=True):
    r = Result()

    try:
        header, payload, signature, signing_input = split_token(token)
    except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
        r.add("1. token is well formed", False, str(exc))
        return r
    r.add("1. token is well formed", True, "alg=%s" % header.get("alg"))

    # 2. Signature FIRST. Never read a claim you have not authenticated.
    ok, detail = verify_signature(header, signing_input, signature, secret, pubkey_pem)
    if not r.add("2. signature verifies", ok, detail):
        return r

    req = payload.get("requestDetails", {})

    # 3. Package binding. Without it, a token minted for any other application
    #    -- including one the attacker legitimately controls -- is accepted.
    got_pkg = req.get("requestPackageName")
    r.add("3. package binding", got_pkg == package,
          "requestPackageName=%r expected=%r" % (got_pkg, package))

    # 4. Freshness. Without it, one clean-device token is valid forever.
    ts = req.get("timestampMillis")
    if ts is None:
        r.add("4. freshness", False, "no timestampMillis in requestDetails")
    else:
        age = time.time() - (int(ts) / 1000.0)
        r.add("4. freshness", 0 <= age <= max_age,
              "token age %.1fs (limit %ds)" % (age, max_age))

    # 5. Nonce: issued by US, for THIS session and operation, not yet used.
    nonce = req.get("nonce")
    rec = store.consume(nonce) if nonce else None
    if rec is None:
        r.add("5. nonce is ours and unused", False,
              "unknown or already-consumed nonce %r" % nonce)
    else:
        bound = rec.get("session") == session and rec.get("operation") == operation
        expired = time.time() > rec.get("expires_at", 0)
        r.add("5. nonce is ours and unused", bound and not expired,
              "session=%r operation=%r%s"
              % (rec.get("session"), rec.get("operation"),
                 " (nonce expired)" if expired else ""))

    # 6. Only now is it meaningful to read the verdict.
    verdicts = set(payload.get("deviceIntegrity", {})
                          .get("deviceRecognitionVerdict", []))
    if require_verdict:
        r.add("6. device verdict acceptable",
              bool(verdicts & ACCEPTABLE_DEVICE_VERDICTS),
              "verdicts=%s acceptable=%s"
              % (sorted(verdicts) or "[] (empty set is a signal, not an error)",
                 sorted(ACCEPTABLE_DEVICE_VERDICTS)))
    else:
        r.add("6. device verdict acceptable", True,
              "policy: not required for this operation (verdicts=%s)"
              % (sorted(verdicts) or "[]"))

    r.allowed = all(ok for _, ok, _ in r.checks)
    return r


# ---------------------------------------------------------------------------
# Self-test: each attack, and the check that stops it
# ---------------------------------------------------------------------------

def mint_hs256(secret, package, nonce, ts_millis, verdicts):
    """Test-fixture minting only. This is NOT how a real token is produced --
    and the fact that anyone holding `secret` can do it in six lines is exactly
    why a symmetric key shipped in an APK is not an attestation."""
    header = b64u_encode(json.dumps({"alg": "HS256", "typ": "JWT"},
                                    separators=(",", ":")).encode())
    payload = b64u_encode(json.dumps({
        "requestDetails": {"requestPackageName": package,
                           "timestampMillis": ts_millis,
                           "nonce": nonce},
        "deviceIntegrity": {"deviceRecognitionVerdict": verdicts},
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED"},
    }, separators=(",", ":")).encode())
    si = (header + "." + payload).encode("ascii")
    sig = b64u_encode(hmac.new(secret, si, hashlib.sha256).digest())
    return header + "." + payload + "." + sig


def selftest():
    secret = b"self-test-key-not-a-real-one"
    pkg = "com.example.app"
    store_path = "selftest-nonce-store.json"
    if os.path.exists(store_path):
        os.remove(store_path)
    store = NonceStore(store_path)
    now = int(time.time() * 1000)

    scenarios = []

    n1 = store.issue("s-1", "transfer")
    scenarios.append((
        "honest token",
        mint_hs256(secret, pkg, n1, now, ["MEETS_DEVICE_INTEGRITY"]),
        "s-1", "transfer", True))

    n2 = store.issue("s-2", "transfer")
    replay = mint_hs256(secret, pkg, n2, now, ["MEETS_DEVICE_INTEGRITY"])
    scenarios.append(("replay, first use", replay, "s-2", "transfer", True))
    scenarios.append(("replay, second use -- stopped by check 5",
                      replay, "s-2", "transfer", False))

    n3 = store.issue("s-3", "transfer")
    scenarios.append((
        "token minted for another app -- stopped by check 3",
        mint_hs256(secret, "com.attacker.other", n3, now,
                   ["MEETS_DEVICE_INTEGRITY"]),
        "s-3", "transfer", False))

    n4 = store.issue("s-4", "transfer")
    scenarios.append((
        "token from two hours ago -- stopped by check 4",
        mint_hs256(secret, pkg, n4, now - 2 * 3600 * 1000,
                   ["MEETS_DEVICE_INTEGRITY"]),
        "s-4", "transfer", False))

    n5 = store.issue("s-5", "transfer")
    scenarios.append((
        "signed with the wrong key -- stopped by check 2",
        mint_hs256(b"attacker-guessed-this", pkg, n5, now,
                   ["MEETS_DEVICE_INTEGRITY"]),
        "s-5", "transfer", False))

    n6 = store.issue("s-6", "transfer")
    unsigned = mint_hs256(secret, pkg, n6, now, ["MEETS_DEVICE_INTEGRITY"])
    h, p, _ = unsigned.split(".")
    h = b64u_encode(json.dumps({"alg": "none", "typ": "JWT"},
                               separators=(",", ":")).encode())
    scenarios.append((
        "alg=none -- stopped by check 2",
        h + "." + p + ".", "s-6", "transfer", False))

    n7 = store.issue("s-7", "transfer")
    scenarios.append((
        "nonce bound to a different operation -- stopped by check 5",
        mint_hs256(secret, pkg, n7, now, ["MEETS_DEVICE_INTEGRITY"]),
        "s-7", "login", False))

    n8 = store.issue("s-8", "transfer")
    scenarios.append((
        "empty verdict set (rooted / unlocked) -- stopped by check 6",
        mint_hs256(secret, pkg, n8, now, []),
        "s-8", "transfer", False))

    failures = 0
    for name, token, session, operation, expect_allow in scenarios:
        print("-" * 72)
        print(name)
        try:
            r = verify(token, store, session, operation, pkg, secret, None, 300)
        except ValueError as exc:
            print("  [FAIL] token did not parse: %s" % exc)
            failures += 1
            continue
        r.render()
        if r.allowed != expect_allow:
            print("  !! UNEXPECTED: expected %s"
                  % ("ALLOW" if expect_allow else "DENY"))
            failures += 1
        print()

    os.remove(store_path)
    print("=" * 72)
    print("selftest: %d scenario(s) behaved unexpectedly" % failures)
    return 0 if failures == 0 else 2


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def main(argv):
    ap = argparse.ArgumentParser(
        description="Server-side integrity-token verification, as running code.")
    ap.add_argument("mode", choices=["issue-nonce", "decode", "verify", "selftest"])
    ap.add_argument("--store", default=DEFAULT_STORE, help="nonce store JSON path")
    ap.add_argument("--session")
    ap.add_argument("--operation")
    ap.add_argument("--package")
    ap.add_argument("--token")
    ap.add_argument("--token-file")
    ap.add_argument("--secret-file", help="raw bytes of the HS256 key")
    ap.add_argument("--pubkey-file", help="PEM public key for ES256/RS256")
    ap.add_argument("--max-age", type=int, default=300,
                    help="freshness window in seconds (default 300)")
    ap.add_argument("--no-verdict-required", action="store_true",
                    help="policy: allow a failing device for a low-value operation")
    args = ap.parse_args(argv)

    if args.mode == "selftest":
        return selftest()

    if args.mode == "issue-nonce":
        if not (args.session and args.operation):
            ap.error("issue-nonce needs --session and --operation")
        store = NonceStore(args.store)
        print(store.issue(args.session, args.operation))
        return 0

    token = args.token
    if args.token_file:
        token = read_bytes(args.token_file).decode("ascii").strip()
    if not token:
        ap.error("give --token or --token-file")

    if args.mode == "decode":
        header, payload, signature, _ = split_token(token)
        print("# NOT VERIFIED. This is precisely what an attacker sees, and")
        print("# what an app that decodes the token on-device is trusting.")
        print(json.dumps({"header": header, "payload": payload,
                          "signature_bytes": len(signature)}, indent=2))
        return 0

    if not (args.session and args.operation and args.package):
        ap.error("verify needs --session, --operation and --package")

    secret = read_bytes(args.secret_file) if args.secret_file else None
    pubkey = read_bytes(args.pubkey_file) if args.pubkey_file else None
    store = NonceStore(args.store)

    r = verify(token, store, args.session, args.operation, args.package,
               secret, pubkey, args.max_age,
               require_verdict=not args.no_verdict_required)
    r.render()
    return 0 if r.allowed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
