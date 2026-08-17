#!/usr/bin/env python3
"""
labs/ctf/ledger_api.py — the deliberately vulnerable backend for Lab 04's CTF.

PURPOSE
  This is "Ledger", a note-keeping service. It plays two roles that a real deployment
  would separate, because separating them here would double the setup for no teaching
  benefit:

      /token          the authorization server's token endpoint (refresh grant)
      /api/*          the resource server, which verifies access tokens

  Four flaws are planted. Each is real, each has been found in production, and each fails
  at a DIFFERENT layer, which is the whole point of the CTF: the flag is reachable four
  ways and the participant must be able to name which control failed for each.

      FLAW A  a departed user's refresh token was never revoked  (process + AS)
      FLAW B  the access-token verifier dispatches on the token's own `alg`  (RS)
      FLAW C  the refresh grant does not intersect requested scope with granted scope (AS)
      FLAW D  the access-token verifier never examines `exp`  (RS)

  None of the four requires breaking any cryptography. Two of them require no forgery at
  all. That distribution is deliberate and mirrors what real engagements find.

USAGE
  # 1. Create key material with the chapter's issuer (this file does NOT generate keys)
  python3 -B ../gauntlet/issuer.py --workdir ~/ch46-ctf --init

  # 2. Seed the CTF state -- accounts, notes, the flag, and the departed user's tokens
  python3 -B ledger_api.py --workdir ~/ch46-ctf --seed

  # 3. Run it
  python3 -B ledger_api.py --workdir ~/ch46-ctf

  # 4. It listens on 127.0.0.1:9200 ONLY. See the SAFETY note.
  curl -s http://127.0.0.1:9200/.well-known/openid-configuration | jq .
  curl -s http://127.0.0.1:9200/jwks | jq .

REQUIREMENTS
  Python 3.8+, flask, cryptography.  pip install flask cryptography
  No PyJWT: the verification is written out by hand so the flaws are visible rather than
  hidden behind a library's options dictionary.

WHAT THIS WILL NOT TELL YOU
  * Nothing here says anything about any real authorization server. Its behaviour is
    whatever this file says it is. The CTF teaches you what each attack LOOKS LIKE so you
    can recognise it elsewhere; it is not evidence about anybody's product.
  * It implements no authorization-code flow, no PKCE, no redirect handling and no
    consent. 45-OAuth owns all of that and its CTF already covers it -- see
    45-OAuth/labs/lab-04-ctf-the-borrowed-identity.md. This one starts after the flow.
  * It does not model refresh-token rotation correctly even in its "fixed" mode. Rotation
    is chapter 46 section 3.9; here the refresh token is deliberately static, which IS
    flaw A.

SAFETY
  * Binds to 127.0.0.1 only, and refuses to start on 0.0.0.0. A deliberately vulnerable
    token endpoint reachable from a network is a genuine hazard, not a teaching aid.
  * Every token it issues is minted from the throwaway keypair in --workdir, which the
    chapter's issuer generates fresh and which you delete when you are done.
  * It contains no real credentials. The "departed employee" is fictional and their
    password is a random value nobody, including the participant, ever sees.

Chapter 46 — Tokens
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

try:
    from flask import Flask, jsonify, request
except ImportError:                                            # pragma: no cover
    sys.exit("pip install flask cryptography")

ISSUER = "https://issuer.lab.local"
AUDIENCE = "com.pentest.ch46.ledger"
RSA_KID = "rsa-2026-08"

app = Flask(__name__)
WORKDIR = None
STATE = {}


# --------------------------------------------------------------------------- #
# Encoding helpers -- identical to the issuer's, so the two agree byte for byte
# --------------------------------------------------------------------------- #
def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def seg(obj) -> str:
    return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def sign_rs256(header, claims):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    with open(os.path.join(WORKDIR, "private", "issuer.pem"), "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    si = f"{seg(header)}.{seg(claims)}".encode("ascii")
    return f"{si.decode()}.{b64url(key.sign(si, padding.PKCS1v15(), hashes.SHA256()))}"


def public_pem():
    with open(os.path.join(WORKDIR, "keys", RSA_KID), "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# THE VERIFIER. This is the vulnerable one. Read it beside
# examples/02-correct-verifier.py.
# --------------------------------------------------------------------------- #
def verify_access_token(token):
    """Return (claims, None) or (None, reason)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, "not a three-segment JWT"
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(payload_b64))
    except Exception:                                          # noqa: BLE001
        return None, "malformed segment"

    si = f"{header_b64}.{payload_b64}".encode("ascii")

    # ----------------------------------------------------------------------- #
    # FLAW B: the algorithm comes from the token, and ONE key blob serves both
    # families. The RSA public key is published at /jwks, so anybody can fetch it
    # and use it as an HMAC secret. Chapter 46 section 5.2.
    #
    # Note what IS done correctly here, because it is why this survives review:
    # alg=none is explicitly rejected. Somebody read about the famous attack and
    # patched exactly that one string. The structural problem is untouched.
    # ----------------------------------------------------------------------- #
    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        return None, "alg=none rejected"                        # they fixed THIS one

    key_material = public_pem()

    if alg.upper().startswith("HS"):
        expected = b64url(hmac.new(key_material, si, hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig_b64):
            return None, "HS signature mismatch"
    elif alg.upper().startswith("RS"):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        try:
            pub = serialization.load_pem_public_key(key_material)
            pub.verify(b64url_decode(sig_b64), si, padding.PKCS1v15(), hashes.SHA256())
        except Exception:                                      # noqa: BLE001
            return None, "RS signature invalid"
    else:
        return None, f"unsupported alg {alg}"

    # iss IS checked. aud IS checked. Somebody did read the guidance.
    if claims.get("iss") != ISSUER:
        return None, "iss mismatch"
    aud = claims.get("aud")
    aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if AUDIENCE not in aud_list:
        return None, "aud mismatch"

    # ----------------------------------------------------------------------- #
    # FLAW D: `exp` is never examined.
    #
    # There is no code here. That is the vulnerability, and it is invisible to
    # anyone reviewing by asking "does it verify the signature?" -- because it
    # does, and it checks iss and aud too, which makes it look thorough.
    # Chapter 46 section 5.5.
    # ----------------------------------------------------------------------- #

    return claims, None


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.route("/.well-known/openid-configuration")
def discovery():
    base = "http://127.0.0.1:9200"
    return jsonify({
        "issuer": ISSUER,
        "token_endpoint": f"{base}/token",
        "jwks_uri": f"{base}/jwks",
        "revocation_endpoint": f"{base}/revoke",
        "grant_types_supported": ["refresh_token"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["notes.read", "notes.write", "admin"],
    })


@app.route("/jwks")
def jwks():
    """The published key set. These bytes are meant to be world-readable.

    That is not a flaw -- it is how asymmetric signing works, and it is exactly why
    FLAW B is a flaw: a value that is CORRECTLY public becomes a symmetric secret
    the moment a verifier picks its primitive from the token.
    """
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(public_pem())
    n = pub.public_numbers().n
    e = pub.public_numbers().e
    def uint(v):
        return b64url(v.to_bytes((v.bit_length() + 7) // 8, "big"))
    return jsonify({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                              "kid": RSA_KID, "n": uint(n), "e": uint(e)}]})


@app.route("/token", methods=["POST"])
def token_endpoint():
    if request.form.get("grant_type") != "refresh_token":
        return jsonify({"error": "unsupported_grant_type"}), 400

    rt = request.form.get("refresh_token", "")
    record = STATE["refresh_tokens"].get(rt)
    if record is None:
        return jsonify({"error": "invalid_grant"}), 400

    # ----------------------------------------------------------------------- #
    # FLAW A: `revoked` is set at offboarding by a process that was never wired up.
    # The field exists, it is checked, and nothing ever writes it. That shape --
    # a control that is present, correct, and never triggered -- is far more common
    # than a control that is absent, and much harder to spot in a code review.
    # Chapter 46 section 3.10.
    # ----------------------------------------------------------------------- #
    if record.get("revoked"):
        return jsonify({"error": "invalid_grant", "error_description": "revoked"}), 400

    # ----------------------------------------------------------------------- #
    # FLAW C: the requested scope is used AS IS.
    #
    # RFC 6749 section 6 says the scope requested on a refresh MUST NOT exceed the
    # scope of the original grant. This line does not intersect; it substitutes.
    # Ask for `admin` and you get `admin`, with no user interaction of any kind.
    # Chapter 46 section 3.12 covers the same failure at the token-exchange endpoint.
    # ----------------------------------------------------------------------- #
    scope = request.form.get("scope") or record["scope"]

    now = int(time.time())
    claims = {
        "iss": ISSUER, "sub": record["sub"], "aud": AUDIENCE,
        "iat": now, "nbf": now, "exp": now + 900,
        "jti": b64url(os.urandom(12)), "scope": scope,
    }
    return jsonify({
        "access_token": sign_rs256({"alg": "RS256", "typ": "at+jwt", "kid": RSA_KID}, claims),
        "token_type": "Bearer",
        "expires_in": 900,
        "scope": scope,
        # No new refresh_token: rotation is off. That absence is itself a finding
        # and it is what makes FLAW A permanent rather than merely late.
    })


@app.route("/revoke", methods=["POST"])
def revoke():
    """RFC 7009. It works. Nothing in the offboarding process ever calls it."""
    rt = request.form.get("token", "")
    if rt in STATE["refresh_tokens"]:
        STATE["refresh_tokens"][rt]["revoked"] = True
    return "", 200                                    # RFC 7009: 200 even on unknown


def _auth():
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None, "no bearer token"
    return verify_access_token(header[7:].strip())


@app.route("/api/notes")
def notes():
    claims, err = _auth()
    if err:
        return jsonify({"error": err}), 401
    sub = claims.get("sub")
    return jsonify({"sub": sub, "scope": claims.get("scope"),
                    "notes": STATE["notes"].get(sub, [])})


@app.route("/api/admin/audit")
def audit():
    claims, err = _auth()
    if err:
        return jsonify({"error": err}), 401
    # Scope IS enforced here. This endpoint is not the weak one; the token endpoint
    # that will hand you the scope for free is.
    if "admin" not in str(claims.get("scope", "")).split():
        return jsonify({"error": "insufficient_scope"}), 403
    return jsonify({"audit": STATE["audit"]})


@app.route("/api/whoami")
def whoami():
    claims, err = _auth()
    if err:
        return jsonify({"error": err}), 401
    return jsonify(claims)


# --------------------------------------------------------------------------- #
# Seeding
# --------------------------------------------------------------------------- #
def seed(workdir):
    """Create the CTF state and the 'device backup' artefact the participant starts with."""
    flag = "LAB{a_token_is_a_cached_decision_and_nobody_invalidated_the_cache}"
    departed_rt = "rt_" + secrets.token_urlsafe(24)
    current_rt = "rt_" + secrets.token_urlsafe(24)

    state = {
        "refresh_tokens": {
            # The departed employee. Offboarded 14 months ago. Never revoked.
            departed_rt: {"sub": "j.mercer", "scope": "notes.read", "revoked": False},
            # A current employee, for comparison.
            current_rt: {"sub": "researcher", "scope": "notes.read", "revoked": False},
        },
        "notes": {
            "researcher": ["shopping list: milk, bread"],
            "j.mercer": ["handover doc: see audit log for the recovery phrase"],
        },
        "audit": [
            {"ts": "2025-06-02", "event": "j.mercer offboarded; laptop and phone returned"},
            {"ts": "2025-06-02", "event": "AD account disabled"},
            {"ts": "2025-06-02", "event": "TODO: revoke API tokens -- ticket LEDGER-4471"},
            {"ts": "2026-08-12", "event": f"recovery phrase: {flag}"},
        ],
    }
    with open(os.path.join(workdir, "ctf-state.json"), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)

    # The artefact the participant is handed: a SharedPreferences file recovered from
    # the returned handset. It contains a year-old access token and the refresh token.
    old = int(time.time()) - 400 * 24 * 3600
    global WORKDIR
    WORKDIR = workdir
    stale_at = sign_rs256(
        {"alg": "RS256", "typ": "at+jwt", "kid": RSA_KID},
        {"iss": ISSUER, "sub": "j.mercer", "aud": AUDIENCE, "iat": old, "nbf": old,
         "exp": old + 900, "jti": b64url(os.urandom(12)), "scope": "notes.read"})

    backup = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="access_token">{stale_at}</string>
    <string name="refresh_token">{departed_rt}</string>
    <long name="expires_at" value="{(old + 900) * 1000}" />
    <string name="account">j.mercer</string>
</map>
"""
    path = os.path.join(workdir, "recovered-auth.xml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(backup)

    print(f"[+] state    {os.path.join(workdir, 'ctf-state.json')}")
    print(f"[+] artefact {path}")
    print("[+] Give the participant ONLY recovered-auth.xml and the hostname.")
    print("[!] ctf-state.json contains the flag. Instructors only.")


def main():
    global WORKDIR, STATE
    ap = argparse.ArgumentParser(description="Ledger -- chapter 46 CTF backend.")
    ap.add_argument("--workdir", required=True, help="the issuer's workdir, OUTSIDE the repo")
    ap.add_argument("--seed", action="store_true", help="create state and the artefact")
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    WORKDIR = args.workdir
    if not os.path.isdir(os.path.join(WORKDIR, "private")):
        sys.exit(f"no key material in {WORKDIR}. Run:\n"
                 f"  python3 -B ../gauntlet/issuer.py --workdir {WORKDIR} --init")

    if args.seed:
        seed(WORKDIR)
        return 0

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("refusing to bind to anything but loopback. This service is "
                 "deliberately vulnerable and must not be reachable from a network.")

    with open(os.path.join(WORKDIR, "ctf-state.json"), encoding="utf-8") as fh:
        STATE = json.load(fh)

    print(f"[*] Ledger on http://{args.host}:{args.port}  (loopback only)")
    print("[*] Four flaws. Four paths. None of them requires breaking any cryptography.")
    app.run(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
