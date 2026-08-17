#!/usr/bin/env python3
# labs/ctf/mock_as.py — deliberately vulnerable OIDC authorisation server.
# Usage: pip install flask pyjwt cryptography && python3 mock_as.py
# Listens on 0.0.0.0:9000. NEVER expose this outside a lab network.

import base64, hashlib, json, os, secrets, time
from flask import Flask, request, redirect, jsonify
import jwt   # PyJWT

app = Flask(__name__)
ISSUER = os.environ.get("ISSUER", "http://10.0.2.2:9000")

# --- key material -----------------------------------------------------------
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIV = KEY.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption())

USERS = {"researcher@lab.local": "researcher", "victim@lab.local": secrets.token_hex(16)}

# Two registered clients. The second one is the whole point of FLAW 3.
CLIENTS = {
    "vaultnotes-android": {"redirect_uris": ["vaultnotes://oauth/callback"]},
    "photofilters-android": {"redirect_uris": ["photofilters://cb"]},   # anyone can register
}

CODES = {}       # code -> {sub, challenge, method, client_id, redirect_uri, nonce, used}

@app.route("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        # FLAW 1 (visible here if you look): `plain` is advertised.
        "code_challenge_methods_supported": ["S256", "plain"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "notes.read", "notes.write"],
    })

@app.route("/jwks")
def jwks():
    from jwt.algorithms import RSAAlgorithm
    pub = KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return jsonify({"keys": [json.loads(RSAAlgorithm.to_jwk(KEY.public_key())) | {"kid": "lab1"}]})

@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    if request.method == "GET":
        q = request.args
        return f"""<html><body><h2>LabID sign-in</h2>
        <p style="color:#666">client: {q.get('client_id')}</p>
        <form method="post">
          {''.join(f'<input type=hidden name={k} value="{v}">' for k, v in q.items())}
          <input name=u placeholder=email><input name=p type=password placeholder=password>
          <button>Sign in</button>
        </form></body></html>"""

    f = request.form
    if USERS.get(f.get("u")) != f.get("p"):
        return "bad credentials", 401

    code = secrets.token_urlsafe(24)
    CODES[code] = {
        "sub": f.get("u"),
        "challenge": f.get("code_challenge"),
        "method": f.get("code_challenge_method", "plain"),
        "client_id": f.get("client_id"),
        "redirect_uri": f.get("redirect_uri"),
        "nonce": f.get("nonce"),
        "used": False,
        "ts": time.time(),
    }
    sep = "&" if "?" in f.get("redirect_uri", "") else "?"
    return redirect(f"{f['redirect_uri']}{sep}code={code}&state={f.get('state','')}")

@app.route("/token", methods=["POST"])
def token():
    code = request.form.get("code")
    rec = CODES.get(code)
    if not rec:
        return jsonify({"error": "invalid_grant"}), 400

    # FLAW 2: the verifier is checked ONLY IF the client bothers to send one.
    # Omit code_verifier entirely and this whole block is skipped.
    verifier = request.form.get("code_verifier")
    if verifier is not None:
        if rec["method"] == "S256":
            calc = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
        else:
            calc = verifier                      # FLAW 1: `plain` accepted
        if calc != rec["challenge"]:
            return jsonify({"error": "invalid_grant"}), 400

    rec["used"] = True
    now = int(time.time())
    claims = {
        "iss": ISSUER, "sub": rec["sub"], "email": rec["sub"],
        "aud": rec["client_id"],          # correct here — the flaw is downstream
        "iat": now, "exp": now + 3600, "nonce": rec.get("nonce"),
    }
    id_token = jwt.encode(claims, PRIV, algorithm="RS256", headers={"kid": "lab1"})
    return jsonify({
        "access_token": secrets.token_urlsafe(32),
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "scope": "openid profile notes.read notes.write",
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
