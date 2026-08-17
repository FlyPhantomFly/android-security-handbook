#!/usr/bin/env python3
# labs/ctf/vault_backend.py — the app's own API. Trusts the id_token it is given.
# Usage: pip install flask pyjwt cryptography requests && python3 vault_backend.py
# Listens on 0.0.0.0:9100.

import json, os, requests
from flask import Flask, request, jsonify
import jwt
from jwt import PyJWKClient

app = Flask(__name__)
ISSUER = os.environ.get("ISSUER", "http://10.0.2.2:9000")
MY_CLIENT_ID = "vaultnotes-android"

NOTES = {
    "researcher@lab.local": ["shopping list: milk, bread"],
    "victim@lab.local": ["LAB{aud_is_not_optional_and_neither_is_pkce}"],
}

@app.route("/api/v1/social-login", methods=["POST"])
def social_login():
    tok = request.json.get("id_token", "")
    jwks = PyJWKClient(f"{ISSUER}/jwks")
    key = jwks.get_signing_key_from_jwt(tok).key

    # The signature IS verified. iss IS checked. exp IS checked.
    # FLAW 3: `aud` is never checked. options={"verify_aud": False} is the entire bug.
    claims = jwt.decode(tok, key, algorithms=["RS256"], issuer=ISSUER,
                        options={"verify_aud": False})

    # And it keys the account on `email` rather than `sub`.
    return jsonify({"session": claims["email"], "notes": NOTES.get(claims["email"], [])})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9100)
