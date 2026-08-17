#!/usr/bin/env python3
# 47-Authentication/labs/ctf/vault_auth.py
#
# ============================================================================
#  CTF BACKEND - "The account that would not close"
#  DELIBERATELY VULNERABLE. Loopback only. Every account is created by this
#  process. It talks to nothing and persists nothing.
# ============================================================================
#
# PURPOSE
#   The backend for lab-04. FOUR flags, reachable by FOUR INDEPENDENT PATHS,
#   each failing at a different layer of the authentication stack:
#
#     FLAG 1  the device layer      - a credential the client should not hold
#     FLAG 2  the login flow        - enumeration chained to a weak reset
#     FLAG 3  the session lifecycle - an intermediate credential with real power
#     FLAG 4  authorisation/privacy - deletion that deletes nothing
#
#   They are independent ON PURPOSE. A player who cannot get one can still get
#   the others, and - more importantly - each teaches that a different layer can
#   be the weakest one. The final question the lab asks is not "did you get the
#   flags" but "which of these would you have rated highest, and were you right".
#
# USAGE
#   python3 -B vault_auth.py                    # port 9047
#   python3 -B vault_auth.py --port 9100
#   python3 -B vault_auth.py --verify           # self-test: proves all 4 paths work
#   python3 -B vault_auth.py --spoilers         # print the solution (instructors)
#
#   Companion Android client: see lab-04. The client is NOT required - every
#   flag is reachable with curl alone - but FLAG 1 is much more natural with it.
#
# DEPENDENCIES
#   Standard library only.

import argparse
import hashlib
import hmac
import http.server
import json
import random
import re
import secrets
import socketserver
import sys
import threading
import time
import urllib.parse

PORT = 9047
LOCK = threading.RLock()

FLAGS = {
    1: "CH47{the_client_was_never_the_gate}",
    2: "CH47{reset_tokens_need_a_csprng_not_a_clock}",
    3: "CH47{half_authenticated_is_authenticated}",
    4: "CH47{deleted_from_the_app_is_not_deleted}",
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

USERS = {}
SESSIONS = {}
MFA = {}
RESETS = {}
DOCUMENTS = {}
AUDIT = []


def now():
    return time.time()


def h(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=1 << 13, r=8, p=1, dklen=32)


def seed():
    for uname, pw, mfa, role in (
        ("player@vault.invalid",  "player-password-1", False, "user"),
        ("dana@vault.invalid",    "sun-flower-tuesday", True,  "user"),
        ("ops@vault.invalid",     "9x!Kq2$vLmZ7wRt4",  True,  "admin"),
    ):
        salt = secrets.token_bytes(16)
        USERS[uname] = {
            "username": uname, "salt": salt, "verifier": h(pw, salt),
            "mfa_enabled": mfa, "role": role,
            "deleted": False,             # <- FLAG 4 lives here
            "created": now(),
        }

    for did, owner, title, body in (
        (4001, "player@vault.invalid", "Welcome",
         "Nothing sensitive here. Try another document id."),
        (4002, "dana@vault.invalid", "Handover notes",
         "Ops rotate the shared mailbox password every quarter."),
        (4711, "dana@vault.invalid", "ARCHIVED - closed account export",
         "Dana closed her account. This document was never removed. " + FLAGS[4]),
        (4900, "ops@vault.invalid", "Vault master record",
         "Restricted. " + FLAGS[3]),
    ):
        DOCUMENTS[did] = {"id": did, "owner": owner, "title": title, "body": body}

    # Dana has already "closed" her account before the CTF begins. The app shows
    # her as gone. The server does not agree.
    USERS["dana@vault.invalid"]["deleted"] = True


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def issue(username, scope):
    tok = secrets.token_urlsafe(24)
    SESSIONS[tok] = {"username": username, "scope": scope, "created": now()}
    return tok


def bearer(headers):
    a = headers.get("Authorization", "")
    return a[7:].strip() if a.lower().startswith("bearer ") else ""


def session_of(headers):
    """VULNERABILITY (FLAG 3): the scope is recorded and NEVER CHECKED.

    Every route that wants an authenticated caller uses this helper, and it
    accepts any live token regardless of what it was issued for. The MFA-scoped
    token handed out before the second factor is therefore a fully-powered
    session credential.

    This is the single most valuable shape in the CTF because it is invisible
    from the client: the app dutifully shows the OTP screen, the server dutifully
    says mfa_required, and the flow LOOKS correct from both ends.
    """
    return SESSIONS.get(bearer(headers))


def audit(event, **kw):
    AUDIT.append({"t": round(now(), 2), "event": event, **kw})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def r_login(body, headers):
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    user = USERS.get(username)

    # VULNERABILITY (FLAG 2, part 1): distinct responses. Note it is subtler
    # than the lab-02 server - the MESSAGE is identical, and the leak is in the
    # extra field. Players who only diff the "error" string will miss it.
    if user is None:
        return 401, {"error": "Invalid credentials"}

    if not hmac.compare_digest(h(password, user["salt"]), user["verifier"]):
        return 401, {"error": "Invalid credentials", "account_state": "active"}

    if user["mfa_enabled"]:
        tok = issue(username, scope="mfa")
        code = "%06d" % secrets.randbelow(1000000)
        MFA[tok] = {"code": code, "created": now(), "attempts": 0}
        audit("mfa_challenge", user=username)
        # The code is NOT returned. This is the one thing this server does right
        # on the login path, and it is deliberate: FLAG 3 must be reached through
        # the scope bug, not by reading the OTP out of a response.
        print("  [out-of-band] OTP for %s: %s" % (username, code))
        return 200, {"mfa_required": True, "mfa_token": tok}

    tok = issue(username, scope="session")
    audit("login", user=username)
    return 200, {"ok": True, "token": tok}


def r_mfa(body, headers):
    tok = str(body.get("mfa_token", ""))
    code = str(body.get("code", ""))
    ch = MFA.get(tok)
    if ch is None:
        return 400, {"error": "no challenge"}
    ch["attempts"] += 1
    if ch["attempts"] > 5:
        MFA.pop(tok, None)
        SESSIONS.pop(tok, None)
        return 429, {"error": "too many attempts"}
    if not hmac.compare_digest(code, ch["code"]):
        return 401, {"error": "incorrect code"}
    MFA.pop(tok, None)
    SESSIONS.pop(tok, None)
    real = issue(SESSIONS.get(tok, {}).get("username") or ch.get("username", ""), "session")
    return 200, {"ok": True, "token": real}


def r_me(body, headers):
    s = session_of(headers)
    if s is None:
        return 401, {"error": "unauthenticated"}
    u = USERS.get(s["username"])
    if u is None:
        return 404, {"error": "no such user"}
    return 200, {"username": u["username"], "role": u["role"],
                 "mfa_enabled": u["mfa_enabled"]}


def r_document(doc_id, body, headers):
    s = session_of(headers)
    if s is None:
        return 401, {"error": "unauthenticated"}
    d = DOCUMENTS.get(doc_id)
    if d is None:
        return 404, {"error": "not found"}
    # VULNERABILITY (FLAG 3 and FLAG 4): authenticated, never authorised.
    audit("document_read", user=s["username"], doc=doc_id, scope=s["scope"])
    return 200, d


def r_documents(body, headers):
    s = session_of(headers)
    if s is None:
        return 401, {"error": "unauthenticated"}
    mine = [{"id": d["id"], "title": d["title"]}
            for d in DOCUMENTS.values() if d["owner"] == s["username"]]
    return 200, {"documents": mine}


def r_reset_request(body, headers):
    username = str(body.get("username", ""))
    user = USERS.get(username)
    if user is None:
        # VULNERABILITY (FLAG 2, part 2): the enumeration oracle, again in a
        # field rather than a message.
        return 404, {"error": "Unable to process", "reason": "unknown_principal"}

    # VULNERABILITY (FLAG 2, part 3): java.util.Random's problem, in Python.
    # The token is derived from the clock with a NON-CRYPTOGRAPHIC generator,
    # seeded from the current second. Anyone who knows roughly when the request
    # was made can reproduce every token the server will ever issue in that
    # second. This is the single most common real reset-token defect.
    rng = random.Random(int(now()))
    token = "%08x" % rng.getrandbits(32)
    RESETS[token] = {"username": username, "created": now(), "used": False}
    audit("reset_request", user=username)
    print("  [out-of-band] reset token for %s: %s" % (username, token))
    return 200, {"status": "sent"}


def r_reset_confirm(body, headers):
    token = str(body.get("token", ""))
    new = str(body.get("new_password", ""))
    r = RESETS.get(token)
    if r is None:
        return 400, {"error": "invalid token"}
    if len(new) < 8:
        return 400, {"error": "password too short"}
    u = USERS[r["username"]]
    salt = secrets.token_bytes(16)
    u["salt"] = salt
    u["verifier"] = h(new, salt)
    r["used"] = True
    audit("reset_confirm", user=u["username"])
    # VULNERABILITY: sessions are not revoked, and MFA is silently DISABLED on
    # reset "so the user can get back in". A recovery flow that weakens the
    # account it recovers is a real and recurring pattern.
    u["mfa_enabled"] = False
    return 200, {"ok": True, "note": "two-factor authentication has been reset"}


def r_close_account(body, headers):
    s = session_of(headers)
    if s is None:
        return 401, {"error": "unauthenticated"}
    u = USERS[s["username"]]
    # VULNERABILITY (FLAG 4): "closing" sets a flag. Nothing is deleted, no
    # session is revoked, the documents remain, and - critically - the account
    # can still authenticate. The APP hides the account; the SERVER keeps it.
    u["deleted"] = True
    audit("account_closed", user=u["username"])
    return 200, {"ok": True, "message": "Your account has been closed and your "
                                        "data deleted."}


def r_status(body, headers):
    return 200, {
        "service": "vault-auth (ch47 CTF)",
        "hint": "GET /api/v1/status is the only unauthenticated route. "
                "There are four flags. Start with the app.",
        "documents_total": len(DOCUMENTS),
        "users_total": len(USERS),
    }


ROUTES = {
    ("POST", "/api/v1/login"):                  r_login,
    ("POST", "/api/v1/login/mfa"):              r_mfa,
    ("GET",  "/api/v1/me"):                     r_me,
    ("GET",  "/api/v1/documents"):              r_documents,
    ("POST", "/api/v1/password/reset-request"): r_reset_request,
    ("POST", "/api/v1/password/reset"):         r_reset_confirm,
    ("POST", "/api/v1/account/close"):          r_close_account,
    ("GET",  "/api/v1/status"):                 r_status,
}

DOC_RE = re.compile(r"^/api/v1/document/(\d+)$")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "vault-auth/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))

    def _respond(self, status, payload):
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _go(self, method):
        path = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw) if raw else {}
            if not isinstance(body, dict):
                body = {}
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return
        with LOCK:
            m = DOC_RE.match(path)
            if m and method == "GET":
                st, pl = r_document(int(m.group(1)), body, self.headers)
            else:
                fn = ROUTES.get((method, path))
                if fn is None:
                    self._respond(404, {"error": "no such route"})
                    return
                st, pl = fn(body, self.headers)
        self._respond(st, pl)

    def do_GET(self):
        self._go("GET")

    def do_POST(self):
        self._go("POST")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Self-verification. Every CTF in this repository must prove its own paths work
# before a player wastes an evening on a broken challenge.
# ---------------------------------------------------------------------------

def verify():
    import urllib.request
    import urllib.error

    base = "http://127.0.0.1:%d" % PORT
    ok = True

    def call(method, path, payload=None, token=None):
        data = json.dumps(payload).encode() if payload is not None else None
        hdr = {"Content-Type": "application/json"}
        if token:
            hdr["Authorization"] = "Bearer " + token
        req = urllib.request.Request(base + path, data=data, method=method, headers=hdr)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    print()
    print("SELF-VERIFICATION")
    print("-" * 66)

    # ---- FLAG 2: enumeration + predictable reset ---------------------------
    s1, b1 = call("POST", "/api/v1/password/reset-request",
                  {"username": "no-such-user@vault.invalid"})
    s2, b2 = call("POST", "/api/v1/password/reset-request",
                  {"username": "dana@vault.invalid"})
    enum_ok = (s1 == 404 and s2 == 200)
    print("  [%s] FLAG2a enumeration oracle on reset (%d vs %d)"
          % ("OK" if enum_ok else "!!", s1, s2))
    ok &= enum_ok

    # Reproduce the token the way a player must: same second, same generator.
    found = None
    for delta in range(0, 3):
        rng = random.Random(int(now()) - delta)
        cand = "%08x" % rng.getrandbits(32)
        s3, b3 = call("POST", "/api/v1/password/reset",
                      {"token": cand, "new_password": "ctf-verify-password"})
        if s3 == 200:
            found = cand
            break
    print("  [%s] FLAG2b reset token reproduced from the clock (%s)"
          % ("OK" if found else "!!", found))
    ok &= bool(found)

    # ---- FLAG 3: mfa-scoped token is a real session ------------------------
    # The reset above disabled dana's MFA, so use ops for the scope test.
    s4, b4 = call("POST", "/api/v1/login",
                  {"username": "ops@vault.invalid", "password": "9x!Kq2$vLmZ7wRt4"})
    mfa_tok = b4.get("mfa_token")
    scope_ok = False
    if mfa_tok:
        s5, b5 = call("GET", "/api/v1/me", token=mfa_tok)
        scope_ok = (s5 == 200)
        s6, b6 = call("GET", "/api/v1/document/4900", token=mfa_tok)
        flag3_ok = (s6 == 200 and FLAGS[3] in b6.get("body", ""))
    else:
        flag3_ok = False
    print("  [%s] FLAG3a mfa-scoped token accepted at /me" % ("OK" if scope_ok else "!!"))
    print("  [%s] FLAG3b mfa-scoped token reads document 4900" % ("OK" if flag3_ok else "!!"))
    ok &= scope_ok and flag3_ok

    # ---- FLAG 4: the closed account still authenticates --------------------
    s7, b7 = call("POST", "/api/v1/login",
                  {"username": "dana@vault.invalid", "password": "ctf-verify-password"})
    dana_tok = b7.get("token")
    closed_ok = bool(dana_tok)
    print("  [%s] FLAG4a a CLOSED account still authenticates" % ("OK" if closed_ok else "!!"))
    flag4_ok = False
    if dana_tok:
        s8, b8 = call("GET", "/api/v1/document/4711", token=dana_tok)
        flag4_ok = (s8 == 200 and FLAGS[4] in b8.get("body", ""))
    print("  [%s] FLAG4b the closed account's document survives" % ("OK" if flag4_ok else "!!"))
    ok &= closed_ok and flag4_ok

    print("-" * 66)
    print("  %s" % ("ALL SERVER-SIDE PATHS VERIFIED" if ok else "SOME PATHS FAILED"))
    print()
    print("  FLAG 1 is client-side and is verified by the Android app in lab-04,")
    print("  not by this script. That is stated rather than silently skipped.")
    print()
    return 0 if ok else 1


def main(argv=None):
    global PORT
    ap = argparse.ArgumentParser(description="Chapter 47 CTF backend.")
    ap.add_argument("--port", type=int, default=9047)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--verify", action="store_true",
                    help="run the self-test against a server already running")
    ap.add_argument("--spoilers", action="store_true")
    args = ap.parse_args(argv)
    PORT = args.port

    if args.spoilers:
        print(__doc__ or "")
        print("SOLUTION")
        print("  FLAG 1  %s" % FLAGS[1])
        print("          The app persists the vault passphrase to survive 'stay")
        print("          signed in'. adb backup / run-as / root reads it.")
        print("  FLAG 2  %s" % FLAGS[2])
        print("          reset-request returns 404 for unknown users; the reset")
        print("          token is random.Random seeded with int(time.time()).")
        print("  FLAG 3  %s" % FLAGS[3])
        print("          session_of() never checks scope, so the mfa_token issued")
        print("          BEFORE the second factor is a full session credential.")
        print("          Use it at /api/v1/document/4900.")
        print("  FLAG 4  %s" % FLAGS[4])
        print("          /account/close sets a flag. The account still logs in and")
        print("          document 4711 still exists.")
        return 0

    if args.verify:
        return verify()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("REFUSING to bind to a non-loopback address. This server is", file=sys.stderr)
        print("deliberately vulnerable.", file=sys.stderr)
        return 2

    seed()
    print("=" * 66)
    print(" CH47 CTF - vault-auth")
    print("   http://%s:%d" % (args.host, args.port))
    print("=" * 66)
    print(" Your account:  player@vault.invalid / player-password-1")
    print(" Four flags. See labs/lab-04-ctf-the-account-that-would-not-close.md")
    print(" Out-of-band values (OTPs, reset tokens) appear on THIS console,")
    print(" standing in for email and SMS. Reading them here is not a solution.")
    print("=" * 66)
    print()

    with Server((args.host, args.port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
