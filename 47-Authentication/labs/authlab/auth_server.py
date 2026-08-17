#!/usr/bin/env python3
# 47-Authentication/labs/authlab/auth_server.py
#
# ============================================================================
#  A DELIBERATELY VULNERABLE AUTHENTICATION SERVER - AND ITS CORRECT TWIN
#
#  Run it on 127.0.0.1 only. It binds to loopback by default and REFUSES to
#  bind to a routable address without --i-understand-this-is-vulnerable.
#  Every account in it is created by it. It talks to nothing.
# ============================================================================
#
# PURPOSE
#   One server, two modes, so every defect in chapter 47 can be exercised AND
#   its fix demonstrated against an otherwise identical implementation:
#
#       --mode vulnerable   every defect in README section 5, switched on
#       --mode secure       the same API, implemented correctly
#
#   The two modes share their routes, their storage and their response shapes.
#   The ONLY differences are the ones the chapter is about, which is what makes
#   the comparison meaningful: you are not comparing two programs, you are
#   comparing two decisions.
#
# USAGE
#   python3 -B auth_server.py --mode vulnerable
#   python3 -B auth_server.py --mode secure --port 8048
#   python3 -B auth_server.py --mode vulnerable --list-defects
#
#   Then, from another terminal:
#     curl -s localhost:8047/api/v1/login \
#          -H 'Content-Type: application/json' \
#          -d '{"username":"alice@example.invalid","password":"wrong"}'
#
#   Seed accounts (printed at startup, and they are the ONLY accounts):
#     alice@example.invalid  / correct-horse-battery   (MFA enabled, OTP)
#     bob@example.invalid    / hunter2-but-longer      (no MFA)
#
# THE DEFECT LIST  (--list-defects prints this)
#   D1  account enumeration by message
#   D2  account enumeration by timing (early return skips the KDF)
#   D3  no rate limiting, no lockout
#   D4  the OTP is returned in the API response
#   D5  the pre-MFA token is a FULL session token
#   D6  the OTP has no attempt limit, no expiry, and is reusable
#   D7  logout does not revoke server-side
#   D8  password change does not invalidate other sessions
#   D9  password reset token is predictable and never expires
#   D10 IDOR: /api/v1/note/<id> does not check ownership
#   D11 sessions never expire
#   D12 no step-up for the sensitive operation (/api/v1/transfer)
#
# DEPENDENCIES
#   Standard library only. No Flask, no pip install. hashlib.scrypt is used as
#   the password KDF so that the timing difference in D2 is real rather than
#   simulated - see 34-Cryptography for why a slow KDF is the point.

import argparse
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socketserver
import sys
import threading
import time
import urllib.parse

# ---------------------------------------------------------------------------
# Configuration and state
# ---------------------------------------------------------------------------

MODE = "vulnerable"
START_TIME = time.time()

# scrypt parameters. Deliberately real: this takes ~50-100 ms, which is what
# makes the D2 timing oracle measurable rather than theoretical.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 14, 8, 1

SESSION_TTL = 900          # seconds, enforced only in secure mode (D11)
MFA_TTL = 300
MFA_MAX_ATTEMPTS = 5
RESET_TTL = 900
LOCKOUT_THRESHOLD = 5

LOCK = threading.RLock()

USERS = {}        # username -> dict
SESSIONS = {}     # token -> dict
MFA_CHALLENGES = {}
RESETS = {}
NOTES = {}        # note_id -> dict
FAILED = {}       # username -> [timestamps]
RESET_COUNTER = [1000]     # for the predictable-token defect

DEFECTS = [
    ("D1",  "account enumeration by message"),
    ("D2",  "account enumeration by timing (early return skips the KDF)"),
    ("D3",  "no rate limiting, no lockout"),
    ("D4",  "the OTP is returned in the API response"),
    ("D5",  "the pre-MFA token is a FULL session token"),
    ("D6",  "the OTP has no attempt limit, no expiry, and is reusable"),
    ("D7",  "logout does not revoke server-side"),
    ("D8",  "password change does not invalidate other sessions"),
    ("D9",  "password reset token is predictable and never expires"),
    ("D10", "IDOR: /api/v1/note/<id> does not check ownership"),
    ("D11", "sessions never expire"),
    ("D12", "no step-up for the sensitive operation (/api/v1/transfer)"),
]


def kdf(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)


# A verifier for an account that does not exist. Computed ONCE at boot so that
# the secure mode can run the KDF on the not-found path at the same cost as the
# found path. This single object is the entire fix for D2.
DUMMY_SALT = secrets.token_bytes(16)
DUMMY_VERIFIER = None


def seed():
    global DUMMY_VERIFIER
    DUMMY_VERIFIER = kdf("a password that belongs to nobody", DUMMY_SALT)

    for username, password, mfa in (
        ("alice@example.invalid", "correct-horse-battery", True),
        ("bob@example.invalid", "hunter2-but-longer", False),
    ):
        salt = secrets.token_bytes(16)
        USERS[username] = {
            "id": len(USERS) + 1,
            "username": username,
            "salt": salt,
            "verifier": kdf(password, salt),
            "mfa_enabled": mfa,
            "balance": 1000,
            "password_changed_at": time.time(),
        }

    # Notes, for the IDOR lab. Note 3 is alice's and is the interesting one.
    for nid, owner, body in (
        (1, "bob@example.invalid",   "bob: buy milk"),
        (2, "bob@example.invalid",   "bob: renew passport"),
        (3, "alice@example.invalid", "alice: recovery phrase reminder - "
                                     "CH47{i_d_o_r_is_an_authorisation_bug}"),
        (4, "alice@example.invalid", "alice: dentist tuesday"),
    ):
        NOTES[nid] = {"id": nid, "owner": owner, "body": body}


def now():
    return time.time()


def new_session(username, scope="session"):
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = {
        "username": username,
        "scope": scope,
        "created": now(),
        "elevated_at": None,
    }
    return token


def lookup_session(token, required_scope="session"):
    """Return (session, error_string)."""
    s = SESSIONS.get(token)
    if s is None:
        return None, "invalid session"

    if MODE == "secure":
        # D11 fix: absolute lifetime, enforced on the server.
        if now() - s["created"] > SESSION_TTL:
            SESSIONS.pop(token, None)
            return None, "session expired"
        # D5 fix: a credential's scope is checked at every use. An MFA-scoped
        # token cannot be used as a session token, no matter where it is sent.
        if s["scope"] != required_scope:
            return None, "wrong credential scope for this operation"
    return s, None


def record_failure(username):
    FAILED.setdefault(username, []).append(now())


def is_locked_out(username):
    """D3 fix: per-account exponential backoff.

    Applied identically whether or not the account exists - otherwise the rate
    limiter itself becomes the enumeration oracle that D1 and D2 were about.
    A hard lock is deliberately NOT used: it is a denial-of-service primitive
    against any user whose address is known.
    """
    if MODE != "secure":
        return 0
    attempts = [t for t in FAILED.get(username, []) if now() - t < 3600]
    FAILED[username] = attempts
    if len(attempts) < LOCKOUT_THRESHOLD:
        return 0
    over = len(attempts) - LOCKOUT_THRESHOLD
    backoff = min(300, 2 ** over)
    since = now() - attempts[-1]
    return max(0, backoff - since)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def h_login(body, headers):
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    if MODE == "vulnerable":
        # ---- D1: distinct messages. A direct oracle, no statistics needed.
        # ---- D2: and the early return skips scrypt entirely, so the
        #          not-found path returns in well under a millisecond while
        #          the found path takes ~50-100 ms. Fixing only the message
        #          leaves this behind, which is the point of the pair.
        # ---- D3: no rate limiting anywhere on this path.
        user = USERS.get(username)
        if user is None:
            return 404, {"error": "No account with that email address"}
        if not hmac.compare_digest(kdf(password, user["salt"]), user["verifier"]):
            return 401, {"error": "Incorrect password"}
    else:
        wait = is_locked_out(username)
        if wait > 0:
            return 429, {"error": "Too many attempts. Try again shortly.",
                         "retry_after": int(wait) + 1}

        user = USERS.get(username)
        # ---- D2 fix: the KDF runs on BOTH paths, at the same cost. The dummy
        #      verifier exists solely so the not-found path is not cheap.
        salt = user["salt"] if user else DUMMY_SALT
        expected = user["verifier"] if user else DUMMY_VERIFIER
        ok = hmac.compare_digest(kdf(password, salt), expected)
        if user is None or not ok:
            record_failure(username)
            # ---- D1 fix: ONE message for every rejection reason.
            return 401, {"error": "Invalid email address or password"}

    if user["mfa_enabled"]:
        code = "%06d" % secrets.randbelow(1000000)
        if MODE == "vulnerable":
            # ---- D5: a FULL session token before the second factor.
            token = new_session(username, scope="session")
            MFA_CHALLENGES[token] = {"code": code, "created": now(), "attempts": 0}
            # ---- D4: and the code itself, in the response body. One proxy
            #      capture is a complete MFA bypass, and this is not rare.
            return 200, {"mfa_required": True, "token": token, "code": code}
        else:
            # ---- D4/D5 fix: the pre-MFA credential is scoped to exactly one
            #      operation, and the code goes out of band only.
            token = new_session(username, scope="mfa")
            MFA_CHALLENGES[token] = {"code": code, "created": now(), "attempts": 0}
            print("  [out-of-band] OTP for %s is %s  (a real deployment sends "
                  "this by SMS or push, never in the response)" % (username, code))
            return 200, {"mfa_required": True, "mfa_token": token}

    token = new_session(username)
    if MODE == "secure":
        FAILED.pop(username, None)
    return 200, {"ok": True, "token": token, "expires_in": SESSION_TTL}


def h_mfa(body, headers):
    token = str(body.get("mfa_token") or body.get("token") or "")
    code = str(body.get("code", ""))

    challenge = MFA_CHALLENGES.get(token)
    if challenge is None:
        return 400, {"error": "no challenge for that token"}

    if MODE == "vulnerable":
        # ---- D6: no attempt limit, no expiry, and the challenge is never
        #      consumed, so a correct code works for ever and a wrong one can
        #      be retried a million times. A 6-digit code falls in seconds.
        if code == challenge["code"]:
            return 200, {"ok": True, "token": token}
        return 401, {"error": "incorrect code"}

    # ---- D6 fix: bounded attempts, bounded lifetime, single use.
    if now() - challenge["created"] > MFA_TTL:
        MFA_CHALLENGES.pop(token, None)
        SESSIONS.pop(token, None)
        return 401, {"error": "challenge expired"}

    challenge["attempts"] += 1
    if challenge["attempts"] > MFA_MAX_ATTEMPTS:
        MFA_CHALLENGES.pop(token, None)
        SESSIONS.pop(token, None)
        return 429, {"error": "too many attempts; challenge destroyed"}

    if not hmac.compare_digest(code, challenge["code"]):
        return 401, {"error": "incorrect code"}

    session = SESSIONS.get(token)
    if session is None:
        return 400, {"error": "no session"}
    MFA_CHALLENGES.pop(token, None)
    SESSIONS.pop(token, None)                 # the mfa-scoped token dies here
    real = new_session(session["username"], scope="session")
    return 200, {"ok": True, "token": real, "expires_in": SESSION_TTL}


def h_me(body, headers):
    session, err = _auth(headers)
    if err:
        return 401, {"error": err}
    u = USERS[session["username"]]
    return 200, {"username": u["username"], "id": u["id"], "balance": u["balance"]}


def h_logout(body, headers):
    token = _bearer(headers)
    if MODE == "vulnerable":
        # ---- D7: the server acknowledges the logout and DOES NOTHING. The app
        #      clears its local copy, the user sees the login screen, every
        #      functional test passes, and the token still works. Replay any
        #      authenticated request to prove it.
        return 200, {"ok": True, "message": "logged out"}
    removed = SESSIONS.pop(token, None) is not None
    return 200, {"ok": True, "revoked": removed}


def h_logout_all(body, headers):
    session, err = _auth(headers)
    if err:
        return 401, {"error": err}
    if MODE == "vulnerable":
        return 200, {"ok": True, "message": "signed out of all devices"}
    username = session["username"]
    victims = [t for t, s in SESSIONS.items() if s["username"] == username]
    for t in victims:
        SESSIONS.pop(t, None)
    return 200, {"ok": True, "revoked": len(victims)}


def h_change_password(body, headers):
    session, err = _auth(headers)
    if err:
        return 401, {"error": err}
    new = str(body.get("new_password", ""))
    if len(new) < 8:
        return 400, {"error": "password too short"}

    user = USERS[session["username"]]
    salt = secrets.token_bytes(16)
    user["salt"] = salt
    user["verifier"] = kdf(new, salt)
    user["password_changed_at"] = now()

    if MODE == "vulnerable":
        # ---- D8: other sessions survive a password change. This is the logout
        #      variant that most often fails while explicit logout works,
        #      because it needs the SERVER to enumerate sessions rather than
        #      the client to delete one.
        return 200, {"ok": True}

    victims = [t for t, s in SESSIONS.items()
               if s["username"] == user["username"] and t != _bearer(headers)]
    for t in victims:
        SESSIONS.pop(t, None)
    return 200, {"ok": True, "other_sessions_revoked": len(victims)}


def h_reset_request(body, headers):
    username = str(body.get("username", ""))
    user = USERS.get(username)

    if MODE == "vulnerable":
        if user is None:
            # enumeration again, on the flow nobody tests
            return 404, {"error": "no such account"}
        # ---- D9: sequential token, no expiry, no single-use marking. And it
        #      is returned in the response, which is the same defect as D4
        #      wearing a different hat.
        RESET_COUNTER[0] += 1
        token = "reset-%d" % RESET_COUNTER[0]
        RESETS[token] = {"username": username, "created": now(), "used": False}
        return 200, {"status": "sent", "token": token}

    # ---- D9 fix: CSPRNG, expiring, single-use, delivered out of band, and an
    #      identical response whether or not the account exists.
    if user is not None:
        token = secrets.token_urlsafe(32)
        RESETS[token] = {"username": username, "created": now(), "used": False}
        print("  [out-of-band] reset token for %s: %s" % (username, token))
    return 200, {"status": "if that address exists, a message has been sent"}


def h_reset_confirm(body, headers):
    token = str(body.get("token", ""))
    new = str(body.get("new_password", ""))
    r = RESETS.get(token)
    if r is None:
        return 400, {"error": "invalid token"}

    if MODE == "secure":
        if r["used"]:
            return 400, {"error": "token already used"}
        if now() - r["created"] > RESET_TTL:
            RESETS.pop(token, None)
            return 400, {"error": "token expired"}

    user = USERS[r["username"]]
    salt = secrets.token_bytes(16)
    user["salt"] = salt
    user["verifier"] = kdf(new, salt)
    r["used"] = True

    if MODE == "secure":
        # Every other reset token for this user dies, and so does every session.
        # A reset whose purpose is recovering a compromised account must eject
        # the attacker, or it has not done its job.
        for t, other in list(RESETS.items()):
            if other["username"] == user["username"] and t != token:
                RESETS.pop(t, None)
        for t, s in list(SESSIONS.items()):
            if s["username"] == user["username"]:
                SESSIONS.pop(t, None)
    return 200, {"ok": True}


def h_note(note_id, body, headers):
    session, err = _auth(headers)
    if err:
        return 401, {"error": err}
    note = NOTES.get(note_id)

    if MODE == "vulnerable":
        # ---- D10: authenticated, and NOT authorised. @require_session looks
        #      like the security decorator - and it is, for authentication.
        #      The per-object check has no natural home, so it must be written
        #      by hand in every handler, and one omission is a vulnerability.
        if note is None:
            return 404, {"error": "not found"}
        return 200, note

    # ---- D10 fix: the ownership predicate is in the LOOKUP, not in an `if`
    #      after it, so a developer cannot omit it by omitting a line. And the
    #      failure is 404, not 403, because a 403 confirms the object exists.
    if note is None or note["owner"] != session["username"]:
        return 404, {"error": "not found"}
    return 200, note


def h_transfer(body, headers):
    session, err = _auth(headers)
    if err:
        return 401, {"error": err}
    amount = int(body.get("amount", 0))
    to = str(body.get("to", ""))

    if MODE == "vulnerable":
        # ---- D12: an ordinary session credential moves money. Any step-up the
        #      app performed was a local prompt the server never learned about.
        user = USERS[session["username"]]
        user["balance"] -= amount
        return 200, {"ok": True, "balance": user["balance"],
                     "flag": "CH47{no_step_up_on_money_movement}"}

    # ---- D12 fix: elevation is a property of the SESSION ON THE SERVER, and
    #      it expires. See README 5.12 and examples/05-EnterpriseAuthSession.kt
    #      for how the client produces something the server can verify.
    if session["elevated_at"] is None or now() - session["elevated_at"] > 300:
        return 403, {"error": "step-up required", "step_up_endpoint": "/api/v1/stepup"}
    user = USERS[session["username"]]
    user["balance"] -= amount
    return 200, {"ok": True, "balance": user["balance"]}


def h_stepup(body, headers):
    session, err = _auth(headers)
    if err:
        return 401, {"error": err}
    password = str(body.get("password", ""))
    user = USERS[session["username"]]
    if not hmac.compare_digest(kdf(password, user["salt"]), user["verifier"]):
        return 401, {"error": "step-up failed"}
    session["elevated_at"] = now()
    return 200, {"ok": True, "elevated_for": 300}


def h_status(body, headers):
    return 200, {
        "mode": MODE,
        "uptime_s": round(now() - START_TIME, 1),
        "sessions": len(SESSIONS),
        "users": sorted(USERS),
        "defects_active": [d for d, _ in DEFECTS] if MODE == "vulnerable" else [],
    }


# ---------------------------------------------------------------------------

def _bearer(headers):
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _auth(headers):
    session, err = lookup_session(_bearer(headers), required_scope="session")
    return session, err


ROUTES = {
    ("POST", "/api/v1/login"):            h_login,
    ("POST", "/api/v1/login/mfa"):        h_mfa,
    ("GET",  "/api/v1/me"):               h_me,
    ("POST", "/api/v1/logout"):           h_logout,
    ("POST", "/api/v1/logout/all"):       h_logout_all,
    ("POST", "/api/v1/password"):         h_change_password,
    ("POST", "/api/v1/password/reset-request"): h_reset_request,
    ("POST", "/api/v1/password/reset"):   h_reset_confirm,
    ("POST", "/api/v1/transfer"):         h_transfer,
    ("POST", "/api/v1/stepup"):           h_stepup,
    ("GET",  "/api/v1/status"):           h_status,
}

NOTE_RE = re.compile(r"^/api/v1/note/(\d+)$")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ch47lab/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    def _respond(self, status, payload):
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self, method):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
            if not isinstance(body, dict):
                body = {}
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        with LOCK:
            m = NOTE_RE.match(path)
            if m and method == "GET":
                status, payload = h_note(int(m.group(1)), body, self.headers)
                self._respond(status, payload)
                return

            fn = ROUTES.get((method, path))
            if fn is None:
                self._respond(404, {"error": "no such route", "path": path})
                return
            status, payload = fn(body, self.headers)
            self._respond(status, payload)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv=None):
    global MODE

    ap = argparse.ArgumentParser(
        description="Chapter 47 authentication lab server - vulnerable and secure modes.")
    ap.add_argument("--mode", choices=("vulnerable", "secure"), default="vulnerable")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8047)
    ap.add_argument("--list-defects", action="store_true")
    ap.add_argument("--i-understand-this-is-vulnerable", action="store_true",
                    dest="ack", help="required to bind to a non-loopback address")
    args = ap.parse_args(argv)

    if args.list_defects:
        print("Defects present in --mode vulnerable:")
        for tag, desc in DEFECTS:
            print("  %-4s %s" % (tag, desc))
        return 0

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.ack:
        print("REFUSING to bind to %s." % args.host, file=sys.stderr)
        print("This server contains twelve deliberate authentication defects and", file=sys.stderr)
        print("must not be reachable from a network. Use 127.0.0.1, or pass", file=sys.stderr)
        print("--i-understand-this-is-vulnerable if you are certain the network", file=sys.stderr)
        print("is isolated (an emulator host-only bridge, for example).", file=sys.stderr)
        return 2

    MODE = args.mode
    seed()

    print("=" * 74)
    print(" 47-Authentication lab server")
    print("   mode : %s" % MODE.upper())
    print("   bind : http://%s:%d" % (args.host, args.port))
    print("=" * 74)
    print(" Accounts (the only ones; both created by this process):")
    print("   alice@example.invalid  correct-horse-battery   [MFA enabled]")
    print("   bob@example.invalid    hunter2-but-longer      [no MFA]")
    print("")
    if MODE == "vulnerable":
        print(" %d deliberate defects are ACTIVE. --list-defects to see them." % len(DEFECTS))
        print(" Do not copy any handler in this file into anything real.")
    else:
        print(" Secure mode. Every defect above is fixed; the API is identical.")
        print(" Out-of-band values (OTPs, reset tokens) are printed HERE, not")
        print(" returned in responses - that is the fix, not a convenience.")
    print("")
    print(" Try:  curl -s localhost:%d/api/v1/status" % args.port)
    print("=" * 74)
    print("")

    with Server((args.host, args.port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
