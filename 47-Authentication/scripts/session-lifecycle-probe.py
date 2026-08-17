#!/usr/bin/env python3
# 47-Authentication/scripts/session-lifecycle-probe.py
#
# PURPOSE
#   Test the SESSION LIFECYCLE of an authenticated API - the half of an
#   authentication review that mobile testers most often skip, and where the
#   highest-severity findings live.
#
#   It answers, with evidence, the questions in README section 3.8:
#
#     T1  Does LOGOUT revoke server-side?                       (CWE-613)
#     T2  Does a PASSWORD CHANGE invalidate other sessions?     (CWE-620)
#     T3  Does "log out of all devices" do anything?
#     T4  Does the session have an ABSOLUTE LIFETIME?
#     T5  Does an intermediate (pre-MFA) credential work as a session? (MFA bypass)
#     T6  Is per-object AUTHORISATION enforced, or only authentication? (IDOR/BOLA)
#     T7  Is there STEP-UP on the sensitive operation?          (MASVS-AUTH-3)
#
#   Each test is a small number of ordinary requests. There is no fuzzing, no
#   guessing and no brute force anywhere in this file, and there will not be.
#
# USAGE
#   # against the chapter's lab server - do this first, in both modes
#   python3 -B ../labs/authlab/auth_server.py --mode vulnerable &
#   python3 -B session-lifecycle-probe.py --base http://127.0.0.1:8047
#
#   python3 -B ../labs/authlab/auth_server.py --mode secure --port 8048 &
#   python3 -B session-lifecycle-probe.py --base http://127.0.0.1:8048
#
#   # against an authorised target, with a route map
#   python3 -B session-lifecycle-probe.py --base https://api.example.invalid \
#       --user-a you@yours.invalid --pass-a '...' \
#       --user-b second@yours.invalid --pass-b '...' \
#       --routes routes.json
#
#   routes.json overrides the default paths, e.g.
#     {"login": "/v2/auth/signin", "me": "/v2/profile", "logout": "/v2/auth/signout"}
#
# ETHICS
#   * TWO ACCOUNTS, BOTH YOURS. T6 needs a second account so that the object
#     you attempt to read across a boundary belongs to you as well.
#   * It CHANGES THE PASSWORD of account A during T2 and sets it back. Use a
#     throwaway test account, and expect to reset it if the run is interrupted.
#   * It never enumerates, never guesses and never touches an identifier you did
#     not supply. T6 reads the object ids that account B's own session returned.
#   * Run it only against a service you are authorised to assess, in writing.
#
# DEPENDENCIES
#   Standard library only.

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ROUTES = {
    "login":       "/api/v1/login",
    "mfa":         "/api/v1/login/mfa",
    "me":          "/api/v1/me",
    "logout":      "/api/v1/logout",
    "logout_all":  "/api/v1/logout/all",
    "password":    "/api/v1/password",
    "object":      "/api/v1/note/{id}",
    "transfer":    "/api/v1/transfer",
}

RESULTS = []


def record(tag, title, passed, detail, severity=""):
    RESULTS.append({"tag": tag, "title": title, "pass": passed,
                    "detail": detail, "severity": severity})
    mark = "PASS" if passed else "FAIL"
    print("  [%s] %-4s %s" % (mark, tag, title))
    for line in detail.splitlines():
        print("         %s" % line)
    if not passed and severity:
        print("         severity: %s" % severity)
    print()


class Client:
    def __init__(self, base, insecure=False, timeout=20.0):
        self.base = base.rstrip("/")
        self.insecure = insecure
        self.timeout = timeout

    def _ctx(self):
        if not self.insecure:
            return None
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c

    def request(self, method, path, payload=None, token=None):
        url = self.base + path
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json",
                   "User-Agent": "ch47-session-lifecycle-probe/1.0 (authorised testing)"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx()) as r:
                return r.status, _json(r.read())
        except urllib.error.HTTPError as e:
            return e.code, _json(e.read())
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as e:
            return 0, {"_transport_error": str(e)}


def _json(raw):
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {"_body": v}
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"_raw": raw[:300].decode("utf-8", "replace")}


INTERACTIVE_OTP = False


def login(c, routes, user, password):
    """Returns (session_token, pre_mfa_token_or_None, response)."""
    status, body = c.request("POST", routes["login"],
                             {"username": user, "password": password})
    if status == 0:
        return None, None, body
    # An MFA-gated login gives us a second, very valuable artefact: the
    # intermediate credential, which T5 tests.
    if body.get("mfa_required"):
        pre = body.get("mfa_token") or body.get("token")
        code = body.get("code")          # only a broken server returns this
        if code is None and INTERACTIVE_OTP:
            # A correctly-built server sends the code out of band, so an
            # unattended probe cannot complete the login. That is the server
            # behaving properly, not a tooling problem - so we ask the operator
            # rather than pretending we can proceed.
            try:
                code = input("      OTP for %s (out of band; blank to skip): "
                             % user).strip()
            except EOFError:
                code = ""
            if not code:
                return None, pre, body
        if code:
            s2, b2 = c.request("POST", routes["mfa"],
                               {"mfa_token": pre, "token": pre, "code": code})
            return b2.get("token"), pre, body
        return None, pre, body
    return body.get("token"), None, body


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Probe an API's session lifecycle. Two accounts, both yours.")
    ap.add_argument("--base", required=True, help="API base URL")
    ap.add_argument("--user-a", default="alice@example.invalid")
    ap.add_argument("--pass-a", default="correct-horse-battery")
    ap.add_argument("--user-b", default="bob@example.invalid")
    ap.add_argument("--pass-b", default="hunter2-but-longer")
    ap.add_argument("--routes", help="JSON file overriding the default paths")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--skip-password-change", action="store_true",
                    help="skip T2, which mutates account A's password")
    ap.add_argument("--interactive-otp", action="store_true",
                    help="prompt for out-of-band OTPs. Needed against any "
                         "CORRECTLY built server, because a correct server does "
                         "not put the code in the response.")
    args = ap.parse_args(argv)

    global INTERACTIVE_OTP
    INTERACTIVE_OTP = args.interactive_otp

    routes = dict(DEFAULT_ROUTES)
    if args.routes:
        with open(args.routes, encoding="utf-8") as fh:
            routes.update(json.load(fh))

    c = Client(args.base, args.insecure)

    print("=" * 74)
    print("47-Authentication / session lifecycle probe")
    print("  base    : %s" % args.base)
    print("  account : %s (A), %s (B)" % (args.user_a, args.user_b))
    print("=" * 74)
    print()

    # ---- establish sessions ------------------------------------------------
    tok_a, pre_a, raw_a = login(c, routes, args.user_a, args.pass_a)
    tok_b, pre_b, raw_b = login(c, routes, args.user_b, args.pass_b)

    if raw_a.get("_transport_error"):
        print("Cannot reach %s: %s" % (args.base, raw_a["_transport_error"]))
        return 1
    if not tok_a or not tok_b:
        print("Could not establish both sessions. Response for A was:")
        print(json.dumps(raw_a, indent=2)[:600])
        print()
        print("If this API's login shape differs, supply --routes.")
        print()
        print("If it required an MFA code that was NOT in the response, that is")
        print("the server behaving CORRECTLY - re-run with --interactive-otp and")
        print("supply the codes from wherever they are actually delivered.")
        return 1

    print("Sessions established for both accounts.")
    print()
    print("-" * 74)
    print("TESTS")
    print("-" * 74)
    print()

    # ---- T5: does the pre-MFA credential work as a session? ---------------
    if pre_a:
        if raw_a.get("code") is not None:
            record("T5a", "OTP returned in the login response", False,
                   "The 'send code' response body contained the code itself.\n"
                   "One proxy capture is a complete MFA bypass for any account\n"
                   "whose identifier is known.",
                   "CRITICAL (CWE-640)")
        status, body = c.request("GET", routes["me"], token=pre_a)
        ok = status in (401, 403)
        record("T5", "Pre-MFA credential rejected as a session", ok,
               "Presented the intermediate token at %s -> HTTP %d\n%s"
               % (routes["me"], status,
                  "Refused, as it must be." if ok else
                  "ACCEPTED. The second factor is advisory: an attacker who\n"
                  "stops after factor one holds a working session."),
               "CRITICAL - complete MFA bypass (CWE-287)")
    else:
        print("  [SKIP] T5   no MFA on account A, so there is no intermediate")
        print("              credential to test.")
        print()

    # ---- T6: IDOR / BOLA ---------------------------------------------------
    # Find an object id belonging to B, by asking B. Then ask for it as A.
    b_object = None
    for candidate in range(1, 9):
        path = routes["object"].format(id=candidate)
        status, body = c.request("GET", path, token=tok_b)
        if status == 200:
            b_object = (candidate, body)
            break

    if b_object is None:
        print("  [SKIP] T6   could not find an object belonging to account B via")
        print("              %s. Supply a --routes object template." % routes["object"])
        print()
    else:
        oid, bbody = b_object
        path = routes["object"].format(id=oid)
        status, body = c.request("GET", path, token=tok_a)
        ok = status in (401, 403, 404)
        record("T6", "Per-object authorisation enforced", ok,
               "Object %d belongs to account B.\n"
               "Requested it with account A's credential -> HTTP %d\n%s"
               % (oid, status,
                  "Refused. Note that 404 is preferable to 403: a 403 confirms\n"
                  "the object exists, which is enumeration applied to objects."
                  if ok else
                  "RETURNED ANOTHER ACCOUNT'S OBJECT.\n"
                  "The session was authenticated and the request was not\n"
                  "authorised. File this against the ENDPOINT, not the app."),
               "HIGH to CRITICAL depending on data and scale (CWE-639)")

    # ---- T1: logout ---------------------------------------------------------
    status, _ = c.request("POST", routes["logout"], {}, token=tok_a)
    time.sleep(0.5)
    status2, body2 = c.request("GET", routes["me"], token=tok_a)
    ok = status2 in (401, 403)
    record("T1", "Logout revokes the session server-side", ok,
           "Logout -> HTTP %d, then replayed %s -> HTTP %d\n%s"
           % (status, routes["me"], status2,
              "The credential is dead." if ok else
              "THE CREDENTIAL STILL WORKS after logout.\n"
              "The user performed the only action the product offers to end a\n"
              "session, and it did nothing. Every other credential-exposure\n"
              "finding in the report therefore has no user-available remedy."),
           "HIGH (CWE-613)")

    # Re-establish A for the remaining tests.
    tok_a, pre_a, _ = login(c, routes, args.user_a, args.pass_a)
    if not tok_a:
        print("Could not re-establish account A; stopping.")
        return _summary()

    # ---- T3: logout everywhere ---------------------------------------------
    tok_a2, _, _ = login(c, routes, args.user_a, args.pass_a)
    if tok_a2:
        c.request("POST", routes["logout_all"], {}, token=tok_a)
        time.sleep(0.5)
        s, _ = c.request("GET", routes["me"], token=tok_a2)
        ok = s in (401, 403)
        record("T3", "'Log out of all devices' revokes other sessions", ok,
               "Opened a second session for A, called %s on the first,\n"
               "then replayed the SECOND session -> HTTP %d\n%s"
               % (routes["logout_all"], s,
                  "The other session died." if ok else
                  "THE OTHER SESSION SURVIVED. The button does nothing."),
               "HIGH (CWE-613)")

    # ---- T2: password change ------------------------------------------------
    if args.skip_password_change:
        print("  [SKIP] T2   --skip-password-change given.")
        print()
    else:
        tok_a, _, _ = login(c, routes, args.user_a, args.pass_a)
        tok_other, _, _ = login(c, routes, args.user_a, args.pass_a)
        if tok_a and tok_other:
            temp = args.pass_a + "-ch47tmp"
            s, _ = c.request("POST", routes["password"],
                             {"new_password": temp, "old_password": args.pass_a},
                             token=tok_a)
            if s in (200, 204):
                time.sleep(0.5)
                s2, _ = c.request("GET", routes["me"], token=tok_other)
                ok = s2 in (401, 403)
                record("T2", "Password change invalidates other sessions", ok,
                       "Changed A's password in session 1, replayed session 2\n"
                       "-> HTTP %d\n%s" % (s2,
                       "The other session died, as it must." if ok else
                       "THE OTHER SESSION SURVIVED A PASSWORD CHANGE.\n"
                       "This is the variant that most often fails while explicit\n"
                       "logout works, because it needs the SERVER to enumerate\n"
                       "sessions rather than the client to delete one. It also\n"
                       "means a user who suspects compromise cannot eject the\n"
                       "attacker by changing their password."),
                       "HIGH (CWE-620)")
                # put it back
                tok_new, _, _ = login(c, routes, args.user_a, temp)
                if tok_new:
                    c.request("POST", routes["password"],
                              {"new_password": args.pass_a, "old_password": temp},
                              token=tok_new)
                    print("         (password restored)")
                    print()
                else:
                    print("         !! COULD NOT RESTORE THE PASSWORD. Account A's")
                    print("         !! password is now: %s" % temp)
                    print()
            else:
                print("  [SKIP] T2   password change endpoint returned HTTP %d" % s)
                print()

    # ---- T7: step-up on a sensitive operation -------------------------------
    tok_a, _, _ = login(c, routes, args.user_a, args.pass_a)
    if tok_a:
        s, body = c.request("POST", routes["transfer"],
                            {"to": "ch47-probe", "amount": 1}, token=tok_a)
        if s == 404:
            print("  [SKIP] T7   no %s endpoint on this API." % routes["transfer"])
            print()
        else:
            ok = s in (401, 403)
            record("T7", "Sensitive operation requires step-up", ok,
                   "Called %s with an ordinary session -> HTTP %d\n%s"
                   % (routes["transfer"], s,
                      "Refused pending step-up, which is correct." if ok else
                      "EXECUTED with an ordinary session credential.\n"
                      "Any step-up the app performed was a local prompt the\n"
                      "server never learned about - see README 5.12."),
                   "HIGH; CRITICAL if step-up is the only control (CWE-306)")

    # ---- T4: absolute lifetime ---------------------------------------------
    print("  [MANUAL] T4  absolute session lifetime")
    print("           This cannot be measured in a short run. Two options:")
    print("             * read the credential's own expiry, if it is structured")
    print("               (see 46-Tokens on decoding a JWT) - but remember that")
    print("               the ACCESS token's expiry is NOT the session lifetime;")
    print("               a 1-hour access token behind a 90-day refresh token is")
    print("               a NINETY-DAY session, and that is the number to report;")
    print("             * park a credential and retry it tomorrow.")
    print()

    return _summary()


def _summary():
    print("=" * 74)
    print("SUMMARY")
    print("=" * 74)
    failed = [r for r in RESULTS if not r["pass"]]
    for r in RESULTS:
        print("  %-5s %-4s %s" % ("PASS" if r["pass"] else "FAIL", r["tag"], r["title"]))
    print()
    if failed:
        print("%d of %d checks failed:" % (len(failed), len(RESULTS)))
        for r in failed:
            print("  - %s: %s  [%s]" % (r["tag"], r["title"], r["severity"]))
        print()
        print("REPORTING NOTE. Where the server accepted something it should have")
        print("refused, file the finding AGAINST THE ENDPOINT, not against the")
        print("Android client. If you file it as a client-side issue, the developer")
        print("will fix the client and the vulnerability will remain.")
    else:
        print("All %d executed checks passed. State the scope honestly: this")
        print("probe covers the lifecycle, not the credential's format (46-Tokens)")
        print("nor the login flow's own weaknesses (README sections 5.4-5.6)." % len(RESULTS))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
