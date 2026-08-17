#!/usr/bin/env python3
"""
oauth-param-decoder.py — decode and analyse an OAuth 2.0 / OIDC authorisation request URL,
a token response, or a JWT, and flag the things that are actually findings.

WHAT IT DOES
  Given a captured /authorize URL it reports every parameter, estimates the entropy of `state`
  and the PKCE challenge, and flags:
      * missing or weak `state`                         -> CSRF / token injection
      * missing PKCE (`code_challenge`)                 -> code interception
      * `code_challenge_method=plain`                   -> PKCE downgrade
      * implicit grant (`response_type` containing token)
      * ROPC (`grant_type=password`)
      * a `client_secret` present in a mobile request
      * non-https redirect_uri (custom scheme)          -> hijackable
      * over-broad or unrecognised scopes
      * `prompt=none` silent flows and `login_hint` username leakage

  Given a token response (JSON) it decodes any JWTs, prints the claims that matter, and flags
  a long-lived access token, a missing `nonce`, an `aud` that is not what you expected, and
  an `alg` of `none`.

  It also verifies PKCE arithmetic locally: give it a verifier and a challenge and it tells you
  whether S256(verifier) really equals the challenge.

USAGE
  # analyse a captured authorisation request
  python3 oauth-param-decoder.py --url "https://login.example.com/authorize?response_type=code&..."

  # analyse a captured token *request* body (form-encoded)
  python3 oauth-param-decoder.py --form "grant_type=authorization_code&code=...&code_verifier=..."

  # analyse a token response saved from Burp
  python3 oauth-param-decoder.py --token-response resp.json
  curl -s ... | python3 oauth-param-decoder.py --token-response -

  # decode a single JWT
  python3 oauth-param-decoder.py --jwt eyJhbGciOi...

  # check PKCE arithmetic
  python3 oauth-param-decoder.py --verify-pkce --verifier "abc..." --challenge "xyz..."

  # generate a conforming verifier/challenge/state triple for your own test flow
  python3 oauth-param-decoder.py --generate

  # tell it which client_id you expect, so `aud` can be checked
  python3 oauth-param-decoder.py --token-response resp.json --expect-aud com.example.client

OUTPUT
  Human-readable by default; `--json` emits a machine-readable findings list for pipelines.

DEPENDENCIES
  Python 3.8+, standard library only.

Chapter 45 — OAuth 2.0 and OpenID Connect on Android
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from urllib.parse import urlparse, parse_qsl, unquote_plus

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

USE_COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def c(text, colour):
    if not USE_COLOUR:
        return text
    codes = {"red": 31, "yellow": 33, "green": 32, "blue": 34, "grey": 90, "bold": 1}
    return f"\033[{codes[colour]}m{text}\033[0m"

FINDINGS = []   # list of (severity, title, detail)

def finding(severity, title, detail):
    FINDINGS.append({"severity": severity, "title": title, "detail": detail})

def rule(char="-"):
    print(c(char * 78, "grey"))

def header(title):
    print()
    rule("=")
    print(c(f"  {title}", "bold"))
    rule("=")

# --------------------------------------------------------------------------- #
# Generic primitives
# --------------------------------------------------------------------------- #

def shannon_entropy_bits(s: str) -> float:
    """Estimate total entropy in bits: per-character Shannon entropy times length.

    This is a heuristic. A 32-character hex string scores about 128 bits, which is right.
    A counter such as '0000000000000001' scores near zero, which is the point: it separates
    'random-looking' from 'sequential' without needing to know the generator.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    per_char = -sum((v / n) * math.log2(v / n) for v in counts.values())
    return per_char * n


def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment that may be missing its padding."""
    segment = segment.replace("-", "+").replace("_", "/")
    segment += "=" * (-len(segment) % 4)
    return base64.b64decode(segment)


def s256(verifier: str) -> str:
    """RFC 7636 s4.2: BASE64URL(SHA256(ASCII(code_verifier)))."""
    return b64url_nopad(hashlib.sha256(verifier.encode("ascii")).digest())

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #

STANDARD_SCOPES = {
    "openid":         "OIDC switch — required to receive an id_token",
    "profile":        "name, family_name, picture, locale, updated_at",
    "email":          "email and email_verified",
    "address":        "the address claim",
    "phone":          "phone_number and phone_number_verified",
    "offline_access": "requests a REFRESH TOKEN — long-lived access",
}

# Scope substrings that deserve a second look in any report.
SENSITIVE_SCOPE_PATTERNS = [
    (r"write|create|update|delete|modify", "grants mutation, not just read"),
    (r"payment|transfer|transaction|funds|money", "financial capability"),
    (r"admin|superuser|root|full", "administrative capability"),
    (r"contacts|calendar|photos|files|drive|mail|sms", "bulk personal data"),
    (r"offline_access", "long-lived refresh token"),
]

PARAM_PURPOSE = {
    "response_type":        "which flow — must be `code` for a mobile app",
    "client_id":            "public identifier of the app; NOT a credential",
    "redirect_uri":         "where the code is delivered — the trust anchor",
    "scope":                "what is being requested",
    "state":                "CSRF protection; must be compared on return",
    "code_challenge":       "PKCE — the hash of the secret verifier",
    "code_challenge_method": "PKCE transform — must be S256",
    "nonce":                "OIDC replay protection, echoed inside the id_token",
    "prompt":               "login / consent / none / select_account",
    "max_age":              "force re-authentication if the session is older",
    "acr_values":           "requested authentication assurance level",
    "login_hint":           "pre-fills the username — leaks it into the URL",
    "grant_type":           "token endpoint: which grant is being redeemed",
    "code":                 "the authorisation code being redeemed",
    "code_verifier":        "PKCE — the secret; must never appear on the front channel",
    "client_secret":        "must NOT be present in a mobile app request",
    "refresh_token":        "long-lived renewal credential",
    "request_uri":          "PAR (RFC 9126) reference — hardened",
    "request":              "signed request object (JAR)",
    "response_mode":        "query / fragment / form_post",
}

# --------------------------------------------------------------------------- #
# Authorisation request analysis
# --------------------------------------------------------------------------- #

def analyse_params(params: dict, kind: str, expect_aud=None):
    """kind is 'authorize' or 'token'. Prints an inventory then runs the checks."""
    header(f"{kind.upper()} REQUEST PARAMETERS")

    width = max((len(k) for k in params), default=10)
    for key, value in params.items():
        purpose = PARAM_PURPOSE.get(key, "")
        shown = value if len(value) <= 90 else value[:87] + "..."
        print(f"  {key.ljust(width)} = {shown}")
        if purpose:
            print(f"  {' ' * width}   {c(purpose, 'grey')}")

    if kind == "authorize":
        check_response_type(params)
        check_state(params)
        check_pkce_request(params)
        check_redirect_uri(params)
        check_scopes(params)
        check_nonce(params)
        check_misc_authorize(params)
    else:
        check_grant_type(params)
        check_pkce_token(params)
        check_client_secret(params)


def check_response_type(p):
    rt = p.get("response_type", "")
    if not rt:
        finding("info", "no response_type",
                "Not an authorisation request, or PAR is in use (look for request_uri).")
        return
    if "token" in rt.split() or "token" in rt.split("%20"):
        finding("high", "implicit grant in use",
                f"response_type={rt!r} returns the access token in the URL fragment, where it "
                "lands in browser history, logs and Referer headers. The implicit grant is "
                "removed in OAuth 2.1. Move to authorisation code + PKCE.")
    elif rt.strip() == "code":
        pass  # correct
    else:
        finding("info", "non-standard response_type", f"response_type={rt!r}")

    if "request_uri" in p:
        finding("good", "PAR in use (RFC 9126)",
                "Request parameters were pushed over the back channel. The front channel carries "
                "only client_id and an opaque request_uri, so there is nothing in the URL to tamper "
                "with.")


def check_state(p):
    st = p.get("state")
    if not st:
        finding("high", "`state` is absent",
                "Without state the redirect is open to CSRF: an attacker completes their own "
                "authorisation, captures the code, and induces the victim's app to consume it. The "
                "victim's app then holds the ATTACKER's tokens, and everything the victim saves "
                "goes into the attacker's account. RFC 6749 s10.12.")
        return
    bits = shannon_entropy_bits(st)
    print(f"\n  state length={len(st)} estimated entropy ~{bits:.0f} bits")
    if bits < 64:
        finding("medium", "`state` has low entropy",
                f"state={st!r} estimates at only ~{bits:.0f} bits. A guessable state is not a "
                "CSRF control. Generate it from SecureRandom with at least 128 bits. Capture three "
                "logins and compare — a counter or timestamp will be obvious.")
    if re.fullmatch(r"[0-9]+", st):
        finding("high", "`state` looks like a counter",
                f"state={st!r} is purely numeric. If it increments between logins it is trivially "
                "predictable and provides no protection.")


def check_nonce(p):
    if "openid" in p.get("scope", "") and "nonce" not in p:
        finding("medium", "OIDC flow without `nonce`",
                "The scope requests `openid` but no nonce was sent. nonce is echoed inside the "
                "signed id_token and is the only mechanism that binds a specific id_token to a "
                "specific authorisation request in a way an attacker cannot forge. Sending it and "
                "not comparing it on receipt is equally useless — verify both.")


def check_pkce_request(p):
    cc = p.get("code_challenge")
    method = p.get("code_challenge_method")

    if not cc:
        finding("high", "no PKCE in the authorisation request",
                "No code_challenge was sent, so an intercepted authorisation code is directly "
                "redeemable by whoever intercepts it. RFC 8252 mandates PKCE for native apps. "
                "NOTE: confirm at the token endpoint whether the server requires it — if the "
                "server enforces PKCE this request would have been rejected, and if it does not, "
                "the finding belongs to the server.")
        return

    if method is None:
        finding("medium", "code_challenge sent without code_challenge_method",
                "Omitting the method means the server defaults to `plain` per RFC 7636 s4.3, "
                "which sends the verifier itself through the front channel.")
    elif method.lower() == "plain":
        finding("high", "PKCE downgraded to `plain`",
                "With method=plain the code_challenge IS the code_verifier, travelling in clear "
                "text through exactly the channel PKCE exists to protect. An attacker who "
                "intercepts the redirect sees both halves. Use S256.")
    elif method.upper() != "S256":
        finding("medium", "unknown code_challenge_method", f"method={method!r}")

    bits = shannon_entropy_bits(cc)
    print(f"  code_challenge length={len(cc)} estimated entropy ~{bits:.0f} bits")
    if method and method.upper() == "S256" and len(cc) != 43:
        finding("info", "unusual S256 challenge length",
                f"A base64url SHA-256 digest without padding is always 43 characters; this one is "
                f"{len(cc)}. The implementation may be hashing the wrong thing — a common bug is "
                "hashing the raw entropy rather than the ASCII bytes of the base64url verifier.")

    print(c("\n  >> REMEMBER: the presence of code_challenge proves only that the CLIENT", "yellow"))
    print(c("     implements PKCE. It proves NOTHING about the server. Run the enforcement", "yellow"))
    print(c("     test (chapter 45 section 7.5) before writing any conclusion.", "yellow"))


def check_pkce_token(p):
    if "code" in p and "code_verifier" not in p:
        finding("info", "token request without code_verifier",
                "Either this app does not use PKCE, or this is your own enforcement-test request. "
                "If it is the app's own request and the server returned tokens, PKCE is not "
                "enforced — a Critical finding.")


def check_redirect_uri(p):
    ru = p.get("redirect_uri")
    if not ru:
        finding("info", "no redirect_uri in the request",
                "The server may be using the single registered URI. Confirm the registration is "
                "exact-match rather than prefix or wildcard.")
        return
    parsed = urlparse(ru)
    scheme = parsed.scheme.lower()

    if scheme in ("http",) and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        finding("high", "plaintext http redirect_uri",
                f"redirect_uri={ru!r} is cleartext HTTP. The authorisation code travels "
                "unprotected.")
    elif scheme == "https":
        finding("good", "https redirect_uri",
                f"{ru} — now confirm the platform actually VERIFIED it as an App Link: "
                "`adb shell pm get-app-links <pkg>` must show `verified`. Declaring "
                "android:autoVerify=\"true\" is not verification.")
    elif scheme in ("http",):
        finding("info", "loopback redirect",
                "A loopback redirect is the desktop pattern. On Android any local app can bind a "
                "port, so it is weaker than an App Link.")
    else:
        finding("medium", "custom URI scheme redirect",
                f"redirect_uri={ru!r} uses the custom scheme {scheme!r}. Android imposes no "
                "uniqueness on schemes — any installed app may declare the same one and receive "
                "the authorisation code. Confirm with:\n"
                f"      adb shell cmd package query-activities -a android.intent.action.VIEW "
                f"-d \"{ru}\"\n"
                "    Severity depends entirely on whether the server enforces PKCE: enforced "
                "makes a stolen code inert (Medium); not enforced makes this account takeover "
                "(Critical).")

    if "*" in ru or ".." in ru:
        finding("high", "suspicious redirect_uri",
                f"redirect_uri={ru!r} contains a wildcard or traversal sequence. Test whether the "
                "server performs exact matching.")


def check_scopes(p):
    raw = p.get("scope", "")
    if not raw:
        return
    scopes = [s for s in re.split(r"[\s+]+", unquote_plus(raw)) if s]
    header("SCOPE ANALYSIS")
    print("  Build the second column yourself. Any empty cell is a finding.\n")
    print(f"  {'scope'.ljust(38)} | meaning / feature that requires it")
    print(f"  {'-' * 38}-+-{'-' * 34}")
    for s in scopes:
        meaning = STANDARD_SCOPES.get(s, c("<vendor-defined — justify it>", "yellow"))
        print(f"  {s.ljust(38)} | {meaning}")

    for s in scopes:
        for pattern, why in SENSITIVE_SCOPE_PATTERNS:
            if re.search(pattern, s, re.I):
                finding("medium", f"sensitive scope requested: {s}",
                        f"{why}. If the tokens leak, the attacker inherits this capability. Strip "
                        "the scope from the request and confirm whether the app still works — a "
                        "demonstrated unused scope is a far stronger finding than an asserted one.")
                break

    if len(scopes) > 8:
        finding("info", "many scopes requested",
                f"{len(scopes)} scopes. Consider whether least privilege at login plus a step-up "
                "flow for sensitive operations would be more appropriate.")


def check_misc_authorize(p):
    if p.get("prompt") == "none":
        finding("info", "silent authorisation (prompt=none)",
                "The app is attempting SSO without user interaction. Confirm the session it relies "
                "on cannot be established by an attacker.")
    if "login_hint" in p:
        finding("low", "login_hint leaks the username into the URL",
                f"login_hint={p['login_hint']!r} appears in the browser URL, and therefore in "
                "history and any logging along the path.")
    if "max_age" in p or "acr_values" in p:
        finding("good", "step-up authentication signals present",
                "max_age / acr_values force a fresh or stronger authentication. Verify the server "
                "actually honours them by checking auth_time and acr in the resulting id_token.")


def check_grant_type(p):
    gt = p.get("grant_type")
    if gt == "password":
        finding("critical", "ROPC (password) grant in use",
                "The app collects the user's identity-provider password and sends it to the token "
                "endpoint. This destroys the single benefit OAuth provides, cannot support MFA or "
                "federated identity, and is removed in OAuth 2.1. Move to authorisation code + "
                "PKCE with an external user agent.")
    elif gt == "client_credentials":
        finding("high", "client_credentials grant from a mobile app",
                "This grant requires a client secret, which a mobile app cannot hold. Whatever "
                "value is being used as the secret is extractable from the APK.")
    elif gt == "refresh_token":
        finding("info", "refresh grant observed",
                "Test three things: does the refresh token rotate, is reuse of an old one detected "
                "and does it revoke the whole chain, and can you widen `scope` beyond the original "
                "grant (RFC 6749 s6 says you must not be able to).")


def check_client_secret(p):
    if "client_secret" in p:
        finding("high", "client_secret present in a mobile request",
                f"client_secret={p['client_secret'][:12]}... was sent from the device. Anything the "
                "app can send, anyone with the APK can extract. Confirm by grepping the decompiled "
                "sources and resources. Its presence usually also indicates a grant type the app "
                "should not be using at all.")

# --------------------------------------------------------------------------- #
# JWT / token response analysis
# --------------------------------------------------------------------------- #

def decode_jwt(token: str, label: str = "jwt", expect_aud=None):
    parts = token.split(".")
    if len(parts) != 3:
        print(c(f"  {label}: not a three-segment JWT (opaque token, {len(token)} chars)", "grey"))
        return None
    try:
        head = json.loads(b64url_decode(parts[0]))
        body = json.loads(b64url_decode(parts[1]))
    except Exception as exc:                                  # noqa: BLE001
        print(c(f"  {label}: could not decode ({exc})", "red"))
        return None

    header(f"{label.upper()}")
    print("  header:")
    print("    " + json.dumps(head, indent=2).replace("\n", "\n    "))
    print("  payload:")
    print("    " + json.dumps(body, indent=2, default=str).replace("\n", "\n    "))
    print(c("  signature: NOT VERIFIED by this script — it has no key. That is the point:", "grey"))
    print(c("             anyone can read these claims. Only a verifier proves them.", "grey"))

    alg = str(head.get("alg", "")).lower()
    if alg == "none":
        finding("critical", f"{label} uses alg=none",
                "The token is unsigned. Any consumer accepting it accepts forged identities.")
    if alg.startswith("hs") and label == "id_token":
        finding("medium", f"{label} signed with a symmetric algorithm ({head.get('alg')})",
                "HMAC signing means the verification key is the client secret, which a public "
                "mobile client cannot hold. It also opens the algorithm-confusion family — see "
                "chapter 46-Tokens.")

    aud = body.get("aud")
    if label == "id_token":
        if aud is None:
            finding("high", "id_token has no `aud` claim",
                    "Without an audience there is nothing identifying which client the token was "
                    "minted for.")
        elif expect_aud is not None:
            auds = aud if isinstance(aud, list) else [aud]
            if expect_aud not in auds:
                finding("critical", "id_token audience mismatch",
                        f"aud={aud!r} does not contain the expected client_id {expect_aud!r}. If a "
                        "backend accepts this token anyway, it accepts tokens minted for other "
                        "clients — the classic 'Sign in with X' account-takeover flaw.")
            else:
                finding("good", "id_token audience matches",
                        f"aud contains {expect_aud!r}. Now confirm the BACKEND checks it too — that "
                        "is where the check is normally missing.")
        else:
            print(c(f"\n  aud={aud!r} — rerun with --expect-aud <your client_id> to check it.",
                    "yellow"))

        if "nonce" not in body:
            finding("medium", "id_token has no `nonce`",
                    "Without nonce this token cannot be bound to a specific authorisation request, "
                    "so it can be replayed into another flow.")
        if "sub" not in body:
            finding("medium", "id_token has no `sub`", "There is no stable user identifier.")
        if "email" in body and not body.get("email_verified", False):
            finding("medium", "id_token contains an unverified email",
                    "email_verified is false or absent. Any system linking accounts by email is "
                    "vulnerable to registering the victim's address at a sloppy issuer. Key "
                    "accounts on `sub`.")

    import time
    now = int(time.time())
    if "exp" in body:
        lifetime = int(body["exp"]) - int(body.get("iat", now))
        print(f"\n  lifetime: {lifetime}s ({lifetime / 3600:.1f}h)")
        if body["exp"] < now:
            finding("info", f"{label} is expired", f"exp={body['exp']} is in the past.")
        if lifetime > 86400:
            finding("medium", f"{label} is long-lived",
                    f"{lifetime / 3600:.1f} hours. Access tokens should live minutes, not days; a "
                    "leaked token is valid for its whole lifetime.")
    return body


def analyse_token_response(raw: str, expect_aud=None):
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(c(f"  not valid JSON: {exc}", "red"))
        return

    header("TOKEN RESPONSE")
    for key, value in data.items():
        if key in ("access_token", "id_token", "refresh_token") and isinstance(value, str):
            print(f"  {key.ljust(16)} = <{len(value)} chars>")
        else:
            print(f"  {key.ljust(16)} = {value}")

    tt = str(data.get("token_type", "")).lower()
    if tt == "dpop":
        finding("good", "sender-constrained tokens (DPoP)",
                "token_type=DPoP means the token is bound to a proof key (RFC 9449). A stolen "
                "token is unusable without the key. If the key lives in the Android Keystore as "
                "non-exportable, it cannot be extracted even on a rooted device.")
    elif tt == "bearer":
        print(c("\n  token_type=Bearer — authority belongs to whoever holds the string.", "grey"))

    if "expires_in" in data:
        secs = int(data["expires_in"])
        if secs > 86400:
            finding("medium", "long-lived access token",
                    f"expires_in={secs} ({secs / 3600:.1f}h). Short access tokens plus a rotating "
                    "refresh token bound the damage from a leak.")

    if "refresh_token" in data:
        finding("info", "refresh token issued",
                "Test rotation and reuse detection: refresh once, then present the OLD refresh "
                "token again. It must fail, and a hardened server revokes the whole chain.")

    if "id_token" in data:
        decode_jwt(data["id_token"], "id_token", expect_aud)
    if "access_token" in data and str(data["access_token"]).count(".") == 2:
        decode_jwt(data["access_token"], "access_token")

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "good": 5}
SEVERITY_COLOUR = {"critical": "red", "high": "red", "medium": "yellow",
                   "low": "yellow", "info": "blue", "good": "green"}
SEVERITY_MARK = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
                 "low": "[LOW ]", "info": "[INFO]", "good": "[ OK ]"}


def print_findings():
    header("FINDINGS")
    if not FINDINGS:
        print("  Nothing flagged. That is not the same as 'secure' — this script only reads what "
              "you gave it.")
        return
    for f in sorted(FINDINGS, key=lambda x: SEVERITY_ORDER[x["severity"]]):
        mark = c(SEVERITY_MARK[f["severity"]], SEVERITY_COLOUR[f["severity"]])
        print(f"\n  {mark} {c(f['title'], 'bold')}")
        for para in f["detail"].split("\n"):
            print(f"        {para}")

    print()
    rule()
    print(c("  The most important test cannot be performed from a captured request:", "yellow"))
    print(c("  whether the SERVER enforces PKCE. Capture a fresh code and replay the token", "yellow"))
    print(c("  exchange with the verifier removed. See chapter 45 section 7.5 and lab 02.", "yellow"))
    rule()

# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Decode and analyse OAuth 2.0 / OIDC requests, responses and JWTs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--url", help="a captured /authorize (or /token) request URL")
    ap.add_argument("--form", help="a captured form-encoded request body")
    ap.add_argument("--token-response", help="file containing the token endpoint's JSON response "
                                             "('-' for stdin)")
    ap.add_argument("--jwt", help="a single JWT to decode")
    ap.add_argument("--expect-aud", help="the client_id you expect in an id_token's aud claim")
    ap.add_argument("--verify-pkce", action="store_true",
                    help="check that S256(--verifier) equals --challenge")
    ap.add_argument("--verifier", help="a code_verifier")
    ap.add_argument("--challenge", help="a code_challenge")
    ap.add_argument("--generate", action="store_true",
                    help="generate a conforming verifier, challenge, state and nonce")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args()

    if args.generate:
        verifier = b64url_nopad(os.urandom(64))[:128]
        print("code_verifier         =", verifier)
        print("code_challenge        =", s256(verifier))
        print("code_challenge_method = S256")
        print("state                 =", b64url_nopad(os.urandom(32)))
        print("nonce                 =", b64url_nopad(os.urandom(32)))
        return 0

    if args.verify_pkce:
        if not (args.verifier and args.challenge):
            ap.error("--verify-pkce needs both --verifier and --challenge")
        computed = s256(args.verifier)
        print(f"  verifier length : {len(args.verifier)} "
              f"({'ok' if 43 <= len(args.verifier) <= 128 else 'OUT OF RANGE, RFC 7636 s4.1'})")
        bad = set(args.verifier) - set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        if bad:
            print(c(f"  illegal characters in verifier: {sorted(bad)}", "red"))
        print(f"  S256(verifier)  : {computed}")
        print(f"  code_challenge  : {args.challenge}")
        if computed == args.challenge:
            print(c("  MATCH — the client's PKCE arithmetic is correct.", "green"))
        else:
            print(c("  MISMATCH — the client is hashing the wrong bytes, or the values came "
                    "from different flows.", "red"))
            print("  A common bug: hashing the raw entropy rather than the ASCII bytes of the")
            print("  base64url-encoded verifier. See chapter 45 section 3.3.")
        return 0

    did_something = False

    if args.url:
        did_something = True
        parsed = urlparse(args.url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params.update(dict(parse_qsl(parsed.fragment, keep_blank_values=True)))
        print(f"\n  endpoint: {parsed.scheme}://{parsed.netloc}{parsed.path}")
        kind = "token" if "grant_type" in params else "authorize"
        analyse_params(params, kind, args.expect_aud)
        if parsed.scheme.lower() != "https":
            finding("high", "authorisation endpoint is not HTTPS",
                    f"{args.url.split('?')[0]} — the whole flow is interceptable on the network.")

    if args.form:
        did_something = True
        params = dict(parse_qsl(args.form, keep_blank_values=True))
        analyse_params(params, "token", args.expect_aud)

    if args.token_response:
        did_something = True
        raw = sys.stdin.read() if args.token_response == "-" \
            else open(args.token_response, encoding="utf-8").read()
        analyse_token_response(raw, args.expect_aud)

    if args.jwt:
        did_something = True
        decode_jwt(args.jwt, "jwt", args.expect_aud)

    if not did_something:
        ap.print_help()
        return 1

    if args.json:
        print(json.dumps(FINDINGS, indent=2))
    else:
        print_findings()

    # Exit non-zero if anything high or critical was found, so CI can gate on it.
    worst = min((SEVERITY_ORDER[f["severity"]] for f in FINDINGS), default=99)
    return 2 if worst <= 1 else 0


if __name__ == "__main__":
    sys.exit(main())
