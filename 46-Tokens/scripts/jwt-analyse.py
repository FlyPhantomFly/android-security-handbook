#!/usr/bin/env python3
"""
jwt-analyse.py — decode a token, give a verdict on every claim, and flag every known
JWT failure class, WITHOUT EVER TRANSMITTING THE TOKEN.

PURPOSE
  You have a token. Before you do anything else you need to know four things: what kind
  of token it is, what it says, what it is missing, and which of the documented failure
  classes it is a candidate for. This script answers all four offline, in one pass, and
  prints its reasoning rather than a score.

  It is deliberately *not* an exploitation tool. It forges nothing and sends nothing. It
  tells you which attacks are worth attempting and, just as usefully, which are not.

  Failure classes it flags, each mapped to chapter 46 section 5:
      5.1  alg=none accepted                    -- header says the token is unsigned
      5.2  HS/RS algorithm confusion            -- symmetric alg on an asymmetric issuer
      5.3  kid injection / path traversal / SQL -- kid contains dangerous syntax
      5.3  jku / x5u / jwk header key injection -- the token names its own key
      5.4  weak HMAC secret                     -- HS* means an offline cracking target
      5.5  missing or absurd exp                -- lifetime measured in months
      5.6  missing iss / aud                    -- nothing binds the token to you
      5.7  no sender-constraining               -- no cnf claim, so it is pure bearer
      5.8  over-scoped or privilege claims      -- role/admin/scope worth reading twice
      5.9  PII in the payload                   -- remember: the payload is not encrypted

USAGE
  python3 -B jwt-analyse.py --token "eyJhbGciOi..."
  python3 -B jwt-analyse.py --file token.txt
  python3 -B jwt-analyse.py --file authstate.json --scan     # find tokens in any file
  python3 -B jwt-analyse.py --token "..." --expect-iss https://issuer.example.com \\
                            --expect-aud com.example.app --expect-alg RS256
  python3 -B jwt-analyse.py --token "..." --json
  python3 -B jwt-analyse.py --token "..." --no-colour

  With --scan the input may be an entire SharedPreferences XML, an AppAuth `AuthState`
  blob, a `strings` dump, or a Burp response: it extracts everything that looks like a
  JWT or an opaque bearer token and analyses each.

REQUIREMENTS
  Python 3.8+. Standard library only. No pip install. No network. No `cryptography`,
  because this script never verifies a signature -- see below.

WHAT THIS WILL NOT TELL YOU
  * It will NOT tell you whether the signature is valid. It has no keys and it will not
    fetch any. A verdict of "structurally sound" is not a verdict of "authentic", and
    every claim printed below is UNVERIFIED text written by whoever wrote the token. To
    verify, use examples/02-correct-verifier.py with a key you already trust.
  * It will NOT tell you whether the SERVER is vulnerable. Every flag it raises is a
    hypothesis about the token's issuer or consumer. `alg: RS256` in the header does not
    mean the verifier requires RS256; only sending an alg=none forgery answers that.
  * It will NOT decrypt a JWE. A five-segment token is identified and then left alone,
    because its payload is genuinely encrypted and there is nothing to read without the
    key.
  * It will NOT tell you the token is safe to store where you found it. Storage is
    chapter 33 and chapter 49.
  * It cannot distinguish an opaque token from a random string. It reports entropy and a
    format guess, and it says so.

TRANSMISSION GUARANTEE
  This script installs a guard that replaces `socket.socket` with a class that raises on
  construction, so any code path that tried to open a network connection -- including one
  added by a future editor, or a URL accidentally passed to urllib -- fails loudly
  instead of quietly leaking a credential. Verify it yourself:
      python3 -B jwt-analyse.py --self-test
  This matters more than it sounds. Public "JWT decoder" websites receive the token you
  paste into them. Pasting a client's token into one is a data-handling incident, and it
  has ended engagements. Decode locally, always.

SAFETY
  Chapter 46's standing rule: every token you handle is one you minted yourself. Do not
  run this against a token belonging to a real account -- yours or anyone's. On an
  engagement, handle only tokens issued to test accounts inside the rules of engagement.

Chapter 46 — Tokens
"""

import argparse
import base64
import binascii
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Transmission guard. Installed before anything else runs.
# --------------------------------------------------------------------------- #
import socket as _socket


class _NoNetwork:
    def __init__(self, *_a, **_kw):
        raise RuntimeError(
            "jwt-analyse.py attempted to open a socket. This script must never "
            "transmit a token. Refusing.")


_socket.socket = _NoNetwork          # noqa: N816
_socket.create_connection = _NoNetwork

USE_COLOUR = sys.stdout.isatty()
_C = {"red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
      "cyan": "\033[96m", "grey": "\033[90m", "bold": "\033[1m", "off": "\033[0m"}


def c(text, colour):
    return f"{_C[colour]}{text}{_C['off']}" if USE_COLOUR else text


FINDINGS = []
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOUR = {"critical": "red", "high": "red", "medium": "yellow",
                   "low": "cyan", "info": "grey"}


def finding(severity, title, detail, section=None):
    FINDINGS.append({"severity": severity, "title": title,
                     "detail": detail, "section": section})


# --------------------------------------------------------------------------- #
# Claim reference. Every registered claim from RFC 7519 section 4.1, the OIDC Core
# claims that show up constantly, and the ones that carry authorisation weight.
# --------------------------------------------------------------------------- #
CLAIM_MEANINGS = {
    "iss": ("Issuer", "Who minted this. Must be compared byte-for-byte against a value "
                      "the verifier holds. RFC 7519 4.1.1"),
    "sub": ("Subject", "The principal. Stable and unique WITHIN the issuer -- so the "
                       "account key is the pair (iss, sub), never sub alone. RFC 7519 4.1.2"),
    "aud": ("Audience", "Who this token is FOR. String or array. Skipping this check is "
                        "the 'Sign in with X' account-takeover flaw. RFC 7519 4.1.3"),
    "exp": ("Expiry", "Seconds since the epoch after which the token must be refused. "
                      "RFC 7519 4.1.4"),
    "nbf": ("Not before", "Seconds since the epoch before which it must be refused. "
                          "RFC 7519 4.1.5"),
    "iat": ("Issued at", "When it was minted. Useful for a max-age policy stricter than "
                         "exp. RFC 7519 4.1.6"),
    "jti": ("JWT ID", "Unique identifier. The hook a replay-detection or denylist "
                      "design hangs on. RFC 7519 4.1.7"),
    "azp": ("Authorized party", "OIDC. Names the client a multi-audience token was "
                                "actually issued to."),
    "nonce": ("Nonce", "OIDC. Echoes the client's per-request random value INSIDE the "
                       "signature, which is what makes it unforgeable. See 45-OAuth 3.12"),
    "auth_time": ("Auth time", "When the human actually authenticated -- not when the "
                               "token was minted. The two differ after a silent refresh."),
    "acr": ("Auth context ref", "Assurance level reached."),
    "amr": ("Auth methods ref", "How they authenticated: pwd, mfa, otp, face, swk, hwk."),
    "scope": ("Scope", "Space-separated permissions. Read every one and ask what feature "
                       "needs it."),
    "scp": ("Scope (array form)", "Same thing, as a JSON array. Azure AD uses this."),
    "cnf": ("Confirmation", "RFC 7800. THE claim that turns a bearer token into a "
                            "sender-constrained one. `jkt` = DPoP thumbprint, "
                            "`x5t#S256` = mTLS certificate thumbprint."),
    "client_id": ("Client ID", "The OAuth client. RFC 9068 puts it in JWT access tokens."),
    "typ": ("Type", "In the payload this is unusual; in the header it should be JWT or, "
                    "for RFC 9068 access tokens, at+jwt."),
    "email": ("Email", "Mutable and sometimes unverified. NEVER the account key."),
    "email_verified": ("Email verified", "If false, `email` means nothing at all."),
    "name": ("Name", "PII."),
    "roles": ("Roles", "Authorisation data inside the token -- read it, then test whether "
                       "the server re-checks it."),
    "role": ("Role", "As above."),
    "groups": ("Groups", "As above."),
    "permissions": ("Permissions", "As above."),
    "sid": ("Session ID", "OIDC back-channel logout hangs off this."),
    "at_hash": ("Access token hash", "Binds an id_token to the access token issued beside it."),
    "c_hash": ("Code hash", "Binds an id_token to the authorisation code."),
    "nickname": ("Nickname", "PII."),
    "picture": ("Picture", "PII (a URL that often identifies the user)."),
    "phone_number": ("Phone number", "PII."),
    "address": ("Address", "PII."),
    "birthdate": ("Birthdate", "PII."),
    "updated_at": ("Updated at", "Profile last-modified time."),
    "ver": ("Version", "Vendor-specific token version."),
    "tid": ("Tenant ID", "Azure AD tenant. In a multi-tenant app this is an authorisation "
                         "input and must be checked."),
    "uid": ("User ID", "Vendor-specific."),
}

PII_CLAIMS = {"email", "name", "given_name", "family_name", "phone_number", "address",
              "birthdate", "nickname", "picture", "preferred_username", "gender",
              "middle_name", "zoneinfo", "locale", "website", "profile"}

PRIVILEGE_CLAIMS = {"role", "roles", "groups", "permissions", "scope", "scp", "admin",
                    "is_admin", "isAdmin", "authorities", "realm_access", "resource_access"}

DANGEROUS_KID = [
    (r"\.\.[/\\]", "path traversal"),
    (r"^/", "absolute path"),
    (r"^[a-zA-Z]:[\\/]", "absolute Windows path"),
    (r"[\x00]", "NUL byte"),
    (r"['\"]|--|\bUNION\b|\bSELECT\b", "SQL metacharacters"),
    (r"^https?://", "a URL -- the verifier may fetch it (SSRF)"),
    (r"[;|`$()]", "shell metacharacters"),
]

SECRET_LIKE = re.compile(
    r"(?i)\b(pass(word|wd)?|secret|api[_-]?key|private[_-]?key|token|credential)\b")


# --------------------------------------------------------------------------- #
# Encoding
# --------------------------------------------------------------------------- #
def b64url_decode(segment, strict=False):
    """Decode a base64url segment. Returns (bytes, note-or-None)."""
    note = None
    if any(ch in segment for ch in "+/"):
        note = ("contains '+' or '/': this is STANDARD base64, not base64url. "
                "A forgery tool that used the wrong alphabet leaves exactly this trace")
        if strict:
            raise ValueError(note)
    if "=" in segment:
        note = "contains '=' padding, which RFC 7515 section 2 says to strip"
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad), note
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"not valid base64url: {exc}") from exc


def shannon_entropy(data):
    """Bits of entropy per character, and total. A crude but effective discriminator."""
    if not data:
        return 0.0, 0.0
    counts = Counter(data)
    n = len(data)
    per_char = -sum((v / n) * math.log2(v / n) for v in counts.values())
    return per_char, per_char * n


def human_time(value):
    try:
        dt = datetime.fromtimestamp(int(value), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%SZ")
    except (ValueError, OSError, OverflowError, TypeError):
        return "unrepresentable"


def human_duration(seconds):
    seconds = int(seconds)
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    if seconds < 90:
        return f"{sign}{seconds}s"
    if seconds < 5400:
        return f"{sign}{seconds / 60:.1f} min"
    if seconds < 172800:
        return f"{sign}{seconds / 3600:.1f} h"
    if seconds < 63072000:
        return f"{sign}{seconds / 86400:.1f} days"
    return f"{sign}{seconds / 31557600:.1f} years"


# --------------------------------------------------------------------------- #
# Opaque tokens
# --------------------------------------------------------------------------- #
def classify_opaque(token):
    """A token with no dots, or the wrong number, is not a JWT. Say what it might be."""
    per_char, total = shannon_entropy(token)
    guesses = []
    if re.fullmatch(r"[0-9a-fA-F]{16,}", token):
        guesses.append(f"hex, {len(token) * 4} bits if uniformly random")
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", token):
        guesses.append("a UUID -- check the version nibble; a v1 UUID leaks a timestamp "
                       "and a MAC address, and is NOT a secure random value")
    if re.fullmatch(r"[A-Za-z0-9_-]{20,}", token):
        guesses.append(f"base64url, roughly {int(len(token) * 6)} bits before decoding")
    if token.startswith("gAAAAA"):
        guesses.append("a Fernet token (Python `cryptography`) -- AES-CBC + HMAC, and "
                       "the first bytes encode a timestamp")
    if token.startswith(("v1.", "v2.", "v3.", "v4.")) and token.count(".") >= 2:
        guesses.append("PASETO -- a JWT alternative with the algorithm fixed by version, "
                       "which is precisely the design that makes algorithm confusion "
                       "impossible")
    if token.startswith("ya29."):
        guesses.append("a Google OAuth 2.0 access token (opaque; introspect it at "
                       "Google's tokeninfo endpoint, not here)")
    if token.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
        guesses.append("a GitHub personal access token -- these are checksummed and "
                       "GitHub auto-revokes ones it finds published")
    if token.startswith("xox"):
        guesses.append("a Slack token")

    print(c("  This is not a JWT.", "bold"))
    print(f"  length          {len(token)} characters")
    print(f"  entropy         {per_char:.2f} bits/char, {total:.0f} bits total (upper bound)")
    print(f"  distinct chars  {len(set(token))}")
    if guesses:
        for g in guesses:
            print(f"  format guess    {g}")
    else:
        print("  format guess    unrecognised")
    print()
    print(c("  What an opaque token changes about your approach:", "bold"))
    print("    * There is nothing to decode. The value is a database lookup key, not a")
    print("      document. Every claim lives on the server.")
    print("    * Therefore NO client-side forgery is possible. alg=none, algorithm")
    print("      confusion and secret cracking are all inapplicable -- do not waste time.")
    print("    * Therefore the interesting questions move server-side: does the resource")
    print("      server introspect (RFC 7662) on every request, is revocation immediate,")
    print("      is the value guessable, and is it rate-limited?")
    print("    * Revocation is usually BETTER than with a JWT, because the server is")
    print("      consulted every time. That is the trade: a round trip for instant kill.")
    print("    * Your remaining tests are replay, expiry, scope and logout invalidation.")
    if per_char < 3.0:
        finding("medium", "opaque token has low entropy",
                f"{per_char:.2f} bits/char suggests structure or a small alphabet. "
                "Collect several and diff them; sequential or timestamp-derived tokens "
                "are guessable.")
    if len(token) < 16:
        finding("high", "opaque token is very short",
                f"{len(token)} characters. Estimate the search space and test whether the "
                "endpoint rate-limits wrong values.")
    finding("info", "token is opaque, not structured",
            "No offline analysis is possible. Test introspection, revocation and replay "
            "instead. See README section 3.3.")


# --------------------------------------------------------------------------- #
# The main analysis
# --------------------------------------------------------------------------- #
def analyse(token, expect_iss=None, expect_aud=None, expect_alg=None, now=None):
    import time
    now = int(time.time()) if now is None else int(now)
    token = token.strip().strip('"').strip("'")
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    print()
    print(c("=" * 78, "grey"))
    print(c(f"  token: {token[:48]}{'...' if len(token) > 48 else ''}  "
            f"({len(token)} chars)", "bold"))
    print(c("=" * 78, "grey"))

    parts = token.split(".")

    if len(parts) == 5:
        print(c("  Five segments: this is a JWE (RFC 7516), an ENCRYPTED token.", "bold"))
        print("  Layout: header . encrypted_key . iv . ciphertext . tag")
        try:
            head, _ = b64url_decode(parts[0])
            print("  header  " + head.decode("utf-8", "replace"))
            hdr = json.loads(head)
            print(f"  alg     {hdr.get('alg')}   (how the content key is wrapped)")
            print(f"  enc     {hdr.get('enc')}   (how the payload is encrypted)")
            if str(hdr.get("alg", "")).lower() == "none":
                finding("critical", "JWE with alg=none", "The content key is not protected.")
            if str(hdr.get("alg", "")) in ("RSA1_5",):
                finding("medium", "JWE uses RSA1_5 key wrapping",
                        "PKCS#1 v1.5 wrapping is vulnerable to Bleichenbacher-style "
                        "padding oracles if the decryptor's error handling differs. "
                        "RFC 8725 section 3.3 recommends against it.")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"  header  unreadable: {exc}")
        print()
        print("  The payload is genuinely encrypted. There is nothing to read here without")
        print("  the decryption key, and that is the point of JWE. Note that encryption is")
        print("  NOT the usual answer to 'the payload is not secret' -- the usual answer is")
        print("  to stop putting secrets in the payload. See README section 3.5.")
        finding("info", "token is a JWE", "Encrypted; offline claim analysis is impossible.")
        return

    if len(parts) != 3:
        classify_opaque(token)
        return

    header_b64, payload_b64, signature_b64 = parts

    # --- header ------------------------------------------------------------- #
    print()
    print(c("  HEADER (JOSE header, RFC 7515 section 4)", "bold"))
    try:
        raw_header, note = b64url_decode(header_b64)
        header = json.loads(raw_header)
    except (ValueError, json.JSONDecodeError) as exc:
        print(c(f"  header will not decode: {exc}", "red"))
        finding("info", "header is not decodable JSON", str(exc))
        return
    if note:
        print(c(f"  ! {note}", "yellow"))
        finding("low", "header segment encoding is non-canonical", note)
    print("  " + json.dumps(header, indent=2, sort_keys=True).replace("\n", "\n  "))

    alg = str(header.get("alg", ""))
    kid = header.get("kid")

    print()
    print(c("  HEADER VERDICTS", "bold"))
    _verdict_alg(alg, expect_alg)
    _verdict_kid(kid)
    _verdict_header_keys(header)

    if header.get("typ") and str(header["typ"]).lower() not in ("jwt", "at+jwt", "jose"):
        print(f"  typ       {header['typ']!r} -- non-standard; note it and move on")
    elif str(header.get("typ", "")).lower() == "at+jwt":
        print("  typ       at+jwt -- an RFC 9068 JWT access token. It is meant for the "
              "resource\n            server, and RFC 9068 requires the RS to check aud.")

    # --- payload ------------------------------------------------------------ #
    print()
    print(c("  PAYLOAD (claims set, RFC 7519 section 4)", "bold"))
    print(c("  Base64url is an ENCODING, not encryption. Anyone holding this token can", "yellow"))
    print(c("  read every line below with two commands and no key. Only a verifier with", "yellow"))
    print(c("  the right key can prove any of it is TRUE.", "yellow"))
    try:
        raw_payload, note = b64url_decode(payload_b64)
        claims = json.loads(raw_payload)
    except (ValueError, json.JSONDecodeError) as exc:
        print(c(f"  payload will not decode: {exc}", "red"))
        finding("info", "payload is not decodable JSON", str(exc))
        return
    if not isinstance(claims, dict):
        print(c("  payload is not a JSON object", "red"))
        finding("medium", "payload is not a JSON object",
                "RFC 7519 requires a JSON object. A parser that tolerates otherwise is "
                "a differential-parsing candidate.")
        return
    print(f"  {len(raw_payload)} bytes, {len(claims)} claims")
    print()
    _print_claim_table(claims, now)

    # --- signature ---------------------------------------------------------- #
    print()
    print(c("  SIGNATURE", "bold"))
    if signature_b64 == "":
        print(c("  EMPTY. Two segments of data and nothing protecting them.", "red"))
    else:
        try:
            sig, _ = b64url_decode(signature_b64)
            print(f"  {len(sig)} bytes ({len(signature_b64)} base64url chars)")
            _verdict_sig_length(alg, len(sig))
        except ValueError as exc:
            print(c(f"  will not decode: {exc}", "red"))
    print(c("  NOT VERIFIED. This script holds no keys and fetches none. Use", "grey"))
    print(c("  examples/02-correct-verifier.py with a key you already trust.", "grey"))

    # --- claim-level failure classes ---------------------------------------- #
    _verdict_time(claims, now)
    _verdict_binding(claims, expect_iss, expect_aud)
    _verdict_constraint(claims, header)
    _verdict_privilege(claims)
    _verdict_pii(claims)


def _verdict_alg(alg, expect_alg):
    low = alg.lower()
    if low == "none":
        print(c(f"  alg       {alg!r} -- THE TOKEN IS UNSIGNED", "red"))
        finding("critical", "alg is 'none'",
                "The header asserts no signature. If any verifier accepts this, anybody "
                "can mint any claim set. Test it directly: take a genuine token, rewrite "
                "the header to {\"alg\":\"none\"}, edit the claims, and leave the third "
                "segment empty (keep the trailing dot).", "5.1")
    elif low.startswith("hs"):
        print(c(f"  alg       {alg} -- SYMMETRIC (HMAC). Verifier and issuer share a "
                f"secret.", "yellow"))
        finding("medium", f"symmetric algorithm {alg}",
                "Two consequences. (1) The token is an OFFLINE cracking target: the whole "
                "verification equation is inside it, so a captured token can be ground "
                "against a wordlist forever with no rate limit and no logging -- see "
                "scripts/jwt-weak-secret.py. (2) Every party that can VERIFY can also "
                "MINT, so a symmetric token cannot be verified by a mobile client without "
                "shipping the minting key. If this is an id_token, that is a design "
                "error.", "5.4")
    elif low.startswith(("rs", "ps", "es", "ed")):
        fam = {"rs": "RSA PKCS#1 v1.5", "ps": "RSA-PSS", "es": "ECDSA",
               "ed": "EdDSA"}[low[:2]]
        print(f"  alg       {alg} -- asymmetric ({fam}). Only the issuer can mint; "
              f"anyone with\n            the public key can verify. Correct for a token a "
              f"client inspects.")
        finding("info", f"asymmetric algorithm {alg}",
                "Test for HS/RS confusion: re-sign the token as HS256 using the issuer's "
                "PUBLIC key bytes (from the JWKS) as the HMAC secret. A verifier that "
                "dispatches on the token's own `alg` while holding one key blob will "
                "accept it. This needs no stolen key -- the public key is published.",
                "5.2")
    elif low == "":
        print(c("  alg       ABSENT from the header", "red"))
        finding("high", "no alg in the header",
                "RFC 7515 requires it. Behaviour is then library-specific, which is "
                "exactly the condition in which one library defaults to 'none'.", "5.1")
    else:
        print(c(f"  alg       {alg!r} -- unrecognised", "yellow"))
        finding("medium", f"unrecognised alg {alg!r}",
                "Non-standard algorithms are rarely reviewed. Find out what implements it.")
    if expect_alg and alg != expect_alg:
        finding("high", f"alg is {alg!r}, you expected {expect_alg!r}",
                "If the issuer signs RS256 and this token says HS256, you are either "
                "looking at a different token family or at a successful algorithm "
                "substitution.", "5.2")


def _verdict_kid(kid):
    if kid is None:
        print("  kid       absent -- the verifier must have exactly one key, or it is "
              "guessing")
        finding("low", "no kid in the header",
                "Without a key identifier, key rotation means a flag day. It also means a "
                "verifier with several keys must try them all, which is a design smell.")
        return
    print(f"  kid       {kid!r}")
    if not isinstance(kid, str):
        finding("medium", "kid is not a string",
                "RFC 7515 says it is a string. A verifier that indexes with a non-string "
                "is doing something unexpected.")
        return
    for pattern, label in DANGEROUS_KID:
        if re.search(pattern, kid):
            print(c(f"            ! contains {label}", "red"))
            finding("high", f"kid contains {label}",
                    "`kid` is attacker-controlled data that many verifiers use to LOCATE "
                    "a key -- by file path, by URL, or by SQL query. If this token already "
                    "carries such a value, the design is confirmed. Try "
                    "kid=../../../../dev/null with an empty HMAC key, and try SQL "
                    "injection returning a key you chose.", "5.3")


def _verdict_header_keys(header):
    for name, what in (("jku", "a URL to a JWK Set"),
                       ("x5u", "a URL to an X.509 certificate chain"),
                       ("jwk", "an embedded public key"),
                       ("x5c", "an embedded certificate chain")):
        if name in header:
            print(c(f"  {name:<9} PRESENT -- the token carries {what}", "red"))
            finding("critical", f"header contains {name}",
                    "The token is telling the verifier which key to trust. That is "
                    "circular: an attacker generates their own keypair, signs the token "
                    "with the private half, and points this header at the public half. A "
                    "verifier that honours it accepts anything. RFC 8725 section 3.8 says "
                    "to ignore these headers entirely unless the URL is on an allow-list "
                    "you control. With `jku`/`x5u` there is a second impact: the verifier "
                    "fetches the URL, giving you SSRF from inside the token.", "5.3")
    if "crit" in header:
        print(f"  crit      {header['crit']!r} -- extensions the verifier MUST understand")
        finding("low", "crit header present",
                "RFC 7515 section 4.1.11 requires a verifier to reject a token whose crit "
                "names anything it does not implement. Many do not check. Send a crit "
                "naming a nonsense extension and see whether it is accepted.")


def _verdict_sig_length(alg, length):
    expected = {"hs256": 32, "hs384": 48, "hs512": 64, "es256": 64, "es384": 96,
                "es512": 132, "rs256": 256, "rs384": 256, "rs512": 256, "ps256": 256}
    want = expected.get(alg.lower())
    if want is None:
        return
    if alg.lower().startswith("rs") or alg.lower().startswith("ps"):
        bits = length * 8
        print(f"            implies a {bits}-bit RSA modulus")
        if bits < 2048:
            finding("high", f"RSA key appears to be {bits} bits",
                    "Below 2048 bits is not acceptable. NIST SP 800-57 retired 1024-bit "
                    "RSA in 2013.")
        return
    if length != want:
        finding("medium", f"{alg} signature is {length} bytes, expected {want}",
                "Either the algorithm label does not match the signature, or the "
                "encoding is non-standard. ECDSA in JOSE is raw r||s, NOT the DER "
                "sequence OpenSSL emits -- a common source of both bugs and confusion.")


def _print_claim_table(claims, now):
    width = max((len(str(k)) for k in claims), default=3)
    width = max(width, 12)
    for key in sorted(claims, key=lambda k: (k not in CLAIM_MEANINGS, k)):
        value = claims[key]
        shown = json.dumps(value) if not isinstance(value, str) else value
        if len(shown) > 60:
            shown = shown[:57] + "..."
        label = CLAIM_MEANINGS.get(key, (None, None))[0]
        suffix = ""
        if key in ("exp", "nbf", "iat", "auth_time", "updated_at") and \
                isinstance(value, (int, float)):
            delta = value - now
            suffix = (f"   [{human_time(value)}, "
                      f"{'in ' + human_duration(delta) if delta >= 0 else human_duration(-delta) + ' ago'}]")
        tag = c(f"({label})", "grey") if label else c("(not a registered claim)", "grey")
        print(f"  {key:<{width}}  {shown}{suffix}")
        print(f"  {'':<{width}}  {tag}")
    unknown = [k for k in claims if k not in CLAIM_MEANINGS]
    if unknown:
        print()
        print(f"  Application-specific claims: {', '.join(sorted(unknown))}")
        print("  Read each one and ask: is this an INPUT to an authorisation decision? If")
        print("  the server trusts it without re-checking, forging it is the attack.")


def _verdict_time(claims, now):
    print()
    print(c("  LIFETIME", "bold"))
    exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")

    if exp is None:
        print(c("  exp       ABSENT -- this token never expires", "red"))
        finding("critical", "no exp claim",
                "A token with no expiry is a permanent credential. One leak -- a log line, "
                "a backup, a screenshot, a crash report -- is permanent account access "
                "with no way to time it out. RFC 8725 section 3.9. Note that a verifier "
                "which 'checks exp if present' is defeated by simply removing it.", "5.5")
    elif not isinstance(exp, (int, float)):
        finding("high", f"exp is {type(exp).__name__}, not a number",
                "RFC 7519 says NumericDate: seconds since the epoch, as a number. A "
                "string here means somebody's parser is lenient. Try exp as a string, as "
                "null, and as a huge number.")
    else:
        remaining = exp - now
        lifetime = (exp - iat) if isinstance(iat, (int, float)) else None
        print(f"  exp       {human_time(exp)}  "
              f"({'expired ' + human_duration(-remaining) + ' ago' if remaining < 0 else human_duration(remaining) + ' remaining'})")
        if lifetime is not None:
            print(f"  lifetime  {human_duration(lifetime)} (exp - iat)")
            _judge_lifetime(lifetime, claims)
        if remaining < 0:
            finding("info", "the token is already expired",
                    "Useless against a correct verifier -- which is exactly why it is the "
                    "cheapest test you can run. Replay it. If it works, exp is not being "
                    "checked and every other token from this issuer is immortal too.")
    if nbf is not None and isinstance(nbf, (int, float)) and nbf > now:
        finding("info", "nbf is in the future",
                f"Not valid for another {human_duration(nbf - now)}.")
    if iat is not None and isinstance(iat, (int, float)) and iat > now + 300:
        finding("medium", "iat is in the future",
                "Either the issuer's clock is wrong or the claim was fabricated.")
    if "jti" not in claims:
        finding("low", "no jti",
                "Without a unique identifier there is no handle for replay detection or "
                "for a denylist. A JWT is stateless by design, so the only way to kill an "
                "individual token before exp is to record its jti somewhere -- which is "
                "the state everyone claims JWTs let them avoid. See README section 3.9.")


def _judge_lifetime(lifetime, claims):
    scope = str(claims.get("scope", "")) + " " + str(claims.get("role", ""))
    privileged = any(w in scope.lower() for w in
                     ("admin", "write", "payment", "transfer", "delete", "manage"))
    if lifetime > 30 * 86400:
        finding("high", f"token lifetime is {human_duration(lifetime)}",
                "This is not an access token in any meaningful sense; it is a password "
                "with extra steps. The point of a short access token is that theft has a "
                "deadline. See README section 5.5 for the honest-severity framing: the "
                "finding is the LIFETIME, and it stands whether or not you stole one.")
    elif lifetime > 86400:
        finding("medium", f"token lifetime is {human_duration(lifetime)}",
                "Longer than a day. Ask what the refresh token is for, if the access "
                "token already lasts this long.")
    elif lifetime > 3600 and privileged:
        finding("medium", f"privileged token lives {human_duration(lifetime)}",
                "The scope includes write or admin capability. Privileged tokens should "
                "be the shortest-lived ones you issue.")
    else:
        print(c(f"            reasonable for an access token", "green"))


def _verdict_binding(claims, expect_iss, expect_aud):
    print()
    print(c("  BINDING -- what ties this token to a specific issuer and consumer", "bold"))
    iss, aud = claims.get("iss"), claims.get("aud")

    if iss is None:
        print(c("  iss       ABSENT", "red"))
        finding("high", "no iss claim",
                "Nothing in the token names its issuer, so a verifier holding several "
                "keys cannot tell whose token this is. Combined with a permissive key "
                "lookup, a token from an issuer you also trust for something else is "
                "accepted here.", "5.6")
    else:
        print(f"  iss       {iss}")
        if expect_iss and iss != expect_iss:
            print(c(f"            ! you expected {expect_iss!r}", "red"))
            finding("high", "iss does not match what you expected",
                    "Compare with `==` on the full string. Prefix or substring matching "
                    "is bypassable: https://evil.example/?x=https://issuer.example.com "
                    "contains your issuer.", "5.6")
        elif expect_iss:
            print(c("            matches --expect-iss", "green"))

    if aud is None:
        print(c("  aud       ABSENT", "red"))
        finding("high", "no aud claim",
                "Nothing says who this token is FOR. Any service that trusts the issuer "
                "will accept it, so a token minted for a low-value first-party service is "
                "a valid credential at a high-value one. This is the mechanism behind the "
                "'Sign in with X' account takeover -- see 45-OAuth section 5.1 Attack 6.",
                "5.6")
    else:
        aud_list = [aud] if isinstance(aud, str) else list(aud)
        print(f"  aud       {aud_list}")
        if len(aud_list) > 1:
            finding("medium", f"token has {len(aud_list)} audiences",
                    "One token accepted by several services means a compromise at the "
                    "weakest one is a valid credential at the strongest. Check that azp "
                    "is present and that every consumer checks it.")
        if expect_aud:
            if expect_aud in aud_list:
                print(c("            matches --expect-aud", "green"))
            else:
                print(c(f"            ! you expected {expect_aud!r}", "red"))
                finding("high", "aud does not contain what you expected",
                        "If a service accepted this token anyway, it is not checking aud, "
                        "and any token that issuer signs is a skeleton key for it.", "5.6")
    if "nonce" in claims:
        print(f"  nonce     {claims['nonce']} -- present, and INSIDE the signature, so it "
              f"cannot be\n            rewritten. Confirm the client actually compares it. "
              f"See 45-OAuth 3.12.")


def _verdict_constraint(claims, header):
    print()
    print(c("  SENDER CONSTRAINING -- is possession alone enough?", "bold"))
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        print(c("  cnf       absent: this is a PURE BEARER TOKEN.", "yellow"))
        print("            Whoever holds these bytes is, as far as the server is")
        print("            concerned, the user. A copy taken off a phone works from a")
        print("            laptop on another continent, and nothing distinguishes it.")
        finding("medium", "no cnf claim -- pure bearer token",
                "Not a vulnerability on its own; it is how most of the internet works. "
                "It IS the amplifier that turns every storage and transport weakness in "
                "this repository into account access. The fixes are DPoP (RFC 9449) and "
                "mTLS-bound tokens (RFC 8705). Raise it where the token is long-lived, "
                "highly scoped, or stored somewhere another app can reach.", "5.7")
        return
    if "jkt" in cnf:
        print(c(f"  cnf.jkt   {cnf['jkt']}", "green"))
        print("            DPoP (RFC 9449): the token is bound to a public key whose")
        print("            private half stays on the device. A stolen token is useless")
        print("            without a fresh DPoP proof signed by that key, so the attack")
        print("            surface moves from 'read the token' to 'use the key in place'.")
        print("            Test: replay the token with the ORIGINAL DPoP proof (should")
        print("            fail on jti replay), and with NO proof at all (should fail).")
        finding("info", "token is DPoP-bound", "Record it as a positive. Then test that "
                "the resource server actually enforces the binding rather than merely "
                "tolerating the header.")
    if "x5t#S256" in cnf:
        print(c(f"  cnf.x5t#S256  {cnf['x5t#S256']}", "green"))
        print("            mTLS-bound (RFC 8705): the token is tied to a client")
        print("            certificate. Replay from anywhere without that certificate's")
        print("            private key fails at the TLS layer.")
        finding("info", "token is mTLS-bound", "A strong positive. Confirm the resource "
                "server compares the presented certificate's thumbprint rather than "
                "merely requiring some client certificate.")


def _verdict_privilege(claims):
    hits = {k: v for k, v in claims.items() if k in PRIVILEGE_CLAIMS}
    if not hits:
        return
    print()
    print(c("  AUTHORISATION DATA CARRIED IN THE TOKEN", "bold"))
    for key, value in hits.items():
        print(f"  {key:<12}  {json.dumps(value)}")
    flat = json.dumps(hits).lower()
    if any(word in flat for word in ("admin", "root", "superuser", "\"*\"", "all")):
        finding("high", "the token carries an elevated privilege claim",
                "Two separate tests follow. (1) FORGERY: can you edit this value? That is "
                "the alg=none / confusion / weak-secret family. (2) TRUST: even with a "
                "perfectly verified token, does the server re-derive the user's privileges "
                "from its own database, or does it trust this string? A server that trusts "
                "it has moved an authorisation decision into a value the client transports "
                "-- which is still wrong even when forgery is impossible, because the "
                "issuer and the resource server may disagree about what the role means.")
    else:
        finding("info", "the token carries authorisation data",
                "Enumerate every scope against a feature that needs it. A scope with no "
                "corresponding feature is over-scoping: see 45-OAuth section 3.12.")


def _verdict_pii(claims):
    found = sorted(set(claims) & PII_CLAIMS)
    secretish = [k for k, v in claims.items()
                 if SECRET_LIKE.search(str(k)) or
                 (isinstance(v, str) and len(v) > 20 and SECRET_LIKE.search(k))]
    if not found and not secretish:
        return
    print()
    print(c("  PAYLOAD CONTENT -- remember it is readable by anyone holding the token",
            "bold"))
    if found:
        print(f"  PII claims: {', '.join(found)}")
        finding("low", "personal data in the payload",
                "The payload is base64url, not encrypted. This data is readable in every "
                "log that records the Authorization header, every proxy, every crash "
                "report, and by any process that can read the app's storage. Minimise the "
                "claim set: if the resource server can look it up from `sub`, it does not "
                "belong in the token.")
    if secretish:
        print(c(f"  Claims whose NAME suggests a secret: {', '.join(secretish)}", "red"))
        finding("high", "a secret-looking value is inside the payload",
                "Nothing in a JWT payload is confidential. If this is a password, an API "
                "key or an internal identifier, treat it as published.")


# --------------------------------------------------------------------------- #
# Scanning arbitrary files
# --------------------------------------------------------------------------- #
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
BEARER_RE = re.compile(r"(?i)bearer\s+([A-Za-z0-9._~+/=-]{16,})")


def scan(text):
    seen = []
    for match in JWT_RE.findall(text):
        if match not in seen:
            seen.append(match)
    for match in BEARER_RE.findall(text):
        if match not in seen and not JWT_RE.fullmatch(match):
            seen.append(match)
    return seen


def self_test():
    print("Transmission guard self-test.")
    try:
        _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    except RuntimeError as exc:
        print(f"  socket.socket()        blocked: {exc}")
    else:
        print("  socket.socket()        NOT BLOCKED -- the guard is broken, do not use "
              "this script")
        return 1
    try:
        import urllib.request
        urllib.request.urlopen("http://127.0.0.1:1/")
    except RuntimeError as exc:
        print(f"  urllib.request         blocked: {exc}")
    except Exception as exc:                                   # noqa: BLE001
        print(f"  urllib.request         failed before connecting ({type(exc).__name__})")
    print("  No token this script reads can leave this machine through it.")
    return 0


def main():
    global USE_COLOUR
    ap = argparse.ArgumentParser(
        description="Offline JWT analyser. Decodes, judges every claim, flags every "
                    "failure class, and never transmits the token.")
    ap.add_argument("--token", help="the token itself")
    ap.add_argument("--file", help="a file containing the token")
    ap.add_argument("--scan", action="store_true",
                    help="with --file: extract every token-looking string and analyse each")
    ap.add_argument("--expect-iss", help="the exact iss you expect")
    ap.add_argument("--expect-aud", help="the exact aud you expect")
    ap.add_argument("--expect-alg", help="the alg the issuer is supposed to use")
    ap.add_argument("--now", type=int, help="override the clock, for reproducible output")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--no-colour", action="store_true")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the transmission guard works, then exit")
    args = ap.parse_args()

    if args.no_colour:
        USE_COLOUR = False
    if args.self_test:
        return self_test()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        tokens = scan(text) if args.scan else [text.strip()]
        if args.scan:
            print(f"[*] {len(tokens)} token-like string(s) in {args.file}")
    elif args.token:
        tokens = [args.token]
    else:
        ap.error("give --token or --file")
        return 2

    if not tokens:
        print("No tokens found.")
        return 0

    for token in tokens:
        FINDINGS.clear() if args.json and len(tokens) == 1 else None
        analyse(token, args.expect_iss, args.expect_aud, args.expect_alg, args.now)

    print()
    print(c("=" * 78, "grey"))
    print(c(f"  FINDINGS ({len(FINDINGS)})", "bold"))
    print(c("=" * 78, "grey"))
    for f in sorted(FINDINGS, key=lambda x: SEVERITY_ORDER[x["severity"]]):
        tag = f["severity"].upper()
        sec = f"  [README {f['section']}]" if f.get("section") else ""
        print(f"\n  {c(tag, SEVERITY_COLOUR[f['severity']])}  {f['title']}{sec}")
        for line in _wrap(f["detail"], 72):
            print(f"        {line}")
    print()
    print(c("  Every finding above is a HYPOTHESIS about a verifier you have not tested.",
            "bold"))
    print("  A token's header says what the ISSUER did. Only sending a forgery tells you")
    print("  what the VERIFIER accepts. Go and send one: labs/lab-02-the-jwt-attack-"
          "gauntlet.md")

    if args.json:
        print()
        print(json.dumps({"findings": FINDINGS}, indent=2))
    return 0


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


if __name__ == "__main__":
    sys.exit(main())
