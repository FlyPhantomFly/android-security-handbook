#!/usr/bin/env python3
"""
redirect-uri-fuzz.py — test how an authorisation server matches `redirect_uri`.

WHAT IT DOES
  RFC 6749 s3.1.2 requires the authorisation server to compare the supplied redirect_uri against
  the registered value using *simple string comparison*. Many servers instead normalise, prefix
  match, allow subdomains, or permit an open redirect on the registered host. Each of those turns
  "the attacker cannot receive the code" into "the attacker can".

  This script sends the target's own authorisation request with a mutated redirect_uri and reports,
  for each mutation, whether the server ACCEPTED it (rendered a login page or redirected onward) or
  REJECTED it (returned an error). It never completes a login and never handles a real credential —
  it only observes the server's acceptance decision, which is visible before any user interaction.

  Mutation families tested:
      exact              the registered value, as a control
      trailing           trailing slash, trailing dot, trailing null-ish encodings
      path               appended path, path traversal, double slash
      query/fragment     appended query and fragment segments
      subdomain          attacker.registered-host and registered-host.attacker
      userinfo           https://registered-host@attacker/
      scheme             http downgrade, and a competing custom scheme
      case               host and scheme case changes
      encoding           percent-encoded separators, unicode dot lookalikes
      open-redirect      a known redirector path on the registered host
      wildcard           a value that only matches under prefix or wildcard rules

USAGE
  python3 redirect-uri-fuzz.py \
      --authorize-url "https://login.example.com/oauth2/authorize" \
      --client-id "com.example.app" \
      --registered "https://login.example.com/android/callback" \
      --attacker "https://attacker.test/cb"

  # feed it a full captured URL instead and it will pull the parameters out
  python3 redirect-uri-fuzz.py --from-url "https://login.example.com/authorize?response_type=code&..." \
      --attacker "https://attacker.test/cb"

  # just print the mutations without sending anything
  python3 redirect-uri-fuzz.py --registered "app://cb" --attacker "https://attacker.test/cb" --dry-run

OPTIONS
  --proxy http://127.0.0.1:8080   route everything through Burp so you can inspect responses
  --delay 0.5                     seconds between requests; be polite, and avoid rate limits
  --insecure                      skip TLS verification (needed behind an intercepting proxy)

SAFETY AND SCOPE
  Only run this against an authorisation server you are authorised to test. The requests are
  unauthenticated GETs to a public endpoint, but volume and intent still matter — set --delay, keep
  the mutation list short, and tell the client you are doing it. The script never submits
  credentials and never follows a redirect to an attacker host with real parameters.

DEPENDENCIES
  Python 3.8+. Uses `requests` if available, otherwise falls back to urllib.

Chapter 45 — OAuth 2.0 and OpenID Connect on Android, section 5.1 Attack 2
"""

import argparse
import sys
import time
from urllib.parse import urlparse, urlencode, parse_qsl, quote

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:                                          # pragma: no cover
    HAVE_REQUESTS = False
    import urllib.request
    import urllib.error

USE_COLOUR = sys.stdout.isatty()


def c(text, colour):
    if not USE_COLOUR:
        return text
    codes = {"red": 31, "yellow": 33, "green": 32, "grey": 90, "bold": 1}
    return f"\033[{codes[colour]}m{text}\033[0m"


# --------------------------------------------------------------------------- #
# Mutation generation
# --------------------------------------------------------------------------- #

def build_mutations(registered: str, attacker: str):
    """Return a list of (family, description, candidate_redirect_uri, why_it_matters)."""
    p = urlparse(registered)
    scheme = p.scheme
    host = p.netloc
    path = p.path or ""
    base = f"{scheme}://{host}{path}"
    att = urlparse(attacker)
    att_host = att.netloc or "attacker.test"

    m = []

    def add(family, desc, uri, why):
        m.append((family, desc, uri, why))

    add("control", "exact registered value", registered,
        "Must be accepted. If this is rejected, the rest of the run is meaningless.")

    # --- trailing characters -------------------------------------------------
    add("trailing", "trailing slash", base + "/",
        "A server that normalises trailing slashes is not doing simple string comparison.")
    add("trailing", "trailing dot on host", f"{scheme}://{host}./{path.lstrip('/')}",
        "DNS treats 'host.' as equivalent to 'host'; string comparison does not.")
    add("trailing", "double trailing slash", base + "//",
        "Reveals path normalisation.")

    # --- appended path -------------------------------------------------------
    add("path", "appended path segment", base + "/anything",
        "If accepted, the server is prefix matching. Combined with an open redirect or a "
        "user-controlled path on that host, the code can be delivered elsewhere.")
    add("path", "path traversal", base + "/../evil",
        "Tests whether the server resolves '..' before or after comparison.")
    add("path", "encoded traversal", base + "/%2e%2e/evil",
        "Same test, but only reachable if the server decodes before comparing.")
    add("path", "semicolon path parameter", base + ";x=/../evil",
        "Some frameworks strip path parameters before routing but after validation.")

    # --- query and fragment --------------------------------------------------
    add("query", "appended query", base + "?x=1",
        "Query strings are not part of the registered URI. Acceptance implies prefix matching.")
    add("query", "appended fragment", base + "#x",
        "A fragment never reaches the server, but it changes the browser's final destination.")
    add("query", "injected redirect param", base + f"?next=https://{att_host}/",
        "Combined with a redirector on the registered host, this delivers the code to the "
        "attacker while the redirect_uri itself looks legitimate.")

    # --- host manipulation ---------------------------------------------------
    add("subdomain", "attacker subdomain of registered host",
        f"{scheme}://{att_host}.{host}{path}",
        "Tests suffix matching. A server allowing *.example.com plus any subdomain takeover "
        "is a full compromise of the flow.")
    add("subdomain", "registered host as a subdomain of the attacker",
        f"{scheme}://{host}.{att_host}{path}",
        "Tests prefix matching on the host — a naive startswith() check fails here.")
    add("subdomain", "attacker host entirely", f"{scheme}://{att_host}{path}",
        "The blunt test. If this is accepted, the registration is not enforced at all.")

    # --- userinfo and authority tricks --------------------------------------
    add("userinfo", "registered host in the userinfo component",
        f"{scheme}://{host}@{att_host}{path}",
        "Everything before '@' is userinfo, not the host. A validator that searches for the "
        "registered host as a substring is fooled; the browser goes to the attacker.")
    add("userinfo", "backslash separator", f"{scheme}://{att_host}\\@{host}{path}",
        "Parser differential: some URL parsers treat backslash as a separator, some do not.")
    add("userinfo", "credentials form", f"{scheme}://user:pass@{att_host}{path}",
        "Tests whether userinfo is stripped before comparison.")

    # --- scheme --------------------------------------------------------------
    if scheme == "https":
        add("scheme", "http downgrade", f"http://{host}{path}",
            "If accepted, the authorisation code travels in cleartext.")
    add("scheme", "competing custom scheme", f"evilapp://{host}{path}",
        "Tests whether the scheme is part of the comparison at all.")
    add("scheme", "scheme case change", f"{scheme.upper()}://{host}{path}",
        "Schemes are case-insensitive per RFC 3986; simple string comparison is not.")

    # --- case ----------------------------------------------------------------
    add("case", "host uppercased", f"{scheme}://{host.upper()}{path}",
        "Hosts are case-insensitive; paths are not. Reveals which normalisation is applied.")
    add("case", "path case changed", f"{scheme}://{host}{path.upper()}",
        "If accepted, path comparison is case-insensitive, which widens the match set.")

    # --- encoding ------------------------------------------------------------
    add("encoding", "percent-encoded slash", f"{scheme}://{host}{path}%2f..%2fevil",
        "Tests decode-then-compare versus compare-then-decode.")
    add("encoding", "double-encoded", f"{scheme}://{host}{path}%252e%252e%252fevil",
        "Catches servers that decode twice.")
    add("encoding", "unicode dot lookalike", f"{scheme}://{host.replace('.', '%E3%80%82', 1)}{path}",
        "Ideographic full stop normalises to '.' in some resolvers.")

    # --- custom scheme specific ---------------------------------------------
    if scheme not in ("http", "https"):
        add("scheme", "host swapped on a custom scheme", f"{scheme}://evil{path}",
            "For custom schemes the 'host' is just a string in the intent filter; check whether "
            "the SERVER treats it as significant.")

    # --- wildcard ------------------------------------------------------------
    add("wildcard", "literal wildcard", f"{scheme}://{host}/*",
        "Some servers store wildcards; sending one shows whether they are interpreted.")
    add("wildcard", "empty redirect_uri", "",
        "If accepted, the server falls back to a default — find out which.")

    return m


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #

def send(url, proxy=None, insecure=False, timeout=15):
    """Return (status_code, location_header, body_snippet) without following redirects."""
    if HAVE_REQUESTS:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        try:
            r = requests.get(url, allow_redirects=False, proxies=proxies,
                             verify=not insecure, timeout=timeout)
            return r.status_code, r.headers.get("Location", ""), r.text[:400]
        except Exception as exc:                             # noqa: BLE001
            return None, "", f"<request failed: {exc}>"
    else:                                                    # pragma: no cover
        req = urllib.request.Request(url, headers={"User-Agent": "oauth-redirect-fuzz/1.0"})
        opener = urllib.request.build_opener(NoRedirect())
        try:
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.headers.get("Location", ""), resp.read(400).decode(
                "utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location", ""), e.read(400).decode("utf-8", "replace")
        except Exception as exc:                             # noqa: BLE001
            return None, "", f"<request failed: {exc}>"


class NoRedirect(getattr(__import__("urllib.request", fromlist=["x"]), "HTTPRedirectHandler")):
    """urllib fallback: never follow redirects, so we can read the Location header ourselves."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):   # noqa: D102, N802
        return None


def classify(status, location, body, candidate, registered, attacker_host):
    """Decide whether the server accepted the mutated redirect_uri."""
    if status is None:
        return "error", "request failed"

    body_l = (body or "").lower()
    rejected_markers = ["invalid_request", "invalid redirect", "redirect_uri_mismatch",
                        "unregistered", "invalid_client", "does not match", "unauthorized_client",
                        "invalid redirect_uri"]
    if any(marker in body_l for marker in rejected_markers):
        return "rejected", "error page names a redirect_uri problem"
    if any(marker in (location or "").lower() for marker in ("error=invalid", "redirect_uri")):
        return "rejected", "error returned via redirect"

    if status in (301, 302, 303, 307, 308):
        if attacker_host and attacker_host in (location or ""):
            return "accepted", f"302 to an attacker-controlled destination: {location[:80]}"
        return "maybe", f"{status} -> {location[:80]}"

    if status == 200:
        if any(k in body_l for k in ("password", "sign in", "login", "consent", "username")):
            return "accepted", "200 with a login/consent page — the server accepted the value"
        return "maybe", "200 but no recognisable login page"

    if status in (400, 401, 403):
        return "rejected", f"HTTP {status}"

    return "maybe", f"HTTP {status}"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Test how an authorisation server matches redirect_uri.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--authorize-url", help="the authorisation endpoint, no query string")
    ap.add_argument("--from-url", help="a full captured /authorize URL; parameters are reused")
    ap.add_argument("--client-id")
    ap.add_argument("--registered", required=True, help="the app's real, registered redirect_uri")
    ap.add_argument("--attacker", default="https://attacker.test/cb",
                    help="a host you control, used in the mutations")
    ap.add_argument("--scope", default="openid")
    ap.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--delay", type=float, default=0.7, help="seconds between requests")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--dry-run", action="store_true", help="print mutations, send nothing")
    ap.add_argument("--family", help="only run one mutation family")
    args = ap.parse_args()

    base_params = {
        "response_type": "code",
        "client_id": args.client_id or "",
        "scope": args.scope,
        "state": "fuzz-" + str(int(time.time())),
    }
    endpoint = args.authorize_url

    if args.from_url:
        p = urlparse(args.from_url)
        endpoint = f"{p.scheme}://{p.netloc}{p.path}"
        captured = dict(parse_qsl(p.query, keep_blank_values=True))
        base_params.update(captured)
        base_params.pop("redirect_uri", None)
        print(c(f"  reusing captured parameters: {sorted(captured)}", "grey"))

    if not endpoint and not args.dry_run:
        ap.error("--authorize-url or --from-url is required unless --dry-run")

    mutations = build_mutations(args.registered, args.attacker)
    if args.family:
        mutations = [m for m in mutations if m[0] == args.family]

    attacker_host = urlparse(args.attacker).netloc

    print()
    print(c(f"  registered redirect_uri : {args.registered}", "bold"))
    print(c(f"  attacker host           : {attacker_host}", "bold"))
    print(c(f"  mutations               : {len(mutations)}", "bold"))
    print()

    results = []
    for family, desc, candidate, why in mutations:
        params = dict(base_params)
        params["redirect_uri"] = candidate
        url = f"{endpoint}?{urlencode(params, quote_via=quote)}" if endpoint else "(dry run)"

        if args.dry_run:
            print(f"  [{family:<10}] {desc}")
            print(f"               {candidate}")
            continue

        status, location, body = send(url, args.proxy, args.insecure)
        outcome, reason = classify(status, location, body, candidate, args.registered,
                                   attacker_host)
        results.append((family, desc, candidate, outcome, reason, why))

        mark = {"accepted": c("[ACCEPTED]", "red"),
                "rejected": c("[rejected]", "green"),
                "maybe":    c("[  ???   ]", "yellow"),
                "error":    c("[ error  ]", "grey")}[outcome]
        print(f"  {mark} {family:<10} {desc}")
        print(f"             uri    : {candidate or '(empty)'}")
        print(f"             result : {reason}")
        print()
        time.sleep(args.delay)

    if args.dry_run:
        return 0

    # ------------------------------------------------------------------ #
    control = next((r for r in results if r[0] == "control"), None)
    if control and control[3] != "accepted":
        print(c("  WARNING: the control (exact registered value) was not accepted.", "red"))
        print("  Every other result in this run is unreliable. Check the client_id, the")
        print("  endpoint and any additional required parameters, then rerun.\n")

    accepted = [r for r in results if r[3] == "accepted" and r[0] != "control"]
    maybe = [r for r in results if r[3] == "maybe"]

    print(c("=" * 76, "grey"))
    print(c("  SUMMARY", "bold"))
    print(c("=" * 76, "grey"))

    if accepted:
        print(c(f"\n  {len(accepted)} mutation(s) ACCEPTED — the server is not performing simple "
                "string comparison.\n", "red"))
        for family, desc, candidate, _, reason, why in accepted:
            print(f"  * [{family}] {desc}")
            print(f"      {candidate}")
            print(f"      why it matters: {why}")
            print()
        print("  Impact: the authorisation code can be delivered somewhere the application does")
        print("  not control. If the server also fails to enforce PKCE (see lab 02), this is")
        print("  account takeover. If PKCE is enforced, the stolen code is inert and this drops")
        print("  to a lower severity — say so explicitly in the report.")
    else:
        print(c("\n  No mutation accepted. The server appears to perform exact matching.", "green"))
        print("  Record this as tested-and-passed rather than not-tested.")

    if maybe:
        print(c(f"\n  {len(maybe)} inconclusive result(s) — inspect these manually in the proxy:",
                "yellow"))
        for family, desc, candidate, _, reason, _why in maybe:
            print(f"    [{family}] {desc}: {reason}")
            print(f"      {candidate}")

    print()
    return 2 if accepted else 0


if __name__ == "__main__":
    sys.exit(main())
