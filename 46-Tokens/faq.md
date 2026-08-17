# 46 — Tokens · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask, which
are usually the important ones.

Full text: [README.md](README.md) · [cheat sheet](cheatsheet.md) · [mind map](mindmap.md)

---

### 1. Is a JWT encrypted?

**No.** This is the single most common misunderstanding about JWTs and it is held by
developers as often as by testers.

The header and payload are **base64url-encoded**. Base64url is a *transport encoding*: its
job is to represent arbitrary bytes using characters that survive being placed in a URL or
an HTTP header. There is no key. There is no secret. Reversing it is one function call.

```bash
echo "$JWT" | cut -d. -f2 | tr '_-' '/+' | base64 -d; echo
```

Anyone holding the token — a proxy, a log aggregator, a crash reporter, a malicious app
that read your storage, someone looking over your shoulder — reads every claim.

The signature makes the claims **authentic**. It does nothing to make them **secret**.

A JWT whose payload genuinely is encrypted is a **JWE**, and it has five segments rather
than three. They are rare. Count the dots: four dots means JWE.

The practical rule for developers: *if the resource server can look this up from `sub`, it
does not belong in the token.*

---

### 2. Can I just edit a JWT?

**You can always edit it. Whether it still works is a completely different question, and
that question is about the server, not the token.**

Editing is trivial: decode the payload, change a value, re-encode, reassemble. Ninety
seconds, no tools.

What happens next depends entirely on the verifier:

| If the verifier | Your edited token |
|---|---|
| Checks the signature properly | is rejected — the signature no longer matches |
| Accepts `alg: none` | works, because you also removed the signature |
| Picks the algorithm from the token | works, if you re-signed as HS256 with the public key |
| Uses a weak HMAC secret you cracked | works, because you re-signed it correctly |
| Never checks `exp` / `iss` / `aud` | works **without any editing at all** |

So the honest answer is: editing is free, and finding out whether it matters costs exactly
one HTTP request. Send it and read the response code.

[Lab 02](labs/lab-02-the-jwt-attack-gauntlet.md) makes you do all eight variants.

---

### 3. What does `alg: none` mean?

It means **"this token is not signed"**.

`none` is a real, registered JWT algorithm. RFC 7519 defines it for the case where
integrity is guaranteed by some *other* mechanism — a JWT already wrapped inside an
authenticated envelope, for instance. It exists legitimately, which is exactly why
libraries implement it, which is why it is available to be accepted by mistake.

The attack: take a genuine token, replace the header with `{"alg":"none","typ":"JWT"}`,
edit the claims to whatever you like, and leave the third segment **empty**.

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
                                                          ^ keep this dot
```

**The trailing dot is mandatory.** A token ending in `.` is structurally a three-segment JWT
with a zero-length signature. Drop the dot and you have sent a two-segment string, which a
verifier rejects for a *structural* reason — and you conclude the attack failed when you
never actually sent it. This costs testers ten minutes each, reliably.

Also try `NoNe`, `NONE` and `nOnE`. Verifiers that block the literal string `none` and
nothing else are a real category.

---

### 4. Where should an Android app store a token?

Depends which token.

| Token | Home | Why |
|---|---|---|
| **Access token** | In memory, re-fetched on cold start | Shortest-lived and least valuable. Losing it costs one refresh |
| **Refresh token** | `EncryptedSharedPreferences` | It must survive restarts, and it is the crown jewel |
| **ID token** | **Nowhere.** Use it once and discard it | It describes a past login and has no ongoing purpose |

`EncryptedSharedPreferences` (Jetpack `androidx.security:security-crypto`, API 23+)
generates a master key inside the Android Keystore, so no key material exists in the APK.

**What that buys, precisely:** an attacker who obtains a *copy* of the preferences file —
through a backup, a forensic image, a world-readable path, a traversal bug elsewhere in the
app — cannot read it.

**What it does not buy:** anything at all against an attacker running code inside the app's
process. They call `prefs.getString("refresh_token", null)` and receive the plaintext,
exactly as the app does. See [49-KeyStore §1.3](../49-KeyStore/README.md) — extraction
versus use.

---

### 5. Is a long-lived token always bad?

**No**, and answering "yes" is a good way to lose credibility with a developer.

Refresh tokens are *designed* to be long-lived. A 90-day refresh token with rotation and
reuse detection is a sound, common, defensible design.

What matters is the **combination**:

| Lifetime | Rotation | Scope | Storage | Verdict |
|---|---|---|---|---|
| 90 days | Yes, with reuse detection | Narrow | Encrypted | ✅ Fine |
| 90 days | **No** | Narrow | Encrypted | 🟠 One theft is three months of access |
| 90 days | No | `payments.write` | Plaintext, survives logout | 🔴 Four findings |
| 15 min | n/a | Narrow | Plaintext prefs | ⚪ Informational at most |

The one absolute: **a token with no `exp` at all is always Critical.** That is not a
long-lived token, it is a permanent credential, and one leak — a log line, a backup, a
screenshot — is permanent account access with no way to time it out.

---

### 6. If I capture a token, is that a finding?

**Usually not, and this is the most common way a mobile report loses credibility.**

You logged in as your own test user. You proxied the traffic, or rooted the device and read
the preferences file, or attached Frida. You now hold a token granting access to **your own
account** — which you already had, because it is your account.

You learned nothing you did not already have.

It becomes a finding when at least one of these is true, and you have evidence for the
specific one:

1. **Over-scoped** — a scope↔feature table with an empty row
2. **Long-lived** — `exp - iat`, or a refresh token demonstrably alive after N days
3. **Replayable after logout** — two `curl` calls, both 200
4. **Accepted without verification** — the forged token **and the server's 200**
5. **Readable by another app** — the path, the modes, the SELinux labels, ideally a
   zero-permission proof-of-concept reader

Ask it out loud before writing: *what did I learn that I did not already have?*

---

### 7. What is the difference between an access token and a refresh token?

| | Access token | Refresh token |
|---|---|---|
| Sent to | Every resource server, on every request | Only the authorization server's `/token` |
| Lifetime | Minutes to an hour | Days to months |
| Format | Opaque or JWT | Almost always opaque |
| If stolen | Access until it expires | **Mint new access tokens indefinitely** |

The design looks contradictory at first — the access token expires in 15 minutes but the
refresh token that mints new ones lasts 90 days, so what was gained?

Two things. The **exposure profiles differ by orders of magnitude**: the access token goes
to every service on every request, so it appears in proxies, logs, load balancers and
third-party APIs constantly. The refresh token goes to exactly one endpoint, occasionally.
And **rotation with reuse detection makes the long lifetime self-limiting** — a stolen
refresh token works until either party uses it twice, at which point the whole family dies
loudly.

---

### 8. What is refresh token rotation, and why does "reuse detection" matter so much?

**Rotation:** every use of a refresh token issues a new one and invalidates the old.
`RT1` → `RT2` → `RT3`.

Rotation alone just bounds the window. **Reuse detection** is where the value is.

If `RT1` is presented twice, exactly one of two things happened: the legitimate client used
it and an attacker replayed it, or an attacker used it and the legitimate client then tried.
**The server cannot tell which, and does not need to.** It knows a copy exists somewhere it
should not, so it revokes the **entire token family**.

That converts a silent, permanent compromise into a loud, bounded one. The cost of a false
positive is one re-login.

Test it in three requests:

```bash
curl -s -X POST "$AS" -d grant_type=refresh_token -d refresh_token="$RT1" -d client_id="$CID" | tee r1.json
curl -s -X POST "$AS" -d grant_type=refresh_token -d refresh_token="$RT1" -d client_id="$CID"
curl -s -X POST "$AS" -d grant_type=refresh_token -d refresh_token="$(jq -r .refresh_token r1.json)" -d client_id="$CID"
```

Fail on the second and fail on the third means it is correct. Do this on a test account and
expect to be logged out — that is the control working.

---

### 9. Why can I not just revoke a JWT?

Because a JWT is verified **locally**, using a cached public key, with no call to the
issuer. That is the entire performance argument for using one.

Revocation asks the resource server to know something that happened *after* the token was
minted. Which means asking somebody. Which means you have reintroduced exactly the state
the JWT existed to avoid.

Four honest options:

1. **Short lifetimes.** Not revocation — a bound on how *late* revocation is. Right for most
   systems, and free.
2. **A `jti` denylist.** Real revocation, but now every resource server needs a shared,
   low-latency store. The state is back and it is distributed.
3. **A per-user "not valid before" timestamp.** Reject any token whose `iat` predates the
   user's last logout or password change. One integer per user instead of one row per token,
   and it makes "log out everywhere" actually work.
4. **Opaque tokens with introspection.** Stop pretending; pay the round trip.

Recommend by size: option 1 for almost everyone, option 3 for anyone who needs "log out
everywhere" to be real.

---

### 10. The app "logs out" but my old token still works. Is that a bug?

**Partly yes, and the interesting part is which part.**

Most Android logout implementations are:

```java
prefs.edit().clear().apply();
startActivity(new Intent(this, LoginActivity.class));
```

That makes the **screen** change. It does nothing to the tokens, which remain valid at the
server until they expire.

| Observation | Verdict |
|---|---|
| Access token works for a few more minutes | **Expected** for a stateless JWT. Note it; do not inflate it |
| Access token works for hours | The lifetime is too long. Medium |
| **Refresh token still works** | **The finding.** Logout must call `/revoke` (RFC 7009). High |
| "Log out of all devices" leaves tokens alive | Higher — the user was given a control that does nothing |
| Tokens survive a **password change** | Highest. The canonical incident response did not work |

Three requests and one button press. It is the highest-yield ninety seconds in a token
test, and it is skipped constantly.

---

### 11. What is HS/RS algorithm confusion? I do not understand how it can possibly work.

It is the most elegant attack in the chapter and the confusion is usually about one point:
**the attacker does not steal anything.**

The issuer signs with RS256, so the verifier holds the issuer's **public** key. That key is
*published*, deliberately, at the JWKS endpoint, for anyone in the world to fetch. That is
how asymmetric signing is supposed to work.

Now suppose the verifier is written like this:

```python
key = load_the_one_key()             # the RSA PUBLIC key
if alg.startswith("HS"):
    check_hmac(key, ...)             # <-- the public key, as an HMAC secret
elif alg.startswith("RS"):
    check_rsa(key, ...)
```

The attacker changes `alg` to `HS256` and signs their forged token using the public key's
bytes as an HMAC secret. The verifier loads the same bytes and computes the same HMAC. It
matches.

No key was stolen. No cryptography was broken. A value that is correctly public was used
for a **second purpose**, because the code let the token choose which purpose.

Two fixes, and you want both:
- An **algorithm allow-list** decided in advance: `ALLOWED_ALGS = {"RS256"}`.
- **Typed key storage**: RSA public keys in one map, HMAC secrets in another, so the HMAC
  path cannot reach an RSA key at all.

[Lab 02](labs/lab-02-the-jwt-attack-gauntlet.md) attack A3 makes you do it, and
[Lab 04](labs/lab-04-ctf-the-token-that-outlived-its-owner.md) Path B makes you reconstruct
the key from the published JWKS first.

---

### 12. My HS256 secret is `Th1s_Is_A_V3ry_L0ng_S3cret!` — is that safe?

No, and the reason is worth understanding rather than just accepting.

An HS256 token carries its own verification equation:

```
signature == HMAC-SHA256( secret, header_b64 + "." + payload_b64 )
             \______/     \_________________________________/
             unknown              all known, from the token
```

Every term except the secret is inside the token. So a captured token is a **self-contained
offline cracking target**: no server, no request, no rate limit, no lockout, no log entry,
and no way for you to know it is happening. An attacker grinds on it for a year on a laptop
under a desk.

Measured while writing this chapter, in pure interpreted Python on one core with no GPU:
**269,937 candidates per second**. `hashcat -m 16500` on a GPU is roughly four orders of
magnitude faster.

An HMAC key is not a password. RFC 7518 §3.2 requires it to be at least as long as the hash
output — 32 bytes for HS256 — and RFC 8725 §3.5 says generate it from a CSPRNG:

```bash
openssl rand -base64 48
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

And strategically: prefer asymmetric. With RS256 the verifier holds only a public key, so a
compromised resource server cannot mint tokens.

---

### 13. What is `kid` and why does everyone say it is dangerous?

`kid` is the **key identifier** in the JOSE header. It tells the verifier which key to use,
which is genuinely useful — you cannot rotate keys without it.

The danger is what it is made of: `kid` is written by **whoever wrote the token**, which
means an attacker writes it. And verifiers use it to *locate* a key:

| Where `kid` goes | Attack |
|---|---|
| `open(os.path.join(keydir, kid))` | `../../../../dev/null` → an empty key you can HMAC with |
| `SELECT key FROM keys WHERE kid = '...'` | SQL injection returning a key you chose |
| `requests.get(kid)` | Key injection **and** SSRF from inside the server |

The correct design has no filesystem, no database and no network in it. `kid` selects from
a small, in-memory map of keys the verifier already trusts, and an unknown `kid` is a
rejection rather than a lookup:

```python
pem = self.rsa_public_pems.get(kid)      # a dict lookup. That is all.
if pem is None:
    return None, f"unknown RSA kid {kid!r}"
```

Related and worse: `jku`, `x5u`, `jwk` and `x5c` let the token carry its own key or a URL
to it. RFC 8725 §3.8 says ignore them.

---

### 14. Why is sending the `id_token` to my API a problem? It is signed by Google.

Because `aud` — the audience claim — names the **client**, not your API.

An `id_token` is a statement *to your app* about who logged in. It is not a credential for
any resource server. If your API accepts one, that proves your API is not checking `aud`.
And an API that does not check `aud` will accept **any** token that issuer signed.

Here is why that is fatal. Anyone can register a client with a public identity provider —
that is what public client registration means. So an attacker:

1. Registers "FunGame" as an OAuth client with the same IdP. Free, takes minutes.
2. Gets a victim to sign into FunGame with their Google account. Entirely voluntary.
3. Receives a **genuinely, correctly, Google-signed** `id_token` for the victim's identity,
   with `aud: "fungame-client-id"`.
4. Replays it to your API.

Every signature check passes perfectly. The only thing that would have caught it is `aud`.

You can prove it against your own account with no victim: register your own test client,
sign in as yourself, and present the resulting token to the target. If it creates a session,
`aud` is not being checked.

[45-OAuth §5.1 Attack 6](../45-OAuth/README.md) has the full flow and its
[CTF path C](../45-OAuth/labs/lab-04-ctf-the-borrowed-identity.md) makes you exploit it.

---

### 15. What is DPoP, and does it actually help?

DPoP (RFC 9449) binds a token to a **key the client holds**, so possession of the token is
no longer sufficient.

The client generates a keypair (on Android, in the Keystore). On every request it builds a
tiny JWT called a *proof*, whose header carries the public key inline and whose claims name
the HTTP method, the URI, a unique id, a timestamp, and a hash of the access token. It signs
the proof with the private key. The access token itself carries `cnf.jkt` — the thumbprint
of the public key it was bound to. The server recomputes the thumbprint from the proof and
compares.

**It genuinely helps** against an attacker who obtained the token but not the key: a leaked
log, a stolen backup, a proxy, a compromised resource server, a token in a URL. That is a
large and realistic class, and DPoP downgrades all of it.

**It does nothing** against an attacker with code execution in the app's process. They do
not need to extract the Keystore key — they call the same signing routine and get valid
proofs. On a rooted device with Frida attached, DPoP buys exactly zero, and claiming
otherwise in a report is wrong.

**The test that decides whether a deployment is real:** strip the DPoP header, change the
scheme to `Bearer`, and send the same token. If it still works, the binding is optional,
which means it is absent — an attacker simply does not send a proof.

---

### 16. What is the difference between an opaque token and a JWT, and why do I care?

An opaque token is a **reference** — a random string that means nothing by itself. All the
state lives in the issuer's database. A JWT is a **document** — the claims are inside it,
signed.

You care because it redirects your entire test plan:

| | Opaque | JWT |
|---|---|---|
| `alg: none` | **Inapplicable** — there is no `alg` | Test it |
| Algorithm confusion | **Inapplicable** | Test it |
| Secret cracking | **Inapplicable** | Test it if HS* |
| Editing claims | **Inapplicable** — there are none | Test it |
| Replay after logout | Test it | Test it |
| Entropy / guessability | Test it | Not applicable in the same way |
| Introspection caching | Test it | Not applicable |

Testers waste hours trying to forge opaque tokens. **Count the dots first.** Three segments
starting `eyJ` is a JWT; anything else is opaque and half the chapter does not apply.

The design trade, in one sentence: *a JWT buys you a network round trip per request and pays
for it with the ability to change your mind.*

---

### 17. Can I use a public JWT decoder website?

**No.** Not for a client's token, not for a token from an engagement, and — practically —
not for any token, because you will not always know which one is in your clipboard.

Those sites receive the token you paste into them. Pasting a client's token into one is a
data-handling incident and it has ended engagements.

Decode locally. `scripts/jwt-analyse.py` installs a guard that replaces `socket.socket` with
a class that raises on construction, so no code path in it can open a connection — not even
one added by a future edit. Prove it:

```bash
python3 -B scripts/jwt-analyse.py --self-test
```

Or use `cut` and `base64`, which also cannot reach the network:

```bash
echo "$JWT" | cut -d. -f2 | tr '_-' '/+' | base64 -d; echo
```

---

### 18. What is `base64url` and why can I not just use `base64`?

They are the same encoding with two characters changed and one convention dropped.

| Value | Standard base64 (RFC 4648 §4) | base64url (RFC 4648 §5) |
|---|---|---|
| 62 | `+` | `-` |
| 63 | `/` | `_` |
| Padding | `=` required | Stripped |

The reason is that `+`, `/` and `=` all have meaning in URLs and would need escaping. A JWT
must survive being placed in a query string, a header, or a cookie without further mangling.

Two practical consequences:

**Decoding:** `base64 -d` on a JWT segment fails or produces garbage unless you convert
first. `tr '_-' '/+'` handles the alphabet, and most decoders tolerate the missing padding.

**As a fingerprint:** a segment containing `+` or `/` means whoever produced the token used
a **standard base64** encoder. Library-produced tokens never look like that. A hand-rolled
forgery often does, which makes it a useful tell — and it is why
`examples/02-correct-verifier.py` rejects such segments outright (RFC 8725 §3.11 asks for
exactly this strictness).

---

### 19. Should the Android app verify the `id_token` itself?

**Usually no**, and this surprises people because "verify your inputs" is such a strong
instinct.

The client already knows who its user is: the person holding the phone who just completed a
login. What it needs from the server is a **session**. The server must verify the token,
because the server is the party that will **act** on the answer.

The failure mode this avoids is subtle and common: an app that verifies the token locally
and then tells the backend *"the user is alice@example.com"* has built a backend that trusts
the **client's conclusion**. The verification was real, correct, and completely worthless.

The rule: **the party that acts on the answer must be the party that checks it.**

`examples/04-HardenedTokenStore.kt` does not contain a fixed version of the broken
`userIdFromIdToken` method — the method is deleted, and the token is sent to the backend.
That deletion is the fix.

(There are exceptions: an offline-capable app that must make a local decision with no server
available has to verify locally. Then do it properly — JWKS, algorithm allow-list, `iss`,
`aud`, `exp`, `nonce` — and be clear that the decision is advisory until the server
confirms.)

---

### 20. I found a JWT hardcoded in an app's `strings.xml`. Is that a jackpot?

**Almost never**, and the reason it is still worth ten minutes is not the reason you think.

Nine times out of ten it is a test fixture somebody forgot to remove, and it expired in
2023. Its value as a *credential* is zero.

Its value as **reconnaissance** is real. Decode it and read:

- `iss` — the identity provider, often an internal hostname you did not know about
- `aud` — a client identifier, which tells you what else is registered
- `scope` / `roles` — the permission vocabulary, for free
- Custom claims — tenant identifiers, environment names, feature flags
- Occasionally, a `sub` that is a real internal account

That is a map of the identity infrastructure obtained from a string in a resource file.
[52-StaticAnalysis](../52-StaticAnalysis/README.md) makes the same point from a different
angle: its most interesting finding in a real sweep was a `Domain` enum shipping thirteen
environments, sitting at MEDIUM confidence while the entire HIGH band was false positives.

Check whether the token still works before deciding — one `curl` — but write it up as
information disclosure about the infrastructure, not as a credential leak, unless it
actually is one.

---

### 21. Why does my `alg: none` token get rejected with a "malformed token" error?

Almost certainly the **trailing dot**.

```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9      ← 2 segments. Structurally invalid.
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.     ← 3 segments, the third empty. Correct.
```

`"a.b".split(".")` gives two elements. `"a.b.".split(".")` gives three, the last empty. A
verifier checking `len(parts) != 3` rejects the first with a structural error that looks
exactly like "the attack failed".

It did not fail. It was never sent.

---

### 22. What does `cnf` mean and why does the analyser make a fuss about it being absent?

`cnf` is the **confirmation** claim, RFC 7800. It is the claim that turns a bearer token
into a sender-constrained one.

| `cnf` member | Binding |
|---|---|
| `jkt` | DPoP — the RFC 7638 thumbprint of a key the client holds |
| `x5t#S256` | mTLS — the thumbprint of a client certificate |

Its **absence** means the token is a pure bearer credential: possession is sufficient, full
stop.

That is not a vulnerability on its own — it is how most of the internet works, and flagging
it as one would be noise. What it *is* is the **amplifier**: it is the reason a token in a
log line, or in a backup, or in another app's reach, becomes account access rather than
local data disclosure.

Write it that way in a report: *"the token is a pure bearer credential (no `cnf` claim), so
the storage weakness in finding 3 results in full account access rather than local data
disclosure."* Do not write it as a standalone finding on a normal consumer app with
short-lived, narrowly-scoped tokens — recommending DPoP there is over-engineering, and
saying so is what makes the rest of the report credible.

---

### 23. The server returned 403 to my forged token. Does that mean it was rejected?

**No — and this is a genuinely valuable distinction that testers miss constantly.**

| Code | Meaning |
|---|---|
| **401** Unauthorized | The token was **rejected**. Authentication failed |
| **403** Forbidden | The token was **accepted**. Authentication succeeded, and then the *authorisation* check failed |

A 403 means your forgery **worked**. The server verified it, decided who you were, and then
decided that person may not do this particular thing.

So do not stop. Change `sub` to another user. Add the scope the endpoint wants. Add
`role: admin`. You have already defeated the authentication layer; you are now negotiating
with the authorisation layer, and every one of those claims is in a token you control.

Recording a 403 as "blocked" and walking away is walking away from a working authentication
bypass.

---

### 24. How do I test any of this without a rooted device?

More than you would think.

**Things that need no device at all:** the entire gauntlet
([Lab 02](labs/lab-02-the-jwt-attack-gauntlet.md)) runs on the host. Every forgery, every
verification failure class, the secret cracking, and the whole CTF
([Lab 04](labs/lab-04-ctf-the-token-that-outlived-its-owner.md)). That is deliberate — the
load-bearing measurements in this chapter do not require a phone.

**Things that need a device but not root:** capture a token with a proxy
([35-SSL](../35-SSL/README.md)); everything in §7.5 through §7.9 (forgery, revocation,
rotation, scope enforcement) is done with `curl` once you have one token; external storage;
logcat; the manifest and backup surface; `dumpsys package` and `dumpsys account`.

**Things that genuinely need root or a debuggable build:** reading `/data/data/<pkg>`, the
SQLite WAL, in-process hooking with Frida.

The device attached while this chapter was written is an **i9000S, Android 13 / API 33, not
rooted** — `su` reports "inaccessible or not found" — and the honest consequence is recorded
throughout: `scripts/token-hooks.js` could not be executed on it, and
`scripts/token-storage-sweep.sh` prints its access level before any results so that an empty
result is never mistaken for an absent token.

Build your own vulnerable app ([Lab 03](labs/lab-03-tokens-at-rest.md)) with
`android:debuggable="true"` and `run-as` gives you most of what root would, on any device.

---

### 25. There is no `exp` in this token. How bad is that, really?

**Critical, essentially always.**

A token with no expiry is not a token. It is a password with a `.` in the middle. One
leak — a log line, a backup, a screenshot in a support ticket, a crash report, a resold
phone — is permanent account access, and there is no mechanism by which it ever stops being
valid.

The subtler version of the same problem, which is far more common: the token *has* an `exp`
and the verifier is written as

```javascript
if (claims.exp && now > claims.exp) { throw new Error("expired"); }
```

Delete the `exp` claim and the block never runs. This is defensive coding gone wrong — the
instinct that a missing optional value should be tolerated is correct for every field except
a security check.

The rule for every mandatory check: **absent means reject.**

```python
exp = claims.get("exp")
if not isinstance(exp, (int, float)):
    return False, None, "no numeric exp -- a token without an expiry is refused"
```

---

Back to [the chapter](README.md) · [cheat sheet](cheatsheet.md) · [mind map](mindmap.md) ·
[references](references/README.md)
