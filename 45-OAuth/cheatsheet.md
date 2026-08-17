# 45 — OAuth 2.0 / OIDC on Android — Cheat Sheet

Printable. Tables and commands only. Full explanations in [README.md](README.md).

---

## 1. Identify the grant in five seconds

| What you see in the captured request | Grant | Verdict for a mobile app |
|---|---|---|
| `response_type=code` + `code_challenge` + `code_challenge_method=S256` | Authorisation code + PKCE | ✅ Correct |
| `response_type=code`, no `code_challenge` | Authorisation code, no PKCE | 🟠 Client-side gap — test server enforcement |
| `response_type=token` or `response_type=id_token token` | Implicit | 🔴 Dead grant; token in the URL fragment |
| `grant_type=password` with `username`/`password` | ROPC | 🔴 App holds the user's IdP password |
| `grant_type=client_credentials` from the app | Client credentials | 🔴 Implies an embedded client secret |
| `device_code` / `user_code` / `verification_uri` | Device grant (RFC 8628) | ⚪ Only for input-constrained devices |
| `grant_type=refresh_token` | Refresh | ⚪ Normal; test rotation and scope escalation |
| `request_uri=urn:ietf:params:oauth:request_uri:...` | PAR (RFC 9126) | ✅ Hardened |

---

## 2. Authorisation request parameters

| Parameter | Required | Check |
|---|---|---|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Identifier, **not** a credential |
| `redirect_uri` | Yes | `https://` App Link ✅ / custom scheme 🟠 / wildcard or open 🔴 |
| `scope` | Usually | Every scope must map to a feature |
| `state` | **Must** | Present, ≥128 bits entropy, validated on return |
| `code_challenge` | **Must** | Present |
| `code_challenge_method` | **Must** | `S256`; `plain` is a downgrade |
| `nonce` | OIDC | Present and compared inside the `id_token` |
| `prompt` | Optional | `login` forces re-auth; `none` = silent |
| `max_age` / `acr_values` | Optional | Step-up authentication signals |
| `login_hint` | Optional | Leaks the username into the URL |

## 3. Token response fields

| Field | Meaning | Check |
|---|---|---|
| `access_token` | Authority at the API | Sent as `Authorization: Bearer` |
| `token_type` | `Bearer` or `DPoP` | `DPoP` = sender-constrained ✅ |
| `expires_in` | Access token lifetime (s) | Minutes, not days |
| `refresh_token` | Long-lived renewal credential | Must rotate; test reuse detection |
| `id_token` | **Identity for the client only** | Never send to a resource server |
| `scope` | Granted scope | May be narrower than requested |

---

## 4. PKCE — the only test that matters

Each variant needs a **FRESH** authorisation code. Run A first as the control.

```bash
# host — A: control. MUST succeed.
curl -s -X POST "$TOKEN_EP" -d grant_type=authorization_code \
  -d code="$CODE" -d redirect_uri="$RURI" -d client_id="$CID" \
  -d code_verifier="$VERIFIER" | jq .

# host — B: verifier REMOVED. MUST fail.
curl -s -X POST "$TOKEN_EP" -d grant_type=authorization_code \
  -d code="$CODE" -d redirect_uri="$RURI" -d client_id="$CID" | jq .

# host — C: verifier WRONG. MUST fail.
curl -s -X POST "$TOKEN_EP" -d grant_type=authorization_code \
  -d code="$CODE" -d redirect_uri="$RURI" -d client_id="$CID" \
  -d code_verifier="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | jq .
```

| Variant | Expected | If it succeeds instead |
|---|---|---|
| A — correct verifier | `200` + tokens | (control) |
| B — verifier omitted | `400 invalid_grant` | 🔴 **Critical — PKCE not enforced** |
| C — verifier wrong | `400 invalid_grant` | 🔴 **Critical — verification not performed** |
| D — code reused | `400 invalid_grant` | 🟠 High — codes not single-use |
| E — `plain` downgrade accepted | `400 invalid_request` | 🟠 High — PKCE defeatable by an interceptor |

**Generate a verifier/challenge pair:**

```bash
# host
V=$(head -c 64 /dev/urandom | basenc --base64url | tr -d '=' | head -c 128)
C=$(printf '%s' "$V" | openssl dgst -binary -sha256 | basenc --base64url | tr -d '=')
echo "verifier=$V"; echo "challenge=$C"
```

---

## 5. Redirect URI

| Mechanism | Exclusive? | How to confirm |
|---|---|---|
| Custom scheme `app://cb` | ❌ Never | `cmd package query-activities` shows every claimant |
| `https://` with `autoVerify` **declared** | ❌ Not yet | Manifest only says the app *wants* it |
| `https://` **verified** App Link | ✅ Platform-enforced | `pm get-app-links` shows `verified` |
| Loopback `http://127.0.0.1:PORT` | ⚠️ Desktop pattern | Any local app can bind a port |

```bash
# host — who claims this redirect?
adb shell cmd package query-activities -a android.intent.action.VIEW -d "exampleapp://oauth/callback"

# host — is the App Link actually verified?
adb shell pm get-app-links com.example.target

# host — fire a callback by hand
adb shell am start -a android.intent.action.VIEW -d "exampleapp://oauth/callback?code=TEST&state=ABC"

# host — force re-verification
adb shell pm verify-app-links --re-verify com.example.target
```

---

## 6. Static triage of an APK

```bash
# host
apktool d app.apk -o work/ && jadx -d out/ app.apk

# redirect schemes and the callback activity
grep -A6 -B6 'android:scheme' work/AndroidManifest.xml | grep -v 'http"\|https"'
grep -n 'autoVerify\|allowBackup\|networkSecurityConfig' work/AndroidManifest.xml

# protocol parameter names survive obfuscation — anchor on them
grep -rn 'code_challenge\|code_verifier\|grant_type\|response_type\|client_secret' out/sources/

# dead grants
grep -rn 'grant_type=password\|response_type=token\|ROPC' out/sources/

# WebView-based flow
grep -rn 'loadUrl' out/sources/ | grep -iE 'authorize|oauth|openid|/auth\?'
grep -rn 'setJavaScriptEnabled(true)\|addJavascriptInterface' out/sources/

# library detection
grep -rn 'net.openid.appauth' out/sources/ | head
ls out/sources/net/openid/appauth/ 2>/dev/null

# cross-platform: the flow may not be in the DEX at all
ls work/lib/*/ ; ls work/assets/ | grep -iE 'bundle|flutter|dll|unity'

# endpoints
grep -rnoE 'https://[a-z0-9.-]+/(oauth2?|connect|auth)[a-z0-9/_-]*' out/sources/ | sort -u
```

Or run [`scripts/oauth-static-triage.sh`](scripts/oauth-static-triage.sh).

---

## 7. Dynamic analysis

```bash
# host — full flow trace
frida -U -f com.example.target -l scripts/oauth-flow-tracer.js

# host — WebView detection only
frida -U -f com.example.target -l scripts/detect-webview-oauth.js

# host — decode a captured authorize URL / token response
python3 scripts/oauth-param-decoder.py --url "https://login.example.com/authorize?..."
python3 scripts/oauth-param-decoder.py --token-response resp.json

# host — redirect_uri handling
python3 scripts/redirect-uri-fuzz.py --authorize-url "..." --registered "app://cb"
```

**The highest-value single hook** — if the app uses AppAuth, this prints `code`, `code_verifier`,
`client_id` and `redirect_uri` in one map:

```javascript
// Frida REPL
Java.use("net.openid.appauth.TokenRequest").getRequestParameters.implementation = function () {
  var m = this.getRequestParameters();
  console.log("[AppAuth TokenRequest] " + m.toString());
  return m;
};
```

**Objection:**

```
android hooking search classes appauth
android hooking watch class_method net.openid.appauth.AuthorizationService.performTokenRequest --dump-args
android hooking watch class_method android.webkit.WebView.loadUrl --dump-args --dump-backtrace
file download /data/data/<pkg>/shared_prefs/AuthStatePrefs.xml ./authstate.xml
```

---

## 8. Discovery document red flags

```bash
# host
curl -s https://login.example.com/.well-known/openid-configuration | jq '{
  issuer, grant_types_supported, response_types_supported,
  code_challenge_methods_supported, token_endpoint_auth_methods_supported,
  id_token_signing_alg_values_supported, require_pushed_authorization_requests,
  revocation_endpoint, introspection_endpoint }'
```

| Field contains | Meaning |
|---|---|
| `grant_types_supported: password` | ROPC enabled server-wide |
| `response_types_supported: token` | Implicit still enabled |
| `code_challenge_methods_supported` absent | AS may not support PKCE at all |
| `code_challenge_methods_supported: plain` | Downgrade possible |
| `id_token_signing_alg_values_supported: none` | 🔴 Unsigned tokens accepted |
| `id_token_signing_alg_values_supported: HS256` for a public client | Algorithm-confusion surface |
| `revocation_endpoint` absent | Logout cannot revoke server-side |
| `require_pushed_authorization_requests: true` | ✅ Hardened |

---

## 9. `id_token` validation checklist

| # | Check | Failure consequence |
|---|---|---|
| 1 | Exactly three base64url segments | Malformed input |
| 2 | `alg` is in **your** allow-list (never the token's word) | Algorithm confusion, `alg: none` |
| 3 | Key selected by `kid` from the issuer's JWKS, fetched over TLS | Wrong-key acceptance |
| 4 | Signature verifies | **Total forgery with a text editor** |
| 5 | `iss` == the exact expected issuer | Cross-issuer confusion |
| 6 | **`aud` contains my `client_id`** (and `azp` == it if multiple) | 🔴 **Cross-client token replay — the classic bug** |
| 7 | `exp` > now (small skew) | Expired token accepted |
| 8 | `iat` recent, `nbf` <= now | Stale token accepted |
| 9 | `nonce` == the one I generated | ID token replay |
| 10 | `acr` / `amr` / `auth_time` meet policy | Weak authentication accepted |
| 11 | Key the account on **`sub`**, not `email` | Account takeover via email re-use |

---

## 10. `state` vs `nonce`

| | `state` | `nonce` |
|---|---|---|
| Layer | OAuth 2.0 | OIDC |
| Returned in | The redirect URL | The signed `id_token` |
| Stops | CSRF on the redirect | ID token replay |
| Forgeable by a redirect-controlling attacker | Yes | No — inside the signature |

---

## 11. Post-flow tests

```bash
# adb shell as root — where did the tokens land?
find /data/data/<pkg> -type f \( -name '*.xml' -o -name '*.db' -o -name '*.json' \) \
  -exec grep -l -E 'refresh_?[Tt]oken|access_token|eyJ[A-Za-z0-9_-]{10,}' {} \;

# host — does logout revoke? Run AFTER logging out in the UI.
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" https://api.example.com/v1/me | jq .
curl -s -X POST "$TOKEN_EP" -d grant_type=refresh_token \
  -d refresh_token="$REFRESH_TOKEN" -d client_id="$CID" | jq .

# host — scope escalation on refresh
curl -s -X POST "$TOKEN_EP" -d grant_type=refresh_token -d refresh_token="$RT" \
  -d client_id="$CID" -d scope="openid profile admin accounts.write" | jq .

# host — refresh token rotation / reuse detection
# 1. refresh once, keep RT_OLD and RT_NEW
# 2. present RT_OLD again — must fail, and a hardened AS revokes RT_NEW too
```

---

## 12. Severity guide

| Finding | Base severity | Modifier |
|---|---|---|
| PKCE not enforced **and** custom-scheme redirect | 🔴 Critical | Account takeover by any installed app |
| PKCE not enforced, verified App Link redirect | 🟠 High | Codes still leak via history, logs, `Referer` |
| ROPC in production | 🔴 Critical | App holds the IdP password; no MFA possible |
| `id_token` accepted without `aud` check | 🔴 Critical | Cross-client account takeover |
| `id_token` accepted without signature check | 🔴 Critical | Forgery with `base64` |
| Implicit grant | 🟠 High | Token in URL fragment |
| WebView used for the flow | 🟠 High | Credential inside the client trust boundary |
| `state` absent | 🟠 High | CSRF / account-injection |
| Custom scheme redirect, PKCE enforced | 🟡 Medium | Interception yields an inert code |
| Logout does not revoke server-side | 🟡 Medium | Stolen token survives "logout" |
| Refresh token never rotated | 🟡 Medium | No theft detection |
| Over-scoped grant | 🟡 Medium | Blast radius; prove the scope is unused |
| `code_challenge_method=plain` accepted | 🟠 High | PKCE downgradeable |

---

## 13. Report sentence templates

**PKCE not enforced:**
> Any application installed on the user's device can register the redirect scheme `app://`, receive
> the authorisation code during a legitimate login, and exchange it at the token endpoint for a full
> access and refresh token set **without presenting any secret**. This results in complete account
> takeover, is invisible to the user and to the application, and persists across password changes
> because the refresh token is unaffected by a credential reset.

**WebView flow:**
> The architecture places the user's identity-provider credential inside the trust boundary of the
> client application, defeating the purpose of federated authentication and making credential theft
> undetectable. RFC 8252 §8.12 prohibits embedded user agents for this reason.

**Missing `aud` check:**
> The backend accepts any `id_token` bearing a valid issuer signature. An attacker who registers
> their own client with the same identity provider can obtain a genuinely signed token for a victim's
> identity and replay it here, taking over the account. The `aud` claim is the only control that
> distinguishes the two, and it is not checked.
