# Lab 01 — Intercept and decode a full authorisation-code + PKCE flow

**Difficulty:** Beginner
**Time:** 1–2 hours
**Prerequisites:** [Chapter 45 §3.1–§3.3, §7.1–§7.2](../README.md),
[35-SSL](../../35-SSL/README.md), [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md)

---

## Objective

Capture one complete OAuth 2.0 login, from the first byte the app sends to the tokens it receives,
and produce a **parameter inventory** — a table naming every parameter, its value, its purpose and
whether it is correct.

This lab produces no findings. It produces the evidence base that every later lab consumes. Do not
skip it: almost every wrong conclusion in mobile OAuth testing comes from someone reasoning about a
flow they only half-captured.

> **Mental Model**
> One login is two conversations in two different processes. The `/authorize` leg happens in the
> **browser**. The `/token` leg happens in the **app**. They have different TLS trust configurations
> and you may need two different interception setups for one login. If you only see half the flow,
> you will draw a confident, wrong conclusion.

---

## Setup

### 1. Choose a target

Use, in order of preference:

1. The **AppAuth-Android sample app** (`https://github.com/openid/AppAuth-Android`, `app/` module)
   pointed at a free developer tenant — Auth0, Okta developer, Keycloak in Docker, or Google. This is
   the best target because it is *correct*, so you learn what correct looks like before you go
   hunting for wrong.
2. A **local Keycloak** instance, which lets you change server settings and watch the effect.
3. Any app on your own device where you own the account and have permission to test.

Setting up Keycloak locally takes two minutes and is worth it, because Lab 02 needs a server whose
PKCE policy you can toggle:

```bash
# host
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Then create a realm, create a **public** client with redirect URI `com.example.lab://oauth/callback`,
and note the discovery URL:
`http://<host-ip>:8080/realms/<realm>/.well-known/openid-configuration`.

### 2. Prepare the device

```bash
# host
adb devices
adb shell getprop ro.build.version.sdk        # note the API level; interception rules differ by it
```

### 3. Proxy the app

Install your Burp CA as a **system** CA on a rooted device or emulator, or build a debug APK with a
`network_security_config` that trusts user certificates. Both routes are covered in
[35-SSL](../../35-SSL/README.md).

```bash
# host — point the device at Burp
adb shell settings put global http_proxy 192.168.1.50:8080
```

### 4. Proxy the browser as well

This is the step people miss. The Custom Tab runs in Chrome's process, with Chrome's trust store.

- On an emulator, installing the CA as a system CA covers both.
- On a rooted physical device, the same.
- If you cannot do either, you can still read the `/authorize` request from `logcat` or from a Frida
  hook on `startActivity`, because the URL is fully visible before it leaves the app. You lose the
  *response*, which for this lab is acceptable.

Verify both halves work before you start:

```bash
# host — should appear in Burp
adb shell am start -a android.intent.action.VIEW -d "https://example.com/"
```

---

## Steps

### Step 1 — Fetch the discovery document first

Always do this before capturing anything. It tells you what the server *claims* to support, which is
the frame for everything you are about to see.

```bash
# host
curl -s "$DISCOVERY_URL" | jq '{
  issuer,
  authorization_endpoint,
  token_endpoint,
  jwks_uri,
  revocation_endpoint,
  grant_types_supported,
  response_types_supported,
  code_challenge_methods_supported,
  id_token_signing_alg_values_supported,
  scopes_supported
}'
```

**Q1.** Which grant types does this server support? Are any of them ones an app should never use?

**Q2.** Does `code_challenge_methods_supported` include `S256`? Does it include `plain`?

**Q3.** Is there a `revocation_endpoint`? Note the answer — Lab 02's post-flow test needs it.

### Step 2 — Start a Frida trace before you touch the app

```bash
# host
frida -U -f com.example.lab -l ../scripts/oauth-flow-tracer.js
```

Leave it running. It prints the authorisation request, the callback, the token exchange and — if the
app uses AppAuth — the `code_verifier` directly. You want it running from process start so you do not
miss an early request.

### Step 3 — Perform one login

Tap "Sign in", authenticate, consent, and let the app return to its logged-in state. **One clean
login.** Resist the urge to click around: a noisy capture is much harder to read than a short one.

### Step 4 — Extract the `/authorize` request

Find it in Burp (or in the tracer output). Copy the full URL. Decode it:

```bash
# host
python3 ../scripts/oauth-param-decoder.py --url "https://login.example.com/authorize?response_type=code&..."
```

Now fill in this table **by hand**, from the actual captured values. Writing it out is the point of
the lab; reading the script's output is not the same thing.

| Parameter | Captured value | What it is for | Correct? |
|---|---|---|---|
| `response_type` | | | |
| `client_id` | | | |
| `redirect_uri` | | | |
| `scope` | | | |
| `state` | | | |
| `code_challenge` | | | |
| `code_challenge_method` | | | |
| `nonce` | | | |
| *(anything else)* | | | |

**Q4.** How many bytes of entropy does `state` appear to have? How would you tell whether it is
random rather than a counter or a timestamp? (Hint: perform three logins and compare.)

**Q5.** Is the `redirect_uri` a custom scheme or an `https://` URL? Note which — Lab 03 depends on it.

**Q6.** For each scope requested, name a feature of the app that requires it. Any scope you cannot
justify is a candidate finding.

### Step 5 — Extract the callback

Find the redirect. In Burp it is a `302` whose `Location` header is your `redirect_uri`; in the
tracer it appears as `[CALLBACK]`.

```
exampleapp://oauth/callback?code=ABC123...&state=XYZ...
```

**Q7.** Which parameters came back? Is `state` byte-for-byte the value you sent?

**Q8.** Was the code delivered over an `https://` App Link or a custom scheme? If custom, run:

```bash
# host
adb shell cmd package query-activities -a android.intent.action.VIEW -d "exampleapp://oauth/callback"
```

How many activities claim it *right now*?

### Step 6 — Extract the token exchange

This is the request that matters most. In Burp it is a `POST` to the `token_endpoint`.

```
POST /oauth2/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=ABC123...&redirect_uri=exampleapp%3A%2F%2Foauth%2Fcallback
&client_id=...&code_verifier=...
```

| Parameter | Captured value | Note |
|---|---|---|
| `grant_type` | | Must be `authorization_code` |
| `code` | | The value from step 5 |
| `redirect_uri` | | Must match the `/authorize` value exactly |
| `client_id` | | |
| `code_verifier` | | **Save this. Lab 02 needs it.** |
| `client_secret` | | **If present, that is a finding — see Q10** |

**Q9.** Verify PKCE yourself. Compute the challenge from the captured verifier and compare it against
the `code_challenge` you recorded in step 4:

```bash
# host
V='<the captured code_verifier>'
printf '%s' "$V" | openssl dgst -binary -sha256 | basenc --base64url | tr -d '='
```

Does it match? If not, either you mis-copied a value or the app is hashing the wrong thing — which is
a real bug that occurs in hand-rolled implementations (see §3.3).

**Q10.** Is a `client_secret` present? If so, extract it from the APK to prove it is not secret:

```bash
# host
apktool d app.apk -o work/ && jadx -d out/ app.apk
grep -rn 'client_secret\|CLIENT_SECRET' out/sources/ work/res/values/strings.xml
```

### Step 7 — Decode the token response

```bash
# host — save the JSON body from Burp to resp.json
python3 ../scripts/oauth-param-decoder.py --token-response resp.json
```

| Field | Value | Note |
|---|---|---|
| `token_type` | | `Bearer` or `DPoP` |
| `expires_in` | | Minutes is good; days is not |
| `access_token` | | Is it a JWT or opaque? |
| `refresh_token` | | Present means long-lived access |
| `id_token` | | Decode the header and payload |
| `scope` | | May be narrower than requested |

**Q11.** Decode the `id_token`'s three segments. What is `aud`? What is `iss`? Is `nonce` present, and
does it match what you sent in step 4?

**Q12.** Is the `access_token` a JWT? If so, what is *its* `aud`, and how does it differ from the
`id_token`'s?

### Step 8 — Draw the flow

Reproduce the sequence you captured as a diagram, from your own notes, without looking at §3.3. Label
each arrow with the actual endpoint and the parameters that travelled. If you cannot draw it, you
have not captured it — go back.

---

## Success criteria

- [ ] The discovery document is saved and its four risk-relevant fields are noted
- [ ] The `/authorize` request is captured and every parameter is in your inventory table
- [ ] The callback is captured and `state` is confirmed to match byte-for-byte
- [ ] The `/token` request is captured, **including the `code_verifier`**, and saved for Lab 02
- [ ] You independently recomputed `S256(verifier)` and it matched the captured `code_challenge`
- [ ] The token response is decoded, including all three `id_token` segments
- [ ] You know whether the redirect is a custom scheme or a verified App Link, and how many apps claim it
- [ ] You produced a scope-to-feature table with no unexplained rows, or you recorded the unexplained rows
- [ ] You drew the flow from your own notes

---

## Debrief

1. You captured `code_challenge_method=S256`. State precisely what that proves and what it does not.
2. The `/authorize` leg and the `/token` leg needed different interception setups. Explain why, in
   terms of processes and trust stores.
3. If the app had used a `WebView` instead of a Custom Tab, which of your capture steps would have
   become easier, and what would that ease tell you about the app's security posture?
4. You now hold a `code_verifier`. What is the *only* party that should ever have seen it, and what
   does your possession of it demonstrate about the interception setup — not about the app?
5. Name one parameter in your inventory that you could not justify, and write the one-sentence
   question you would ask the developer about it.

---

## Where this goes next

You are holding a live `code` and its matching `code_verifier`. That is exactly the input
[Lab 02](lab-02-pkce-enforcement.md) needs, and Lab 02 is where the actual finding lives. Keep your
capture.
