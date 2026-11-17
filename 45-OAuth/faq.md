# 45 — OAuth on Android — FAQ

The questions people actually ask, including the ones that feel too basic to ask out loud. Answers
are direct. Section references point back into [README.md](README.md).

---

### 1. I keep seeing "OAuth", "OAuth 2.0", "OIDC", "SSO" and "SAML". Are they the same thing?

No, and mixing them up in a report is expensive.

| Term | What it is |
|---|---|
| OAuth 1.0a | The original, signature-based, obsolete |
| **OAuth 2.0** | An **authorisation** framework — "this app may read your calendar" |
| **OpenID Connect (OIDC)** | An **authentication** layer built on OAuth 2.0 — "this is who the user is" |
| SAML | An older XML-based federation protocol, common in enterprises, not typically used by mobile apps |
| SSO | A *goal* ("log in once, access many things"), achievable with any of the above |

If the `scope` contains `openid` and you get an `id_token` back, you are looking at OIDC. Otherwise
it is plain OAuth 2.0. See §3.12.

### 2. What actually is a "token"? Is it a password?

It is a string that a server issues and later accepts as proof of authority. It differs from a
password in three ways that matter: it is issued *to a specific client for a specific scope*, it
**expires**, and it can be **revoked** without changing the user's password. A password is a secret
that identifies a human forever; a token is a capability that can be scoped down and thrown away.

The catch is that a plain **bearer** token confers its authority on whoever presents it, so it is
effectively a password for whatever it can reach, for as long as it lives. That is why so much of
this chapter is about stopping tokens and codes from being copied. See §10, Principal tier.

### 3. Why is there a code *and* a token? Why not just send the token back?

Because the redirect travels through the **browser**, and the browser is the least trustworthy
channel in the system: URLs land in history, in server access logs, in `Referer` headers, in crash
reports and in screen recordings. Anything valuable that travels there will eventually leak.

So the redirect carries a **claim ticket** instead — the authorisation code — which is short-lived,
single-use and useless on its own. The client redeems it over a direct, server-to-server HTTPS
request that no browser sees. The valuable thing never touches the fragile channel. Sending the token
directly is exactly what the implicit grant did, and it is exactly why implicit is dead. See §3.2 and
§3.4.

### 4. Everyone says apps can't keep secrets. Can't I just obfuscate it? Or put it in the NDK? Or split it into pieces?

No, and the reason is structural rather than a matter of effort. The app must be able to *use* the
secret at runtime, so the secret must be present in a file you can download from the Play Store and
unzip, and present in memory that Frida can read. Obfuscation, native code, string splitting and
white-box crypto all change the *time* it takes — minutes to hours — not the *outcome*.

The correct conclusions are: the app is a public client, PKCE replaces the secret's role, and
anything genuinely secret belongs on a server you control. If you find yourself designing an
elaborate scheme to hide a secret in an APK, the architecture is wrong one level up. See §10,
Intermediate tier.

### 5. If `client_id` isn't secret, what stops anyone from using my `client_id`?

Nothing stops them from *sending* it, and that is fine. `client_id` is an identifier, like a username
without a password. What stops abuse is that the authorisation server will only deliver the resulting
code to a **registered redirect URI**, and that redeeming the code requires the `code_verifier` that
only the app that started the flow knows.

This is why redirect URI registration and exact matching matter so much on mobile: with no client
secret, the redirect URI is doing much of the work of proving "the right app is at the other end of
this flow". See §3.10.

### 6. What does PKCE actually do, in plain words?

The app rolls a big random number (the **verifier**), keeps it, and sends only a **hash** of it
(the **challenge**) through the browser. The server remembers the hash. Later, when the app trades
the code for tokens, it shows the original number; the server hashes it and checks it matches.

An attacker who steals the code from the browser has the code but not the number, and cannot work the
number out from the hash. So the stolen code is worthless. See §3.3.

### 7. The app sends `code_challenge`. So PKCE is fine, right?

**No.** This is the single most important misunderstanding in mobile OAuth.

The app sending a challenge proves the *client* implements PKCE. PKCE's protection comes entirely
from the *server* **refusing** a token exchange that lacks a matching verifier. If the server accepts
the exchange anyway, the challenge was decoration and a stolen code still yields full tokens.

The client cannot enforce this, cannot detect it, and cannot fix it. You test it by capturing a live
code and attempting the exchange with the verifier removed. If tokens come back, that is a Critical
finding. See §7.5.

### 8. Why does each PKCE test variant need a fresh code? That's annoying.

Because a correct server **burns the code on first presentation**, whether the exchange succeeded or
failed. If you reuse a code for variant B, the server rejects it because it is spent, not because
PKCE is enforced — and you record a false pass on the most important test in the engagement.

Run variant A (correct verifier) first as a control to prove the code was live, then get fresh codes
for B and C. The annoyance is the price of a result you can defend. See §7.5.

### 9. What is `state` for, really? It just gets echoed back.

That is exactly the point. `state` is an unguessable value your app invents, sends out, and demands
back. Its purpose is to prove that *this callback belongs to a flow this app started*.

Without it: an attacker starts their own login, grabs the resulting code, and tricks the victim's app
into consuming it. The victim's app now holds the **attacker's** tokens. Everything the victim then
saves — a document, a photo, a payment card — goes into the attacker's account, where the attacker
reads it. It is account takeover in reverse, and users do not notice. See §3.11.

Sending `state` and never comparing it on return is the same as not having it.

### 10. So `state` and `nonce` do the same thing?

Related but different, and the difference is where they travel.

`state` comes back in the **URL**, so an attacker who controls the redirect can rewrite it. It stops
CSRF, which is an attacker who can *induce* a callback but not *see* your traffic.

`nonce` comes back **inside the signed `id_token`**, so changing it breaks the signature. It stops ID
token replay — an `id_token` obtained somewhere else cannot be injected into your flow. It is the
only one of the two that a redirect-controlling attacker cannot forge. See §3.12.

### 11. What is a Custom Tab and why is it better than a WebView? They look the same to the user.

They look similar and are architecturally opposite.

A `WebView` is a view **inside your app's process**. Your app can read the DOM (including the
password field), read every request body, read the identity provider's cookies, and inject
JavaScript. There is no address bar, so the user cannot tell a real login page from a fake.

A Custom Tab is an activity in the **browser's** process, under the **browser's UID**, with the
browser's cookie jar. Your app cannot touch any of it — the app sandbox enforces that, not good
manners. The user sees the real origin and padlock, and existing browser sessions make SSO work. See
§3.9.

### 12. Is using a WebView really a *vulnerability*? The app isn't stealing anything.

Yes, and phrase it carefully. The finding is not "the app steals the password". The finding is
**"the architecture places the user's identity-provider credential inside the trust boundary of the
client, defeating the purpose of federated authentication and making credential theft
undetectable."**

Three supporting arguments make it stick: the app *could* harvest the credential with five lines of
code and nobody could tell; the user has no address bar and therefore no way to detect a phishing
page; and RFC 8252 §8.12 — a BCP — explicitly prohibits embedded user agents for exactly these
reasons. See §3.9.

### 13. Can any app really register `myapp://`? That seems like a huge platform flaw.

Yes, any app can, and it is a deliberate design property rather than a bug. Android's
`IntentFilter.matchData` compares scheme, host, port and path against a filter's declarations. It has
no concept of ownership, no central registry, and no first-claim priority. Custom schemes were never
designed to be exclusive.

The platform's answer to "I need an exclusive redirect" is **App Links**: an `https://` URI whose
host publishes an `assetlinks.json` naming your package and signing certificate. That *is* enforced,
because the platform fetches the file over TLS and checks it. See §3.10 and §4.3.

### 14. Then why does anyone still use custom schemes?

Because they work everywhere with no server-side setup, they were the documented pattern for years,
and App Link verification requires control of a domain plus a correctly served JSON file — which is
often owned by a different team. Legacy and organisational friction, not a technical reason.

### 15. My target uses `android:autoVerify="true"`. Is the App Link verified?

Not necessarily. `autoVerify` is the app *asking* the platform to verify. Verification can fail —
the domain does not serve `assetlinks.json`, it serves it with the wrong content type, the signing
certificate fingerprint does not match, or the fetch failed on a bad network at install time.
When it fails, the app silently falls back to being one of several possible handlers.

Check the actual state:

```bash
# host
adb shell pm get-app-links com.example.target
```

Look for `verified` rather than `legacy_failure`, `none` or `1024` (retry). A declared-but-unverified
App Link is a real finding, because the developer believes they have exclusivity and they do not.
See §3.10.2.

### 16. What is the difference between an `id_token` and an `access_token`? They're both JWTs.

They answer different questions and are meant for different consumers.

| | `id_token` | `access_token` |
|---|---|---|
| Answers | Who authenticated, when, how | What may the bearer do |
| `aud` (audience) | Your **client_id** | The **resource server** |
| Send to an API? | **No** | Yes, as `Authorization: Bearer` |
| Format | Always a signed JWT | Anything — often opaque |

An `access_token` may or may not be a JWT; that is the resource server's business, not yours.
Sending an `id_token` to an API is a common bug: the API is not the intended audience, and an API
that accepts it is trusting a token minted for someone else. See §3.12.

### 17. Our backend takes the Google `id_token` from the app and logs the user in. Is that OK?

It is OK **only if the backend performs the full validation**, and the two steps that get skipped are
both fatal.

If it does not verify the signature, an attacker edits the JSON payload to any email they like,
base64-encodes it, and becomes anyone. No cryptography needed.

If it verifies the signature but does not check **`aud`**, the attack is subtler: the attacker
registers their own trivial app with Google, gets the victim to sign into that app, receives a
**genuinely Google-signed** `id_token` for the victim, and replays it to your backend. Every
signature check passes. `aud` is the only field naming which client the token was minted for, and it
is the only thing that catches this. See §3.12 and §10, Senior tier.

### 18. Why should accounts be keyed on `sub` instead of `email`?

`sub` is the issuer's stable, unique, immutable identifier for that user at that issuer. `email` is
mutable, can be re-assigned by some providers, and may be unverified.

The concrete attack: register `victim@example.com` at a sloppy identity provider that does not verify
addresses, sign into the target with it, and if the target links accounts by email, land inside the
victim's account. Always check `email_verified` if you must touch `email` at all, and never use it as
the primary key. See §3.12.

### 19. I can't see the login page traffic in Burp even though the app's traffic works. What's wrong?

Nothing — the two halves of the flow run in two different processes.

The `/authorize` leg runs in the **browser's** process (Custom Tab), so your app-level interception
does not touch it. Configure the proxy and CA for the browser as well. The `/token` leg runs in the
**app's** process, so it needs your CA in the app's trust store, which since API 24 means a
`network_security_config` that trusts user CAs — or a pinning bypass.

One login can therefore need two different interception setups. See §7.1,
[35-SSL](../35-SSL/README.md) and [44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md).

### 20. How do I get the `code_verifier`? It never leaves the app.

It leaves in the `/token` request body, so a proxy on the app's traffic shows it. If interception is
blocked, hook it. If the app uses AppAuth, one hook gives you everything at once:

```javascript
// Frida REPL
Java.use("net.openid.appauth.TokenRequest").getRequestParameters.implementation = function () {
  var m = this.getRequestParameters();
  console.log("[AppAuth TokenRequest] " + m.toString());   // code, code_verifier, client_id, redirect_uri
  return m;
};
```

For hand-rolled implementations, hook `java.security.MessageDigest.digest` or the app's own
challenge-generation method, or use `scripts/oauth-flow-tracer.js`. See §7.4.

### 21. The app uses AppAuth. Doesn't that mean it's secure?

It means the **client** is very likely correct — AppAuth is the OpenID Foundation's certified
reference implementation of RFC 8252 and refuses to run the flow in a `WebView` at all. That is a
real and meaningful signal.

It says nothing about whether the server enforces PKCE, whether the redirect is a *verified* App
Link, whether the backend checks `aud`, where the tokens are stored afterwards, whether logout
revokes, or whether the same app also ships a second, hand-rolled `WebView` flow for one partner
integration. Enumerate every entry point and test the server. See §3.14 and §11.

### 22. What is PAR, and should I care?

Pushed Authorization Requests (RFC 9126). Instead of putting all the parameters in the browser URL,
the client POSTs them to a `/par` endpoint over the back channel and gets a one-time `request_uri`.
The browser request then contains only `client_id` and that opaque reference.

It matters because it removes the front channel as a tampering surface entirely — there is nothing in
the URL to rewrite. If you see `require_pushed_authorization_requests: true` in the discovery
document, the deployment is hardened and several classic attacks are unavailable. See §3.13.

### 23. What is DPoP and why does it keep coming up with the Keystore?

Demonstrating Proof of Possession (RFC 9449). The client holds a key pair and signs a small JWT proof
— covering the HTTP method, URI and a timestamp — with every request. The authorisation server binds
the access token to that key's thumbprint, so presenting the token without the matching signature
fails.

The Keystore connection is the whole point on Android: generate the DPoP key in the Android Keystore
as non-exportable, ideally StrongBox-backed. The private key then never enters the app's address
space, so even an attacker with full code execution on a rooted device cannot exfiltrate it. A stolen
DPoP-bound token becomes useless off-device — the property bearer tokens can never have. See §3.13,
[49-KeyStore](../49-KeyStore/README.md).

### 24. Is it a finding if the app asks for too many scopes?

Yes, with two distinct impacts, and you should demonstrate rather than assert it.

Blast radius: if the tokens leak — and much of this chapter is about how they leak — the attacker
inherits whatever the scope allows. An app whose only feature is showing a balance, requesting
`payments.write`, has converted an information disclosure into a funds-transfer capability.

Consent erosion: users approve walls of permissions they cannot evaluate, which devalues consent
everywhere.

To prove it, build a two-column table of every scope and the specific feature requiring it; empty
second cells are the finding. Then strip the scope from the request and show the app still works.
See §3.12.

### 25. I logged out in the app but my captured token still works. Is that a bug?

Almost certainly, and it is very common. Many apps implement "logout" as deleting the local token.
The server never hears about it, so the access token remains valid until it expires and the
**refresh token remains valid indefinitely** — meaning a token stolen before logout gives permanent
access after it.

Correct logout calls the `revocation_endpoint` (RFC 7009) for the refresh token and confirms the
result. Test it by capturing tokens, logging out in the UI, then using the access token against the
API and the refresh token against `/token`. If either works, it is a finding. See §7.9.

### 26. How severe is a scheme-hijack finding, honestly?

It depends entirely on PKCE enforcement, and getting this wrong in either direction damages your
report.

If PKCE is **not** enforced: Critical. Any installed app steals the code and exchanges it for full
tokens — complete account takeover, invisible, surviving password changes.

If PKCE **is** enforced: Medium at most. The stolen code is inert. It is still worth reporting,
because the redirect should be a verified App Link and because a future server change re-arms the
whole attack, but do not call it Critical.

The severity is a property of the **combination**, which is why you test enforcement before writing
the rating. See §9.4 and §11.

### 27. Everything looks correct. What do I write in the report?

Write what you *tested* and what the enforcement point was for each control, not just "no issues
found". A defensible clean OAuth section names the grant, states that PKCE enforcement was tested
with variants B and C against fresh codes and both returned `400 invalid_grant`, states that
`pm get-app-links` showed `verified`, states that a competing-scheme app was installed and did not
receive the callback, states that the discovery document showed no ROPC, implicit, `plain` or `none`,
and states that logout revoked server-side.

That is a far more valuable deliverable than a finding, because it tells the client exactly what was
proven and — implicitly — what a future regression would break.
