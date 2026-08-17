# 45 — OAuth on Android — Annotated References

Every link has a one-line note explaining why you would open it. Ordered by how often you will
actually need them.

---

## Read these first

| Document | Why |
|---|---|
| [RFC 8252 — OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252) | The one document that governs this chapter: mandates PKCE, mandates an external user agent, and §8.12 is the normative basis for treating a `WebView` flow as a finding |
| [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636) | §4.1 gives the exact `code_verifier` charset and length; §4.2 gives the `S256` construction you will re-implement to test enforcement |
| [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700) | The consolidated modern guidance; cite this when a developer says "the spec allows it" |
| [OpenID Connect Core 1.0 §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) | The normative `id_token` validation algorithm — quote it verbatim when reporting a missing `aud` check |

---

## Core specifications

| RFC / spec | One-line summary |
|---|---|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | The OAuth 2.0 Authorization Framework — roles, grants, endpoints, error codes |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | Bearer token usage: how a token is presented and what the error responses mean |
| [RFC 6819](https://www.rfc-editor.org/rfc/rfc6819) | The original threat model — still the best source on *why* each control exists |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token, the container format of every `id_token` |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature — the `alg` header field and why trusting it is circular |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key — the JWKS document you fetch to verify a signature |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) | Token revocation — the endpoint a correct logout must call |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) | Token introspection — how a resource server asks the AS what a token means |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) | Dynamic client registration — relevant when an app registers itself at runtime |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Authorization server metadata — the sibling of OIDC Discovery |
| [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) | Device Authorization Grant — the TV/console flow with `user_code` and polling |
| [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) | mTLS client authentication and certificate-bound tokens |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | Pushed Authorization Requests — removes the front channel as a tampering surface |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) | Issuer identification — the mitigation for mix-up attacks across multiple IdPs |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | DPoP — application-layer sender-constrained tokens; pairs with the Android Keystore |
| [OAuth 2.1 draft](https://oauth.net/2.1/) | The consolidation that makes PKCE mandatory and deletes implicit and ROPC |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Defines `.well-known/openid-configuration` — the cheapest evidence you will collect |
| [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | What a correct logout looks like at the protocol level |
| [FAPI 2.0 Security Profile](https://openid.net/wg/fapi/) | Financial-grade profile; use as a conformance checklist for a hardened deployment |

---

## Android platform

| Link | Why |
|---|---|
| [Verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks) | The verification process behind `pm get-app-links`, including every way it silently fails |
| [Digital Asset Links](https://developers.google.com/digital-asset-links/v1/getting-started) | The `assetlinks.json` format and how the fingerprint is computed |
| [Chrome Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs/) | What a Custom Tab is and what customisation is actually available — useful when arguing against a `WebView` |
| [`CustomTabsIntent`](https://developer.android.com/reference/androidx/browser/customtabs/CustomTabsIntent) | The API surface a correct app uses |
| [Intents and intent filters](https://developer.android.com/guide/components/intents-filters) | Intent resolution — the mechanism scheme hijacking abuses |
| [Network security configuration](https://developer.android.com/privacy-and-security/security-config) | Required reading before you can intercept the token exchange |
| [Android Keystore](https://developer.android.com/privacy-and-security/keystore) | Where a DPoP or attestation key must live |
| [`AccountManager`](https://developer.android.com/reference/android/accounts/AccountManager) | Android's account framework; some apps store OAuth tokens here rather than in preferences |
| [Package visibility on Android 11+](https://developer.android.com/training/package-visibility) | Changes what a malicious app can see about your redirect handlers |

---

## AOSP source

| Path | Why it matters |
|---|---|
| `frameworks/base/core/java/android/content/IntentFilter.java` | `matchData` — the method that decides whether an app's filter matches a redirect URI. It has **no concept of scheme ownership**, which is the whole basis of scheme hijacking |
| `frameworks/base/services/core/java/com/android/server/pm/` | Package manager intent resolution and App Link verification state |
| `frameworks/base/core/java/android/content/pm/verify/domain/` | The domain verification APIs behind `pm get-app-links` |
| `frameworks/base/core/java/android/webkit/WebView.java` | The API surface that makes an embedded flow dangerous |
| [Android Code Search](https://cs.android.com/) | Search all of the above without cloning AOSP |

---

## Libraries and reference implementations

| Link | Why |
|---|---|
| [AppAuth-Android](https://github.com/openid/AppAuth-Android) | The OpenID Foundation's certified client library — the reference implementation of RFC 8252. Refuses to run the flow in a `WebView` |
| [AppAuth-Android sample app](https://github.com/openid/AppAuth-Android/tree/master/app) | A known-correct flow to diff a target's behaviour against |
| [AppAuth `TokenRequest`](https://github.com/openid/AppAuth-Android/blob/master/library/java/net/openid/appauth/TokenRequest.java) | Read this to know exactly what `getRequestParameters()` returns — the highest-value Frida hook in the chapter |
| [Google Identity Services for Android](https://developers.google.com/identity/android) | What "Sign in with Google" actually does on Android today |
| [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt) | A correct JWT validator — use it to demonstrate what a backend *should* have done |
| [jwt.io](https://jwt.io/) | Quick decoding during testing. Never paste a real production token into a third-party site |

---

## OWASP

| Link | Why |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | MASVS-AUTH, MASVS-NETWORK, MASVS-STORAGE and MASVS-PLATFORM are the controls this chapter maps to |
| [MASTG](https://mas.owasp.org/MASTG/) | The Android authentication, deep-link and interception test cases, with concrete procedures |
| [Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | M3 Insecure Authentication/Authorization is where these findings land in an executive summary |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | The OAuth 2.0 and JWT cheat sheets, useful as a remediation appendix |

---

## Testing tools

| Tool | Use |
|---|---|
| [Burp Suite](https://portswigger.net/burp) | Intercepting both legs of the flow; Repeater is where the PKCE enforcement variants are run |
| [mitmproxy](https://mitmproxy.org/) | Scriptable alternative, better for automating the enforcement probe |
| [Frida](https://frida.re/) | Extracting the `code_verifier` and detecting `WebView` flows — see [53-Frida](../../53-Frida/README.md) |
| [Objection](https://github.com/sensepost/objection) | Fast class search and method watching without writing a script |
| [jadx](https://github.com/skylot/jadx) | Decompilation; anchor searches on protocol parameter names, which survive obfuscation |
| [apktool](https://apktool.org/) | Manifest and resource extraction — the redirect scheme is visible before any decompilation |
| [`jq`](https://jqlang.github.io/jq/) | Reading discovery documents and token responses |

---

## Further reading

| Link | Why |
|---|---|
| [oauth.net](https://oauth.net/) | Aaron Parecki's reference site — the fastest correct answer to "which RFC covers X" |
| [OAuth 2.0 Simplified](https://www.oauth.com/) | A readable walkthrough of the whole framework when the RFCs are too dense |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Platform-level intent and domain-verification fixes that change what the attacks above can do |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | Deep mobile IPC and deep-link research |
| [PortSwigger Web Security Academy — OAuth](https://portswigger.net/web-security/oauth) | Free hands-on labs; the web-side attacks translate directly to the mobile front channel |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [26-Intent](../../26-Intent/README.md) | Intent resolution — the mechanism that makes scheme hijacking possible |
| [26-Intent](../../26-Intent/README.md) | App Links, `assetlinks.json` and verification state |
| [35-SSL](../../35-SSL/README.md) | Intercepting the back-channel token exchange |
| [43-WebView](../../43-WebView/README.md) | Why the embedded user agent is dangerous, in depth |
| [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | Trusting your proxy CA so the token leg is visible |
| [46-Tokens](../../46-Tokens/README.md) | What happens after the flow: JWT internals, algorithm confusion, storage |
| [47-Authentication](../../47-Authentication/README.md) | Sessions, logout, step-up and biometrics |
| [49-KeyStore](../../49-KeyStore/README.md) | Where a DPoP or attestation key must live |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | StrongBox and key attestation |
| [53-Frida](../../53-Frida/README.md) | The instrumentation used throughout §7 |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The UID boundary that makes a Custom Tab safe |
