# Lab 02 — Testing PKCE *enforcement*, not PKCE presence

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-intercept-the-flow.md),
[Chapter 45 §3.3, §7.4–§7.5](../README.md)

---

## Objective

Prove, with reproducible transcripts, whether the authorisation server **refuses** a token exchange
that does not present a matching `code_verifier`.

This is the single highest-value test in mobile OAuth, and it is the one most commonly skipped —
because everything the tester can see from the client says PKCE is working.

> **🧠 Mental Model**
> `code_challenge=...&code_challenge_method=S256` in the request proves that the **client** implements
> PKCE. It proves nothing whatsoever about the **server**. PKCE's entire security value comes from the
> server refusing a token request that does not present a matching verifier. A server that accepts the
> request anyway has PKCE as decoration. The client cannot fix this and cannot detect it. Only you can.

---

## Why this lab exists

A tester captures a login, sees `code_challenge_method=S256`, writes "PKCE correctly implemented" and
moves on. Six months later someone discovers that any installed app can steal the redirect and
exchange the code for tokens, because the token endpoint never checked. The client-side code was
perfect the whole time.

The gap between "the client sends it" and "the server checks it" is invisible from the app and
invisible from the traffic of a *successful* login. It only becomes visible when you deliberately
send a **wrong** request and observe what happens.

---

## Setup

You need three things:

1. **A live authorisation code** — obtained but not yet redeemed.
2. **Its matching `code_verifier`**.
3. **The ability to get fresh codes on demand**, because each test variant burns one.

### Getting the verifier

If the app uses AppAuth, one hook prints everything:

```javascript
// Frida REPL — the highest-value hook in the chapter
Java.perform(function () {
  Java.use("net.openid.appauth.TokenRequest").getRequestParameters.implementation = function () {
    var m = this.getRequestParameters();
    console.log("[AppAuth TokenRequest] " + m.toString());
    return m;
  };
});
```

Otherwise run the full tracer:

```bash
# host
frida -U -f com.example.lab -l ../scripts/oauth-flow-tracer.js
```

Or simply read the `/token` request body in Burp — the verifier is right there in a successful
exchange. Reading it from a *successful* exchange is fine for learning the value's shape, but for the
actual test you need a code that has **not** been redeemed.

### Catching a code before it is spent

Two workable techniques:

**A — Intercept and drop.** In Burp, set an intercept rule on `POST` to the token endpoint. Perform a
login. When the app's `/token` request is held, copy `code` and `code_verifier` out of it, then
**drop** the request. The code is now live and unspent, and you have its verifier.

**B — Drive the flow yourself.** Generate your own verifier and challenge, construct the
`/authorize` URL by hand, open it in the device browser, and catch the redirect. This is more work
but gives you unlimited fresh codes without touching the app.

```bash
# host — generate a conforming verifier and challenge
V=$(head -c 64 /dev/urandom | basenc --base64url | tr -d '=' | head -c 128)
C=$(printf '%s' "$V" | openssl dgst -binary -sha256 | basenc --base64url | tr -d '=')
S=$(head -c 32 /dev/urandom | basenc --base64url | tr -d '=')
echo "verifier=$V"
echo "challenge=$C"
echo "state=$S"

# host — open the authorisation URL on the device
adb shell am start -a android.intent.action.VIEW -d \
"https://login.example.com/oauth2/authorize?response_type=code\
&client_id=$CID\
&redirect_uri=exampleapp%3A%2F%2Foauth%2Fcallback\
&scope=openid%20profile\
&state=$S\
&code_challenge=$C\
&code_challenge_method=S256"
```

Catch the redirect either in Burp or with `adb logcat` if you have a hijacker installed
([Lab 03](lab-03-scheme-hijack.md)).

> **⚠️ Warning**
> Authorisation codes are short-lived — typically 30 to 600 seconds. Have your `curl` commands
> prepared in a shell script with variables before you capture the code, so you are pasting one value
> rather than composing a command under time pressure.

---

## The five variants

Save this as `pkce-test.sh` and fill in the endpoints before you start.

```bash
#!/usr/bin/env bash
# host — run each function with a FRESH code. Variant A must be run first, as the control.
TOKEN_EP="https://login.example.com/oauth2/token"
RURI="exampleapp://oauth/callback"
CID="your-client-id"

variant_A() {  # correct verifier — MUST succeed
  curl -s -w '\nHTTP %{http_code}\n' -X POST "$TOKEN_EP" \
    -d grant_type=authorization_code -d code="$1" \
    -d redirect_uri="$RURI" -d client_id="$CID" -d code_verifier="$2"
}
variant_B() {  # verifier REMOVED — MUST fail
  curl -s -w '\nHTTP %{http_code}\n' -X POST "$TOKEN_EP" \
    -d grant_type=authorization_code -d code="$1" \
    -d redirect_uri="$RURI" -d client_id="$CID"
}
variant_C() {  # verifier WRONG — MUST fail
  curl -s -w '\nHTTP %{http_code}\n' -X POST "$TOKEN_EP" \
    -d grant_type=authorization_code -d code="$1" \
    -d redirect_uri="$RURI" -d client_id="$CID" \
    -d code_verifier="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

### Step 1 — Variant A, the control

Redeem a fresh code with the correct verifier.

```bash
# host
variant_A "$CODE_1" "$VERIFIER_1"
```

**This must return `200` with tokens.** If it does not, your capture is wrong — the code expired, the
`redirect_uri` does not match exactly, or you copied the verifier from a different flow. **Do not
proceed until A succeeds.** Without a working control, a failure in B tells you nothing.

**Q1.** Record the exact response. What is `expires_in`? Is a `refresh_token` present?

### Step 2 — Variant B, verifier omitted

Get a **fresh** code, then:

```bash
# host
variant_B "$CODE_2"
```

**Expected:** `400` with `{"error":"invalid_grant"}` or `invalid_request`.

**If tokens come back, stop and take careful evidence.** This is a Critical finding. Save the full
request and response, note the timestamp, and confirm the code was fresh by checking that it differs
from `CODE_1`.

**Q2.** What exactly did the server return? Quote the body verbatim — a report with a paraphrased
error message is weaker than one with the bytes.

### Step 3 — Variant C, verifier wrong

Fresh code again:

```bash
# host
variant_C "$CODE_3"
```

**Expected:** `400 invalid_grant`.

**Q3.** Did B and C behave the same way? A server that rejects C but accepts B is *checking the
verifier when present and not requiring it when absent* — which is the most common shape of this bug,
and it is fully exploitable, because an attacker simply omits the parameter.

### Step 4 — Variant D, code reuse

Take a fresh code, redeem it correctly (which succeeds), then redeem the **same** code again with the
same correct verifier.

```bash
# host
variant_A "$CODE_4" "$VERIFIER_4"      # succeeds
variant_A "$CODE_4" "$VERIFIER_4"      # must fail
```

**Expected:** the second attempt returns `400 invalid_grant`.

**Q4.** Did the second attempt fail? Bonus: a hardened AS **revokes the tokens issued by the first
exchange** when it detects reuse, on the theory that a replayed code means someone else has it. Test
the first exchange's access token after the replay and see whether it still works.

### Step 5 — Variant E, PKCE downgrade

Start an entirely **new** authorisation, but with `code_challenge_method=plain` and
`code_challenge=X` where you choose `X`. Then redeem with `code_verifier=X`.

```bash
# host
X="thisisaveryplainverifierof43charsminimumlength"
adb shell am start -a android.intent.action.VIEW -d \
"https://login.example.com/oauth2/authorize?response_type=code&client_id=$CID\
&redirect_uri=exampleapp%3A%2F%2Foauth%2Fcallback&scope=openid&state=abc\
&code_challenge=$X&code_challenge_method=plain"
# then, with the resulting code:
variant_A "$CODE_5" "$X"
```

**Expected:** the authorisation request itself is rejected, or the exchange returns
`400 invalid_request`.

**Q5.** Did it work? If the server honours `plain`, an attacker who can rewrite the front channel can
choose their own challenge and defeat PKCE entirely, regardless of what the app sends. Cross-check
against `code_challenge_methods_supported` from the discovery document — a server that lists `plain`
is telling you in advance.

### Step 6 — Two more checks while you have a live flow

**`redirect_uri` matching at the token endpoint.** RFC 6749 requires the `redirect_uri` on `/token`
to match the one used on `/authorize`. Try a fresh code with a slightly different value:

```bash
# host
curl -s -X POST "$TOKEN_EP" -d grant_type=authorization_code -d code="$CODE_6" \
  -d redirect_uri="exampleapp://oauth/callback/" -d client_id="$CID" -d code_verifier="$V6"
```

**Q6.** Note the trailing slash. Did the server care? Servers that normalise or prefix-match here have
a second weakness.

**Cross-client redemption.** If you can register your own client on the same AS, try redeeming a code
issued to the target's `client_id` while presenting **your** `client_id`.

**Q7.** Did it work? It must not. A server that binds the code only to the redirect and not to the
client is broken in a different and interesting way.

---

## Recording the results

Fill this in. It goes into the report verbatim.

| Variant | Request summary | HTTP status | Response body | Expected | Verdict |
|---|---|---|---|---|---|
| A — correct verifier | | | | `200` + tokens | control |
| B — verifier omitted | | | | `400 invalid_grant` | |
| C — verifier wrong | | | | `400 invalid_grant` | |
| D — code reused | | | | `400 invalid_grant` | |
| E — `plain` downgrade | | | | rejected | |
| F — `redirect_uri` mismatch | | | | `400 invalid_grant` | |

---

## Writing the finding

If B or C returned tokens, the report writes itself. The business-impact sentence is the part that
gets it fixed:

> Any application installed on the user's device can register the redirect scheme `exampleapp://`,
> receive the authorisation code during a legitimate login, and exchange it at the token endpoint for
> a full access and refresh token set **without presenting any secret**. This results in complete
> account takeover, is invisible to the user and to the application, and persists across password
> changes because the refresh token is unaffected by a credential reset.

Attach the variant A and variant B transcripts. That is the whole finding.

**Severity depends on the redirect.** If the redirect is a *verified* App Link, the on-device
interception path is closed and the severity drops to High rather than Critical — but the flaw is
real, because codes also leak through browser history, `Referer` headers, server logs and screen
recordings, and because App Link verification can silently fail. Say so explicitly. Being able to
argue *why something is not Critical* is what makes your Critical ratings credible.

---

## Success criteria

- [ ] Variant A succeeded, proving the control was valid
- [ ] Variants B and C were each run against a **fresh, unspent** code
- [ ] All five variants are recorded with verbatim status codes and response bodies
- [ ] You can explain why reusing one code across variants would have produced a false pass
- [ ] The `redirect_uri` matching behaviour at the token endpoint was tested
- [ ] Your conclusion names the **server** as the enforcement point, not the client
- [ ] If enforcement is missing, you wrote the impact sentence and attached both transcripts
- [ ] If enforcement is present, you wrote the positive assurance statement naming exactly what was proven

---

## Debrief

1. Explain, to a developer who wrote the Android app, why this finding is not their bug — and what
   they should ask their identity team.
2. Variant C failed but variant B succeeded. Describe the server's likely implementation and why it is
   fully exploitable.
3. Why does a correct server burn the code even on a *failed* exchange? What attack does that prevent?
4. You have a verified App Link and no PKCE enforcement. List three ways an authorisation code can
   still leak.
5. Design an automated version of this test that could run nightly against 50 authorisation servers.
   What is the hardest part, and why does nobody do it?
6. A vendor says "we support PKCE". Write the single question that determines whether that statement
   means anything.
