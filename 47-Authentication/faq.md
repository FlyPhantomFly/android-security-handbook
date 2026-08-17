# 47 — Authentication · FAQ

Real questions, answered directly. Including the ones people feel stupid asking, which are
usually the ones worth asking.

---

### 1. What is the actual difference between authentication and authorisation? I always mix them up.

Authentication is the bouncer checking your ID at the door: **who are you?** It happens once.

Authorisation is the bouncer checking whether your wristband gets you into the VIP room:
**may you do this specific thing?** It happens every single time you try to go somewhere.

The reason it matters and is not just vocabulary: they break differently and they are fixed in
different places. An app with flawless authentication can hand you every other user's data if
the server forgets to check ownership on one endpoint. If your report says "authentication
issue" for that, it goes to the identity team, who will correctly say it is not theirs.

---

### 2. Why can't the Android app just decide whether I'm logged in? It seems like the obvious place.

Because the app is running on a computer the attacker owns.

Think about what "the app decides" means physically. The decision is a value in memory or a
line in a file, on a device somebody can root, in code they can decompile and edit. Asking the
app whether the user is authenticated is like asking someone to check their own exam paper.

This is not a theoretical concern — it is one Frida line, or one `sed` on an XML file. The
server is the only participant the attacker cannot reach.

---

### 3. So is a client-side check completely pointless?

No, and this is where a lot of reports go wrong in the other direction.

A client-side check is a **user-experience feature** and it is often a good one. Checking a
stored credential's expiry before making a request saves a round trip and lets the app prompt
at the right moment instead of failing halfway through a payment. A biometric prompt to open
the app raises the cost of casual snooping by someone holding an unlocked phone.

The discipline is being able to answer, for each check: **what breaks if an attacker removes
it?** If the answer is "the user experience", it is fine. If the answer is "the security", it
is in the wrong process.

---

### 4. I found an app storing its auth token in SharedPreferences. Is that a finding?

Almost certainly not on its own, and reporting it as one will get you rejected by any reviewer
who knows the platform.

That is how essentially every Android app works. On a stock, locked, unrooted device the app
sandbox plus file-based encryption genuinely keeps that file private. "The app stores a token
in SharedPreferences" describes normal behaviour.

It becomes a finding when you can add a clause: the token is **over-scoped**, **long-lived**,
**still valid after logout**, **accepted without signature verification**, or **readable by
another app**. Pick the clause you can actually demonstrate, and show the evidence for that
specific one. [33-Storage §5.3](../33-Storage/README.md) is the reference.

---

### 5. I read the token off a rooted device. Isn't that a finding?

Root reads everything. That is what root means. Demonstrating that a root shell can read an
app's private file is demonstrating that the sandbox is a sandbox.

The finding is never "I could read it with root". It is what the token *is* and what it still
*does* — its scope, its lifetime, whether it survives logout, and whether anything short of
root could reach it (a backup, another app, a log, a proxy).

---

### 6. What is the single most valuable thing I can do in an authentication review?

Take one authenticated request the app made and replay it from `curl`, without the app.

That single step tells you which of two completely different reports you are writing. If the
server refuses, everything you find on the client is bounded and you can say so. If the server
serves it, you have the finding already, it is bigger than anything on the device, and you
should file it against the endpoint.

It takes thirty seconds and it is the step most commonly skipped.

---

### 7. How do I test whether logout works?

Three requests:

1. Capture a request that needs authentication. Note the credential.
2. Log out in the app.
3. Replay request 1, unchanged.

If step 3 works, logout did not revoke anything. The app forgot the credential; the server did
not.

Then test the other three variants, because apps implement them independently: password
change, "sign out of all devices", and account deletion. The password-change one fails most
often, because it needs the server to enumerate a user's sessions rather than the client to
delete one.

---

### 8. Why is "logout doesn't revoke" usually rated High? It sounds minor.

Because of what it does to every *other* finding in your report.

The user performed the only action the product offers to end their session, and the credential
kept working. So every way that credential could leak — a log line, a backup, a shared device,
a captured request, a resold phone — now has **no user-available remedy**. The user cannot fix
it, and cannot even know it needs fixing.

Phrase it that way and it stops being arguable.

---

### 9. The app has two-factor authentication. Doesn't that make all this less important?

Only if the second factor is actually part of the decision, and very often it is not.

The failure to look for: the server returns `{"mfa_required": true}` **together with a usable
session token**. The app dutifully shows the OTP screen. But the token in that first response
already works. One proxy rule, or one `curl`, and the second factor never happened.

The fix is that the pre-MFA credential must be scoped to exactly one operation and rejected
everywhere else. The general rule is worth memorising: **an intermediate authentication state
must be represented by a credential that cannot do what the final state can do.**

---

### 10. The app requires a fingerprint before a bank transfer, and the fingerprint prompt genuinely works. Is the transfer protected?

No, and this is the most common category error in the chapter.

`onAuthenticationSucceeded` is a callback in the app's own process. It is a fact about a phone,
not a claim the server has any reason to believe — and it is one hook away.

For the prompt to matter, it has to gate a **key** (a Keystore key created with
`setUserAuthenticationRequired`), the key has to sign a **server-issued challenge**, and the
server has to verify the signature. Then hooking the callback gets you nothing, because the
callback is not what authorises the transfer.

One more detail people miss: the challenge must cover the **operation's parameters**. If the
app signs an opaque nonce, the user can approve a £5 payment while the client submits £5,000.

[48-Biometrics](../48-Biometrics/README.md) owns the prompt itself.

---

### 11. Everyone says to grep the APK for `FLAG_SECURE`. My greps always come back empty. Am I doing it wrong?

You are doing it right. The check is wrong.

`FLAG_SECURE` is a `public static final int` with the value `0x2000`. javac performs constant
folding, so the *name* is substituted with the literal at compile time and never reaches the
class file — let alone the DEX.

This was verified rather than assumed: an Activity that provably sets the flag was compiled,
and the string `FLAG_SECURE` is absent from both the `.class` and the DEX, while `setFlags`
survives and the constant appears only as `const/16 v0, #int 8192`.

So the grep has a true-positive rate of **zero**: every hit is something else, and every app
that really sets the flag is invisible to it.

Do this instead:

```bash
# reliable, and gives per-screen coverage
frida -U -f com.example.app -l scripts/auth-hooks.js   # hooks Window.setFlags

# zero-tooling, and this is the evidence you paste into the report
adb shell screencap -p /sdcard/p.png     # black image = the flag is working
```

---

### 12. `GET_ACCOUNTS` is in the manifest. Can the app read my Google account?

Not because of that permission. Since API 26 it grants nothing.

Account visibility is decided **per package by the authenticator**, and recorded in a
`visibility` table. On a real device that table contained 17 explicit grants to named packages
and no blanket access at all.

Finding `GET_ACCOUNTS` in a modern manifest tells you the manifest has accumulated years of
copy-paste. It tells you nothing about what the app can see. To find that out, hook
`AccountManager.getAccounts()` and look at what comes back.

---

### 13. Are the tokens in AccountManager encrypted?

No. This surprises people and it is worth being precise.

`/data/system_ce/<user>/accounts_ce.db` is an ordinary SQLite database. `authtokens.authtoken`
is a `TEXT` column containing the token. `accounts.password` is a `TEXT` column that some
authenticators genuinely still use — measured on a real device, one account held a
352-character value there.

What protects it is file permissions (`0660 system:system`) and SELinux
(`system_data_file`). An app cannot read it. The adb shell cannot read it. **Root can read all
of it.**

That is the platform's design, not an app's defect. Do not report it against an app that
merely uses `AccountManager`.

---

### 14. Should an app avoid `AccountManager` then, since it's plaintext?

Usually not. The comparison people make is wrong.

The alternative is the app storing the credential in its own private directory — which is also
plaintext unless it does the Keystore work, and which is *also* readable by root. You have not
gained anything by avoiding the platform database.

What `AccountManager` gives you is a single sign-in shared across apps, an OS-level "remove
account" affordance, and per-package visibility control. Those are real benefits.

The thing to actually avoid is `setPassword` — putting a user-chosen credential in that
plaintext column, rather than a revocable token.

---

### 15. Why is account enumeration only Low? It feels worse than that.

On its own, against a general consumer service, it usually is Low, and it will be argued down.
Knowing that `alice@example.com` has an account somewhere is rarely damaging by itself.

It stops being Low in two situations, and you should look for both:

**When existence *is* the disclosure.** A dating service, a medical service, a support service
for a stigmatised group, an employer-specific portal. There, "this person has an account" is
the sensitive fact, and it can reach High.

**When it chains.** Enumeration plus missing rate limiting turns a broad guessing campaign into
a targeted one and materially raises the success rate. Report the chain, not the parts.

---

### 16. Can I really detect enumeration from response timing? That sounds fragile.

You can, and it is fragile, and both halves matter.

The reason it works: a server that returns early for an unknown account skips the password
hash. A proper KDF takes 50–100 ms *by design*, so the difference is enormous — measured on
the chapter's lab server, **+69.2 ms**, cleanly separated.

The reason it is fragile: network jitter routinely produces differences that look like that
and are not. Against the *secure* server the same measurement gave **+10.9 ms** — bigger than
plenty of numbers people happily report — and the correct verdict was **INCONCLUSIVE**,
because the interquartile ranges overlapped.

[`scripts/enum-timing-probe.py`](scripts/enum-timing-probe.py) compares quartiles rather than
means and refuses to conclude when they overlap. Being able to say "inconclusive" is the skill.

---

### 17. Does an app need `READ_SMS` to auto-fill an OTP?

No. It never needs it, and there are three permissionless ways to do it.

The best is the **SMS Retriever API**: the server appends an 11-character hash derived from the
app's package name and signing certificate, and Play services delivers only the matching
message, only to that app. No permission, no prompt, no user interaction.

If you find an app that has SMS Retriever *and* `READ_SMS`, the usual cause is not malice. It
is that the hash was computed from the debug signing key, so it never matched in production,
the API appeared broken, and someone "fixed" it with a permission. Compute the real hash with
[`scripts/sms-retriever-hash.py`](scripts/sms-retriever-hash.py) before you write the finding —
the finding is still valid, but the recommendation is different.

Measured across 17 real apps: 12 had SMS Retriever markers and 9 also had full-inbox SMS
markers.

---

### 18. If the app doesn't request any SMS permission, is the OTP safe from other apps?

Not necessarily, and this is the channel most threat models miss.

An app with `BIND_NOTIFICATION_LISTENER_SERVICE` can read the OTP straight out of the
notification shade and never touch an SMS permission. "We do not request `READ_SMS`" is not
the same as "the code cannot be read by another app on this device".

---

### 19. Passkeys are supposed to fix authentication. Do they make this chapter obsolete?

They make about a third of it obsolete and leave the rest untouched.

What they genuinely fix: phishing (structurally, via `rpId` binding to the app's signing
identity through Digital Asset Links), password reuse, credential stuffing, and
database-breach replay. There is no shared secret, so there is nothing in the app's storage to
steal.

What they do not touch: **everything after login**. The ceremony ends with an ordinary session
credential that has ordinary lifetime, storage, revocation and replay problems. Sessions,
logout, step-up and IDOR are all exactly as they were.

The emerging finding shape is an app with beautiful passkey sign-in and a non-expiring bearer
token in `SharedPreferences`. **Passkeys fix login. They fix nothing after login.**

Also: adoption is still thin. Across 17 real apps, 4 carried passkey ceremony objects and only
1 carried the unified `androidx.credentials` entry point.

---

### 20. My device doesn't have Credential Manager. Is something broken?

Probably not — check the API level. The platform `CredentialManager` service arrived in
**API 34**. On the chapter's API 30 test device, `service list` shows no `credentials` service
at all.

`androidx.credentials` exists precisely to bridge this: it routes to Google Play services'
FIDO2 implementation on older releases and to the platform service on 34+.

One trap to know about: `android.security.identity` **is** present from API 30 and is **not**
Credential Manager. It is the Identity Credential API, for things like mobile driving licences.
Two unrelated APIs with "credential" in the name, on the same device.

---

### 21. Should an app disable autofill on its password field to be safe?

No. It is a hardening-checklist item that is backwards, and you should report it as a defect
when you see it.

`importantForAutofill="no"` on a password field does not stop a malicious autofill service
seeing the rest of the screen, does not stop a third-party keyboard seeing keystrokes, and does
not stop screenshots. What it *does* stop is legitimate password managers — which pushes users
toward passwords they can type from memory. The measurable outcome is weaker credentials.

Where the attribute genuinely belongs is `noExcludeDescendants` around subtrees that *display*
account data, which is where an app actually over-shares — and almost nothing uses it there.

---

### 22. Is it bad that my password manager can see every app's login screen?

It is the design, and the mediation is better than it sounds.

The autofill service never gets a handle to the target app's process. `system_server` builds an
`AssistStructure` — a snapshot of the view tree — and passes that one way, and `Dataset` values
back the other way. The service cannot read the app's memory and the app cannot learn which
service filled the field.

The genuine risks are that the user might select a *malicious* app as their autofill service
(one Settings toggle, with wording that does not convey the consequence), and that the
`AssistStructure` includes the **text of views the app forgot to exclude** — a "logged in as
alice@…" label, a masked account number.

A related observation worth carrying into a threat model: on a stock Google device, the
autofill service and the `AccountManager` authenticator that owns the `com.google` account type
are **the same uid**.

---

### 23. What is IDOR, in plain terms?

You change a number in a request and get somebody else's data.

`GET /api/v1/invoice/10412` returns invoice 10412 to whoever asks, because the server checked
that you are *logged in* and forgot to check that the invoice is *yours*.

It is the most common serious backend finding reached through a mobile client, and mobile
clients are unusually good at finding it: the app's traffic is a complete, uniform inventory of
the API in ten minutes of tapping.

---

### 24. The developer says their IDs are UUIDs so IDOR isn't exploitable. Are they right?

No, and the answer is short: that is an argument about **discoverability**, not about
**authorisation**.

It fails the moment an identifier is legitimately shared — in a URL, an invoice PDF, a support
ticket, a referral link, an exported file, a webhook payload, or a departed employee's records.

Report the missing check on its merits and record the random identifier separately as a
mitigating factor. Downgrading a missing authorisation check to Informational because the id is
random is a mistake worth unlearning.

---

### 25. Why should a server return 404 instead of 403 for an object I'm not allowed to see?

Because 403 says "this exists and you may not have it", which is an existence oracle. It is
account enumeration applied to objects: an attacker can map what exists without reading
anything.

404 is indistinguishable from "no such object", so they learn nothing.

---

### 26. What actually survives `pm clear`?

`pm clear` deletes the package's data directories, so it removes the app's own stored
credential. It does **not** remove:

- the row in `accounts_ce.db`, which belongs to `system` and lives outside the package's
  directory entirely;
- anything on shared external storage;
- the account **visibility** grants;
- and, most importantly, **the server-side session**.

That last one is the useful test: an app that comes back logged out after `pm clear` while its
credential still works against the server has just demonstrated a client-side logout.

---

### 27. How do I know if a session has actually expired without waiting hours?

Three options, in order of preference.

If the credential is structured, decode it and read its own expiry — see
[46-Tokens](../46-Tokens/README.md). But remember the access token's expiry is not the session
lifetime.

Find the refresh credential and its lifetime. **The session lifetime is the lifetime of the
longest-lived credential in the chain.** One hour plus ninety days is a ninety-day session.

Or park a credential and retry it tomorrow. Unglamorous, and it is the only way to test an
absolute lifetime you cannot read.

---

### 28. There's no CVE for any of this. Am I missing something?

You are not. Authentication defects are overwhelmingly *application* defects: they live in one
app and its backend, they are fixed by a deployment, and they never get a CVE.

Use **CWE** identifiers instead — CWE-613 for sessions that do not expire, CWE-639 for IDOR,
CWE-640 for weak recovery, CWE-307 for missing throttling — plus the **MASVS** control. A CWE
and a clean reproduction is stronger evidence than a CVE number anyway, and inventing a CVE
identifier is the fastest way to lose a reader's trust.

---

### 29. My scanner says 15 of 17 apps have a client-side authentication gate. Is that plausible?

No, and the number is this chapter's own scanner being honest about being noisy.

It means 15 apps contain at least one of `isLoggedIn`, `isPremium`, `isAdmin` or
`savedPassword` somewhere in up to 94 MB of DEX — **including every bundled third-party SDK**.
An ad library's `isPremium` field is not the app's authentication gate.

It is a *read list*, not a finding list. Four chapters of this repository measured the same
thing independently: [33-Storage](../33-Storage/README.md) got 132 hits and 132 false
positives; [36-CertificatePinning](../36-CertificatePinning/README.md) found 12 of 14 apps with
a pinning surface and 4 actually pinning; [52-StaticAnalysis](../52-StaticAnalysis/README.md)
reduced 16,836 hits to 168 leads and rejected 15 of its top 17 by hand.

**A sweep produces leads, not findings, and confidence ranking is not severity ranking.**

---

### 30. I patched `isLoggedIn()` to return true and nothing changed. Does the app have anti-tampering?

Probably not. That is the third hypothesis, not the first.

More likely: the method has other callers you did not patch, or **its body was inlined** into
the caller so your patched copy is called by nothing, or the decision is made somewhere else
entirely.

This is measured elsewhere in the repository rather than guessed:
[18-ARM](../18-ARM/README.md) patched a signature check to return 1, verified it returning 1,
and the program still refused — because clang had inlined it. [65-Hooking](../65-Hooking/README.md)
found a perfectly-installed hook on a function with **zero** call instructions targeting it.

The fix is to hook the **call site** or the platform method underneath — which is why
[`scripts/auth-hooks.js`](scripts/auth-hooks.js) hooks
`SharedPreferencesImpl.getBoolean` rather than the app's own method.

---

### 31. Why does this chapter keep telling me to hook platform classes instead of the app's?

Three reasons, all practical:

- **R8 does not rename them.** `Landroid/accounts/AccountManager;` is the same in every app,
  obfuscated or not, because renaming it would break the call.
- **They cannot be inlined away** from the app's perspective — they live in a different DEX,
  loaded by a different class loader.
- **One script works everywhere**, and keeps working after the app is updated, obfuscated or
  rewritten.

The counter-example worth knowing: [54-Objection](../54-Objection/README.md) measured its
`android sslpinning disable` reporting three successful hooks against an app **with no network
code at all** — because the hooks target platform classes. Take the lesson in both directions:
platform hooks are portable, and a successful hook is evidence that a hook installed, not that
the app was doing the thing.

---

### 32. I'm asked to test authentication but there's no login — the app just works. What do I test?

Quite a lot, and this is a good situation to be in.

Something authenticated you. Find out what: a device-bound registration on first launch, an
account on the device via `AccountManager`, a silent OAuth exchange, or an anonymous
installation identifier that the backend treats as an identity.

Then ask the usual questions of whatever you found. Can it be copied to another device? Does it
expire? Can it be revoked? Is the "anonymous" identifier actually being used as an
authorisation subject — because an app with no login and an `X-Device-Id` header that the
server trusts has an authentication system, just not a good one.

---

### 33. How do I write this up so the developer actually fixes it?

Two things matter more than everything else.

**Title it against the right layer.** If the server accepted something it should have refused,
name the *endpoint*. If you file it as "Android client authentication bypass", the developer
will harden the app — obfuscation, root detection, pinning — and the vulnerability will survive
the remediation and the retest.

**Do not inflate the client-side findings.** Rating a bypassable boolean as Critical when the
server re-checks is the fastest way to make a developer stop reading, and you need them reading
for the three server-side findings that actually matter. The chapter's CTF deliberately
**deducts points** for over-rating its client-side decoy, and that is not a joke.

---

### 34. What is the safest thing to practise all of this on?

The lab in this chapter. [`labs/authlab/auth_server.py`](labs/authlab/auth_server.py) runs on
loopback, contains two accounts it creates itself, and has a `--mode vulnerable` and a
`--mode secure` that share their routes and storage — so the *only* differences are the ones
the chapter is about. Twelve labelled defects, each with a working fix beside it.

Then [`labs/ctf/vault_auth.py`](labs/ctf/vault_auth.py), which self-verifies all four flag
paths with `--verify` before you spend an evening on it.

Every endpoint in every example uses the `.invalid` TLD, which is reserved so it can never
resolve. Nothing in this chapter can accidentally point at a real service.
