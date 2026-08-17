# Lab 03 — Enumeration, lockout and OTP

> **Difficulty:** Intermediate → Advanced
> **Time:** 2–3 hours
> **You will need:** Python 3, the lab server from
> [Lab 02](lab-02-session-lifecycle-and-logout.md), and — for Part 5 — the Android NDK or any
> C compiler.

---

## Objective

Attack the login flow itself, before a session exists. You will:

- find an account-enumeration oracle in the response **message**, then find it again in the
  **timing** after the message is fixed;
- learn to say *"inconclusive"* and mean it;
- defeat a six-digit OTP that has no attempt limit, and measure exactly how much a limit
  costs an attacker;
- break a password reset built with the wrong random number generator;
- and **measure** whether a non-constant-time credential comparison is really a timing
  oracle — with a result that contradicts what almost every write-up on the subject claims.

---

## Ethics — read this before running anything

Enumeration and lockout material is the part of this chapter with the most obvious potential
for misuse, so the boundaries are explicit and they are not negotiable.

- **Everything in Parts 1–4 runs against `127.0.0.1`**, on a server you started, containing
  two accounts it created itself.
- Against a real target, confirming an oracle takes **two accounts you own** and a handful of
  requests. It never needs a list of other people's addresses.
- This repository contains **no credential-stuffing or mass-targeting tooling** and will not
  gain any. [`enum-timing-probe.py`](../scripts/enum-timing-probe.py) accepts exactly two
  identifiers and refuses a list, caps its sample count, and sends a fixed wrong password so
  it never authenticates.
- If you need to demonstrate impact beyond a two-account comparison, **describe the
  extrapolation in the report** rather than performing it.
- Lockout is a control. If a target locks you out mid-test, that is a **positive finding
  about the target**, and the correct response is to record it and stop.

---

## Setup

```bash
# host - terminal 1
cd 47-Authentication/labs/authlab
python3 -B auth_server.py --mode vulnerable --port 8047

# host - terminal 2
python3 -B auth_server.py --mode secure --port 8048
```

This lab covers defects **D1, D2, D3, D4, D6 and D9**.

---

## Part 1 — The message oracle (20 min)

```bash
# host
curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"nobody@example.invalid","password":"x"}'
curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"bob@example.invalid","password":"x"}'
```

```json
{ "error": "No account with that email address" }
{ "error": "Incorrect password" }
```

That is CWE-203, an observable discrepancy, and it needs no statistics.

Secure mode returns `{"error": "Invalid email address or password"}` for both.

**Task 1.** The status codes also differ — 404 versus 401. Why does that matter separately
from the message?

<details>
<summary>Answer</summary>

Because a client that never displays the server's message still leaks. An attacker reads the
status code, the `Content-Length`, or the response time — the message is only the most
convenient of four independent channels.

This is why [`enum-timing-probe.py`](../scripts/enum-timing-probe.py) tests **four oracles**
(body, status, length, time) rather than one. A team that "fixes" enumeration by editing a
string and does not check the other three has fixed nothing measurable.
</details>

**Task 2.** Registration and password reset are usually easier oracles than login. Why?

<details>
<summary>Answer</summary>

Because their *purpose* pushes towards disclosure. Registration must tell the user "that
address is already registered" or it cannot function usefully, and password reset naturally
wants to say "we have no account for that address".

They are also used once per user and therefore tested once, so they receive far less
security attention than login. Test all three flows; they frequently disagree, and one leaky
flow is enough.
</details>

---

## Part 2 — The timing oracle, and learning to say "inconclusive" (40 min)

This is the part that survives fixing the message.

```bash
# host
python3 -B ../scripts/enum-timing-probe.py \
    --url http://127.0.0.1:8047/api/v1/login \
    --known bob@example.invalid \
    --unknown nobody-8f2a@example.invalid \
    --samples 30
```

Measured result against the vulnerable server:

```
ORACLE 4 - response time
  known    n=27   median=   84.6 ms   IQR=[   78.0,    91.0]
  unknown  n=27   median=   15.4 ms   IQR=[   13.7,    15.6]
  delta (known - unknown) = +69.2 ms

  >> DIFFERENT. The distributions are separated.
     The KNOWN account is SLOWER, which is the expected shape:
     the server runs a slow password KDF only when the account
     exists, and returns early when it does not.
```

**Sixty-nine milliseconds**, cleanly separated, with no message difference needed.

**Task 3.** Look at the vulnerable handler. Where exactly does the 69 ms come from?

```python
user = USERS.get(username)
if user is None:
    return 404, {"error": "No account with that email address"}
if not hmac.compare_digest(kdf(password, user["salt"]), user["verifier"]):
    return 401, {"error": "Incorrect password"}
```

<details>
<summary>Answer</summary>

From the **early return**. `kdf()` is `hashlib.scrypt` with `n=2**14`, which takes roughly
70–90 ms by design — that slowness is a security *requirement*, per
[34-Cryptography](../../34-Cryptography/README.md).

When the account does not exist, the function returns before ever calling it. The
not-found path costs a dictionary lookup; the found path costs a full scrypt derivation.

The important part: **this is a side effect of doing password hashing correctly.** The
developer who wrote it was not careless — they wrote the natural early return, and the
expensive KDF they were right to choose created the oracle.
</details>

**Task 4.** Now run it against secure mode and explain the result.

```bash
# host
python3 -B ../scripts/enum-timing-probe.py \
    --url http://127.0.0.1:8048/api/v1/login \
    --known bob@example.invalid --unknown nobody-8f2a@example.invalid --samples 30
```

<details>
<summary>Answer, with the measured output</summary>

```
ORACLE 2 - status code
  known   : [401, 429]
  unknown : [401, 429]
  identical

  NOTE: the status changed part way through. That is very likely a
  RATE LIMIT or LOCKOUT engaging - which is a control working.

ORACLE 4 - response time
  known    n=27   median=   15.1 ms   IQR=[   12.7,    15.7]
  unknown  n=27   median=    4.2 ms   IQR=[    2.6,    16.3]
  delta (known - unknown) = +10.9 ms

  >> INCONCLUSIVE. The interquartile ranges overlap.

No enumeration oracle detected on any of the four channels.
```

Two things happened, and both are the fix working.

The **dummy verifier** flattens the timing: `DUMMY_VERIFIER` is computed once at boot, and
the not-found path runs scrypt against it, so both branches cost the same.

The **rate limiter** engaged (the 429s), which both compresses the remaining timing
difference and is itself a control. The tool correctly identified it rather than reporting the
resulting noise as a finding.

Note the delta is still `+10.9 ms` — larger, in absolute terms, than differences people
happily report as findings. The tool refuses to call it, because the interquartile ranges
overlap. **That refusal is the feature.**
</details>

**Task 5.** Why does the probe compare interquartile ranges rather than means, and why does
it discard the slowest decile?

<details>
<summary>Answer</summary>

**Means are dominated by outliers.** One 400 ms response caused by scheduling or garbage
collection moves a mean by more than the effect you are looking for. Medians and quartiles do
not care.

**The slowest decile is almost entirely network and scheduler noise**, and it is the same
noise in both populations, so including it makes two genuinely different distributions look
identical — it hides real findings as well as creating false ones.

The deeper point: a timing claim you cannot reproduce destroys a report's credibility, and
you will be asked to reproduce it. A tool that says INCONCLUSIVE has protected you.
</details>

---

## Part 3 — D3: no rate limiting, and what a limit is worth (30 min)

```bash
# host - twelve attempts against the vulnerable server, YOUR OWN lab account
for i in $(seq 1 12); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8047/api/v1/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"bob@example.invalid","password":"wrong-'"$i"'"}')
  echo "attempt $i -> $code"
done
```

All twelve return 401. Now the same loop against port 8048; the responses become 429 with a
`retry_after`.

**Task 6.** Secure mode uses **exponential backoff**, not a hard lock. Why is a hard lock
usually the wrong answer?

<details>
<summary>Answer</summary>

Because it is a **denial-of-service primitive**. Anyone who knows a user's email address can
lock that account out at will, repeatedly and for free. For a service where the identifier is
a public email address, a hard lock converts a guessing defence into an availability
vulnerability.

Lockout state is also an **enumeration oracle**: an account that can be locked exists, and an
account that cannot does not. That is why the lab's limiter applies to the identifier
whether or not it exists — otherwise the fix for D1 and D2 is undone by the fix for D3.

Backoff gives the same defence against guessing without either problem.
</details>

**Task 7.** A target's *web* login has a CAPTCHA and lockout. Its *mobile* API has neither.
Why does this happen, and what do you do?

<details>
<summary>Answer</summary>

Because the mobile client is implicitly trusted: it is "our app", it ships with a secret
header, and it was not built by the team that hardened the web front end. Frequently the
mobile API is newer, and the anti-automation controls live in a web application firewall or
front-end framework that the mobile endpoints do not pass through.

What you do: take the login request the app sends, **replay it from `curl` with the app's
headers**, and confirm the CAPTCHA, the rate limit and the lockout are all still absent. A
small number of attempts against your own account is sufficient evidence.

This is a common and high-value finding, and it is **invisible to anyone testing only the
website**. Do not run a guessing campaign to prove it; demonstrate the absence of the control
and describe the consequence.
</details>

---

## Part 4 — D6 and D9: OTP and password reset (40 min)

### 4.1 The OTP with no limit

```bash
# host
R=$(curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
    -d '{"username":"alice@example.invalid","password":"correct-horse-battery"}')
echo "$R"
TOK=$(echo "$R" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# wrong codes, as many as you like
for c in 000000 111111 222222 333333 444444; do
  echo -n "$c -> "
  curl -s -X POST localhost:8047/api/v1/login/mfa -H 'Content-Type: application/json' \
       -d "{\"token\":\"$TOK\",\"code\":\"$c\"}"
  echo
done
```

Every one returns `{"error": "incorrect code"}` and the challenge stays alive for ever.

Against secure mode, the sixth attempt returns
`{"error": "too many attempts; challenge destroyed"}` and the session is dropped.

**Task 8.** With no attempt limit, how many requests does a six-digit code take, and what
does the secure server's limit of 5 reduce the attacker's success probability to?

<details>
<summary>Answer</summary>

A six-digit code has 1,000,000 values, so worst case 1,000,000 requests and on average
500,000. At a modest 50 requests per second that is under six hours — **an unbounded OTP is
not a second factor, it is a delay.**

With 5 attempts against a uniformly random code, the probability of success per challenge is
5 / 1,000,000 = **0.0005%**. If the attacker can request unlimited fresh challenges the
attempts accumulate, which is why the challenge request itself must also be rate-limited —
worth checking separately and frequently missed.

Also confirm the code is **single-use** and **expiring**: in the lab, secure mode destroys
the challenge on success (`MFA_CHALLENGES.pop`) and after 300 seconds.
</details>

**Task 9.** Test whether a *correct* code can be reused in vulnerable mode. What is the
severity of reuse alone?

<details>
<summary>Answer</summary>

It can — the vulnerable handler never consumes the challenge, so a correct code works
indefinitely.

Reuse alone is **Medium**: it requires the attacker to have obtained a valid code, which
usually means they already had access to the delivery channel. It rises sharply when
combined with a code that appears somewhere durable — a notification history, a screenshot, a
backup, a support ticket, or an SMS on a shared or resold device.
</details>

### 4.2 The predictable reset token

```bash
# host
curl -s -X POST localhost:8047/api/v1/password/reset-request \
     -H 'Content-Type: application/json' -d '{"username":"bob@example.invalid"}'
curl -s -X POST localhost:8047/api/v1/password/reset-request \
     -H 'Content-Type: application/json' -d '{"username":"alice@example.invalid"}'
```

```json
{ "status": "sent", "token": "reset-1001" }
{ "status": "sent", "token": "reset-1002" }
```

**Task 10.** Two defects in three lines of output. Name them, then take over alice's account.

<details>
<summary>Answer</summary>

**The token is in the response** (the same defect as D4) and **the token is sequential**, so
even if it were delivered properly you could guess the next one.

Takeover:

```bash
curl -s -X POST localhost:8047/api/v1/password/reset \
     -H 'Content-Type: application/json' \
     -d '{"token":"reset-1002","new_password":"owned-by-lab-03"}'
curl -s -X POST localhost:8047/api/v1/login -H 'Content-Type: application/json' \
     -d '{"username":"alice@example.invalid","password":"owned-by-lab-03"}'
```

Secure mode uses `secrets.token_urlsafe(32)` — 256 bits from a CSPRNG — returns an identical
response whether or not the account exists, prints the token to the **server console**
standing in for email, expires it after 900 seconds, marks it used, deletes every *other*
reset token for that user, and **revokes every session for that user**.

That last step is the one people forget, and it is the one that matters most: a reset flow
exists to recover a **compromised** account, so if it does not eject the attacker it has not
done its job.
</details>

**Task 11.** Which random number generator produces `reset-1001`, and what is the Java or
Kotlin equivalent mistake?

<details>
<summary>Answer</summary>

A counter — the worst case. The more common real-world version is `java.util.Random`, which
is a linear congruential generator seeded from the clock: given a few outputs, the internal
state is recoverable and all future outputs are predictable. `Math.random()` and
`System.currentTimeMillis()`-derived tokens are the same defect.

The correct choice is `java.security.SecureRandom` on the JVM, `secrets` in Python. See
[34-Cryptography](../../34-Cryptography/README.md) on CSPRNGs.

Severity for a predictable reset token: **Critical**. It is unauthenticated account takeover
against any account whose identifier is known.
</details>

---

## Part 5 — Measure a timing oracle in C, and get an honest answer (40 min)

Everything so far has been about a *server's* timing. This part is about the comparison
itself, and it produces a result that contradicts most published treatments.

```bash
# host
cd ../examples
cc -Wall -Wextra -O2 -o otp-verify 06-otp-verify.c && ./otp-verify

# or on an arm64 device, with the NDK
NDK=$HOME/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/bin
$NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 -o otp-verify 06-otp-verify.c
adb push otp-verify /data/local/tmp/ && adb shell /data/local/tmp/otp-verify
```

Then vary the secret length — this is the experiment:

```bash
# host
cc -Wall -Wextra -O2 -DSECRET_LEN=64  -o otp64  06-otp-verify.c && ./otp64
cc -Wall -Wextra -O2 -DSECRET_LEN=512 -o otp512 06-otp-verify.c && ./otp512
```

**Measured on the chapter's reference device** — Redmi `M2101K6P`, arm64-v8a, Android 11 /
API 30, NDK r25c `-O2`, 200,000 samples per case:

| Secret length | `naive_compare` (early return) | `ct_compare` (constant time) |
|---:|---|---|
| 6 bytes — an OTP | **INCONCLUSIVE**, delta **−51 ns** | INCONCLUSIVE, +0 ns |
| 64 bytes — a session token | **INCONCLUSIVE**, delta +1 ns | INCONCLUSIVE, +0 ns |
| 512 bytes | **DISTINGUISHABLE**, delta +417 ns | INCONCLUSIVE, **+0 ns** |

**Task 12.** At six bytes the naive comparison's delta was **negative** — the case that
should have been faster measured slower. What does that mean, and what does it mean for how
you report this defect?

<details>
<summary>Answer</summary>

It means the measurement is **noise**. Six bytes of early exit is smaller than this device's
timer granularity — visible in the quantised medians (156, 208, 260, 313 ns, all multiples of
about 52 ns) — so the sign of the difference is arbitrary.

This was measured **locally, on the same CPU, with no network in the path**, which is the
most favourable possible conditions for the attacker. Anyone claiming a remote timing attack
on a six-digit OTP needs to show their work.

For reporting: argue the defect **from the code**, at Low to Medium, and **do not attach a
timing measurement you cannot reproduce**. The argument is that exploitability depends on
secret length, CPU and attacker position — none of which the developer controls — and the fix
is four lines. Attaching a bogus measurement lets the developer dismiss the whole finding by
failing to reproduce it.
</details>

**Task 13.** The 64-byte case — session-token length — was also inconclusive. Most write-ups
say "the effect scales with length, and tokens are long". Is that wrong?

<details>
<summary>Answer</summary>

It is **true but insufficient**. The effect does scale — the 512-byte case is cleanly
distinguishable at +417 ns — but it needed roughly an order of magnitude more length than a
real session token has before it rose above the noise on this hardware.

This surprised the author of the chapter, and it is recorded rather than smoothed over. It is
the honest handling of a test that refuses to reproduce, in the same spirit as
[65-Hooking](../../65-Hooking/README.md), which reported that omitting an instruction-cache
flush **did not** fail and still required the flush, with the reasoning.
</details>

**Task 14.** `ct_compare` measured **+0 ns at every length** and ran 1,406 ns against naive's
208 ns at 512 bytes. State both facts as you would in a report.

<details>
<summary>Answer</summary>

> The constant-time comparison was verified to be constant: across 200,000 samples at 6, 64
> and 512 bytes, the median time to reject a value differing at the first byte was identical
> to one differing at the last (delta 0 ns in all three cases). The mitigation measurably
> does what it claims.
>
> Its cost is approximately 7x on the fast path at 512 bytes (1,406 ns against 208 ns), which
> is negligible at these magnitudes and is incurred once per authentication attempt.

The positive result is worth stating explicitly. Most reports assert that a fix works; this
one demonstrates it, and demonstrates what it costs, which is what makes the recommendation
easy for an engineer to accept.
</details>

**Task 15.** Read `ct_compare`. Why is `volatile` on the accumulator, and what breaks without
it?

<details>
<summary>Answer</summary>

```c
volatile unsigned char diff = 0;
for (size_t i = 0; i < n; i++) {
    diff |= (unsigned char)(a[i] ^ b[i]);
}
return diff == 0;
```

Without `volatile`, a compiler is entitled to observe that once `diff` is non-zero the result
is determined, and to insert the early exit the function exists to remove. That is not
hypothetical — it is the standard reason hand-written constant-time code silently stops being
constant-time after a compiler or optimisation-level change.

There is a related measurement in this repository worth knowing:
[19-Memory](../../19-Memory/README.md) found that **`explicit_bzero` is absent from the NDK
r25c sysroot entirely**, so the textbook advice for scrubbing secrets fails at link time and
the workaround is — again — a `volatile` loop. On Android you frequently cannot rely on the
standard hardening helpers existing.
</details>

---

## Part 6 — Put it together (20 min)

**Task 16.** You have found, on one target: enumeration by message (Low), no rate limiting
(Medium), and a six-digit OTP with no attempt limit (High). Write the chained finding.

<details>
<summary>A model answer</summary>

> **Account takeover through unthrottled OTP verification, enabled by account enumeration.**
> Severity: **Critical**.
>
> The registration endpoint discloses whether an email address has an account, allowing an
> attacker to reduce an arbitrary address list to confirmed users before spending any
> attempts. The login endpoint applies no rate limiting, and the second-factor verification
> endpoint accepts unlimited attempts against a single challenge. A six-digit code has
> 1,000,000 values; with no attempt limit the second factor is a delay rather than a control.
>
> The three defects compose: enumeration converts a broad attack into a targeted one, and the
> absent limits make the targeted attack succeed. Demonstrated against two accounts under our
> control; **no third-party account was tested and no guessing campaign was performed.**

That last sentence belongs in every report of this shape. It states the boundary you worked
within, which is what makes the extrapolation credible rather than alarming.
</details>

---

## Success criteria

- [ ] You found the same enumeration oracle in the message **and** in the timing, and can
      explain why fixing the message leaves the timing behind.
- [ ] You can explain the dummy-verifier fix and why the rate limiter must apply to
      non-existent accounts too.
- [ ] You ran the probe against secure mode and got INCONCLUSIVE with a **+10.9 ms** delta,
      and understand why refusing to call that a finding is correct.
- [ ] You defeated the unlimited OTP and can compute what a limit of 5 reduces the success
      probability to.
- [ ] You took over an account through the reset flow and can name both defects in the
      response.
- [ ] You compiled `06-otp-verify.c` with `-Wall -Wextra`, ran it at three lengths, and can
      state honestly at which length the oracle becomes measurable.
- [ ] You can write a chained finding that states its own ethical boundary.

---

## Next

[Lab 04](lab-04-ctf-the-account-that-would-not-close.md) is the CTF. It needs everything from
Labs 01–03 and adds an Android client on top.
