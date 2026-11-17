# 46 — Tokens · Examples

Five files, graded simple to enterprise. The first two are the highest-value pair in the
chapter: **read them as a diff, not as two files.**

| File | Language | Runs? | What it is |
|---|---|---|---|
| [`01-broken-verifier.py`](01-broken-verifier.py) | Python 3 | Runs, and is driven by the gauntlet | A deliberately broken JWT verifier. Nine numbered flaws |
| [`02-correct-verifier.py`](02-correct-verifier.py) | Python 3 | Runs, and is the gauntlet's control | The same verifier, written correctly |
| [`03-BrokenTokenStore.java`](03-BrokenTokenStore.java) | Java (Android) | Compiles inside an Android project; **not built here** | The Android side, with nine flaws |
| [`04-HardenedTokenStore.kt`](04-HardenedTokenStore.kt) | Kotlin (Android) | Same | The same class, fixed |
| [`05-DpopInterceptor.kt`](05-DpopInterceptor.kt) | Kotlin (Android) | Same | Sender-constrained tokens, client side |

---

## The pair that matters

`01-broken-verifier.py` and `02-correct-verifier.py` take the same input, return the same
`(accepted, claims, reason)` tuple, and differ by about forty per cent in length — most of
which is comments.

The **security-relevant** difference is:

- one `frozenset` (the algorithm allow-list)
- two dictionaries instead of one variable (typed key storage)
- four string comparisons (`iss`, `aud`, `azp`, and strict base64url)
- one `isinstance` check (`exp` is required, not optional)
- `hmac.compare_digest` instead of `==`

That is the whole thing. JWT verification failures are not a cryptography problem; they are
a handful of comparisons that were never written, in code that looks finished because the
hard-looking part — the signature — was done correctly.

```bash
# host — read them side by side
diff -u 01-broken-verifier.py 02-correct-verifier.py | less

# and run each against one token
python3 -B 01-broken-verifier.py --keydir /tmp/lab/keys --token "$T"
python3 -B 02-correct-verifier.py --token "$T" \
    --issuer https://issuer.lab.local --audience com.pentest.ch46.client \
    --rsa-key rsa-2026-08=/tmp/lab/keys/rsa-2026-08
```

Both are driven automatically by
[`../labs/gauntlet/run-gauntlet.py`](../labs/gauntlet/run-gauntlet.py), which submits nine
tokens to each and asserts the result matrix.

### The nine flaws in `01`, and where each is fixed

| # | Flaw in `01` | Fixed in `02` by | README |
|---|---|---|---|
| F1 | `alg` is read from the token and obeyed; `none` accepted | `ALLOWED_ALGS` frozenset | §5.1 |
| F2 | One key blob serves every algorithm | Typed key maps (`rsa_public_pems`, `hmac_secrets`) | §5.2 |
| F3 | The HMAC secret is a human-chosen word | A 32-byte minimum enforced at key selection | §5.4 |
| F4 | `kid` is used as a filesystem path | `kid` is a dictionary lookup, nothing else | §5.3 |
| F5 | `exp` / `nbf` / `iat` never examined | `exp` **required**, compared with bounded skew | §5.5 |
| F6 | `iss` never compared | Exact `!=` against the trust store | §5.6 |
| F7 | `aud` never compared | Membership test, plus `azp` when multi-audience | §5.6 |
| F8 | `==` on a secret-dependent comparison | `hmac.compare_digest` | §5.1 |
| — | (no `crit` handling) | `crit` present ⇒ reject | §3.2.1 |

---

## The Android pair

`03-BrokenTokenStore.java` and `04-HardenedTokenStore.kt` are the same class with and
without nine flaws. The most consequential is `userIdFromIdToken`, which performs five steps
and gets four of them right — splitting, decoding, parsing, reading — and never touches the
signature. Four correct steps is exactly why it survives code review.

**The fix is not a better version of that method. The method is deleted**, and the
`id_token` is sent to the backend, which verifies it and returns a session. The rule behind
that decision: *the party that acts on the answer must be the party that checks it.* A
client that verifies locally and then tells the backend "the user is alice@example.com" has
built a backend that trusts the client's conclusion.

| # | Flaw in `03` | Fixed in `04` by |
|---|---|---|
| F1 | `id_token` decoded, not verified | The method is deleted; the backend verifies |
| F2 | Account keyed on `email` | The backend derives `(iss, sub)` |
| F3 | Refresh token in plaintext SharedPreferences | `EncryptedSharedPreferences` |
| F4 | Hardcoded AES key, ECB, no authentication | No key material in the APK at all |
| F5 | Token logged | A `@JvmInline value class` whose `toString()` redacts |
| F6 | Logout clears local state only | Revoke **first**, clear regardless, report failure honestly |
| F7 | Expiry from a client-side field | From the signed `exp`; the server's 401 remains authoritative |
| F8 | `id_token` sent to the API | The access token is sent; the `id_token` never is |
| F9 | Callback URI forwarded onward | Consumed and dropped |

---

## The enterprise example

`05-DpopInterceptor.kt` implements RFC 9449 client-side: a P-256 keypair in the Android
Keystore, a proof JWT per request, `cnf.jkt` binding.

Two details in it break every hand-rolled implementation and are called out where they bite:

- **The RFC 7638 thumbprint** is over the required members only, sorted lexicographically,
  with no whitespace. For EC that is `crv`, `kty`, `x`, `y` in that order. Wrong order or
  stray spaces and the thumbprint silently does not match the server's.
- **Java's `Signature` emits ASN.1 DER**; JOSE ES256 requires raw `r‖s` at fixed width. Send
  the DER and every server rejects the proof with an error that looks like a key problem.
  Plus the `BigInteger.toByteArray()` width normalisation, which is wrong about one time in
  a hundred — the worst failure mode, because it passes testing.

Its closing comment lists the four requests that decide whether a DPoP deployment is real.
**Test 2 — strip the proof and send `Bearer` — is the one that matters**, and the one most
often skipped.

---

## Build status, honestly

| File | State |
|---|---|
| `01-broken-verifier.py` | **Executed.** Driven by the gauntlet; accepted 8 of 9 tokens as designed |
| `02-correct-verifier.py` | **Executed.** Accepted 1 of 9 — the genuine one — as designed |
| `03-BrokenTokenStore.java` | **Not compiled.** Needs the Android SDK on the compile path. Reviewed line by line; every API used is a documented public one |
| `04-HardenedTokenStore.kt` | **Not compiled.** Same. Needs `androidx.security:security-crypto`, `net.openid:appauth`, `okhttp` |
| `05-DpopInterceptor.kt` | **Not compiled.** Same. Needs `okhttp` |

To build the three Android files for real, drop them into an app module's
`src/main/java/com/pentest/ch46/` and add the dependencies listed in each file's header.
[`30-Activities/examples/build.sh`](../../30-Activities/examples/build.sh) has a complete
no-Gradle pipeline — `aapt2 link` → `javac` → `d8` → `zipalign` → `apksigner` — that builds
**out of tree**, so no `.apk`, `.dex` or `.class` reaches this repository.

---

## Safety

Every token these examples handle is one you minted, from the throwaway keypair
[`../labs/gauntlet/issuer.py`](../labs/gauntlet/issuer.py) generates and destroys.

`01-broken-verifier.py` says `ACCEPTED` when it should say `REJECTED`. **Never use it to
triage anything.** It exists to be read beside `02`, and to be defeated by the gauntlet.

Do not copy a method out of `03-BrokenTokenStore.java`. Do not ship it. Do not use it as a
starting point.

---

Back to [the chapter](../README.md) · [labs](../labs/) · [scripts](../scripts/) ·
[cheat sheet](../cheatsheet.md)
