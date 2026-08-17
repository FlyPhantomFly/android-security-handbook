# 47-Authentication — Examples

Six graded examples, simple to enterprise. Each is a complete, annotated file; the
annotations are the teaching material and are worth more than the code.

| # | File | Level | What it shows |
|---|---|---|---|
| 01 | [`01-VulnerableLogin.java`](01-VulnerableLogin.java) | Simple | Seven numbered defects `[V1]`–`[V7]` in the canonical client-side gate — and, for each, **why a competent developer wrote it** |
| 02 | [`02-HardenedLogin.kt`](02-HardenedLogin.kt) | Intermediate | The corrected counterpart, defect for defect. Deliberately contains **no `isLoggedIn()`** |
| 03 | [`03-CredentialManagerLogin.kt`](03-CredentialManagerLogin.kt) | Advanced | Passkeys, saved passwords and federation through one `androidx.credentials` call — plus the six things a reviewer must check, all of which are on the server |
| 04 | [`04-SmsRetrieverOtp.kt`](04-SmsRetrieverOtp.kt) | Advanced | Permissionless SMS OTP, and the `READ_SMS` version beside it for contrast |
| 05 | [`05-EnterpriseAuthSession.kt`](05-EnterpriseAuthSession.kt) | Enterprise | Device binding, silent re-auth, three lifetimes, and step-up the server can verify |
| 06 | [`06-otp-verify.c`](06-otp-verify.c) | Real application | Constant-time credential comparison — **measured**, with a result that contradicts the folklore |

---

## Defect map for example 01

`01-VulnerableLogin.java` is the reference specimen. Find these before reading the list —
[`../labs/lab-01-map-the-authentication-surface.md`](../labs/lab-01-map-the-authentication-surface.md)
asks you to.

| Tag | Defect | Fixed in 02 by | README |
|---|---|---|---|
| `[V1]` | A boolean on disk *is* the authentication decision | Removing the concept: state is derived from a server response | [§5.1](../README.md#51-the-client-side-authentication-gate) |
| `[V2]` | The password is persisted for "remember me" | Persisting a revocable refresh token instead | [§3.9](../README.md#39-remember-me-and-persistent-sessions) |
| `[V3]` | Logout is local only | Server revocation first, with a retry queue | [§5.7](../README.md#57-logout-that-does-not-revoke) |
| `[V4]` | No `FLAG_SECURE` on a credential screen | Setting it before the window is drawn | [§3.10](../README.md#310-flag_secure-and-what-it-does-not-do) |
| `[V5]` | Password becomes an immutable `String` | `CharArray`, scrubbed in a `finally` | [§3.3](../README.md#33-password-handling--where-a-password-comes-from-before-it-reaches-a-kdf) |
| `[V6]` | The credential is logged | Removing it; found in one `adb logcat` | [§7.8](../README.md#78-logcat-and-what-leaks-there) |
| `[V7]` | The client decides whether MFA happened | A pre-MFA token scoped to exactly one endpoint | [§5.6](../README.md#56-otp-and-multi-factor-where-the-flaws-actually-are) |

---

## Building and running example 06

This is the only example that is a standalone program, and it is the only one this chapter
could execute end to end.

```bash
# host
cc -Wall -Wextra -O2 -o otp-verify 06-otp-verify.c && ./otp-verify

# Android arm64, with the NDK
NDK=$HOME/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/bin
$NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 -o otp-verify 06-otp-verify.c
adb push otp-verify /data/local/tmp/ && adb shell /data/local/tmp/otp-verify

# vary the secret length - this is the interesting experiment
cc -Wall -Wextra -O2 -DSECRET_LEN=64  -o otp64  06-otp-verify.c
cc -Wall -Wextra -O2 -DSECRET_LEN=512 -o otp512 06-otp-verify.c
```

### What it measured here

Built with NDK r25c `aarch64-linux-android21-clang -O2 -Wall -Wextra` (zero warnings) and
run on the physical test device — Redmi `M2101K6P`, arm64-v8a, Android 11 / API 30 —
200,000 samples per case:

| Secret length | `naive_compare` | `ct_compare` |
|---:|---|---|
| 6 bytes (an OTP) | **INCONCLUSIVE**, delta **−51 ns** | INCONCLUSIVE, +0 ns |
| 64 bytes (a session token) | **INCONCLUSIVE**, delta +1 ns | INCONCLUSIVE, +0 ns |
| 512 bytes | **DISTINGUISHABLE**, delta **+417 ns** | INCONCLUSIVE, **+0 ns** |

Three readings, two of which contradict the usual teaching:

**The textbook demonstration did not reproduce at OTP length.** Six bytes of early exit is
below this device's timer granularity — roughly 52 ns, visible in the quantised medians
(156, 208, 260, 313 …) — and the measured delta came out *negative*, meaning the case that
should have been faster measured slower. That is noise, locally, with no network in the
path.

**It did not reproduce at session-token length either.** 64 bytes still gave +1 ns. The
common formulation "the effect scales with length, and tokens are long" is true and needs
roughly an order of magnitude more length than a real token has.

**The fix provably works and provably costs.** `ct_compare` measured +0 ns at *every*
length, which is the positive result: the mitigation is doing exactly what it claims. It
also ran 1,406 ns against naive's 208 ns at 512 bytes — about seven times slower on the
fast path, which is negligible at these magnitudes.

The reporting consequence is in the program's own output and is worth repeating: argue this
finding **from the code**, at Low to Medium, and do not attach a timing measurement you
cannot reproduce — because at OTP length you probably cannot.

---

## Safety and ethics

- `01-VulnerableLogin.java` is **deliberately broken** and labelled as such at the top of the
  file. Do not lift any part of it. It is compiled only as part of the lab app in
  [`../labs/authlab/`](../labs/authlab/), which installs on a device you own.
- Every network endpoint in every example uses the **`.invalid`** TLD, which
  [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) reserves so that it can never resolve.
- `06-otp-verify.c` generates its own "secret", talks to nothing, and reads nothing.
- No file here contains a real credential, key or token.

## Related

| Chapter | Why |
|---|---|
| [46-Tokens](../../46-Tokens/README.md) | The credential these flows issue — format, storage, verification failure classes |
| [45-OAuth](../../45-OAuth/README.md) | Third-party delegation, where the login is not first-party |
| [48-Biometrics](../../48-Biometrics/README.md) | The prompt in example 05's step-up, and how it is attacked |
| [49-KeyStore](../../49-KeyStore/README.md) | The key behind `CredentialStore` and the binding key in example 05 |
| [34-Cryptography](../../34-Cryptography/README.md) | The KDF the server applies to what example 02 sends |
