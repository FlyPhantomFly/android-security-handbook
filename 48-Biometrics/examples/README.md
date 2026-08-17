# Examples — 48 Biometrics

Three implementations of the same feature: "unlock a stored secret with a fingerprint."

They are deliberately the same shape, the same length and the same user experience. The only
differences are the ones that matter, and the point of reading them side by side is to see how
small those differences are in code and how total they are in effect.

| File | Language | Grade | The one thing that decides the grade |
|---|---|---|---|
| [`01-CallbackOnlyVault.java`](01-CallbackOnlyVault.java) | Java | **D** | `authenticate(info)` — one argument. No key exists, so there is nothing for the hardware to refuse. |
| [`03-TimeBoundTrap.kt`](03-TimeBoundTrap.kt) | Kotlin | **B** | `setUserAuthenticationValidityDurationSeconds(86400)` — one line. Everything else is correct. |
| [`02-CryptoBoundVault.java`](02-CryptoBoundVault.java) | Java | **A** | `authenticate(info, CryptoObject(cipher))` on a per-use key, and the Cipher is read **from the result**. |

Read them in the order D → B → A, not in filename order. File 03 is the interesting one: it is what
a team produces after being told to "use a CryptoObject", and it passes review.

---

## Grading them yourself

```bash
# host, from the chapter root
python3 -B scripts/grade-biometric-usage.py examples/ --show-evidence
```

Measured output at the time of writing:

```
scanned 3 files; 3 carry biometric evidence

grade distribution: A=1  B=1  D=1

[D] examples/01-CallbackOnlyVault.java
     prompt with no CryptoObject and no auth-bound key

[B] examples/03-TimeBoundTrap.kt
     time-bound key, validity 86400s (>= 1 hour): satisfied by ANY device unlock in that
     window, by any process, with no prompt from this app

[A] examples/02-CryptoBoundVault.java
     per-use binding: setUserAuthenticationRequired(true) with a per-use validity value
     (0 or -1) - the strong form
```

### The grader graded these files wrong twice before it graded them right

Both failures are recorded in the script's own comments, because both are failure modes of *every*
regex-based static tool and neither is obvious:

1. **It read the comments.** File 01 discusses `CryptoObject` at length in prose while never using
   one; file 02 quotes a 30-second window as an example of what not to do. On the first run the
   tool reported `01 = C` and `02 = B` — the exact inverse of the truth. Decompiler output is
   comment-free, so this rarely bites a `jadx` tree; it bites hard on source. Reproduce it with
   `--keep-comments`.

2. **It could not resolve a named constant.** File 03 writes
   `private const val VALIDITY_SECONDS = 86_400` and passes the symbol. A regex looking for a
   literal found nothing, concluded there was no window, and graded the worst file **A**. The tool
   now resolves same-file constants, and where it still cannot, it grades **C** with the unresolved
   symbol named rather than guessing.

The lesson generalises past this tool: **a static grader that cannot see a value will report the
absence of a problem, not the absence of evidence** — unless someone makes it say so out loud.

---

## Building and running them

These are single-file fragments, presented for reading. To exercise them:

- **Lab 01** — [`../labs/lab-01-callback-vs-crypto.md`](../labs/lab-01-callback-vs-crypto.md)
  builds 01 and 02 into a real APK and attacks both with the same Frida script, so the reader sees
  one technique succeed and then fail against the fix.
- **Lab 02** — [`../labs/lab-02-auth-bound-keys.md`](../labs/lab-02-auth-bound-keys.md) reproduces
  file 03's measurement without any app at all, using
  [`../scripts/probe-biometrics.sh`](../scripts/probe-biometrics.sh).

Dependencies for a project that compiles them:

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
}
// minSdk 23; the API 30+ branches are taken at runtime, not at compile time
```

> **⚠️ Warning**
> `01-CallbackOnlyVault.java` and `03-TimeBoundTrap.kt` are deliberately vulnerable. Install them
> only on a device or emulator you own. Neither contacts the network; the only data either handles
> is a hard-coded string. Do not lift either into production code, and do not lift file 02 either
> without reading its `FIX 6` comment about enrolment invalidation, which is a product decision as
> much as a security one.

---

## The diff that matters, in six lines

If you read nothing else in this directory, read this.

```java
// D  — examples/01-CallbackOnlyVault.java
prompt.authenticate(info);
public void onAuthenticationSucceeded(AuthenticationResult r) { unlocked = true; }
```

```java
// A  — examples/02-CryptoBoundVault.java
prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
public void onAuthenticationSucceeded(AuthenticationResult r) {
    then.run(r.getCryptoObject().getCipher());     // from the RESULT, never from the closure
}
```

In the first, "authenticated" is a field. In the second, "authenticated" is the existence of a
`Cipher` that KeyMint agreed to initialise. An attacker can write the field. An attacker cannot
write the `Cipher`.

---

## Related

- [`../README.md`](../README.md) — the chapter, §3.6 for the time-bound measurement
- [`../../49-KeyStore/examples/02-auth-bound-key.java`](../../49-KeyStore/examples/02-auth-bound-key.java) — the same key from the key-material side
- [`../../50-HardwareBackedSecurity/README.md`](../../50-HardwareBackedSecurity/README.md) — the Gatekeeper → HAT → KeyMint chain that makes the refusal real
