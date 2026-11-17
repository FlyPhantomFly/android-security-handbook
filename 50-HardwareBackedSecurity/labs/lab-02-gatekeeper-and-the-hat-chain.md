# Lab 02 — Gatekeeper and the hardware auth-token chain

> **Difficulty:** intermediate
> **Time:** 60–120 minutes (includes deliberate waiting — the throttle is the point)
> **Needs root:** **no**
> **Needs an installed app:** **no** (Part E is optional and does)
> **Needs a device you are allowed to change the lock screen on:** **yes** — read the warning below

---

## Objective

Follow a PIN from the moment a human types it to the moment a chip permits or refuses a
cryptographic operation, and prove each link by observation rather than by reading about it.

By the end you will have:

- located Gatekeeper's state on a live device and read the Secure User ID;
- demonstrated that an auth-bound key **cannot exist** without a lock-screen credential;
- deliberately **destroyed** a set of keys by changing the credential, and explained exactly why;
- distinguished per-use binding from a timeout window, by their observable behaviour;
- and articulated precisely which parts of this chain `root` can attack and which it cannot.

---

## Read this before you start

**This lab changes the device's lock-screen credential.** That is not incidental — it is the
experiment. Consequences on a real device:

- **Every auth-bound Keystore key on the device is permanently destroyed.** Not yours: *every app's*.
  Banking apps will ask you to re-enrol. Password managers will ask for the master password again.
  Payment cards may need re-adding.
- On some devices a credential change forces a re-encrypt or a reboot.
- If you forget the new PIN you may factory-reset the device to recover it.

**Do not run Parts C or D on someone else's phone, on your own primary phone, or on any device
holding data you cannot re-create.** Use a spare device or a fully-backed-up test device. Parts A,
B and E are read-only and safe anywhere.

> This warning is itself a lesson. The blast radius of a credential change *is* the security
> property: a credential change revokes everything the old credential authorised, and it does so
> device-wide because the alternative — a credential change that leaves old authorisations standing
> — would let anyone who reaches the settings screen inherit them.

---

## Background you need

Read [README §3.6 and §3.7](../README.md) first. The three sentences that matter:

1. Gatekeeper's stored **password handle is a keyed MAC**, not a password hash. The key `K_gk`
   lives only inside the secure world, so there is nothing to brute-force offline.
2. On success Gatekeeper mints a **hardware auth token** signed with `K_shared` — a key shared only
   between Gatekeeper, the biometric matcher and KeyMint. Nothing under Android has it.
3. Each credential enrolment has a **Secure User ID**. Auth-bound keys carry it. Change the
   credential, the SID changes, and every key carrying the old one is dead forever.

---

## Setup

```bash
# host — identify the device and record it, always
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
export ANDROID_SERIAL=<serial>          # if more than one device is attached
```

Create a log:

```bash
# host
echo "# Lab 02 — $(adb shell getprop ro.product.model | tr -d '\r'), API $(adb shell getprop ro.build.version.sdk | tr -d '\r')" > lab02-results.md
```

---

## Part A — Find Gatekeeper on the device (15 minutes, read-only)

### A.1 — The three processes

```bash
# host
adb shell 'ps -A -o USER,PID,NAME' | grep -i gatekeeper
adb shell lshal | grep -i gatekeeper
adb shell getprop | grep -i gatekeeper
```

Expect something like this (target B, a Qualcomm device):

```
system   715 android.hardware.gatekeeper@1.0-service-qti
system  1582 gatekeeperd
```

and on target A, a MediaTek device:

```
[ro.hardware.gatekeeper]: [beanpod]
system   559 android.hardware.gatekeeper@1.0-service
```

Map what you found onto the architecture:

| What you see | What it is | Which world |
|---|---|---|
| `gatekeeperd` | The framework-facing daemon. Relays Binder calls to the HAL | Normal |
| `android.hardware.gatekeeper@1.0-service*` | The vendor HAL process. Issues the `smc` | Normal |
| *(not visible in `ps` at all)* | The **Gatekeeper trusted application** | **Secure** |
| `ro.hardware.gatekeeper` | Names the vendor's implementation — `beanpod`, `qti`, and so on | — |

**Record which TEE vendor you found.** It determines which published research applies to your
device, and it belongs in any report.

### A.2 — Notice what you cannot reach

```bash
# host
adb shell service list | grep -i gatekeeper
adb shell service check android.service.gatekeeper.IGateKeeperService
```

On target B:

```
19  android.service.gatekeeper.IGateKeeperService: []
Service android.service.gatekeeper.IGateKeeperService: not found
```

The service is **listed** but reports an empty interface, and `service check` says `not found`. The
shell can see that it exists and cannot use it. That is SELinux policy, not a broken device, and it
is worth internalising: *"I could not reach it"* and *"it is not there"* are different findings.

---

## Part B — Read the credential state (15 minutes, read-only)

```bash
# host
adb shell dumpsys lock_settings | head -30 | tee -a lab02-results.md
```

Target B, before any changes:

```
Current lock settings service state:

User State:
  User 0
    SP Handle: db7d9cba3308b20e
    Last changed: 2026-08-12 00:37:44 (a1a02f9d20b4a6ed)
    SID: 0
    Quality: 0
    CredentialType: None
    SeparateChallenge: true
    Metrics: known

Storage:
  User 0 [/data/system_de/0/spblob]:
    16384 db7d9cba3308b20e.secdis
       89 db7d9cba3308b20e.pwd
       72 db7d9cba3308b20e.metrics
      186 db7d9cba3308b20e.spblob
```

### B.1 — Decode every line

| Line | Meaning |
|---|---|
| `SP Handle` | Identifier of the **synthetic password** blob for this user |
| `Last changed` | When the credential last changed. **Every auth-bound key on the device died at this instant** |
| `SID` | The **Secure User ID**. `0` means Gatekeeper holds no password handle: no credential is set |
| `Quality` | The `DevicePolicyManager` password-quality constant. `0` = unspecified |
| `CredentialType` | `None`, `Pin`, `Pattern` or `Password` |
| `SeparateChallenge` | Whether the work profile has its own challenge |
| `spblob` files | The synthetic-password state on disk, owned by `system` |

### B.2 — Why the synthetic password exists

Android does not feed your PIN directly into disk-encryption key derivation. It generates a
high-entropy **synthetic password**, protects *that* with the credential, and derives everything
else from the synthetic password.

The payoff: changing the PIN re-protects one small blob instead of re-encrypting the entire device.
The cost, which is the subject of Part C: the *Gatekeeper enrolment* still changes, so the SID still
changes, so auth-bound keys still die. The synthetic password saves your files. It does not save
your keys, and it was never meant to.

### B.3 — Record your baseline

| Field | Value now |
|---|---|
| `SID` | |
| `CredentialType` | |
| `Quality` | |
| `Last changed` | |
| `SP Handle` | |

---

## Part C — Prove that no credential means no auth-bound key (20 minutes)

### C.1 — With no credential set

If your device currently has `SID: 0` / `CredentialType: None`, run the probe now:

```bash
# host
cd 50-HardwareBackedSecurity
./scripts/probe-security-levels.sh 2>&1 | grep -A2 'auth-bound'
```

Expected:

```
AES-256 auth-bound (per-use)   REFUSED   IllegalStateException: Gatekeeper service not available
                               ^ two possible causes  (a) no lock-screen credential is set …
```

### C.2 — Set a credential

On a device you are permitted to change (see the warning at the top):

Settings → Security → Screen lock → PIN → set `135790`.

Then:

```bash
# host
adb shell dumpsys lock_settings | head -15 | tee -a lab02-results.md
```

The `SID` should now be **non-zero** and `CredentialType` should read `Pin`. Record the SID — this
number is the identity every auth-bound key you create from now on will be tied to.

### C.3 — Re-run the probe

```bash
# host
./scripts/probe-security-levels.sh 2>&1 | grep -A2 'auth-bound'
```

If the auth-bound row now reports a security level rather than an exception, you have demonstrated
the dependency directly: **a key that requires user authentication cannot exist until there is an
authentication to require.**

If it still fails, the cause is (b) from [Lab 01 Part C](lab-01-measure-every-key-type.md) — the
shell cannot reach `IGateKeeperService` on this device — and you must do the rest of this lab with
an installed app instead. Record which it was; do not report an unmeasured result as measured.

### C.4 — Create a key that will die

Leave a key behind on purpose, so Part D has something to kill:

```bash
# host
./scripts/probe-security-levels.sh --keep --prefix lab02_ 2>&1 | tail -5
```

Note the aliases it reports keeping.

---

## Part D — Destroy them on purpose (20 minutes)

### D.1 — Change the credential

Settings → Security → Screen lock → PIN → change to `246810`.

### D.2 — Look at what changed

```bash
# host
adb shell dumpsys lock_settings | head -15
```

| Field | Before (Part C) | After |
|---|---|---|
| `SID` | | |
| `Last changed` | | |
| `SP Handle` | | |

**The SID is different.** That single number is the whole mechanism. A new enrolment means a new
Secure User ID, and every key carrying the old one is now unreachable — not "hidden", not
"needs re-authentication", but permanently unusable, because no auth token will ever again carry a
matching `userId`.

### D.3 — Try to use the old key

Re-run the probe with the same prefix and observe the auth-bound behaviour, or use an installed app
if the shell path is not available to you. The exception you are looking for is:

```
android.security.keystore.KeyPermanentlyInvalidatedException
```

Write down where you saw it. This exception is **evidence the binding is real** — it is the single
cleanest positive result available in this whole area, and it needs no tooling.

### D.4 — The test this gives you, for free, forever

You have just performed the most useful non-root test in the chapter:

| Observation after a credential change | Conclusion |
|---|---|
| The app's protected feature breaks, or asks you to set it up again | **The key was genuinely auth-bound.** Correct behaviour |
| The protected feature keeps working exactly as before | **The key was never bound.** The "biometric protection" is a UI check with no cryptographic backing |

That second row is a Medium-to-High finding in most applications, and you established it with a
settings screen and no instrumentation at all. Compare the effort with the equivalent Frida work.

### D.5 — Clean up

```bash
# host
./scripts/probe-security-levels.sh --prefix lab02_ >/dev/null   # runs without --keep, deletes them
```

And return the device's lock screen to whatever the owner had before, if it was not yours to change.

---

## Part E — Observe the throttle (20 minutes, patience required)

> **Do this only on a spare device.** Repeated failures escalate real lockouts, and on a
> device-policy-managed device enough failures can trigger a **wipe**. Never do this on a device you
> did not set up yourself, and never with device admin enabled.

### E.1 — Fail deliberately

At the lock screen, enter the wrong PIN five times. Then observe.

| Consecutive failures | Typical behaviour (vendors tune this) |
|---|---|
| 1–4 | No delay |
| 5–9 | ~30 seconds |
| 10–29 | 30 seconds, escalating |
| 30+ | Doubling, up to a long cap |

### E.2 — Test whether the throttle is real

While it is counting down, try these and record what happens:

| Attempt | Expectation | Why |
|---|---|---|
| Wait it out and enter the **correct** PIN | Works | The throttle is a delay, not a lockout |
| **Reboot** the device and try immediately | Still throttled (or throttled again quickly) | The failure record is persisted in, or bound to, secure state |
| Change the system clock forward | No effect on the retry timeout | The TA uses a **secure** timer, not the normal world's clock |
| `adb shell` reads of `/data/system/locksettings.db` | Not readable as shell | Framework-side state, and not the authoritative counter anyway |

### E.3 — The point of the exercise

Ten thousand candidates is nothing for a computer. What makes a four-digit PIN survivable is that
**you cannot ask the question quickly, and you cannot take the question somewhere else to ask it**.

The second half is the important one. There is no offline attack because there is nothing to attack
offline: the stored handle is `HMAC(K_gk, salt ‖ SID ‖ password)` and `K_gk` never leaves the secure
world. Copy the handle to a cluster of GPUs and it is a random string. That is the difference
between a keyed MAC and a password hash, and it is why the entire lock-screen security model rests
on a piece of hardware rather than on the choice of hash function.

### E.4 — Where a vendor could get this wrong

Reading [README §4.2](../README.md), the Gatekeeper reference implementation delegates four things
to the vendor. Two of them decide whether any of the above is true:

| Hook | If a vendor implements it badly |
|---|---|
| `GetMillisecondsSinceBoot()` | Wired to a normal-world clock ⇒ the throttle can be fast-forwarded ⇒ offline-speed guessing |
| `GetFailureRecord` / `WriteFailureRecord` with `secure=false` | The counter can be rolled back by restoring storage ⇒ unlimited attempts |

Neither is visible from Android, and neither is something an app assessment can test. Both are
legitimate targets for a firmware or vendor audit, and both are the right *kind* of thing to raise
as a risk rather than a finding when you cannot test it.

---

## Part F — Reason precisely about what root can do (15 minutes, no device needed)

Fill this in from memory, then check it against [README §3.7.2](../README.md). Getting this table
right is the difference between a report that is taken seriously and one that is not.

| Action | Can `root` do it? | Why |
|---|---|---|
| Read a TEE-backed key's material | | |
| Use a key that has no auth binding | | |
| Use a key with `AUTH_TIMEOUT=300` within 300 s of an unlock | | |
| Use a key with per-use binding, with no authentication | | |
| Mint a new hardware auth token | | |
| Replay a token it captured | | |
| Change a token's SID or timestamp | | |
| Make `BiometricPrompt` report success | | |
| Make KeyMint ignore `Tag::USER_SECURE_ID` | | |
| Rewrite `ro.boot.verifiedbootstate` | | |
| Change `rootOfTrust` inside an attestation | | |
| Reset the Gatekeeper failure counter by deleting a file | | |

<details>
<summary>Answers</summary>

| Action | Root? | Why |
|---|---|---|
| Read a TEE-backed key's material | **No** | The bytes never exist in normal-world memory; the blob is ciphertext under a HUK-derived key |
| Use a key with no auth binding | **Yes** | Inject into the owning app and call it. This is *use*, not extraction |
| Use a key with `AUTH_TIMEOUT=300` inside the window | **Yes** | That is what a window means. This is why the timeout value is the control worth arguing about |
| Use a per-use-bound key with no authentication | **No** | The token must carry this operation's handle as its challenge |
| Mint a token | **No** | `K_shared` is inside the secure world |
| Replay a captured token | **Yes, within its window** | Nothing binds a timeout-form token to a caller |
| Change a token's SID or timestamp | **No** | The HMAC covers every field |
| Make `BiometricPrompt` report success | **Yes** | That result is a callback in an attacker-controlled process — which is exactly why an unbound prompt is worthless |
| Make KeyMint ignore `USER_SECURE_ID` | **No** | The check runs on the far side of the `smc` |
| Rewrite `ro.boot.verifiedbootstate` | **Yes** | Ordinary normal-world property. Measured `green` on a rooted device |
| Change `rootOfTrust` in an attestation | **No** | Latched at boot inside the TEE, and covered by the attestation signature |
| Reset the failure counter by deleting a file | **No** (framework counter yes, TA counter no) | Which is why the correct PIN is still refused after you "clear" the lockout |

</details>

---

## Success criteria

- [ ] You can name the **Gatekeeper HAL process and the TEE vendor** on your device.
- [ ] You read the **SID** before and after a credential change and recorded both values.
- [ ] You demonstrated that an auth-bound key **cannot be created** with no credential, *or*
      explained precisely why your test setup could not demonstrate it.
- [ ] You produced a `KeyPermanentlyInvalidatedException`, or observed the app-level equivalent,
      and can explain it in one sentence without using the word "expired".
- [ ] You can state, without notes, why the stored handle cannot be brute-forced offline.
- [ ] You completed Part F's table correctly.
- [ ] You returned the device's lock screen to its original state.

---

## Hints

<details>
<summary>Hint 1 — dumpsys lock_settings prints nothing</summary>

Some OEM builds restrict it. Try:

```bash
adb shell dumpsys lock_settings --help
adb shell dumpsys | grep -i lock_settings
```

If it is genuinely unavailable, `SID` can also be inferred behaviourally: create an auth-bound key,
change the credential, and see whether the key survives. Slower, but it answers the same question.
</details>

<details>
<summary>Hint 2 — the SID did not change after I changed the PIN</summary>

Check that the credential actually changed type or value, and that `Last changed` moved. Some
devices treat "set the same PIN again" as a no-op. Also confirm you are reading the right user —
work profiles are separate users with separate SIDs.
</details>

<details>
<summary>Hint 3 — I want to see the auth token itself</summary>

You cannot, and that is the point. The token is minted inside the secure world and delivered to
KeyMint through `keystore2`. There is no supported way to read one, and if there were, reading it
would not help — you cannot alter it without invalidating its HMAC, and you cannot mint another.

What you *can* observe is its effect: the same key operation succeeding immediately after
authentication and failing before it, with `UserNotAuthenticatedException` in between.
</details>

<details>
<summary>Hint 4 — is a 30-second AUTH_TIMEOUT a finding?</summary>

It depends on what the key does, and the honest answer belongs in the report rather than in a
severity rating alone. For "unlock the notes list" it is a reasonable usability trade. For "sign
this payment" it means that for thirty seconds after the user unlocks their phone for *any* reason,
any code in the process can sign a payment with no prompt. Write the number, write what the key
authorises, and let those two facts sit next to each other.
</details>

---

## Next

- [Lab 03 — Read an attestation offline](lab-03-attestation-offline.md): see `noAuthRequired`,
  `userAuthType` and `authTimeout` as the hardware reports them, and confirm from the outside what
  you established from the inside here.
- [Lab 04 — CTF](lab-04-ctf-the-honest-phone.md).
