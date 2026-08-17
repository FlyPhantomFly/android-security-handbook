# Example 02 — the same question, the same tier, a weak and a strong answer

Three questions. Each is answered twice, **at the same tier**, by two candidates who
know roughly the same facts. The difference between them is not knowledge. It is
shape, provenance and honesty — the three things
[`../scripts/answer-shape-lint.py`](../scripts/answer-shape-lint.py) counts.

Read the weak answer first and try to say what is wrong with it *before* reading the
commentary. If your objection is "it is missing a fact", read it again: in all three
pairs the weak answer contains no false statement.

Lint these with:

```bash
# host — each H2 becomes one graded section
python3 -B ../scripts/answer-shape-lint.py --split --budget 240 02-weak-and-strong-at-the-same-tier.md
```

---

## Q1 WEAK — Senior — "How would you assess an app's root detection?"

I'd run Frida and hook the root check. Usually you use objection — `android root
disable` — and that handles it. If that doesn't work you decompile with jadx, grep for
`su`, find the method that returns a boolean, and hook that to return false. Most apps
check for `/system/bin/su`, `/system/xbin/su`, the Magisk package name and `test-keys`
in `Build.TAGS`. Root detection is always bypassable because it runs on the attacker's
device, so it never really stops anyone. I'd report it as a low-severity finding and
move on.

## Q1 STRONG — Senior — "How would you assess an app's root detection?"

Root detection is a client-side check running inside a process the attacker fully
controls, so the interesting question is never "can it be bypassed" — it can — but "how
much does bypassing it cost, and does the app do anything with the answer that matters".
I assess it in three parts: what the app checks, whether those checks can fire at all
from an app's vantage, and what happens to the verdict.

On what it checks, the published lists are worse than they look. I have measured
`/system/xbin/su` on a rooted Android 15 emulator: the file is there and setuid root, and
`adb shell` sees it — but `/system/xbin` is mode `0750 root:shell`, so an app uid gets
`EACCES` and `File.exists()` returns false. Worse, that binary is not what grants root on
that device; Magisk is, from a different path entirely. So the single most-copied check in
the field returns the wrong answer for the wrong reason, and it returns it on a genuinely
rooted device — the only kind where it could matter. That is a client-side check that is
not merely bypassable but non-functional, which is a different and more interesting
finding.

On vantage, I will not accept a probe verified from `adb shell`. Shell is not an app: on
this device the shell can read properties and traverse directories an app cannot. I run
the check as the app — `run-as`, a purpose-built probe APK, or Frida in-process — or I
label the result as a shell measurement and say so in the report.

On the verdict, I look for the shape rather than the count. If fifty checks collapse into
one boolean, one hook defeats all fifty and the fiftieth check bought nothing. If the app
sends structured evidence to a server and the server decides, the cost to the attacker
goes up substantially, because the decision is evaluated outside the process they control.

Severity: on its own, weak root detection is **Informational to Low** in my reports, and I
say why — the control is not a security boundary and inflating it trains developers to
distrust the report. It becomes material when it is the *only* thing standing between a
rooted device and a payment flow, or when the app claims hardware-backed key protection
that measurement shows it does not have. I would want to check the latter before rating
it, and I would check it with a key attestation rather than by reading a property, because
I have seen `ro.boot.verifiedbootstate` report a healthy state on a device whose own TEE
reported `Unverified` seconds later.

---

## Q2 WEAK — Senior — "How do you detect an emulator?"

There are a lot of good checks. `Build.FINGERPRINT.startsWith("generic")` catches most
emulators, and you can check whether `/dev/qemu_pipe` exists, because that file only
exists under QEMU. Emulators are slower than real hardware, so a timing loop works too —
you run a tight loop and compare against a threshold. Any property with `qemu` in the
name means you are on an emulator. Together those are basically 100% reliable and they are
what every app uses.

## Q2 STRONG — Senior — "How do you detect an emulator?"

Before the checks, the question: "am I on an emulator" and "am I being analysed" are
different questions, and most apps that write the first one wanted the second. Serious
analysis happens on rooted physical phones at least as often as on emulators, so an
emulator check is a poor proxy for the analysis question and a good proxy for fleet-fraud
and bot-farm questions. Which one the app is asking changes what a good answer looks like.

Then the awkward part, which is that I have measured the standard list and most of it is
dead. On a stock Android 15 emulator I read the fingerprint as
`google/sdk_gphone16k_x86_64/emu64xa16k:15/…:userdebug/dev-keys` — it does not start with
`generic`, and neither the brand nor the device contains it. `/dev/qemu_pipe` is `ENOENT`;
the node is `/dev/goldfish_pipe_dprctd` now. The most-copied `isEmulator()` on the
internet is three checks and all three of them return false on a current stock AVD.

Two of them are worse than dead, they are inverted. A retail Xiaomi I tested sets
`qemu.hw.mainkeys` and `ro.kernel.qemu.gles`; the emulator sets neither — so "a property
containing `qemu` means emulator" calls the phone an emulator and the emulator a phone.
And on a benchmark of identical C compiled with the same NDK and run at the same app uid,
the emulator was **1.47 times faster** — 2.398 nanoseconds per iteration against 3.516 on
the physical device. Modern AVDs virtualise on the host CPU; they do not interpret. A
timing check calibrated on "emulators are slow" fires backwards.

What still works is structural rather than value-based, because a value is a string an
attacker edits and a structure is a bill of materials they have to invent. The sensor
population is the clearest: the phone reported 41 sensors from six real silicon vendors,
the emulator 18, all 18 vendored to AOSP. The ABI list is another — an AVD advertising
`x86_64` while an arm64 binary actually runs proves a translation layer from something
with no input to spoof. `ro.kernel.qemu` does still read `1`, so the classic property check
is not dead, only the Java one.

Two caveats I would state without being asked. First, everything above was measured from
`adb shell` unless I say otherwise, and the shell is not the app. I would give the numbers
carefully here, because they are easy to get wrong and I did: on this device an app sees
about 638 properties and the shell about 678 — a gap of roughly forty — while **root** sees
about 1,062. A figure I used to quote had the root number labelled as the shell number, and
that inflated gap makes the shell look useless when it is actually a fair proxy for the app.
Where the gap *is* total is `ro.boottime.*`: 111 properties to root, zero to the shell, zero
to an app — which is exactly the family that looks like a perfect emulator signal from a
privileged prompt and cannot be read by the code that would need it. Second, none of this is
a security control: it runs in the attacker's process, and the honest use of the score is
risk-weighting on the server, not a client-side gate.

---

## Q3 WEAK — Senior — "The app uses BiometricPrompt. Is its authentication secure?"

Yes. It uses `BiometricPrompt`, which is the modern API, and it's backed by hardware
because the fingerprint sensor talks to the TEE. The success callback only fires after
the TEE has matched the fingerprint, so the app knows the user is present. They also use
an Android Keystore key with authentication required, which means the key can't be used
without a biometric. That's the correct pattern and there's nothing to report.

## Q3 STRONG — Senior — "The app uses BiometricPrompt. Is its authentication secure?"

I cannot answer that from the API name, and I would say so before saying anything else.
`BiometricPrompt` has two quite different modes and the weaker one is the default shape
people write.

The weak shape is callback-only: the app calls `authenticate()`, waits for
`onAuthenticationSucceeded`, and then does the sensitive thing. That callback is a Java
method in the app's own process, so its result is one hook away, and nothing
cryptographic depends on it. It proves that *something* told the app a match happened.

The strong shape binds a Keystore key to the authentication, so the sensitive operation
cannot proceed unless a key the TEE controls was unlocked. The distinction is observable
without any reverse engineering, which is what makes it a good first check: `dumpsys
fingerprint` reports `accept` alongside `acceptCrypto`. On a device I tested, `accept` was
3 and `acceptCrypto` was 0 — three successful biometric authentications since boot and not
one of them attached to a key. If `accept` moves during your test and `acceptCrypto` does
not, the app is callback-only and you are done.

Even the strong shape has a parameter people get wrong, and I have measured it. A
time-bound key with a 24-hour validity window encrypted for me with **no authentication at
all** during the window, and a 30-second key went from refused to allowed because an
unrelated process performed a device-credential check — the app never showed a prompt. So
`setUserAuthenticationValidityDurationSeconds` does not mean "the user authenticated to
this app"; it means "some acceptable authentication happened on this device recently".
Per-use authentication is a materially different guarantee from time-bound, and the gap is
larger than the API naming suggests.

So my answer is: I would check `acceptCrypto`, then read how the key was created, and
only then rate it. If it is callback-only on a payment or credential flow I would rate it
**Medium** and be ready to defend that against "but it is on a rooted device only" —
because the failure I actually care about is not the bypass, it is the team believing the
guarantee is stronger than it is, which is an institutional problem that outlives the
finding.

---

## What separates them, in one table

| | Weak | Strong |
|---|---|---|
| Opens with | a tool, or a verdict | the problem, or a refusal to answer yet |
| Provenance | none — every claim equally certain | measured, read, and unknown are distinguished |
| Trust boundary | mentioned as a slogan ("it runs on the attacker's device") and then dropped | used to decide what the finding *is* |
| Absolutes | "always", "never", "100%", "nothing to report" | hedged, with the condition named |
| Severity | asserted, or omitted | rated, with the counter-argument pre-empted |
| Length | short because it stopped early | long because it had more to say, and still ended |

**None of the three weak answers contains a false statement.** Every one of them would be
accepted by a checklist. That is the point: at Senior and above the interviewer is not
checking whether you know the facts, they are checking whether you know what the facts are
*evidence for*.
