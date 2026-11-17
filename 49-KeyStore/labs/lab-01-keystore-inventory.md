# Lab 01 — Keystore Inventory and Profiling

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 49 §3.1–3.8](../README.md#3-deep-internal-working), a rooted device or
emulator with `frida-server` running, `adb`. See [51 — Dynamic Analysis](../../51-DynamicAnalysis/README.md)
for the environment build and [53 — Frida](../../53-Frida/README.md) for Frida itself.

---

## Objective

Enumerate every `AndroidKeyStore` alias an application owns, read back each key's **actual**
properties from `KeyInfo`, and produce the inventory table that belongs in every report where a client
claims to use the Keystore. Then do the part no tool does for you: work out what each key **protects**.

## Why this matters

"We store it in the hardware Keystore" is the most common sentence in a mobile security questionnaire,
and on its own it means almost nothing. It does not say which keys exist, what algorithm and mode they
use, whether they are authentication-bound, whether they are actually in hardware on *this* device, or
whether the value they protect also exists in plaintext three directories away.

This lab turns that sentence into a table of facts.

> **Mental Model**
> `KeyGenParameterSpec` is what the app **asked for**. `KeyInfo` is what the device **gave it**. They
> differ on real hardware more often than anyone expects — a StrongBox request silently downgraded, or
> no hardware request at all on a device that then produced a software key. You cannot audit key
> handling by reading source code; you have to read the key back on the target's own hardware.

> **Definition — alias**
> The string handle under which a key is stored. It is the app's only reference to the key: there is no
> API that returns key material, and `getEncoded()` on an `AndroidKeyStore` key returns `null`.

---

## Setup

```bash
# host
adb devices
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.type
```

Record all four. Keystore behaviour is version-dependent and hardware-dependent, and a finding without
the device it came from is not reproducible.

Check what the device can do at all — this needs no root and takes five seconds:

```bash
# host
adb shell pm list features | grep -Ei 'hardware_keystore|strongbox|keystore'
adb shell getprop | grep -Ei 'keystore|keymaster|keymint|strongbox'
adb shell 'lshal 2>/dev/null | grep -i keymint'
adb shell 'service list | grep -i keystore'
```

Start `frida-server` and pick a target:

```bash
# adb shell as root
/data/local/tmp/frida-server &
```

```bash
# host
frida-ps -Ua | head -30
```

Use a real app you are authorised to test, or build the correct implementation from
[`../examples/05-secure-token-store.kt`](../examples/05-secure-token-store.kt) so you know the ground
truth while learning the tooling.

---

## Steps

### Step 1 — Establish what the device is capable of

```bash
# host
adb shell pm list features | grep -i hardware_keystore
# android.hardware.hardware_keystore=100
adb shell pm list features | grep -i strongbox
# android.hardware.strongbox_keystore=100   (absent on most devices)
```

**Question 1.** `pm list features` reports a *feature version* number. What does that number tell you,
and why is confirming this before you start testing worth the five seconds? What would you conclude if
an app claims StrongBox protection and this command shows no `strongbox_keystore` feature?

### Step 2 — Enumerate the aliases

```bash
# host
frida -U -f com.target.app -l ../scripts/enumerate-keystore.js
```

The script runs `ks.list()` automatically at startup. If it prints nothing, that is a result, not a
failure — see Question 2.

```
ks.list()          # re-run after exercising the app
ks.table()         # markdown table for the report
```

**Question 2.** The inventory is empty. There are exactly two explanations and they lead to completely
different findings. Name both, and say which single command distinguishes them.

### Step 3 — Make the app create its keys

Keys are frequently created lazily — on first login, on enabling biometrics, on opening a protected
screen. A hook installed at spawn and left running for a full session catches things a single screen
never will.

```bash
# host — in a second terminal, catch creation as it happens
frida -U -n com.target.app -l ../scripts/hook-keygenparameterspec.js
```

Now exercise the app fully: first launch, register or log in, enable every security feature it offers,
open every screen that handles data. Then re-run `ks.list()`.

**Question 3.** The builder hook reports options that were **never called**, listing their defaults.
Why is that more useful than reporting only the options that *were* called? Give a concrete example of
a finding you can only detect this way.

### Step 4 — Profile every key

For each alias:

```
ks.one("db_key_v2")
```

Fill in a row per alias:

| Alias | Alg | Size | Purposes | Block/pad/digest | Auth req | Timeout | Auth type | Invalidated by enrolment | Sec level | Origin |
|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | |

**Question 4.** One key reports `securityLevel = 0` (`SECURITY_LEVEL_SOFTWARE`). The app's marketing
and its privacy policy both say "hardware-backed encryption". Is that a finding? What must you check
before writing it up, and how would you phrase it so a developer cannot dismiss it?

**Question 5.** Another key reports `origin = IMPORTED`. What does that tell you, and what is your very
next investigative step?

### Step 5 — Distinguish per-use binding from a time window

This is the subtlest and most consequential distinction in the chapter, and it is a single number.

```
ks.one("bio_key")
```

Look at `authValidityDurationSeconds`.

| Value | Meaning |
|---|---|
| `-1` or `0` | **Per-use.** The authorisation is tied to one operation handle via a `CryptoObject` |
| any positive `N` | An **N-second window** after *any* authentication, including an unrelated device unlock |

**Question 6.** A key reports `isUserAuthenticationRequired = true` and
`authValidityDurationSeconds = 30`. Write the one-sentence description of that key's real security
property, as you would put it in a report. Then say what an attacker with code execution in the process
has to do to use it — and note how little that is.

### Step 6 — Prove non-extractability, once, so you never doubt it again

```
ks.proveHandle("db_key_v2")
```

**Question 7.** `getEncoded()` returned `null`. State precisely what that proves and — more
importantly — what it does **not** prove. Why is this the fastest single diagnostic in the chapter?

### Step 7 — Catch the keys that never reach the Keystore

The inventory only shows keys that *are* in the Keystore. The most common real finding is a key that
never went near it.

```bash
# host
frida -U -f com.target.app -l ../scripts/hook-secretkeyspec.js
```

Exercise the app again, fully.

```
sks.summary()
sks.heap()
```

**Question 8.** The hook fires and prints 16 bytes with an entropy of 3.1 bits/byte. What does the low
entropy suggest? What are the three follow-up steps, in order, before this becomes a finding?

### Step 8 — Map each key to what it protects

This is the column `ks.table()` cannot fill in, and it is the column that turns an inventory into an
assessment.

```
ks.watch()
```

Then exercise the app and watch which aliases are touched, and when. Cross-reference with the
filesystem:

```bash
# adb shell as root
ls -laR /data/data/com.target.app/
cat /data/data/com.target.app/shared_prefs/*.xml
```

```bash
# host — and where the plaintext usually turns up
adb logcat -d | grep -Ei 'token|bearer|secret|password|key='
```

Complete the table:

| Alias | Protects | Where the ciphertext lives | Does the plaintext exist anywhere else? |
|---|---|---|---|
| | | | |

**Question 9.** One alias is touched by nothing during a full session, and you cannot find any
ciphertext it corresponds to. What have you found, and why is it worth reporting?

**Question 10.** For one alias, the same value appears both as a ciphertext blob in `secure.xml` **and**
in plaintext in `session.xml`. Which finding number is that in §5.2, what is its severity, and why does
the sophistication of the key configuration become irrelevant?

### Step 9 — Check the namespace boundary

```bash
# adb shell
dumpsys package com.target.app | grep -iE 'userId|sharedUser'
pm list packages -U | grep ':10412$'      # substitute the target's UID
```

**Question 11.** The target shares a UID with `com.vendor.updater`. What does that mean for the
Keystore specifically, and what is the finding shape? Does exploiting it require root?

### Step 10 — Without Frida

Not every engagement permits instrumentation. Establish what is still available.

```bash
# adb shell as root
ls -la /data/misc/keystore/
sqlite3 /data/misc/keystore/persistent.sqlite ".tables"
sqlite3 /data/misc/keystore/persistent.sqlite "select id, domain, namespace, alias from keyentry;"
```

**Question 12.** You can read alias names and namespaces out of that database, but not key material.
Why not — and what exactly would you have if you copied the whole file to another device?

---

## Hints

<details>
<summary>Hint 1 — the script reports "Could not load AndroidKeyStore"</summary>

The Keystore is loaded per-process, and if you spawned with `-f` the app may not have finished
starting. Wait for the UI, then call `ks.list()` from the REPL by hand.

If it persists, confirm you are actually in the app's process:

```
Java.perform(function () {
    console.log(Java.use('android.app.ActivityThread').currentProcessName());
});
```

An app with `android:process` components has several processes, and only some of them touch the
Keystore.
</details>

<details>
<summary>Hint 2 — <code>getSecurityLevel()</code> throws</summary>

It is API 31+. On older devices the script falls back to `isInsideSecureHardware()`, which is a
boolean floor rather than a grade: `true` means "not pure software" and tells you nothing about whether
the TEE is strong or minimal.

If you need a finer answer on an older device, generate an attested key and read
`keymasterSecurityLevel` out of the attestation instead — see
[lab 03](lab-03-attestation-analysis.md).
</details>

<details>
<summary>Hint 3 — the app crashes when you attach</summary>

Some apps detect Frida. That is [37 — Root Detection](../../37-RootDetection/README.md) and
[67 — Bypassing Protections](../../67-BypassingProtections/README.md), not this chapter. For now, get
what you can without instrumentation (Step 10), and note in the methodology that anti-instrumentation
was present — that is itself a control worth recording.
</details>

<details>
<summary>Hint 4 — you cannot find where the ciphertext is stored</summary>

Widen the search. Apps put it in `shared_prefs`, in a Room/SQLite database, in a file under `files/`,
in the account manager, or in a WebView's storage. Watch the filesystem while you drive the app:

```bash
# adb shell as root
inotifyd - /data/data/com.target.app/shared_prefs:n
```

or just diff the directory before and after the action.
</details>

<details>
<summary>Hint 5 — the inventory looks fine and you have nothing to report</summary>

Good. Write that up.

A report that says "the application generates a 256-bit AES-GCM key in the trusted execution
environment, binds the refresh-token key to a per-use strong biometric authentication, and stores no
plaintext copy of either credential" is worth a great deal to a client, and it makes your other
findings far more credible. Testers who only ever report breakage give clients no way to distinguish a
control that worked from one nobody tested.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** The number is the Keymaster/KeyMint feature version the device declares — it tells you which
generation of the HAL is present, and therefore which capabilities exist at all. Checking it first is
worth the time because it bounds everything else: if the device declares no `hardware_keystore`
feature, no key on it can be hardware-backed regardless of what the app requests.

If an app claims StrongBox and the device has no `strongbox_keystore` feature, the app is either
falling back silently (Finding 8) or the claim is false. Confirm with `KeyInfo` before writing
it up — and confirm that the *device* you were given may not be the device the claim was made about, which
is a question for the client rather than a finding.

**2.** Either (a) the keys are created lazily and have not been created yet, or (b) the app does not
actually use the Keystore.

The command that distinguishes them is the builder hook:

```bash
frida -U -f com.target.app -l ../scripts/hook-keygenparameterspec.js
```

Exercise the app with it running. If `KeyGenParameterSpec.Builder` fires, it is (a). If it never does,
run `hook-secretkeyspec.js` — the key is almost certainly a raw byte array, which is Finding 1 and is
the most common real mistake in the whole subject.

**3.** Because `setUserAuthenticationRequired`'s default is **`false`**. The most consequential
Keystore misconfiguration is therefore an *absence*, and you cannot grep for a method that was never
called. Reading source, or reading a builder chain in JADX, requires you to notice something that is
not there — which people reliably fail to do.

The concrete example is Finding 4: a key protecting a payment credential with no authentication
binding at all. In the decompiled builder chain there is no line to see. The hook says
"`setUserAuthenticationRequired` NOT SET (default: false — NO auth binding)", which is unmissable.

**4.** Yes, it is a finding, but the phrasing decides whether it survives.

Check first: is this the *only* device you tested on? A key can be TEE-backed on a Pixel and
software-backed on a low-cost device, so the honest statement is device-specific. Check also whether
the app requested hardware at all, and what it does when it cannot get it — the builder hook tells you.

Phrase it as: *"On the tested device (fingerprint X, Android Y, patch Z), the key `alias` reports
`KeyInfo.getSecurityLevel() == SECURITY_LEVEL_SOFTWARE`. The key material is therefore protected only
by the operating system and is recoverable on a rooted device. The application does not read this value
back and consequently cannot distinguish a hardware-backed key from a software one, so its
'hardware-backed encryption' claim is unverified rather than deliberately false."*

That version is hard to dismiss because it states exactly what was observed, on what, and what the app
failed to do.

**5.** It means the key material existed in plaintext, in the application's heap, before it was
imported. So it came from somewhere: a server response, a file, a compiled-in constant, or a
derivation.

The next step is to find that source, because **it is now the weakest link and it is where you
attack**. Run `hook-secretkeyspec.js` with a stack trace, or grep for `KeyStore.setEntry` and
`KeyProtection` in the decompiled source and read backwards from there.

Note also that `IMPORTED` is visible in attestation, so a server that accepts attestations should
reject imported keys for anything claiming device-binding.

**6.** *"The key requires user authentication, but any authentication within the preceding 30
seconds — including an unrelated device unlock — authorises unlimited use of the key by any code in the
application's process, with no prompt."*

What the attacker has to do: wait. The user unlocks their phone for any reason at all, and for the next
thirty seconds the hook can use the key freely. There is no need to defeat the biometric, hook a
callback, or interact with the sensor. That is why the timeout is the whole story and why "the key is
auth-bound" is not a useful sentence on its own.

**7.** It proves that this is a genuine `AndroidKeyStore` key: the material is not in the process, so
no hook, heap scan, or memory dump will produce it. That guarantee holds even against root.

It does **not** prove the key is safe to rely on. The key can still be *used* by any code in the
process. Non-extractability and non-usability are different guarantees, and confusing them is the
central error in this area.

It is the fastest diagnostic because it is one line and unambiguous: `null` means the Keystore, a
non-null byte array means the material is in the heap right now and you should go and find where it
came from.

**8.** Low entropy means the bytes are not randomly generated. 3.1 bits/byte is consistent with ASCII
text, a repeated pattern, or heavy padding — all strong indicators of a hardcoded constant rather than
a generated key. (Treat the number as a hint on a 16-byte sample, not a verdict.)

Three follow-up steps, in order:

1. **Is it constant?** `adb uninstall` then `adb install`, and re-run. Same bytes means hardcoded,
   which is the High-severity case: it works on every installation, needs no device access, and cannot
   be rotated without a new build. Different bytes means per-install, and you must then find what it is
   derived from — and confirm that if it is derived from `ANDROID_ID` or a device identifier, the attacker
   can read that too.
2. **Find it statically**, so the finding does not depend on Frida:
   `grep -rn "<first 8 bytes hex>" out/sources/` and `strings` over `assets/` and `res/raw/`.
3. **Determine what it protects.** The severity is the value of that, not the fact that a key was
   hardcoded.

**9.** An **orphaned key** — created by a previous version of the app and never deleted after a
rotation or a migration.

It is worth reporting for two reasons. It is evidence that the rotation process is incomplete, which
implies the *next* rotation will also leave debris. And orphans are frequently the weakest keys on the
device, precisely because the reason for rotating was usually to strengthen the policy — so the old key
has the old, weaker configuration and is still usable by anything in the process.

**10.** Finding 3 — a Keystore-protected value that also exists in plaintext elsewhere.

It is High, and the sophistication of the key configuration is irrelevant because **the attacker does
not need to attack the key at all**. Everything above it — the hardware backing, the GCM mode, the
per-use biometric binding — is bypassed by reading a different file. Severity comes from the easiest
path to the data, not the hardest.

This is the single most demoralising finding to deliver to a team that did the crypto well, and it is
common, usually as the residue of an incomplete migration.

**11.** Keystore keys are scoped to a **namespace**, and for ordinary apps the namespace is the UID. Two
apps with the same UID share one namespace, so `com.vendor.updater` can list, use and delete every key
belonging to `com.target.app`.

The finding shape: *"The hardened application shares a Unix UID with `com.vendor.updater`, a
less-maintained helper with [an exported component / a weaker attack surface]. Because Keystore keys
are namespaced by UID, compromise of the helper yields the ability to use every one of the target's
Keystore keys, including the credential-store key."*

And no — it requires **no root at all**. That is exactly what makes it valuable: a genuine, non-root,
cross-application key-use finding. See [21 — App Sandbox §3.2](../../21-App-Sandbox/README.md).

**12.** Because the blobs are encrypted under a **hardware-unique key** that lives inside the secure
hardware and never leaves it. The database holds ciphertext and metadata; the decryption key is not in
the file, is not in `/data` at all, and cannot be exported.

If you copied the file to another device you would have a set of inert blobs. The other device's
hardware-unique key is different, so nothing decrypts. You would also gain nothing by editing a blob's
authorization list — for instance to remove `noAuthRequired` — because the authorization list is bound
into the blob's authentication tag, so tampering makes it fail to decrypt rather than granting looser
permissions.

What you *do* get from the file is real and worth having: the alias names, the namespace (UID)
ownership, and the creation ordering. That is enough to build the inventory skeleton on an engagement
where instrumentation is not permitted.

</details>

---

## Success criteria

- [ ] You recorded the device's release, patch level, build type and Keystore feature version
- [ ] You enumerated every alias the app owns, after exercising the app fully
- [ ] You produced the inventory table with algorithm, size, purposes, auth binding, timeout, security
      level and origin for every key
- [ ] You can explain why `KeyGenParameterSpec` and `KeyInfo` are different facts
- [ ] You distinguished per-use binding from a time window, and can state the security consequence of a
      positive timeout in one sentence
- [ ] You demonstrated `getEncoded() == null` and can say precisely what it does and does not prove
- [ ] You ran the `SecretKeySpec` hook and can say whether any key bypasses the Keystore entirely
- [ ] You mapped at least one alias to the specific data it protects
- [ ] You searched for a plaintext copy of every protected value
- [ ] You checked `sharedUserId` and can explain its Keystore consequence
- [ ] You obtained the alias list without Frida, from `persistent.sqlite`
- [ ] Your notes include at least one control that **worked**, phrased as a positive finding
