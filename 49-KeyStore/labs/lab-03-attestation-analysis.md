# Lab 03 — Read a Key Attestation Certificate

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-keystore-inventory.md), [Chapter 49 §3.7](../README.md#37-key-attestation-in-full),
a device with hardware attestation support, Python 3.8+ with `cryptography` and `asn1crypto`,
`openssl`.

---

## Objective

Generate an attested key on a real device, export the certificate chain, parse the attestation
extension field by field, and then **verify** it the way a server must — pinning the Google root,
checking a fresh challenge, and reading the hardware-enforced authorization list and nothing else.

Then break it four ways, and understand why each break works.

## Why this matters

Attestation is the only mechanism in Android that lets a **server** learn something true about a device
without trusting that device. Every other client-side check — root detection, signature verification,
emulator detection, integrity self-tests — is code the attacker owns, and therefore proves nothing. See
[37 — Root Detection](../../37-RootDetection/README.md).

But attestation's value is entirely conditional on the verifier, and the verifier is on the server. The
client side is fifteen lines and hard to get wrong. Every attestation finding worth writing up is on
the other end of the wire.

> **Definition — key attestation**
> A certificate chain, produced by the device's secure hardware, in which the **leaf** certificate
> contains an X.509 extension (`1.3.6.1.4.1.11129.2.1.17`) describing the attested key's properties and
> the device's boot state. The chain is signed by a factory-provisioned key that software cannot reach,
> and terminates at a root certificate Google publishes.

> **Warning — the `softwareEnforced` trap**
> Every field in the authorization list appears **twice**: once in `softwareEnforced` and once in
> `hardwareEnforced`. The software-enforced copy is asserted by the Android framework, which is on the
> attacker's side of the trust boundary. A verifier that reads `rootOfTrust` or `origin` from it — or
> that merges both lists into one dictionary, which is the usual shape of the bug — is trivially
> defeated. **This is the first thing to check in any verifier review.**

---

## Setup

**Device.** Attestation needs hardware support. Confirm before you start:

```bash
# host
adb shell pm list features | grep -Ei 'hardware_keystore|strongbox'
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.boot.verifiedbootstate      # green / orange / yellow / red
adb shell getprop ro.boot.flash.locked           # 1 = locked
```

> **Pentester's Note**
> A rooted device is convenient for the rest of this repository and *inconvenient* here: unlocking the
> bootloader changes `verifiedBootState` to `Unverified` and `deviceLocked` to `false`, which is
> exactly what you want to *observe* but means you cannot produce a "clean" attestation for comparison.
> Ideally use two devices: one stock and locked, one rooted. The diff between their two attestations is
> the most instructive artefact in this lab.

**Host.**

```bash
# host
python3 -m pip install cryptography asn1crypto
openssl version
```

**Google roots.** Obtain the Google hardware attestation root certificate(s) from Google's own
published location and save them as `google-roots.pem`. Do **not** fetch them at runtime from the
verifier: a verifier that downloads its trust anchor has no trust anchor.

**App.** Build [`../examples/03-key-attestation.java`](../examples/03-key-attestation.java) into a
scratch app.

---

## Steps

### Step 1 — Generate an attested key with a known challenge

```bash
# host — a real server would generate this and store it with a short expiry
python3 -c "import os,binascii; print(binascii.hexlify(os.urandom(32)).decode())"
# 3f9a7c...
```

Feed that challenge to the app and generate the key.

```bash
# host
adb logcat -c
adb shell am start -n com.example.keystorelab/.MainActivity --es challenge 3f9a7c...
adb logcat -s KEYSTORELAB:I
```

**Question 1.** The challenge must come from the server, be freshly generated per request, and be
consumed after one use. Name the specific attack each of those three properties prevents, and say which
of the three is the *only* anti-replay control in the entire mechanism.

### Step 2 — Export the chain

Extract the PEM from the log, or read it directly:

```bash
# host
adb logcat -d -s KEYSTORELAB:I | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > chain.pem
```

Confirm you have something sane:

```bash
# host
grep -c 'BEGIN CERTIFICATE' chain.pem
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -noout
```

**Question 2.** How many certificates are in your chain? On a device with Remote Key Provisioning you
will see more, with short-lived intermediates. If the chain has exactly **one** certificate, what has
happened, and what must a server do about it?

### Step 3 — Read the leaf by hand, once

Do this once with `openssl` before you use any script. You should know what the raw object looks like.

```bash
# host
openssl x509 -in chain.pem -text -noout | head -40
openssl x509 -in chain.pem -text -noout | grep -A5 '1.3.6.1.4.1.11129.2.1.17'
```

**Question 3.** Which certificate in the chain carries the attestation extension, and why is it that
one and not another? What is in the leaf's `Subject` and `Issuer`, and why is the subject useless for
identification?

### Step 4 — Parse every field

```bash
# host
python3 ../examples/04-verify-attestation.py --chain chain.pem --dump
```

Record everything:

| Field | Value |
|---|---|
| `attestationVersion` | |
| `attestationSecurityLevel` | |
| `keymasterVersion` | |
| `keymasterSecurityLevel` | |
| `attestationChallenge` (hex) | |
| `hardwareEnforced.purpose` | |
| `hardwareEnforced.algorithm` / `keySize` / `digest` | |
| `hardwareEnforced.origin` | |
| `hardwareEnforced.noAuthRequired` | |
| `hardwareEnforced.rootOfTrust.verifiedBootState` | |
| `hardwareEnforced.rootOfTrust.deviceLocked` | |
| `hardwareEnforced.rootOfTrust.verifiedBootKey` | |
| `hardwareEnforced.osVersion` / `osPatchLevel` | |
| `hardwareEnforced.attestationApplicationId` | |
| Fields present in `softwareEnforced` | |

**Question 4.** `attestationSecurityLevel` and `keymasterSecurityLevel` are different fields. What does
each one actually describe, and construct a case in which they would differ.

**Question 5.** List every field that appears in **both** lists on your device. For each, say which copy
a verifier must use and what an attacker gains if it uses the other.

### Step 5 — `attestationApplicationId`, the binding nobody checks

```bash
# host — get your app's signing certificate digest
apksigner verify --print-certs app-debug.apk | grep -i 'SHA-256 digest'
```

Compare it with what the attestation reports.

**Question 6.** `attestationApplicationId` lists package names **and** signing-certificate digests, and
it lists them for every package sharing the calling UID. Two questions: why does it list more than one
package, and what exactly can an attacker do if a server verifies everything else but skips this field?

### Step 6 — `rootOfTrust`, the field that says whether to trust the device at all

**Question 7.** Fill in what each `verifiedBootState` value implies about the device in front of you,
and what a server should do:

| `verifiedBootState` | Means | Server action |
|---|---|---|
| `Verified` (0) | | |
| `SelfSigned` (1) | | |
| `Unverified` (2) | | |
| `Failed` (3) | | |

If you have a rooted device, generate a second chain on it and diff:

```bash
# host
python3 ../examples/04-verify-attestation.py --chain chain-rooted.pem --dump > rooted.txt
python3 ../examples/04-verify-attestation.py --chain chain.pem        --dump > stock.txt
diff stock.txt rooted.txt
```

**Question 8.** Which fields changed? Note especially `verifiedBootKey`. What does a *non-default*
`verifiedBootKey` combined with `SelfSigned` tell you, and why is that more informative than
`deviceLocked` alone?

### Step 7 — Verify it properly

Now run the verifier as a server would.

```bash
# host
python3 ../examples/04-verify-attestation.py \
    --chain chain.pem \
    --roots google-roots.pem \
    --challenge 3f9a7c... \
    --package com.example.keystorelab \
    --signer-digest <sha256 of your signing cert> \
    --min-patch 202401
```

**Question 9.** It accepted. Walk the fourteen steps in §3.7.5 and say which of them the tool performed
and which it did not. Which omitted step is the one that would matter most in production, and why is it
not something a library can do for you?

### Step 8 — Break it four ways

Each break corresponds to a real, recurring server-side bug. Do each one, observe what the verifier
does, and explain why the break works.

**Break 1 — replay.** Run the verifier again with the *same* chain but a *different* expected
challenge. Then run it with no `--challenge` at all.

**Break 2 — the wrong list.** Modify a copy of the verifier so that it merges `softwareEnforced` and
`hardwareEnforced` into one dictionary (with software last, so it wins), then re-run against the
rooted device's chain.

**Break 3 — the wrong anchor.** Remove `--roots`. Then supply an *intermediate* from your own chain as
the root and see what happens.

**Break 4 — no app binding.** Drop `--package` and `--signer-digest`, and imagine a repackaged copy of
the app on the same device.

**Question 10.** For each break: what did the verifier do, what would a real server have concluded, and
what does an attacker gain? Rank the four by exploitability.

### Step 9 — Attack the client side, and find that you cannot

**Question 11.** With Frida attached, try to make the device produce an attestation claiming
`verifiedBootState = Verified` on a device where it is not. Try at least: hooking
`getCertificateChain`, hooking `X509Certificate.getExtensionValue`, and substituting a chain captured
from a clean device.

Which of those *does* work, against *which* verifier, and what does that tell you about where
verification must happen?

### Step 10 — The honest limits

**Question 12.** Write the paragraph you would put in a report for a client who has implemented
attestation correctly, explaining what it does **not** protect them against. Cover at minimum: runtime
integrity, devices with no attestation support, the fallback policy, and manufacturer compromise.

---

## Hints

<details>
<summary>Hint 1 — no attestation extension in the leaf</summary>

Either the device has no hardware attestation support, or `setAttestationChallenge` was never called,
or you are looking at the wrong certificate. Check in that order:

```bash
# host
adb shell pm list features | grep hardware_keystore
```

```javascript
// Frida — confirm the app actually requested it
frida -U -f com.example.keystorelab -l ../scripts/hook-keygenparameterspec.js
// look for "setAttestationChallenge = NN bytes"
```

Emulators frequently produce a single self-signed certificate with no extension. That is itself the
answer to Question 2.
</details>

<details>
<summary>Hint 2 — asn1crypto fails on a tag you have never seen</summary>

The tag set grows with every KeyMint version, so a strict schema breaks on new devices — which is a
real production failure mode, not just a lab annoyance: verifiers start rejecting brand-new phones.

`04-verify-attestation.py` parses generically for exactly this reason. If you hit an unknown tag,
look it up in `hardware/interfaces/security/keymint/aidl/.../Tag.aidl` for the AOSP branch matching the
device, rather than in any written table including this chapter's.
</details>

<details>
<summary>Hint 3 — the chain will not verify to the root</summary>

Three usual causes. You have the wrong root file. Your chain does not include an intermediate that the
device expected you to fetch. Or the device is RKP-provisioned and the chain has extra short-lived
intermediates — in which case verifying to the root still works, but pinning an intermediate does not,
which is the point of Break 3.

Inspect the issuer/subject linkage by hand:

```bash
# host
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -noout
```
</details>

<details>
<summary>Hint 4 — you want to see a "bad" attestation but have no rooted device</summary>

An emulator gets you most of the way: emulators typically produce either no attestation at all or a
software-level one, and `attestationSecurityLevel = Software` is the single most important negative
case to have seen.

You can also construct one by hand for parser testing: take your real chain, decode the leaf, flip a
field in `softwareEnforced`, and re-encode. It will not verify — that is the point — but it lets you
confirm your verifier rejects it for the *right reason*, which is a check worth doing.
</details>

<details>
<summary>Hint 5 — you are unsure whether the finding is on the client or the server</summary>

It is on the server. It is essentially always on the server.

Split your testing accordingly. **Client:** confirm the challenge is server-issued and single-use, and
confirm the app does not verify its own attestation locally. **Server:** if you have access, review
which authorization list it reads, whether it pins the root or an intermediate, whether it checks
`attestationApplicationId`, and whether it binds the attested key to the session afterwards. If you do
not have server access, test it as a black box by replaying a captured chain.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.**
- **Server-issued** prevents the client choosing a challenge it has a pre-made attestation for.
- **Fresh per request** prevents an attacker reusing one valid attestation for many sessions.
- **Single-use** prevents replay of a captured attestation.

The single-use freshness property is the **only** anti-replay control in the whole mechanism. Nothing
else in the chain says when it was produced in a way a verifier can bind to *this* request:
`creationDateTime` is a device-asserted timestamp, and certificate validity windows are months long. If
the challenge is constant, never checked, or accepted twice, an attacker captures one chain from a
clean stock device and submits it forever from a rooted one — and every other check in the verifier
passes, because the chain is genuine.

**2.** Typically three or four: leaf, one or two intermediates, and the root (or a chain ending just
below a root you pin separately). On an RKP device expect more, with short-lived intermediates.

A chain of **exactly one** self-signed certificate means the device produced **no attestation**. This is
normal on emulators and on devices without hardware attestation support. The server must treat it as an
unattested device and apply an explicit fallback policy — and *that policy is where the real bug usually
is*, because "allow with a warning" is the commercially convenient answer and is exactly what attackers
use.

**3.** The **leaf**. The extension describes the properties of *the key that was just generated*, and
that key's public half is the leaf's subject public key. Intermediates and the root describe the
attestation-signing hierarchy, not your key.

The leaf's `Subject` is a fixed placeholder (commonly `CN=Android Keystore Key`) and the `Issuer` names
the intermediate. The subject is useless for identification because it is not derived from anything
about your app or device — all the identifying information is in the extension, which is precisely why
a verifier that only looks at the certificate's normal X.509 fields learns nothing.

**4.** `attestationSecurityLevel` describes where the **attestation statement itself** was produced —
that is, how much you should believe anything in the extension. `keymasterSecurityLevel` describes where
the **attested key** lives.

They differ, for example, when a device produces a software-level attestation about a key that the
framework believes is TEE-backed — in which case the whole statement is untrustworthy regardless of
what it says about the key. They can also differ on devices whose StrongBox attests keys held in the
TEE, or during transitional HAL implementations.

The verifier rule: if `attestationSecurityLevel` is `Software`, stop. Nothing else in the extension
means anything, because software the attacker controls asserted it.

**5.** Typically `purpose`, `algorithm`, `keySize`, `digest`, `padding`, `origin`, `rootOfTrust`,
`osVersion`, `osPatchLevel`, `creationDateTime`, `attestationApplicationId` and the auth-related tags
may appear in either list depending on the device and KeyMint version.

A verifier must use the **hardware-enforced** copy, always, without exception. What an attacker gains
from a verifier that reads the software copy:

| Field read from software | Attacker gains |
|---|---|
| `rootOfTrust` | Claim `verifiedBootState = Verified` and `deviceLocked = true` on a rooted device — total defeat |
| `origin` | Claim `GENERATED` for an imported key, defeating device-binding |
| `attestationApplicationId` | Claim to be a different package or a different signer |
| `osPatchLevel` | Claim a current patch level on an unpatched device |

The pathological version, which is common, is a parser that merges both lists into one dictionary. It
does not look like a security decision in the code — it looks like tidy-up — and it removes the entire
distinction.

**6.** It lists more than one package because the attestation is bound to the **UID**, and a UID can be
shared by several packages via `sharedUserId`. The field therefore enumerates every package in that UID
and every signing-certificate digest among them. (This is also a neat cross-reference: if you see more
than one package here, the app shares a UID, which has its own Keystore consequences — see
[21 — App Sandbox §3.2](../../21-App-Sandbox/README.md) and lab 01 question 11.)

If a server skips it, a **repackaged copy of the app on the same device produces an equally valid
attestation**. Everything else passes: the chain is genuine, the boot state is `Verified`, the device is
locked, the key really is in hardware — because the hardware attests the *device*, not which app asked.
The attacker takes the app, modifies it however they like, re-signs it with their own key, installs it
on a clean stock phone, and the server accepts it.

That is why this field exists, and it is the most commonly skipped check in the list.

**7.**

| `verifiedBootState` | Means | Server action |
|---|---|---|
| `Verified` (0) | Boot chain verified against the OEM's key. Stock, unmodified boot image | Accept |
| `SelfSigned` (1) | Boot image verified against a **user-installed** key. Custom ROM, or a rooted device with a custom AVB key | Reject for anything sensitive; at minimum, downgrade privileges and log it |
| `Unverified` (2) | Bootloader unlocked, verification not performed | Reject |
| `Failed` (3) | Verification was attempted and **failed** | Reject, and treat as actively suspicious |

**8.** Expect `verifiedBootState`, `deviceLocked`, `verifiedBootKey` and usually `verifiedBootHash` to
change, plus possibly `osPatchLevel` if the ROMs differ.

A non-default `verifiedBootKey` with `SelfSigned` says: *the device is booting an image signed by a key
that is not the manufacturer's, and the bootloader has been told to trust that key.* That is the
signature of a custom ROM or a rooted device with a custom AVB key installed — someone deliberately
replaced the root of trust with their own.

It is more informative than `deviceLocked` alone because a device can be **locked** and still
`SelfSigned`: the user unlocked it, flashed their own boot image and their own AVB key, and re-locked
it. `deviceLocked = true` on its own would look reassuring. `verifiedBootKey` is what exposes it, which
is why a verifier should check the state *and* the key, not just the lock flag.

**9.** The tool performs steps 1–13 given the right arguments: chain verification to a pinned root,
validity dates, the extension parse, challenge comparison, security level, root of trust from the
hardware list, `attestationApplicationId`, patch level, and the key's policy. It does **not** do step 6
(revocation) unless you supply a status list, and it explicitly does not do **step 14**.

Step 14 — *bind the leaf public key to the account and require it to sign every subsequent request* —
is the one that matters most, and no library can do it for you because it is an **architectural**
decision about the rest of your API, not a parsing step. An application that attests at registration and
then issues bearer tokens has thrown the whole guarantee away: the attestation applies to one moment in
the past, and every request since is authenticated by a copyable string. Verifying the chain perfectly
and then not using the key is the most expensive way to gain nothing.

Revocation matters too, and for a concrete reason: attestation keys **have** been extracted from real
devices. A verifier that skips the status list accepts chains signed by keys that are publicly known to
be compromised.

**10.**

| Break | Verifier did | A real server would have | Attacker gains |
|---|---|---|---|
| 1 — replay | Rejected on mismatch; warned loudly with no `--challenge` | Accepted, if it does not check | **Total.** One captured chain from any clean device authenticates forever from any compromised one |
| 2 — merged lists | Accepted the rooted device | Accepted | **Total.** The attacker's own OS asserts `Verified` and `deviceLocked` |
| 3 — no/wrong anchor | Refused to proceed without a pinned root; a self-supplied intermediate "verifies" a chain the attacker constructed | Accepted a forged chain | **Total** if the anchor is attacker-influenced; a **robustness** failure if merely pinned too low |
| 4 — no app binding | Accepted | Accepted | Repackaged app on a clean device attests successfully |

Exploitability ranking: **2 ≈ 1 > 4 > 3**. Breaks 1 and 2 require nothing but one captured chain or one
rooted device and defeat the mechanism outright. Break 4 requires the attacker to repackage and install
on a clean stock device, which is easy but is one more step. Break 3's pinning-too-low variant is not
exploitable at all — it is a reliability bug that fails closed at an unpredictable future date when
intermediates rotate — but it still belongs in a report.

**11.** All of the client-side attacks work perfectly *against a client-side verifier*, and none of them
work against a server-side one.

- Hooking `getCertificateChain` to return a chain captured from a clean device: succeeds trivially. The
  app has no way to tell.
- Hooking `getExtensionValue` to return forged bytes: succeeds against any app that parses its own
  attestation.
- Substituting a clean chain wholesale and sending it to the server: **succeeds** — unless the server
  checks a fresh, single-use challenge, which is Break 1 again.

What none of them can do is produce a chain that a *correct* server accepts, because forging one
requires signing with the device's factory-provisioned attestation key, which is inside the secure
hardware and is not reachable from the app's process by any of these techniques.

The conclusion: **verification must happen on the server, and the challenge must be fresh.** Those two
properties together are what make the mechanism work; either one missing collapses it. This is also
exactly why an app that verifies its own attestation locally has built an expensive `return true;` — and
why finding that pattern is a legitimate and instructive finding.

**12.** Something close to:

> "Key attestation, as implemented here, gives the server a hardware-asserted statement about the
> device's boot integrity, patch level, and the properties of the key it is being asked to trust. That
> is a genuine control and it is correctly implemented: the challenge is server-issued and single-use,
> the chain is verified to a pinned Google root, and only the hardware-enforced authorization list is
> consulted.
>
> It does not, however, say anything about the application's **runtime integrity**. An attested key on
> a locked, verified-boot device can still be commanded by an attacker who obtains code execution
> inside the application's process; attestation describes the state of the device at key generation, not
> the state of the process at request time. It also cannot help on devices that produce no attestation
> at all — emulators, some low-cost hardware, and devices with incorrect factory provisioning — so the
> **fallback policy for those devices is the effective security boundary**, and it should be reviewed as
> carefully as the verifier itself. Finally, the chain conveys the *manufacturer's* claim and inherits
> any compromise of that manufacturer's provisioning process or trusted execution environment; published
> research has recovered attestation keys from production devices, which is why the revocation status
> list must be fetched and honoured rather than treated as optional."

</details>

---

## Success criteria

- [ ] You confirmed the device supports hardware attestation before starting
- [ ] You generated a key with a fresh, externally supplied challenge and exported the full chain
- [ ] You located the attestation extension by hand with `openssl` at least once
- [ ] You can say why the extension is in the leaf and not elsewhere
- [ ] You recorded every field in the table, from both lists
- [ ] You can explain the difference between `attestationSecurityLevel` and `keymasterSecurityLevel`
- [ ] You listed the fields that appear in both lists and can say what each grants an attacker if read
      from the wrong one
- [ ] You checked `attestationApplicationId` against your own signing certificate digest
- [ ] You can state what each `verifiedBootState` value implies and what a server should do
- [ ] You diffed a stock chain against a rooted one, or explained what would differ
- [ ] You ran the full verifier successfully and identified which of the fourteen steps it omits
- [ ] You performed all four breaks and can rank them by exploitability
- [ ] You demonstrated that client-side verification is defeatable and server-side verification is not
- [ ] You wrote the honest-limits paragraph
