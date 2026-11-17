# Lab 03 — Read a key attestation offline, and catch a phone lying about itself

> **Difficulty:** intermediate to advanced
> **Time:** 60–90 minutes
> **Needs root:** **no**
> **Needs an installed app:** **no**
> **Needs a network connection:** **no** — deliberately. Nothing in this lab contacts Google.

---

## Objective

Take a key attestation certificate chain apart by hand and by tool, entirely offline, and finish
able to answer four questions about any chain someone hands you:

1. Is this chain internally valid — is every certificate really signed by the next one?
2. What does the hardware actually assert, and which assertions are *not* the hardware's?
3. Is the device it came from real, emulated, rooted, or lying?
4. Which bug in a verifier would let this chain through when it should not?

The last question is the one that pays. Attestation client code is fifteen lines and hard to get
wrong. **The exploitable bug is almost always in the verifier.**

---

## Background

Read [README §3.9](../README.md) and [49 §3.7](../../49-KeyStore/README.md) first. The three facts
this lab is built on:

1. The attestation lives in an X.509 extension at OID **`1.3.6.1.4.1.11129.2.1.17`**, in the
   **leaf** certificate, and it was signed inside the secure world.
2. Every authorisation appears in one of two lists: **`hardwareEnforced`** (asserted by the secure
   world) and **`softwareEnforced`** (asserted by Android). Only the first is evidence.
3. A chain can be **cryptographically perfect and completely worthless**. Validity and
   trustworthiness are different questions.

---

## Setup

```bash
# host
cd 50-HardwareBackedSecurity
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk
export ANDROID_SERIAL=<serial>        # if several devices are attached
python3 --version                     # 3.7 or later; no third-party modules needed
```

---

## Part A — Produce a chain from your own device (15 minutes)

```bash
# host
./scripts/probe-security-levels.sh --attest \
  | sed -n '/BEGIN CHAIN/,/END CHAIN/p' > chain.pem
grep -c 'BEGIN CERTIFICATE' chain.pem
```

You should have three to five certificates. The probe generated an EC P-256 key with a
freshly-random 32-byte challenge and asked for an attestation; the chain you now hold is the
hardware's signed statement about that key.

> **Handle this file with a little care.** It contains no private key material — certificates are
> public — but it does contain your device's boot state, patch levels and attestation-key serial
> numbers. It identifies the device. Do not commit it to a repository and do not paste it into a
> public issue tracker.

### A.1 — Look at it raw first

Before running any parser, look at the structure with tools you already trust. If `openssl` is
available:

```bash
# host
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -noout
```

If it is not, that is fine — the whole point of this lab is that you do not need it.

---

## Part B — Parse it offline (20 minutes)

```bash
# host
python3 -B ./scripts/parse-attestation.py chain.pem | tee lab03-results.txt
```

### B.1 — The chain section

For each certificate you get subject, issuer, serial, key type, validity and an `spki-sha256`.
Answer these:

| Question | Where to look |
|---|---|
| How many certificates? | the header |
| Which one carries the attestation extension? | `attestation extension: YES` — it should be **index 0**, the leaf |
| What is the leaf's subject? | almost always `CN=Android Keystore Key` |
| Is the last certificate self-signed? | `issuer == subject` |
| What key type is the root? | often RSA-4096 for the Google hardware attestation root |

Target B (a real Qualcomm TEE) produced this root:

```
[3] subject : serialNumber=f92009e853b6b045
    issuer  : serialNumber=f92009e853b6b045
    key     : rsa-4096
    spki-sha256 : feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae
```

Target C (an emulator) produced this one:

```
[2] subject : O=Google Test LLC, CN=Droid Unregistered Device CA
    issuer  : O=Google Test LLC, CN=Droid Unregistered Device CA
```

**Which do you have?**

### B.2 — The signature checks

```
  PASS cert[0] signed by cert[1]   names_match=True
  PASS cert[1] signed by cert[2]   names_match=True
  PASS cert[2] signed by cert[3]   names_match=True
  PASS root cert[3] self-signature   names_match=True
```

Those `PASS` results are real ECDSA and RSA verifications, computed in pure Python with no
libraries. Read `ecdsa_verify` and `rsa_verify` in the script if you want to see the arithmetic;
they are about eighty lines between them.

> **The trap this section exists to teach.** Every certificate signature passing tells you the
> chain is **internally consistent**. It tells you nothing about whether the root is *the right
> root*. An attacker with a laptop can generate a perfectly valid chain rooted at their own CA in
> under a second. That is exactly what the emulator does, and its chain passes every signature
> check too. The parser prints the root's `spki-sha256` and then explicitly refuses to decide for
> you — because that comparison is the one step that cannot be delegated to the artefact you are
> examining.

### B.3 — The attestation itself

Record:

| Field | Your value | What it means |
|---|---|---|
| `attestationVersion` | | 3 = Keymaster era; 100/200/300 = KeyMint 1/2/3 |
| `attestationSecurityLevel` | | **where the statement was made** |
| `keymasterVersion` | | implementation version |
| `keymasterSecurityLevel` | | **where the key lives** |
| `attestationChallenge` | | should be the random 32 bytes the probe generated |
| `uniqueId` | | usually empty for third-party callers |

### B.4 — The two lists, side by side

This is the most important table you will fill in today.

| Field | In `hardwareEnforced`? | In `softwareEnforced`? |
|---|---|---|
| `purpose` | | |
| `algorithm` | | |
| `keySize` | | |
| `ecCurve` | | |
| `origin` | | |
| `rootOfTrust` | | |
| `osVersion` / `osPatchLevel` | | |
| `vendorPatchLevel` / `bootPatchLevel` | | |
| `noAuthRequired` | | |
| `creationDateTime` | | |
| `attestationApplicationId` | | |

On a real TEE device, most of the security-relevant fields are in the **hardware** list and only
`creationDateTime` and `attestationApplicationId` are in the software one. On an emulator the
hardware list is **empty** and everything is in the software one.

If you have access to both a physical device and an emulator, produce both chains and put the
tables next to each other. It is the single clearest way to understand why the merge bug is fatal.

---

## Part C — Catch the phone lying about itself (20 minutes)

This part is most striking on a **rooted** device. On an unrooted device you will get agreement,
which is also a result worth having.

### C.1 — Ask the normal world

```bash
# host
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.veritymode
adb shell getprop ro.boot.flash.locked
```

### C.2 — Ask the hardware

From your Part B output, the hardware-enforced `rootOfTrust`:

```
    rootOfTrust:
      verifiedBootState : ?
      deviceLocked      : ?
      verifiedBootKey   : ?
```

### C.3 — Compare

| Source | Trustworthy? | Says |
|---|---|---|
| `ro.boot.verifiedbootstate` | **No** — a normal-world property, rewritable by any root solution | |
| attestation `rootOfTrust.verifiedBootState` | **Yes** — latched into the TEE by the bootloader before any attacker-controlled code ran, and covered by the attestation signature | |

Measured on target B, a rooted Redmi, seconds apart:

```
$ adb shell getprop ro.boot.verifiedbootstate
green

    rootOfTrust:
      verifiedBootState : Unverified
      deviceLocked      : False
      verifiedBootKey   : 0000000000000000000000000000000000000000000000000000000000000000
```

### C.4 — What this settles

Write out, in your own words, why every one of these is now a defeated control on that device:

- an app that reads `ro.boot.verifiedbootstate` and refuses to run unless it says `green`;
- an app that checks `ro.debuggable` and `ro.secure`;
- an SDK that reads `Build.TAGS` for `test-keys`;
- a server that trusts a client-supplied "device is not rooted" boolean.

Then write out why the attestation is *not* defeated by the same attacker, and be precise. The
answer is not "because it is signed" — it is that the signing key lives on the other side of a
hardware boundary and the boot values were latched before any of the attacker's code existed.

> If your device is not rooted and the two sources agree, record that. Agreement on a clean device
> is exactly what you should expect, and having seen both the agreeing and disagreeing cases is what
> makes the disagreeing one meaningful.

---

## Part D — Find the verifier bug (20 minutes)

Now switch sides. You are reviewing a backend that accepts these chains.

### D.1 — Turn your chain into a decision

```bash
# host
python3 -B ./scripts/parse-attestation.py chain.pem --json > parsed.json
python3 -B ./examples/hardware_posture_policy.py parsed.json
```

Read the reasons. Then run it the way a *correct* deployment would, with the root pinned:

```bash
# host
python3 -B ./examples/hardware_posture_policy.py parsed.json \
    --trusted-root-spki <the spki-sha256 of the root you decided to trust>
```

Note how the tier changes, and confirm that the policy **refuses to invent a trusted root for you** —
without `--trusted-root-spki` it caps the tier and says why.

### D.2 — Write the bug yourself

Here is the merge bug, in four lines of Python. Type it out; do not just read it.

```python
# host — the WRONG way, and the most common one
import json
parsed = json.load(open("parsed.json"))
att = parsed["attestation"]
fields = {**att["softwareEnforced"], **att["hardwareEnforced"]}   # <-- the bug
rot = fields.get("rootOfTrust")
print("verifiedBootState:", rot and rot["verifiedBootState"])
print("origin:", fields.get("origin"))
```

Run it against a chain from a real device: it prints the right answer, because on real hardware
those fields *are* in the hardware list. It looks correct. It passes every test the team wrote.

Now run it against an emulator chain (Part E gives you one if you do not have an emulator). It
prints `verifiedBootState: Unverified` and `origin: GENERATED` — values supplied entirely by the
software the verifier was trying to check. Change `Unverified` to `Verified` in a patched framework
and the verifier accepts a fabricated device state without a single signature failing.

### D.3 — The correct version

```python
# host — the RIGHT way
hw = att["hardwareEnforced"]
rot = hw.get("rootOfTrust")           # hardware list ONLY, no fallback to software
if rot is None:
    reject("rootOfTrust is not hardware-enforced")
if att["attestationSecurityLevel"] not in ("TrustedEnvironment", "StrongBox"):
    reject("attestation was not produced in secure hardware")
if rot["verifiedBootState"] != "Verified" or not rot["deviceLocked"]:
    reject("device is not in a stock, locked, verified state")
```

Four lines, and the difference between a control and a decoration.

### D.4 — The verifier review checklist

Use this on any real backend you get to look at:

| Check | Failure mode |
|---|---|
| Reads `hardwareEnforced` **only** | Merged dict ⇒ an emulator supplies `rootOfTrust` |
| Requires `attestationSecurityLevel` ∈ {TrustedEnvironment, StrongBox} | `Software` accepted ⇒ any emulator passes |
| Pins the **root**, not an intermediate | Breaks under Remote Key Provisioning; the "fix" is usually to stop checking |
| Challenge is server-issued, single-use, and **consumed** | Replay |
| `attestationApplicationId` matched to package **and** signer digest | A repackaged app produces an equally valid attestation |
| `osPatchLevel` compared against a minimum | Stale devices accepted indefinitely |
| Revocation status list fetched and honoured | An extracted attestation key stays valid forever |
| **The attested key is bound to the account and signs every later request** | Attestation becomes a one-off ceremony and the session reverts to a bearer token |

---

## Part E — Compare against a known-emulated chain (15 minutes)

If you have an emulator available:

```bash
# host
export ANDROID_SERIAL=emulator-5554        # your emulator's serial
./scripts/probe-security-levels.sh --attest \
  | sed -n '/BEGIN CHAIN/,/END CHAIN/p' > emu-chain.pem
python3 -B ./scripts/parse-attestation.py emu-chain.pem
```

Expected, and measured on an API 35 image:

```
  attestationSecurityLevel : Software
  keymasterSecurityLevel   : Software

  HARDWARE-ENFORCED (trustworthy)
    (empty)

  SOFTWARE-ENFORCED (asserted by Android, NOT trustworthy)
    purpose  : ['SIGN', 'VERIFY']
    ...
    rootOfTrust:
      verifiedBootState : Unverified
      deviceLocked      : False
    attestationApplicationId:
      package : com.android.shell (version 35)
      signer  : 301aa3cb081134501c45f1422abc66c24224fd5ded5fdc8f17e697176fd866aa
```

### E.1 — Three independent tells

Any one of these identifies an emulated attestation, and you can check all three offline in one
command:

1. `attestationSecurityLevel: Software`
2. `hardwareEnforced` list **empty**
3. Root is `O=Google Test LLC, CN=Droid Unregistered Device CA`

### E.2 — And yet

Run the signature checks on that chain. They all pass. **A worthless attestation is not an invalid
attestation**, and a verifier that only checks validity has checked nothing that matters.

---

## Success criteria

- [ ] You produced a chain from your own device with **no network access** at any point.
- [ ] You can state how many certificates it has and which one carries the extension.
- [ ] You filled in the two-list table in B.4 and can say which fields a verifier may rely on.
- [ ] You recorded `attestationSecurityLevel` and `keymasterSecurityLevel` and can explain why they
      are two different fields.
- [ ] You compared `ro.boot.verifiedbootstate` against the attested `verifiedBootState` and recorded
      whether they agreed.
- [ ] You wrote the merge bug yourself and explained, in one sentence, why it survives testing.
- [ ] You can name three independent tells for an emulated attestation.
- [ ] You can explain why a chain can pass every signature check and still prove nothing.

---

## Hints

<details>
<summary>Hint 1 — the chain is empty or has one certificate</summary>

`getCertificateChain` returns a single self-signed certificate when no attestation was requested. A
`CN=Android Keystore Key` certificate with **no** extension is what the Keystore wraps around every
asymmetric key; it proves nothing at all. Confirm `--attest` was passed and that the probe reported
`CHAIN-LENGTH-N` with N greater than 1.
</details>

<details>
<summary>Hint 2 — the parser reports "no attestation extension in any certificate"</summary>

Either the key was generated without `setAttestationChallenge`, or you fed it the wrong file. Check
that the OID `1.3.6.1.4.1.11129.2.1.17` is present at all:

```bash
python3 -B ./scripts/parse-attestation.py chain.pem --json | grep -i has_attestation
```
</details>

<details>
<summary>Hint 3 — a signature check reports SKIP rather than PASS</summary>

The parser implements ECDSA over P-256 and P-384 and RSA PKCS#1 v1.5. A chain using P-521 or a
PSS-signed certificate reports `SKIP` with the reason attached, rather than silently claiming
success — which is the correct behaviour for an analysis tool. Note it and verify that link another
way.
</details>

<details>
<summary>Hint 4 — why is attestationApplicationId always software-enforced?</summary>

Because KeyMint has no idea what a package name is. That is framework knowledge, so the framework
supplies it. It is still covered by the attestation signature, so a normal-world attacker cannot
edit it after the fact — but a compromised framework could supply a false value at generation time.
Treat it as a strong signal alongside the chain and the challenge, never as the sole binding.
</details>

<details>
<summary>Hint 5 — the challenge looks like readable text</summary>

Then it is almost certainly a constant, and the attestation is replayable forever. The parser prints
the challenge as both hex and ASCII specifically so this is impossible to miss. Confirm it by
attesting twice and comparing: a server-issued nonce differs every time.
</details>

---

## Next

- [Lab 04 — CTF: The Honest Phone](lab-04-ctf-the-honest-phone.md): five chains, one broken
  verifier, and a decision to make about each.
