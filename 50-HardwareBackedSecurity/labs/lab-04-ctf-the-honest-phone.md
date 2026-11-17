# Lab 04 — CTF: The Honest Phone

> **Difficulty:** advanced
> **Time:** 90–150 minutes
> **Needs root:** **no**
> **Needs a device:** **no** — everything runs on your host
> **Needs a network:** **no**
> **Format:** three flags, in order. Each one requires the previous.

---

## The scenario

You have been handed the backend of a mobile banking product two weeks before launch.

At enrolment the Android app generates a key with a server-issued challenge and posts the
attestation chain. The backend verifies it and, if satisfied, binds the device to the account.
Every high-value transaction after that is supposed to be protected by the fact that the account is
tied to one specific, genuine, unmodified phone.

The team is proud of it. They wrote it from the official documentation, the code is clean, the tests
pass, and it has been running in staging for a month against five reference devices without a single
false rejection.

**Five devices. Not one rejection that anybody expected.** That is what you have been asked to look
at.

Your materials:

| File | What it is |
|---|---|
| [`ctf-verifier.py`](ctf-verifier.py) | The backend's verifier, as shipped |
| [`ctf-attestations.json`](ctf-attestations.json) | Five parsed attestations, one per reference device, in the shape [`../scripts/parse-attestation.py`](../scripts/parse-attestation.py) produces with `--json` |
| [`../examples/hardware_posture_policy.py`](../examples/hardware_posture_policy.py) | The same decision, written correctly. Use it — the diff is the point |
| [README §3.9](../README.md), [§5.9](../README.md), and [cheatsheet §6](../cheatsheet.md) | Everything you need to know |

> **The chains are synthetic**, and deliberately so: a real attestation chain identifies the device
> it came from, so this repository ships none. Every signature check in the material is recorded as
> already passed. **All five chains are internally valid.** That is the trap the whole exercise
> turns on.

---

## Rules

1. Do not modify `ctf-attestations.json`. Read it, do not rewrite it.
2. You may modify `ctf-verifier.py` freely — in fact you should, once you know what is wrong.
3. Every flag has the form `CH50{...}`, lower case, hyphen-separated.
4. Answer from the evidence. Every claim you make should be traceable to a field you can point at.

---

## Stage 1 — Which devices does this verifier wrongly accept?

### The task

Run the verifier:

```bash
# host
cd 50-HardwareBackedSecurity/labs
python3 -B ctf-verifier.py
```

It prints a verdict and its reasoning for each of the five devices. Now work out, for each one,
whether that verdict is **correct**.

A device should be accepted only if the *hardware* asserts that:

- the attestation itself was produced in secure hardware;
- the attested key lives in secure hardware;
- the device booted verified, with a locked bootloader;
- the key was generated in the secure hardware, not imported into it;
- the key belongs to **our** application, signed by **our** signing certificate;
- the challenge is one **we** issued, and has not been used before;
- and the patch level meets our minimum.

### The flag

Take the devices that the verifier **accepts but should not**, in alphabetical order, joined with
hyphens:

```
CH50{<device>-<device>-...}
```

For example, if it wrongly accepted only `device-zulu`, the flag would be `CH50{zulu}` — use the
short name, without the `device-` prefix.

### Working method

Do not read the JSON by eye first; that is how you miss things. Run the correct policy over each
device and compare:

```bash
# host
for d in device-alpha device-bravo device-charlie device-delta device-echo; do
  python3 -B -c "import json,sys; print(json.dumps(json.load(open('ctf-attestations.json'))['$d']))" > /tmp/one.json
  echo "== $d"
  python3 -B ../examples/hardware_posture_policy.py /tmp/one.json \
      --expect-package com.bank.example \
      --expect-signer b1946ac92492d2347c6235b4d2611184a1e0b0bd06d8a1e8c1e0b0bd06d8a1e8 \
      --min-patch 202401 \
      --trusted-root-spki feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae
done
```

(The package name, signer digest and minimum patch level are the constants at the top of
`ctf-verifier.py`. The root SPKI digest is the one this chapter measured from a real device with a
genuine Google-rooted chain — see [README §3.9.2](../README.md). Taking those four values from the
system under test is exactly what you would do on a real engagement.)

Then put the two sets of verdicts side by side. Where they disagree, find out why.

<details>
<summary>Hint 1.1 — where to look first</summary>

For each device, ask the single question this chapter keeps returning to: **which list did that
field come from?** Print the two lists separately rather than letting anything merge them:

```bash
python3 -B -c "
import json
d = json.load(open('ctf-attestations.json'))
for name, doc in d.items():
    if name == '_README': continue
    a = doc['attestation']
    print(name, '| level:', a['attestationSecurityLevel'],
          '| hw fields:', len(a['hardwareEnforced']),
          '| sw fields:', len(a['softwareEnforced']))
"
```

One of the five should stop you immediately.
</details>

<details>
<summary>Hint 1.2 — one device is not what its chain claims to be</summary>

Look at the last certificate in each chain. Two distinct roots appear across the five devices. One
of them is the Google hardware attestation root that a real Qualcomm device produced when this
chapter was written. The other one is not a hardware root at all, and its name says so out loud.
</details>

<details>
<summary>Hint 1.3 — one device's challenge is not a challenge</summary>

The parser records the challenge as hex *and* as ASCII, specifically so that this is impossible to
miss. Print `attestationChallengeAscii` for all five.
</details>

<details>
<summary>Hint 1.4 — one device is the right hardware running the wrong app</summary>

Everything the hardware asserts about it is impeccable. Read `attestationApplicationId` — and then
read `ctf-verifier.py` again and ask where it checks that field.
</details>

<details>
<summary>Stage 1 answer</summary>

**`CH50{bravo-delta-echo}`**

| Device | Verifier says | Correct verdict | Why |
|---|---|---|---|
| `device-alpha` | ACCEPTED | **ACCEPTED** | StrongBox attestation, StrongBox key, Verified and locked, `origin=GENERATED` hardware-enforced, auth-bound with no `authTimeout` (per-use), our package and our signer, a random challenge we issued, patch 202508. Genuinely fine |
| `device-bravo` | ACCEPTED | **REJECT** | `attestationSecurityLevel: Software`, `hardwareEnforced` is **empty**, root is `O=Google Test LLC, CN=Droid Unregistered Device CA`. Every "good" value — including `verifiedBootState: Verified` and `deviceLocked: true` — is in the **software** list, supplied by the software being checked. An emulator, and a hostile one |
| `device-charlie` | REJECTED | **REJECT** | Correctly rejected, and for the right reason: hardware-enforced `verifiedBootState: Unverified`, `deviceLocked: false`, all-zero `verifiedBootKey`. A rooted device. (It would also fail the patch minimum at 202112.) This is the one verdict the verifier gets right by accident of the field being in the hardware list anyway |
| `device-delta` | ACCEPTED | **REJECT** | Two independent reasons. The challenge is the ASCII string `attestation-challenge-v1` — a constant, so the attestation is replayable forever and the server's own issued-nonce list does not contain it. And `origin: IMPORTED` means the key material existed outside the secure hardware, so no device-binding claim about it survives |
| `device-echo` | ACCEPTED | **REJECT** | Perfect hardware posture — and `attestationApplicationId` names `com.bank.example.clone` with signer digest `deadbeef…`. A repackaged application on a genuine, verified device produces an entirely valid attestation. Also note `authTimeout: 300`, a five-minute window on a key that authorises transactions |

</details>

---

## Stage 2 — Name the bugs

### The task

You now know *which* devices get through. Find *why*. There are **four** distinct defects in
`ctf-verifier.py`. Each one is a few characters; each one is a pattern you will meet in production.

For each, note the line and write one sentence explaining what an attacker gains.

### The flag

Name the four bugs with these tokens, in the order they occur in `verify()` reading top to bottom:

| Bug | Token |
|---|---|
| The two authorisation lists are merged into one dictionary | `merge` |
| `attestationSecurityLevel` is never checked | `seclevel` |
| The challenge is checked for presence but never matched against what the server issued | `challenge` |
| `attestationApplicationId` is never checked at all | `appid` |

```
CH50{<token>-<token>-<token>-<token>}
```

<details>
<summary>Hint 2.1 — the merge is one line and it looks like tidy code</summary>

```python
fields = dict(att.get("softwareEnforced", {}))
fields.update(att.get("hardwareEnforced", {}))
```

Read that carefully and work out which list wins when a field is in **both**, and — more
importantly — what happens when a field is in the software list **only**. Then check which case
`device-bravo` is.
</details>

<details>
<summary>Hint 2.2 — one bug is an absence, not a mistake</summary>

Two of the four bugs are things the code does wrongly. Two are things it never does at all. Grep
for what is missing:

```bash
grep -n "attestationSecurityLevel\|attestationApplicationId\|ISSUED_CHALLENGES" ctf-verifier.py
```

Note where `ISSUED_CHALLENGES` is defined, and where it is *used*.
</details>

<details>
<summary>Stage 2 answer</summary>

**`CH50{merge-seclevel-challenge-appid}`**

**Bug 1 — `merge`** (step 2 of `verify()`).

```python
fields = dict(att.get("softwareEnforced", {}))
fields.update(att.get("hardwareEnforced", {}))
```

The two lists exist precisely because one is trustworthy and one is not. Merging them destroys that
distinction. When the hardware list is empty — as it is on any software-only implementation — every
subsequent lookup silently reads an attacker-supplied value. This is the whole of `device-bravo`.

It is worth noticing *why* this is written: it makes the rest of the function shorter and easier to
read. That is what makes it survive review.

**Bug 2 — `seclevel`.** `attestationSecurityLevel` is never read. The verifier never asks the one
question that decides whether anything else in the extension is evidence: was this statement made by
hardware, or by the software being interrogated? `device-bravo` announces `Software` and is accepted
anyway.

**Bug 3 — `challenge`** (step 6). The code checks the challenge is *non-empty* and stops:

```python
challenge = att.get("attestationChallenge", "")
if not challenge:
    return False, reasons + ["no attestation challenge"]
```

`ISSUED_CHALLENGES` is defined at the top of the file and **never used anywhere**. So the challenge
is neither matched against what the server issued nor consumed, which means every chain is
infinitely replayable and a constant challenge such as `device-delta`'s sails through.

Run `python3 -B ctf-verifier.py --show-issued` and compare against `device-delta`'s challenge: it is
not in the list at all. The server accepted an attestation answering a question it never asked.

**Bug 4 — `appid`.** `attestationApplicationId` is never examined, so nothing ties the key to *our*
application. `device-echo` is a genuine, verified, locked device running `com.bank.example.clone`,
signed with a different certificate — and the backend binds it to a customer account.

</details>

---

## Stage 3 — Fix it, and prove the fix

### The task

Write a corrected verifier. It must accept exactly the devices a correct verifier should accept, and
reject the rest — for the right reasons, stated in its output.

You may either patch `ctf-verifier.py` or write your own; `../examples/hardware_posture_policy.py`
is a working reference, and reading it before you start is not cheating.

Your fixed verifier must:

1. Read `rootOfTrust`, `origin`, `purpose`, `keySize` and the patch level from the
   **hardware-enforced list only**, with no fallback to the software list.
2. Require `attestationSecurityLevel` to be `TrustedEnvironment` or `StrongBox`.
3. Match the challenge against `ISSUED_CHALLENGES` **and remove it**, so that a replay of the same
   chain is rejected on the second attempt.
4. Match `attestationApplicationId` against both `OUR_PACKAGE` and `OUR_SIGNER`.
5. Require `origin == "GENERATED"`.
6. Compare the chain's root against a pinned SPKI digest rather than merely checking that some
   certificate is self-signed.
7. Report, for any device it accepts, whether the key is per-use bound or carries an `authTimeout`
   window — and say how long the window is.

### The flag

Run your fixed verifier over all five devices. The flag names, in alphabetical order, the devices it
accepts:

```
CH50{<device>}
```

### Proof obligations

Your fix is not finished until all four of these hold:

- [ ] Running your verifier twice over the accepted device makes the **second** run reject it, with
      "challenge already used" or equivalent. (If it does not, you matched the challenge but forgot
      to consume it — a bug that is *worse* than not checking at all, because it looks correct.)
- [ ] Changing `device-bravo`'s `verifiedBootState` to `Verified` in a copy of the JSON does **not**
      make your verifier accept it. (If it does, you are still reading the software list.)
- [ ] Changing `device-echo`'s package back to `com.bank.example` but leaving the signer digest as
      `deadbeef…` still rejects it. (Package and signer are two checks, not one.)
- [ ] Your verifier's rejection messages name the field and the list it came from. A verdict without
      a reason is not reviewable, and a security control nobody can review is a decoration.

<details>
<summary>Stage 3 answer</summary>

**`CH50{alpha}`**

`device-alpha` alone. Every other device fails at least one hardware-enforced check:

| Device | First failure a correct verifier hits |
|---|---|
| `bravo` | `attestationSecurityLevel: Software`, and an empty hardware list |
| `charlie` | hardware-enforced `verifiedBootState: Unverified`, `deviceLocked: false` |
| `delta` | challenge not in `ISSUED_CHALLENGES`; also `origin: IMPORTED` |
| `echo` | `attestationApplicationId` names a different package and a different signer |

And the correct reference policy, run with the four constants supplied, produces exactly this
gradation — which is a useful thing to have seen, because it is not a boolean:

```
device-alpha    FULL
device-bravo    MINIMAL
device-charlie  RESTRICTED
device-delta    RESTRICTED
device-echo     MINIMAL
```

</details>

---

## Stage 4 — The write-up (no flag, and the part that matters most)

A CTF flag is worth nothing to a client. Turn what you found into two findings and one non-finding.

### Finding A — write it yourself

The merge bug. Your write-up must contain:

- the exact line of code;
- what an attacker needs to exploit it (be honest: what does it actually cost them?);
- a demonstration — `device-bravo` is your proof of concept;
- the fix as code;
- a severity, with justification.

<details>
<summary>A model answer</summary>

> **Attestation verifier reads authorisation fields from the software-enforced list.**
>
> `ctf-verifier.py` merges the attestation's `softwareEnforced` and `hardwareEnforced` lists into a
> single dictionary before evaluating device state:
>
> ```python
> fields = dict(att.get("softwareEnforced", {}))
> fields.update(att.get("hardwareEnforced", {}))
> ```
>
> The two lists exist because only the second is asserted by secure hardware. On any device with a
> software-only KeyMint implementation — every Android emulator, and any device with a patched
> framework — the hardware-enforced list is **empty** and all fields appear in the software list.
> The verifier therefore evaluates `rootOfTrust.verifiedBootState`, `deviceLocked`, `origin` and
> `osPatchLevel` from values supplied by the software it is attempting to verify.
>
> **Demonstrated** with `device-bravo`, whose attestation announces
> `attestationSecurityLevel: Software`, carries an empty hardware-enforced list, chains to
> `O=Google Test LLC, CN=Droid Unregistered Device CA`, and is nonetheless accepted and bound to an
> account. Every certificate signature in that chain verifies correctly; chain validity is not the
> control that failed.
>
> **Cost to the attacker:** an emulator. No device access, no root on any victim device, no
> cryptographic work.
>
> **Fix:**
>
> ```python
> hw = att["hardwareEnforced"]                    # no merge, no fallback
> if att["attestationSecurityLevel"] not in ("TrustedEnvironment", "StrongBox"):
>     reject("attestation was not produced in secure hardware")
> rot = hw.get("rootOfTrust")
> if rot is None:
>     reject("rootOfTrust is not hardware-enforced")
> ```
>
> **Severity: High.** It defeats the device-binding control entirely, remotely, at negligible cost,
> and the failure is silent — the verifier reports success.

</details>

### Finding B — the replayable challenge

`device-delta`.this one has *two* independent problems (the constant challenge and
`origin: IMPORTED`) and that they have different fixes. Decide whether they are one finding or two,
and be able to defend the choice.

### The non-finding — write this one too

Somewhere in your report there should be a paragraph that says, in effect: *"Only one of the five
reference devices supports StrongBox. This is a property of the devices, not a defect in the
application or the backend, and the backend correctly does not require StrongBox."*

Writing non-findings down is not padding. It is what stops the next reviewer re-raising them, and it
is what demonstrates you understand the difference between a hardware limitation and a security
defect. [README §1.4](../README.md).

---

## Success criteria

- [ ] All three flags.
- [ ] A fixed verifier that satisfies all four proof obligations in Stage 3.
- [ ] You can explain, in one sentence each, why `device-bravo` and `device-echo` are dangerous *in
      completely different ways*.
- [ ] You can state why "every signature verified" is not a security conclusion.
- [ ] Your write-up contains at least one explicit non-finding.

---

## Flags

| Stage | Flag |
|---|---|
| 1 | `CH50{bravo-delta-echo}` |
| 2 | `CH50{merge-seclevel-challenge-appid}` |
| 3 | `CH50{alpha}` |

*(Instructor note: the flags are printed here because this repository is a study resource, not a
scoreboard. Cover this section before handing the lab to someone else. The stage-2 flag is the one
worth reasoning to rather than reading — the four tokens map to four distinct real-world verifier
defects, and a student who can name them from the code has learned the transferable thing.)*

---

## Where to go next

- Re-read [README §5.9](../README.md) — every bounty pattern listed there is one of the bugs you
  just found, in the wild.
- Then [49 — Keystore §3.7.5](../../49-KeyStore/README.md) for the fourteen-step server verification
  this exercise is a compressed version of, and
  [`49-KeyStore/examples/04-verify-attestation.py`](../../49-KeyStore/examples/04-verify-attestation.py)
  for a production-shaped implementation.
- If you have a real device, go back to [Lab 03](lab-03-attestation-offline.md) and run your fixed
  verifier against a chain you produced yourself. Predicting the verdict correctly before you run
  it is the real test.
