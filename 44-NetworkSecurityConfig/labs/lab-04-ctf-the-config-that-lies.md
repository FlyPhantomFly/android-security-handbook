# Lab 04 — CTF: the config that lies

**Difficulty:** advanced
**Time:** 90 minutes on paper; 3 hours if you build and verify it
**Prerequisites:** labs [01](lab-01-extract-a-real-config.md),
[02](lab-02-make-an-app-trust-your-ca.md) and [03](lab-03-prove-it-on-the-device.md);
[README §3](../README.md#3-deep-internal-working) in full
**Artefacts:** [`ctf-vaultpay-config.xml`](ctf-vaultpay-config.xml),
[`ctf-vaultpay-manifest.xml`](ctf-vaultpay-manifest.xml)

---

## The brief

VaultPay is a payments application. Their security team has just handed you their network security
configuration and a summary of their posture:

> *All application traffic is HTTPS only. We trust the platform certificate authority store and
> nothing else. Our payments API is pinned to our issuing intermediate and to a backup key held
> offline, with an expiry in 2031, so we are covered for the life of the current PKI. Cleartext is
> permitted only for public marketing assets on the CDN and for one third-party analytics endpoint,
> both of which carry no user data. Our debug relaxation is inside `<debug-overrides>` so it cannot
> affect production.*

Every sentence in that paragraph is either false, or true in a way that does not mean what they
think it means.

**Your job:** find all six defects, and produce the flag.

---

## The artefacts

- [`ctf-vaultpay-config.xml`](ctf-vaultpay-config.xml) — the configuration, with the developers' own
  ticket comments preserved. Several comments are wrong.
- [`ctf-vaultpay-manifest.xml`](ctf-vaultpay-manifest.xml) — the manifest. Four attributes in it
  change what the config means and three of them are easy to read past.

Read both before you run anything. This challenge is solvable entirely on paper, and doing it that
way first is the point — the tool is the marking scheme, not the method.

---

## Rules

1. **Reason first, run the tool second.** Write your answers down before running
   [`../scripts/nsc-audit.py`](../scripts/nsc-audit.py). The tool agrees with the answer key; if it
   agrees with you as well, you have learnt something, and if it does not, you have learnt more.
2. **Every answer must name a mechanism**, not a feeling. "This looks risky" is not an answer;
   "`<domain-config>` inherits `cleartextTrafficPermitted` from its enclosing `<domain-config>`, which
   declares `true`" is.
3. **You may build it.** Instructions at the end. Verifying an answer on a device is worth more than
   the flag.

---

## The questions

### Q1 — the base case

For the host **`www.vaultpay.io`**, state:

- which scope applies,
- the effective `cleartextTrafficPermitted`,
- the effective trust anchor sources,
- whether pinning applies.

### Q2 — the nested config

For the host **`img.cdn.vaultpay.io`**, state the same four things.

Then answer the developers' claim directly: *"img.cdn.vaultpay.io serves user profile pictures, which
are not public, so we pin it."* Is that claim true of the shipped configuration? Give the mechanism.

### Q3 — the date

The `<pin-set>` on `img.cdn.vaultpay.io` declares `expiration="2023-02-29"`.

- Is that a valid calendar date?
- What date does the **platform** use? Name the class and the property of it that decides.
- What date does a strict parser report? Why does the difference matter to you?

### Q4 — the pinned API

For the host **`api.vaultpay.io`**, state the four things again.

Then answer the developers' claim: *"api.vaultpay.io is pinned … expiry is 2031 so we are covered."*
Assume you are testing the **release** build, and that you can install a certificate authority into
the device's **user** store and nothing else. Can you read this host's traffic? Give the mechanism,
in one sentence, naming the attribute responsible.

### Q5 — the manifest

The manifest declares `android:usesCleartextTraffic="true"`.

- What is the effective cleartext policy for a host that no `<domain-config>` matches?
- Which one wins, and at what point in the app's lifecycle is that decided?
- Construct, in two lines of XML, the *opposite* trap: a manifest that says `false` and an effective
  policy of `true`.

### Q6 — the debug block

`<debug-overrides>` trusts the user store.

- Is it a finding in the release build described by the manifest? Justify with the exact condition.
- Name the attribute whose default value differs inside `<debug-overrides>` from outside it, state
  both defaults, and say what that difference does to the `api.vaultpay.io` pin-set in a build where
  the block **is** live.

### Q7 — the count

Run the effective-policy table for all five scopes in the document — `<base-config>` plus the four
`<domain-config>` elements, counting the nested one separately.

**How many of the five have an effective `cleartextTrafficPermitted` of `true`?**

### Q8 — severity

Rank the six defects you have found from highest to lowest severity for a payments application, and
justify the top one and the bottom one in a sentence each. There is no single right ordering; there
is a wrong one, which is any ordering that puts the `<debug-overrides>` block above the others.

---

## The flag

```
NSC{<Q7 answer>_<Q3 platform date, yyyy-mm-dd>_<Q4 hostname>}
```

Three fields, all derivable from the questions above. No brute force is possible or intended — either
you read the configuration correctly or you did not.

---

## Marking it yourself

```bash
# host - from labs/
PYTHONIOENCODING=utf-8 python3 -B ../scripts/nsc-audit.py ctf-vaultpay-config.xml \
        --target-sdk 33 --debuggable false
```

The effective-policy table answers Q1, Q2, Q4 and Q7 directly. The findings list answers Q3, Q5 and
Q6. Compare it against what you wrote, line by line.

Try these too, because each one demonstrates a mechanism rather than just a verdict:

```bash
# host - what changes if the release build were debuggable?
python3 -B ../scripts/nsc-audit.py ctf-vaultpay-config.xml --target-sdk 33 --debuggable true

# host - what would this config have meant on an app targeting API 23?
python3 -B ../scripts/nsc-audit.py ctf-vaultpay-config.xml --target-sdk 23 --debuggable false

# host - travel forward past the 2031 expiry
python3 -B ../scripts/nsc-audit.py ctf-vaultpay-config.xml --target-sdk 33 \
        --debuggable false --now 2031-06-01
```

The last one is worth doing properly. It shows you the app's posture in five years' time, which is
the posture it will actually have, because nobody is going to edit this file again.

---

## Building it, if you want to verify on a device

The challenge ships as text XML so that this repository contains no build artefacts. Compiling it is
straightforward and turns every answer above into a measurement.

```bash
# host - drop the artefacts into the lab-02 project
cp ctf-vaultpay-config.xml   <lab02>/app/src/main/res/xml/network_security_config.xml
cp ctf-vaultpay-manifest.xml <lab02>/app/src/main/AndroidManifest.xml
# then restore the <activity> block's real class name if you changed it
```

Adjust `applicationId` and `namespace` in `app/build.gradle.kts` to `com.vaultpay.wallet`, set
`targetSdk = 33`, and build both variants:

```bash
# host
./gradlew assembleDebug assembleRelease
python3 -B ../scripts/nsc-audit.py app/build/outputs/apk/release/app-release-unsigned.apk --xml
```

Install the release build (see lab 02 for the MIUI root-install fallback) and measure:

```bash
# host
frida -U -p $(adb shell pidof com.vaultpay.wallet | tr -d '\r') -l ../scripts/nsc-runtime.js
```

Set `CONFIG.hosts` in the script to:

```javascript
hosts: ['www.vaultpay.io', 'img.cdn.vaultpay.io', 'assets.cdn.vaultpay.io',
        'api.vaultpay.io', 'v2.api.vaultpay.io', 'telemetry-vaultpay.example']
```

Then check the two things a static read can never fully settle:

1. **The real `expirationTime`** the platform stored for the `img.cdn.vaultpay.io` pin-set, in epoch
   milliseconds. Convert it. Does it match your Q3 answer?
2. **The anchor sources** for `api.vaultpay.io`, and whether the user entry carries `[overridePins]`.

> **Verification checkpoint**
> If `nsc-runtime.js` prints a pin-set expiry for `img.cdn.vaultpay.io` that is not
> `2023-03-01T00:00:00` in your device's local time, one of your assumptions about the platform's
> date parsing is wrong, and finding out which is worth more than the flag.

---

## Hints

Read them one at a time, and only when stuck.

<details>
<summary>Hint 1 — Q2</summary>

The nested `<domain-config>` declares a `<pin-set>` and nothing else. What does it declare about
cleartext? What does it declare about trust anchors? Now re-read
[README §3.3](../README.md#3-deep-internal-working) on what happens to a property that is not
declared, and confirm that the resolution walks to the **enclosing `<domain-config>`** before it reaches
`<base-config>`.
</details>

<details>
<summary>Hint 2 — Q3</summary>

2023 is not a leap year. The platform parses this with
`new SimpleDateFormat("yyyy-MM-dd")`. Look up what `Calendar.setLenient(boolean)` defaults to and
what a lenient calendar does with a field that is out of range. It does not throw.
</details>

<details>
<summary>Hint 3 — Q4</summary>

The pin-set is live — its expiry really is in 2031. So the pins are enforced. Now read
`NetworkSecurityTrustManager.isPinningEnforced()` in
[README §3.6](../README.md#3-deep-internal-working) again, and confirm that it has **three** exit
conditions, not one. Then look at the `<certificates>` element next to the pinned domain and read
every one of its attributes.
</details>

<details>
<summary>Hint 4 — Q6</summary>

Two different questions are hiding in Q6. The first is whether the block applies at all, which the
manifest settles. The second is what the block would do if it did apply, and that turns on a default
value that the developer did not write and probably does not know about. See the attribute reference
table in [README §3.2](../README.md#3-deep-internal-working) — one row has two different defaults in
the same cell.
</details>

<details>
<summary>Hint 5 — Q7</summary>

Five scopes: `<base-config>`, `cdn.vaultpay.io`, `img.cdn.vaultpay.io`, `api.vaultpay.io`,
`telemetry-vaultpay.example`. Two of them declare `cleartextTrafficPermitted="true"` explicitly. At
least one more has an effective value of `true` without declaring it. Count effective values, not
declarations — the tool's `NSC-002` finding counts declarations and will give you a different number
on purpose.
</details>

---

## Answer key

Do not read this until you have written your own answers down.

<details>
<summary>Full answers and the flag</summary>

### Q1 — `www.vaultpay.io`

No `<domain-config>` matches. The declared domains are `cdn.vaultpay.io` (with subdomains),
`img.cdn.vaultpay.io` (exact), `api.vaultpay.io` (with subdomains) and
`telemetry-vaultpay.example` (with subdomains). Suffix matching on `www.vaultpay.io` strips to
`vaultpay.io` and then `io`, neither of which is declared.

| | |
|---|---|
| Scope | `<base-config>` |
| Cleartext | **false**, declared |
| Anchors | `system`, declared |
| Pinning | none |

This one is genuinely fine, and saying so is part of the answer.

### Q2 — `img.cdn.vaultpay.io`

Exact match on the **nested** `<domain-config>`.

| | |
|---|---|
| Scope | the nested `<domain-config>` |
| Cleartext | **true** — inherited from the enclosing `<domain-config>` for `cdn.vaultpay.io`, which declares `true` |
| Anchors | `system` — the nested config declares none, the enclosing one declares none, so it falls through to `<base-config>` |
| Pinning | declared, and **not enforced** (see Q3) |

**The developers' claim is false, twice over.** Profile pictures they describe as "not public" travel
over a scope where cleartext is permitted, and the pinning they added to protect them has expired.

The mechanism is per-property inheritance: declaring a `<pin-set>` does not stop
`cleartextTrafficPermitted` being inherited. This is the single most common misreading of the file
format and it is why [README §2.3](../README.md#2-high-level-architecture) compares it to CSS.

### Q3 — the date

- **Not a valid calendar date.** 2023 is not a leap year; February has 28 days.
- The platform uses **2023-03-01**. `XmlConfigSource` parses the attribute with
  `new SimpleDateFormat("yyyy-MM-dd")`, and `SimpleDateFormat` delegates to `java.util.Calendar`,
  which is **lenient by default**: an out-of-range field is carried into the next unit rather than
  rejected. The 29th day of a 28-day February becomes the 1st of March.
- A strict parser reports **invalid** and typically stops. That divergence matters because the strict
  answer ("this config is malformed") and the lenient answer ("this pin-set expired on 1 March 2023")
  lead to completely different findings — and the device uses the lenient one.

`nsc-audit.py` reports this as `NSC-030` and then continues the analysis with the rolled-over date,
which is why it also reports `NSC-014`, the expiry, rather than stopping at "invalid".

### Q4 — `api.vaultpay.io`

| | |
|---|---|
| Scope | the `<domain-config>` for `api.vaultpay.io` |
| Cleartext | **false** — inherited from `<base-config>` |
| Anchors | `system`, and `user` **with `overridePins="true"`** |
| Pinning | declared, expiry 2031, **live** |

**Yes, you can read the traffic, in the release build, with a CA in the user store only.**

The mechanism, in one sentence: the `<domain-config>` trusts `src="user"` outside
`<debug-overrides>`, so a user-installed CA is a valid trust anchor in the release build, and that
same `<certificates>` element carries `overridePins="true"`, so a chain terminating in it is exempt
from the pin-set — `NetworkSecurityTrustManager.isPinningEnforced()` returns false when an anchor in
the validated chain overrides pins, before `checkPins` is ever reached.

The developers' claim — *"expiry is 2031 so we are covered"* — is true about the expiry and
irrelevant. **They wrote the bypass themselves, in the same element, for a legitimate reason** (an
enterprise TLS-inspection appliance), and did not notice that it applies to every user-installed CA
on every device rather than only to the corporate one. The fix is to bundle the corporate CA as
`<certificates src="@raw/corp_ca" overridePins="true"/>` and remove `src="user"` entirely.

This is the highest-severity defect in the file and it is the one that looks most like good practice.

### Q5 — the manifest

- Effective cleartext for an unmatched host: **false**.
- **The config wins.** `ActivityThread.handleBindApplication()` sets the policy from the manifest
  boolean and then calls `NetworkSecurityConfigProvider.install()`, which replaces the whole
  `NetworkSecurityPolicy` object with one backed by the parsed config. The manifest attribute is dead
  from that point. Measured on a real app in
  [README §4.6](../README.md#4-source-code-walkthrough-aosp).
- The opposite trap:

  ```xml
  <application android:usesCleartextTraffic="false" ... >
  ```
  ```xml
  <base-config cleartextTrafficPermitted="true" />
  ```

  A manifest-only checker reports "cleartext denied" and the app permits it everywhere.

`nsc-audit.py` reports the disagreement as `NSC-026` and states which value is effective, which is
the correct thing to put in a report.

### Q6 — the debug block

- **Not a finding.** `<debug-overrides>` is applied if and only if the running application's
  `ApplicationInfo.flags` carries `FLAG_DEBUGGABLE`. The manifest declares
  `android:debuggable="false"`, so the block is parsed and discarded and the platform builds no trust
  anchors from it. `nsc-audit.py` says exactly this as `NSC-010`, at INFO.
- The attribute is **`overridePins`**. Outside `<debug-overrides>` it defaults to `false`; inside it,
  the platform builds the anchors with `overridePins = true` whether or not it is written. In a build
  where the block is live, that means every anchor it contributes — including the whole user store —
  is exempt from **every** pin-set in the document, so `api.vaultpay.io`'s live 2031 pin-set stops
  constraining anything as well. That is why a debuggable release build with a `<debug-overrides>`
  block is a CRITICAL and not a HIGH: it removes pinning as well as adding trust.

### Q7 — the count

| Scope | Effective cleartext | Source |
|---|---|---|
| `<base-config>` | false | declared |
| `cdn.vaultpay.io` (+ subdomains) | **true** | declared |
| `img.cdn.vaultpay.io` | **true** | inherited from the enclosing `<domain-config>` |
| `api.vaultpay.io` (+ subdomains) | false | inherited from `<base-config>` |
| `telemetry-vaultpay.example` (+ subdomains) | **true** | declared |

**Three.**

`nsc-audit.py`'s `NSC-002` finding says "cleartext permitted for 2 specific domain(s)",
because it counts `<domain-config>` elements that *declare* `true`. Two declarations, three effective
scopes. Counting declarations rather than effective values is exactly the mistake the nested config
is built to catch, and the tool's own output is not the answer here — the effective-policy table
above it is.

### Q8 — severity

A defensible ordering for a payments application:

1. **`src="user"` with `overridePins="true"` on the payments API.** Full interception of the
   application's most sensitive traffic, in a release build, with no root and no repackaging, and it
   defeats the control the team believes protects it.
2. **Cleartext permitted on `img.cdn.vaultpay.io`**, which the team believes carries non-public user
   profile images. Plaintext, on a scope they explicitly reasoned about and got wrong.
3. **The expired pin-set** on that same host. It would not have helped anyway given (2), but it
   means the second layer they thought they had has been absent since March 2023.
4. **Global-ish cleartext on `cdn.vaultpay.io` and all its subdomains.** Marketing assets, plus
   whatever else ends up under that name later. Response injection into an asset path is a real
   attack surface.
5. **Cleartext to the analytics endpoint.** Rate it on what the SDK actually sends; name the SDK.
6. **The `<debug-overrides>` block.** Not a finding. Mention it in one line, if at all.

The wrong ordering is any that puts item 6 above any other item, and the reason it is wrong is
[README §3.7](../README.md#3-deep-internal-working).

### The flag

```
NSC{3_2023-03-01_api.vaultpay.io}
```

</details>

---

## Success criteria

- [ ] You produced the flag without reading the answer key.
- [ ] Every answer you wrote names a mechanism — an inheritance rule, a class, an attribute default —
      rather than describing an impression.
- [ ] You correctly identified the one scope in the document that is genuinely fine.
- [ ] You correctly identified the one "finding" that is not one.
- [ ] You can explain why the tool's `NSC-002` count and the correct answer to Q7 differ, and why
      that is not a bug in the tool.
- [ ] If you built it: the runtime dump's `expirationTime` for `img.cdn.vaultpay.io` matched your Q3
      answer, and the `api.vaultpay.io` anchor list showed `UserCertificateSource [overridePins]`.

---

## Where to go next

- [README §5](../README.md#5-security-perspective) — writing each of these up so it survives a
  developer's response.
- Chapter 36 — `api.vaultpay.io`'s pin-set is live for every anchor except the one the developers
  added. Defeating a pin that is genuinely live is a different problem.
- [10-APK-Internals lab 04](../../10-APK-Internals/labs/lab-04-ctf-the-lying-manifest.md) — a CTF
  built on the layer below this one, where the *decoder* is what disagrees rather than the reader.
