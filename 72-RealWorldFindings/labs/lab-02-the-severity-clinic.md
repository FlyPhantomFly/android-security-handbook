# Lab 02 — The severity clinic

> **Objective.** Rate **fourteen** real observations and defend every rating. You are scored on the
> reasoning, not the number — and five of the fourteen are correctly **Informational**, which is the
> answer people find hardest to write down.

**Difficulty:** intermediate. This is the lab the chapter exists for.
**Time:** 90 minutes to do honestly. Twenty-five if you pattern-match, and you will score badly.
**Prerequisites:** [Chapter 72 §3.4](../README.md#34-gate-2--is-it-reachable-and-by-whom),
[§3.6](../README.md#36-gate-3--is-there-anything-behind-it),
[§3.7](../README.md#37-where-severity-actually-comes-from).
No device, no APK, no internet. Everything you need is on this page.
**You will produce:** fourteen ratings, each with a four-line justification, scored against a key.

---

## 0. Why this lab exists

Severity is the only part of a mobile assessment that a tool cannot produce and that a client reads
first. It is also the part almost nobody is trained on: you are taught to find things, and then one
day somebody asks you to put a word next to one and you reach for a feeling.

The failure is measurable. This repository has recorded both directions:

| Direction | Measured instance |
|---|---|
| **Over-rating** | 15 of 17 high-confidence leads on a real commercial app were rejected outright — 88% — and *not one of the seventeen* became a High-severity finding | [52](../../52-StaticAnalysis/README.md) |
| **Over-rating** | 132 of 132 high-confidence secret hits against real browser data were false positives | [33](../../33-Storage/README.md) |
| **Under-rating** | The genuinely interesting finding in that same commercial sweep sat at **MEDIUM 0.50** — a tester who worked the HIGH band and stopped would have shipped nothing but the fifteen rejects | [52](../../52-StaticAnalysis/README.md) |
| **Inverted** | Task hijacking by affinity, a staple High on published checklists, was measured *mitigated* on a real device, while the unglamorous attack that still works rates High and a squatted affinity rates INFO | [30](../../30-Activities/README.md) |

That last row is the one to sit with. **A widely-published severity can be exactly backwards**, and
the only defence is that you rated the instance rather than the class.

---

## 1. The rules

### 1.1 The four inputs

Every rating you write must name all four. A rating that cannot is a guess.

| # | Input | The question |
|---|---|---|
| 1 | **Attacker** | Which position from §3.4? Co-installed app, network attacker, hostile device owner, brief physical access, backend? |
| 2 | **Preconditions** | What must be true first, and how plausible is each? |
| 3 | **Gain** | Specifically what data, what state change, whose accounts? |
| 4 | **Population** | How many users, and is it repeatable at scale? |

### 1.2 The scale

Use five bands. The rubric itself belongs to
[80-Appendix §5](../../80-Appendix/README.md#5-severity-cvss-and-business-impact); this lab uses a
deliberately coarse version so that arguments, not gradations, decide the answer.

| Band | Meaning in one sentence |
|---|---|
| **Critical** | A remote or trivially-positioned attacker reaches other users' data or funds |
| **High** | A realistic in-scope attacker reaches this user's sensitive data or takes a meaningful action |
| **Medium** | A realistic attacker gains something real but bounded, or needs a meaningful precondition |
| **Low** | Real weakness, narrow attacker or narrow gain |
| **Informational** | True, worth saying, and no attacker in the threat model gains anything today |

### 1.3 The engagement

**All fourteen observations come from one engagement.** Rate them against *this* threat model, not
against a generic one. This is the whole exercise: the same observation belongs in different bands
under different threat models, and a rating detached from a threat model is meaningless.

> **Engagement brief — "Meridian", a consumer messaging application**
>
> - **Distribution:** public app store, roughly 4 million installs.
> - **Data handled:** message content, contact identifiers, profile photos, a phone number used as
>   the account identifier. No payments. No health or financial data.
> - **Threat model, agreed with the client:**
>   - *In scope:* a malicious co-installed application; a network attacker on a shared or hostile
>     network; a person with brief physical access to an unlocked device.
>   - **Out of scope:** the device owner as an adversary. Meridian sells nothing in-app, enforces no
>     entitlement locally, and has no anti-fraud requirement. The client has stated explicitly that
>     a user rooting their own phone is not a threat they wish to spend on.
>   - *Backend:* **out of scope.** Server-side authorisation was not tested.
> - **Devices:** testing on Android 13 and Android 15, both unrooted for the primary pass, one
>   rooted device used for instrumentation only.

Write the "out of scope: device owner" line on a sticky note. Four of the fourteen observations
exist to see whether you honour it.

---

## 2. The observations

Rate each one. For each, write exactly four lines: **Attacker / Preconditions / Gain / Rating**.
Do not read Part 3 until all fourteen are done.

---

**O-01.** `com.meridian.app.attachments` is an exported `ContentProvider` with no
`android:readPermission` and no `android:permission`. Queried from a purpose-built app declaring
**zero** permissions, `content://com.meridian.app.attachments/files` returns 1,204 rows giving the
absolute path and MIME type of every attachment the user has ever received. A second query using the
returned path via `openFile` returns the file content.

---

**O-02.** Nine Activities in the `feature-settings` module are declared `android:exported="true"`
with no `<intent-filter>` and no permission guard. All nine are internal settings screens. Each
reads only from the app's own preferences and accepts no `Intent` extras. Launching each from a
co-installed app displays the screen.

---

**O-03.** `grep` over the decompiled tree returns 23 strings matching a secret-shaped-value rule. On
inspection: 14 are `sha256/…` constants inside OkHttp's own certificate-pinner *parser* (not
configured pins), 6 are Firebase client identifiers restricted server-side by package name and
signing certificate, 2 are test fixtures inside a bundled analytics SDK, and 1 is a base64 blob that
decodes to a PNG header.

---

**O-04.** The app performs no root detection, no debugger detection and no integrity self-check. On
a rooted device, Frida attaches without resistance and every method is hookable.

---

**O-05.** On a failed token refresh, the app writes the full refresh token to logcat at `WARN`. The
token has a 30-day lifetime and is not revoked on logout — the client discards it locally only.
Android 13 and 15 both prevent one app reading another's log output.

---

**O-06.** `android:allowBackup` is absent from the manifest. `targetSdkVersion` is 34.

---

**O-07.** The app's `WebView` calls `addJavascriptInterface` to expose an object with a method
`getAuthToken()`. The `WebView` loads only `https://meridian.example/help/*`, enforced by a
`shouldOverrideUrlLoading` implementation that checks `uri.getHost().endsWith("meridian.example")`.
`setJavaScriptEnabled(true)` and `setAllowFileAccess(false)`.

---

**O-08.** The same `WebView` as O-07, but the host check is
`uri.getHost().contains("meridian.example")`. An attacker-controlled URL
`https://meridian.example.evil.test/x` satisfies it, and an exported deep-link Activity passes an
arbitrary `https` URL from an `Intent` extra into `loadUrl()` with no validation.

---

**O-09.** The app pins no certificates. It declares no `networkSecurityConfig`, so on
`targetSdkVersion` 34 it trusts the system CA store and not user-installed CAs.

---

**O-10.** A `SharedPreferences` file in the app's private directory contains the user's phone number
and a session identifier in cleartext. File mode is `0600`, owned by the app's uid, inside a
directory with mode `0700`. Reading it requires root.

---

**O-11.** The app sends `GET /v2/conversations/{conversationId}/messages`, where `conversationId`
comes from local state and is modifiable on a rooted device. The backend is out of scope and was not
tested. `conversationId` values are sequential 64-bit integers.

---

**O-12.** An exported `BroadcastReceiver` with `<action android:name="com.meridian.app.SYNC_NOW"/>`
and no permission guard. Sending the broadcast from a co-installed app triggers an immediate full
message sync. There is no rate limit. Repeating it in a loop keeps the radio and CPU active; on a
test device, sustained broadcasting drained 14% of battery in 40 minutes and generated 180 MB of
traffic in that period.

---

**O-13.** The app's own crash reporter uploads the last 200 lines of logcat with each crash report,
to a third-party SDK's endpoint. Combined with O-05, a crash occurring after a failed token refresh
transmits the refresh token to the third party. The third party's data-processing agreement with the
client covers crash data but does not mention credentials.

---

**O-14.** `android:debuggable="true"` in the build obtained from the public app store listing.

---

## 3. The key

Read only after rating all fourteen.

> **How to score.** One point for the band if it matches or is one adjacent, **two further points**
> if your four lines name the same attacker and the same decisive factor as the key. Maximum 42.
> The band is worth less than the reasoning on purpose.

---

### O-01 — **High**

- **Attacker:** malicious co-installed app, zero permissions. Weakest attacker in the model, fully
  in scope.
- **Preconditions:** the user installs the attacker's app. Nothing else.
- **Gain:** every attachment the user has ever received, by content, not just by name.
- **Decisive factor:** all three gates pass with data of obvious value. The `openFile` step is what
  moves this from "a list of filenames" to "the files"; make sure you tested it rather than assuming.

**Common error:** rating Critical. Critical is reserved for reaching *other users'* data or funds.
This reaches *this* user's data from a local attacker.

---

### O-02 — **Low**

- **Attacker:** malicious co-installed app.
- **Preconditions:** installation.
- **Gain:** nothing today. The screens accept no input and read no caller-supplied data.
- **Decisive factor:** Gate 3 fails on present impact, but the *cause* is systemic — nine components
  sharing one module default — so the class will apply to the next component added, which may handle
  input. Rate Low, report as **one finding with nine instances**, and aim the remediation at the
  module template.

**Common errors:** nine separate Mediums (prevalence mistaken for severity, and nine tickets instead
of one fix); or dropping it entirely, which discards the trajectory.

---

### O-03 — **Informational, or not reported at all**

- **Attacker:** none identified.
- **Preconditions:** n/a.
- **Gain:** none. Every one of the 23 was adjudicated and rejected.
- **Decisive factor:** this is a **lead list**, not a finding. The 14 `sha256/` hits are the exact
  false positive [36-CertificatePinning](../../36-CertificatePinning/README.md) documents — the
  constant belongs to OkHttp's own parser, so grepping it "hits on everything", and it is why 12 of
  14 apps show a pinning *surface* while only 4 carry a pin value.

**What to write:** if anything, one line in the methodology noting that 23 candidates were
adjudicated and none survived. That sentence is worth writing because it tells the client the
check was performed.

**Common error:** reporting "hardcoded cryptographic material" at High. That is the shape
[33-Storage](../../33-Storage/README.md) measured at **132 false positives out of 132**.

---

### O-04 — **Informational**

- **Attacker:** the device owner — **explicitly out of scope** for this engagement.
- **Preconditions:** the user roots their own phone.
- **Gain:** access to their own data.
- **Decisive factor:** there is no in-scope attacker. Meridian enforces no local entitlement, so
  nothing is protected by the absent control. This is class **F-12**: a fact about the platform
  reported as a finding about the app.

**Common error:** High. This is the single most common credibility-destroying rating in mobile
reports, because the developer knows it is unactionable and discounts everything else you wrote.

**When it *would* be a finding:** change the brief so Meridian sells a subscription enforced
client-side, and O-04 becomes a Medium — and even then the top remediation is "move the check
server-side", not "add root detection".

---

### O-05 — **Medium**

- **Attacker:** brief physical access to an unlocked device (in scope). Not a co-installed app —
  cross-app log reading has been blocked since API 26.
- **Preconditions:** a failed refresh must have occurred, and the attacker needs the device.
- **Gain:** a 30-day refresh token that survives logout server-side. That is durable account access.
- **Decisive factor:** the **absence of server-side revocation** is what makes this Medium rather
  than Low. A token that died at logout would be a much smaller finding. Rate the composite, and say
  so.

**Common errors:** High, by assuming another app can read the log (measure it — it cannot); or Low,
by treating "logs are local" as the end of the analysis and missing the lifetime.

---

### O-06 — **Not a finding**

- **Decisive factor:** `allowBackup` **absent** is not `allowBackup="true"` as a *finding*; it is
  the platform default, and reporting the default as a misconfiguration is the absent-attribute
  trap from [§3.5](../README.md#35-a-corpus-measurement-of-the-largest-finding-class).

In the reference corpus the attribute was absent on **176 of 243** apps; a checker counting the
default reports **205 of 243**. Before writing this one you must (a) state what the default is at
`targetSdk` 34, (b) establish what is actually in the backup set, and (c) show that `adb backup`
still extracts it on the versions in scope — which is progressively less true on modern releases.

**If you rated it anything at all without doing (b), you rated a manifest attribute rather than a
risk.** The honest version is a hardening note: adopt `dataExtractionRules`, which the reference
corpus found declared by only **5 of 243** packages.

---

### O-07 — **Low**

- **Attacker:** network attacker (in scope) or a malicious co-installed app.
- **Preconditions:** the attacker must get content of their choosing into the `WebView`. The
  `endsWith` check and TLS make that hard.
- **Gain:** `getAuthToken()` if they succeed.
- **Decisive factor:** the bridge is dangerous, and the containment is currently correct. `endsWith`
  on a host is the right shape of check. Rate Low for the fragility — one refactor away from O-08 —
  and say precisely that.

**Common error:** High for "JavaScript interface exposed". The interface is the *capability*; the
finding requires a path to reach it.

---

### O-08 — **High**

- **Attacker:** malicious co-installed app, via the exported deep-link Activity. No network position
  needed.
- **Preconditions:** installation, and one `startActivity` with a crafted `https` URL.
- **Gain:** `getAuthToken()` from attacker-controlled JavaScript — the account.
- **Decisive factor:** `contains()` instead of `endsWith()`. One method call is the entire
  difference between O-07 and O-08, and this is a **chain**: exported deep link + unvalidated
  `loadUrl` + weak host check + bridge. Report it as one finding presenting the chain, and name the
  cheapest link to break — the host check.

**Common errors:** reporting the four links as four findings (guaranteeing two get fixed and the
chain survives); or rating it Critical — it reaches this user's account, not other users'.

---

### O-09 — **Informational**

- **Attacker:** network attacker (in scope).
- **Preconditions:** the attacker must hold a certificate the *system* store trusts.
- **Gain:** traffic interception, if that precondition holds.
- **Decisive factor:** on `targetSdk` 34 the platform default already excludes user-installed CAs.
  Absence of pinning is a **hardening opportunity**, not a vulnerability, unless the threat model
  includes a compromised or coerced public CA — and this brief does not say so.

**Common error:** High for "no certificate pinning". Also worth knowing before you write this class
at all: 12 of 14 apps present a pinning *surface* and only 4 pin, so "the app uses certificate
pinning" is a claim most scanners get wrong in the other direction.

**Careful:** if your test device has a modified system CA store — a `trustusercerts` module
promoting an interception CA into the *system* store — you cannot measure this class at all. Check
`adb shell "mount | grep cacerts"` first. This repository has a device where 139 certificates sit in
a tmpfs-backed system store, and it teaches you the opposite of the truth.

---

### O-10 — **Informational**

- **Attacker:** requires root. Root is **out of scope** here.
- **Preconditions:** root, or a separate vulnerability that yields arbitrary file read.
- **Gain:** a phone number the app already knows and a session identifier.
- **Decisive factor:** the sandbox is intact — `0600` file inside a `0700` directory. "Sensitive
  data stored in SharedPreferences" where the only attacker is root is a **restatement of the
  sandbox**, and it is the single most padded finding in mobile reporting.

**When it *would* rise:** if O-01's provider could reach it, this becomes evidence in that chain
rather than a finding of its own.

---

### O-11 — **Informational, with an explicit testing gap**

- **Attacker:** would be the backend attacker — out of scope.
- **Preconditions:** unknown; server-side authorisation was not tested.
- **Gain:** unknown, potentially other users' messages.
- **Decisive factor:** you do not know, and the only professional output is to say so. Sequential
  identifiers make the *hypothesis* cheap to test, which is exactly the argument for scoping it.

**Both common errors are serious.** Rating it Critical is a fabrication — nobody tried it. Dropping
it silently means the client never learns their most valuable untested surface is reachable from a
client they *did* pay to have tested. The correct output converts an untestable item into a scoping
recommendation: see [§5.4](../README.md#54-the-scope-boundary-that-eats-severity).

---

### O-12 — **Medium**

- **Attacker:** malicious co-installed app, no permissions.
- **Preconditions:** installation.
- **Gain:** no data. A denial-of-service against the user's battery and mobile data allowance, plus
  forced network activity the user did not initiate.
- **Decisive factor:** this is the one where **you measured the impact** — 14% of battery in 40
  minutes, 180 MB — instead of asserting it. That measurement is what makes Medium defensible
  instead of arguable. Resource exhaustion is real but bounded; the user can uninstall the attacker.

**Common errors:** Informational, because "no data was disclosed" (impact is not only
confidentiality); or High, without measuring anything.

**Worth checking:** whether the action name is on the protected-broadcast list.
[29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) measured that `INSTALL_REFERRER`,
`c2dm.intent.RECEIVE` and `PROVIDER_CHANGED` are **not** protected despite being widely trusted, and
that `am broadcast` sends `ordered=true`, so a receiver may behave differently under `am` than in
production.

---

### O-13 — **High**

- **Attacker:** none, in the usual sense — and that is the point.
- **Preconditions:** a crash after a failed token refresh. Ordinary operation, not an attack.
- **Gain:** the user's 30-day, non-revocable refresh token is transmitted to a third party outside
  the agreed processing terms, at whatever rate crashes occur across 4 million installs.
- **Decisive factor:** **population.** O-05 alone needs an attacker with the device. This needs
  nobody: it happens by itself, to some fraction of four million users, continuously. Input 4 of the
  four is doing all the work here, and it is the input testers most often forget.

**Common error:** rating it alongside O-05 as one Medium. They share a cause and have completely
different blast radii. Report O-13 separately and rate it on the population.

---

### O-14 — **Critical — and check it is not yours first**

- **Attacker:** anyone with brief physical access, plus anyone who can reach ADB.
- **Preconditions:** essentially none. `run-as` gives a shell in the app's data directory; a
  debugger attaches to the process.
- **Gain:** everything the app holds, on every one of 4 million installs.
- **Decisive factor:** it is in the **public store build**. That is what makes it Critical rather
  than a build-hygiene note.

**The trap, and it is a real one.** Before you write this, confirm the APK came from the store
listing and not from your own build, your CI, or a helper you installed. In this repository's own
243-package sweep, **exactly one package was `debuggable=true` and it was a locally built test app
belonging to the machine's owner** — the single most alarming-looking hit in the highest-severity
build-hygiene class was the tester's own artefact.

**Also know how `run-as` really behaves**, because misreading it loses genuine findings: a
debuggable *third-party* app succeeds, a debuggable **system** app returns `package not an
application`, and a non-debuggable app returns `package not debuggable`. Reading the first message
as "not debuggable" throws the finding away.

---

## 4. Scoring and what your errors mean

| Score /42 | Reading |
|---|---|
| 34–42 | You are rating instances against a threat model. |
| 24–33 | Sound instincts, inconsistent discipline. Re-read your four lines for the ones you missed — the attacker is usually the line that was vague. |
| 14–23 | You are rating classes, not instances. Work through §3.7's inflation table against each miss. |
| < 14 | Do not rate anything unsupervised yet. Start with the four inputs and refuse to write a band until all four are filled in. |

### Diagnose your own bias

| If you over-rated… | Your bias | The corrective |
|---|---|---|
| O-04, O-10 | Root assumed for free | Root is a *premise*. Is the device owner in the threat model? |
| O-03 | Leads reported as findings | Adjudicate before rating. 132 of 132 were wrong once |
| O-06, O-09 | Absent attribute read as misconfiguration | Establish the default at the target's `targetSdk` |
| O-07 | Capability read as impact | A dangerous API needs a *path* to reach it |
| O-11 | Untested consequence asserted | Write what you tested, in the mood you tested it |

| If you under-rated… | Your bias | The corrective |
|---|---|---|
| O-08 | Chain rated at its weakest link | Rate the chain; remediate the cheapest link |
| O-12 | Impact equated with confidentiality | Availability and cost are impacts |
| O-13 | Population ignored | 4 million users × ordinary operation is not the same as one attacker |
| O-02 | Trajectory discarded | A systemic cause with no present impact is still Low, not nothing |

---

## 5. The exercise that actually calibrates you

Ratings improve only with feedback, and engagements give you feedback slowly and noisily. Build the
loop yourself:

1. **Before** you send the report, write your rating and a one-line prediction of whether the client
   will dispute it.
2. Record the outcome: accepted, disputed-and-you-held, disputed-and-you-moved, or ignored.
3. After twenty findings, look at the pattern **per class**.

Almost everyone discovers the same thing: they are systematically wrong in one direction on one or
two classes, consistently, and had no idea. That is what a base-rate dataset is for — and note the
limit from [§10](../README.md#10-common-interview-questions): a base rate is a prior about where to
spend hours, never a substitute for arguing severity from *this* app's threat model.

---

## Success criteria

1. Fourteen ratings, each with the four lines filled in — no blank "attacker" fields.
2. You scored 24 or better.
3. You can say, without looking, which four observations exist to test whether you honour the
   out-of-scope device-owner rule (O-04, O-10, and partly O-11 and O-06).
4. You can explain why O-07 and O-08 are three bands apart when they differ by one method call.
5. You can explain why O-13 outranks O-05 despite sharing a root cause.
6. You wrote the O-11 finding as an Informational **with** a scoping recommendation, and did not
   drop it.

---

## What comes next

[Lab 03 — Write the finding](lab-03-write-the-finding.md) takes three of these observations and
makes you write them up to the rubric in
[`../examples/finding-writeups-graded.md`](../examples/finding-writeups-graded.md).
