# Graded finding write-ups

Six findings, each written twice — once badly and once well — against the **same underlying
observation**. The bad version is not a straw man: every one of them is a shape that appears in real
commercial reports, and several are shapes I have written myself.

The grading rubric is [chapter 72 §3.9](../README.md#39-reporting-units-what-actually-goes-in-the-table).
The severity rubric and the finding template itself belong to
[80-Appendix §5–§6](../../80-Appendix/README.md#5-severity-cvss-and-business-impact); this file is
about the *writing*, not the scale.

> **Anonymisation.** Every application here is anonymised, and the observations are composites drawn
> from the classes this repository has measured. No product is named, and no write-up below should
> be read as an assessment of any real published build. That is the rule from
> [§1.5](../README.md#15-authorisation-and-how-findings-get-anonymised): describe the class,
> quantify the population, anonymise the instance.

---

## Contents

| # | Underlying observation | The failure the bad version demonstrates |
|---|---|---|
| 1 | An exported `ContentProvider` with no read guard | Severity inherited from the class |
| 2 | Eleven exported components in one module | Reporting per instance instead of per root cause |
| 3 | A string that looks like an API key | Reporting a lead as a finding |
| 4 | An app that does not detect root | A platform fact reported as an app vulnerability |
| 5 | A user-controllable object identifier sent to the backend | Claiming what you did not test |
| 6 | A cross-app readable file | Under-rating by stopping at "not exploitable" |

---

## 1. Exported ContentProvider with no read guard

### The observation

`com.anon.app.provider` is declared `android:exported="true"` with no `android:readPermission` and
no `android:permission`. Querying it from a co-installed application holding **zero** permissions
returns 4,182 rows containing message bodies, sender identifiers and timestamps.

### The bad version

> **HIGH — Insecure Data Storage (M2)**
>
> The application exposes a ContentProvider without proper permission controls. An attacker could
> exploit this to access sensitive information. This is a violation of OWASP MASVS-STORAGE-1 and
> MASVS-PLATFORM-1.
>
> **Evidence:** see screenshot.
>
> **Remediation:** Implement proper permission controls on all exported components.

Six defects in eight lines:

| Defect | Why it costs you |
|---|---|
| **Title is a category, not a claim** | "Insecure Data Storage" tells a developer nothing about what to open |
| **Severity inherited from the control** | MASVS-STORAGE-1 did not make this High; the message bodies did. The rating is unreviewable because no argument is attached |
| **"An attacker could"** with no attacker named | Which of the five positions in [§3.4](../README.md#34-gate-2--is-it-reachable-and-by-whom)? The answer here is excellent for the client's risk and the write-up does not say it |
| **"See screenshot"** | A screenshot of your tool is not evidence. The developer cannot reproduce it |
| **Remediation is a slogan** | "Implement proper permission controls" is the finding restated as an imperative |
| **Two control IDs, no reasoning** | Mapping is [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md)'s job and it is a *cross-reference*, not a justification |

### The good version

> **F-01 — Any installed app can read all stored messages via an unguarded ContentProvider**
>
> **Severity: High.** **Confidence: Demonstrated.**
>
> **Summary.** `com.anon.app.provider` is exported with no read permission. Any application
> installed on the same device — with no permissions of its own, and without the user being prompted
> — can read the complete local message store, including message bodies, counterpart identifiers and
> timestamps. On the test account this returned 4,182 rows.
>
> **Threat model.** Attacker position: *a malicious co-installed application, no special
> privileges*. This is the weakest attacker in the mobile threat model and the one the Android
> sandbox exists to stop. No root, no physical access, no network position and no user interaction
> beyond installing the attacker's app are required.
>
> **Technical detail.** The provider is declared:
>
> ```xml
> <provider
>     android:name=".data.MessageProvider"
>     android:authorities="com.anon.app.provider"
>     android:exported="true" />
> ```
>
> There is no `android:readPermission`, no `android:writePermission` and no `android:permission`, so
> `ContentProvider.enforceReadPermissionInner` finds nothing to enforce and the query proceeds. The
> export is not required by any observed functionality: the provider carries no `<intent-filter>`,
> and every internal caller reaches it in-process.
>
> **Steps to reproduce.** From an app declaring zero `<uses-permission>` elements:
>
> ```java
> Cursor c = getContentResolver().query(
>         Uri.parse("content://com.anon.app.provider/messages"),
>         null, null, null, null);
> Log.i("PROBE", "rows=" + c.getCount() + " cols=" + c.getColumnCount());
> ```
>
> A ready-made probe is at [`ProviderReachProbe.java`](ProviderReachProbe.java). Confirm from an app
> uid, **not** from `adb shell` — the shell holds pre-granted permissions an app does not.
>
> **Evidence.** `rows=4182 cols=9`, column names `_id, thread_id, address, body, date, read,
> type, sub_id, service_center`, captured at app uid 10247 with an empty permission set, on
> build 4.2.1 (versionCode 40201).
>
> **Impact.** Complete disclosure of the user's message history to any application on the device.
> The data is directly attributable to the user, is retained indefinitely by the app, and its
> disclosure is likely to be reportable under the client's own privacy commitments.
>
> **Remediation.** Set `android:exported="false"`. Every observed caller is in-process, so no
> further change is needed:
>
> ```xml
> <provider
>     android:name=".data.MessageProvider"
>     android:authorities="com.anon.app.provider"
>     android:exported="false" />
> ```
>
> If an external caller is required in a future release, add
> `android:readPermission="com.anon.app.permission.READ_MESSAGES"` declared at
> `android:protectionLevel="signature"`, and confirm that a `normal`-level permission is granted to any
> app that asks for it and is therefore not a control.
>
> **Cross-reference.** MASVS-PLATFORM-1. The mapping is a cross-reference; the severity above comes
> from the threat model.

**What makes it good** is that every sentence is falsifiable. A developer can check the manifest,
run the snippet, and either reproduce `4182` or come back and tell you that you were wrong — which
is the property a finding needs.

---

## 2. Eleven exported components in one module

### The observation

Eleven components across one feature module are exported with no guard and no intent-filter. All
eleven are internal screens. None handles attacker-controlled input.

### The bad version

Eleven separate findings, `M-04` through `M-14`, each rated **Medium**, each with the same body text
and a different class name.

That is defensible only if you believe the client's remediation cost is eleven times one component.
It is not. It produces eleven tickets, eleven code reviews, and — because nothing in the report
explains *why* eleven components ended up this way — a twelfth exported component next quarter.

It also silently inflates the report's apparent severity: eleven Mediums reads as a worse app than
one Medium, and the underlying risk is identical.

### The good version

> **F-06 — Components in the `feature-account` module are exported by an inherited build default**
>
> **Severity: Low.** **Instances: 11.** **Confidence: Demonstrated.**
>
> **Summary.** Eleven components in `feature-account` are declared `android:exported="true"` while
> carrying no `<intent-filter>` and no permission guard, so they are reachable by any installed app
> with no declared reason to be. All eleven are internal screens that accept no extras and read no
> caller-supplied data, so there is no direct impact today. They are reported as one finding because
> they share one cause: the module's shared manifest template sets the export default, so **any
> component added to this module in future will also be exported** — including one that does handle
> input.
>
> **Threat model.** Attacker position: *a malicious co-installed application*. Present impact: none
> demonstrated. The finding is about the trajectory, not the current state, and it is rated Low on
> that basis rather than Informational because the cause is systemic and the fix is cheap.
>
> **Instances.**
>
> | Component | Type |
> |---|---|
> | `.account.ProfileActivity` | activity |
> | `.account.PreferencesActivity` | activity |
> | *(nine further components listed in Appendix B)* | |
>
> **Remediation.** Fix the template, not the eleven:
>
> ```xml
> <!-- feature-account/src/main/AndroidManifest.xml -->
> <!-- was: no android:exported, inherited from the module template -->
> <activity android:name=".account.ProfileActivity"
>           android:exported="false" />
> ```
>
> Then add a lint rule so the class cannot recur:
>
> ```groovy
> // build.gradle.kts -- fail the build on an exported component with no guard
> android { lint { error += "ExportedActivity"; error += "ExportedContentProvider" } }
> ```
>
> **Note on prevalence.** Eleven instances is an *aggravating factor within this rating*, not eleven
> ratings. See [chapter 72 §3.7](../README.md#37-where-severity-actually-comes-from).

---

## 3. A string that looks like an API key

### The observation

`grep` over the decompiled tree returns `AIza…`-shaped strings and a constant named
`API_SECRET_KEY`.

### The bad version

> **CRITICAL — Hardcoded API Key**
>
> A hardcoded API key was found in the application: `API_SECRET_KEY = "…"`. An attacker can extract
> this key and use it to access the backend API.

This is a **lead reported as a finding**, and the repository has the numbers for exactly how often
that goes wrong. [33-Storage](../../33-Storage/README.md) ran a shape-based secret scanner against
real browser data and got **132 high-confidence hits, 132 of them false positives** — every one a
component-updater signature manifest. [52-StaticAnalysis](../../52-StaticAnalysis/README.md)
hand-adjudicated a 17-lead HIGH band and rejected **fifteen**, including seven documentation URLs
from a logging façade and three Compose `@Preview` fixtures.

The specific unasked questions here:

- **Is it a secret?** Many `AIza…` keys are *public* client identifiers, restricted server-side by
  package name and signing certificate. Shipping one is the documented design.
- **Is it live?** A key that 401s is a hygiene issue, not a Critical.
- **What does it authorise?** "Access to the backend API" is a guess dressed as an impact.
- **Is it in the app's code or a bundled SDK's?** Different owner, different remediation.

### The good version

> **F-02 — A live server-side API credential is shipped in the application binary**
>
> **Severity: High.** **Confidence: Demonstrated.**
>
> **Summary.** A credential for the client's transactional email provider is present as a string
> constant in `classes2.dex`. It was extracted from the release APK obtained from the public store
> listing, and confirmed live: an authenticated request against the provider's API returned HTTP 200
> and the account's sending quota. The credential authorises sending mail **as the client's domain**.
>
> **Threat model.** Attacker position: *anyone who can download the app*. No device access, no
> network position, no user. The APK is publicly distributed, so the credential should be treated as
> already public.
>
> **Why this one and not the others.** Nineteen further strings matched the scanner's
> secret-shaped-value rule and were rejected on inspection: eleven are public client identifiers
> restricted by package name and signing certificate (the documented design), five are test fixtures
> inside a bundled SDK, and three are resource identifiers that are syntactically but not
> semantically keys. They are listed in Appendix C as observations. **Only this one was validated
> against a live service.**
>
> **Evidence.** Redacted to first and last four characters in this report; the full value was
> transmitted separately and should be treated as compromised and rotated regardless of remediation
> timeline.
>
> **Impact.** Send-as-domain capability enables convincing phishing against the client's own
> customers, and consumes a paid quota. The blast radius is the domain's reputation, which is slow
> and expensive to repair.
>
> **Remediation.** Rotate the credential **first** — remediation of the code does not un-publish it.
> Then move the send operation server-side; the client should never hold a credential that
> authorises sending as the domain. If a client-side call is unavoidable, issue a short-lived,
> narrowly-scoped token from your own backend after authenticating the user.

The paragraph headed *Why this one and not the others* is the single highest-value paragraph in this
whole file. It tells the client that nineteen candidates were adjudicated and rejected, which is
simultaneously evidence of thoroughness and the reason they should believe the one that survived.

---

## 4. An app that does not detect root

### The observation

The app runs normally on a rooted device. There is no root detection.

### The bad version

> **HIGH — Lack of Root Detection**
>
> The application does not detect rooted devices. On a rooted device an attacker can access the
> application's private data, hook its methods with Frida, and bypass client-side controls.

Everything in it is true and it should not be in the findings table. Three problems:

**The attacker is the user.** The only person who benefits is the device's owner. Unless the
engagement's threat model names the device owner as an adversary — licensing, anti-fraud, DRM,
regulated content — there is no attacker here.

**The premise is smuggled in as an impact.** "On a rooted device an attacker can access private
data" is a description of what root *is*, not a consequence of this app's design. This is class
**F-12** in [chapter 72 §3.2](../README.md#32-the-classes-and-what-each-one-actually-is): a finding
about the platform, reported as a finding about the app.

**It is unactionable, and the developer knows it.** Root detection is bypassable by construction —
this repository has a whole chapter on doing so ([67-BypassingProtections](../../67-BypassingProtections/README.md))
— and [54-Objection](../../54-Objection/README.md) measured that even a purpose-built bypass tool
covered only **1 of 5** checks in a small purpose-built app. Rating it High tells the developer you
cannot tell methodology from risk, and every other rating in the document is discounted accordingly.

### The good version, when resilience *is* in the threat model

> **F-09 — Client-side integrity controls are absent, and the threat model requires them**
>
> **Severity: Medium.** **Confidence: Demonstrated.**
>
> **Summary.** The engagement's threat model names the device owner as an adversary, because the app
> enforces a paid content entitlement locally. The app performs no root detection, no debugger
> detection, no integrity self-check and no remote attestation. The entitlement check is a single
> method returning a boolean, which was flipped at runtime in under five minutes, granting access to
> paid content on an account with no entitlement.
>
> **Threat model.** Attacker position: *the device owner, hostile, with root*. This position is in
> scope **only because the client's business model places it there**. On an engagement without that
> premise this would be Informational.
>
> **What the rating does and does not claim.** Resilience controls do not stop a determined
> attacker; they raise cost and enable detection. The rating reflects that the current cost is
> approximately zero, not that a control would make it infinite. A realistic target is to move
> entitlement enforcement server-side so that the client-side control stops being load-bearing.
>
> **Remediation, in priority order.**
> 1. **Enforce the entitlement server-side.** Content should be served only against a token the
>    backend validates. This removes the finding rather than raising its cost.
> 2. Add server-verified attestation (Play Integrity) as a signal, not a gate, and monitor it.
> 3. Only then consider client-side detection, understanding that it is a speed bump.
>
> **Note.** Recommendation 3 without recommendation 1 is the expensive mistake. See
> [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) on naming the adversary before recommending
> MASVS-RESILIENCE work.

the *good* version is a **Medium**, not a High, and that its top recommendation deletes
the finding rather than hardening it.

---

## 5. A user-controllable object identifier sent to the backend

### The observation

The app calls `GET /api/v2/accounts/{accountId}/statements`, and `accountId` comes from local state
that can be modified. The backend was **out of scope**.

### The bad version A — claiming what you did not test

> **CRITICAL — Insecure Direct Object Reference (IDOR)**
>
> The application sends a user-controllable account identifier to the server. An attacker can modify
> this value to access other users' financial statements.

The last sentence is a **fabrication**. Nobody tried it. It may well be true; it is equally likely
the server checks. Writing an untested consequence in the indicative mood is the fastest way to
publish something a client can prove false, and one disproved Critical discredits the entire report.

### The bad version B — the opposite error

> Not reported. The backend was out of scope.

Silently dropping it means the client never learns that their most valuable untested surface is
reachable from a client they *did* pay to have tested.

### The good version

> **F-04 — Client transmits a user-controllable account identifier; server-side authorisation was
> not in scope**
>
> **Severity: Informational — with an explicit and important testing gap.**
> **Confidence: Observation confirmed; consequence untested.**
>
> **Summary.** The statements endpoint takes the account identifier from a client-side value that a
> device owner can modify. Whether that is exploitable depends entirely on the server's
> authorisation logic, which was **outside the agreed scope** and was **not tested**. This finding
> records the observation and the gap; it does not claim a vulnerability.
>
> **What was confirmed.** The identifier is read from local storage, is modifiable on a rooted
> device, and is placed in the request path unmodified. Confirmed by static reading of the request
> builder and by observing the request in the intercepting proxy.
>
> **What was not tested, and why.** No request was sent with a modified identifier, because the
> agreed rules of engagement excluded the backend and because a successful request would have
> returned another individual's financial data — which is a data-protection event, not a test
> result. **This gap is the finding.**
>
> **Why it is still worth reporting at Informational.** If the server does not authorise per
> account, this is Critical. If it does, it is nothing. The client currently has no evidence either
> way, and the cost of obtaining it is small compared with the cost of being wrong.
>
> **Recommended next step.** A scoped API assessment against a test tenant with two provisioned
> accounts, verifying that account A cannot retrieve account B's statements. This repository's
> position on this pattern is in [chapter 72 §5.4](../README.md#54-the-scope-boundary-that-eats-severity):
> **"out of scope" is not "secure", and the correct output of an untestable item is a scoping
> recommendation.**

---

## 6. A cross-app readable file

### The observation

An app with zero permissions reads a file inside another package's private directory on a stock,
Enforcing device.

### The bad version — over-rating

> **HIGH — Sandbox Bypass**
>
> An application with no permissions was able to read a file from another application's private data
> directory, bypassing the Android sandbox.

### The bad version — under-rating

> Not reported. The file only contained configuration flags.

### The good version

> **F-07 — A private-directory file is world-readable, on a path with no per-app SELinux categories**
>
> **Severity: Informational.** **Confidence: Demonstrated.**
>
> **Summary.** A file inside another package's private data directory was read by an application
> holding no permissions, on a stock device with SELinux Enforcing. The file's contents are SDK
> feature flags, so nothing of value is disclosed and the severity is Informational. It is reported
> because the *cause* is structural rather than specific to this file, and will apply to whatever is
> written to the same path next.
>
> **Why Informational and not High.** Three conditions must hold for a storage finding to have
> impact: the discretionary permissions must permit the path walk, SELinux/MCS must permit the read,
> and the content must matter. The first two hold here. The third does not. Two other candidate
> files on the same device were blocked by a `0700` ancestor directory, which is the control that
> actually holds.
>
> **Why it is reported at all.** The directory class involved carries **no per-app MCS categories**,
> so MAC provides no isolation between packages on this path — the isolation is coming from
> discretionary permissions alone. A future release writing a token or an identifier to the same
> directory would be readable by every app on the device, with no code change and no signal that
> anything had changed.
>
> **Remediation.** Set the directory mode to `0700` and the file to `0600`, and treat the path as
> having no MAC isolation when deciding what may be written there.
>
> **Reference.** The three-gate model is [33-Storage](../../33-Storage/README.md), which measured
> this exact case and rated it Informational for the same reason.

---

## The rubric, condensed

Score any write-up out of ten. Every point is binary.

| # | Criterion | Fails when |
|---|---|---|
| 1 | Title is a specific claim | It is a category name |
| 2 | Attacker position is named | "An attacker could" |
| 3 | Preconditions are stated | They live in the methodology section |
| 4 | Severity is argued, not looked up | The only justification is a control ID |
| 5 | Evidence is reproducible by the developer | "See screenshot" |
| 6 | The vantage is stated where it matters | A shell result presented as an app result |
| 7 | Impact is specific | "Sensitive information" |
| 8 | What was *not* tested is stated | An untested consequence written in the indicative |
| 9 | One finding per root cause | Eleven near-identical entries |
| 10 | Remediation is code, aimed at the mechanism | "Implement proper controls" |

The bad versions above score 1, 2, 1, 2, 2 and 3 out of ten respectively. The good versions score
ten — which is achievable, and is the point.

---

## Related files

- [`corpus-sweep-output.txt`](corpus-sweep-output.txt) — the raw measurement behind chapter 72 §3.5.
- [`ProviderReachProbe.java`](ProviderReachProbe.java) — the app-vantage probe write-up 1 depends on.
- [`../labs/lab-03-write-the-finding.md`](../labs/lab-03-write-the-finding.md) — practises this
  rubric against fresh observations.
- [`../labs/lab-04-ctf-the-peer-review.md`](../labs/lab-04-ctf-the-peer-review.md) — a whole draft
  report with these defects planted in it.
- [80-Appendix §6](../../80-Appendix/README.md#6-report-templates) — the finding template and the
  executive summary skeleton these write-ups instantiate.
