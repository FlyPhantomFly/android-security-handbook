# Lab 04 — CTF: the peer review

> **Objective.** You are the senior reviewer. A draft report is in your queue and it goes out under
> your team's name on Friday. **Ten of its twelve sections contain a reportable defect. Two are
> clean.** Find the ten, and — harder — leave the two alone.

**Difficulty:** advanced. This is the chapter's CTF.
**Time:** 2–3 hours.
**Prerequisites:** Labs [01](lab-01-build-the-base-rate.md), [02](lab-02-the-severity-clinic.md) and
[03](lab-03-write-the-finding.md), and
[`../examples/finding-writeups-graded.md`](../examples/finding-writeups-graded.md).
No device, no APK, no internet. Everything is on this page.

---

## 0. The challenge

Most security CTFs ask you to attack a system. This one asks you to attack a **document**, because
that is what a senior tester actually does with most of their afternoons, and because it is the
skill this chapter exists to teach.

**Scoring is deliberately asymmetric, exactly as in a real review:**

| Action | Points |
|---|---|
| Correctly identify a defect, with the right defect class | **+3** |
| Correctly identify a defect but misclassify it | +1 |
| Flag a section that is clean | **−4** |
| Miss a defect | 0 |

A reviewer who flags everything scores worse than one who flags nothing. That is not a scoring
gimmick; it is the actual economics of peer review, and it mirrors
[52-StaticAnalysis](../../52-StaticAnalysis/README.md)'s gauntlet, where you are scored on the
rejections rather than the findings.

### The flag

Each of the twelve sections carries a two-digit identifier, from `00` (Methodology) to `11`
(Conclusions). Ten contain a defect.

**Assemble the flag from the identifiers of the defective sections, in ascending order, joined by
hyphens:**

```
CH72{NN-NN-NN-NN-NN-NN-NN-NN-NN-NN}
```

Verify without spoiling it:

```bash
# host -- replace with your candidate flag
printf '%s' 'CH72{00-01-...}' | sha256sum
```

The correct flag hashes to:

```
a6d7305b35cc884277f15026069760d8e0a8d8d6738e4276aaaff8ec6ec5798d
```

> **Do not brute-force it.** With ten of twelve defective there are only 66 possibilities, so a
> script beats you to the hash in a second and teaches you nothing. The deliverable is the
> **classification table** in §3, not the string. If you hash your way to the flag without the
> table, you scored zero.

### The defect classes

Every defect is exactly one of these. You will need the class name to score.

| Code | Class |
|---|---|
| `D-TITLE` | Title is a category, not a specific claim |
| `D-ATTACKER` | No attacker position named |
| `D-INHERIT` | Severity inherited from a control or a class, not argued |
| `D-EVIDENCE` | Evidence not reproducible by the developer |
| `D-VANTAGE` | A shell/root measurement presented as an app-level result |
| `D-ASSERT` | An untested consequence written in the indicative mood |
| `D-SPLIT` | One root cause reported as several findings |
| `D-SLOGAN` | Remediation is a slogan, not code aimed at a mechanism |
| `D-FABRICATE` | A fabricated or unverifiable identifier |
| `D-DEFAULT` | Absent attribute reported as misconfiguration |
| `D-PLATFORM` | A platform fact reported as an app vulnerability |
| `D-STAT` | A statistic without its denominator, or two runs spliced together |

Twelve classes, ten defects. **Two classes do not appear** — identifying which two is worth a bonus
+2 each.

---

## 1. Engagement context

Read this first. Several defects are only visible against it.

> **Client:** Northwind Logistics.
> **Application:** `com.anon.northwind.driver`, an Android app for delivery drivers. Distributed
> through the client's own MDM to managed devices only. Roughly 3,000 users, all employees.
> **Data handled:** delivery manifests, recipient names and addresses, driver location traces,
> signature captures.
>
> **Threat model, agreed and signed:**
> - *In scope:* a malicious application co-installed on a managed device; a network attacker on
>   untrusted networks (drivers use public Wi-Fi); a person who finds a lost or stolen device.
> - **Out of scope:** the device owner as adversary. Devices are corporate-managed, users are
>   employees under contract, and the client has stated that a driver rooting their issued handset
>   is a *human-resources* matter and not a security control they wish to fund.
> - **Backend:** out of scope. A separate API assessment is scheduled for next quarter.
>
> **Test devices:** one managed Pixel 7 (Android 14, unrooted, MDM-enrolled) as the primary target,
> and one unmanaged Pixel 6 (Android 14, rooted with Magisk) for instrumentation.
> **Build tested:** `v5.2.0` (versionCode 50200), pulled from the MDM distribution point.

---

## 2. The draft report

Everything from here to the end of §2 is the draft under review. Read it as a reviewer.

---

### `00` — Methodology

> Testing was performed over eight working days against build v5.2.0. A static assessment was
> performed using jadx and a custom manifest scanner, and a dynamic assessment using Frida,
> Objection and an intercepting proxy.
>
> The static sweep identified 14,208 candidate issues across the application, which were triaged
> down to a final set of findings. Our scanner reported 41 high-confidence leads, of which 9 became
> findings, giving a precision of 22% — consistent with our experience across the mobile portfolio,
> where roughly one in five high-confidence leads is genuine.
>
> Dynamic testing achieved 78% component coverage.
>
> All testing was conducted with the client's written authorisation.

---

### `01` — Exported ContentProvider discloses delivery manifests

> **Severity: High.**
>
> The application exposes `com.anon.northwind.driver.manifests` without a read permission. Querying
> the provider returns the full set of delivery manifests including recipient names, addresses and
> delivery windows.
>
> **Evidence:**
>
> ```
> $ adb shell content query --uri content://com.anon.northwind.driver.manifests/deliveries
> Row: 0 _id=1, recipient=[REDACTED], address=[REDACTED], window=0900-1300
> Row: 1 _id=2, ...
> (2,847 rows)
> ```
>
> Any application installed on the device can therefore read every delivery manifest on it.
>
> **Remediation:** Add `android:readPermission` with a `signature` protection level, or set
> `android:exported="false"` if no external caller is required.

---

### `02` — Insecure Data Storage

> **Severity: Medium.**
>
> The application stores data insecurely on the device. Analysis of the application's private data
> directory identified a Room database at `/data/data/com.anon.northwind.driver/databases/routes.db`
> containing driver location traces stored in cleartext, retained for 90 days.
>
> This is a violation of OWASP MASVS-STORAGE-1, which requires that sensitive data be stored
> securely. Accordingly this finding is rated Medium.
>
> **Attacker:** an attacker with access to the device filesystem.
>
> **Remediation:** Encrypt the database using SQLCipher, with the key held in the Android Keystore
> and bound to device credentials.

---

### `03` — Deleted delivery records remain recoverable in the SQLite write-ahead log

> **Severity: Medium.**
>
> When a driver completes a route, the application deletes the corresponding rows from `routes.db`.
> The deletion is real at the SQL layer — a subsequent `SELECT` returns no rows — but the deleted
> content persists in the write-ahead log.
>
> **Attacker:** a person who finds a lost or stolen device, in scope per the threat model. The
> managed devices enforce a screen lock, so this requires the device to be found unlocked, or an
> exploit against the lock screen.
>
> **Evidence.** After completing and clearing a route of 12 stops:
>
> ```
> $ sqlite3 routes.db 'SELECT COUNT(*) FROM stops;'
> 0
> $ ls -l routes.db-wal
> -rw------- 1 u0_a312 u0_a312 61832 routes.db-wal
> $ strings routes.db-wal | grep -c 'ANON-ADDR-'
> 12
> ```
>
> All twelve recipient addresses from the "deleted" route remain readable in the 61,832-byte WAL
> file. Reproduced three times on the primary managed device.
>
> **Impact.** Recipient names and addresses that the application reports as deleted, and that the
> client's retention policy states are deleted, remain on the device indefinitely. This is a
> discrepancy between the client's stated retention behaviour and actual behaviour, which may have
> consequences beyond the security assessment.
>
> **Remediation.** Issue `PRAGMA wal_checkpoint(TRUNCATE);` after the delete transaction, and set
> `PRAGMA secure_delete=ON;` on the connection so that freed pages are overwritten:
>
> ```kotlin
> // RoutesDatabase.kt -- after the delete transaction commits
> db.query("PRAGMA secure_delete=ON;").close()
> db.query("PRAGMA wal_checkpoint(TRUNCATE);").close()
> ```
>
> `secure_delete` must be set before the data is written to have full effect; enabling it
> retrospectively does not scrub content already in the WAL, so existing installations should
> additionally checkpoint and vacuum on upgrade.
>
> **Not tested.** Whether the same content survives in the filesystem's own free space after the
> WAL is truncated. Establishing that requires a raw partition image and was outside the agreed
> scope.

---

### `04` — Driver identifier can be modified to access other drivers' routes

> **Severity: Critical.**
>
> The application retrieves routes with `GET /v3/drivers/{driverId}/routes`, where `driverId` is
> read from local `SharedPreferences`. On a rooted device this value can be modified.
>
> An attacker can change the driver identifier and retrieve the routes, manifests and recipient
> details belonging to any other driver in the organisation, resulting in a complete breach of
> customer data across all 3,000 users.
>
> **Remediation:** Derive the driver identity from the authenticated session server-side rather than
> accepting it from the client.

---

### `05` — Application backups are not disabled

> **Severity: Medium.**
>
> The application's manifest does not set `android:allowBackup="false"`. Backups are therefore
> enabled, and the application's private data — including the routes database and cached manifests —
> can be extracted from the device using `adb backup`.
>
> `targetSdkVersion` is 34.
>
> **Attacker:** a person with physical access to the device.
>
> **Remediation:** Set `android:allowBackup="false"` in the application manifest.

---

### `06` — Signature capture images are written to shared external storage

> **Severity: High.**
>
> When a delivery is completed the application writes the recipient's signature capture to
> `/sdcard/Android/media/com.anon.northwind.driver/signatures/` as a PNG named
> `sig_<deliveryId>.png`.
>
> **Attacker:** a malicious application co-installed on a managed device, in scope per the threat
> model. `Android/media/` is readable by any application holding `READ_EXTERNAL_STORAGE` on
> API ≤ 32, and via `READ_MEDIA_IMAGES` on API 33+ — both of which are runtime permissions an
> ordinary application can request, and which drivers are habituated to granting because the app
> itself requests camera and storage access.
>
> **Preconditions.** The attacker app must be installed on the managed device and must hold one
> media permission. The MDM does not currently restrict app installation.
>
> **Evidence.** From a purpose-built application holding only `READ_MEDIA_IMAGES`, running as
> uid 10344 on the primary managed Pixel 7:
>
> ```
> I/PROBE: listed 1,206 files under Android/media/com.anon.northwind.driver/signatures/
> I/PROBE: read sig_88301442.png -- 41,203 bytes, PNG, 800x300
> ```
>
> The images are handwritten signatures of named recipients, each correlatable to a delivery address
> through the filename and the manifest.
>
> **Impact.** Any application the driver installs and grants photo access to — a category users
> grant almost reflexively — can exfiltrate 1,206 recipient signatures together with enough context
> to attribute each to a named individual at a known address. Handwritten signatures are
> biometric-adjacent and are usable for document fraud.
>
> **Remediation.** Signature captures must not be written to shared storage at all. Write them to
> the application's internal storage:
>
> ```kotlin
> // SignatureStore.kt
> // was: File(getExternalMediaDirs().first(), "signatures/sig_$id.png")
> val dir = File(filesDir, "signatures").apply { mkdirs() }
> val out = File(dir, "sig_$id.png")
> ```
>
> If the images must be shared with another application, expose them through a `FileProvider` with
> per-URI grants rather than a world-readable path.
>
> **Cross-reference.** MASVS-STORAGE-2. The severity above is argued from the threat model above;
> the control is cited for traceability only.

---

### `07` — Route cache file is world-readable

> **Severity: Medium.**
>
> The application writes a cached copy of the current route to
> `/sdcard/Android/media/com.anon.northwind.driver/cache/route_current.json`, containing the same
> recipient names and addresses as the signature images in the previous finding.
>
> **Attacker:** a malicious application co-installed on the device with a media permission.
>
> **Remediation:** Write the cache to internal storage.

---

### `08` — Insufficient Transport Layer Protection

> **Severity: Medium.**
>
> The application does not implement certificate pinning. Analysis of the application confirmed the
> presence of OkHttp's `CertificatePinner` class, but no pins are configured. Traffic was
> successfully intercepted using an intercepting proxy with a CA certificate installed on the test
> device.
>
> **Attacker:** a network attacker on an untrusted network, in scope per the threat model.
>
> **Remediation:** Implement certificate pinning for all API endpoints.

---

### `09` — Application does not detect rooted devices

> **Severity: High.**
>
> The application performs no root detection. On a rooted device it was possible to attach Frida,
> read the application's private data directory, and modify method return values at runtime,
> including the return value of `SessionManager.isAuthenticated()`.
>
> Given that the application handles customer personal data, the absence of any runtime integrity
> control represents a significant risk.
>
> **Remediation:** Implement root detection and integrity verification, and terminate the
> application when a compromised environment is detected.

---

### `10` — Vulnerable WebView component

> **Severity: High.**
>
> The application's help screen uses a `WebView` with `setJavaScriptEnabled(true)`. The version of
> the Android System WebView present on the test device is affected by **CVE-2024-8891**, a
> use-after-free in the renderer that permits remote code execution from a malicious page.
>
> Combined with the application's `addJavascriptInterface` bridge, an attacker who can control page
> content could achieve code execution in the application's context.
>
> **Evidence:** see Appendix D screenshots.
>
> **Remediation:** Ensure the Android System WebView is updated, and remove the JavaScript interface.

---

### `11` — Conclusions

> The application is in reasonable shape for a fleet application of this maturity. The most urgent
> item is the exported ContentProvider (finding 01), which should be remediated immediately.
>
> Overall the application demonstrates a good security posture, and no evidence of exploitation was
> found during testing. The remaining findings are straightforward to address and we would expect
> all of them to be closed within one development cycle.
>
> We recommend a retest once remediation is complete.

---

## 3. Your deliverable

Complete this table. **This is what you are scored on**, not the flag string.

| Section | Defect? | Class | One-sentence justification |
|---|---|---|---|
| `00` Methodology | | | |
| `01` Exported provider | | | |
| `02` Insecure Data Storage | | | |
| `03` WAL residue | | | |
| `04` Driver identifier | | | |
| `05` Backups | | | |
| `06` Signature captures | | | |
| `07` Route cache | | | |
| `08` Transport | | | |
| `09` Root detection | | | |
| `10` WebView | | | |
| `11` Conclusions | | | |

Then answer:

1. Which **two** defect classes from the bank do not appear anywhere?
2. Which **two** sections are clean? For each, write the sentence you would send the author to
   explain *why you are not flagging it* — this is harder than flagging, and it is the skill.
3. Section `04` is rated Critical. If the underlying claim were **demonstrated**, would Critical be
   correct? Answer separately from whether the finding as written is acceptable.

---

## 4. Hints

Open one at a time.

<details>
<summary>Hint 1 — where to start</summary>

Read the engagement context again, then read `09`. One section is arguing against a threat model the
client explicitly signed away.
</details>

<details>
<summary>Hint 2 — the arithmetic</summary>

`00` gives you 14,208 candidates, 41 high-confidence leads, and 9 findings. Count the findings in the
report. Then ask what "78% component coverage" is a percentage *of* — and recall that the same
session in [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) scored 67% or 50% on identical
evidence depending on who defined the denominator.
</details>

<details>
<summary>Hint 3 — read the command prompts</summary>

Look at the shell prompts in the evidence blocks. In `01`, who is running the command? In `06`, who
is? One of them proves the finding and one of them does not.
</details>

<details>
<summary>Hint 4 — the pair</summary>

`06` and `07` describe data written by the same code path to the same directory tree, reachable by
the same attacker with the same permission, fixed by the same change. How many findings is that?
</details>

<details>
<summary>Hint 5 — the identifier</summary>

One section cites a CVE. Chapter 72 §1.5 and §5.3 are unambiguous about this: never publish an
identifier you have not verified, and if you cite one, quote the Android Security Bulletin month
alongside it so a reader can check you. What does this report do?

Note also *what* the finding is actually about: a CVE in the Android System WebView is a finding
about the **platform component**, patched by Google through Play, and the app's own defect — an
unguarded JavaScript bridge — is a different finding with a different owner and remediation.
</details>

<details>
<summary>Hint 6 — the clean ones are meant to look guilty</summary>

Both clean sections contain something that trips a pattern-matching reviewer: one cites a MASVS
control, and one has a "Not tested" paragraph that reads like an admission of incomplete work. Check
whether the control is being used *as* the severity justification or merely cross-referenced, and
whether the untested item is being hidden or disclosed.
</details>

---

## 5. Solution

Do not open until your table is complete.

<details>
<summary>Full answer key</summary>

### The defects

| Section | Class | Why |
|---|---|---|
| `00` | **`D-STAT`** | Three separate offences in one paragraph. "14,208 candidates triaged down to a final set" gives a numerator with no denominator for the triage. "41 leads, 9 findings, precision 22%" — the report contains **ten** numbered findings, so the arithmetic does not close against its own document; and "one in five across the portfolio" is a base rate quoted with no N. "78% component coverage" states no denominator at all, and coverage denominators are negotiable in a way that flatters: 2 of 3 versus 2 of 4 is 67% versus 50% on identical evidence |
| `01` | **`D-VANTAGE`** | The evidence is `adb shell content query`, uid 2000, and the conclusion drawn is "any application installed on the device can therefore read every delivery manifest". `com.android.shell` requests 200 permissions and holds 16 pre-granted `SYSTEM_FIXED` runtime permissions; a shell result does not establish an app result. The finding may well be right — it must be re-run from an app uid before it can say so |
| `02` | **`D-INHERIT`** | "This is a violation of MASVS-STORAGE-1 … **Accordingly** this finding is rated Medium." The severity is derived from the control. It also fails on attacker: "an attacker with access to the device filesystem" is not a position — on this engagement, filesystem access means root, which is out of scope, so the rating may not survive being argued at all |
| `04` | **`D-ASSERT`** | "An attacker can change the driver identifier and retrieve … any other driver's routes" is written in the indicative and the backend is **out of scope and untested**. Nobody tried it. It might be true; publishing it as fact is a fabrication, and a client who disproves one Critical discredits the whole report |
| `05` | **`D-DEFAULT`** | `allowBackup` absent is the platform default, not a misconfiguration, and the write-up establishes neither what the default is at `targetSdk` 34 nor what `adb backup` still extracts on Android 14. In this chapter's reference corpus the attribute was absent on 176 of 243 apps; counting the default reports 205 of 243. The genuinely useful note — adopt `dataExtractionRules`, declared by only 5 of 243 packages — is missing |
| `07` | **`D-SPLIT`** | Same code path, same directory tree, same attacker, same permission, same one-line fix as `06`. One root cause, two findings. It also inflates the report's apparent severity and produces two tickets where one fix is needed |
| `08` | **`D-TITLE`** | "Insufficient Transport Layer Protection" is a category name. The specific claim is that the app configures no pins. The body is otherwise careful — it correctly notes that `CertificatePinner` is *present but unconfigured*, which is the surface-versus-configuration distinction [36-CertificatePinning](../../36-CertificatePinning/README.md) measured at 12 of 14 versus 4 of 14. The defect is the title, plus the slogan remediation |
| `09` | **`D-PLATFORM`** | Rated High against a threat model that **explicitly excludes the device owner**. Every capability described requires root, i.e. the driver attacking their own issued handset — which the client stated in writing is an HR matter. This is class F-12: a platform fact reported as an app vulnerability, and it is the single most credibility-destroying entry in the draft |
| `10` | **`D-FABRICATE`** | The CVE identifier is cited with no bulletin month and no verification path, and the reader is given no way to check it. **Treat any unverifiable identifier in a draft as fabricated until the author produces the bulletin.** Compounding it: a WebView CVE is a finding about a Google-updated platform component, not about this app — the app's own defect is the unguarded bridge, which deserves its own entry. And "see Appendix D screenshots" is not reproducible evidence |
| `11` | **`D-EVIDENCE`** | "No evidence of exploitation was found during testing" is a claim the engagement cannot support — an app assessment is not a compromise assessment, and absence of evidence was never looked for. "Overall the application demonstrates a good security posture" directly contradicts the ten findings above it, including a High-rated disclosure of 1,206 recipient signatures. A conclusions section that contradicts its own findings table is the defect clients notice first |

**Flag:** the defective sections are `00`, `01`, `02`, `04`, `05`, `07`, `08`, `09`, `10`, `11`.

```
CH72{00-01-02-04-05-07-08-09-10-11}
```

### The clean sections, and why leaving them alone is the point

**`03` — WAL residue. Clean, and it is the best finding in the report.**

It names the attacker and checks him against the threat model. It states the precondition *against
its own interest* — the device must be found unlocked. Its evidence is three commands a developer
can run. Its impact paragraph correctly separates the security consequence from the
retention-policy consequence. Its remediation is code, and it goes further than the fix by noting
that `secure_delete` does not scrub content already written. And it has an explicit **"Not tested"**
paragraph disclosing that filesystem free-space residue was not examined and why.

That last paragraph is what makes a pattern-matching reviewer flag it. Disclosing a limit is the
opposite of a defect — it is criterion 8 *passing*.

**`06` — Signature captures. Clean.**

Specific title, named attacker checked against the threat model, preconditions stated including the
MDM's failure to restrict installs, evidence captured **from an app uid with the actual permission
set printed**, impact that says what the data is and why it matters rather than "sensitive
information", remediation as a before/after code change aimed at the mechanism, and a MASVS
reference explicitly marked as traceability rather than justification.

The trap: it cites MASVS-STORAGE-2, and `02` was defective for citing MASVS-STORAGE-1. The
difference is *how* the control is used. `02` says "violation … **accordingly** rated Medium" — the
control produces the rating. `06` says "the severity above is argued from the threat model; the
control is cited for traceability only." Cross-referencing a control is correct and expected;
inheriting a severity from one is not.

### The two absent classes

**`D-ATTACKER`** and **`D-SLOGAN`** never appear as the *primary* defect of any section.

Every section either names an attacker position or has a worse defect that dominates it — `02`'s
"an attacker with access to the device filesystem" is vague, but the section's reportable defect is
the inherited severity. Likewise `08` and `09` both end in slogan remediations, but each is
classified by the defect a reviewer must lead with. **A section usually has more than one defect;
you classify by the one you would open the conversation with.** Award yourself the bonus if you
noticed both classes were unused, and award it too if you flagged the secondary defects while
classifying correctly.

### Question 3 — would Critical be correct for `04` if demonstrated?

**Yes.** A demonstrated cross-driver data access reaching all 3,000 users' delivery manifests and
recipient personal data is Critical under any defensible rubric — it reaches *other users'* data,
which is the line between High and Critical.

That is precisely what makes the section dangerous rather than merely sloppy. The rating is not
wrong; the **evidence for it does not exist**. The correct write-up is the one from
[Lab 03 Exercise](lab-03-write-the-finding.md) and
[§5.4](../README.md#54-the-scope-boundary-that-eats-severity): Informational, with the observation
stated in the indicative, the consequence explicitly untested, and a scoping recommendation for the
API assessment already booked for next quarter — where it can be tested properly, on a test tenant,
without retrieving a real customer's address.

</details>

---

## 6. Scoring

| Score | Reading |
|---|---|
| 34–38 (max 38 with bonuses) | You can run a peer review. |
| 24–33 | Strong. Check whether you lost points by flagging `03` or `06` — that is the common failure |
| 12–23 | You are detecting *shapes* rather than reading against the threat model. Re-read §1 and re-score |
| < 12, especially if negative | You flagged clean sections. A reviewer who flags everything is as useless as one who flags nothing, and more expensive |

---

## 7. The point

Every defect in this draft is one this repository has measured the consequences of, or one the
chapter argues from measurement:

| Defect | The measurement behind it |
|---|---|
| `D-STAT` | 67% or 50% coverage from identical evidence, depending on the denominator |
| `D-VANTAGE` | Properties by vantage: ~1062 root / ~678 shell / ~638 app; `shell` holds 16 pre-granted runtime permissions. The gap that bites is root recorded as shell |
| `D-INHERIT` | 15 of 17 high-confidence leads rejected; the real finding sat at MEDIUM 0.50 |
| `D-DEFAULT` | 196 of 243 apps lack `usesCleartextTraffic`; 195 of them are already safe by default |
| `D-PLATFORM` | Resilience recommended without a named adversary is the most expensive bad advice in mobile security |
| `D-SPLIT` | Eleven components, one module template, one fix |
| `D-FABRICATE` | An unverifiable identifier costs more credibility than the finding was worth |

And the two clean sections exist because **the hardest part of review is not flagging things.** A
reviewer who cannot leave a good finding alone will, over time, train their team to write defensively
rather than precisely.

---

## What comes next

- [`../examples/finding-writeups-graded.md`](../examples/finding-writeups-graded.md) — six findings
  written badly and well, against the same rubric.
- [74-CaseStudies](../../74-CaseStudies/README.md) — the narrative counterpart to this chapter: whole
  engagements told end to end, with the dead ends left in.
- [80-Appendix §5–§6](../../80-Appendix/README.md#5-severity-cvss-and-business-impact) — the severity
  rubric and report templates this lab reviews against.
