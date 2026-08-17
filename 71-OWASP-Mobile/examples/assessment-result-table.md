# Worked example — a control-by-control result table

> **This is an illustrative artefact.** The app, the findings and the evidence filenames are
> invented. What is real is the *shape*: this is what the coverage section of a mobile assessment
> looks like when every row is defensible, and it is the target output of
> [`labs/lab-02-map-a-known-app.md`](../labs/lab-02-map-a-known-app.md).
>
> **Build yours before reading this one.** Reading the finished article first removes the part of the
> exercise that teaches you anything.

The finding write-ups themselves, the severity rubric and the executive summary structure belong to
[80-Appendix §5–§6](../../80-Appendix/README.md#5-severity-cvss-and-business-impact). This document is
only the **coverage table** — the part that says what was assessed, how, and with what evidence.

---

## 1. Methodology header

Everything below is a claim about a specific artefact on a specific platform against a specific
version of the standard. A table without this header is not reproducible, and coverage tables get
extracted from reports and circulated on their own — so the header travels with the table, not just
with the report.

| Field | Value |
|---|---|
| Application | `com.northfield.retail` — Northfield Retail |
| Version | 5.8.1 (versionCode 50801) |
| APK SHA-256 | `a41c…` (full digest in the evidence index) |
| Signer | SHA-256 `9f02…`, CN=Northfield Software Ltd |
| minSdk / targetSdk | 26 / 33 |
| Device | Pixel 6 (oriole), Android 14 |
| Build fingerprint | `google/oriole/oriole:14/…` |
| Security patch | 2026-06-05 |
| Root | Magisk, SELinux enforcing |
| Standard | MASVS v2.x and MASTG v2.x, resolved 2026-07-14 at mas.owasp.org |
| Assessment window | 2026-07-14 to 2026-07-25 |
| Backend | **In scope**, assessed against OWASP ASVS; reported separately |

> **Why the standard version and resolution date are both here.** The version says which controls
> existed. The date says when the identifiers were resolved. A year from now, someone comparing this
> table to a newer assessment will find different control IDs, and these two fields are what stops
> them concluding that one of the two testers was careless. See
> [`references/README.md §2`](../references/README.md).

---

## 2. Scope statement

Six sentences, as produced by [`labs/lab-01`](../labs/lab-01-build-the-checklist.md) step 8.

> The Northfield Retail Android application, build 5.8.1 (50801), was assessed against MASVS v2.x
> and MASTG v2.x as resolved on 2026-07-14. All eight control categories were assessed;
> MASVS-RESILIENCE was assessed at reduced depth by agreement, on the basis that the loyalty-points
> balance is authoritative server-side and no client-side entitlement exists (agreed with
> J. Okonkwo, Head of Engineering, 2026-07-11). Two controls were blocked: MASVS-AUTH-1 could not be
> fully exercised until a second, lower-privileged test account was provisioned on day 6, and
> MASVS-PRIVACY-3 was blocked pending delivery of the current privacy policy, which arrived after
> the assessment window closed. The backend API was in scope and was assessed against OWASP ASVS;
> its findings are reported in a separate document. Third-party SDK behaviour was assessed only as
> observed egress; SDK source code was not reviewed. Findings are against the build named above and
> no other.

---

## 3. State vocabulary

The legend must be in the document, because "PASS" is not self-explanatory and readers will assume
the strongest reading of whatever you wrote.

| State | Means | Requires |
|---|---|---|
| `PASS` | Tested, and the requirement holds | An evidence reference |
| `FAIL` | Tested, and the requirement does not hold | A finding ID **and** an evidence reference |
| `PARTIAL` | Some tests run and some not, or the requirement holds in some flows and not others | Evidence for what was run, and a note on what was not |
| `NOT-TESTED` | Deliberately excluded at scoping | The reason, and who agreed |
| `BLOCKED` | Would have tested; could not | The obstacle, and what would remove it |
| `N/A` | The control has no subject in this app | Why there is no subject |

> **⚠️ The distinction that matters most.** `NOT-TESTED` is a decision you made about risk.
> `BLOCKED` is a limitation imposed on you. A client who reads a `BLOCKED` row as `NOT-TESTED`
> believes you considered and dismissed something you could not reach. Keep them apart, and never let
> either become `PASS`.

---

## 4. The table

| Control | State | Evidence | Finding | Severity | Note |
|---|---|---|---|---|---|
| `MASVS-STORAGE-1` | FAIL | `E-12` | F-03 | High | Refresh token written to `shared_prefs/auth.xml` in plaintext; reproduced across the full feature exercise, not only at login |
| `MASVS-STORAGE-2` | FAIL | `E-13` | F-07 | Medium | Order identifiers and the customer email address emitted to the system log at `INFO` on every basket update |
| `MASVS-CRYPTO-1` | PASS | `E-21` | — | — | Runtime JCA trace over the full exercise shows AES-GCM only, with `SecureRandom`-sourced IVs and no IV reuse across 1,412 observed operations |
| `MASVS-CRYPTO-2` | FAIL | `E-21`, `E-22` | F-04 | Medium | The card-tokenisation key is hardware-backed and correct; the *loyalty* key is a `SecretKeySpec` over a constant in DEX and never reaches the KeyStore |
| `MASVS-AUTH-1` | FAIL | `E-31`, `E-32` | F-01 | Critical | Order history retrievable for arbitrary customer identifiers with a valid low-privileged session; server performs no object-level authorization |
| `MASVS-AUTH-2` | FAIL | `E-33` | F-05 | High | Biometric prompt succeeds into a plain boolean; no `CryptoObject`, and the gated secret is independently readable — see F-03 |
| `MASVS-AUTH-3` | PARTIAL | `E-34` | — | — | Step-up enforced server-side for card changes; **not** verified for address changes, which the client confirmed are also sensitive. Reported as a coverage gap |
| `MASVS-NETWORK-1` | PASS | `E-41` | — | — | All four certificate-failure cases refused: expired, self-signed, wrong hostname, user-store CA. Full pcap shows no cleartext and no non-HTTP egress |
| `MASVS-NETWORK-2` | PARTIAL | `E-42` | F-09 | Low | Primary API pinned with a valid backup pin; the analytics host is unpinned. Client states analytics is out of the pinning policy — recorded, not disputed |
| `MASVS-PLATFORM-1` | FAIL | `E-51`, `E-52` | F-02 | High | `ShareTargetActivity` forwards an externally supplied `Intent` extra to an internal component. **Reproduced from an unprivileged probe app, not from `adb shell`** |
| `MASVS-PLATFORM-2` | PASS | `E-53` | — | — | Three WebViews enumerated from the shipped artefact; JavaScript enabled on one, no bridge attached, file access disabled, origins restricted to an allow-list verified at runtime |
| `MASVS-PLATFORM-3` | FAIL | `E-54` | F-08 | Low | No `FLAG_SECURE` on the card-entry screen; the recents thumbnail retains a partially masked PAN |
| `MASVS-CODE-1` | PASS | `E-11` | — | — | `targetSdk` 33; no debug artefacts, no `testOnly`, no shipped instrumentation, `debuggable` absent from the shipped artefact as well as the source manifest |
| `MASVS-CODE-2` | FAIL | `E-35` | F-10 | Low | The app prompts to update but the API serves clients back to 4.0.0, including one with a known-vulnerable bundled component |
| `MASVS-CODE-3` | PARTIAL | `E-14` | F-06 | Medium | 31 dependencies inventoried; two bundled native libraries could not be version-identified from the shipped artefact and are recorded as unknown, not as clean |
| `MASVS-CODE-4` | PASS | `E-55` | — | — | Every external entry point enumerated and fuzzed with malformed input: deep links, provider arguments, push payloads and imported files. No unhandled parse path reached |
| `MASVS-RESILIENCE-1` | NOT-TESTED | — | — | — | Reduced-depth agreement: no client-side entitlement; loyalty balance authoritative server-side (J. Okonkwo, 2026-07-11) |
| `MASVS-RESILIENCE-2` | NOT-TESTED | — | — | — | As above |
| `MASVS-RESILIENCE-3` | PARTIAL | `E-61` | — | — | Assessed to the extent that it affects other findings: R8 name mangling present, string constants not encrypted, which is how F-04's constant key was located |
| `MASVS-RESILIENCE-4` | NOT-TESTED | — | — | — | As above |
| `MASVS-PRIVACY-1` | FAIL | `E-11`, `E-71` | F-11 | Low | `ACCESS_FINE_LOCATION` requested; only coarse resolution is used, for store lookup |
| `MASVS-PRIVACY-2` | PASS | `E-71` | — | — | Advertising identifier present but not joined to the authenticated customer ID in any observed request; verified across the full exercise including post-login |
| `MASVS-PRIVACY-3` | BLOCKED | — | — | — | Current privacy policy not provided within the assessment window; observed egress cannot be compared to a disclosure that was not available |
| `MASVS-PRIVACY-4` | FAIL | `E-72` | F-12 | Medium | Account deletion clears local state and returns success; the account remains usable via the API 24 hours later |

---

## 5. Evidence index

The table is only as good as this index. Every reference above resolves to a stored artefact a second
person can open.

| Ref | Artefact | Produced by |
|---|---|---|
| `E-11` | `evidence/11-manifest-audit.md` | [32-Manifest `manifest-audit.py`](../../32-Manifest/scripts/manifest-audit.py) on the shipped APK |
| `E-12` | `evidence/12-datadir-diff.txt` + `shared_prefs/auth.xml` extract | `tar`/`diff` across the full feature exercise |
| `E-13` | `evidence/13-logcat-filtered.txt` (pid-filtered, 41 min) | `adb logcat --pid=` during the exercise |
| `E-14` | `evidence/14-dependency-inventory.csv` | `apkid` + class-signature fingerprinting |
| `E-21` | `evidence/21-jca-trace.log` (1,412 operations) | Frida JCA hook — [34-Cryptography](../../34-Cryptography/README.md) |
| `E-22` | `evidence/22-keystore-properties.txt` | `KeyInfo` dump per key alias |
| `E-31` | `evidence/31-authz-matrix.md` (48 endpoints × 3 roles) | Burp Repeater, scripted |
| `E-32` | `evidence/32-idor-proof.http` | Request/response pair, redacted |
| `E-33` | `evidence/33-biometric-callback.smali` + runtime trace | `jadx` + Frida |
| `E-34` | `evidence/34-stepup-matrix.md` | Manual, per sensitive operation |
| `E-35` | `evidence/35-version-gate.http` | Replay with an old `User-Agent` and version header |
| `E-41` | `evidence/41-cert-failure-matrix.md` + four pcaps | `mitmproxy` with four certificate configurations |
| `E-42` | `evidence/42-pin-inventory.md` | Network security config + runtime confirmation |
| `E-51` | `evidence/51-exported-inventory.md` | `dumpsys package` + manifest audit |
| `E-52` | `evidence/52-probe-app-results.txt` | **Unprivileged probe app** — [21-App-Sandbox lab 03](../../21-App-Sandbox/labs/lab-03-attacker-app.md) |
| `E-53` | `evidence/53-webview-settings.txt` | Frida hook over `WebSettings` |
| `E-54` | `evidence/54-recents-thumbnail.png` (redacted) | Screen capture of the recents overview |
| `E-55` | `evidence/55-entrypoint-fuzz.log` | Scripted intent and provider fuzzing from the probe app |
| `E-61` | `evidence/61-obfuscation-assessment.md` | `jadx` output review — [40-Obfuscation](../../40-Obfuscation/README.md) |
| `E-71` | `evidence/71-egress-by-host.csv` | pcap, attributed by destination host |
| `E-72` | `evidence/72-deletion-followup.http` | API call 24 h after in-app deletion |

---

## 6. Coverage figure, with its denominator stated

A percentage without a denominator is a decoration. State both.

| | |
|---|---|
| Controls in the reference catalogue | 24 |
| Assessed with evidence (`PASS`, `FAIL`, `PARTIAL`) | 20 |
| Not tested by agreement | 3 |
| Blocked | 1 |
| Not applicable | 0 |
| **Coverage** | **20 of 24 (83%)**, with the four non-assessed controls itemised above |

Produced mechanically:

```bash
# host
python3 ../scripts/mas-coverage.py results.csv --markdown
```

The script will not count a `PASS`, `FAIL` or `PARTIAL` row that carries no evidence reference. That
refusal is the whole reason to run it: it catches the row you meant to come back to.

---

## 7. What this table would look like done badly

The same assessment, written by someone in a hurry. Every row below is a real reporting habit.

| Control | State | The problem |
|---|---|---|
| `MASVS-STORAGE-1` | FAIL | *(no evidence reference)* — the reader cannot check it, and neither can you in six months |
| `MASVS-CRYPTO-1` | PASS | Based on a `grep` for `"AES"`. The runtime trace is what makes this a `PASS`; a grep makes it a guess |
| `MASVS-AUTH-1` | PASS | Only one account was available. This is `BLOCKED`, and calling it `PASS` hides the entire IDOR class — which is where F-01, the Critical, actually lived |
| `MASVS-NETWORK-1` | PASS | "Burp works" tested interception, not validation. Without the four-case failure matrix this is `PARTIAL` at best |
| `MASVS-PLATFORM-1` | FAIL | Reproduced only from `adb shell`. UID 2000 holds privileges no app has; the finding may not exist for an attacker |
| `MASVS-PLATFORM-2` | PASS | The developer said there are no WebViews. Three were in the artefact |
| `MASVS-RESILIENCE-*` | *(absent)* | Silently missing. The reader cannot tell whether it passed, was skipped, or was forgotten |
| `MASVS-PRIVACY-3` | PASS | No policy existed to compare against, so nothing was verified. This is `BLOCKED` |
| — | — | No standard version, no build identity, no evidence index |

Every one of those rows produces a *higher* coverage figure than the honest table. That is the trap:
the incentive runs towards the version that cannot be checked.

---

## 8. Six rules the table encodes

| Rule | Why |
|---|---|
| Every `PASS` carries evidence | "No finding" and "passed" are different claims; only the second one is strong, and only the second one needs proof |
| `BLOCKED` is never written as `PASS` | A limitation misread as an assessment is worse than an admitted gap |
| `NOT-TESTED` names who agreed | An exclusion nobody signed is an exclusion nobody can revisit |
| `PARTIAL` says what was *not* done | It is the most honest state in the vocabulary and the most underused |
| PLATFORM findings are reproduced from an app UID | `adb shell` is not an app, and this is the commonest false positive in mobile reports |
| Severity comes from the threat model, not the control | F-03 and F-08 both violate a control; one is High and one is Low, and the control text is silent on why |

---

## 9. Where the interesting finding is not

Look at the table again. F-01, the Critical, is a **backend** authorization failure — reachable only
because the mobile client was a convenient way to discover the endpoint and the shape of a valid
request. MASVS has very little to say about it; ASVS has a great deal.

And the finding that took the most skill is not in this table at all: it did not map to a control, so
it lives in the report's "findings outside the MAS control set" appendix. That is
[`labs/lab-03-find-the-gap.md`](../labs/lab-03-find-the-gap.md), and it is the reason a coverage
table is a floor rather than a deliverable.
