# 71 — OWASP MAS · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure — which for this chapter usually means "a client asked a question during a scoping call and
you have ninety seconds".

The MAS project is unusual among security standards in that the whole thing is public, versioned, and
maintained in the open on GitHub. That is a gift and a hazard: you can always resolve an identifier,
and identifiers have moved more than once.

> **Read §2 before citing anything.** The standard was renumbered between major versions. Historical
> reports cite identifiers that no longer resolve, and copying one forward silently corrupts a
> remediation tracker.

---

## 1. The primary documents

Read these directly. They are short, and every secondary summary you will find online is pinned to
whichever version its author read.

| Resource | Why you would open it |
|---|---|
| [OWASP MAS project home](https://mas.owasp.org/) | **The entry point, and the version statement.** Start here every time you are about to write an identifier into a report — it is the fastest way to confirm which version is current |
| [MASVS](https://mas.owasp.org/MASVS/) | The controls themselves. One short page per category. Read the whole thing once — it takes under an hour and it is the only way to stop treating the categories as vague themes |
| [MASTG](https://mas.owasp.org/MASTG/) | The procedures. You will not read this end to end; you will resolve individual tests from it during an engagement. Read the *Evaluation* section of any test carefully — it is where the pass criterion lives, and where you will most often disagree for a specific app |
| [MASWE](https://mas.owasp.org/MASWE/) | The weakness catalogue. Open it when you have a confirmed observation and need the precise name for the failure, between "MASVS-STORAGE-1 is violated" and "the refresh token is in the log" |
| [MAS Checklist](https://mas.owasp.org/checklists/) | The join table: control to tests, in spreadsheet form. This is the artefact a compliance team asks for, and the one that gets read most. Use it for scoping and coverage tracking — not as a test plan, see [faq.md §20](../faq.md) |

### The repositories

Open these when the website is ambiguous, when you need to see *what changed*, or when you want to
contribute a fix rather than complain about a gap.

| Repository | Why |
|---|---|
| [`OWASP/owasp-masvs`](https://github.com/OWASP/owasp-masvs) | The standard's source, plus translations. **The release tags are how you pin a version** in a methodology statement |
| [`OWASP/owasp-mastg`](https://github.com/OWASP/owasp-mastg) | Every test, technique, tool page and demo as Markdown. `git log` on a test file tells you when a procedure changed, which matters when you are reconciling two assessments |
| [`OWASP/owasp-maswe`](https://github.com/OWASP/owasp-maswe) | The weakness catalogue's source. Useful when an entry is newer than the rendered site |

> **Why the repositories are worth knowing, not just the site.** The rendered site shows you the
> current state. A diff shows you the *history*, and history is what you need when a client's
> remediation tracker was built against an older version and you have to explain why two documents
> that both say "MASVS" disagree.

---

## 2. The renumbering, and why old reports mislead

This section exists because the problem is real, recurring, and invisible until it has already
corrupted something.

### What changed

| Change | Consequence when reading an older report |
|---|---|
| v1 requirement IDs were `MSTG-<CATEGORY>-<n>`; v2 controls are `MASVS-<CATEGORY>-<n>` | A pasted v1 ID resolves to nothing, or — worse — a reader assumes the number carried over and lands on an unrelated control |
| v1 had an **ARCH** group covering architecture, design and threat modelling. v2 has no ARCH category | Every historical ARCH finding must be re-homed **by meaning**. Most land in CODE, PRIVACY, or in the methodology narrative rather than in any control |
| v1 defined verification levels **L1 / L2 / R** inside the standard. v2 removed them from the standard body | "L2 compliant" is a v1 sentence. When a client says it in 2026, they are quoting a document, an internal policy, or a vendor — find out which before agreeing to anything |
| MASTG v1 was long narrative chapters; v2 is atomic `MASTG-TEST-<nnnn>` pages, renumbered | A v1 test reference has no one-to-one successor. Some v1 tests split into several; some merged |
| MASTG gained `TECH`, `TOOL`, `APP`, `DEMO` and `BEST` identifier families | An unadorned "MASTG-…" in an old report is ambiguous about which family it meant |
| Control counts per category changed | "We tested all N controls" is meaningless without a version |

### The drill for reading a historical assessment

| Step | Do |
|---|---|
| 1 | Find the version statement. If there is none — and often there is none — date the report, infer the version, and **say in your own report that you inferred it** |
| 2 | Translate by **category**, never by number. `MSTG-STORAGE-*` tells you the finding concerned data at rest. That is the entire safe conclusion |
| 3 | Read the finding text. Prose does not rot; identifiers do. The meaning is authoritative |
| 4 | Re-map fresh against the current standard, and write both forms: "previously reported as `MSTG-…` under MASVS v1; assessed here as `MASVS-…`" |
| 5 | If a historical finding was ARCH, decide explicitly where it now lives and say so. Do not let it vanish because its category did |

### The rule for your own writing

Never type a four-digit identifier from memory. Resolve it, paste it, and record the date you
resolved it. Where you are unsure, **describe the control and name the category** — "the test covering
local storage of sensitive data on Android" is never wrong, costs nothing, and ages better than a
wrong number. A confidently wrong control ID damages a report more than a missing one, because the
reader follows it, arrives somewhere unrelated, and begins doubting everything else.

---

## 3. Adjacent standards

You will need at least two of these on any real engagement, because MASVS does not cover the backend,
and the backend is where severity concentrates.

| Standard | Why you would open it | Relationship to MASVS |
|---|---|---|
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | **The one you will actually need most.** The web and API verification standard. Open it the moment a finding is server-side: authorization, session management, rate limiting, input handling | Complementary, not overlapping. MASVS stops at the app; ASVS covers what the app talks to |
| [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) | Fast shape for API findings when you need an awareness-level label for an executive summary | Awareness list, like the Mobile Top 10. Not a verification standard |
| [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | Communicating risk categories to non-specialists | **Not interchangeable with MASVS** — see [faq.md §2](../faq.md). Awareness versus verification |
| [OWASP SAMM](https://owaspsamm.org/) | When the client's question is "how do we stop producing these findings" rather than "what is wrong with this build" | Programme maturity, one level up from any per-app standard |
| [NIST SP 800-163 Rev.1](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final) | US federal mobile app vetting. Open it when the client is a government supplier, or when someone asks for a *process* standard rather than a control standard | Process-oriented; describes how an organisation vets apps. MASVS describes what a good app looks like |
| [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final) | Secure software development practices; increasingly cited in procurement | Development lifecycle, not app verification |
| [PCI Mobile Payments on COTS (MPoC)](https://www.pcisecuritystandards.org/) | When the app accepts card payments on the device itself. **Mandatory controls, formal labs, and an attestation process** — this is not a self-assessment | Overlaps MASVS-CRYPTO, AUTH and RESILIENCE, and goes considerably further on attestation and monitoring |
| [PCI DSS](https://www.pcisecuritystandards.org/) | When the app touches cardholder data at all | Organisational and network scope; your report becomes evidence within it |
| [ISO/IEC 27001](https://www.iso.org/standard/27001) and SOC 2 | When the client asks whether your report "counts" for their audit | Organisational, not application-level. A MASVS-mapped report is an input, not a substitute |
| [ETSI EN 303 645](https://www.etsi.org/) | IoT companion apps — the app is often the weakest part of an IoT product | Device-focused, with a companion-app section |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) / [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) / [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | OAuth 2.0, OAuth for native apps, and PKCE. **RFC 7636 is the anchor for the canonical unmappable finding** in [README §9](../README.md#9-examples) | Protocol obligations MASVS does not restate — the correct citation when a server-side OAuth behaviour is wrong |
| [FIRST CVSS](https://www.first.org/cvss/) | When a severity is disputed | Scoring, not control mapping. The rubric lives in [80-Appendix §5](../../80-Appendix/README.md#5-severity-cvss-and-business-impact) |

> **The pattern worth internalising.** MASVS answers "is this app built correctly". ASVS answers "is
> the service behind it built correctly". PCI and NIST answer "does this organisation meet an
> external obligation". Reaching for the wrong one wastes a day and produces a report the client
> cannot use.

---

## 4. Platform documentation you will cite in remediation

A finding's remediation section is far more persuasive when it cites the vendor's own guidance rather
than the standard. Developers implement what Google documents.

| Resource | Why |
|---|---|
| [App security best practices](https://developer.android.com/privacy-and-security/security-tips) | Google's own guidance. Paste the relevant subsection into a remediation and the argument is over |
| [Android security overview (AOSP)](https://source.android.com/docs/security) | The platform model behind most PLATFORM and STORAGE controls |
| [Behaviour changes, all releases](https://developer.android.com/about/versions) | **Check before asserting any version-dependent claim.** A control written against older platform assumptions may be moot on a current `targetSdk` |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Environmental findings — issues in the platform rather than the app |
| [Play Console policy and data safety](https://play.google.com/console/about/programs/datasafety/) | PRIVACY findings frequently have a policy consequence as well as a security one, and the policy consequence is what gets a fix scheduled |
| [Android Code Search](https://cs.android.com/) | Settling an argument about what the platform actually does |

---

## 5. Practice targets

The apps the labs in this chapter use. The full catalogue, with difficulty ratings, is
[80-Appendix §3](../../80-Appendix/README.md#3-vulnerable-apps-and-lab-targets) — this table is only
the subset the MAS material references.

| Target | Why this chapter uses it |
|---|---|
| [OVAA — Oversecured Vulnerable Android App](https://github.com/oversecured/ovaa) | Modern, high-quality vulnerability set with strong PLATFORM coverage. Used as the primary target in [`labs/lab-02`](../labs/lab-02-map-a-known-app.md) |
| [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) | Ships with a backend, which is the only way to practise AUTH properly. The alternative target for lab 02 |
| [DIVA](https://github.com/payatu/diva-android) | Short, focused STORAGE and CODE challenges. Good third app for the [`lab-04`](../labs/lab-04-portfolio-heatmap.md) heatmap |
| [AndroGoat](https://github.com/satishpatnayak/AndroGoat) | Kotlin source, broad coverage. Another good heatmap target |
| MASTG test apps, including the Android UnCrackable series | The canonical RESILIENCE progression. Resolve their current `MASTG-APP-*` identifiers on the site rather than citing them from memory |

> **⚠️ Warning**
> Every target above is deliberately vulnerable and licensed for this purpose. Nothing in this
> chapter authorises testing anything else. See
> [80-Appendix §11](../../80-Appendix/README.md#11-legal-reference) before you point any of this at
> an app you did not write.

---

## 6. Chapter tooling

| File | Purpose |
|---|---|
| [`scripts/mas-coverage.py`](../scripts/mas-coverage.py) | Findings list to per-control coverage and multi-app heatmap. **Refuses to call a control covered without an evidence reference**, which is the discipline the whole chapter is about |
| [`scripts/scope-checklist.py`](../scripts/scope-checklist.py) | App profile to in-scope control set, with a written justification for every **exclusion** — exclusions are where scoping is actually judged |
| [`examples/assessment-result-table.md`](../examples/assessment-result-table.md) | A worked control-by-control result table in the shape a report actually uses |
| [`examples/finding-mapped-twice.md`](../examples/finding-mapped-twice.md) | One finding mapped mechanically and then mapped thoughtfully, with the difference explained |
| [`examples/findings-ovaa.csv`](../examples/findings-ovaa.csv) | Single-app findings fixture |
| [`examples/portfolio-findings.csv`](../examples/portfolio-findings.csv) | Three-app fixture for the heatmap |
| [`examples/profile-banking.json`](../examples/profile-banking.json) | Consumer banking app profile — resilience in scope |
| [`examples/profile-internal-tool.json`](../examples/profile-internal-tool.json) | Internal managed-device app — resilience out of scope, with the reason recorded |

---

## 7. Related chapters

Chapter 71 owns **the standard and how to use it**: scoping, mapping, coverage, and its limits. Every
technical control belongs to the chapter that teaches the mechanism.

| Chapter | Relationship |
|---|---|
| [33-Storage](../../33-Storage/README.md) | MASVS-STORAGE — the mechanism behind every data-at-rest control |
| [34-Cryptography](../../34-Cryptography/README.md) | MASVS-CRYPTO-1 — algorithms, modes, parameters, randomness |
| [49-KeyStore](../../49-KeyStore/README.md) | MASVS-CRYPTO-2 — key generation, storage, hardware backing, auth binding |
| [45-OAuth](../../45-OAuth/README.md) | MASVS-AUTH — and the source of the canonical unmappable finding |
| [46-Tokens](../../46-Tokens/README.md), [47-Authentication](../../47-Authentication/README.md), [48-Biometrics](../../48-Biometrics/README.md) | The rest of MASVS-AUTH: sessions, server enforcement, `CryptoObject` binding |
| [35-SSL](../../35-SSL/README.md), [36-CertificatePinning](../../36-CertificatePinning/README.md), [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | MASVS-NETWORK-1 and NETWORK-2 |
| [24-IPC](../../24-IPC/README.md) | MASVS-PLATFORM-1 — the IPC surface and intent redirection |
| [27-ContentProviders](../../27-ContentProviders/README.md) | MASVS-PLATFORM-1 — providers, grants, traversal |
| [32-Manifest](../../32-Manifest/README.md) | MASVS-PLATFORM-1 and CODE-1 — the declaration audit and the `targetSdk` matrix |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The UID boundary every PLATFORM finding depends on — **and the probe app that makes a PLATFORM finding reproducible** |
| [43-WebView](../../43-WebView/README.md) | MASVS-PLATFORM-2 |
| [30-Activities](../../30-Activities/README.md), [31-Fragments](../../31-Fragments/README.md) | MASVS-PLATFORM-1 and PLATFORM-3 — exported Activities, task hijacking, tapjacking, and fragment injection |
| [23-Permissions](../../23-Permissions/README.md) | MASVS-PRIVACY-1 and part of PLATFORM-1 |
| [17-Libraries](../../17-Libraries/README.md) | MASVS-CODE-3 and most of PRIVACY — third-party SDKs and their egress |
| [08-Build-System](../../08-Build-System/README.md) | MASVS-CODE-1 and CODE-2 — build types, debug artefacts, manifest merging |
| [37-RootDetection](../../37-RootDetection/README.md), [40-Obfuscation](../../40-Obfuscation/README.md) | MASVS-RESILIENCE — and how to measure bypass cost honestly |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md), [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The methodologies the MASTG procedures assume you already have |
| [55-MobSF](../../55-MobSF/README.md) | Automated MASVS mapping and its false positives |
| [72-RealWorldFindings](../../72-RealWorldFindings/) | Findings written up against these controls |
| [80-Appendix](../../80-Appendix/README.md) | **The boundary.** Severity rubric, CVSS, report templates, engagement checklist. Cite it; this chapter does not restage it |
| [79-Glossary](../../79-Glossary/README.md) | Terminology |
