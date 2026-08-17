# 71 — OWASP MAS · FAQ

Questions learners and clients actually ask, including the ones people are embarrassed to ask out
loud. Answers are direct, and where the honest answer is "it depends", the answer says what it
depends on.

---

## 1. What is the difference between MASVS, MASTG and MASWE?

They are three different *kinds of statement*, not three versions of one document.

| Document | Kind of statement | Example shape |
|---|---|---|
| **MASVS** | A claim that is true or false about an app | "Sensitive data is stored securely" |
| **MASWE** | A named way that claim becomes false | "Sensitive data written to the system log" |
| **MASTG** | A procedure with an evaluation rule | "Run logcat filtered to the app's pid while exercising every feature; the app fails if…" |

The everyday consequence: **cite MASVS to say what is wrong, cite MASTG to say what you did.** A
finding whose only reference is a MASTG test ID has told the reader your methodology and left them to
guess the requirement you believe was breached. A methodology section with only MASVS categories has
told them what you looked at and not how.

MASWE sits between the two. It is the layer that lets "MASVS-STORAGE-1 is violated" become "…because
the refresh token is written to the system log", which is the sentence a developer can act on.

---

## 2. Is the OWASP Mobile Top 10 the same thing?

**No, and the distinction matters more than it looks.**

| | Mobile Top 10 | MASVS |
|---|---|---|
| Purpose | Awareness | Verification |
| Audience | Executives, product managers, curriculum designers | Testers, auditors, developers writing requirements |
| Shape | A ranked list of risk *categories* | A set of *controls* with pass/fail semantics |
| Granularity | "Insecure Data Storage" | "Sensitive data is stored securely" plus the tests that decide it |
| Answers | "What kinds of thing go wrong on mobile?" | "Is *this app* acceptable?" |
| Updated | Occasionally, as an awareness artefact | As a maintained standard with versioned controls |

Three reasons the confusion is expensive:

1. **You cannot scope from a Top 10.** "Test for M2" does not tell you what to do or when to stop. A
   MASVS control does, because a MASTG test carries an evaluation rule.
2. **You cannot claim coverage against a Top 10.** There is no defined set of checks, so "we covered
   the Mobile Top 10" is unfalsifiable — and an auditor will eventually notice.
3. **The two do not even partition the same space.** The Top 10 is ranked by prevalence and impact
   across the whole industry; MASVS is organised by control area. A single Top 10 entry can touch
   four MASVS categories, and several MASVS categories map to no Top 10 entry at all.

Use the Top 10 in the executive summary, where a non-specialist needs a shape to hold onto. Use MASVS
everywhere else. Never let the two appear as if they were interchangeable in the same table.

---

## 3. Do I have to test every control?

No. You have to *decide* about every control, which is a different obligation and a harder one.

For each control there are exactly three defensible states:

| State | What the report must contain |
|---|---|
| **Tested, passed** | The evidence that made you say so — not the absence of a finding |
| **Tested, failed** | The finding, with severity argued from the threat model |
| **Not tested** | The reason, and who agreed to it |

The state that is not defensible is the fourth one: silently absent. A control that appears nowhere
in your report leaves the client unable to tell whether it passed, whether you ran out of time, or
whether you forgot it existed.

"Not tested" is a professional answer when it carries a reason. "MASVS-RESILIENCE was not assessed:
the agreed threat model does not include a hostile device owner" is a *better* line in a report than
four thin resilience findings, because the client can revisit the decision when their threat model
changes. See [`labs/lab-01-build-the-checklist.md`](labs/lab-01-build-the-checklist.md) — it is
entirely about justifying exclusions.

---

## 4. What does L1 vs L2 actually mean for scope and price?

First, the history, because it is the source of most of the confusion.

MASVS **v1** defined verification levels inside the standard: **L1** (baseline), **L2** (defence in
depth), and **R** (resilience) as an orthogonal add-on. MASVS **v2** removed the levels from the
standard body — the controls no longer carry an L1/L2 tag — and the job of saying "which controls
apply to this app" moved outward, to the checklist and to profile work maintained alongside it.

So the honest answer to "are we L1 or L2?" has two parts.

**What it meant, and still means informally:**

| Level | Applies to | Practical effect on testing |
|---|---|---|
| L1 | Every app | Every category gets covered, at hygiene depth |
| L2 | Apps handling sensitive data — finance, health, identity, credentials | Same categories, materially more depth: local auth binding, key management, transport identity, data minimisation |
| R | Apps where the device owner may be the adversary | Adds the whole resilience category — a different skill set and a different kind of evidence |

**What it means for scope and price:**

| | Effect |
|---|---|
| L1 → L2 | Not more controls so much as more *evidence per control*. Runtime crypto tracing instead of a code read; every endpoint replayed instead of a sample. Realistically 1.5× to 2× the days |
| Adding R | A separate workstream, not a percentage uplift. Enumerating protections is cheap; *measuring bypass cost* is open-ended and needs a time box agreed in advance |
| The trap | Quoting "L2" as a fixed number of days. Depth is continuous; the label is discrete. Quote the days and describe the depth they buy |

**What to say when a client uses the label:** ask which data the app handles and who the adversary
is. The data decides the depth; the adversary decides whether resilience is in scope. Then write the
scope statement in those terms and mention the level only as a shorthand, never as the definition.

---

## 5. Is "MASVS compliant" a meaningful claim?

On its own, no. It becomes meaningful when it carries four things:

| Missing | Why the claim collapses without it |
|---|---|
| **Version** | Controls change between major versions; ARCH existed once and does not now. "Compliant" with what? |
| **Scope** | Which categories were assessed, and which were excluded and why |
| **Depth** | A code read and a runtime trace are both "assessing MASVS-CRYPTO", and they are not the same assessment |
| **Build** | Package name, versionName, versionCode and APK SHA-256. Compliance is a property of an artefact, not of a product |

"This build was assessed against MASVS v2.x, all categories except RESILIENCE, which was excluded by
agreed threat model; two controls failed and are reported below" is a meaningful claim. "The app is
MASVS compliant" is marketing.

There is also a deeper problem worth saying to a client directly: **satisfying every control is a
floor.** It means no known category of failure was found by a known procedure. It says nothing about
the business logic flaw in the refund flow, because no committee could have written a control about
your client's refund flow. Anyone selling "MASVS compliant" as "secure" is selling the wrong thing,
and if you let them do it in your report's executive summary, your name is on it.

---

## 6. My finding maps to no control. Is it still a finding?

**Yes.** This is the single most important answer in this file, and it is
[README §5](README.md#5-security-perspective)'s whole argument.

The reasoning is short. A control set is a record of failure modes that were known and general enough
to be written down at the time the document was published. Anything genuinely novel — by definition —
is not in it. If "maps to a control" were your inclusion criterion, you would systematically discard
exactly the findings that required you rather than a tool.

What to do instead:

| Step | |
|---|---|
| 1 | Write the finding on its own merits: threat model, reproduction, evidence, impact |
| 2 | Assign severity from the impact. The absence of a control changes nothing about the risk |
| 3 | Map it to the closest category as *context*, and say in one sentence that it falls outside the letter of the standard |
| 4 | Anchor it to something external where one exists — an RFC, OWASP ASVS, a platform advisory, the client's own policy |
| 5 | Never invent a control ID to make it look mapped |

The canonical example is in [README §9](README.md#9-examples): the app sends a PKCE `code_verifier`
correctly, and the authorization server accepts the exchange without it. The app is compliant. The
security property PKCE exists to provide is entirely absent. No mobile control describes a server's
obligation. Report it under AUTH as the closest fit, cite RFC 7636, and say plainly why the mapping
is imperfect.

The inverse failure is subtler and just as bad: **stretching a control until it fits**. If you find
yourself arguing that a data-at-rest control "really covers" a server-side authorization bug, you
have stopped reporting and started negotiating with a document.
[`labs/lab-03-find-the-gap.md`](labs/lab-03-find-the-gap.md) drills this distinction deliberately.

---

## 7. Can I automate this?

Partly, and knowing exactly which part is a mark of seniority.

| Automatable | Why |
|---|---|
| Manifest flags — `debuggable`, `allowBackup`, `exported`, `usesCleartextTraffic` | Deterministic, declared, checkable |
| `minSdk` / `targetSdk` and the legacy behaviours they re-enable | A lookup table |
| Dependency versions against a vulnerability database | Mechanical, given a reliable inventory |
| Network security config parsing | XML with fixed semantics |
| Presence of debug artefacts, mapping files, instrumentation tags | Presence checks |
| **Coverage bookkeeping** | The highest-value automation in this chapter — see [`scripts/mas-coverage.py`](scripts/mas-coverage.py) |

| Not automatable | Why |
|---|---|
| Whether stored data is **sensitive** | This is the entire question for MASVS-STORAGE and it needs to know your client's business |
| Whether authorization is enforced server-side | Requires a valid session, a second account, and knowing what "should" be forbidden |
| Whether a biometric gate is cryptographically meaningful | Requires reading how the key and the callback are wired together |
| Severity | Requires a threat model |
| Whether a protection is worth its cost | Requires naming an adversary |
| Anything novel | Definitionally |

The dangerous middle ground is a tool that emits a MASVS-shaped table. It has produced a *mapping*,
not a *verdict*, and the two look identical on the page. Treat automated MASVS output as a coverage
tracker: it tells you where to look, and every row still needs a human before it enters a report.

---

## 8. Which version should I test against, and where do I say so?

Test against the current published version unless the client's compliance programme is pinned to an
older one — which happens, and is a legitimate reason.

Say so in the **methodology section**, in one sentence naming the standard, the version, and the date
you resolved it. Then repeat the version in the coverage table header, because coverage tables get
extracted from reports and circulated on their own.

The failure this prevents is specific: a year later someone compares your table to a new assessment,
finds different control IDs, and concludes one of the two testers was sloppy.

---

## 9. An old report cites `MSTG-STORAGE-2`. What is that, and does it still exist?

`MSTG-*` are the **retired MASVS v1 requirement identifiers**. They were the requirement IDs used
throughout v1-era reports and checklists. They do not resolve against the current standard, and this
is a real problem when you are reading a historical assessment or a client's remediation tracker.

Two specific traps:

- **v1 had an `ARCH` group** covering architecture, design and threat modelling. v2 has no ARCH
  category at all. Historical ARCH findings must be re-homed by meaning, usually into CODE, PRIVACY,
  or into the report's methodology narrative rather than into a control.
- **Numbers were not preserved.** `MSTG-STORAGE-2` and `MASVS-STORAGE-2` are not the same
  requirement, and assuming otherwise silently corrupts a remediation tracker.

The drill: translate by **category**, never by number. `MSTG-STORAGE-*` tells you the finding
concerned data at rest — that is all you may safely conclude without reading the finding text. Then
read the finding text, which never rotted, and map it fresh. In your own report, write both:
"previously reported as `MSTG-…` under MASVS v1; assessed here as `MASVS-…`."

---

## 10. Can I just remember the control IDs?

The **category** names, yes — there are eight and they are stable. The **control numbers** within a
category, mostly, if you work with them daily. The **four-digit MASTG and MASWE numbers**, never.

Resolve every numeric identifier at the time of writing, from
[mas.owasp.org](https://mas.owasp.org/) or the GitHub repositories, and paste it. A wrong control ID
in a report is worse than no control ID, because it is confidently wrong: the reader follows it, lands
somewhere unrelated, and now doubts everything else in the document. "The test covering local storage
of sensitive data on Android" costs you nothing and is never wrong.

---

## 11. The client says they need MASVS-RESILIENCE. Do they?

Ask one question: **who is the adversary you want this to stop?**

If they can name them — "customers who share cracked builds", "fraud rings automating our onboarding",
"a licensing bypass we have already seen in the wild" — then yes, and now you also know what to test
and how to rate it.

If they cannot, the honest answer is that resilience controls will cost them engineering effort,
complicate their crash reporting and their support workflow, break on some legitimate devices, and buy
nothing measurable. Resilience is **orthogonal** to the other categories, not a higher tier — an app
can satisfy every storage, crypto, network and auth control with zero resilience measures and be
correctly built for its threat model.

The pattern worth naming out loud when it appears: an app with root detection and obfuscation, and a
session token in plaintext `SharedPreferences`. That is a hardened door on an unlocked building, and
it usually means resilience was bought as a product and the baseline was never assessed.

---

## 12. I already have a methodology I trust. Why adopt MASVS?

Three things it gives you that a private methodology cannot, and one thing it does not.

| Gives you | |
|---|---|
| **Comparability** | Your client can compare this year to last year, and you to the other firm |
| **A shared vocabulary with the compliance side** | Their auditor already knows what MASVS-CRYPTO means; they do not know your section numbering |
| **A defence in a dispute** | "This violates a control your organisation agreed to be measured against" ends an argument that "I think this is bad" does not |

| Does not give you | |
|---|---|
| **Findings** | It tells you where to look and never what you will see |

The productive arrangement is to keep your methodology as the *how* and adopt MASVS as the *index*.
Map your existing steps to controls once, and you get the comparability without losing the depth that
made your methodology worth trusting.

---

## 13. Does MASVS cover the backend API?

Barely, and this is the most consequential gap in practice.

MASVS is a *mobile application* standard. It has controls about the app authenticating correctly and
handling sessions correctly, but the obligations of the server — enforce authorization on every
object, reject a code exchange without a verifier, rate-limit, validate — are not its subject.

Meanwhile, on most mobile engagements **the highest-severity findings are on the API**. The app is
frequently just a convenient way to discover the endpoints and the shape of a valid request.

What to do:

- Scope OWASP ASVS for the backend explicitly, as a named workstream with its own days.
- If the backend is genuinely out of scope, say so in one unambiguous sentence in the scope section.
  A client who reads "we tested your mobile product" will reasonably assume the API was included.
- When a backend finding surfaces anyway — and it will — report it. Map it to the closest MASVS
  category, note the imperfect fit, and cite ASVS. See question 6.

---

## 14. How long does a MASVS-mapped assessment take?

There is no honest single number, but there is an honest way to build one.

| Driver | Effect |
|---|---|
| Number of *features* to exercise | Dominates STORAGE and PRIVACY: you must drive every feature to see every write and every egress |
| Number of endpoints | Dominates AUTH: authorization testing is per-endpoint, per-role |
| Protections present | Dominates RESILIENCE, and is the least predictable item in the whole plan |
| Third-party SDK count | Dominates PRIVACY attribution |
| Source access | Cheapens CODE and CRYPTO; does **not** cheapen PLATFORM, which still needs a probe app |
| Device availability | No rooted device removes several categories of evidence entirely |

The ten-day banking shape in [README §9](README.md#9-examples) is a reasonable anchor. Below about
five days, say which categories you are covering at depth and which are triage only — a thin pass
across everything is the worst possible allocation, because it produces coverage claims you cannot
substantiate.

---

## 15. MobSF says the app is 72% MASVS compliant. Is that useful?

As a work queue, yes. As a finding, no. As a number in a report, actively harmful.

A percentage requires a denominator that means something. That denominator is "controls the tool can
evaluate mechanically", which is a small and unrepresentative subset weighted towards manifest flags —
the cheapest controls to satisfy and the least likely to carry real risk. The controls that decide
whether the app is safe are precisely the ones no tool can evaluate.

Worse, the arithmetic is misleading in a specific direction: an app can score highly while storing
session tokens in plaintext, because "is this data sensitive?" is not a mechanical question.

Use the output as a starting list, validate every row by hand, and never let the percentage into the
document. See `55-MobSF` for the false-positive discussion in detail.

---

## 16. Where does severity come from, if not from the control?

From the threat model, always. The control violation is a *fact*; the severity is an *argument*.

The same violation — a token in plaintext `SharedPreferences` — is Informational on an app whose
token is a five-minute read-only session on a managed corporate device, and High on an app whose
token is a thirty-day refresh token with no device binding. The control text is identical in both
cases; the report should not be.

Before rating anything, answer three questions in writing: **who** is the attacker, **what** do they
get, and **what must be true** for it to work. If you cannot answer all three concretely, you have an
observation and not yet a finding.

The rubric, the CVSS discussion and the finding template all live in
[80-Appendix §5–§6](../80-Appendix/README.md#5-severity-cvss-and-business-impact). This chapter maps;
that chapter rates. Keeping the two apart is deliberate.

---

## 17. In a finding, do I cite the control or the test?

Both, and they do different jobs.

| Field | Job | Reader who uses it |
|---|---|---|
| MASVS control | States the requirement you believe is breached | Compliance, the developer's manager, next year's tester |
| MASWE weakness | Names the specific failure | The developer |
| MASTG test | States the procedure you followed | Anyone reproducing you, including you in six months |
| Version + date resolved | Makes all three resolvable later | Everyone, eventually |

If you can only supply one, supply the control: a reader can find a test from a control far more
easily than the reverse.

---

## 18. I only have the APK and no rooted device. Can I still claim coverage?

You can claim what you can evidence, which is less than a full assessment — and saying so precisely is
the professional move.

| Category | Without root |
|---|---|
| STORAGE | Severely limited. No data-directory inspection unless the app is debuggable. Log capture still works |
| CRYPTO | Limited. Static reading only, unless you can instrument a debuggable build or use a patched APK |
| AUTH | Largely unaffected — this is network and server work, and it is where the severe findings are anyway |
| NETWORK | Mostly workable. Interception may need a repackaged APK, which changes the artefact you are testing — say so |
| PLATFORM | Workable **and still requires a probe app**, which needs no root at all |
| CODE | Unaffected |
| RESILIENCE | Largely unassessable; several protections exist specifically to stop you |
| PRIVACY | Partly workable through traffic analysis |

Write the constraint into the methodology section as a limitation, not as a footnote, and list the
controls it made unverifiable. A report that quietly claims full coverage from a constrained
environment is the kind of thing that is discovered a year later.

---

## 19. Should developers read MASVS, or is it a testing artefact?

Developers get more value per hour from it than testers do, and earlier.

A team that reads MASVS-STORAGE *before* choosing where the session token lives never produces the
finding. A team that reads it after shipping produces a finding, a ticket, a release, and a
regression test. The controls are short and written as requirements, which makes them unusually easy
to fold into a definition of done.

The failure mode to warn them about: treating it as an audit checklist run at the end of a release
cycle, which is exactly when every violation is most expensive to fix, and which trains the team to
see security as an external tax rather than a design input.

---

## 20. What is the MAS Checklist and do I need the spreadsheet?

It is a spreadsheet that joins every MASVS control to the MASTG tests that verify it. It is
maintained by the project and it is the artefact a compliance team will usually ask you for, because
it is the only one of the four that is a *tracker* rather than a *document*.

You need it for three things and not for a fourth:

| Use it for | |
|---|---|
| Scoping | Strike out what the threat model excludes; what remains is the plan |
| Coverage tracking | One row per control, one state per row, no silent gaps |
| The client deliverable | Filled in, it is often the thing that gets read most |

| Do not use it for | |
|---|---|
| Your test *plan* | It is ordered by the standard's structure, not by the app's. Testing in checklist order means logging in eight separate times and never building a mental model of the app |

[`scripts/scope-checklist.py`](scripts/scope-checklist.py) produces the scoping half of this from an
app profile, and forces a written reason for every exclusion —
[`labs/lab-01-build-the-checklist.md`](labs/lab-01-build-the-checklist.md) is the manual version of
the same discipline, and you should do it by hand once before using the script.

---

## 21. A control has several tests. Have I covered it if I ran one?

No, and this is the most common way a coverage table lies.

A control is covered when you can defend the *claim*, which usually needs more than one procedure. A
storage control covered only by a data-directory diff has said nothing about logs, backups, the
clipboard or the recents thumbnail. A network control covered only by an interception proxy has said
nothing about non-HTTP traffic.

Two practices that fix it:

- Track coverage at **test** granularity and report at **control** granularity. Then a control's state
  is derived from evidence rather than asserted.
- Record the *hook* — the specific artefact — for each control, not just a tick. If a control's
  evidence column is empty, it is not covered, whatever the tick says.
  [`scripts/mas-coverage.py`](scripts/mas-coverage.py) enforces exactly this by refusing to call a
  control covered when it has no evidence reference.

---

## Related reading

| Where | For |
|---|---|
| [README §5](README.md#5-security-perspective) | The argument that a checklist is a floor |
| [README §12](README.md#12-hands-on-labs) | The four labs and the closing assignment |
| [cheatsheet.md](cheatsheet.md) | Every control, the identifier schemes, the finding-to-control lookup |
| [references/README.md](references/README.md) | Where to read the primary documents, and the renumbering problem in detail |
| [80-Appendix](../80-Appendix/README.md) | Severity, CVSS, report templates, engagement checklist |
