# 75 — Interview Questions: References

Annotated. Everything here is either generated from this repository, or a primary source you
can cite in an interview without having to hedge about where you read it.

---

## Generated index files in this directory

These three are **built mechanically** from the `## 10. Common Interview Questions` section of
every chapter README by [`../scripts/build-interview-index.py`](../scripts/build-interview-index.py).
They are regenerated, not edited. If a chapter changes, re-run the script and they are correct
again.

| File | What it is | Use it when |
|---|---|---|
| [`question-index.md`](question-index.md) | All 1,258 questions, grouped by tier, each linked to the chapter section that answers it | you want the whole corpus at your level |
| [`question-index-by-role.md`](question-index-by-role.md) | Six role tracks, with per-tier counts per chapter | you know the job title you are interviewing for |
| [`question-index-by-round.md`](question-index-by-round.md) | Six interview rounds, with the tiers each draws from and the in-scope pool per chapter | you know which stage is next |

**They deliberately contain no answers.** The link goes to the chapter that derives the answer,
because an answer read next to its question teaches recall and an answer read inside the section
that derives it teaches the derivation — which is what the follow-up question probes.

Rebuild:

```bash
# host — from 75-InterviewQuestions/
python3 -B scripts/build-interview-index.py --by tier
python3 -B scripts/build-interview-index.py --by role  --out references/question-index-by-role.md
python3 -B scripts/build-interview-index.py --by round --out references/question-index-by-round.md
```

**Corpus as measured 2026-08-16** — from `--stats`, not estimated. Two runs, ninety minutes
apart, with sibling chapters landing in between:

| | Beginner | Intermediate | Senior | Staff | Principal | Total | Chapters |
|---|---:|---:|---:|---:|---:|---:|---:|
| Run 1 | 321 | 333 | 272 | 177 | 155 | **1,258** | 71 |
| Run 2 | 337 | 346 | 286 | 187 | 164 | **1,320** | 75 |

**Neither number is a constant, and neither should be quoted.** The corpus grows every time a
chapter lands, which is precisely the argument for generating these files rather than
transcribing them. Run `--stats` for today's figure.

`--check` reported 0 problems on run 1: every chapter with a section carried all five tiers. On
run 2 it reported one chapter with a README and no section — correctly, because that chapter
was mid-write. The two reference chapters that have a README — `79-Glossary` and
`80-Appendix` — carry no interview section by design, under
[STYLE-GUIDE §4a](../../STYLE-GUIDE.md), and are excluded from the gate.

---

## This repository, as interview material

The single most valuable thing this repository offers a candidate is its record of
**measurements that contradict the received answer**. Each is verified against the chapter that
owns it, and none should be quoted without the device and the method.

| Source | Why it is here |
|---|---|
| [`../../STYLE-GUIDE.md`](../../STYLE-GUIDE.md) | The *analogy → plain → precise → internals → consequence* shape that [README §3.3](../README.md#33-the-answer-shape-and-why-it-is-this-repositorys-own-house-style) argues is also the strong-answer shape, plus the five-tier definition every §10 follows |
| [`../../39-EmulatorDetection/README.md`](../../39-EmulatorDetection/README.md) | Nine published emulator checks measured dead, four inverted. The richest single source of interview-usable contradictions |
| [`../../37-RootDetection/README.md`](../../37-RootDetection/README.md) | The `/system/xbin/su` vantage measurement — why the most-copied root check cannot answer on the device where it matters |
| [`../../47-Authentication/README.md`](../../47-Authentication/README.md) | `FLAG_SECURE`'s provably-zero true-positive rate under a string grep |
| [`../../48-Biometrics/README.md`](../../48-Biometrics/README.md) | `accept` versus `acceptCrypto`, and the 24-hour key that encrypted with no authentication at all |
| [`../../49-KeyStore/README.md`](../../49-KeyStore/README.md) · [`../../50-HardwareBackedSecurity/README.md`](../../50-HardwareBackedSecurity/README.md) | What an attestation chain proves; the property that said `green` while the TEE said `Unverified` |
| [`../../52-StaticAnalysis/README.md`](../../52-StaticAnalysis/README.md) | 16,836 hits → 168 leads → 15 of 17 rejected. The base rate behind every take-home rubric here |
| [`../../56-JADX/README.md`](../../56-JADX/README.md) | jadx under-reporting its own failures by thirty times |
| [`../../64-Xposed/README.md`](../../64-Xposed/README.md) | 1,141 keyword hits, 1,141 explained by an English word, zero findings — and the R8-manufactured false-positive class that gets worse on better-protected apps |
| [`../../61-Fastboot/README.md`](../../61-Fastboot/README.md) | `--disable-verity` as a one-byte change that breaks the image's own AVB signature |
| [`../../80-Appendix/README.md`](../../80-Appendix/README.md) | The career-progression table — what each level is expected to *do*, which is the defensive complement to this chapter's tiers |
| [`../../71-OWASP-Mobile/README.md`](../../71-OWASP-Mobile/README.md) | MASVS/MASTG/MASWE, the vocabulary every mobile security interview uses |

---

## Standards and vocabulary

Know what each of these *is*, not what is in it. Confusing MASVS with MASTG is the commonest
vocabulary error at intermediate level.

- **OWASP MASVS** — https://mas.owasp.org/MASVS/ — the standard stating what must be true.
  Categories: Storage, Crypto, Auth, Network, Platform, Code, Resilience, Privacy.
- **OWASP MASTG** — https://mas.owasp.org/MASTG/ — the guide explaining how to test it.
  Procedures, not requirements.
- **OWASP MASWE** — https://mas.owasp.org/MASWE/ — the catalogue of specific weaknesses that
  violate MASVS requirements.
- **OWASP Mobile Top 10** — https://owasp.org/www-project-mobile-top-10/ — an **awareness**
  list for communicating risk categories to non-specialists. Not a verification standard, and
  saying so is a small, cheap signal.
- **CVSS v3.1 specification** — https://www.first.org/cvss/v3-1/specification-document — the
  vocabulary most severity arguments are conducted in. Know what the attack-vector and
  attack-complexity metrics mean, because that is where mobile findings are usually contested.
- **CWE** — https://cwe.mitre.org/ — the weakness taxonomy report templates reference.

---

## Android primary sources

Naming a file is cheap evidence that your model came from the source. **Never quote a line
number** — they move, and a wrong one is worse than none.

- **Android Code Search** — https://cs.android.com/ — the practical route to every AOSP path in
  [README §4.2](../README.md#42-the-aosp-files-a-strong-answer-can-name). "I'd look it up on
  cs.android.com" is a perfectly good answer to "do you know where that lives?"
- **AOSP security documentation** — https://source.android.com/docs/security
- **Android Security Bulletins** — https://source.android.com/docs/security/bulletin — the
  source of truth for patch-level questions, and the reason
  `ro.build.version.security_patch` is a *claim* rather than evidence.
- **Verified Boot** — https://source.android.com/docs/security/features/verifiedboot
- **Key attestation** — https://developer.android.com/privacy-and-security/security-key-attestation
  — read the part about the hardware-enforced versus software-enforced authorisation lists;
  it is the whole of [README §3.6 Q4](../README.md#36-cross-cutting-questions-the-ones-no-chapter-owns).
- **App security best practices** — https://developer.android.com/privacy-and-security/security-tips
- **Android compatibility definition documents** — https://source.android.com/docs/compatibility/cdd
  — occasionally decisive when an interviewer claims a behaviour is guaranteed.

---

## Disclosure and authorisation

Relevant to [README §5.2](../README.md#52-the-take-home-that-is-unpaid-work-or-worse) and
[§5.3](../README.md#53-the-disclosure-question).

- **`security.txt` (RFC 9116)** — https://www.rfc-editor.org/rfc/rfc9116 — the standard location
  a vendor publishes a disclosure channel. Knowing it exists is a small differentiator.
- **Google Play Security Reward Program** — https://bughunters.google.com/
- **Android Vulnerability Rewards Program** —
  https://bughunters.google.com/about/rules/android-friends
- **CVE Program** — https://www.cve.org/ — identifier assignment. **Never quote an identifier
  you have not verified**; describing the class of issue is a correct and respected answer.

---

## Intentionally vulnerable targets

The only applications you should practise on, other than ones you wrote yourself. Used by
[Lab 02](../labs/lab-02-take-home-with-a-rubric.md) and referenced elsewhere in this
repository.

| Target | Character |
|---|---|
| [OVAA — Oversecured Vulnerable Android App](https://github.com/oversecured/ovaa) | broad and modern; strong on component-level and IPC issues |
| [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) | a plausible banking-app shape; storage, credentials, logging |
| [DIVA](https://github.com/payatu/diva-android) | small, sharply scoped exercises |
| [InjuredAndroid](https://github.com/B3nac/InjuredAndroid) | CTF-flavoured, good for dynamic practice |
| [OWASP MASTG crackmes](https://mas.owasp.org/crackmes/) | resilience controls and native anti-analysis |

**Public availability is not authorisation.** These are here because their authors published
them for exactly this purpose. An application from the store is not.

---

## On interviewing itself

The research literature on structured interviewing is large, contested, and almost entirely
outside security. Two claims from it are established enough to be worth knowing, and both are
recorded here **as claims about that literature**, not as measurements made in this repository:

1. **Structured interviews predict job performance better than unstructured ones.**
2. **Unstructured interviews measure the interviewer with higher reliability than they measure
   the candidate.**

Every item in [README §11.2](../README.md#112-interviewer-mistakes) is a consequence of those
two. This repository does not cite a specific meta-analysis, because it has not read one
end-to-end and its own rule is that a claim you have not verified does not get an
authoritative-looking citation attached to it. If you want to argue the point in a design
round, read the primary literature yourself first — and that instruction is the same one this
chapter gives about every measured contradiction it publishes.

---

## What is deliberately absent

Stated so nobody assumes it was overlooked.

- **No company's interview process, question bank, or leaked material.** Every stage in this
  chapter is described generically. A leaked bank is an integrity problem, and in practice it
  is also out of date.
- **No "top 100 Android interview questions" listicles.** The corpus in
  [`question-index.md`](question-index.md) is 1,258 questions attached to the chapters that
  justify their answers, which is strictly better and costs nothing.
- **No salary or negotiation material.** Out of scope, and done badly by everyone who bolts it
  onto a technical document.
- **No CVE list.** Chapter 74 owns worked public cases. Quoting a CVE identifier you have not
  verified is the fabrication this repository refuses everywhere else, and a list here would
  invite exactly that.

---

## Related chapters

| Chapter | Why |
|---|---|
| [00-Introduction](../../00-Introduction/README.md) | Reading order, and the first-hour lab this chapter's four-week programme assumes |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | The *altitude* vocabulary, and the trust-boundary framing the design round is built on |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) · [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Coverage denominators and lead-versus-finding conversion rates — the evidence behind the take-home rubric |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | The seam vocabulary behind "rate the shape, not the list" |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Where MASVS stops reaching; the fuzzing campaign that passed with a live memory-safety bug |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The commands you should be able to produce without looking them up |
| [79-Glossary](../../79-Glossary/README.md) · [80-Appendix](../../80-Appendix/README.md) | Terminology; the severity rubric, report templates, and the career-progression table |

Referenced by directory name rather than as links: `72-RealWorldFindings`, `73-Labs`,
`74-CaseStudies`, `76-CheatSheets`, `78-Diagrams`. `72` and `74` were being written in parallel
with this chapter; `73`, `76` and `78` had no `README.md` when this chapter was verified.
