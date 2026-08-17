# Lab 03 — Legal Scope Triage

> **Difficulty:** Beginner (conceptually) / Senior (in consequence) · **Time:** 45–60 minutes ·
> **Chapter:** [00 — Introduction](../README.md)

This is a paper lab. There are no commands to run and nothing to install, and it is the most
important lab in this chapter. Technical skill is what gets you a finding. Scope discipline is what
keeps the finding from becoming a criminal matter, and it is the single characteristic that
distinguishes a professional from a hobbyist with the same tooling.

> **⚠️ Warning — this is not legal advice.** The author is not your lawyer and this repository is
> educational material, not a legal opinion. Statutes are summarised here to build judgement about
> *when to ask*, not to substitute for asking. Where a real engagement is concerned, the answer to
> "is this allowed?" comes from a signed document and, where the document is ambiguous, from
> counsel. The correct professional instinct is not "I read that it is probably fine"; it is "I stop
> and get it in writing."

---

## Objective

Given six realistic scenarios, you will decide for each whether the activity is **AUTHORISED**,
**NOT AUTHORISED**, or **NEEDS CLARIFICATION**, and you will name the legal instrument that governs
the decision. You will then build a reusable pre-engagement checklist that you apply before every
future piece of work in this repository and in your career.

---

## Prerequisites

- No technical prerequisites. Do this lab before [Lab 02](lab-02-first-60-minutes.md) if you have
  any doubt at all about what you are permitted to touch.
- A willingness to answer "NEEDS CLARIFICATION" without feeling that you have failed. In this lab,
  as in real work, that answer is frequently the correct and senior one.

---

## Setup

### The one idea underneath every computer crime statute

> **🧠 Mental Model.** Nearly every computer misuse law in the world is built on a single concept:
> **authorisation**. The law does not care how clever your technique was, how trivially exposed the
> data was, or whether you intended harm. It asks one question: *did the person who controls this
> system permit you to do what you did?* A door left unlocked is still not an invitation to enter.
> Technical accessibility and legal permission are entirely independent variables, and confusing the
> two is how competent people acquire convictions.

### The instruments you should be able to name

> **📖 Definition — CFAA.** The United States *Computer Fraud and Abuse Act*, 18 U.S.C. § 1030,
> criminalises accessing a "protected computer" **without authorisation** or in a manner that
> **exceeds authorised access**. In *Van Buren v. United States* (2021) the Supreme Court narrowed
> "exceeds authorised access" to obtaining information from areas of a system that are off-limits to
> you, rather than merely using permitted access for a disallowed purpose. That narrowing helps
> researchers, but it does not create a research exemption: accessing a system you were never
> permitted to access at all remains squarely covered. The US Department of Justice has published a
> charging policy stating that good-faith security research should not be charged under the CFAA,
> but a prosecutorial policy is a promise about discretion, not a legal right, and it binds no
> private plaintiff bringing a civil claim.

> **📖 Definition — Computer Misuse Act 1990 (UK).** Section 1 creates the offence of causing a
> computer to perform a function with intent to secure **unauthorised access** to a program or data.
> Section 2 aggravates that where the access is intended to facilitate a further offence. Section 3
> covers unauthorised acts impairing operation, including denial of service. Section 3ZA covers
> unauthorised acts causing serious damage. Critically, the UK Act has **no public-interest or
> research defence**: the fact that you were trying to help, and the fact that you disclosed
> responsibly, are matters of mitigation rather than a defence to the offence. Section 1 has a low
> threshold — the mere act of causing a computer to attempt unauthorised access satisfies it.

> **📖 Definition — Information Technology Act 2000 (India).** Section 43 imposes **civil** liability
> (compensation to the affected person) for accessing a computer resource without the permission of
> its owner or the person in charge, and for downloading, extracting, damaging, disrupting, or
> introducing contaminants. Section 66 makes the same acts a **criminal** offence where they are
> committed dishonestly or fraudulently, punishable by imprisonment, a fine, or both. Section 65
> covers tampering with computer source documents. Section 72 addresses breach of confidentiality.
> As with the UK Act, permission of the owner is the pivot on which everything turns.

> **🔍 Pentester's Note.** Three practical consequences follow from the shape of these statutes.
> First, **your authorisation is only as broad as the document that grants it** — a scope excerpt in
> a chat message is not a contract. Second, **jurisdiction follows the system, the data, and you**;
> a researcher in India testing a UK company's app whose backend is hosted in the US can plausibly
> be exposed to all three regimes at once. Third, **contract law bites even where criminal law does
> not** — a terms-of-service clause prohibiting reverse engineering can support a civil claim
> whether or not any criminal statute was engaged, and app-store distribution agreements routinely
> contain one.

### The distinction that resolves half of these scenarios

There is a meaningful difference between the three things people lump together as "testing an app":

| Activity | What it touches | Typical legal analysis |
|---|---|---|
| Static analysis of an APK you lawfully possess, on your own hardware | Only your own machine | Generally not a computer-misuse offence, because no third-party system is accessed. May still breach a contractual anti-reverse-engineering clause, and copyright law's treatment of decompilation varies by jurisdiction |
| Dynamic analysis on your own device, offline or against your own backend | Your device only | Same analysis as above |
| Sending traffic to somebody else's server, or accessing another user's data | A system you do not control | This is where CFAA / CMA / IT Act §43/§66 engage directly. Authorisation is mandatory |

Most beginners assume the risky part is the decompiler. It is not. The risky part is the moment a
packet leaves your machine for a server you were not invited to.

---

## Steps

Work through each scenario in order. For each one, write down three things **before** reading the
solution:

1. Your verdict: `AUTHORISED`, `NOT AUTHORISED`, or `NEEDS CLARIFICATION`.
2. The legal instrument or contractual document that drives the verdict.
3. The single question you would ask, or the single document you would demand, to move a
   `NEEDS CLARIFICATION` to a firm answer.

---

### Scenario 1 — The bug bounty scope excerpt

You are enrolled in a public bug bounty programme. The scope page reads:

```text
IN SCOPE
  *.example.com
  com.example.mobile  (Android, Google Play)

OUT OF SCOPE
  legacy.example.com
  Any denial-of-service testing
  Social engineering of employees or users
  Physical attacks against offices or staff
  Third-party services used by Example Inc.

RULES
  Use only test accounts you create yourself.
  Do not access, modify, or store data belonging to other users.
  Report within 24 hours of discovery. Do not publish before we agree a date.
  Safe harbour: we will not pursue legal action for good-faith research that
  follows this policy.
```

You download `com.example.mobile` from Google Play, decompile it, discover a hardcoded API key, and
use that key to call `api.example.com` and enumerate 40,000 user records to prove impact.

**Your verdict?**

---

### Scenario 2 — The client statement of work

You are a consultant. The signed SOW reads:

```text
SCOPE OF WORK
  Grey-box security assessment of the ACME Retail Android application,
  version 4.2.1 (build 4210), supplied by the Client as an APK.

  Testing window: 12 May 2026 09:00 IST – 23 May 2026 18:00 IST.

  Environment: the Client's UAT environment at uat-api.acme.example only.
  Credentials for three test accounts will be supplied by the Client.

  Permitted: static analysis, dynamic instrumentation, traffic interception,
  local storage inspection, and authenticated API testing of endpoints
  reachable from the mobile application.

  Not permitted: testing against production, testing the Client's web
  properties, load or stress testing, and any testing of third-party
  payment processors.

  Point of contact for scope questions: security@acme.example
```

On day three, while intercepting traffic, you notice the app calls
`https://payments.thirdparty.example/v2/charge` directly, and the request appears to accept a
client-supplied `amount` field. Testing this would likely demonstrate a serious flaw.

**Your verdict?**

---

### Scenario 3 — The third-party app store download

A colleague sends you an APK they downloaded from a third-party mirror site. It claims to be a
popular messaging app but is 30 MB larger than the Play Store version. You want to analyse it on an
isolated emulator with no SIM, no accounts, and network access blocked at the host firewall, to
determine whether it is trojanised.

**Your verdict?**

---

### Scenario 4 — A friend's banking app

A friend is convinced their bank's Android app is insecure. They hand you their phone, verbally say
"go ahead, test it, you have my permission", and log in with their own account so you can see real
transactions. They ask you to find out whether the app stores their card number in plaintext.

**Your verdict?**

---

### Scenario 5 — A competitor's app

Your employer's product manager asks you to download a direct competitor's Android app, decompile
it, and write an internal report on the algorithms it uses for its recommendation feature and the
API endpoints it calls. Nothing will be published. The app is free on Google Play.

**Your verdict?**

---

### Scenario 6 — An app you wrote

You wrote and published an Android app yourself. It is entirely your own code, on your own Play
Console account, and it talks to a backend running on a VPS you rent and administer. You want to
root a test device, hook your own app with Frida, bypass your own certificate pinning, and fuzz your
own API.

**Your verdict?**

---

## Hints

- The strongest signal in any scope document is not what it lists as in-scope. It is what it lists
  as **out of scope**, and what it says about **other users' data**.
- "Permission" from a person is only meaningful if that person is the party entitled to grant it.
  Ask yourself who actually controls the system being accessed.
- Analysing a binary on your own machine and sending traffic to somebody else's server are
  different acts with different legal exposure. Split every scenario along that line before you
  decide.
- Safe-harbour language in a bounty policy is a **conditional** promise. It protects behaviour that
  followed the policy. It offers nothing to behaviour that did not.
- A verdict of `NEEDS CLARIFICATION` costs you an email and a day. The alternative costs
  considerably more.

---

## Solution

### Scenario 1 — Bug bounty scope excerpt

**Verdict: partially AUTHORISED, and the action taken was NOT AUTHORISED.**

Downloading, decompiling, and analysing `com.example.mobile` is authorised: the package is
explicitly in scope, and the safe-harbour clause covers good-faith research that follows the policy.
Discovering the hardcoded API key is a legitimate finding, and reporting it is exactly right.

Enumerating 40,000 user records is not authorised, and it is not a grey area. The policy states
plainly: *do not access, modify, or store data belonging to other users*. By pulling those records
you exceeded the authorisation you were given, which under **18 U.S.C. § 1030** is precisely the
"exceeds authorised access" conduct that survives *Van Buren* — you obtained information from a part
of the system that the gatekeeper had told you was off-limits. Under the **UK Computer Misuse Act
1990 s.1** the access is unauthorised because consent was expressly withheld for it, and under
**India's IT Act §43(b)** downloading or extracting data without the owner's permission gives rise
to civil liability, with **§66** available where the act is dishonest. You also stepped outside the
safe harbour, so the programme's promise not to pursue you no longer applies.

The correct action was to stop at the *minimum* evidence of impact: prove the key is valid with a
single request against your own test account, screenshot the response, and report it immediately.
Impact is demonstrated by showing the door opens, not by walking through it and inventorying the
building. Triage teams understand this; a report saying "I confirmed the key authenticates and
stopped there" is graded no lower and is very often graded higher.

> **🔍 Pentester's Note.** Every bug bounty programme's policy page is a contract of adhesion that
> you accept by testing. Read it before you touch anything, save a dated copy of it as a PDF, and
> re-read it when the programme changes. Scope changes silently, and "it was in scope last month" is
> not a defence.

---

### Scenario 2 — Client statement of work

**Verdict: NOT AUTHORISED, and it is a NEEDS CLARIFICATION that you escalate rather than test.**

The SOW is explicit twice over. It restricts the environment to `uat-api.acme.example` only, and it
separately excludes "any testing of third-party payment processors".
`payments.thirdparty.example` is both a system outside the named environment and a third-party
payment processor. Your client cannot grant you authorisation over a system they do not control,
regardless of how enthusiastic they are about the finding — authorisation must come from the party
with control over the target system.

Testing it anyway would constitute unauthorised access to the processor's systems. Depending on
where that processor's infrastructure sits, that is **CFAA § 1030** exposure in the US, **CMA 1990
s.1** in the UK, and **IT Act §43/§66** in India. It would also put your own firm in breach of the
SOW, which is a commercial and professional problem independent of the criminal one.

What you actually do is worth spelling out because it is the correct professional reflex:

1. Stop testing that request path immediately. Do not send one more probe "just to be sure".
2. Document exactly what you observed passively — the endpoint, the parameter, and why it looks
   dangerous — from traffic that the app generated on its own.
3. Email `security@acme.example`, the named point of contact, the same day. Describe the observation
   and state clearly that you have **not** tested it and will not without written authorisation from
   the processor.
4. Raise it in the report as an observation with a recommendation that the client obtain
   authorisation and have it tested, or ask the processor directly.

This produces a *better* engagement outcome than testing would have. You have given the client
something actionable, and you have demonstrated the judgement that gets consultancies re-engaged.

---

### Scenario 3 — Third-party store download

**Verdict: NEEDS CLARIFICATION, leaning AUTHORISED for the malware-triage purpose, with real caveats.**

The computer-misuse analysis is straightforward and favourable: you are analysing a file on your own
hardware, in an isolated environment, with no network egress. No third-party system is accessed, so
**CFAA**, **CMA s.1**, and **IT Act §43** are not engaged by the act of analysis itself. Malware
triage on an isolated system is routine, legitimate work performed by every security team in the
world.

The genuine issues lie elsewhere and you should be able to name them:

| Concern | Why it matters |
|---|---|
| Copyright and licence terms | The legitimate app is copyrighted. Its EULA very likely prohibits reverse engineering. Jurisdictions differ sharply: the EU Software Directive permits decompilation for interoperability in narrow circumstances, the US DMCA has a security-research exemption renewed periodically by the Copyright Office with conditions attached, and India's Copyright Act §52(1)(ab) permits certain acts for interoperability |
| Possession of malware | Some jurisdictions criminalise possessing or distributing tools and articles for computer misuse. The **UK CMA s.3A** is the clearest example, covering the making, supplying, or obtaining of articles for use in offences. Legitimate professional purpose matters, but so does being able to evidence it |
| The sample may contain unlawful content | Trojanised apps have been observed shipping stolen data. Coming into possession of a third party's personal data creates data-protection obligations under GDPR, India's DPDP Act, and equivalents |
| Egress control | "Blocked at the host firewall" must actually be true. A sample that phones home from your corporate network turns a clean analysis into an incident |

**What to clarify:** confirm your employer has a written policy permitting malware analysis, confirm
the analysis environment is genuinely isolated and approved, and confirm who you notify if the
sample turns out to contain third-party personal data. If you are doing this as an individual with
no organisational backing, the honest answer is that you should submit the sample to an established
malware-analysis service rather than hoard it.

---

### Scenario 4 — A friend's banking app

**Verdict: NOT AUTHORISED.**

This is the scenario that catches out well-meaning people, so be precise about why the friend's
permission does not help.

Your friend can consent to you handling *their phone* and to you seeing *their* account data. They
cannot consent on behalf of the **bank**, and the bank is the party that controls the systems your
testing would reach. The moment your instrumented client sends a crafted request to the bank's API,
you are accessing the bank's computer system, and the only person who could authorise that is the
bank. Under **CMA 1990 s.1** the access is unauthorised, and because a financial institution is
involved, **s.2** — unauthorised access with intent to commit or facilitate a further offence — is
in the frame if the facts are read unsympathetically. Under **IT Act §43** you would face civil
liability to the bank, and **§66** criminal exposure if any element of dishonesty is alleged.
Financial-services targets also attract regulatory attention that ordinary targets do not.

The banking app's terms of service, which your friend accepted, near-certainly prohibit reverse
engineering, unauthorised access, and account sharing. Your friend handing you a logged-in session
may itself breach their own agreement with the bank and jeopardise their fraud protections. You are
not doing them a favour.

**What you can legitimately do:**

| Action | Status |
|---|---|
| Explain to your friend how to check whether the bank runs a bug bounty or VDP | Fine |
| Analyse the APK statically, offline, on your own device, with no account and no traffic | Legally much safer, though still potentially a EULA breach |
| Point them at the bank's published security contact and let them raise a concern | Fine, and genuinely useful |
| Instrument the app while logged into their real account and probe the API | Not authorised |

If the bank runs a bug bounty programme, that programme's policy is the authorisation you need — and
it will require you to use your own test accounts, not your friend's real one. That single
requirement exists precisely because of this scenario.

---

### Scenario 5 — A competitor's app

**Verdict: NEEDS CLARIFICATION — and the decision belongs to your employer's legal counsel, not to
you.**

Split it, as always, into acts:

The **computer-misuse** analysis is mild. Downloading a free app from Google Play and decompiling it
on your own machine accesses no third-party system, so **CFAA**, **CMA**, and **IT Act §43** are not
engaged by that act alone. Enumerating the competitor's API endpoints by *calling them* is a
completely different act and would engage all three.

The **contract and IP** analysis is where the risk lives, and it is substantial:

| Instrument | Exposure |
|---|---|
| The competitor's EULA / terms of service | Almost certainly prohibits reverse engineering and competitive analysis. Breach supports a civil claim |
| The Google Play Developer Distribution Agreement and Play terms | Contain restrictions relevant to how apps obtained from Play may be used |
| Copyright law | Decompilation creates a derivative representation. Research and interoperability exemptions exist in the EU, US, and India, but *competitive product analysis* is exactly the use case those exemptions are drafted to exclude |
| Trade secrets law | If the recommendation algorithm is a protected trade secret, deriving it by reverse engineering can be actionable. The US Defend Trade Secrets Act and equivalent regimes generally treat *independent* reverse engineering of a lawfully obtained product as a proper means, but "lawfully obtained" interacts badly with a EULA you breached to obtain it |
| Your employment contract and professional obligations | Being instructed by a manager is not a defence, and it will not be your manager who is named |

**What to do:** put the request in writing, forward it to legal, and do nothing until you have a
written answer. Ask specifically: are we permitted to accept the competitor's EULA and then breach
it, and does the company accept the risk. A product manager's enthusiasm is not authorisation. This
is a case where "I need this in writing from legal" is the entire correct answer, and where a
professional who says it is doing their job rather than obstructing it.

---

### Scenario 6 — An app you wrote

**Verdict: AUTHORISED.**

You own the code, you control the Play Console account, you own or lawfully control the device, and
you administer the backend. Every party whose authorisation matters is you. Rooting your own test
device, hooking your own app, defeating your own pinning, and fuzzing your own API on your own VPS
engages no computer-misuse statute, because there is no unauthorised access anywhere in the chain.

Four caveats remain, and a senior researcher states them without being asked:

1. **Your hosting provider's acceptable use policy** governs what you may run on the VPS. Sustained
   fuzzing can look like an attack from the provider's perspective and can get the instance
   suspended. Tell them, or throttle.
2. **If the backend uses third-party services** — a payment gateway, an SMS provider, a mapping API,
   an authentication provider — those are not yours. Fuzzing that reaches them reaches somebody
   else's system, and Scenario 2's analysis applies.
3. **Real user data.** If your production app has real users and your backend holds their data, then
   testing against production implicates data-protection law even though you own the system. Test
   against a separate environment with synthetic data.
4. **Rooting the device may void its warranty** and will trip Play Integrity, which is a practical
   consideration rather than a legal one. See [62 — Magisk](../../62-Magisk/README.md).

This scenario is the model for everything in this repository. Where a lab needs a target, use an app
you wrote, a deliberately vulnerable training app published for that purpose, or a CTF you were
invited to.

---

### Verdict summary

| # | Scenario | Verdict | Governing instrument |
|---|---|---|---|
| 1 | Bug bounty, enumerated 40k user records | Analysis AUTHORISED; enumeration NOT AUTHORISED | Programme policy as contract; CFAA § 1030 "exceeds authorised access"; CMA 1990 s.1; IT Act §43(b)/§66 |
| 2 | SOW, third-party payment endpoint | NOT AUTHORISED — escalate to the named contact | The SOW itself; CFAA § 1030; CMA 1990 s.1; IT Act §43/§66. Client cannot grant rights over a system it does not control |
| 3 | Third-party store APK, isolated triage | NEEDS CLARIFICATION, leaning AUTHORISED | No computer-misuse exposure; copyright/EULA; UK CMA s.3A on articles; data-protection duties if the sample carries personal data |
| 4 | Friend's banking app, real account | NOT AUTHORISED | The bank, not the friend, controls the system. CMA 1990 s.1 and potentially s.2; IT Act §43/§66; the bank's terms of service |
| 5 | Competitor's app, internal report | NEEDS CLARIFICATION — legal decides | EULA and Play terms; copyright and its interoperability exemptions; trade secrets law. Not primarily a computer-misuse question |
| 6 | Your own app and backend | AUTHORISED | You hold every relevant authorisation. Constrained only by hosting AUP, third-party dependencies, and data-protection law over real user data |

---

### The reusable pre-engagement checklist

Copy this into your notes. Complete it, in writing, before the first command of any engagement. If
any row cannot be answered, you are not ready to start, and saying so is the job.

| # | Question | Evidence required | ✅ |
|---|---|---|---|
| 1 | Who owns the target system, and who owns the data in it? | Named legal entity, not a person's job title | ☐ |
| 2 | Who has authorised this work, and are they entitled to? | Signed SOW, bounty policy, or written client authorisation | ☐ |
| 3 | What exactly is in scope? | Explicit list of package names, hostnames, IP ranges, and app versions | ☐ |
| 4 | What is explicitly out of scope? | The exclusions list, copied verbatim into your notes | ☐ |
| 5 | Which environment may I touch? | Named hostnames. "Not production" is not a hostname | ☐ |
| 6 | What is the testing window? | Start and end date/time with time zone | ☐ |
| 7 | Which techniques are prohibited? | DoS, social engineering, physical, spam, automated scanning limits | ☐ |
| 8 | What accounts may I use? | Test credentials issued to me, in writing | ☐ |
| 9 | What is the rule on other users' data? | Written; assume "do not touch" until told otherwise | ☐ |
| 10 | Are third-party services in the request path? | Enumerated, with their authorisation status recorded separately | ☐ |
| 11 | Which jurisdictions are involved? | Where I am, where the company is, where the data is hosted | ☐ |
| 12 | Who do I contact if I find something critical or break something? | Name, email, phone, and an out-of-hours route | ☐ |
| 13 | What is the disclosure agreement? | Embargo period, publication rights, redaction requirements | ☐ |
| 14 | Is there a safe-harbour clause, and what conditions attach? | Quoted verbatim in my notes | ☐ |
| 15 | Have I saved a dated copy of the scope document? | PDF or screenshot with a timestamp | ☐ |
| 16 | What is my stop condition? | The written trigger that makes me halt and call | ☐ |

> **🔍 Pentester's Note.** Row 15 is the one people skip and the one that saves them. Scope pages
> change. Programmes get retired. A client's memory of what they authorised can be creative once a
> finding is embarrassing. A dated PDF of the scope as it stood when you tested is your record, and
> it costs ten seconds.

> **⚠️ Warning — the stop condition.** Decide *before* you start what makes you stop: evidence of a
> prior compromise, access to another customer's data, a production outage, or discovery of personal
> data you were not meant to see. In the moment, curiosity is louder than judgement. Write the rule
> down while you are still calm, and follow the rule rather than the curiosity.

---

## Success Criteria

You have completed this lab when you can:

1. State, in one sentence, the single concept that every computer-misuse statute turns on.
2. Name the US, UK, and Indian instruments and the section numbers that matter, without notes.
3. Explain why a friend's permission does not authorise testing their bank's app, in terms of who
   controls which system.
4. Explain why analysing a binary offline and sending traffic to a third-party server carry
   different legal exposure.
5. Produce your completed pre-engagement checklist for the very next thing you intend to test —
   including the labs in this repository.
6. Answer "NEEDS CLARIFICATION" out loud, to a manager, without apologising for it.

---

## Going Further

- **Read one real bug bounty policy end to end** on a platform such as HackerOne, Bugcrowd, or
  Intigriti, and map every clause of it onto the 16-row checklist above. Note which rows the policy
  answers and which it leaves silent — the silences are where the risk is.
- **Read the DOJ's published CFAA charging policy** for good-faith security research and articulate
  precisely what it does and does not give you. The distinction between prosecutorial discretion and
  a legal right is a senior-level distinction.
- **Read the primary sources.** The UK Computer Misuse Act 1990 is short enough to read in full in
  twenty minutes on `legislation.gov.uk`. Sections 43, 65, 66, and 72 of India's IT Act are
  similarly brief. Reading a statute yourself, once, permanently changes how you read summaries of
  it.
- **Follow the UK CMA reform debate.** The absence of a statutory defence for security research has
  been the subject of sustained campaigning by the UK industry, and the outcome will directly change
  the risk profile of research conducted from the UK.
- **Build your engagement template now.** Turn the checklist into a file you copy for every piece of
  work. Then apply it to the labs in this repository, so that discipline is a habit rather than a
  thing you perform when a client is watching.
- **Continue to [Chapter 01 — Computer Science Basics](../../01-Computer-Science-Basics/README.md)**
  once all three labs in this chapter are complete.

---

**Previous:** [Lab 02 — Your First 60 Minutes](lab-02-first-60-minutes.md)
