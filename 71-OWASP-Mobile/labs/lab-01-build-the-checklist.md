# Lab 01 — Build the Checklist

**Difficulty:** Beginner
**Time:** 2–3 hours
**Prerequisites:** [Chapter 71 §2–§3](../README.md#2-high-level-architecture), a browser, a
spreadsheet or text editor, Python 3.6+ for the optional script step. **No device and no APK
required** — this lab is entirely about judgement.

---

## Objective

Take the current MAS Checklist, a specific app, and a specific threat model, and produce a scoped
test plan in which **every control is either in scope with a reason or out of scope with a reason**.

The deliverable is two documents: a test plan you could hand to a junior tester, and an exclusions
table you could defend to a client who is unhappy that you did not test something.

By the end you will never again write a scope that consists of the word "MASVS".

---

## Why this matters

Scoping is the part of an engagement that decides whether the other nine days were well spent, and it
is the part nobody practises. Testers practise Frida. Nobody practises deciding what not to do.

The failure it prevents is specific and common. A tester receives "test our app against MASVS",
starts at the top of the checklist, works down, runs out of time somewhere in PLATFORM, and ships a
report covering six categories in the order the document happens to list them. Two things are wrong
with that report and neither is visible on the page:

1. The days were allocated by **document order**, not by where the client's risk actually is.
2. The categories that were never reached are simply absent, so the client cannot tell whether they
   passed, were skipped deliberately, or were forgotten.

> **📖 Definition**
> A **scope** is not a list of what you will do. It is a pair of lists: what you will do, and what you
> will not do — with the second list carrying reasons. A scope with only the first list is a *plan*,
> and a plan makes no promises the client can hold you to.

> **🧠 Mental Model**
> Inclusions are cheap to justify: "it is in the standard" is almost always sufficient. **Exclusions
> are where your judgement is actually visible**, because each one is a claim that a category of
> failure does not matter for this app. That claim can be wrong, and the client is entitled to see it
> and disagree.

There is a second, quieter reason to do this by hand once. The checklist is ordered by the standard's
structure. An app is not. Testing in checklist order means logging into the app eight separate times,
once per category, and never building the model of the application that lets you find the
interesting bug. Scoping is where you convert the standard's order into the app's order.

---

## Setup

### 1. Get the current checklist and record its version

```bash
# host
mkdir -p ~/lab71-01 && cd ~/lab71-01
```

Open <https://mas.owasp.org/checklists/> and download the current MAS Checklist. Then, before you do
anything else, write this file:

```text
# ~/lab71-01/VERSION.txt
Checklist downloaded : <date>
MASVS version stated : <version as printed in the document>
MASTG version stated : <version as printed in the document>
Source URL           : https://mas.owasp.org/checklists/
```

**This is not busywork.** Everything else in this lab is derived from a document that changes. A scope
that does not name its source version cannot be reproduced, compared to last year's, or defended when
the control IDs move — and they have moved before. See
[references/README.md §2](../references/README.md).

### 2. Pick a scenario

Three briefs follow. Do **one** properly. Then, in Step 9, do the other two quickly — the contrast is
where most of the learning is.

---

#### Scenario A — Internal expense reporting

> Mid-size engineering company, 900 employees. Android app for submitting expense claims: photograph
> a receipt, enter an amount and a category, submit for manager approval. Data is employee names,
> receipt images, amounts, cost centres. Devices are corporate-owned and MDM-managed, with a
> non-removable device passcode policy; the app is distributed through a managed Play channel and
> cannot be installed on a personal device. The backend is an internal service reachable only over
> the corporate VPN. **Three days.** The client's stated worry is "an employee seeing another
> employee's salary-adjacent expense claims".

#### Scenario B — Consumer retail banking

> Regional bank, 1.2 million customers. Full-service banking app: balances, transfers between own
> accounts, transfers to third parties, card freeze, mobile cheque deposit, biometric login. Public
> Play Store distribution to any Android device. Backend is a public API. The bank has had two
> incidents in the last year: an account-takeover wave via SIM swap, and a fraud ring automating
> onboarding with emulator farms. **Ten days.** The client's stated worry is "we do not want to be in
> the newspaper".

#### Scenario C — Children's reading app

> Education startup, 400,000 installs. Reading app for ages 5–9. Child accounts are created by a
> parent; content is downloaded and cached; usage analytics feed a "reading progress" report to the
> parent. Three third-party SDKs are present: analytics, crash reporting, and an ad network on the
> free tier. No payments in the app; subscription is purchased on the web. **Five days.** The
> client's stated worry is "we are about to be audited for children's privacy compliance".

---

## Steps

### Step 1 — Write the threat model in five lines

Before touching the checklist. Five lines, no more — the discipline is the point.

| Line | Your answer |
|---|---|
| **Assets** — what is worth stealing or breaking | |
| **Adversaries** — who, concretely, with what starting access | |
| **Entry points** — how they reach the assets | |
| **Existing controls** — what the client already has | |
| **Consequence** — what actually happens to the business if this goes wrong | |

**Question 1.** For your scenario, is the *device owner* one of the adversaries? Write one sentence
justifying your answer. If you wrote "maybe", you have not finished.

**Question 2.** Name one adversary the client did **not** mention in their stated worry, but who is
real for this app.

> **🔍 Pentester's Note**
> "Adversaries" must be people with starting access, not abstractions. "A hacker" is not an
> adversary. "Another employee with a corporate device and a valid login" is. The difference decides
> whether an exported component finding is Critical or noise, and you cannot make that call later if
> you did not write the adversary down now.

### Step 2 — Category-level pass

Eight categories. For each, write **in scope** or **out of scope**, plus one sentence. Do this before
looking at individual controls — the category call is a threat-model decision and the control calls
are budget decisions, and mixing them produces incoherent scopes.

| Category | In / Out | One-sentence reason |
|---|---|---|
| MASVS-STORAGE | | |
| MASVS-CRYPTO | | |
| MASVS-AUTH | | |
| MASVS-NETWORK | | |
| MASVS-PLATFORM | | |
| MASVS-CODE | | |
| MASVS-RESILIENCE | | |
| MASVS-PRIVACY | | |

**Question 3.** How many did you mark out of scope? If the answer is zero, you have not scoped
anything — you have restated the standard. Go back and find the one you genuinely believe does not
earn its days.

**Question 4.** For any category you marked out, write the sentence a client would say if they later
disagreed with you. Can you answer it?

### Step 3 — Control-level pass

Now open the checklist properly and go control by control. For each, one of four states:

| State | Meaning | What the report will eventually contain |
|---|---|---|
| `FULL` | Tested to depth, evidence collected | The evidence, and any finding |
| `TRIAGE` | Checked cheaply; will escalate if something surfaces | A statement that it was triaged, not assessed |
| `EXCLUDED` | Deliberately not tested | The reason and who agreed |
| `BLOCKED` | Would test, cannot — no rooted device, no second account, no test data | The limitation, stated as a limitation |

`BLOCKED` is the state people forget, and it is the most honest one in the set. It says "this is a gap
in the assessment, and it is not a decision I made about risk". Blocked controls belong in the report
under limitations, not under exclusions — conflating the two is how a client comes to believe a
category was considered and dismissed when in fact it was simply unreachable.

**Question 5.** In your scenario, name one control that is `BLOCKED` rather than `EXCLUDED`, and say
what would have to change for it to become `FULL`.

**Question 6.** Name one control you marked `TRIAGE` and state the trigger that would escalate it to
`FULL` during the engagement. A `TRIAGE` state without a trigger is just a shrug.

### Step 4 — Justify every exclusion, properly

This is the step the lab exists for. For every `EXCLUDED` control, fill in all five columns. A row
that cannot be completed is a row that should not have been excluded.

| Column | What goes in it |
|---|---|
| Control | The identifier, resolved from the checklist — not from memory |
| Reason | Why this category of failure does not matter *for this app under this threat model* |
| Who agreed | A named person on the client side, or "tester's judgement, not yet confirmed" |
| What would change it | The concrete future event that puts it back in scope |
| Residual risk | What the client is accepting by not knowing |

Three worked rows, from Scenario A:

| Control | Reason | Who agreed | What would change it | Residual risk |
|---|---|---|---|---|
| RESILIENCE-1 | Devices are corporate-owned, MDM-managed and cannot be personally provisioned. The device owner is the employer, not an adversary. Integrity checks would add support burden with no adversary to stop | R. Patel, Head of IT | The app becoming installable on BYOD devices, or handling data the employee has an incentive to alter | An employee who roots a corporate device and modifies the app would not be detected by the app itself. MDM compliance reporting is the compensating control |
| RESILIENCE-3 | Same reasoning; the app contains no client-side secret worth extracting and no logic worth hiding | R. Patel | The app gaining an embedded API key or client-side pricing/approval logic | Application logic is readable. Accepted, because the logic is not a secret |
| NETWORK-2 | The backend is internal, reachable only over the corporate VPN, and certificate issuance is controlled by the same organisation that owns both endpoints | R. Patel | The API becoming internet-reachable, or moving to a public CA | A corporate-CA-issued interception certificate would not be detected by the app. Accepted, because the interception capability is the employer's own |

Notice what those rows have in common: the reason is about **this app's situation**, never about
budget. "We ran out of days" is a legitimate thing to say — but it belongs in the limitations section,
not in an exclusions table, because it is not a risk decision.

> **⚠️ Warning**
> The single most common bad exclusion is excluding MASVS-RESILIENCE for a consumer app because
> "it's out of scope for a standard pentest". For Scenario B that is not a scoping decision, it is an
> omission: the client has an active fraud ring using emulator farms, which is a named adversary
> operating on devices they control. Resilience is the most in-scope category they have.

**Question 7.** Take your longest exclusion reason and shorten it to one sentence without losing the
argument. If you cannot, the argument was decoration.

### Step 5 — Turn the scope into a day plan

A scope in checklist order is not a test plan. Reorder it into the order you will actually work, which
is driven by dependency and by the app.

| Constraint | Consequence for ordering |
|---|---|
| You cannot test storage until you have exercised every feature | Feature exercise is day 1–2 work, and storage evidence is a by-product of it |
| You cannot test authorization until you have two accounts at different privilege levels | Request accounts on day 0, not on day 5 |
| You cannot capture traffic until interception works | Pinning bypass, if needed, blocks the entire NETWORK and AUTH workstream |
| Static triage informs everything | Manifest and dependency work goes first because it changes where you look |
| Resilience work is open-ended | Time-box it explicitly, or it eats the reporting day |

Produce a table:

| Day | Focus | Controls covered | Blocked by | Evidence produced |
|---|---|---|---|---|
| 1 | | | | |
| … | | | | |

**Question 8.** Which single dependency, if it fails on day 1, invalidates the largest part of your
plan? What is your fallback?

**Question 9.** How many days did you leave *unallocated* for the app's actual functionality — the
part no checklist describes? If the answer is zero, re-read [README §5](../README.md#5-security-perspective)
and try again.

### Step 6 — Check yourself against the script

Now, and only now, run the scoping helper on the matching profile. Doing it after the manual pass is
deliberate: the script is a cross-check, and a cross-check you run first is just an answer key.

```bash
# host
cd ~/lab71-01
python3 /path/to/71-OWASP-Mobile/scripts/scope-checklist.py \
    /path/to/71-OWASP-Mobile/examples/profile-internal-tool.json
```

Or from inside the chapter directory:

```bash
# host — from 71-OWASP-Mobile/
python3 scripts/scope-checklist.py examples/profile-internal-tool.json
python3 scripts/scope-checklist.py examples/profile-banking.json --markdown
```

The two shipped profiles correspond to Scenario A ([`profile-internal-tool.json`](../examples/profile-internal-tool.json))
and Scenario B ([`profile-banking.json`](../examples/profile-banking.json)). For Scenario C, write
your own — the profile schema is documented in the script's `--help` and in its header comment.

**Question 10.** List every control where the script's call differs from yours. For each, decide who
is right. **The script is not the answer key** — it applies stated rules to a stated profile, and it
has no idea that your client mentioned a fraud ring. Where you disagree with it and are right, that
disagreement is the value you add over a tool.

**Question 11.** The script prints a reason for every exclusion. Are any of them reasons you would be
uncomfortable defending to a client verbatim? Rewrite those in your own words — a generated
justification is a starting point, never a deliverable.

### Step 7 — Adversarial review

Hand your exclusions table to someone else — a colleague, or yourself after a night's sleep. Their job
is to attack it. Yours is to either defend or amend.

Attack prompts that work:

| Prompt | What it tests |
|---|---|
| "What if this app is later published to the public store?" | Whether your exclusions depend on distribution assumptions you never wrote down |
| "What if a third-party SDK is added next quarter?" | Whether PRIVACY and CODE exclusions assume a static dependency set |
| "What if the user is the attacker for *one* feature only?" | Whether you excluded resilience wholesale when it applies to a single flow |
| "Show me the compensating control you are relying on" | Whether "MDM manages it" is a real control or a hope |
| "Who signed off?" | Whether "the client agreed" means a named person or an assumption |

**Question 12.** Which exclusion did you amend after review? If none, find someone more hostile.

### Step 8 — Write the scope paragraph

The paragraph that goes into the report. Six sentences maximum. It must state:

1. The standard and version, with the date you resolved it.
2. Which categories were assessed and to what depth.
3. Which were excluded, and the one-line reason.
4. Which were blocked, and by what.
5. What was explicitly out of scope beyond the standard — the backend, most often.
6. The build tested, identified by package, versionName, versionCode and hash.

**Question 13.** Read your paragraph as though you were the client's auditor. Is there anything in it
you would have to ask a follow-up question about? Fix that.

### Step 9 — Do the other two scenarios in twenty minutes each

Category-level only. You are looking for the *contrast*, not for depth.

| | Scenario A | Scenario B | Scenario C |
|---|---|---|---|
| RESILIENCE in scope? | | | |
| Where do the days concentrate? | | | |
| What is the single highest-risk category? | | | |
| Which category would a lazy tester over-invest in? | | | |
| Is the backend in scope? | | | |

**Question 14.** One category has a completely different weight in each of the three scenarios. Which,
and why?

---

## Hints

<details>
<summary>Hint 1 — I cannot decide whether the device owner is an adversary</summary>

Ask instead: **does the user gain anything by breaking their own app?**

- Expense app: an employee gains nothing by rooting their own phone — they already have their own
  claims, and the fraud they might attempt is a *server-side authorization* problem, not a
  client-side one.
- Banking app: absolutely yes. Fraud rings automate onboarding, bypass device binding, and script
  transfers. The user is a paying adversary.
- Children's reading app: mostly no, though a parent bypassing a paywall is a mild case. The real
  adversary is the app's own SDK egress, which is a PRIVACY question.

If the user gains nothing, resilience buys nothing.
</details>

<details>
<summary>Hint 2 — every category feels in scope</summary>

That usually means you are scoping the *standard* rather than the *app*. Force the decision by
allocating your actual days: three days is roughly six half-day workstreams. Write the six you would
pick. Everything you did not pick is either `TRIAGE`, `EXCLUDED` or `BLOCKED`, and now you have to say
which.
</details>

<details>
<summary>Hint 3 — the client will not give me a name to record for sign-off</summary>

Then record "tester's judgement, not confirmed with client" and put those rows at the top of the
exclusions table. That is a completely legitimate state, and surfacing it usually produces the
sign-off — an unconfirmed exclusion is a thing project managers respond to.

What is not legitimate is writing "agreed with client" when nobody agreed.
</details>

<details>
<summary>Hint 4 — the script rejects my profile JSON</summary>

Run it with no arguments for the schema, or read the header comment:

```bash
# host
python3 scripts/scope-checklist.py --help
python3 scripts/scope-checklist.py --print-schema
```

The two most common errors are a missing `threat_model` block and a boolean written as a string
(`"true"` instead of `true`).
</details>

<details>
<summary>Hint 5 — how much detail belongs in "residual risk"?</summary>

One sentence naming a concrete consequence. "The client accepts that X is possible and undetected."
If you cannot name a consequence, you have either excluded something that does not matter at all — in
which case say that, it is a fine answer — or you have not understood what the control protects.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** Scenario A: no. Corporate-owned, MDM-managed devices, and the employee gains nothing by
attacking their own installation; their fraud opportunity is submitting false claims, which is a
server-side authorization and business-logic question. Scenario B: yes, emphatically — the client has
already named a fraud ring using emulator farms. Scenario C: mostly no; a parent bypassing a paywall
is the only case, and there is no in-app payment to bypass.

**2.** Scenario A: another employee's *app*, running on another managed device, using IPC. Everyone on
the fleet has the same app installed and MDM does not isolate apps from each other. Scenario B: a
malicious app installed alongside the banking app on a customer's own device — overlay, accessibility
abuse, exported component reachability. Scenario C: the ad SDK itself, which is an adversary the
client contracted with and does not think of as one.

**3.** For Scenario A, two or three: RESILIENCE almost certainly, and arguably NETWORK-2. For B,
probably none at category level. For C, arguably none, though several controls within AUTH and CRYPTO
will drop to `TRIAGE`. A scope with zero exclusions is either a very high-risk app or an unscoped
engagement.

**4.** For A/RESILIENCE, the client's objection would be: "what if someone roots a corporate phone?"
The answer: they can, and MDM compliance reporting is the control that detects it; the app adding its
own root check would duplicate that at the cost of support burden and would not stop a determined
insider. That answer is defensible. Notice that it names a compensating control — an exclusion
without one is much weaker.

**5.** Scenario B: any control requiring a second customer account at a different privilege level.
That is `BLOCKED` until the client provisions test accounts, not `EXCLUDED`. It becomes `FULL` the
moment two accounts exist. Scenario A: anything needing a rooted corporate device that MDM will not
permit.

**6.** A reasonable one for Scenario C: CRYPTO-1 at `TRIAGE`, with the trigger "any locally stored
value that looks like a credential, or any custom crypto in the content-caching path". If neither
appears, a static read is proportionate. If either appears, escalate to a runtime JCA trace.

**7.** The test is whether the sentence survives without the surrounding context. "Corporate-owned
MDM-managed devices mean the device owner is the employer, not an adversary" survives. "We discussed
this at length and felt that given the environment it was probably not necessary" does not.

**8.** Scenario B: establishing interception. If pinning cannot be bypassed on day 1, NETWORK, AUTH
and half of PRIVACY are blocked simultaneously. Fallbacks, in order of preference: a client-provided
debug build with pinning disabled, a patched APK (state clearly that you tested a modified artefact),
or Frida-based unpinning. Agree the fallback **before** the engagement, because discovering it on day
1 costs you a day.

**9.** For a ten-day engagement, at least one full day, and arguably two. This is not slack — it is
the only time allocated to finding what the checklist cannot describe, which is the part of the
report that will differ from a competitor's. See [`lab-03`](lab-03-find-the-gap.md).

**10.** Expect divergence on RESILIENCE for Scenario B if your profile does not encode the fraud
ring, and on PRIVACY for Scenario C if your profile does not encode the child-user attribute. Both
are cases where the script is applying general rules and you hold specific facts. You are right; the
script is not wrong, it is uninformed. Record the divergence — it is exactly what a scoping call is
for.

**11.** The generated reasons are deliberately generic ("no hostile-device-owner adversary declared
in the profile"). That is fine as an internal note and thin in a client document, because it cites
your own input rather than the client's situation. Rewrite as: "corporate-owned MDM-managed devices;
the employer, not an adversary, controls the device."

**12.** The most common amendment is a RESILIENCE exclusion that survived category level but should
not have survived feature level — one flow in the app (a licence check, an offline mode, a stored
value) has a hostile-user incentive even though the app as a whole does not. Scope resilience to that
flow rather than excluding it wholesale, and say so.

**13.** Common follow-ups an auditor will raise: "against which version?", "was the backend included?",
"what does 'assessed' mean for the categories you did not find anything in?", and "which build?".
All four are answerable in the six sentences; if yours are not, they are missing.

**14.** **PRIVACY.** In Scenario A it is nearly trivial — an internal app, no third-party SDKs, data
the employer already holds. In Scenario B it is real but secondary to AUTH. In Scenario C it is the
single highest-risk category and the reason the engagement exists: child users, three third-party
SDKs including an ad network, and an imminent regulatory audit. The same control text, three
completely different weights — which is the whole argument for scoping from a threat model rather
than from the document.

</details>

---

## Success criteria

- [ ] You recorded the checklist version and source date before doing anything else
- [ ] You wrote a five-line threat model naming adversaries with concrete starting access
- [ ] You made a category-level in/out call for all eight categories, each with a reason
- [ ] You assigned every control one of `FULL`, `TRIAGE`, `EXCLUDED`, `BLOCKED`
- [ ] You can explain the difference between `EXCLUDED` and `BLOCKED` without hesitating
- [ ] Every exclusion has all five columns filled in, including residual risk
- [ ] No exclusion reason is "we ran out of days" — those are limitations, and they are elsewhere
- [ ] Your day plan is in dependency order, not checklist order
- [ ] You left unallocated time for functionality no checklist describes
- [ ] You ran [`scripts/scope-checklist.py`](../scripts/scope-checklist.py) **after** your manual
      pass and reconciled every difference
- [ ] Someone attacked your exclusions and you amended at least one
- [ ] You wrote a six-sentence scope paragraph an auditor would not need to follow up on
- [ ] You compared all three scenarios at category level and can say why PRIVACY differs most

---

## Where next

| Then do | For |
|---|---|
| [`lab-02-map-a-known-app.md`](lab-02-map-a-known-app.md) | Executing a scope like this against a real vulnerable app and producing the result table |
| [`lab-03-find-the-gap.md`](lab-03-find-the-gap.md) | The findings your scope could never have predicted |
| [80-Appendix §7](../../80-Appendix/README.md#7-the-engagement-checklist) | The operational checklist that runs *inside* a scope like this one |
