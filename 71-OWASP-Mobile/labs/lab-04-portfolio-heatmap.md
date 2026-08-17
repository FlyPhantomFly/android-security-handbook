# Lab 04 — Portfolio Heatmap

**Difficulty:** Advanced
**Time:** 8–12 hours, realistically across three sessions
**Prerequisites:** [`lab-02`](lab-02-map-a-known-app.md) completed at least once,
[Chapter 71 §9 "Enterprise"](../README.md#9-examples), three deliberately vulnerable apps installed
and working, Python 3.6+

---

## Objective

Assess **three different apps against the same control subset, using the same rubric**, produce a
heatmap, and extract from it the **systemic themes** — the shared causes that explain several
findings at once.

The deliverable is not three assessments. It is one document that tells a programme owner where to
spend engineering effort so that fixing one thing fixes several apps.

---

## Why this matters

At one app, the unit of analysis is the **bug**. At forty apps, the unit of analysis is the **cause**,
and the two demand completely different work.

An organisation with forty mobile apps does not want forty reports. Forty reports produce forty
backlogs, forty owners, and forty independent decisions about whether a Medium is worth a sprint. What
that organisation needs is the sentence "the same internal networking library ships in twenty-six of
your apps and it disables hostname verification in its debug configuration, which four of them ship" —
because that sentence has one owner, one fix, and twenty-six beneficiaries.

You cannot produce that sentence from forty independent reports written by different people to
different depths. You can only produce it from **comparable measurement**, and comparability is a
methodological property you have to design in before you start testing.

> **🧠 Mental Model**
> A heatmap of inconsistently-measured apps measures **the testers**, not the apps. If tester A goes
> deep on storage and tester B goes deep on network, the heatmap shows you who tested what. Every
> methodological decision in this lab exists to prevent that specific artefact.

> **⚠️ Warning**
> A heatmap is a management artefact, and management artefacts become targets. The moment a control
> pass rate becomes a team KPI, teams optimise the metric: they satisfy the cheap controls, dispute
> the expensive ones, and route work away from the apps that would score badly. Step 9 addresses this
> directly, and if you produce heatmaps for a living it is the most important step in the lab.

---

## Setup

### Choose three apps

You need three that differ enough to make comparison interesting and overlap enough to make it
possible.

| App | Why it earns a place | Expect it to be weak in |
|---|---|---|
| **OVAA** | Modern, broad PLATFORM surface | PLATFORM, and parts of STORAGE |
| **InsecureBankv2** | Has a backend, so AUTH is real | AUTH, STORAGE, CRYPTO |
| **DIVA** or **AndroGoat** | Short, focused, different author | STORAGE, CODE, CRYPTO |

Any three work. What matters is that they were written by different people, because **different
authorship is what makes a shared finding interesting**. Two apps by the same author sharing a flaw
tells you about the author. Three apps by three authors sharing a flaw tells you about the platform,
the ecosystem, or the documentation — and those are the findings a programme owner can act on.

```bash
# host
mkdir -p ~/lab71-04/{apps,evidence,results} && cd ~/lab71-04
```

Record the three artefacts properly. Comparability starts here:

```bash
# host — one line per app, and keep it
for f in apps/*.apk; do
  echo "$f  $(sha256sum "$f" | cut -d' ' -f1)"
done | tee results/00-artefacts.txt
```

---

## Steps

### Step 1 — Choose the control subset, and justify it

You are **not** assessing every control on every app. Three reasons, and understanding them is half
the lab:

| Reason | |
|---|---|
| **Cost** | Full depth on 24 controls times three apps is a fortnight. At forty apps it is impossible, and the technique has to scale to forty or it is not a portfolio technique |
| **Comparability** | Every control you add is another place where your rigour can drift between apps. A smaller subset measured identically beats a larger subset measured variably |
| **Signal** | Systemic causes cluster. A well-chosen subset of eight to twelve controls surfaces almost all of them |

Choose your subset now and write the justification. A defensible starting set:

| Control | Why in the subset | Cost per app |
|---|---|---|
| STORAGE-1 | Highest-frequency real finding; cheap once the exercise is done | Medium |
| STORAGE-2 | Log leakage is near-universal and near-free to check | Low |
| CRYPTO-1 | A runtime trace answers it definitively and comparably | Medium |
| CRYPTO-2 | Key handling is where copy-paste patterns show most clearly | Medium |
| NETWORK-1 | Mechanically checkable *and* runtime-verifiable; strong systemic signal via shared libraries | Low |
| PLATFORM-1 | The largest attack surface, and shared SDKs inject components | High |
| CODE-1 | Almost free from the manifest, and a strong proxy for maintenance discipline | Low |
| CODE-3 | Dependency inventory is the single best source of systemic findings | Medium |
| PRIVACY-1 | Permission-to-use justification exposes copy-pasted manifests immediately | Low |

**Question 1.** Which control did you *exclude* that you would have included for a single-app
assessment, and why is the trade-off different at portfolio scale?

**Question 2.** Your subset must be answerable at roughly equal cost on all three apps. Which of your
chosen controls is most likely to cost dramatically more on one app than another, and what will you
do about it?

### Step 2 — Write the rubric before you test anything

This is the step that separates a real heatmap from a coloured table of opinions.

For every control in the subset, write the pass criterion **in advance**, in falsifiable terms. Not
"stores data securely" — that is the control text and it is not a criterion.

| Control | PASS if… | FAIL if… | PARTIAL if… | Evidence required |
|---|---|---|---|---|
| STORAGE-2 | No value matching the credential pattern set appears in logcat during the standard exercise | Any such value appears | A value appears only in a debug build, or is truncated/masked | Filtered logcat with the app's pid, for the standard exercise |
| NETWORK-1 | App refuses connection for all four bad-certificate cases | Connects for any | Refuses some | The four-row failure matrix, with captures |
| CODE-1 | `targetSdk` within N of current, no debug artefacts | `debuggable` true, or `targetSdk` older than the platform's minimum for new submissions | `targetSdk` current, one debug artefact present | `aapt2 dump badging` plus manifest audit output |
| … | | | | |

Two rules that make the rubric hold:

- **The criterion must not mention the app.** If you find yourself writing "PASS if the token is
  handled reasonably given that this app…", you have written an excuse, not a criterion.
- **Define the "standard exercise" once**, and use it identically on all three apps: launch, register
  or log in, visit every top-level screen, trigger one error, background and resume, log out. Write it
  down. Deviating on one app silently destroys comparability.

**Question 3.** Write the standard exercise for your three apps. Which app makes it hardest to follow
identically, and how did you adapt without breaking comparability?

**Question 4.** Take one rubric row and try to defeat it: describe an app that would pass your
criterion while being obviously insecure. Fix the criterion.

### Step 3 — Test column-wise, not row-wise

**This is the most important methodological move in the lab and it is counter-intuitive.**

The obvious approach is to assess app 1 completely, then app 2, then app 3. Do not. Instead, take one
control and assess it on all three apps back to back, then move to the next control.

| Row-wise (app at a time) | Column-wise (control at a time) |
|---|---|
| Your understanding of a control deepens as you go, so app 3 gets a stricter assessment than app 1 | You apply one interpretation of one criterion three times in twenty minutes |
| Tooling is set up and torn down repeatedly | Set the tooling up once per control |
| Differences you notice are between apps *and* between your own two states of mind | Differences you notice are between apps |
| Systemic patterns emerge late, if at all | Patterns are visible immediately — you see the same weakness three times in a row |

The drift is real and it is large. On a row-wise pass, the first app is almost always assessed most
leniently, and it is entirely invisible in the output.

**Question 5.** Run one control column-wise across all three apps and time it. Then estimate how long
the same control would have taken you row-wise, including tooling setup three times. What is the
ratio?

**Question 6.** During a column, did you change your interpretation of the criterion partway through?
If so, **go back and re-assess the apps you had already done.** Note that you would not have noticed
this row-wise.

### Step 4 — Record results in a single machine-readable file

One row per (app, control) pair. No exceptions, including for the pairs you did not test.

```csv
app,control,state,evidence,finding,note
ovaa,MASVS-STORAGE-1,FAIL,evidence/ovaa-datadir-diff.txt,F-01,Token plaintext in shared_prefs
ovaa,MASVS-STORAGE-2,FAIL,evidence/ovaa-logcat.txt,F-02,Token logged on refresh
insecurebankv2,MASVS-STORAGE-1,FAIL,evidence/ib2-datadir-diff.txt,F-11,Credentials in SQLite
diva,MASVS-STORAGE-1,FAIL,evidence/diva-datadir-diff.txt,F-21,Credentials in shared_prefs
...
```

A worked three-app fixture in exactly this shape ships as
[`examples/portfolio-findings.csv`](../examples/portfolio-findings.csv). Use it to check your tooling
works before you have your own data.

**Question 7.** How many rows should your file have? (Number of apps times number of controls,
exactly. If it has fewer, something was silently skipped — which is the whole failure mode this
format prevents.)

### Step 5 — Generate the heatmap

```bash
# host — from 71-OWASP-Mobile/
python3 scripts/mas-coverage.py examples/portfolio-findings.csv --heatmap
```

```bash
# host — your own data, as Markdown for the report
python3 /path/to/71-OWASP-Mobile/scripts/mas-coverage.py \
    ~/lab71-04/results/portfolio.csv --heatmap --markdown \
    | tee ~/lab71-04/results/heatmap.md
```

Read the output three ways, in this order:

| Read | Question it answers |
|---|---|
| **By row (control)** | Which controls fail across the portfolio? These are the systemic candidates |
| **By column (app)** | Which apps are weakest overall? These are the remediation priorities |
| **By blank** | Which cells have no state at all? These are gaps in *your* work, and they must be zero |

**Question 8.** Which controls fail on all three apps? Which fail on exactly one? Write both lists —
they lead to completely different recommendations.

### Step 6 — Find the systemic causes

A control failing on all three apps is a *pattern*. A pattern is not yet a cause. Turn one into the
other.

For each pattern, generate hypotheses and then **test them**:

| Hypothesis class | How to test it | If confirmed, the recommendation is |
|---|---|---|
| **Shared dependency** | Compare library inventories across the three apps; look for the same library and version | Fix or replace the library once |
| **Shared internal SDK or template** | Compare class names, package structure, and identical code shapes | Fix the template; the apps inherit the fix |
| **Copy-pasted pattern** | The same *code shape* with different names — a copied StackOverflow answer, not a shared binary | Publish a secure internal reference implementation |
| **Platform default** | Does the failure follow from a default nobody overrode? | Fix in a shared Gradle configuration or a lint rule |
| **Missing guidance** | No shared cause; three teams each invented the same wrong thing | Write the guidance and add a CI check |
| **Coincidence** | With three apps, this is a live possibility. Be honest about it | Nothing yet — flag for confirmation at larger n |

```bash
# host — the shared-dependency hypothesis, mechanically
for app in ovaa insecurebankv2 diva; do
  echo "== $app"; cat evidence/$app-dependencies.txt
done | sort | uniq -c | sort -rn | head -30
```

**Question 9.** Pick your strongest pattern and work all the way to a cause. What evidence would
*disprove* your hypothesis? If you cannot answer that, you have a story rather than a finding.

**Question 10.** For one pattern, the honest answer is "coincidence, n is too small". Which one, and
what would you need to raise confidence?

> **🔍 Pentester's Note**
> The most valuable systemic finding is usually the least dramatic one. "All three apps request a
> permission they never use" is not exciting, but it points at a copy-pasted manifest template, which
> means there is a shared origin — and the shared origin will be carrying other things too. Follow the
> boring pattern back to its source; interesting things live there.

### Step 7 — The n=3 honesty problem

Three apps is enough to generate hypotheses and nowhere near enough to confirm them. Say so, in the
report, in these terms:

| Observation | What you may claim at n=3 | What you may not |
|---|---|---|
| Fails on 3/3 | "Present in every app assessed; a systemic cause is likely and the following hypothesis is testable" | "Affects the whole portfolio" |
| Fails on 2/3 | "Present in two of three; worth checking against the wider estate" | "Affects two-thirds of your apps" |
| Fails on 1/3 | "App-specific in this sample" | Anything about the portfolio |
| Passes on 3/3 | "No failure observed in this sample, against this criterion" | "The portfolio is strong here" |

**Question 11.** Rewrite your strongest claim twice: once as you *want* to say it, and once as the
evidence actually supports. Which one goes in the report? (Both, if you are good — the first as the
hypothesis, the second as the finding.)

### Step 8 — Write the programme report

Completely different shape from a per-app report. Structure:

| Section | Content | Length |
|---|---|---|
| **Method** | Subset, rubric, standard exercise, apps, dates, versions, and the column-wise procedure — because the method is what makes the numbers comparable | 1 page |
| **The heatmap** | The table itself, with a legend that defines every state | 1 page |
| **Systemic themes** | Three to five, each with: pattern, hypothesis, evidence, confidence, single owner, single fix | 2–3 pages |
| **App-specific findings** | Everything that did not generalise, one line each with a pointer | 1 page |
| **What is working** | Controls that passed everywhere, with the evidence. This is not padding — it is what stops the programme from re-litigating solved problems | Half a page |
| **Limitations** | n, subset, what was not assessed, and the drift risks you mitigated | Half a page |

**Question 12.** Your themes section names an owner per theme. For a shared library, who is that? For
a copy-pasted pattern with no shared binary? The second is harder, and the answer tells you why
"publish a reference implementation" is a real recommendation and "tell teams to be careful" is not.

### Step 9 — Anticipate the metric being gamed

You are handing an organisation a scoreboard. Write the section that protects it.

| Gaming behaviour | How it shows up | Counter-measure to recommend |
|---|---|---|
| Satisfying only cheap controls | Pass rate climbs; severe findings do not fall | Report severity-weighted results alongside raw pass rates |
| Disputing expensive findings | Rising volume of "risk accepted" | Track accepted risk as a first-class number, with an owner and an expiry |
| Routing new work to unassessed apps | Portfolio coverage stalls while pass rates rise | Report coverage (apps assessed) as prominently as pass rate |
| Optimising for the subset | Controls outside the subset silently rot | Rotate part of the subset each cycle, and say that you will |
| Fixing the finding, not the cause | Same failure reappears next cycle in a new app | Track recurrence explicitly; a repeat is a process finding, not an app finding |

**Question 13.** Which of these is your heatmap most vulnerable to, given the subset you chose? Add
the counter-measure to your limitations section.

**Question 14.** What would you measure *instead of* control pass rate, if you could measure only one
thing about this portfolio? Defend it in two sentences.

### Step 10 — Repeat one control at a distance

If you have the time, come back a week later and re-assess a single control on all three apps without
looking at your earlier results. Then compare.

**Question 15.** Did you reach the same verdicts? Any disagreement with yourself is a measure of how
reproducible your rubric is — and if you cannot reproduce yourself, two testers certainly cannot
reproduce each other. Tighten the criterion that drifted.

---

## Hints

<details>
<summary>Hint 1 — the three apps are too different to compare</summary>

That is a real constraint and the answer is not to force it. Narrow the subset until every control in
it is meaningful for all three. A control that cannot apply to one app is not a `FAIL` for that app —
it is `N/A`, and `N/A` must be a distinct state in your rubric, or your heatmap lies by omission.

For example: NETWORK-2 (pinning) is not meaningfully assessable on an app with no backend. Mark it
`N/A` with a reason, and exclude it from any percentage you calculate.
</details>

<details>
<summary>Hint 2 — the heatmap is entirely red and tells me nothing</summary>

You picked three deliberately vulnerable apps, so that is expected — and it is a useful lesson about
real heatmaps too. Two fixes:

- **Increase resolution.** Split `FAIL` into severity bands, or count failing *instances* per control
  rather than a binary. "Six plaintext-storage sites" and "one" are different states of the world.
- **Change the question.** With everything failing, the interesting axis is *which failures share a
  cause*, not which controls fail. Go straight to Step 6.
</details>

<details>
<summary>Hint 3 — I cannot get a dependency inventory that compares across apps</summary>

Normalise to something stable rather than to version strings, which are often absent:

```bash
# host — package prefixes present in each app, which survives obfuscation better than version strings
jadx -d src/ app.apk >/dev/null 2>&1
find src/ -name '*.java' | sed 's|src/sources/||; s|/[^/]*$||' | \
  cut -d/ -f1-3 | sort -u > deps.txt
```

Then `comm` or `sort | uniq -c` across the three files. Shared third-party package prefixes are your
shared-dependency candidates.
</details>

<details>
<summary>Hint 4 — the script rejects my CSV</summary>

Check the header row and the state vocabulary:

```bash
# host
python3 scripts/mas-coverage.py --help
head -1 examples/portfolio-findings.csv
```

The commonest errors are a missing `app` column (which puts it in single-app mode) and a state string
outside the allowed set — states are validated deliberately, because a typo'd state that is silently
ignored is how a cell goes blank without anyone noticing.
</details>

<details>
<summary>Hint 5 — how many themes should I find?</summary>

Three to five is the useful range for a report. Fewer and you have probably stopped at patterns
without working through to causes. More and you have listed findings rather than synthesised them —
if a "theme" has one owner and one app, it is a finding.

The compression test: could the programme owner act on each theme with a single decision? If not, it
is not yet a theme.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** RESILIENCE is the usual exclusion, and correctly so: bypass cost is open-ended, varies wildly
between apps, and is the least comparable measurement in the whole standard. At single-app scale it
may be the most important category; at portfolio scale it destroys the property the exercise depends
on. Say so explicitly rather than dropping it silently.

**2.** PLATFORM-1 almost always. An app with three exported components and one with forty are not the
same measurement, and forty will get less careful treatment simply through fatigue. Mitigations: cap
the effort per app and record the cap; or measure a normalised quantity (proportion of exported
components reachable from a probe app) rather than an absolute count.

**3.** InsecureBankv2 usually makes it hardest, because its flows depend on a backend that behaves
differently from a modern app's. Adapt by defining the exercise in terms of *user intent* — "complete
one primary transaction" — rather than in terms of specific screens, and record the concrete steps you
took per app in an appendix so a reader can judge equivalence themselves.

**4.** Almost every first-draft criterion is defeatable. The classic: "PASS if no credential-shaped
string appears in logcat" is defeated by an app that base64-encodes the token before logging it. Fix
by adding a decoding pass to the criterion, and note that this is exactly how criteria get better —
by being attacked before they are used, rather than after the results are published.

**5.** Column-wise is typically two to three times faster overall, and the saving is almost entirely
tooling setup and mental context switching. The more important benefit is not speed: it is that you
apply one interpretation three times in twenty minutes rather than three interpretations over three
days.

**6.** Interpretation drift within a column is common and it is *good* that you can see it — that is
the point of the ordering. Re-assess the earlier apps. Row-wise, this drift happens too, but between
apps and days, where nothing surfaces it.

**7.** Exactly apps times controls. Nine controls times three apps is 27 rows, including `N/A` and
`BLOCKED` rows. Any fewer means a pair was skipped; the format exists so that skipping is impossible
to do quietly.

**8.** Controls failing on all three are systemic candidates and lead to "fix the shared cause"
recommendations. Controls failing on exactly one lead to "fix this app" recommendations. The two get
different owners, different urgency and different sections of the report — collapsing them into one
findings list is what makes portfolio reports useless.

**9.** A real hypothesis is disprovable. "All three use the same vulnerable HTTP library" is disproved
by finding that two of them use different libraries with the same defect — which would point instead
at a documentation or ecosystem cause, and would be a *more* interesting finding. If you cannot state
the disproof, you have narrative, not analysis.

**10.** Usually a CODE or PRIVACY pattern: three deliberately vulnerable teaching apps all requesting
excessive permissions is much better explained by "they are teaching apps" than by any shared cause.
Raising confidence needs either more apps or a mechanism — find the shared template and you no longer
need n.

**11.** Want to say: "the portfolio has a systemic TLS validation problem." Evidence supports: "TLS
validation failed in all three apps assessed; in two, the failure originates in the same third-party
component, which we recommend checking across the wider estate." The second is weaker as a sentence
and stronger as a finding, because it survives being checked.

**12.** For a shared library, the owner is the team that maintains it, and the fix is one version bump
— which is why shared-dependency themes are the most valuable ones you can find. For a copy-pasted
pattern there is no owner, and that is precisely the finding: the recommendation must create one.
"Publish a reviewed reference implementation and a lint rule that detects the bad shape" creates an
owner and a mechanism. "Remind teams to validate certificates" creates neither and will be in next
year's report unchanged.

**13.** Subsets weighted towards cheap, mechanically-checkable controls (CODE-1, PRIVACY-1, STORAGE-2)
are most vulnerable to cheap-control optimisation, because the pass rate can be moved substantially
without improving security. Counter by reporting severity-weighted results alongside the raw rate, and
by rotating part of the subset each cycle.

**14.** A defensible answer: **time from finding to fix, for findings of a given severity.** It
measures the thing that actually reduces risk — the organisation's capacity to respond — rather than
the state of a sample at a moment. It is also much harder to game, because gaming it requires
actually fixing things. Any answer is acceptable if it is defended; the point is noticing that pass
rate is a proxy and a weak one.

**15.** Most people disagree with themselves on at least one cell, and it is almost always a
`PARTIAL`/`FAIL` boundary. That is the criterion to tighten. Self-disagreement at one week is the
cheapest possible measure of inter-rater reliability, and it is the number that decides whether your
heatmap can survive being produced by a team rather than by you.

</details>

---

## Success criteria

- [ ] You chose a control subset and wrote the justification for both inclusions and exclusions
- [ ] You wrote a falsifiable pass criterion for every control **before** testing
- [ ] You defined one standard exercise and applied it identically to all three apps
- [ ] You tested column-wise and can explain why row-wise would have biased the result
- [ ] You re-assessed earlier apps whenever your interpretation shifted mid-column
- [ ] Your results file has exactly apps × controls rows, with `N/A` and `BLOCKED` as real states
- [ ] You generated the heatmap with [`scripts/mas-coverage.py`](../scripts/mas-coverage.py) and read
      it by row, by column, and by blank cell
- [ ] You have zero blank cells
- [ ] You turned at least one pattern into a cause, with a stated disproof
- [ ] You identified at least one pattern that is honestly just coincidence at n=3, and said so
- [ ] Every theme has one owner and one fix
- [ ] Your report contains a limitations section that names the n=3 problem in plain terms
- [ ] You wrote the section on how the metric will be gamed, before anyone games it

---

## Where next

| Then do | For |
|---|---|
| [`lab-03-find-the-gap.md`](lab-03-find-the-gap.md) | If you have not — the heatmap will never contain the finding that lab produces, which is exactly the point |
| [`examples/assessment-result-table.md`](../examples/assessment-result-table.md) | The single-app table this lab aggregates |
| [80-Appendix §6](../../80-Appendix/README.md#6-report-templates) | The executive summary skeleton, and why themes beat findings |
| [17-Libraries](../../17-Libraries/README.md) | Dependency inventory technique — the richest source of systemic causes |
