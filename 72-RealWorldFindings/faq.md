# 72 — Real World Findings: FAQ

The questions people actually ask about adjudication, severity and reporting — including the ones
that feel too basic to ask out loud, which are usually the ones worth answering.

---

### 1. What is the actual difference between a vulnerability and a finding?

A vulnerability is a property of the software. A finding is a *reported claim* about it, and a claim
has parts a property does not: a named attacker, a demonstrated path, an impact, and a severity you
argued.

The two do not map one-to-one in either direction. A vulnerability that no in-scope attacker can
reach does not become a finding. An Informational finding — "your backup configuration relies on a
default that will not hold when you add accounts" — is a finding with no vulnerability behind it.

---

### 2. My scanner found 3,000 issues. Where do I start?

Not by reading them. Do the mechanical adjudication first, because it requires no judgement and it
removes most of the pile:

1. **Deduplicate by root cause.** Eleven components exported by one module template are one thing.
2. **Scope by file path.** Separate application code from bundled libraries. In a real commercial
   sweep, seven of fifteen rejected high-confidence leads were documentation URLs from a single
   logging façade — a property of a dependency, not of the app.
3. **Apply platform defaults.** An absent attribute whose default is already safe is not a finding.

In this chapter's own corpus, steps of exactly this kind removed **84.7%** of the largest finding
class before a human looked at anything.

Then adjudicate the top confidence band **by hand, first**. And sample the middle band, because the
best finding in this repository's biggest real sweep was ranked MEDIUM.

---

### 3. Is it really true that most high-confidence findings are wrong?

In the measurements this repository has taken, yes, and the numbers are uncomfortable:

| Measurement | Result |
|---|---|
| 17 HIGH-confidence leads on a 17 MB commercial app | **15 rejected — 88%** |
| High-confidence secret hits against real browser data | **132 of 132 false** |
| `grep -i xposed` over 237 APKs, 1,141 occurrences | **0 findings** |
| A self-signature detector's first run | **18 of 18** apps — an artefact |

The common thread is not that the tools are bad. It is that **confidence is a property of the
detector and severity is a property of the business**, and a tool can only ever estimate the first.

---

### 4. How do I know whether my detector is lying to me?

Ask whether the arithmetic closes. Take every hit and account for it. If you cannot say what each
one is, the signature is not evidence.

The strongest example in this repository: a sweep found 1,141 occurrences of a substring across 237
APKs and accounted for **1,141** of them as the English word "exposed". Zero unexplained. That
closing arithmetic is what makes it a measurement rather than an impression.

And the standing rule: **if a detector agrees with you about almost every sample, suspect the
detector.** A real security property is not uniformly distributed. Uniformity is the signature of a
tautology.

---

### 5. Why is a short search token dangerous?

Two reasons, and the second is counter-intuitive.

Short tokens collide with ordinary language — that is why `xposed` matches "exposed" every time.

But short tokens also collide with **minified identifiers**. A three-character signature produced 16
high-confidence hits in one sweep, and all sixteen were R8-generated class names sitting in
alphabetical runs of obfuscated code. The more aggressively an app is minified, the more short
lowercase identifiers exist — so **the false-positive rate rises on better-protected applications**,
which is exactly backwards from the intuition that obfuscation makes detection harder.

The rule: nothing under about eight characters goes in a high-confidence tier.

---

### 6. I grepped for `FLAG_SECURE` and got hits. Is that a finding?

No, and it is worse than that: those hits cannot be uses of the flag.

`FLAG_SECURE` is a `public static final int`. javac performs constant folding, so the *name* never
reaches the class file, let alone the DEX. A compile-and-check experiment found the string absent
from both. The detector's true-positive rate is **zero** — it cannot find real uses, and anything it
does report came from somewhere else.

To detect the flag, look for `setFlags`/`addFlags` calls carrying the value 8192, or observe
screenshot behaviour at runtime.

The general lesson reaches much further: **any `static final` primitive constant is invisible to
string search in DEX.** Before building a detector on an identifier, check that the identifier
survives compilation.

---

### 7. Why does everyone keep saying `adb shell` results do not count?

Because `adb shell` is not an app, and the gap has been measured from four directions:

- Properties visible by vantage: **~1062 to root, ~678 to `shell`, ~638 to an app** — so the
  shell-to-app gap is small (~40) and the **root-to-shell gap is large (~384)**. The whole
  `ro.boottime.*` family (111 properties) is typed `boottime_prop` and is invisible to `shell` *and*
  to an app.
- `/system/xbin/su` is visible and setuid-root to `shell` and `Permission denied` to an app, because
  the directory is `0750 root:shell`.
- `locksettings clear` as uid 2000 reports *"The device does not support lock screen"* — a
  permission failure disguised as a capability failure.

The cause is not the shell GID, which `platform.xml` grants only `INTERNET`. It is the
`com.android.shell` **package**, which requests 200 permissions, holds 183 at install, and holds
**16 runtime permissions pre-granted `SYSTEM_FIXED`**, including `CAMERA`, `RECORD_AUDIO` and
`READ_SMS`.

The failure is silent in both directions: a signal that only fires for `shell` reads as a working
check, and a signal invisible to `shell` reads as absent.

---

### 8. That sounds theoretical. Did it actually change a result in this chapter?

Yes, and it cost the chapter its headline. Of 82 exported provider authorities probed read-only,
exactly one returned rows — the most eye-catching result of the sweep. That authority belongs to a
telephony component, and `adb shell` holds telephony permissions. So the rows may have been returned
to the *privileged vantage*, not to an attacker.

The honest verdict on my own best result was therefore **indeterminate pending an app-uid re-test**.
A result you like is exactly the one to re-check from the correct vantage.

---

### 9. A provider query failed. Is that the end of it?

No — and this is the most practically useful distinction in the chapter. Read the exception, because
it tells you *which layer* refused you:

| What you get | Where it came from | What it means |
|---|---|---|
| `SecurityException: Permission Denial` | `ContentProvider.enforceReadPermissionInner`, before the app runs | You are **outside**. Gate 2 fails |
| `UnsupportedOperationException` with app frames | The **app's own code** | You are **inside**, holding the wrong verb. Try `call`, `openFile`, `insert` |
| `No result found.` | Query executed, table empty | Reachable. Gate 3 is *untested* |
| "Could not find provider" / unknown URI | The authority root is not a queryable path | Indeterminate — enumerate path segments |

My first classifier bucketed the second row as "error" and I nearly published a 30% inconclusive
rate. Reading the stack traces moved 25 of 82 from "failed" to "reachable".

---

### 10. Is an exported component a finding?

Almost never on its own. In this chapter's 243-package corpus, 2,674 components were declared
exported. Two mechanical filters — is it guarded by a permission a third-party app cannot hold, and
does it carry an `<intent-filter>` giving it a declared reason to be reachable — reduced that to
410. And 410 is still 410 *leads*.

The finding requires knowing what invoking it achieves. An exported Activity showing a static
licence list is Informational. An exported provider returning message bodies is High. Same class,
same manifest attribute, three bands apart.

---

### 11. What about implicit export — components with an intent-filter and no `android:exported`?

That class is **extinct on modern targets**, and the number is stark: across 6,465 components on a
current platform image, **313 omit `android:exported` and zero of those 313 carry an
`<intent-filter>`**. Android 12 (API 31) made that combination a build error, and 237 of 243 apps
in the corpus target API 31 or later.

If your checklist still allocates time to it, you are spending an engagement's budget on a check
whose true-positive rate on modern apps is approaching zero. Finding classes have lifecycles;
checklists do not.

---

### 12. When is "the app does not set X" a valid finding?

Only when you have established what the platform does when X is absent, **at the target's
`targetSdkVersion`**.

The measured example: `usesCleartextTraffic` is absent from 196 of 243 apps in the corpus, and 195
of those target API 28 or above, where the platform default is **already `false`**. A check that
reports "cleartext traffic is not disabled" whenever the attribute is missing fires 196 times and is
wrong 195 of them — a false-positive rate of roughly **99.5%**.

`allowBackup` has the same shape with a different default: counting the default as a finding reports
205 of 243 apps.

Call this family the **absent-attribute finding**, and treat every instance as guilty until you have
looked up the default.

---

### 13. Where does severity actually come from?

From the threat model, and it is an *argument*, not a lookup. Four inputs, and a rating that cannot
name all four is a guess:

1. **Who is the attacker**, and are they in the client's threat model?
2. **What must they do first** — preconditions, and how plausible?
3. **What do they get** — which data, which state change, whose accounts?
4. **How many users**, and is it repeatable at scale?

"This violates MASVS-STORAGE-1, therefore Medium" is a lookup and it is wrong even when the number
it produces happens to be right. Two apps can violate the same control and deserve Low and High.

The rubric itself lives in [80-Appendix §5–§6](../80-Appendix/README.md#5-severity-cvss-and-business-impact).

---

### 14. Is "the app does not detect root" ever a finding?

Only when the engagement's threat model **names the device owner as an adversary** — licensing,
anti-fraud, DRM, regulated content. Even then it is a finding about a *control*, not a
vulnerability, and the correct top recommendation is usually to move the enforcement server-side so
that the client-side control stops being load-bearing.

Without that premise it is class F-12: a fact about the platform reported as a fact about the app.
Rating it High is the fastest way to tell a developer you cannot distinguish your methodology from
their risk, and every other rating in your report gets discounted accordingly.

---

### 15. The backend is out of scope but I found something that depends on it. What do I write?

Write it as **Informational with an explicit testing gap**, and never as either of the two things
people actually write.

Consider a client sending a modifiable `accountId` to `/accounts/{accountId}/statements`. Three
possible worlds: the server returns another user's data (Critical, and it is a *server* finding); the
server returns 403 (not a finding); or you did not test (Informational, plus a stated gap).

Writing the third as the first is a **fabrication** — nobody tried it, and one disproved Critical
discredits the whole report. Dropping it silently means the client never learns that their most
valuable untested surface is reachable from a client they *did* pay to have tested.

The correct output converts an untestable item into a scoping recommendation, which is genuinely
useful and is how the next engagement gets funded. **"Out of scope" is not "secure."**

---

### 16. How do I report coverage without lying?

Put the denominator and its source in the same sentence, or do not report coverage at all.

Measured instance: one session reached two components. The static manifest declared 4; the device's
resolver tables reported 3. That is 50% or 67% from identical evidence — a 17-point spread produced
entirely by an unstated choice, and the flattering number comes from letting the *device* define the
total.

The structural reason: **runtime evidence cannot supply its own denominator.** That is also the
mechanical argument for why a static pass and a dynamic pass are mutually dependent rather than
alternatives.

---

### 17. Eleven components have the same problem. Is that one finding or eleven?

One, with eleven instances listed.

Eleven entries imply eleven remediations, so the developer fixes them one at a time and misses the
twelfth. One finding that says "these eleven inherit an export default from the shared feature-module
template; change the template and add a lint rule" produces a fix that holds.

Eleven entries also silently inflate the report's apparent severity when the underlying risk is
identical. Prevalence is an **aggravating factor within one rating**, not a multiplier on the count.

---

### 18. Should I ever report an Informational finding at all?

Yes, when one of three things is true: the cause is *structural* and will apply to the next thing
written there; the observation is a **link in a chain** you are documenting; or it is a hardening
recommendation the client explicitly asked for.

What must not be in the Informational band is platform facts — "the device can be rooted", "the app
can be decompiled". Those belong in the test-environment record. An Informational band full of them
trains the client to skip the band, and one day something real will be in it.

---

### 19. Can I cite CVEs in a report?

Only ones you have verified. Take them from the Android Security Bulletins directly and quote the
bulletin month alongside the ID, so the reader can check you.

An unverifiable identifier is worse than no identifier, because it invites the client to check one
thing and disbelieve everything else. And in a peer review, treat any CVE cited without a
verification path as **fabricated until the author produces the bulletin** — that is not cynicism,
it is the only workable default.

Where you are unsure, describe the class. The class is the useful part; the identifier is decoration.

---

### 20. Can I name the apps I tested in a write-up or a talk?

No. Describe the class, quantify the population, anonymise the instance.

"Twelve of fourteen apps present a pinning surface and four actually pin" is publishable and useful.
The same sentence with product names attached is a disclosure you were not authorised to make, and —
given that this chapter is a long argument that adjudication is wrong more often than people think —
potentially defamatory if you got it wrong.

This applies to your own corpus too. This chapter's own measurements refer to "243 packages on a
stock Android 15 image" and "a 17 MB commercial app" for exactly this reason.

---

### 21. My corpus is 243 apps. Can I say "56% of Android apps expose components"?

No, and this is the question the chapter cares most about. Of those 243 packages, **four are
third-party**. It is a *platform* corpus: it supports statements about how Android and its bundled
applications are built, and nothing at all about banking, retail, or any category a commercial
assessment targets.

Three questions demolish most published mobile statistics: 56% of *which* apps, what did "expose"
mean mechanically, and who adjudicated? Answer all three in the same paragraph as the number, and
include at least one explicit sentence of the form "this supports nothing about X".

---

### 21a. I cannot reproduce a number another team published. Do I correct it?

No. Publish your own figure, publish the **exact command** that produced it, name the disagreement,
and route it to whoever owns the original. You have two hypotheses — their measurement is wrong, or
yours is — and no basis yet for choosing between them.

Silently overwriting their number asserts an adjudication you have not performed. Silently dropping
your own result loses the only evidence that anything is wrong. **"I could not reproduce this" is a
publishable finding.**

This is not hypothetical for this repository. Chapter 39 published a property-count figure that was
quoted onward into six chapters, including this one, before anyone re-ran it — and it was wrong: a
*root* measurement wearing a *shell* label. The divergence was found by
[74-CaseStudies](../74-CaseStudies/README.md), which did exactly the above and changed nothing in the
chapter it could not adjudicate. See [README §3.3a](README.md#33a-a-worked-gate-1-failure-committed-by-this-repository).

Two lessons worth carrying: **a number that makes a dramatic point deserves more scrutiny than one
that does not**, and this one got less precisely because it was quotable. And **six citations of one
measurement is one measurement** — repetition is not corroboration.

---

### 22. Two of my tools disagree about a manifest. Which is right?

The device, when one of them is the device — `dumpsys` reports what `PackageManagerService` actually
stored, which is what the platform will act on.

But expect most disagreements to be your own bugs. In this chapter's cross-check of 245 guard
permissions, eleven disagreed. **All eleven were defects in my static reader** — three were a
protection level added in API 31 that my table lacked, and eight were a deprecated spelling of a
level whose effect is identical. Zero were app defects.

That is a poor yield in findings and an excellent one in tool correctness, and it is the yield you
should expect. Chase them anyway: the cost is minutes and the alternative is a report built on a
parser nobody has validated.

---

### 23. Can I build a finding on jadx output?

For a lead, yes. For a load-bearing finding, confirm it in Smali or at runtime and say which reading
produced the claim.

Two measured reasons. jadx **under-reports its own failures by about 30×**: on a real 17.5 MB APK the
console said `finished with errors, count: 61` while the output tree held **2,104 refused methods
across 1,424 files** — so absence of a finding in the missing 2,000 is evidence of nothing. And
decompiled Java can **silently disagree with the bytecode**: one constructed case decompiles to
clean, warning-free Java returning 100 while the bytecode returns 105.

"Decompiled with jadx 1.4.7; confirmed in Smali" is one clause, and it is the difference between a
finding that survives developer review and one that does not.

---

### 24. My Frida hook installed and nothing happened. Does that mean the app is clean?

No. It means your hook did not fire, and you must establish which.

A perfectly-installed hook can change nothing: with plain `-O2` a function remained exported while
its body was inlined into every caller, so zero call sites targeted it. The hook installs, verifies,
and has no effect. ART inlines managed code too.

Related and worth knowing: a bypass tool reported **three successful pinning hooks against an app
with no network code at all**, because the hooks target platform classes rather than the app. **A
"successful bypass" message is evidence that a hook installed, not that the app pinned.**

Always run a self-test — reach something you know reaches the hook — before a silence means anything.

---

### 25. My dynamic session produced nothing. Is that a clean result?

Unknown until you prove the session was alive. A **void run and a clean negative produce identical
reports**, and telling them apart is entirely on you.

The measured case: `am start` was absorbed by a pending permission dialog, all nine capture channels
went silent, and the report looked exactly like a well-behaved app doing nothing wrong. Read all of
`am start -W` — the `Activity:` line names what actually ended up in front — check
`dumpsys window | grep mCurrentFocus`, and check `pidof` at the end.

---

### 26. Does the MASVS tell me where to spend my time?

No. It tells you what not to *forget*, which is a different and also valuable thing.

The distributions genuinely differ. MASVS-RESILIENCE is one of eight categories and consumes far
more than an eighth of testing time while producing almost no defensible findings without a named
adversary. Authentication and session logic is one category and holds nearly all the Criticals. And
the framework is version-agnostic while finding classes go extinct.

Use MASVS as a completeness check and base rates plus the client's threat model as the work plan. A
report structured strictly by MASVS category tends to give equal prominence to the section with four
Informational items and the section with the account takeover.

---

### 27. What is the single most common mistake in a junior report?

Reporting the platform as though it were the app. "The device can be rooted", "the APK can be
decompiled", "the emulator has no hardware-backed keystore" — all true, none a finding, and their
presence at the top of a findings table tells the reader you have confused your methodology with
their risk.

Close second: reporting per instance instead of per root cause, which produces eleven tickets, one
regression next quarter, and a report that looks thorough and is not.

---

### 28. Where does this chapter stop and the case studies start?

This chapter's unit is the **finding class** and its evidence is **counts across many apps**: what
turns up, how often, how severe, and how to write it. [74-CaseStudies](../74-CaseStudies/README.md)'s unit
is the **story** — a small number of engagements told end to end, with the reasoning and the dead
ends left in.

If you want to know how often a vulnerable `ContentProvider` shows up and what it is usually worth,
you are in the right place. If you want to watch somebody find one, go there.
