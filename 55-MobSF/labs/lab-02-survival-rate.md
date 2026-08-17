# Lab 02 — The survival rate

**Level:** Core. This lab is the point of the chapter.
**Time:** 3–4 hours. Do not compress it; the compression is the mistake it exists to prevent.
**Prerequisites:** [Lab 01](lab-01-first-scan-and-inventory.md),
[52-StaticAnalysis §3.7](../../52-StaticAnalysis/README.md#37-stage-7--validate).
**MobSF required:** **No.** Two saved reports ship with this chapter.

---

## 0. The one-sentence brief

> Run a scan. Validate **every** finding by hand. Report the survival rate as a number, with a
> written reason against every rejection.

**The number is the deliverable.** Not the findings — the *ratio*, and the reasons. It takes an
afternoon, it is the single most useful thing anyone can produce about a scanner, and almost nobody
has ever done it.

---

## 1. Why this is the lab that matters

The economics of validation are hostile, and that is the whole problem.

Confirming one lead is slow and produces one line in a report. Pasting the scanner output is instant
and produces forty. Nothing in your day pushes back — the client cannot tell the difference from the
outside, the tool does not complain, and the report is longer.

The only defence is to make validation a **stage with a deliverable**, so that its absence becomes
visible. That deliverable is the ledger, and the survival rate is its headline.

[52-StaticAnalysis](../../52-StaticAnalysis/README.md) says it in one line: *"when it is not a named
stage it does not happen."*

### 1.1 What "survival" means, exactly

Three different things get confused here, so they are defined once:

| Term | Meaning |
|---|---|
| **Report item** | One row emitted by the scanner. A single rule firing once |
| **Corroborated** | The artefact independently shows the claimed construct, where it is claimed. **This is not a finding** |
| **Finding** | A construct that is real, reachable, reachable by *someone*, and gets them *something* |

So there are two rates and both are worth reporting:

```
corroboration rate = corroborated items / total items      (a property of the TOOL)
finding rate       = findings / total items                 (a property of the ENGAGEMENT)
```

`MEASURED` reference numbers from this chapter's own run, so you have something to compare against:

| | Value |
|---|---|
| Report items normalised | **39** |
| Corroborated | **17** (43.6%) |
| Corroborated, excluding the scorecard's restatements | 17 of 27 (**63.0%**) |
| Refuted by measurement | 2 |
| Over-rated | 3 |
| Under-rated | 1 |
| Scorecard restatements | 11 (28%) |
| **Findings after hand adjudication** | **8** |
| Rejected with a written reason | 15 |
| **Findings the scan never mentioned** | **2** |

---

## 2. Objective

Produce **one CSV** in which every row of a scanner report has:

- a verdict a human assigned,
- a reason in words,
- the evidence that settles it,

plus a summary paragraph containing the two rates.

---

## 3. Setup

```bash
# host
cd 55-MobSF
ls examples/synthetic-mobsf-report.json          # the report
ls scripts/mobsf-validate.py                     # the evidence-gatherer
```

You need the **artefact the report describes**. For the shipped fixture that is
`CMPen-Android-App-v1.2.apk` (SHA-256 `137186672dd93517bd6c85637c04c7f7cf912458e3ea9c887072dbbf00c39638`),
a public deliberately-vulnerable training application. Any APK plus its own report works equally
well — and if you are using your own, everything below applies unchanged.

```bash
# host — decompile once; the validator needs a tree to open the cited lines
jadx -d out target.apk
# or, when jadx on PATH is the GUI launcher (Windows):
java -Xmx3g -cp "/c/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar" jadx.cli.JadxCLI -d out target.apk
```

> **⚠️ Check the tree before you trust it.** If `jadx` printed `finished with errors, count: N`,
> every refused class produced no findings *because it could not be read*. Count the tree:
> `grep -rl 'JADX ERROR' out/sources | wc -l`. Chapter 56 measured the console under-reporting by
> **30×**.

---

## 4. Step 1 — Normalise, and count honestly

```bash
# host
python3 -B scripts/mobsf-validate.py \
    --report examples/synthetic-mobsf-report.json \
    --apk target.apk --tree ./out --csv ledger.csv
```

The header tells you three things before any finding:

```
  manifest via: aapt2
  schema seen : manifest_analysis: dict; certificate_analysis: dict; code_analysis: dict;
                network_security: dict; appsec: dict
  findings    : 39
```

**`manifest via:`** is the strength of every manifest check that follows. `aapt2` means the platform's
own parser answered. `raw-axml` means presence checks only, and the tool says so rather than pretending.

**`schema seen:`** exists so that *"the report has no manifest findings"* and *"my parser did not find
the manifest findings"* are distinguishable. A parser that silently returns zero is worse than one
that crashes.

**`findings: 39`** is the denominator. Write it down. And note immediately that it is **not** 39
distinct claims — §6 deals with that.

---

## 5. Step 2 — Read the automated evidence, and understand what it is not

The tool gathers evidence. It does not adjudicate. Its vocabulary is deliberately missing one word:

| Verdict | Meaning | What you still owe it |
|---|---|---|
| `CORROBORATED` | The artefact shows the construct where claimed | Reachability, an actor, an asset |
| `REFUTED` | A measurement contradicts the report | Write the correction |
| `UNSUPPORTED` | The cited evidence is not where the report says | Find out why — wrong build? unreadable class? |
| `UNDER-RATED` | Real, and the severity is too low | **Raise it, and say why** |
| `OVER-RATED` | Real, and the severity is too high | Lower it or reject it |
| `RESTATES` | A scorecard entry duplicating another section | Do not count it |
| `NEEDS-HUMAN` | No automated check applies | All of it |

**There is no `FINDING`.** A finding is written by a person who can name the asset, and no
file-reading tool knows the asset. That is a design constraint, stated in the script's own header.

Read a few blocks in full. A good one looks like this (`MEASURED`, unedited):

```
V017  [HIGH]  code
  claim     Insecure WebView Implementation. WebView is configured with addJavascriptInterface...
  cvss      8.8   <- rule metadata, constant for every app. Not YOUR severity.
  cites     org/android/cmpen/WebViewActivity.java:15
    FOR     org/android/cmpen/WebViewActivity.java:15  webView.addJavascriptInterface(new WebAppInterface(), "AndroidBridge");
  VERDICT   CORROBORATED
  NEXT STEP Two more questions decide severity: (1) what does the exposed
            object's @JavascriptInterface method return, and (2) can an attacker
            control the URL loaded into that WebView? Without (2) it is not
            remote. 43-WebView.
```

Everything after `NEXT STEP` is your work. The tool has established that the construct exists at the
cited line. It has established nothing else.

---

## 6. Step 3 — Deduplicate before you count

Two mechanisms inflate an item count, and both must be handled before the rate means anything.

### 6.1 The scorecard restates the other sections

`MEASURED`: **11 of 39 items (28%)** in this chapter's run were `appsec` entries duplicating the
manifest, code and certificate sections. The validator flags them `RESTATES` and reports the rate
twice:

```
  all items          : 17 of 39 survived first-pass corroboration (43.6%)
  excluding scorecard: 17 of 27 (63.0%)
```

**Report the second number**, and say which you used. Counting a report's own summary as extra
findings is how a 12-item scan becomes a 39-item "report", and it is almost always unintentional: a
script walks every list in the JSON and the scorecard lists get walked too.

### 6.2 One component, several rules

`MEASURED`: `DeepLinkActivity` appears twice in the example report — once under `exported_activity`
and once under `browsable_activity`. Two rows, one component, one finding.

Merge them. In the ledger, mark the second `MERGED` with a pointer to the first.

---

## 7. Step 4 — Work the queue, top-down, including the ones you expect to reject

This is the lab. Budget two to three hours.

Open `ledger.csv`. It has two deliberately blank columns: `human_verdict` and `human_reason`. Fill in
**every row**. All of them.

### 7.1 The four questions

For each row, [52 §3.7](../../52-StaticAnalysis/README.md#37-stage-7--validate)'s four:

| # | Question | How you answer it | If "no" |
|---|---|---|---|
| 1 | **Is the construct really there?** | Read the code, not the grep. Read Smali if the semantics matter | Reject: rule artefact |
| 2 | **Is it reachable?** | Caller closure to an entry point, or a hook that fires | Reject or downgrade |
| 3 | **Who can reach it?** | Exported? Network input? Only the app itself? | Downgrade |
| 4 | **What does reaching it get them?** | The asset. **This is the severity** | Downgrade: no asset |

### 7.2 The kill list — in the order that kills most leads soonest

1. Is it in the app's own code, or in a library?
2. Is the value a **value**, or a **name**?
3. Does it decode to something meaningful?
4. Is the code dead, or behind `BuildConfig.DEBUG`?
5. Did you analyse the **shipped** artefact?
6. Is the mechanism actually dangerous *here*? (Some keys are designed to ship.)
7. Does the control you think is missing exist somewhere else?
8. Would the client's own logs corroborate it?

### 7.3 The verdicts you may assign

| Verdict | Use when |
|---|---|
| `FINDING` | All four questions answered, and you can write the impact sentence |
| `MERGED` | Real, and it is part of another finding. **Point at which one** |
| `LEAD` | Real, and question 2, 3 or 4 is unanswered. Say what would answer it |
| `REJECTED` | Not a finding. **Always with a reason** |
| `LIMIT` | Not a finding, and it belongs in the limits section |

### 7.4 Four worked rows

`MEASURED`, from this chapter's own ledger.

**A rejection nobody would argue with:**

```
V005 | Activity (…MainActivity) is not Protected. An intent-filter exists.
     | tool: OVER-RATED | human: REJECTED
     | It is the LAUNCHER activity. Every installed app has exactly one and it
     | is exported because the platform must be able to start it. Reporting it
     | is the single most common artefact in scanner-derived reports.
     | evidence: manifest — MainActivity carries action.MAIN + category.LAUNCHER
```

**A rejection that takes thirty seconds and saves your credibility:**

```
V011 | App can be installed on a vulnerable Android version. [minSdk=24]
     | tool: OVER-RATED | human: REJECTED
     | The rule fires on an integer. It names no weakness, no CVE and no
     | platform behaviour this application depends on. minSdk is a support
     | decision. Reporting it wastes the client's remediation budget and costs
     | credibility on the items that matter.
     | evidence: aapt2 — minSdkVersion=24
```

**An upgrade — the row a skim would have missed:**

```
V004 | Content Provider (…FlagProvider) is Protected by a permission…
     | tool: UNDER-RATED | human: FINDING | severity: Medium
     | The scanner rated this INFO because a permission is present. The
     | permission is declared in the SAME manifest with protectionLevel
     | 0x00000000 = normal, so any app may request and receive it at install
     | time. The guard is decorative and query() returns a token.
     | evidence: aapt2 — E: permission name=…ACCESS_FLAG protectionLevel=0x00000000
```

**A split — one rule, five files, five different answers:**

```
V015  | Files may contain hardcoded sensitive information (5 files)
      | tool: CORROBORATED | human: SPLIT
V015a | adminUser = "admin"                  | REJECTED  | a username, and a default one
V015b | passHash = 64 hex                    | FINDING   | Medium — the finding is the
      |   unsalted single-round SHA-256 client-side password verifier, not the value
V015c | encodedFlag = base64 → plaintext     | FINDING   | Medium — returned by an
      |   exported provider; severity comes from the provider, not the encoding
V015d | ch4Cipher / ch6Cipher = ciphertext   | MERGED    | into the crypto finding;
      |   ciphertext matters because the key derivation is in the same APK
V015e | XOR-obfuscated base64                | FINDING   | Low — defeated in two lines
```

That split is the highest-value single act in the whole lab. **One `high` row with five file
citations is not one finding**; it is five questions, and on this run they had four different
answers.

---

## 8. Step 5 — Find what the scan did not report

**This is the step that separates an analyst from an operator**, and it is graded hardest.

While reading the files the scanner cited, you will see things no rule fired on. Record them.

`MEASURED`, this chapter found two findings and one limit this way.

**(a) A hash used as a key derivation function.** The ECB rule cited `B/g.java:28`. Opening the file
shows the ECB is the *second*-worst thing in it:

```java
// out/sources/B/g.java:20-28
MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
byte[] bArrDigest = messageDigest.digest(str2.getBytes(charset));   // caller-supplied
byte[] bArrCopyOf = Arrays.copyOf(bArrDigest, 16);                  // truncate to 128 bits
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(2, new SecretKeySpec(bArrCopyOf, "AES"));
```

One unsalted SHA-256 round, truncated, used directly as an AES key, no IV because the mode is ECB.
**No rule exists for "hash used as a KDF"**, so the defect with the widest blast radius in the
application appears nowhere in the report.

**(b) The provider's file handling.** `LeakyFileProvider.openFile` opens
`new File(getFilesDir(), uri.getLastPathSegment())`. `getLastPathSegment()` limits classic `../`
traversal because a segment cannot contain an unencoded slash — but the provider still opens **any
file directly under `files/`** for **any caller**, and percent-encoded separator handling must be
tested on a device before either sentence is written. **That is a `LEAD`, recorded as such.**
Recording it honestly rather than inflating it is the same discipline as rejecting the fifteen.

**(c) The runtime broadcast surface.** Nothing in the report or the artefact can enumerate receivers
registered with `registerReceiver()`. Recorded as a `LIMIT`.

**The habit:** every time you open a file because the scanner pointed at it, read the whole file. The
scanner pointed at a line; the finding is often three lines above it.

---

## 9. Step 6 — Compute and write the numbers

```bash
# host — count your own ledger
python3 -B -c "
import csv, collections
rows = list(csv.DictReader(open('ledger.csv')))
tool  = collections.Counter(r['verdict'] for r in rows)
human = collections.Counter(r['human_verdict'] or 'UNWORKED' for r in rows)
n = len(rows)
distinct = [r for r in rows if not r['section'].startswith('appsec')]
print('total items          ', n)
print('tool verdicts        ', dict(tool))
print('human verdicts       ', dict(human))
print('corroboration rate   %.1f%%' % (100.0*tool['CORROBORATED']/max(1,n)))
print('  excl. scorecard    %.1f%%' % (
      100.0*sum(1 for r in distinct if r['verdict']=='CORROBORATED')/max(1,len(distinct))))
print('finding rate         %.1f%%' % (100.0*human['FINDING']/max(1,n)))
if human['UNWORKED']:
    print('*** %d rows UNWORKED - the lab is not finished ***' % human['UNWORKED'])
"
```

Then write the paragraph. This is the artefact that goes in a report:

> *N* report items were generated by automated analysis. *A* were corroborated against the artefact;
> *B* were refuted or found to be over-rated by direct measurement; *C* were entries in the tool's own
> summary restating other sections. After manual adjudication, **M findings** were reported and
> **R items were rejected with reasons** (Appendix B). **K findings did not originate from the
> automated analysis at all.**

`MEASURED` reference: **N=39, A=17, B=5, C=11, M=8, R=15, K=2.**

---

## 10. The traps this lab is built to catch

<details>
<summary>Trap 1 — validating only the items you already believe</summary>

The most common failure, and the reason the instructions say *top-down, including the ones you expect
to reject*.

On this chapter's run, the `UNDER-RATED` provider — the only row where severity moved **up** — was
rated `info` by the tool. A validator working the `high` band first and stopping when tired would
never have reached it.

The rejection reasons are also the deliverable. A report that shows only what survived looks like
luck. A report showing 39 items worked down to 8, with a reason against each of the 15 rejections,
looks like a method.

</details>

<details>
<summary>Trap 2 — treating "corroborated" as "finding"</summary>

`CORROBORATED` means the construct is where the report says it is. That is question 1 of four.

`MEASURED`: 17 items were corroborated; **8** became findings. Six were merged, two stayed leads, and
one was corroborated *and* rejected — the base64-is-used row, which is entirely real and entirely
meaningless on its own.

</details>

<details>
<summary>Trap 3 — reporting the ratio as a property of MobSF</summary>

**It is a property of the pairing**: this rule set against this application.

Run it on a well-built app with three components and it will be higher. Run it on a 200-component
enterprise app and it will be far lower, because the exported-component rules fire once per component
and almost none of them will matter.

Measure it on your own corpus. **Do not quote 63% at anyone.** What generalises is the *shape* — a
sweep produces leads, not findings — not the number.

</details>

<details>
<summary>Trap 4 — the ledger with no reasons</summary>

A row reading `REJECTED | false positive` is worthless. It records that you had an opinion.

A row reading `REJECTED | It is the LAUNCHER activity; every app has one and it is exported because
the platform must start it` records that you *looked*, and it survives someone disagreeing with you
six months later.

The reason column is the entire point of the file.

</details>

<details>
<summary>Trap 5 — forgetting that a rejected item can still be evidence</summary>

Four of nine leads in [52 §9.3](../../52-StaticAnalysis/README.md#93-advanced--a-complete-static-pass-ending-in-a-validated-finding)
were rejected purely because they had **zero sites in app code**. That rejection is itself a finding
about the application: its own code does not log, does not touch legacy external storage, and does
not reflect. That sentence is only available *because* the leads were worked and classified.

</details>

---

## 11. Extension — do it twice, and compare

Run the whole lab against the second fixture,
[`examples/synthetic-mobsf-report-v1.0.json`](../examples/synthetic-mobsf-report-v1.0.json), which
describes the **same application one version earlier, built without R8**.

`MEASURED`:

| | v1.0 (no R8) | v1.2 (R8) |
|---|---|---|
| Items | 29 | 39 |
| Corroborated | 10 | 17 |
| Refuted | 3 | 2 |
| Corroboration rate excl. scorecard | 47.4% | 63.0% |

Then answer, in writing: **why is the rate different, and does the difference tell you anything about
the applications?**

(It does not tell you much about the *applications*. It tells you a great deal about what the tool
could see. That is lab 03.)

---

## 12. Success criteria

- [ ] `ledger.csv` with **every** row carrying a `human_verdict` and a `human_reason`. Zero
      `UNWORKED`.
- [ ] At least one row where you **raised** the severity, with the measurement that justified it.
- [ ] At least one multi-file row **split** into per-file verdicts.
- [ ] At least one item **refuted** by direct measurement of the artefact.
- [ ] At least one finding that **did not come from the report**.
- [ ] The summary paragraph, with both rates and all of N, A, B, C, M, R, K.
- [ ] A limits statement (carried forward from lab 01) naming what neither you nor the tool could see.

---

## 13. What you should have learned

| Lesson | Evidence from your own run |
|---|---|
| A report item is a hypothesis, not a finding | Your corroboration rate |
| The rejection reasons are a deliverable | Your ledger's reason column |
| Severity errors point in **both** directions | Your `UNDER-RATED` row |
| One rule, five files, five answers | Your split row |
| The best findings are often not in the report | Your `K` |
| Working the low-severity rows pays | Where the upgrade came from |
| The ratio is a property of the pairing, not of the tool | The v1.0 comparison |

---

## 14. Next

[Lab 03 — obfuscation blindness](lab-03-obfuscation-blindness.md) explains the difference between the
two runs you just compared, and demonstrates the failure mode that a survival rate cannot detect:
the finding that was never in the report because the tool could not see it.
