# Lab 02 — The Full Audit

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-three-way-read.md),
[Chapter 32 §3 and §5.6](../README.md#56-how-pentesters-test-it--the-manifest-audit-checklist)

---

## Objective

Apply the complete §5.6 checklist, by hand, to
[`examples/vulnerable-manifest.xml`](../examples/vulnerable-manifest.xml), and produce a
severity-rated findings table you would be willing to put your name on. Then run
[`scripts/manifest-audit.py`](../scripts/manifest-audit.py) and reconcile the two.

Then repeat the whole exercise on a real APK from your own phone.

## Why this matters

The checklist has roughly seventy rows. A human running it at 17:40 on the last day of an engagement
skips rows, and the rows people skip are always the same ones: the elements below `</application>`,
the `activity-alias`, the referenced XML resources, and the resolution of custom `protectionLevel`
values.

Doing it slowly and completely three times is what makes doing it quickly and completely possible.

There is a second, less obvious reason. A findings table is not a list of attributes; it is a list of
**claims about a system**, each with evidence and a severity you can defend. This lab is the first
time you write one.

> **Mental Model**
> Think of the manifest as an **inventory of doors**, not an inventory of defects. Each entry tells
> you whether a door exists and whether it is locked. It tells you nothing about what is behind the
> door. The audit produces leads; the labs that follow turn leads into findings.

---

## Setup

```bash
# host
cd Android-Pentesting-Notes/32-Manifest/examples
ls
```

You need nothing else for Part 1. For Part 2 you need a real APK, `apktool`, `aapt2`, `jadx` and a
device.

**Print or copy the checklist.** Open [README §5.6](../README.md#56-how-pentesters-test-it--the-manifest-audit-checklist)
in a second window and work down it row by row: sections A, B, C, D, E, F, G, H.

**Do not open** `vulnerable-manifest-ANSWERS.md` until Step 5. Reading it first turns a three-hour
skill-building exercise into a twenty-minute reading exercise.

---

## Steps

### Step 1 — Set up your findings table

Create the table you will fill in. Use exactly these columns; every one of them earns its place:

| # | Check | Component / location | Observation | Why it matters | Severity | Proven? |
|---|---|---|---|---|---|---|

- **Check** is the checklist row (`C1`, `D5`, `E3`…). It makes your work auditable by a reviewer.
- **Observation** is what the file says, quoted. Not your interpretation.
- **Why it matters** is one sentence of consequence, written for the developer who must fix it.
- **Severity** is your judgement, and you must be able to defend it.
- **Proven?** is `no` for everything in this lab, because you have no device and no code. Being
  disciplined about this column now is what stops you shipping an unproven claim later.

### Step 2 — Work sections A through C

**A — extraction and integrity.** You were handed a text file, so A1–A5 are partly not applicable.
Write down *why* each is not applicable rather than skipping it. On a real engagement, skipping A2
("tools agree on every security attribute") is how you miss a deliberately malformed manifest.

**B — identity and SDK levels.** Read `<uses-sdk>` first. Everything below depends on it.

**Question 1.** What is `targetSdkVersion`? Now write out, from the Version Matrix in
[§3.4](../README.md#34-sdk-versions--the-attribute-that-changes-every-other-attributes-meaning),
every platform protection this app has **not** opted into. You should have at least six rows.

**Question 2.** What is the effective default `exported` value for a component with an
`<intent-filter>` and no explicit attribute, at this `targetSdk`? For a `<provider>`?

**Question 3.** `sharedUserId` is present. Write the recommendation you would give the developer —
and note why "just remove it" is not an actionable recommendation.

**C — application flags.** There are eight findings in `<application>` alone.

**Question 4.** Which single attribute here is Critical, and what exactly does an attacker with only
USB access do with it?

**Question 5.** `allowBackup="true"` — what is your severity, and what would you need to know to
raise or lower it?

**Question 6.** There is a `<profileable>` element. Explain, in one sentence each, what it does and
why it is *not* equivalent to `debuggable`. (Getting this distinction wrong in a report is how you
lose an argument with a competent developer.)

### Step 3 — Work sections D and E, the component surface

This is the bulk of the work. Enumerate **every** component before you assess any of them.

```text
Type            Name                        exported (value / basis)   permission
--------------  --------------------------  -------------------------  ----------
activity        .MainActivity
activity        .WebViewActivity
activity        .debug.DevSettingsActivity
activity        .AdminActivity
activity-alias  .PublicAdminEntry
activity        .PinActivity
activity        .ShareReceiverActivity
activity        .LegacyImportActivity
service         .AdminService
service         .SyncService
service         .MediaParseService
service         .AssistService
receiver        .BootReceiver
receiver        .CommandReceiver
provider        .UserProvider
provider        androidx.core.content.FileProvider
provider        com.analytics.sdk.AnalyticsInitProvider
```

**Question 7.** Two components in that list have **no** `android:exported` attribute. What is their
effective export state, and what does it depend on?

**Question 8.** One `activity-alias` completely defeats the protection on the Activity it targets.
Explain the mechanism in two sentences, and say why an auditor who greps for `<activity` misses it.

**Question 9.** For every exported component with an `android:permission`, resolve that permission's
`protectionLevel` from the `<permission>` declarations at the top of the file. Which of those
permissions provide **no protection at all**, and why?

**Question 10.** One exported component in this file is correctly configured and is **not** a
finding. Which one, and what is the reasoning? What *would* be the finding on a component like it?

**Question 11.** `UserProvider` has four separate defects. Name all four. (Two are on the `<provider>`
element, one is on a child element, and one is in a `<permission>` declaration elsewhere in the file.)

**Question 12.** Explain, from the AOSP logic quoted in
[§3.9](../README.md#39-provider--the-richest-and-most-dangerous-element), why the `<path-permission>`
in `UserProvider` **widens** access rather than restricting it.

**Question 13.** The `FileProvider` entry has two problems that are visible in the manifest, and one
that is not. What is the third, and how do you get at it?

### Step 4 — Work sections F, G and H

**F — permissions.** Both directions: permissions the app *declares*, and permissions it *requests*.

**Question 14.** Three `<permission>` elements are declared. Rank them from weakest to strongest and
say what each is worth as an access control.

**Question 15.** The `<queries>` block is free intelligence. What does it tell you about the app
before you have decompiled a single class?

**G — intent filters and deep links.** There are two `<intent-filter>` blocks on `WebViewActivity`.

**Question 16.** Assess each separately. For each, answer the three questions from the deep-link audit
note in [§3.10](../README.md#310-intent-filter-and-its-children): is it verifiable, what does the
Activity do with the URI, and can it be reached from a web page?

**H — metadata and stragglers.** This is where people stop reading. Do not.

**Question 17.** Four `<meta-data>` entries carry a `value`. Classify each as *candidate secret*,
*public by design*, or *needs validation*. Justify each classification — misclassifying a public
identifier as a leaked credential costs you credibility on the entire report.

**Question 18.** What is below `</application>`? Why does it matter, and what is the exact command an
attacker runs?

### Step 5 — Run the script and reconcile

Only now:

```bash
# host
python3 ../scripts/manifest-audit.py vulnerable-manifest.xml --markdown > script-findings.md
python3 ../scripts/manifest-audit.py vulnerable-manifest.xml --min-severity HIGH
```

**Question 19.** Put your hand-written table next to the script output and answer three questions:

- What did the **script** find that **you** missed? Those are gaps in your process — write them on
  the checklist so you never miss them again.
- What did **you** find that the **script** missed? Those are gaps in the script. Can you say why a
  tool cannot find them?
- Where do your **severities** differ, and whose reasoning is better?

**Question 20.** The script marks many findings with `*` (UNPROVEN). Why does it do that, and what
would it take to remove the mark from each one?

### Step 6 — Read the answer key

Now open [`vulnerable-manifest-ANSWERS.md`](../examples/vulnerable-manifest-ANSWERS.md).

Read it for the *reasoning*, not the score. For each finding, check that you can independently
reproduce four things: why a developer writes it, how you detect it, what an attacker does with it,
and the fix as code.

**Question 21.** The key names three deliberate **non-findings**. Did you report any of them? If so,
write down what led you there — the reasoning error is more valuable to you than the finding.

### Step 7 — Do it again, on something real

The exercise only pays off on a real target.

```bash
# host
export PKG=<a third-party app on your phone>
adb pull "$(adb shell pm path $PKG | head -1 | tr -d '\r' | sed 's/package://')" real.apk
apktool d -f real.apk -o real-work/ >/dev/null
aapt2 dump xmltree --file AndroidManifest.xml real.apk > real-aapt2.txt
adb shell dumpsys package $PKG > real-dumpsys.txt
```

Run the full §5.6 checklist **by hand** first, then:

```bash
# host
python3 ../scripts/manifest-audit.py real-work/AndroidManifest.xml --markdown > real-findings.md
python3 ../scripts/manifest-audit.py --format xmltree real-aapt2.txt --markdown > real-findings-aapt2.md
diff real-findings.md real-findings-aapt2.md
```

**Question 22.** How many components does the real app have? How many are attributable to third-party
SDKs by class-name prefix? Name the SDKs.

**Question 23.** How many of the app's exported components did you find that a `grep exported=true`
would have missed?

### Step 8 — Write two findings properly

Pick the two highest-severity findings from your real-app audit and write them as they would appear
in a report:

- Title, one line
- Affected component, fully qualified
- Evidence — the exact manifest lines, and the exact command that reproduces
- Impact — what an attacker gains, in the client's language, not yours
- Severity, with the reasoning that produced it
- Remediation, **as code**
- **Provenance** — state explicitly what you proved and what you did not

**Question 24.** For each of your two findings, what would you have to do to move it from "declared"
to "proven"? That work is [Lab 03](lab-03-proving-reachability.md).

---

## Hints

<details>
<summary>Hint 1 — I cannot find the elements below `</application>`</summary>

Search for them by name rather than reading top to bottom:

```bash
# host
grep -n -E 'instrumentation|profileable|permission-tree|original-package|protected-broadcast' vulnerable-manifest.xml
```

`<instrumentation>` is a **sibling** of `<application>`, not a child. `<profileable>` *is* a child but
sits at the very bottom of it.
</details>

<details>
<summary>Hint 2 — how do I resolve a custom protectionLevel?</summary>

In this lab, from the `<permission>` declarations at the top of the same file. On a real app the
permission may be declared by a *different* app, in which case:

```bash
# host
adb shell pm list permissions -f | grep -A6 'com.example.permission.NAME'
```

If the attribute is **absent** from a `<permission>` element, the level is `normal`. That is the
single most consequential default in the whole file.
</details>

<details>
<summary>Hint 3 — how do I decide a severity?</summary>

Three questions, in order:

1. **Reachability** — can an ordinary app reach it? (In this lab you can only reason about the
   declaration. Mark it unproven.)
2. **Capability** — what does it let the attacker do? Read data, change state, execute code?
3. **Data sensitivity** — what does *this* app hold?

`allowBackup="true"` is Informational on a torch app and High on a banking app. The attribute never
decides the severity; the data does.
</details>

<details>
<summary>Hint 4 — the script and I disagree and I think I am right</summary>

You probably are. The script cannot judge impact and says so in its own header. Its value is
completeness, not judgement. Where you disagree, write down *why* — that note is worth more than the
finding.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1–2.** `targetSdkVersion=28`. Not opted in to: 29 (scoped storage), 30 (package visibility, scoped
storage enforcement), 31 (`exported` mandatory, `PendingIntent` mutability), 33 (receiver export
flags, stricter intent-filter matching), 34 (`foregroundServiceType` mandatory), 35. At this level a
component with an `<intent-filter>` and no explicit attribute is **exported**; a `<provider>` with no
attribute is **not** exported, because that default flipped at `targetSdk` 17, not 31.

**3.** Recommend `android:sharedUserMaxSdkVersion` plus a migration plan. "Remove it" is not
actionable: changing an installed app's UID is unsupported, so removal requires a data migration and
an uninstall/reinstall. A recommendation the developer cannot act on is a recommendation you will
have to defend in a meeting.

**4.** `android:debuggable="true"`. With USB access alone: `adb shell run-as com.example.vulnerable`
gives a shell as the app's UID with full read/write of its private data; JDWP attaches; Frida and
Objection work without root.

**5.** High **if** the private storage holds credentials, Medium otherwise, and you cannot tell from
the manifest. The next step is to enumerate the files that would actually leave the device. Note also
that there is no `fullBackupContent` and no `dataExtractionRules`, so *everything* except
`no_backup/` and `cache/` is included.

**6.** `<profileable android:shell="true">` lets UID 2000 profile the app and take heap dumps on a
production, non-debuggable build. It is not `debuggable`: no `run-as`, no JDWP, no arbitrary file
access. It is Medium, and saying so precisely is what makes the finding survive review.

**7.** `.ShareReceiverActivity` has an `<intent-filter>` and no attribute, so at `targetSdk` 28 it is
**implicitly exported**. `com.analytics.sdk.AnalyticsInitProvider` declares `exported="false"`
explicitly. (The subtler point: at `targetSdk` ≥ 31 the missing attribute would be a build failure,
so on a modern app you would never see this shape — which is exactly why low `targetSdk` is a
cluster finding.)

**8.** `.PublicAdminEntry` targets `.AdminActivity`. An `<activity-alias>` is a second, independently
configured entry point whose `exported` and `permission` are its **own** and do not inherit from the
target; here the alias is `exported="true"` with `android:permission=""`, which explicitly *removes*
the application-level requirement. An auditor who greps `<activity` matches `<activity-alias` too but
reads it as just another Activity and never resolves `targetActivity` — so the connection to a
supposedly locked-down component is never made.

**9.** `com.example.vulnerable.permission.ADMIN` is `normal` and `…READ_USERS` has no
`protectionLevel` at all, which also means `normal`. A `normal` permission is granted automatically,
with no prompt and no signature check, to any app that declares `<uses-permission>` — so both provide
zero access control. `…INTERNAL_IPC` is `signature` and is a real control.

**10.** `.AssistService`, guarded by `android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"`.
It must be exported because the *system* binds to it, and only the system holds that permission. The
finding on a component like this would be the **absence** of the `BIND_` permission. The real work
here is reading `@xml/accessibility_config` to see what the service may observe and do.

**11.** (a) exported with no `writePermission`, so insert/update/delete are open; (b)
`grantUriPermissions="true"` with no `<grant-uri-permission>` child, so any URI under the authority is
grantable; (c) a `<path-permission>` naming `android.permission.INTERNET`; (d) the `readPermission`
it names has no `protectionLevel`, so it is `normal`.

**12.** `<path-permission>` is an **OR**, not an AND: `enforceReadPermissionInner` returns
`MODE_ALLOWED` as soon as *either* the component permission *or* a matching path permission is
satisfied. `INTERNET` is a `normal` permission every app holds, so `/public/` becomes readable by
every app regardless of the component-level `readPermission`. Worse, when a provider declares no
component permission at all, `allowDefaultRead` means every path matching *no* rule is allowed.

**13.** Visible: `exported="true"` (a `FileProvider` should be `exported="false"` with
`grantUriPermissions="true"`), and the authority `files` is not namespaced so it can collide with
another app's. Not visible: the contents of `@xml/file_paths_insecure` — resolve it from
`apktool`'s `res/xml/` output. See [`file_paths_insecure.xml`](../examples/file_paths_insecure.xml).

**14.** Weakest to strongest: `READ_USERS` (no attribute → `normal`) and `ADMIN` (explicitly
`normal`) are worth nothing; `INTERNAL_IPC` (`signature`) is a real control because only same-signed
apps can be granted it.

**15.** It lists Magisk, SuperSU and the Xposed installer, so the app does package-name-based root and
hooking detection and you now know which checks to defeat before reading any code. It also lists two
competitor banking apps, which is a behavioural and privacy finding in itself. Combined with
`QUERY_ALL_PACKAGES`, the app can enumerate everything anyway.

**16.** Filter 1 (`vulnapp://open`): not verifiable — a custom scheme is unowned and any app can
declare it; `BROWSABLE` means a web page can reach it. Filter 2 (`https`, `host="*"`,
`pathPattern=".*"`): matches every https URL on the internet, has no `autoVerify`, so it is an
ordinary deep link that any app can compete for, and it is remotely reachable. Both feed a WebView.

**17.** `com.google.android.geo.API_KEY` — needs validation (a key restricted to package + signing
digest is largely fine, and you cannot check that from outside; report it as "verify restrictions").
`com.example.partner.API_SECRET` — candidate secret, High if live. `…BACKEND_TOKEN` (JWT shape) —
candidate secret, High if live. `com.google.android.gms.ads.APPLICATION_ID` — **public by design**,
not a finding.

**18.** `<instrumentation android:targetPackage="com.example.vulnerable">`. The command is
`adb shell am instrument -w com.example.vulnerable/androidx.test.runner.AndroidJUnitRunner`, which
runs code **inside the app's process with the app's UID and permissions**. It matters because
`<instrumentation>` is a sibling of `<application>`, so it sits below the closing tag where auditors
have already stopped reading.

**19–20.** The script marks findings UNPROVEN when they depend on reachability, on data it has not
seen, or on a referenced file it cannot open. Removing the mark means, respectively: reaching the
component from an unprivileged app; enumerating the actual data; and reading the referenced XML. It
cannot judge impact, which is the whole reason a human does this job.

**21.** The three non-findings are the `BIND_ACCESSIBILITY_SERVICE`-guarded service, the `signature`
permission, and the AdMob application id. Reporting any of them is a specific and correctable error:
the first comes from pattern-matching on `exported="true"`, the second from pattern-matching on
"custom permission", the third from pattern-matching on "looks like an id". All three are cured by
the same habit — resolve the thing before you report it.

**22–24.** Target-specific. On a typical commercial app expect 40–120 components with 40–70% of them
contributed by SDKs, several implicitly exported components that a `grep` would miss, and at least
one `activity-alias`. Moving a finding from "declared" to "proven" always means the same thing:
reach the component from an **unprivileged app**, which is Lab 03.

</details>

---

## Success criteria

- [ ] You completed every row of the §5.6 checklist by hand before running any tool
- [ ] Your findings table has all seven columns, including **Proven?**
- [ ] You wrote out the full Version Matrix consequence list for `targetSdk=28`
- [ ] You enumerated every component, including the `activity-alias` and the two SDK-contributed ones
- [ ] You determined the effective `exported` value of the two components that have no attribute
- [ ] You resolved every custom `protectionLevel`, including the one that is absent
- [ ] You found all four `UserProvider` defects and can explain the `<path-permission>` logic
- [ ] You found both elements outside/at the bottom of `<application>`
- [ ] You classified every `<meta-data>` value and did **not** report the public one
- [ ] You identified at least one deliberate non-finding and did not report it
- [ ] You reconciled your table against the script and wrote down both sets of gaps
- [ ] You repeated the whole audit on a real APK from your own device
- [ ] You wrote two findings in full report form, each stating what you proved and what you did not
