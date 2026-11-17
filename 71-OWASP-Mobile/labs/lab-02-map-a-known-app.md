# Lab 02 — Map a Known App

**Difficulty:** Intermediate
**Time:** 6–10 hours, best split across two sessions
**Prerequisites:** [`lab-01`](lab-01-build-the-checklist.md),
[Chapter 71 §3 and §7](../README.md#3-deep-internal-working), a rooted device or emulator, `adb`,
`jadx`, `apktool`, Frida, an interception proxy, and the probe app from
[21-App-Sandbox lab 03](../../21-App-Sandbox/labs/lab-03-attacker-app.md)

---

## Objective

Run a complete, MASVS-mapped assessment against a deliberately vulnerable app — **OVAA** or
**InsecureBankv2** — and produce a **control-by-control result table** in which every row carries a
state *and a pointer to the evidence that justifies it*.

The deliverable is not a list of bugs. Everyone finds the bugs in OVAA; they are the point of OVAA.
The deliverable is a table where a reader can pick any row, follow the evidence reference, and
reproduce your conclusion — including the rows where the conclusion was "this passed".

---

## Why this matters

There is a specific and very common failure this lab is built to prevent, and it is invisible in a
finished report.

A tester runs a good assessment, finds eight real issues, writes them up well, and attaches a
coverage table. In the coverage table, every control with a finding says FAIL and every control
without a finding says PASS. The report looks complete.

But "no finding" and "passed" are different claims, and the second one is much stronger. A control
passes when you looked and it was fine. A control has no finding when you did not look, looked
briefly, could not look because you had no rooted device, or looked in the wrong place. Collapsing all
of those into PASS is the most common lie in mobile reporting, and it is almost always accidental.

> **Mental Model**
> A coverage table is a set of **claims about your own work**, not about the app. Each row says "here
> is what I did and what it showed". If a row cannot name an artefact, the row is empty regardless of
> what the state column says.

> **Definition**
> **Evidence reference** — a pointer to a stored artefact that a second person could open and reach
> your conclusion from: a filename, a log excerpt with a timestamp, a request/response pair, a script
> output file. Not "observed during testing".

The second lesson is ordering. You will work in **app order**, not checklist order, exactly as
[`lab-01`](lab-01-build-the-checklist.md) argued. The result table is assembled at the end, from
evidence collected in the order that was efficient. That inversion — test in the app's order, report
in the standard's order — is the practical skill this chapter teaches.

---

## Setup

### Choose your target

| Target | Choose it if | Trade-off |
|---|---|---|
| **OVAA** (Oversecured Vulnerable Android App) | You want a strong MASVS-PLATFORM workout: intent redirection, provider abuse, URI grant theft, deep links | No real backend, so MASVS-AUTH coverage is thin and you will record a lot of `BLOCKED` |
| **InsecureBankv2** | You want to practise AUTH and NETWORK properly | Ships with a backend you must run; PLATFORM surface is smaller and more dated |

Doing **both** is the ideal, and is what [`lab-04`](lab-04-portfolio-heatmap.md) will ask for anyway.
Pick one now.

### Record the environment first

```bash
# host
mkdir -p ~/lab71-02/{evidence,notes} && cd ~/lab71-02
export PKG=<the package name>
```

```bash
# host — identity of the artefact under test
sha256sum target.apk | tee evidence/00-apk-sha256.txt
apksigner verify -v --print-certs target.apk | tee evidence/00-signer.txt
aapt2 dump badging target.apk | grep -E 'package|sdkVersion' | tee evidence/00-badging.txt
```

```bash
# host — identity of the platform under test
adb shell getprop ro.build.fingerprint | tee evidence/00-fingerprint.txt
adb shell getprop ro.build.version.security_patch | tee -a evidence/00-fingerprint.txt
```

Fill in the test environment record from
[80-Appendix §6](../../80-Appendix/README.md#6-report-templates) and save it as
`notes/environment.txt`. Every claim you make in the result table is a claim about *this* artefact on
*this* platform, and a result table that does not identify either is not reproducible.

### Set up the evidence convention

Decide the naming scheme now, once, and never think about it again:

```text
evidence/NN-<workstream>-<what>.<ext>
```

for example:

```text
evidence/00-apk-sha256.txt
evidence/12-storage-datadir-diff.txt
evidence/21-crypto-jca-trace.log
evidence/33-platform-provider-query-from-probe.txt
```

The number prefix is the workstream, so evidence sorts in the order you collected it while the report
sorts by control. That is the whole trick — one artefact set, two orderings.

---

## Steps

### Workstream 0 — Scope, in the shape of lab 01

Before testing, produce the scope. Yes, for a deliberately vulnerable app. Do it anyway — the habit is
what transfers.

| Category | State | Reason |
|---|---|---|
| STORAGE | | |
| CRYPTO | | |
| AUTH | | |
| NETWORK | | |
| PLATFORM | | |
| CODE | | |
| RESILIENCE | | |
| PRIVACY | | |

**Question 1.** For a deliberately vulnerable training app with no real users, what is the honest
threat model? Write it in one sentence, and note how it differs from the threat model you would write
for the real app this one imitates.

**Question 2.** Which categories will be `BLOCKED` rather than assessable, purely because of the
target's nature? (OVAA users: think about what has no backend.)

### Workstream 1 — Static triage (feeds CODE, PLATFORM, and everything else)

Static work goes first because it changes where you look afterwards.

```bash
# host
apktool d -f target.apk -o out/ > /dev/null
jadx -d src/ target.apk > evidence/10-jadx.log 2>&1
```

```bash
# host — the declaration audit. Chapter 32 owns this; run its tool, do not rewrite it.
python3 ../../32-Manifest/scripts/manifest-audit.py out/AndroidManifest.xml \
    --markdown | tee evidence/11-manifest-audit.md
```

```bash
# host — the sandbox view of the same manifest
python3 ../../21-App-Sandbox/scripts/manifest-exposure.py out/AndroidManifest.xml \
    --markdown | tee evidence/11-manifest-exposure.md
```

```bash
# host — referenced config files, which is where the network policy lives
for f in out/res/xml/*.xml; do echo "== $f"; cat "$f"; echo; done \
    | tee evidence/11-res-xml.txt
```

**Controls this workstream feeds:** CODE-1 (`debuggable`, `targetSdk`, test artefacts), CODE-3
(dependency inventory), PLATFORM-1 (exported inventory — *as a shortlist, not a finding*),
NETWORK-1 (cleartext and trust configuration), STORAGE-1 (`allowBackup`).

**Question 3.** The manifest audit lists exported components. Which control does that output satisfy,
and which does it merely *shortlist*? Write the distinction in one sentence — you will use it again in
Workstream 5.

**Question 4.** Find `targetSdk`. List every legacy behaviour it re-enables, using
[80-Appendix §2](../../80-Appendix/README.md#2-the-android-version-matrix). Each one is a separate
observation, not one finding.

### Workstream 2 — Feature exercise with capture running (feeds STORAGE, PRIVACY, NETWORK, AUTH)

The single highest-value hour of the engagement, and the one people rush.

```bash
# host — snapshot before
adb shell "su -c 'tar czf /sdcard/before.tgz -C /data/data/$PKG .'"
adb pull /sdcard/before.tgz evidence/12-before.tgz
```

```bash
# host — start capture, in three terminals
adb logcat -c && adb logcat -v threadtime > evidence/12-logcat-full.txt
adb shell "su -c 'tcpdump -i any -s 0 -w /sdcard/cap.pcap'"
# and your interception proxy, configured and verified working
```

Now **drive every feature**. Log in, log out, log in again. Open every screen. Trigger every error.
Change a setting. Background the app. Rotate it. Let it sit until a token would expire. Keep a
timestamped list as you go:

```text
notes/exercise-log.txt
14:02  cold start
14:03  login as user1
14:06  viewed transaction list
14:08  changed a setting
...
```

That log is what lets you correlate a log line or a file write back to the action that caused it. Without
it, you have a heap of artefacts and no causality.

```bash
# host — snapshot after
adb shell "su -c 'tar czf /sdcard/after.tgz -C /data/data/$PKG .'"
adb pull /sdcard/after.tgz evidence/12-after.tgz
mkdir -p b a && tar xzf evidence/12-before.tgz -C b && tar xzf evidence/12-after.tgz -C a
diff -rq b a | tee evidence/12-storage-datadir-diff.txt
```

**Question 5.** For every file that appeared or changed, answer three things: what wrote it, what is
in it, and is any of it sensitive? The third question is the one no tool can answer for you — it is
the entire content of MASVS-STORAGE-1.

**Question 6.** Grep your logcat for credential-shaped strings. For each hit, decide whether it is a
STORAGE-2 finding or a PRIVACY finding — or both — and say why.

> **Pentester's Note**
> Do the storage diff **twice**: once across login, and once across a full feature exercise. Apps
> frequently write the interesting file on the third screen, not at authentication. A single diff
> across login only is the most common way a real storage finding is missed.

### Workstream 3 — Runtime cryptography (feeds CRYPTO)

```bash
# host — the JCA trace. Chapter 34 owns the hooking; this lab owns the mapping.
frida -U -f $PKG -l ../../34-Cryptography/scripts/frida-jca-universal-hook.js \
    | tee evidence/21-crypto-jca-trace.log
```

For every operation the trace shows, record a row:

| Operation | Algorithm | Mode | Padding | Key source | IV source | Control |
|---|---|---|---|---|---|---|
| | | | | | | |

**Question 7.** Is there any cryptographic operation in `jadx` output that does **not** appear in your
runtime trace? What are the two possible explanations, and how do you tell them apart?

**Question 8.** Which rows in your table are CRYPTO-1 and which are CRYPTO-2? State the dividing
principle in one sentence.

### Workstream 4 — Network and identity (feeds NETWORK, AUTH, PRIVACY)

```bash
# host — what the app actually talks to, including non-HTTP
adb pull /sdcard/cap.pcap evidence/22-cap.pcap
tshark -r evidence/22-cap.pcap -q -z endpoints,ip | tee evidence/22-endpoints.txt
```

Then run the deliberate-failure matrix. Presenting a *valid* proxy certificate proves only that
interception works; the control is about what the app does with a *bad* one.

| Certificate presented | Expected if NETWORK-1 satisfied | Observed | Evidence file |
|---|---|---|---|
| Valid, correctly chained | Connects | | |
| Expired | Refuses | | |
| Self-signed, untrusted | Refuses | | |
| Valid CA, wrong hostname | Refuses | | |
| User-store CA (device-installed) | Refuses on modern `targetSdk` | | |

**Question 9.** If the app connects through an interception proxy with no bypass at all, what have you
proven about NETWORK-2, and what have you *not* proven?

**Question 10.** Replay one authenticated request with the session token removed, and one with a
different user's identifier. What do the results tell you about AUTH-1 that no amount of app reading
could have?

### Workstream 5 — Platform surface, from a probe app (feeds PLATFORM)

**This is the workstream where reports most often go wrong**, and it is why the probe app is a
prerequisite.

```bash
# host — the shortlist, from the device's own view
adb shell dumpsys package $PKG | tee evidence/30-dumpsys.txt
```

```bash
# host — the WRONG way, useful only as a first probe
adb shell content query --uri content://<authority>/<path>
adb shell am start -n $PKG/<activity> --es url "https://example.com"
```

`adb shell` runs as UID 2000 with developer privileges no application holds. A component you reach
from a shell may be completely unreachable from an app, and a report that conflates the two is not
defensible. Reproduce each one from the probe app:

```bash
# host — install and drive the unprivileged probe
adb install -r probe.apk
adb shell am start -n com.probe/.MainActivity --es target "<authority-or-component>"
adb logcat -s PROBE | tee evidence/33-platform-provider-query-from-probe.txt
```

For every exported component, one row:

| Component | Type | Reached from `adb shell`? | Reached from probe app? | What came back | Control |
|---|---|---|---|---|---|
| | | | | | |

**Question 11.** Find a component where the two "reached from" columns differ. Which one goes in the
report, and what exactly does the other one tell you?

**Question 12.** For one component that *is* reachable from the probe app, write the finding's impact
sentence. Note how little the reachability itself contributes — the impact comes from what the
component does with the input.

### Workstream 6 — Code and dependencies (feeds CODE)

```bash
# host
apkid target.apk | tee evidence/40-apkid.txt
strings out/lib/*/*.so 2>/dev/null | grep -iE 'openssl|curl|sqlite|zlib|libpng' \
    | sort -u | tee evidence/40-native-versions.txt
```

Build the inventory: library, version, source of the version claim, known-vulnerable yes/no/unknown.
"Unknown" is a legitimate and common state — record it rather than guessing.

**Question 13.** For one library where you could not determine the version, write the sentence you
would put in the report. It should be honest about the limitation without being useless.

### Workstream 7 — Resilience, if and only if it is in scope

If your Workstream 0 scope excluded RESILIENCE, **skip this and record the exclusion**. Do not test it
because it is fun. That is the discipline.

If it is in scope: inventory the protections, then measure each one's bypass cost in minutes, and
record the number. A protection inventory without bypass costs is a list, not an assessment.

| Protection | Present? | Bypass method | Time to bypass | Server consumes verdict? |
|---|---|---|---|---|
| | | | | |

**Question 14.** For any protection you bypassed, write the finding. Check it against this rule: the
finding is never "I bypassed X". It is either "these protections are absent or trivially defeated and
here is the business risk" or "having bypassed them, here is what I found". Which is yours?

### Workstream 8 — Assemble the result table

Now, and only now, reorder everything into the standard's structure.

One row per control. States:

| State | Means | Requires |
|---|---|---|
| `PASS` | Tested, and the requirement holds | An evidence reference |
| `FAIL` | Tested, and the requirement does not hold | A finding ID **and** an evidence reference |
| `PARTIAL` | Some tests run, some not; or holds in some flows and not others | Evidence for what was run, and a note on what was not |
| `NOT-TESTED` | Deliberately excluded | The reason, from Workstream 0 |
| `BLOCKED` | Would have tested, could not | The obstacle |

```markdown
| Control | State | Evidence | Finding | Note |
|---|---|---|---|---|
| MASVS-STORAGE-1 | FAIL | evidence/12-storage-datadir-diff.txt | F-01 | Session token plaintext in shared_prefs |
| MASVS-STORAGE-2 | FAIL | evidence/12-logcat-full.txt:4471 | F-02 | Token logged at INFO on every refresh |
| MASVS-CRYPTO-1 | FAIL | evidence/21-crypto-jca-trace.log | F-03 | AES/ECB, static key |
| MASVS-CRYPTO-2 | FAIL | evidence/21-crypto-jca-trace.log | F-03 | Key is a constant byte array, never reaches KeyStore |
| MASVS-AUTH-1 | BLOCKED | — | — | No backend available for this target |
| ... | | | | |
```

A worked example of the finished article, at report quality, is
[`examples/assessment-result-table.md`](../examples/assessment-result-table.md). **Build yours first,
then compare** — reading the answer before doing the work removes the entire point.

**Question 15.** How many of your rows say `PASS`? For each one, open the evidence file you cited. Does
it actually support the claim? Change any that do not to `PARTIAL` or `NOT-TESTED`. This is the most
uncomfortable step in the lab and the one that most improves your reports.

### Workstream 9 — Run the coverage tool

```bash
# host — from 71-OWASP-Mobile/
python3 scripts/mas-coverage.py examples/findings-ovaa.csv
```

Then against your own findings, written in the same CSV shape (the header row is documented in the
script's `--help`):

```bash
# host
python3 /path/to/71-OWASP-Mobile/scripts/mas-coverage.py ~/lab71-02/notes/findings.csv --markdown
```

The script deliberately refuses to treat a control as covered when its row has no evidence reference.
That refusal is the entire discipline of Workstream 8, mechanised.

**Question 16.** Compare the script's gap list against your own result table. Did it find a control you
had silently dropped? Most people's first run does.

---

## Hints

<details>
<summary>Hint 1 — the data directory diff is enormous and full of noise</summary>

Filter the classes that are always noisy, and look at the rest by hand:

```bash
# host
diff -rq b a | grep -vE 'cache/|code_cache/|/files/PersistedInstallation|\.lock$'
```

Then, for anything that survived, diff the *contents*, not just the presence:

```bash
# host
diff -u b/shared_prefs/*.xml a/shared_prefs/*.xml
```

The `shared_prefs` and `databases` directories are where the answer usually is.
</details>

<details>
<summary>Hint 2 — the app crashes under Frida</summary>

Either the app has anti-instrumentation (a RESILIENCE observation in its own right — record it) or
your spawn timing is wrong. Try attaching to a running process instead of spawning:

```bash
# host
frida -U -n <process-name> -l script.js
```

If it is genuinely detection, note it and continue with static analysis for CRYPTO, marking the
affected controls `PARTIAL` with the reason. Do not silently downgrade to a code read and call it
`PASS`.
</details>

<details>
<summary>Hint 3 — I cannot get the probe app to see the target's components</summary>

Package visibility. From API 30, your probe cannot see the target unless it declares it:

```xml
<queries>
    <package android:name="com.target.package" />
</queries>
```

This is a real and instructive failure: a probe app that omits `<queries>` silently returns wrong
results, and you would have recorded "not reachable" for a component that is perfectly reachable. See
[21-App-Sandbox](../../21-App-Sandbox/README.md).
</details>

<details>
<summary>Hint 4 — InsecureBankv2's backend will not start</summary>

It is a Python 2-era Flask application. Run it in a container or a virtualenv pinned to its
documented dependencies rather than fighting your system Python. If you cannot get it running, record
every AUTH control as `BLOCKED` with that reason — which is itself a realistic engagement outcome and
worth experiencing.
</details>

<details>
<summary>Hint 5 — how do I decide PASS vs PARTIAL?</summary>

Ask: "could I have reached this conclusion by looking at only part of the surface?" A NETWORK-1
`PASS` based on HTTP interception alone is `PARTIAL`, because you did not look at non-HTTP traffic. A
STORAGE-1 `PASS` based on a diff across login alone is `PARTIAL`, because you did not exercise every
feature.

If in doubt, `PARTIAL` with a note is always defensible. `PASS` is a strong claim.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** Honest threat model for a training app: there is none, because there are no real assets and no
real adversaries. What you are actually doing is rehearsing procedure against known-vulnerable code.
Say so — and note the difference from the real app it imitates, where the threat model would drive
scope and severity. This matters because severity ratings assigned to OVAA findings are exercises,
not judgements: there is no business impact to argue from.

**2.** For OVAA: most of AUTH, because there is no backend to enforce anything against, and much of
PRIVACY, because there is no real egress. Record these as `BLOCKED` with the reason "target has no
backend", not as `PASS`. Recording them as `PASS` would be the exact error this lab exists to prevent.

**3.** The manifest audit *satisfies* nothing about PLATFORM-1 and *shortlists* everything. A
declaration is not a reachability proof. The one-sentence version: "the manifest tells me what the
developer declared; only an unprivileged app tells me what an attacker can reach."

**4.** Depends on the target, but for anything below `targetSdk` 31 you get implicit `exported`
defaults on filtered components and implicitly mutable `PendingIntent`s; below 28, cleartext
permitted by default; below 24, user-added CAs trusted; below 29/30, legacy external storage. Each is
its own observation because each is separately fixable and separately testable.

**5.** The three questions decompose the control correctly. "What wrote it" needs the exercise log or
a Frida file-open hook. "What is in it" needs you to actually open the file — including SQLite
databases, which must be opened with `sqlite3`, not `strings`. "Is it sensitive" needs the app's
business context and is not automatable, which is why an automated MASVS score is not an assessment.

**6.** STORAGE-2 covers leakage through unintended channels, and the system log is the canonical one.
PRIVACY applies when the leaked value identifies a *user* rather than authenticating a *session*. A
session token is STORAGE-2. A device identifier joined to an account ID is both. Say which and why in
the finding rather than picking one silently.

**7.** Two explanations: (a) the code path never executed during your exercise — meaning your feature
coverage was incomplete, which is a gap in *your* work; or (b) it executed in native code, below the
JCA, and your hook cannot see it. Tell them apart by hooking the native crypto entry points, or by
forcing the path with a targeted interaction. Never assume (a) without checking (b) — a native crypto
implementation is exactly where a hardcoded key hides.

**8.** CRYPTO-1 is about the *operation*: algorithm, mode, padding, IV, randomness. CRYPTO-2 is about
the *key*: where it came from, where it lives, what protects it. The dividing principle: if the finding
survives changing the algorithm, it is CRYPTO-2. A hardcoded key is still a hardcoded key under
AES-GCM.

**9.** You have proven there is no *effective* pinning: NETWORK-2 is not satisfied. You have proven
nothing about NETWORK-1, which is about validation generally — the app might still correctly reject
an expired or wrong-host certificate. The failure matrix is what separates the two claims, and it is
why "Burp works, therefore no TLS validation" is wrong.

**10.** It tells you where enforcement lives. If removing the token still returns data, authorization
is not enforced at all. If a different user's identifier returns their data with your token, you have
an IDOR — the highest-value class of finding on most mobile engagements, and one that is entirely
invisible from the app's code, because the app is behaving correctly. This is the practical form of
"most high-severity mobile findings are on the backend".

**11.** The probe-app result goes in the report. The `adb shell` result tells you the component is
reachable *by a shell*, which matters for a physical-access or ADB-enabled threat model and nothing
else. If they differ, the difference is usually a permission the shell holds and an app does not — say
which permission, because that is the actual control that saved them.

**12.** The impact sentence should name what an attacker achieves, not what they invoke. "Any installed
app can read the user's stored session token by querying an exported provider, yielding full account
access with no user interaction" is impact. "The provider is exported" is a declaration. Reachability
is a precondition; the payoff is the finding.

**13.** Something like: "The bundled native library could not be version-identified from the shipped
artefact; symbol strings suggest an OpenSSL-derived build but do not carry a version. We recommend the
vendor confirm the version from their build pipeline and check it against current advisories." Honest,
actionable, and does not fabricate a CVE.

**14.** Almost always the first form for a training app, because the protections are token. Write it
as: "The app implements a single root check that is defeated in under two minutes with a standard
tool. Given [the named adversary], this provides no meaningful cost increase." If you found something
*after* the bypass, that finding is separate and usually more severe.

**15.** Most people find at least one `PASS` whose evidence does not support it — typically NETWORK-1
based on an HTTP-only capture, or STORAGE-1 based on a login-only diff. Downgrading them is not a
failure; it is the moment the coverage table starts being true.

**16.** The commonest silent drop is a control that no workstream naturally produced evidence for —
CODE-2 (update enforcement) and PRIVACY-4 (user control over data) are the usual suspects, because
neither falls out of any tool. They have to be tested deliberately or excluded deliberately.

</details>

---

## Success criteria

- [ ] You recorded APK hash, signer, and device fingerprint before testing anything
- [ ] You wrote a scope with category-level decisions *before* starting, even for a training app
- [ ] You tested in app order and reported in standard order
- [ ] You kept a timestamped exercise log and can correlate any artefact back to an action
- [ ] Your storage diff spans a full feature exercise, not just login
- [ ] Your crypto evidence is a runtime trace, not a grep
- [ ] You ran the full certificate-failure matrix, not just "does Burp work"
- [ ] Every PLATFORM conclusion was reproduced from an unprivileged probe app
- [ ] Every result-table row carries an evidence reference, including the `PASS` rows
- [ ] You used `BLOCKED` where you could not test, and never wrote `PASS` in its place
- [ ] You downgraded at least one `PASS` after checking its evidence
- [ ] You ran [`scripts/mas-coverage.py`](../scripts/mas-coverage.py) and reconciled its gap list
- [ ] You compared your table to [`examples/assessment-result-table.md`](../examples/assessment-result-table.md)
      only *after* finishing your own

---

## Where next

| Then do | For |
|---|---|
| [`lab-03-find-the-gap.md`](lab-03-find-the-gap.md) | The finding this whole table could never have contained |
| [`lab-04-portfolio-heatmap.md`](lab-04-portfolio-heatmap.md) | The same table across three apps, and what only becomes visible then |
| [`examples/finding-mapped-twice.md`](../examples/finding-mapped-twice.md) | What the difference between a mechanical and a considered mapping looks like on the page |
