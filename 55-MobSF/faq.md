# 55 — MobSF FAQ

Twenty questions, in the order people actually ask them. Several are the "dumb" ones, which are
usually the ones with the most expensive wrong answers.

---

## 1. Can I just send a client the MobSF report?

**No.** And this is the question the chapter exists to answer, so it gets a long answer.

A MobSF report is a list of things a rule set matched in a file. It is not an assessment, and
sending it as one fails in four specific ways:

- **The severities are not yours.** Every severity and CVSS in it is a constant written by a rule
  author for every application that will ever match. On this chapter's worked example, one finding
  carried `cvss: 8.8` — the same 8.8 it carries for an app whose WebView only ever loads a bundled
  help page.
- **The item count is not a finding count.** 39 items became **8 findings** after validation here.
  Fifteen were rejected outright, six were merged into other findings, and eleven were the report's
  own scorecard restating its other sections.
- **Some of it is simply wrong**, including in the reassuring direction. The same report claimed the
  app does not implement certificate pinning. It does — one grep proves it.
- **It has no limits section**, so the reader cannot tell what was not examined. Nothing in the
  report says that 69% of the broadcast surface is invisible to it, or that a split APK would have
  produced a full, plausible report of a fraction of the app.

If you want to give the client the raw output as well, do — as **Appendix C, labelled "raw scanner
output, unvalidated"**. That is genuinely useful and completely honest. What you cannot do is put a
cover page on it.

> The fastest way to lose a client is to deliver a scanner export as a penetration test. The second
> fastest is to deliver one where two items are visibly nonsense, because everything else you wrote
> gets discounted with them.

---

## 2. Why does it flag every app for certificate pinning — or say every app has none?

Because it is looking for a **type name**, and a type name is a bad proxy for a behaviour in both
directions.

**The false-positive direction.** `okhttp3.CertificatePinner` is on the classpath of every
application that uses OkHttp, whether or not a pin was ever configured. So does OkHttp's own
`X509TrustManager`, its `HostnameVerifier`, and its pin-failure message string. All of that ships
unconditionally with the library.

[36-CertificatePinning](../36-CertificatePinning/README.md) measured the gap across **fourteen real
applications**: **twelve presented a pinning surface, and four had a pin value anywhere in the APK.**
Reporting the surface would have produced twelve findings, **eight of them wrong**.

**The false-negative direction is worse, and it is measured in this chapter.** R8 renames
`okhttp3.CertificatePinner` to something like `m.e`, and a name-based rule finds nothing. The
application in §5.3 of the README configures a pin and the scan says it does not.

**The fix is one grep, and it works in both directions**, because R8 renames symbols and not string
literals:

```bash
mkdir -p /tmp/dexes && unzip -o -j target.apk 'classes*.dex' -d /tmp/dexes
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/dexes/*.dex | sort -u
```

The 43 characters matter. `grep sha256/` alone matches OkHttp's own parser constant and hits on
essentially every app that uses OkHttp.

And even a real pin value is not proof of enforcement. The honest sentence is *"the application
configures a pin for host X"*, followed by whether you observed a handshake being rejected.

---

## 3. Is the dynamic analyser worth it?

**For breadth on an unfamiliar app, yes. For answering a specific question, no — use Frida.**

What it gives you that static analysis cannot: a traffic log, a filesystem diff, and a runtime API
trace. The traffic log is the genuinely valuable part, because it shows what the app actually sends.

What it does not give you:

- **Coverage.** It launches activities and pokes exported components. It does not log in, complete a
  purchase, or reach the branch behind a feature flag. It describes the app's front porch.
- **Any idea what it missed.** This is the fatal one.
  [51-DynamicAnalysis](../51-DynamicAnalysis/README.md) measured the failure mode exactly: an
  `am start` absorbed by a permission dialog left all nine capture channels silent, and **the report
  looked identical to a well-behaved app doing nothing wrong.** Every dynamic session needs a
  liveness check before its silence means anything, and MobSF does not provide one.

Add your own liveness check before you believe any quiet dynamic report:

```bash
adb shell pidof com.example.target
adb shell "logcat -d --pid=\$(pidof com.example.target)" | wc -l   # zero is a RED FLAG
```

---

## 4. Does MobSF need root?

**Static analysis: no.** You need only the file. No device at all.

**Dynamic analysis: effectively yes.** It needs to install a CA into the *system* trust store, run
`frida-server` as root, and read the app's private directories. In practice that means MobSF's own
prepared AVD image, Genymotion, or a rooted physical device. A stock retail phone will not do.

And a warning that applies to any rooted test device: check what your rooting stack did to the trust
store first.

```bash
adb shell mount | grep cacerts
```

On the rooted device used by several chapters in this repository, APatch had replaced
`/system/etc/security/cacerts` with a tmpfs containing 139 certificates including an interception CA.
The consequence is severe and easy to miss: **a successful intercept on that device does not prove
the app trusts user-installed CAs**, because the proxy CA is in the *system* store. A device whose
posture you have not established will teach you the opposite of the truth.

---

## 5. Why do two runs of the same APK give different results?

Four distinct causes. Check them in this order.

1. **It is a different artefact.** Compare the `sha256` in the two reports. Do this first, always —
   a rebuild with no source changes produces a different hash because the signature block and ZIP
   metadata differ.
2. **The cache.** MobSF keys scans on the file hash. Uploading the same bytes again returns the
   *stored* result, produced under whatever rule set was installed when the scan actually ran. So an
   upgrade plus a re-upload gives you the old report. Fix:
   `POST /api/v1/delete_scan` with the hash, then re-upload.
3. **Different MobSF versions.** Rule sets move between releases. The `version` key is at the top of
   the JSON for exactly this reason. **Two reports from different MobSF versions are not comparable**,
   and the differences will look like application changes.
4. **Schema drift broke your parser.** `manifest_analysis` has been a bare list and a dict with a
   `manifest_anal` key. A parser that assumes one shape silently reads *zero* findings from the
   other — which looks like a clean app.

Record the MobSF version next to the artefact hash in your notes. "MobSF flagged it" is not a
citation.

---

## 6. Should I put the security score in my report?

**No.** It is a count of rule matches weighted by rule metadata. It contains no information about
your application's assets, users, threat model or deployment.

The demonstration in the README is worth repeating. Two builds of one application:

| | v1.0 | v1.2 |
|---|---|---|
| Score | 34 | 38 |
| `debuggable=true` | yes | no |
| Exported providers | 0 | 2, one unprotected |
| WebView bridge with attacker-controllable URL | none | **yes** |
| Browsable deep link granting access on a literal | none | **yes** |

The score says v1.0 is worse. v1.2 carries a bridge that leaks an auth token to any co-installed
app, plus an unprotected provider over the app's private files. **The ranking is inverted relative to
attacker value.**

And if a client wants to *gate* on it: they have specified passing a rule set, not being secure, and
the specification is trivially gamed. Offer the replacement — gate on a short list of unambiguous
facts (`debuggable`, debug certificate, `allowBackup` with no rules file, a *new* exported component,
a *new* cleartext endpoint), gate on deltas rather than absolutes, and file everything else as a
lead.

---

## 7. MobSF says my app has 14 exported activities. Is that 14 findings?

No. It is fourteen **doors**. MobSF has not tried any of the handles, does not know what is behind
them, and does not know that one of them is the launcher activity, which is exported because the
platform must be able to start it.

An exported component becomes a finding when you can say what an unprivileged caller *achieves*. So:

```bash
# NOT this - adb shell is not an app
adb shell am start -n com.example/.SomeActivity
```

[60-ADB](../60-ADB/README.md) measured why that proves nothing: the `com.android.shell` package
requests **200 permissions**, 183 granted at install and **16 runtime permissions pre-granted
`SYSTEM_FIXED`**, including `CAMERA`, `RECORD_AUDIO` and `READ_SMS`. Anything reachable from the
shell may be unreachable from an ordinary app. Prove reachability from an app.

---

## 8. What is the very first thing I should read in a MobSF report?

**The bottom.** The file list and the app type.

MobSF prints them below sixty findings, so almost nobody reads them — and they are what tells you
whether the sixty findings above are about the application at all:

| What you see | What it means |
|---|---|
| One small `classes.dex` in a large app | A packer or a cross-platform runtime. Everything above describes a stub |
| `assets/index.android.bundle` | React Native — the logic is JavaScript |
| `libflutter.so` + `flutter_assets/` | Flutter — the HTTP stack is Dart and no Java rule sees it |
| `libil2cpp.so` | Unity |
| No `lib/` in a big app | The native code is in a split you were not given |

Read a report bottom-up on the first pass: files, app type, libraries, component inventory, then
findings.

---

## 9. It found 40 "hardcoded secrets". Is my app leaking 40 secrets?

Almost certainly not. Classify each value before you use the word.

`MEASURED` on this chapter's example — of seven "secrets", **one** was interesting:

| Shape | It actually is | Verdict |
|---|---|---|
| `sha256/` + 43 base64 chars | An **SPKI pin** — a *public* key hash, published in every TLS handshake | Not a secret. Ever |
| 64 hex characters | A **digest**. If it is a password verifier, the finding is the algorithm, not the value | Re-frame |
| base64 → readable text | Obfuscation, defeated. "Encoding is not encryption" | Real; severity from what it protects |
| base64 → high-entropy bytes | Ciphertext. **Only a finding if the key is also in the artefact** | Follow the key |
| A URL | An endpoint | Endpoint inventory |

[33-Storage](../33-Storage/README.md) published the extreme case: its own secret hunter returned
**132 high-confidence hits against real Chrome data, all 132 false positives** — every one a
component-updater signature manifest that matched a JWT-shaped rule because it genuinely *is* signed
JSON. Not one was a mistake by the tool. Every rule fired correctly. The tool was answering "does
this look like a credential", and the question that mattered was "is this a credential".

---

## 10. Is MobSF's CVSS the CVSS I put in my report?

No. It is the rule's CVSS, written once by a rule author, identical for every application that ever
matched. It does not know whether the construct is reachable, what it protects, or whether it is in
the app's own code or a vendored library from 2014.

Derive your own severity from **what an attacker gains by reaching the construct**. The rubric in
[52 §5.5](../52-StaticAnalysis/README.md#55-the-four-questions-as-a-rubric) is four questions:

1. Is the construct really there?
2. Is it reachable?
3. Reachable **by whom**?
4. **What does reaching it get them?** — this is the severity.

---

## 11. My scan found almost nothing. Is the app secure?

Five explanations, in descending order of likelihood, and only the last one is "the app is fine":

1. **You scanned the wrong artefact.** `base.apk` of a split app, or a stub. 36 measured the professional-network app's
   installed `base.apk` at **334 KB** — a scan of that describes a downloader.
2. **The app is packed or cross-platform.** Check `assets/` size against DEX size.
3. **Obfuscation defeated the name-based rules.** The signature of this case is distinctive: a full
   URL list and secrets section (value-derived, unaffected) beside an empty code-analysis section
   (name-derived, gone).
4. **Strings are encrypted.** An app with no URLs at all is building them, not lacking them.
5. **It is small and genuinely clean.** More common than cynics expect.

Report it as **"the scan produced no findings above threshold"**, never as "no issues found", and put
the blind-spot section immediately underneath.

---

## 12. Can I trust MobSF on an obfuscated app?

Half of it. The rule is exact and worth memorising:

> **Anything a scanner derives from DATA survives obfuscation. Anything it derives from NAMES does
> not.**

| Survives R8 | Destroyed by R8 |
|---|---|
| Manifest attributes and component names | Application class, method and field names |
| String literals (URLs, secrets, pins) | Package prefixes |
| Resource values | Library and tracker identification |
| ZIP structure and file list | Type-name rules (pinning, root-detection libraries) |
| Framework API names (`javax.crypto`, `WebView`) | Readability of the cited file |
| Certificate and signature data | — |

The consequence people get backwards: **a scanner's report on an obfuscated app is systematically
shorter, and shorter is not safer.** It is less visibility. If a client enables obfuscation between
two tests, expect the report to shrink, re-baseline on the value-derived sections, and re-check every
*negative* claim by hand.

---

## 13. Why does MobSF flag `setJavaScriptEnabled(true)`? Every app does that.

It does, and on its own it is not a finding. It is an **aggravator**: it matters only when joined to
something else.

The join that makes it a High, `MEASURED` on this chapter's example app — three facts in three
different report sections plus one that is in no section at all:

| Fact | Section |
|---|---|
| `WebViewActivity` is `exported="true"` | manifest |
| `setJavaScriptEnabled(true)` | code |
| `addJavascriptInterface(new WebAppInterface(), "AndroidBridge")` | code |
| The URL comes from `getIntent().getStringExtra("load_url")`, unvalidated | **nowhere** — no rule fires on a data flow |

Any app on the device, holding no permissions, can point that WebView at a page it controls and call
`AndroidBridge.getAuthToken()` from JavaScript.

**MobSF's analysers are one-pass and independent**, so it cannot make that join even in principle.
Making it is your job, and it is most of what makes a report worth paying for.

---

## 14. Should I add my own rules?

Yes, if your engagements repeat — an in-house crypto helper, a company-specific credential format, a
particular SDK. Ten minutes of YAML runs on every future scan.

Two disciplines keep an added rule from making things worse:

1. **Set `severity: info`, whatever you think it is worth.** Severity belongs to stage 7. The same
   argument applies to `semgrep`'s severity field, and 52 makes it there.
2. **Write it as `regex_and`** so it requires two independent signals. A single-pattern rule over a
   decompiled tree will find you a hundred hits in `androidx/`.

Read your instance's existing catalogue first — it is the single most useful file in the project:

```bash
find . -path '*android/rules*' -name '*.yaml' | head
grep -n -A6 'AES/ECB' mobsf/StaticAnalyzer/views/android/rules/*.yaml
```

---

## 15. Is it safe to upload a client's APK to a public MobSF instance?

**No, and it may be a contract breach.**

A MobSF instance retains, indefinitely and on disk: every artefact ever uploaded, the **decompiled
source** of every one, and the extracted secrets, endpoints and certificates — all guarded by a
**single static API key with no scopes**.

Rules:

| Rule | Why |
|---|---|
| Never upload a client artefact to an instance you do not control | It is a disclosure of an unreleased binary |
| Bind to localhost: `-p 127.0.0.1:8000:8000` | The common `-p 8000:8000` listens on every interface |
| One instance per engagement, destroyed afterwards | `delete_scan` per hash, then remove the container |
| Treat the key as a credential and rotate it | It will end up in CI logs and `docker inspect` |
| Run it in a container on a host you can lose | It parses hostile input for a living |
| Check the engagement scope first | Some contracts prohibit third-party processing entirely |

The dynamic analyser raises the stakes further: it installs the app on a device it controls and can
route its traffic through its own proxy. On a shared instance, a third party sees your client's API
traffic.

---

## 16. MobSF says the provider is "protected by a permission". Is it safe?

**Read the title again — the tool is telling you it has not done the check.** MobSF's own wording is
usually *"…but the protection level of the permission should be checked"*, and in a 39-item report
nobody reads that clause.

Do the check. `MEASURED` on this chapter's example:

```bash
aapt2 dump xmltree --file AndroidManifest.xml target.apk | grep -A2 'E: permission'
#       E: permission (line=23)
#         A: ...:name="org.android.cmpen.permission.ACCESS_FLAG"
#         A: ...:protectionLevel(0x01010009)=0x00000000
```

`0x00000000` is `normal`. **Any application may declare `<uses-permission>` for it and receive it at
install time**, with no prompt and no signature check. The guard is decorative, and the provider
returns a token from `query()`.

MobSF rated that `info`. It is a Medium. This is the one class of scanner error that points the
*wrong way*, and it is the reason you work the low-severity rows too.

The levels, for reference: `0` normal, `1` dangerous, `2` signature, `3` signatureOrSystem — and the
high bits are flags. Only `signature` and above are guards.

---

## 17. What about the `minSdk` warning?

Reject it, unless you can name the weakness.

The rule performs an integer comparison and produces prose about "multiple unfixed vulnerabilities"
without naming one. Ask: *which* vulnerability, and how does this application touch it? If you cannot
answer, the item is not a finding — `minSdk` is a support decision.

Reporting it spends the client's remediation budget on a compatibility choice and costs you
credibility on the items that matter. It goes in the rejected-leads ledger with that reason written
out.

---

## 18. How long should validating a report take?

`MEASURED` on this chapter's 39-item example: about **three hours**, of which the automated
evidence-gathering pass was under a minute and the rest was reading files.

A rough budget for a single medium application:

| Step | Time |
|---|---|
| Scan (MobSF) | 2–10 minutes of the machine's time |
| Orient — files, app type, libraries, splits | 15 minutes |
| Automated corroboration (`mobsf-validate.py`) | 1 minute |
| **Hand adjudication of every item** | **the rest of the day** |
| Write findings, ledger and limits section | 2 hours |

The shape of that table is the argument. The scan is ninety seconds; the job is the adjudication.
A methodology that spends its day scanning and its last twenty minutes validating produces a report
that is 90% scanner output, and everyone downstream can tell.

If you only have half a day: validate the items an automated check settled outright plus everything
in the app's own packages, and **say in the report that you did exactly that**.

---

## 19. What do I do with the appsec scorecard?

Ignore it as a source of findings. It **restates** the manifest, code and certificate sections —
`MEASURED`, 11 of 39 items in this chapter's run, **28%**.

Counting scorecard entries separately is how a 12-item scan becomes a 39-item "report", and it is
usually unintentional: a script walks every list in the JSON and the scorecard lists get walked too.
This chapter's validator gives them their own verdict, `RESTATES`, and excludes them from the
survival rate, printing both numbers so the difference is visible:

```
  all items          : 17 of 39 survived first-pass corroboration (43.6%)
  excluding scorecard: 17 of 27 (63.0%)
```

The one thing the scorecard is good for: its `secure` band tells you what MobSF thinks the app got
*right*, and those are the claims most worth disbelieving (question 2).

---

## 20. If MobSF is this unreliable, why run it at all?

Because "unreliable" is the wrong word. It is **reliable at what it does** — census, inventory,
pattern matching, configuration checks — and people ask it for something else.

Four reasons to run it, none of which this chapter retracts:

- **Seven hours of mechanical work per unfamiliar application, in ninety seconds**, done the same way
  every time including the day you are tired.
- **Corpus work.** Twenty APKs, one command, comparable JSON per app, cached by hash. Nothing else in
  this repository's toolbox does that.
- **A checklist you did not have to remember.** It will check `allowBackup`, the signature scheme,
  the `<pin-set>` and forty other things every single time.
- **A shared vocabulary with the client.** Their security team runs MobSF too. Being able to say
  *"your scan flagged fourteen items; here is why nine are not findings, and here are two findings it
  missed"* is a more valuable conversation than never mentioning it — and it is
  [STYLE-GUIDE §7](../STYLE-GUIDE.md)'s definition of senior, which is precisely *"explain why an
  automated tool's finding is a false positive"*.

You cannot do that for a tool you refuse to run.

The failure is not running MobSF. **The failure is stopping where MobSF stops.**
