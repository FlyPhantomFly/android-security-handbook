# Lab 01 — The first scan, and reading it bottom-up

**Level:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [10-APK-Internals](../../10-APK-Internals/README.md),
[32-Manifest](../../32-Manifest/README.md), and a working `aapt2` (Android build-tools).
**MobSF required:** **No.** A saved report ships with this chapter. If you have MobSF, step 2 says
which command to replace.

---

## 0. Why this lab exists

Everybody reads a scanner report the same way the first time: score at the top, then the red items,
then stop. Every one of those is the **least** reliable part of the document.

The parts that are reliable — the file list, the app type, the library inventory, the component
census — are printed near the *bottom*, below sixty findings, so almost nobody reads them. And they
are the parts that tell you whether the sixty findings above them are about the application at all.

By the end of this lab you will have read one report in the correct order, produced two lists (things
you would sign your name to, and things you would not), and written a limits statement. You will not
be able to read a scanner report top-down again, which is the actual objective.

---

## 1. Objective

Produce three artefacts about one application:

1. **An inventory you trust** — what this application *is*, structurally.
2. **A claims list you do not trust** — every opinionated line in the report, with the check that
   would settle each one.
3. **A limits statement** — at least four classes of thing the scan structurally could not see.

Nothing in this lab asks you to find a vulnerability. That is lab 02.

---

## 2. Setup

### 2.1 The artefact

You need one APK. Any of these work:

| Source | Note |
|---|---|
| A public training app (CMPen, InsecureBankv2, DIVA, OVAA, the MobileHackingLab targets) | Best for a first run — they are *meant* to be analysed |
| An app already on your own device | Real, and free. See below |
| An APK from a mirror | Fine for practice; hash it and record where it came from |

Pulling one off your own device, which is the habit worth building:

```bash
# host — EVERY path, not just the first. This matters and section 4 says why.
adb shell pm list packages -3 | head -20
adb shell pm path com.example.target
# package:/data/app/~~AbC==/com.example.target-XyZ==/base.apk
# package:/data/app/~~AbC==/com.example.target-XyZ==/split_config.arm64_v8a.apk

adb pull /data/app/~~AbC==/com.example.target-XyZ==/base.apk .
sha256sum base.apk | tee -a evidence/hashes.txt
```

> **Do not skip the hash.** A finding backed by "file X, SHA-256 …" can be re-checked by anyone, a
> year later, with no device. A finding backed by "I looked at the app on Tuesday" cannot.

### 2.2 A report

**Without MobSF** — use the fixture that ships with this chapter:

```bash
# host
cd 55-MobSF
ls examples/synthetic-mobsf-report.json
python3 -B -c "import json;d=json.load(open('examples/synthetic-mobsf-report.json'));print(d['_fixture']['WHAT_IS_REAL'][:200])"
```

Read that `_fixture` block before anything else. It tells you exactly which parts of the file are
real measurements and which are reconstructed structure. **A report whose provenance you have not
read is a report you cannot cite** — which is a lesson this lab wants you to learn on a file that is
honest about it, rather than on a client's.

**With MobSF** — produce your own:

```bash
# host
export MOBSF_API_KEY='<key from the UI>'; export MOBSF_SERVER='http://127.0.0.1:8000'
AUTH="Authorization: $MOBSF_API_KEY"
H=$(curl -s -H "$AUTH" -F "file=@base.apk" "$MOBSF_SERVER/api/v1/upload" \
    | python3 -B -c "import sys,json;print(json.load(sys.stdin)['hash'])")
curl -s -H "$AUTH" -X POST --data "hash=$H&scan_type=apk&file_name=base.apk" \
     "$MOBSF_SERVER/api/v1/scan" >/dev/null
curl -s -H "$AUTH" -X POST --data "hash=$H" "$MOBSF_SERVER/api/v1/report_json" > report.json
```

### 2.3 Tools

```bash
# host — check what you have before you need it
aapt2 version            || echo "no aapt2 - install Android build-tools"
python3 --version
unzip -v | head -1
jadx --version           || echo "no jadx - steps 6 and 7 will be shallow"
apksigner --version      || echo "no apksigner - step 5 uses a fallback"
```

None of this lab requires root, a device, or a network.

---

## 3. Step 1 — Read the bottom of the report first

Open the JSON, not the HTML. The HTML is a rendering; the JSON is what the tool decided.

```bash
# host — what sections exist at all?
python3 -B -c "import json;print('\n'.join(sorted(json.load(open('report.json')))))"
```

Now, in this order:

### 3.1 What kind of application is this?

```bash
# host
python3 -B -c "
import json; d=json.load(open('report.json'))
for k in ('app_type','app_name','package_name','version_name','version_code',
          'size','min_sdk','target_sdk','sha256','version'):
    print('%-14s %s' % (k, d.get(k)))"
```

Write those down. The last one — `version` — is the **MobSF version**, and it belongs in your notes
next to the artefact hash for the reason in
[README §3.12](../README.md#312-schema-drift-and-the-four-reasons-two-runs-differ): two reports from
different MobSF versions are not comparable, and the differences will look like application changes.

### 3.2 What is actually in the file?

The report has a file list. Read it. Then read the container yourself, because it takes ten seconds
and it is the check the rest of the lab depends on:

```bash
# host
unzip -l base.apk | grep -cE '\.dex$'                              # how many DEX?
unzip -l base.apk | grep -E 'lib/[^/]+/' | awk -F/ '{print $2}' | sort -u   # which ABIs?
unzip -l base.apk | grep -E 'assets/' | sort -k1 -rn | head -10    # biggest assets
unzip -l base.apk | grep -cE 'META-INF/.*\.version$'               # library version stamps
```

**Interpret it against this table before you read a single finding:**

| What you see | What it means for everything above it in the report |
|---|---|
| One small `classes.dex` in a large app | A packer or a cross-platform runtime. **The code analysis describes a stub** |
| `assets/index.android.bundle` | React Native — the logic is JavaScript. The DEX rules will be complete and useless |
| `libflutter.so` + `flutter_assets/` | Flutter — the HTTP stack is Dart. No Java rule sees the app's real traffic |
| `libil2cpp.so`, `assets/bin/Data/` | Unity — `global-metadata.dat` holds the type names |
| Ten `classes*.dex` | An ordinary large app. Each DEX has its own string table |
| No `lib/` at all in a big app | The native code ships in an **ABI split** you were not given |
| A large high-entropy `.bin`/`.dat` in `assets/` | *Possibly* an encrypted payload — and entropy alone proves nothing |

> **High entropy is not evidence of encryption.** Compressed data, PNGs, ZIPs, ML model weights
> and font atlases are all high entropy. The signal is entropy **plus** context: a high-entropy asset
> **plus** an unusually small DEX **plus** an `<application android:name>` you do not recognise
> **plus** a `System.loadLibrary` in that class. Any one alone is nothing.

**Record your answer**: *"This is a `<type>` application, `<n>` MB, with `<n>` DEX files, `<abis>`
native ABIs, and `<n>` MB of assets. The scan's code analysis therefore covers `<all / a fraction
of>` the program."*

### 3.3 What libraries is it built from?

```bash
# host — from the report
python3 -B -c "
import json; d=json.load(open('report.json'))
print('libraries:', d.get('libraries'))
print('trackers :', (d.get('trackers') or {}).get('detected_trackers'))"

# host — the better version, which gives you VERSIONS
bash ../17-Libraries/scripts/lib-inventory.sh base.apk -o inventory/
```

Note the difference. MobSF's library list is prefix-based and shallow — 17's own tool table says so:
*"treat as a starting inventory"*. MASVS-CODE asks for an inventory **with versions**, and versions
are what `lib-inventory.sh` and `lib-fingerprint.py` exist to produce.

---

## 4. Step 2 — Is this even the whole application?

This step takes one command and it is the difference between a valid report and an invalid one.

```bash
# adb shell
adb shell pm path com.example.target
```

**Count the lines.** If there is more than one, you are looking at a fraction of the application.

[38-TamperDetection](../../38-TamperDetection/README.md) measured the consequence across 18 real
APKs: **one large app showed *zero* integrity controls in `base.apk` because its code ships in
splits.** A report on that base alone would have concluded the application had no protection
whatsoever — and it would have looked complete, professional and plausible while doing so.

Record: *"The application is delivered as `<n>` APKs. This analysis covers `<n>` of them:
`<list them>`."*

If you cannot check (you were handed a file, there is no device), record *that*:

> *"We were provided with a single artefact, `base.apk` (SHA-256 …). We were not able to confirm
> whether the application is delivered as a split bundle. If it is, native libraries, dynamic feature
> modules and manifest contributions from other splits were not examined."*

That sentence costs nothing and protects everything.

---

## 5. Step 3 — Separate the facts from the opinions

This is the core exercise. Every section of a MobSF report falls into one of two buckets, and mixing
them is how people end up trusting opinions and ignoring facts.

Make two lists. Genuinely make them — a file, not a mental note.

### 5.1 List A: facts (things you would sign your name to)

```bash
# host — the component census
python3 -B -c "
import json; d=json.load(open('report.json'))
for k in ('activities','exported_activities','services','receivers','providers'):
    v=d.get(k) or []
    print('%-22s %d' % (k, len(v)))
    for x in v: print('    ', x)
print('browsable:', json.dumps(d.get('browsable_activities'), indent=2))
print('permissions:', '\n  '.join(sorted(d.get('permissions') or {})))"
```

```bash
# host — the certificate
python3 -B -c "
import json; d=json.load(open('report.json'))
ca=d.get('certificate_analysis') or {}
print(ca.get('certificate_info',''))"
```

Cross-check **one** of them against the platform's own parser, so you learn the habit:

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml base.apk | grep -E 'E: (activity|provider|service|receiver)|exported|android:name'
```

Do the numbers agree? If not, you have found something more interesting than any finding in the
report — see [README §4.6](../README.md#46-the-aosp-code-that-decides-whether-the-inventory-is-right)
for the three legitimate reasons they might differ, and
[32-Manifest](../../32-Manifest/README.md)'s CTF for the illegitimate one.

### 5.2 List B: opinions (things you would not sign)

```bash
# host — the manifest finding list
python3 -B -c "
import json; d=json.load(open('report.json')); ma=d.get('manifest_analysis')
items = ma.get('manifest_anal', ma) if isinstance(ma,dict) else (ma or [])
for it in items:
    print('%-8s %s' % (it.get('severity'), (it.get('title') or '')[:100]))"

# host — the code finding list, with its CVSS constants
python3 -B -c "
import json; d=json.load(open('report.json')); ca=d.get('code_analysis',{})
f = ca.get('findings', ca)
for t,b in f.items():
    if not isinstance(b,dict): continue
    m = b.get('metadata', b)
    print('%-8s cvss=%-5s %s' % (m.get('severity'), m.get('cvss'), t[:78]))"
```

For **each** line in list B, write the one command or observation that would settle it. Not the
answer — the *check*. Use [`../cheatsheet.md`](../cheatsheet.md) §3, which is exactly this mapping.

Worked example of what a row should look like:

```
CLAIM     high | Clear text traffic is Enabled For App [android:usesCleartextTraffic=true]
DETECTED  one attribute in the parsed manifest
CHECK     (a) aapt2 dump xmltree ... | grep -i cleartext        -> confirm the attribute
          (b) is there a networkSecurityConfig? It SUPERSEDES the attribute
          (c) is there an actual http:// endpoint in the urls section that is
              not an XML namespace URI?
STATUS    unchecked
```

**Do this for every row.** On a real app that is 20–60 rows and it takes forty minutes. That is the
lab.

### 5.3 The one row everyone gets wrong

If your report contains a line like *"Content Provider … is Protected by a permission, but the
protection level of the permission should be checked"*, stop and read it again.

**The tool is telling you it has not done the check**, in a clause nobody reads, on a row rated
`info`. Do the check:

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml base.apk | grep -B2 -A3 'E: permission'
```

`protectionLevel` values: `0` = `normal`, `1` = `dangerous`, `2` = `signature`,
`3` = `signatureOrSystem`, and the high bits are flags. **Only `signature` and above are guards.**
A `normal` permission is granted at install time to any application that asks for it, with no prompt.

If you find a `normal`, you have just moved an `info` row to a Medium finding, which is the single
most valuable thing a beginner can learn to do with a scanner report.

---

## 6. Step 4 — How much of the app did the scan actually read?

The report has no answer to this. Produce one.

```bash
# host
jadx -d out base.apk 2>&1 | tail -5
# note the "finished with errors, count: N" line if there is one

find out/sources -name '*.java' | wc -l
grep -rl 'JADX ERROR' out/sources 2>/dev/null | wc -l
```

> **The console number lies, and by a lot.** [56-JADX](../../56-JADX/README.md) measured a real
> 17.5 MB APK where jadx's console said `finished with errors, count: 61` while the output tree
> contained **2,104 refused methods across 1,424 files** — a 30× under-report. **Count the tree, not
> the summary.**

If your tree has hundreds of refused files, then hundreds of classes produced no code-analysis hits
*because they could not be read*, and an unreadable class is indistinguishable from a clean one in
the report. That goes in the limits statement.

While you are here, classify the tree, because it changes the meaning of every code finding:

```bash
# host — which packages are the APP's, and which are dependencies?
find out/sources -name '*.java' | sed 's#^out/sources/##' \
  | awk -F/ 'NF>=3 {print $1"/"$2"/"$3}' | sort | uniq -c | sort -rn | head -25
```

A rule that fired inside `androidx/`, `kotlin/` or `okhttp3/` is reporting somebody else's code.
[52-StaticAnalysis](../../52-StaticAnalysis/README.md) scores that difference at **+0.25 versus
−0.30** — the largest single term in its model, because it is the dominant signal.

---

## 7. Step 5 — Write the limits statement

Four classes minimum, with the numbers. This is a deliverable, not a footnote, and it goes in its own
section of any report you write.

Template — fill in the angle brackets from your own run:

```
SCOPE AND LIMITS

This analysis examined <artefact>, SHA-256 <hash>, obtained <how>, on <date>.
The application is delivered as <n> APK(s); <n> were examined.
The decompiler produced <n> source files and refused <n>.

An analysis of an application artefact cannot observe:

  - Broadcast receivers registered at runtime. registerReceiver() builds an
    IntentFilter in code and writes nothing to the manifest. On a comparable
    device, 299 of 431 distinct broadcast actions in use by third-party
    applications (69%) had no manifest-declared receiver anywhere on the
    device. The receiver list in this report is the manifest's, not the
    application's.

  - Native methods bound with RegisterNatives. <state whether the artefact has
    native libraries, and whether JNI_OnLoad is present with zero Java_
    exports>.

  - Reflective dispatch. A target chosen by string at runtime creates no
    textual link, so no reachability analysis covers it.

  - Code loaded after installation. <state whether DexClassLoader or
    InMemoryDexClassLoader appear; absence of evidence is recorded as such>.

  - Server-side behaviour and remote configuration. These are not on the
    device, and a remote flag can disable a control after testing concludes.

<N> items were generated by automated analysis. <M> were validated; the
remaining <N-M> are recorded as leads or rejections in Appendix B.
```

You can generate most of the evidence for that statement in one command:

```bash
# host — the chapter's validator prints a blind-spot block derived from the ARTEFACT
python3 -B ../scripts/mobsf-validate.py --report report.json --apk base.apk --tree ./out --quiet
```

---

## 8. Hints

<details>
<summary>Hint 1 — the report has no findings at all and I think something is wrong</summary>

Five explanations, in descending order of likelihood:

1. You scanned a **stub** or a **split**. Check the APK size against what you expect;
   [36-CertificatePinning](../../36-CertificatePinning/README.md) measured a major social app whose
   installed `base.apk` was **334 KB**.
2. The app is **packed** or cross-platform. Check `assets/` size against DEX size.
3. **Obfuscation** killed the name-based rules. The signature of this case is distinctive: a full URL
   list and secrets section (value-derived, unaffected) beside an empty code-analysis section.
4. **Strings are encrypted.** An app with no URLs *at all* is building them.
5. The app is small and genuinely clean. It happens.

</details>

<details>
<summary>Hint 2 — the component list from the report and from aapt2 disagree</summary>

Three legitimate causes and one interesting one:

- A component is **disabled** (`android:enabled="false"`, or `setComponentEnabledSetting` at runtime).
- A component was contributed by a **split** or by **manifest merging** from a dependency.
- The platform computes `exported` implicitly: a component with an `<intent-filter>` and no
  `android:exported` **is exported**.

And the interesting one: a deliberate **AXML parser divergence**, where the manifest a tool renders
differs from the manifest the platform parses. That is
[32-Manifest](../../32-Manifest/README.md)'s CTF and
[10-APK-Internals](../../10-APK-Internals/README.md)'s, built on two different primitives. If
`aapt2` (the platform's own code) and another tool disagree, **the disagreement is the finding.**

</details>

<details>
<summary>Hint 3 — I do not know which sections are facts and which are opinions</summary>

The test: **could the tool be wrong about this without being broken?**

If the answer is no — the component list, the permission list, the signature scheme, the file list —
it is a fact. It is reading structured data.

If the answer is yes — anything with a `severity` field, anything called a "finding", the score,
the secrets list — it is an opinion produced by a pattern.

The scorecard is a third thing: a **restatement** of the other sections. It is neither a new fact nor
a new opinion, and counting it separately is how a 12-item scan becomes a 39-item report.

</details>

<details>
<summary>Hint 4 — the "secrets" section is enormous</summary>

Classify before you read. Most entries are not secrets:

| Shape | Actually |
|---|---|
| `sha256/` + 43 base64 chars + `=` | An SPKI **pin** — a *public* key hash |
| 32 / 40 / 64 hex | A **digest** |
| base64 → readable text | Obfuscation, defeated |
| base64 → high-entropy bytes | **Ciphertext** |
| `http(s)://…` | An **endpoint** |

```bash
python3 -B -c "import base64,sys;print(repr(base64.b64decode(sys.argv[1])[:120]))" '<value>'
```

</details>

---

## 9. Success criteria

You have finished when you can hand someone the following four things:

- [ ] **The identity block**: artefact name, SHA-256, package, version, `minSdk`/`targetSdk`, MobSF
      version, and the number of APKs in the delivery.
- [ ] **List A (facts)**: component census, permission list, browsable map, certificate summary,
      library inventory, file inventory — with **at least one** cross-checked against `aapt2`.
- [ ] **List B (opinions)**: every finding line, each with the specific check that would settle it,
      and a status of `unchecked`. No verdicts yet — that is lab 02.
- [ ] **The limits statement**: at least four blind-spot classes, with the numbers, plus the split
      count and the decompiler's refusal count.

And you can answer these three questions out loud:

1. What kind of application is this, and what fraction of it did the scan read?
2. Which sections of this report would you quote to a client verbatim, and which would you not?
3. Name four things this scan structurally could not see.

---

## 10. What you should have learned

| Lesson | Why it matters |
|---|---|
| **Read bottom-up.** File list, app type, libraries, inventory, *then* findings | The findings only mean something once you know what produced them |
| **The inventory is a fact; the finding list is an opinion** | Mixing them is how people trust the wrong half |
| **A single-APK analysis of a split app is a fraction of an analysis** | One app in eighteen had zero controls in `base.apk` |
| **The report has no answer to "how much did you read"** | Count the decompiler's refusals in the tree, not the console |
| **"Protected by a permission" is a question, not an answer** | `normal` means any app can hold it |
| **The limits statement is a deliverable** | Without it, a clean scan reads as a clean application |
| **Provenance first, always** | Hash the artefact; record the tool version |

---

## 11. Next

[Lab 02 — the survival rate](lab-02-survival-rate.md) takes list B and works every row to a verdict,
producing the number that is the point of this chapter.
