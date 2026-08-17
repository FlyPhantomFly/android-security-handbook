# Lab 03 — Audit an app you did not build

**Difficulty:** Intermediate–Advanced
**Time:** 2–3 hours
**Needs:** Android SDK build-tools, Python 3, and at least one APK you are authorised to analyse. A
device is useful but **not required** — the whole lab works on a file.
**Chapter sections:** [§5](../README.md#5-security-perspective),
[§6.3](../README.md#63-recognising-each-rule-from-the-output), [§8](../README.md#8-static-analysis)

---

## Objective

Given an APK and nothing else, determine how its shrinking and obfuscation were configured,
reconstruct the rules that produced it, and write a finding at a severity you can defend.

This is the assessment skill. Lab 02 gave you the rules and asked what they produced; this lab gives
you the product and asks for the rules.

> **⚠️ Authorised testing only.** Analyse apps you own, apps you have written permission to test, or
> apps distributed as deliberately-vulnerable training targets. Pulling an APK off your own device is
> fine; publishing findings about a third party's app is not, unless you have permission. Where this
> lab shows measured output from a real app, the app is not named, for exactly that reason.

---

## Setup

Pick a target. Three good sources, in increasing order of difficulty:

```bash
# host — 1. a system app. Almost certainly shrunk but NOT obfuscated. Good calibration.
adb shell pm list packages -s | head -40
adb shell pm path com.google.android.feedback
adb pull /system/system_ext/priv-app/GoogleFeedback/GoogleFeedback.apk .

# host — 2. any third-party app on a device you own
adb shell pm list packages -3
adb shell pm path <package>
adb pull <path> target.apk

# host — 3. the build you produced in lab 02, if you have no device
ls /tmp/ch41/c-overbroad/app.apk
```

> **Note on `adb pull` under Git Bash / MSYS.** Device paths beginning with `/` are rewritten into
> Windows paths and the pull fails with "failed to stat remote object". Prefix the command with
> `MSYS_NO_PATHCONV=1`, and give the *local* destination as a Windows-style path
> (`C:/Users/you/work/`), not an MSYS one. This cost real time while writing this chapter.

**Split APKs.** `pm path` may print several lines. Pull all of them — a class missing from
`base.apk` is frequently in a split, and concluding "the class does not exist" from `base.apk` alone
is a genuine methodology error:

```bash
# host
for p in $(adb shell pm path <package> | tr -d '\r' | sed 's/^package://'); do adb pull "$p" .; done
```

---

## Part 1 — The census (30 minutes)

**Task 1.1.** Run the reporter with no rules file:

```bash
# host — from the chapter root
python3 -B scripts/what-survived.py target.apk --max-list 40
```

Record, from section 1 of its output:

| Measurement | Value |
|---|---|
| DEX files | |
| Total classes | |
| Machine-generated-looking names | |
| Original-looking names | |
| Percentage renamed | |

**Task 1.2.** Now scope to the app's own package — and read the note the tool prints:

```bash
# host
aapt2 dump packagename target.apk
python3 -B scripts/what-survived.py target.apk --package "$(aapt2 dump packagename target.apk | tr -d '\r')"
```

**Two numbers, not one.** The whole-APK percentage is dominated by dependencies. The app's own
package is where the developers' decisions show. Record both.

**Task 1.3 — calibration.** Here are two measured reference points from the device this chapter was
written against (`i9000S`, Android 13 / API 33), so you have a sense of what "normal" looks like:

| App | Classes | Renamed | Notes |
|---|---|---|---|
| `GoogleFeedback.apk` (system, `/system/system_ext/priv-app/`) | 315 | **1.3%** | Shrunk, not obfuscated. Platform builds set `obfuscate: false` — the source is public, so hiding names buys nothing |
| A commercial enterprise app, 22.8 MB (not named) | 18,447 | **52.5%** | Two DEX files. Its own module is 90% renamed; the other half is library code kept by consumer rules |

Where does your target sit? If it is near 0%, go to Part 2. If it is above 40%, go to Part 3.

---

## Part 2 — The app is not renamed. Which of three causes? (30 minutes)

Three things produce "0% renamed", and they are distinguishable from the artefact alone.

| Cause | Distinguishing evidence |
|---|---|
| Minification is off (`D8` only) | Dead code present **and** original `.java` filenames in `SourceFile` |
| `-dontobfuscate` with shrinking on | Dead code plausibly removed, **no** original filenames (on R8) |
| An over-broad `-keep` covering the app's namespace | *Some* packages mangled and others not; dependencies mangled while the app is not |

**Task 2.1.** Read section 6 of the report — the `SourceFile` section. Original `.java`/`.kt`
filenames present?

```bash
# host — the same thing, directly
unzip -p target.apk classes.dex | strings -a | grep -E '\.(java|kt)$' | sort -u | head -30
```

**Task 2.2.** Read section 2 — the package table. Is the picture uniform, or is it split?

**Task 2.3.** Look for evidence of shrinking having happened at all. This is the hardest of the three
to establish from outside, and the honest answer is often "cannot determine". Two usable signals:

- A dependency whose public class list you know (e.g. OkHttp, Guava, RxJava) is present in the APK
  with only a fraction of its classes. That is shrinking.
- The `R` classes. If `R`, `R$id`, `R$string` are present as classes, no shrinker inlined their
  constants, which points at minification being off entirely.

**Task 2.4.** Write down your conclusion **and the evidence for it**, in the form
"*cause*, because *observation*". If two causes remain possible, say so — an assessment that
distinguishes what was measured from what was inferred is worth more than one that guesses.

---

## Part 3 — The app is renamed. What was kept, and why? (45 minutes)

**Task 3.1.** List the survivors:

```bash
# host
python3 -B scripts/what-survived.py target.apk --max-list 200 | sed -n '/CLASSES THAT KEPT/,/RULE CORRELATION/p'
```

**Task 3.2.** Classify every survivor into one of these buckets. This is the core of the lab.

| Bucket | How to recognise it | Rule that produced it |
|---|---|---|
| Manifest component | Appears in `aapt2 dump xmltree … AndroidManifest.xml` | AGP's generated keeps — **not the developer's doing** |
| Native-bound | Its name appears in a `Java_…` symbol in a bundled `.so` | the standard JNI rule |
| Library kept by its own consumer rules | Belongs to a third-party namespace | imposed by the dependency |
| Data model | `implements Serializable`/`Parcelable`, or annotated fields | a serialisation keep |
| An empty or near-empty class | No fields, no methods | a wildcard `keepclasseswithmembernames` artefact — see [§6.4](../README.md#64-a-measured-subtlety-a-name-kept-for-a-reason-that-no-longer-exists) |
| Unexplained | none of the above | **the interesting bucket** |

Commands for the first two buckets:

```bash
# host — every manifest-declared component
aapt2 dump xmltree target.apk --file AndroidManifest.xml \
    | grep -A2 -E '^ *E: (activity|service|receiver|provider)' | grep 'android:name'

# host — every statically-bound JNI symbol
unzip -p target.apk 'lib/*/*.so' | strings -a | grep -E '^Java_' | sort -u
```

**Task 3.3.** The *unexplained* bucket is the finding. For each class in it, ask: why would somebody
keep this? Common answers, in order of how often they are the right one:

1. A dependency's consumer rules you have not identified.
2. A package-scoped `-keep` the developers added during an incident.
3. A genuine reflection requirement you have not spotted.

**Task 3.4.** If your target has an unrenamed package while its neighbours are mangled, you have
found a package-scoped keep. Write down the package name. **That is where the developers thought the
value was**, which is a lead in its own right — it is a hint about what to read first.

---

## Part 4 — Reconstruct the rules (30 minutes)

**Task 4.1.** Write a `recovered-rules.pro` that would produce what you are looking at. You do not
need to be exactly right; you need to be *defensibly* right.

```proguard
# recovered-rules.pro — a hypothesis, not a fact
-keep class <every manifest component you found>
-keepclasseswithmembernames class * { native <methods>; }
-keep class <the unrenamed package>.** { *; }        # if you found one
-keepattributes RuntimeVisibleAnnotations            # if annotations survived
-keepattributes Signature                            # if generics survived
```

**Task 4.2.** Test the hypothesis by correlation:

```bash
# host
python3 -B scripts/what-survived.py target.apk --rules recovered-rules.pro --max-list 100
```

Read section 5, "survivors your rules do not explain". Iterate until that list is short and every
remaining entry has a written explanation. **A short unexplained list is the deliverable of this
part**, not a perfect reconstruction.

**Task 4.3 — check for attribute retention.** Two greps decide whether the annotations survived:

```bash
# host
jadx -d out --no-res target.apk 2>/dev/null
grep -rhoE '@(GET|POST|PUT|DELETE|PATCH|HTTP)\("[^"]*"\)' out | sort -u | head -40
grep -rhoE '@SerializedName\("[^"]*"\)' out | sort -u | head -40
```

Any output at all means `-keepattributes RuntimeVisibleAnnotations` (or `*Annotation*`) is in force,
and you now have the client-side API contract. Record how many distinct endpoints you recovered.

---

## Part 5 — The things renaming never touched (20 minutes)

**Task 5.1.** Work through section 7 of the report and record each:

```bash
# host
python3 -B scripts/what-survived.py target.apk | sed -n '/SURVIVORS RENAMING NEVER TOUCHES/,/FILES INSIDE/p'
```

| Survivor | Count | Most interesting example |
|---|---|---|
| Distinct URLs | | |
| Strings ≥ 20 chars, no spaces | | |
| Framework type references | | |
| `kotlin.Metadata` present | | |
| Resource names | | |
| JNI symbols | | |

**Task 5.2.** Pick the three most interesting strings and say what each tells you about the app's
architecture. For calibration: on the 22.8 MB app measured for this chapter, the sweep returned
**68 distinct URLs and 42,451 long strings** in an app that is half renamed.

**Task 5.3 — resist the obvious mistake.** A long random-looking string is **not** a finding. It is a
lead. [52-StaticAnalysis](../../52-StaticAnalysis/README.md) measured a real sweep where 15 of 17
"high confidence" hits were rejected on inspection, and [33-Storage](../../33-Storage/README.md)
found 132 high-confidence hits that were 132 false positives. Validate before you write anything
down.

---

## Part 6 — The archive check (10 minutes)

**Task 6.1.**

```bash
# host
unzip -l target.apk | grep -iE 'mapping\.txt|seeds\.txt|usage\.txt|configuration\.txt|\.pro$|\.jobf$|proguard'
```

**Task 6.2.** If you find `mapping.txt`, stop and use it — this is the one command that ends the
exercise:

```bash
# host
unzip -p target.apk '*mapping.txt' > mapping.txt
jadx -Prename-mappings.format=PROGUARD_FILE --mappings-path mapping.txt -d out-mapped target.apk
```

Then verify it before trusting it: pick three classes the mapping names and confirm their contents
match the names. A mapping from a different build of the app will mislabel everything silently. See
[56-JADX §3.10](../../56-JADX/README.md).

**Task 6.3.** If you find nothing, say so explicitly in your notes. "Checked and absent" is a
result; silence is not.

---

## Part 7 — Write the finding (30 minutes)

**Task 7.1.** Before writing anything, answer this in one sentence: **does this application have a
threat model in which client-side reverse engineering matters?** Payments, DRM, licensing,
anti-fraud, a game economy, an enterprise MDM agent — yes. A read-only news reader — probably not.

If the answer is no, your finding is one informational paragraph and you move on. Writing three pages
about obfuscation for an app that does not need it is how a report loses credibility.

**Task 7.2.** If the answer is yes, use the template in
[§9 Example 5](../README.md#example-5-enterprise--the-deliverable). It requires:

- The specific rule or configuration, quoted.
- A measurement table with numbers from your own run.
- An impact statement that says **hardening only** and names the two observable consequences.
- An explicit "not claimed" paragraph.
- Remediation as steps, with a verification step and a CI gate.

**Task 7.3 — the severity.** Write it, then challenge it:

- Is anything exploitable? (Almost certainly not. That is the point.)
- Does it make any other finding in your report worse? (Almost certainly not.)
- Would the client's own threat model justify raising it above Low? (Sometimes. Say which part.)
- Did any *retained dead code* contain non-public endpoints or credentials? (If yes, that is a
  separate finding at its own severity, and it is usually the more valuable one.)

**Task 7.4 — the developer's challenge.** Write your answer to:

> "We have `minifyEnabled true`. What more do you want?"

Three sentences maximum, and it must include a number from your own measurement.

---

---

## Part 8 — Version diffing (25 minutes, optional but the highest-value part)

A rules file change is invisible from the outside — unless you have two versions of the app.

**Task 8.1.** Obtain two builds of the same application. Any of these works: two APKs from a device
you updated, two releases from a vendor's own download page, or the `b-tightened` and `c-overbroad`
builds from lab 02 (which are, for this purpose, "the same app with the rules changed").

**Task 8.2.**

```bash
# host
python3 -B scripts/what-survived.py v1.apk --json > v1.json
python3 -B scripts/what-survived.py v2.apk --json > v2.json
python3 -B - <<'EOF'
import json
a = json.load(open('v1.json')); b = json.load(open('v2.json'))
na, nb = set(a['not_renamed']), set(b['not_renamed'])
print('classes v1/v2      :', len(a['renamed']) + len(na), len(b['renamed']) + len(nb))
print('newly UNRENAMED    :', sorted(nb - na)[:30])
print('newly renamed      :', sorted(na - nb)[:30])
EOF
```

**Task 8.3.** Interpret. A package that was mangled in v1 and readable in v2 means **a keep was
widened between the two releases**. In a real engagement that is worth asking about directly,
because the usual cause is an incident: something crashed in production, somebody added a wildcard
under pressure, and it was never narrowed again. The reverse — newly renamed — usually means a
dependency was updated and its consumer rules changed.

**Task 8.4.** Record the numbers as a time series if you have more than two versions. The *trend* is
the finding, not any single value, and it is the same metric recommended as a CI gate in
[§10, Staff Engineer](../README.md#staff-engineer).

---

## Part 9 — Sanity checks on your own conclusions (15 minutes)

Before you write anything down, run these against your own draft. Each corresponds to a mistake that
has been made in this repository's own measurements.

**Task 9.1 — did you compare the right thing?** If any claim rests on file size, redo it against
`classes.dex`. APK sizes are padded by the signing block; three genuinely different builds can be
byte-identical in length.

**Task 9.2 — did you scope away your own evidence?** If you used `--package`, run it again without.
Renamed classes leave the package.

**Task 9.3 — did you check every DEX?** An app with `classes2.dex` and `classes3.dex` will fool any
analysis that reads only the first. The tool reads all of them; `strings classes.dex` does not.

**Task 9.4 — did you check every split?** A class absent from `base.apk` may be in
`split_config.arm64_v8a.apk` or a feature split.

**Task 9.5 — is a "secret" you found actually a secret?** Three independent measurements in this
repository found sweeps producing overwhelmingly false positives:
[52-StaticAnalysis](../../52-StaticAnalysis/README.md) rejected 15 of 17 high-confidence hits by
hand, and [33-Storage](../../33-Storage/README.md) recorded 132 high-confidence hits that were 132
false positives. Validate each one, or report it as a lead rather than a finding.

**Task 9.6 — is your severity defensible to a hostile reader?** Read your finding as if you were the
engineering manager who has to schedule the fix. Does it tell them something they can act on, at a
severity proportionate to the harm? If not, cut it to one paragraph.

---

## Success criteria

- [ ] You have a whole-APK renamed percentage **and** an app-package renamed percentage.
- [ ] Every unrenamed class in the app's own package is in a labelled bucket, or explicitly listed as
      unexplained.
- [ ] You produced a `recovered-rules.pro` that explains most of the survivors, and you can say what
      it does not explain.
- [ ] You checked the archive for build artefacts and recorded the result either way.
- [ ] You recorded the survivors renaming never touched, with counts.
- [ ] You wrote a finding whose severity you can defend against a hostile reviewer, or you correctly
      decided the finding is one informational paragraph.

---

## Hints

<details>
<summary>The tool reports a high renamed percentage but the classes I care about are readable</summary>

That is the normal and interesting case. A global percentage is a weak statistic; the package table
in section 2 is the useful one. Look for a package that is 90% *kept* in an app that is 60% renamed
overall — that is a scoped keep, and it is a decision somebody made.

</details>

<details>
<summary>Everything is renamed and I cannot find an entry point</summary>

Start from the manifest, which is never obfuscated. Every `<activity>`, `<service>`, `<receiver>`
and `<provider>` names a class that must exist under that exact name. From there, follow the
framework calls — they cannot be renamed either.

</details>

<details>
<summary>`what-survived.py` says "MATCHED NOTHING" for a rule I am sure is right</summary>

Three innocent causes, in the tool's own header: the class was shrunk away anyway; the rule targets a
library that is not in this DEX; or the rule keys on an `extends`/`implements` relationship deeper
than one level, which the tool resolves only one level. It is a reading aid, not an oracle.

</details>

---

## Where to go next

[Lab 04](lab-04-ctf-the-rule-that-lied.md) is the CTF. A rules file and a build that disagree, and a
flag you can only get right by reading the artefact.
