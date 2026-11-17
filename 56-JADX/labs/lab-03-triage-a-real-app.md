# Lab 03 — Triage a real application

**Difficulty:** Intermediate
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-first-decompilation.md),
[Chapter 56 §3.14, §8, §9.4, §9.5](../README.md),
[10 — APK Internals](../../10-APK-Internals/README.md).
An APK you are permitted to analyse, jadx, Python 3, and about 4 GB of free disk.

> **Scope first.** Use an app you own, an app from a bug bounty programme whose scope you have
> read, a deliberately vulnerable training app, or an open-source app from F-Droid. Nothing in this
> lab requires a *particular* app; it requires a *realistically sized* one, which means something
> above roughly 10 MB.

---

## Objective

Turn "here is an APK" into "here are the twenty classes worth reading, and here is exactly how much
of this app I can and cannot read" — in under an hour, repeatably, and with a written coverage
statement you could put in a report.

By the end you will have produced:

1. A provenance record for the input.
2. A full decompilation with a measured wall time.
3. A **failure census**: refusals, warning histogram, and their distribution by package.
4. A partition of the tree into the app's own code and its dependencies.
5. A ranked reading list.
6. A written coverage paragraph in the form §9.5 specifies.

---

## Part 1 — Get the input, all of it (25 min)

### 1.1 Pull from a device

```bash
# host
adb shell pm list packages | grep -i <fragment>
adb shell pm path com.example.app
```

If more than one path comes back, the app ships as **splits**, and code can live in any of them.

```bash
# host — pull every split
for p in $(adb shell pm path com.example.app | sed 's/package://' | tr -d '\r'); do
    adb pull "$p" .
done
```

On the reference device (Redmi `M2101K6P`, Android 11 / API 30, MIUI 12.5, rooted with
frida-server running) pulling works normally. **Do not install or modify anything on that device; it
is a daily driver.**

### 1.2 Provenance

```bash
# host
sha256sum *.apk | tee provenance.txt
unzip -l base.apk | tail -3
unzip -l base.apk | grep -E "classes.*\.dex|\.so$|\.jar$"
```

Record the jadx version alongside it. Chapter §3.17 explains why: jadx output changes between
versions, so a quoted listing without a version is unreproducible.

**Questions:**

1. How many `classes*.dex` files? What does more than one imply?
2. Which ABIs have native libraries? What does the presence of `lib/` tell you about §6.9?
3. Is there a `mapping.txt`, or anything in `assets/` that looks like build output? (Chapter §3.10 —
   if yes, that is a finding before you have decompiled anything.)

---

## Part 2 — The fast pass (15 min)

Manifest and resources are the highest information density per second in the whole APK, and they
decode in seconds.

```bash
# host
jadx -s -d out-res base.apk
```

While the full decompilation runs in another terminal, read:

1. `out-res/resources/AndroidManifest.xml` — every `exported="true"` component. That is the attack
   surface. ([32 — Manifest](../../32-Manifest/README.md))
2. The `networkSecurityConfig` reference, and the XML it points at.
   ([44](../../44-NetworkSecurityConfig/README.md)) Will interception even work?
3. `android:debuggable`, `allowBackup`, `usesCleartextTraffic`.
4. `out-res/resources/res/values/strings.xml` — endpoints and keys hide here surprisingly often.

Write down three questions you now want the code to answer. Having questions before you have code is
the difference between analysis and browsing.

---

## Part 3 — The full decompilation, and how long it takes (20 min)

```bash
# host
time java -Xmx4g -cp "$JADX_JAR" jadx.cli.JadxCLI \
     --no-res -j 4 --log-level error -d out base.apk
```

Record: wall time, and the last line jadx printed.

**Reference figures**, measured for this chapter on a 17.5 MB commercial app, 8 threads, `--no-res`:

| Measurement | Value |
|---|---|
| Wall time | 148 s |
| Java files | 20,091 |
| Lines of Java | 1,829,607 |
| jadx console error count | **61** |

**Questions:**

1. How does your app compare?
2. Did jadx exit zero? Did it print errors? Are those the same question?
3. Compare your file count against the class count in the DEX:
   ```bash
   # host
   unzip -p base.apk classes.dex | dexdump - | grep -c "Class descriptor"
   find out/sources -name '*.java' | wc -l
   ```
   These will not match exactly — inner classes share a file. An order-of-magnitude gap means the
   run failed. Which possibility does chapter §3.15 warn about?

---

## Part 4 — The failure census (40 min)

**Do this before you read a single line of the app.** It tells you how much of the app you can read
at all.

```bash
# host
python3 -B ../scripts/jadx-triage.py --sources out/sources --app-package com.example.app
```

Or by hand, which is worth doing once so you know what the script is doing:

```bash
# host
grep -rho "Method not decompiled" out/sources | wc -l
grep -rl  "Method not decompiled" out/sources | wc -l
grep -rho "JADX WARN: [A-Za-z' -]*" out/sources | sed 's/ *$//' | sort | uniq -c | sort -rn
```

### The number that should surprise you

On the reference app, jadx's console said `finished with errors, count: 61`, and the output tree
contained **2,104** refused methods across **1,424** files.

1. Compute both numbers for your app. What is the ratio?
2. Why are they different? (The console reports methods that *threw during processing*; refusals
   jadx handled gracefully are recorded in the files and never mentioned.)
3. What does that mean for anyone judging decompilation quality from the console summary?

### Read the warning histogram

Reference distribution:

| Count | Warning |
|---|---|
| 9,102 | `Removed duplicated region for block` |
| 3,303 | `Type inference failed for` |
| 2,160 | `'super' call moved to the top of the method` |
| 1,539 | `Code restructure failed` |
| 1,197 | `Multi-variable type inference failed` |

1. Which is most common in *your* app?
2. `Removed duplicated region for block` means the Java below it is missing a control-flow path.
   How many of your files contain one? What fraction is that?
3. `'super' call moved to the top of the method` reorders code. Name one kind of security finding
   that would be wrong if you read such a constructor from the Java.

### Read the *distribution*, not the total

```bash
# host
grep -rl "Method not decompiled" out/sources \
  | sed 's|out/sources/||; s|/[^/]*$||' | cut -d/ -f1-3 | sort | uniq -c | sort -rn | head -20
```

Reference result: 180 in `io/vendorchat/android`, 127 in `com/google/android`, **95 in the app's own
package** out of 2,211 app files — 4.3%, which is background noise. Inspecting the refused signatures
confirmed it: Kotlin synthetic default-argument constructors and generated JSON adapters.

1. What is your app's own refusal rate?
2. Sample five refused methods in the app's own package. What are they? (Look at the signature in the
   `UnsupportedOperationException` message.) Are they generated code or hand-written?
3. Chapter §8.5 gives four distribution patterns and their diagnoses. Which one is your app?

---

## Part 5 — Whose code is this? (20 min)

```bash
# host
find out/sources -name '*.java' | sed 's|out/sources/||; s|/[^/]*$||' \
  | cut -d/ -f1-3 | sort | uniq -c | sort -rn | head -20
```

Reference result:

| Files | Package |
|---|---|
| 4,555 | `com/google/android` |
| **2,211** | **the app itself** |
| 1,530 | `io/vendorchat/android` |

**The app was 11% of its own tree.**

1. What fraction is your app?
2. Which third-party SDKs are present? For each, what does it *do*, and does its presence imply data
   leaving the device?
3. Any packages with short obfuscated names (`ri`, `i1`, `d1`)? What does it mean when *some*
   packages are obfuscated and the app's own are not?
4. Now re-scope every command in Part 4 to `out/sources/com/example/app` and re-read the numbers.
   How different is the picture?

---

## Part 6 — Rank and read (45 min)

```bash
# host
python3 -B ../scripts/jadx-triage.py --sources out/sources \
        --app-package com.example.app --app-only --limit 30 --json triage.json
```

Read the script's header first — in particular its "WHAT THIS WILL NOT TELL YOU" section. Then:

1. Open the top five. For each, write one sentence: what is this class for?
2. Was the ranking right? Which entries were noise, and what signal produced the false positive?
3. Which classes did the ranking **miss** that you found by other means? What signal would have
   caught them?
4. Run the grep catalogue and compare:
   ```bash
   # host
   python3 -B ../scripts/jadx-triage.py --sources out/sources/com/example/app \
           --grep secrets,network,crypto,webview
   ```
5. Any class carrying a `!` (a refusal) in the ranked output goes to Smali before you say anything
   about it. Pick one and do it, using
   [`../scripts/jadx-vs-smali.sh`](../scripts/jadx-vs-smali.sh).

### The un-obfuscatable foothold

Even in a heavily obfuscated app, framework contracts keep their names — the runtime resolves them by
name, so they cannot be renamed. Find them:

```bash
# host
grep -rn "extends ContentProvider\|public Cursor query\|onReceive(\|shouldOverrideUrlLoading\|checkServerTrusted\|onCreate(Bundle" \
     out/sources/com/example/app --include=*.java | head -40
```

How many did you get? Compare against the manifest's component list. Any component in the manifest
whose class you cannot find in the tree is a question worth chasing (§3.15, §6.10).

---

## Part 7 — Write the coverage statement (25 min)

This is the deliverable, and almost nobody produces it.

Write the methodology paragraph, in the form of chapter §9.5:

> Static review was performed on decompiled Java produced by jadx **[version]** from
> **[artefact]**, SHA-256 **[hash]**. The output comprised **[N]** classes and **[M]** lines.
> **[R]** methods across **[F]** files could not be reconstructed and were reviewed as Dalvik
> bytecode instead; of these, **[A]** were in the application's own package and **[B]** were in
> third-party components. **[W]** methods carried decompiler warnings indicating incomplete control
> flow; findings touching those methods were confirmed against the bytecode. Native code in
> **[libs]** was not covered by this review. **[Splits]** split APKs were included.

Fill in every bracket from your own measurements.

Then answer, in writing:

1. Which of those numbers would you have guessed wrong if you had not measured?
2. What claim can you now *not* make about this app, that you might otherwise have made?
3. If a developer disputed a finding, which of these numbers would you produce?

---

## Part 8 — Cross-check the manifest with a second tool (20 min)

jadx and `apktool` both *decode* binary XML, which means both apply an interpretation. Crafted
manifests exist specifically to make two decoders disagree with each other and with the platform's
own parser — see [32 — Manifest](../../32-Manifest/README.md) and
[10 — APK Internals](../../10-APK-Internals/README.md).

```bash
# host — three readings of the same file
jadx -s -d out-res base.apk
aapt2 dump xmltree base.apk --file AndroidManifest.xml > manifest-aapt2.txt
apktool d -f -o work base.apk 2>/dev/null && cp work/AndroidManifest.xml manifest-apktool.xml
```

1. Compare the exported-component list from all three. Do they agree?
2. Compare `android:permission` attributes specifically. A component that one decoder shows as
   permission-protected and another does not is a **finding**, not a tooling annoyance.
3. If they agree — and they usually will — write down what you have and have not established. You
   have established that three decoders agree; you have not established what the *platform* parser
   does, which is a fourth reading.

## Part 9 — What `--deobf` costs and buys (20 min)

Run the same app twice:

```bash
# host
time jadx --no-res -d out-plain base.apk
time jadx --no-res --deobf --deobf-cfg-file names.jobf --deobf-cfg-file-mode read-or-save \
          -d out-deobf base.apk
```

1. How much longer did the second take?
2. Pick an obfuscated class from the plain output. Find it in the deobf output. Is it easier or
   harder to read? (Chapter §3.9 predicts harder.)
3. Now do the thing `--deobf` is actually for:
   ```bash
   # host
   grep -rc "\bm[0-9]*a(" out-deobf/sources | grep -v ":0$" | wc -l   # unique method names
   grep -rc "\ba(" out-plain/sources | grep -v ":0$" | wc -l          # ambiguous ones
   ```
   Which tree can you cross-reference by text, and which cannot?
4. Try the recovery flag that genuinely recovers:
   ```bash
   # host
   jadx --use-source-name-as-class-name-alias always --no-res -d out-src base.apk
   grep -rn "renamed from" out-src/sources | head -20
   ```
   Did the app strip its `SourceFile` attributes? If not, how many class names did you just recover
   for free? That is a one-line finding for the report: `-renamesourcefileattribute` was not set.

## Part 10 — Hunt for a shipped `mapping.txt` (10 min)

The single highest-value thing you can find in an obfuscated APK.

```bash
# host
unzip -l base.apk | grep -iE "mapping|proguard|seeds|usage"
unzip -l base.apk | grep -i "assets/" | head -40
```

If you find one (they do ship, by accident, more often than anyone would like):

```bash
# host
unzip -p base.apk assets/mapping.txt > mapping.txt
head -5 mapping.txt
jadx -Prename-mappings.format=PROGUARD_FILE --mappings-path mapping.txt \
     --no-res -d out-mapped base.apk
```

**Verify before you trust it.** A `mapping.txt` from a different build silently mislabels classes.
Spot-check three: if a class the mapping calls `LoginPresenter` contains image-loading code, the
mapping is from another build and every name it gave you is suspect.

Write the finding either way — including "no mapping file was present", which is a *negative* result
worth recording because it took you ten minutes to establish and saves the next person ten.

## Stretch goals

- **Diff two versions.** Get two releases of the same app and run chapter §8.7's shared-`.jobf`
  recipe. What changed? Can you find a security fix in the diff?
- **Compare with MobSF.** Run MobSF ([chapter 55](../../55-MobSF/README.md)) on the same APK. Which findings does
  it have that your triage missed, and which does it claim that your triage shows to be false
  positives? Explain each disagreement.
- **Cross-check the string table.** Pick a string your grep found. Confirm it in
  `strings -a classes.dex`. Then pick a string that is in the DEX string pool and *not* in
  `out/sources` — what does that class's decompilation look like?
- **Measure the cost of `--deobf`.** Re-run with and without it. How much longer, and is the output
  more or less usable for your workflow?

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| jadx prints help then hangs forever | You are running the GUI launcher | Chapter §1.3. Set `JADX_JAR` to `lib/jadx-gui-<ver>-all.jar` |
| `OutOfMemoryError`, or far fewer files than classes | Heap | `java -Xmx8g -cp jadx.jar jadx.cli.JadxCLI -j 4 --no-res ...` |
| Run "succeeds" but a class you expect is absent | Silent partial run (chapter §3.15) | Compare class count in DEX against file count out, **before** concluding absence |
| Everything is in `defpackage/` | The DEX has no package structure, or R8 repackaged into the default package | Not an error. `-repackageclasses` |
| Only 30 classes in a 40 MB app | A **packer**. The real DEX loads at runtime | Chapter §5.8; dump it at runtime and decompile that |
| `INSTALL_FAILED_USER_RESTRICTED` when you try to reinstall | MIUI's "Install via USB" policy on the reference device — an OEM gate, not a bad APK | You do not need to install anything for this lab. If you must, push the APK to `/data/local/tmp` and run `pm install` as root; chapter 60's [FAQ](../../60-ADB/faq.md) §14 covers it |
| `grep` returns thousands of hits | You did not scope to the app package | Part 5. The app is ~10% of the tree |
| The triage script takes minutes on Windows | 20,000 small files is slow on NTFS | Expected. Scope `--sources` to the app package for iteration |

## Deliverables checklist

By the end you should have written down, in a file you could hand to someone else:

- [ ] `provenance.txt` — APK SHA-256, jadx version, date, command line
- [ ] `coverage.txt` — files, lines, refusals, files-with-refusals, warning histogram
- [ ] The package table, with the app's own share as a percentage
- [ ] The refusal distribution, with your diagnosis of which of §8.5's four patterns it matches
- [ ] A ranked reading list of 20 classes, with one sentence each on the top five
- [ ] The coverage paragraph from Part 7, fully filled in
- [ ] One sentence naming something you can **not** conclude about this app, and why

That last item is the one that separates a triage from a browse.

## What you should carry out of this lab

- **Census before you read.** How much of the app you can read is a number, and jadx will not
  volunteer it.
- The console error count is not the failure count.
- Most of the tree is somebody else's code. Partition first, always.
- Ranking beats browsing, and a written ranking is defensible where a hunch is not.
- The coverage statement converts "we reviewed the app" into a measurement, and it takes ten minutes.

Next: [Lab 04 — CTF: The Honest Decompiler](lab-04-ctf-honest-decompiler.md).
