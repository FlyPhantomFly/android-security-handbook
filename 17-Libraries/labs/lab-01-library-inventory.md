# Lab 01 — Build the Inventory

**Difficulty:** Beginner
**Time:** 2–3 hours the first time, twenty minutes once it is muscle memory
**Prerequisites:** [Chapter 17 §8](../README.md#8-static-analysis) and
[§2](../README.md#2-high-level-architecture), [10-APK-Internals](../../10-APK-Internals/README.md),
a computer with `python3`. Everything else is optional and the lab tells you what you lose without it.

---

## Objective

Produce a **complete, evidence-backed library inventory** for a real APK, using every enumeration
technique in chapter 17 §8, and end with the one-row-per-library table that §8.1 Phase 5 calls the
deliverable.

"Evidence-backed" is the whole assignment. Every row in your final table must have a column saying
*how you know*. A row you cannot defend is a row you delete.

---

## Why this matters

A typical commercial Android app is, by class count, 80% to 98% code somebody else wrote. That code
runs with the app's UID, its permissions, its network access and its keystore access, and there is no
sandbox between it and the app. §1 of the chapter makes the argument; this lab makes it a number you
generated yourself, about an app you use.

There is also a blunt professional reason. This process takes twenty minutes once you have done it
five times, and roughly one engagement in four produces a real finding from this step alone —
a known-vulnerable bundled library, an SDK the client did not know was in their app, or a permission
nobody could account for. It is the highest ratio of finding-to-effort in mobile testing, and most
testers skip it because it is not exciting.

The reason it is a *beginner* lab and not a trivial one: doing it completely is harder than it looks.
There are six places code hides in an APK and most people check two.

---

## Choosing a target

> **Warning**
> Only analyse applications you have written permission to test, or that are licensed to permit it.
> The safest targets for practice are your own builds and open-source applications.

Three good options, in increasing order of usefulness:

| Target | Why | Catch |
|---|---|---|
| An app you built yourself, with 8–10 dependencies you chose | You know the right answer, so you can grade yourself exactly | You will unconsciously look for what you know is there |
| An **F-Droid** application | Open source, freely redistributable, and **the build files are public** — so after you finish you can check your inventory against the real `build.gradle` | Its dependency list is usually short and tidy, unlike commercial apps |
| A large commercial app you have permission to test | Realistic: two hundred dependencies, obfuscated, split | No ground truth to check against |

**Do the F-Droid one.** Being able to diff your answer against the project's actual build file is
worth more at this stage than realism, and it is the only way to discover which of your techniques
systematically miss things.

```bash
# host — pull an installed app off a device, ALL of it
adb shell pm path org.example.target
# package:/data/app/~~aBc.../org.example.target-XyZ.../base.apk
# package:/data/app/~~aBc.../org.example.target-XyZ.../split_config.arm64_v8a.apk
# package:/data/app/~~aBc.../org.example.target-XyZ.../split_config.en.apk

mkdir target && cd target
adb shell pm path org.example.target | sed 's/^package://' | tr -d '\r' | \
  while read -r p; do adb pull "$p" .; done
ls -la
```

If you pull only `base.apk` you will do this entire lab and produce a wrong answer. On an App Bundle
build the native libraries live in `split_config.<abi>.apk`, so a base-only inventory reports zero
`.so` files with total confidence.

---

## Setup

Nothing is mandatory except `python3`. The lab is written so that you can complete every step with
the two scripts in this chapter and no Android tooling at all — and so that you can see what each
optional tool buys you.

| Tool | What it gives you | What you lose without it |
|---|---|---|
| `python3` | The DEX and ELF parsers in `lib-fingerprint.py` | Four fallback chains lose their last link. Get it |
| `unzip` | Fast container listing | Nothing — `python3` covers it |
| `apktool` or `aapt2` | A decoded manifest | Structure. The fallback recovers the *names* from the binary XML string pool but cannot tell you which element an attribute belonged to |
| `baksmali` or `dexdump` | Fast, authoritative class listing | Nothing — `lib-fingerprint.py --list-classes` parses the DEX directly |
| `readelf` (binutils or LLVM) | Native analysis | Nothing — `lib-fingerprint.py` parses ELF too |
| `jadx` | Readable decompiled code | The ability to answer "what does this class actually do", which you will want in step 9 |

---

## Steps

Do steps 1 to 7 **by hand** the first time. Then run the script and compare. If the script found
something you did not, work out which technique you skipped — that gap is the actual output of
this lab, not the table.

### Step 1 — What is in the container at all?

```bash
# host
unzip -l base.apk | head -40
unzip -l base.apk | awk '{print $4}' | grep -oE '^[^/]+/' | sort | uniq -c | sort -rn
```

No `unzip`? Same answer, portably:

```bash
# host
python3 -c "import zipfile,sys,collections
z=zipfile.ZipFile(sys.argv[1])
c=collections.Counter(n.split('/')[0] for n in z.namelist())
[print('%7d  %s'%(v,k)) for k,v in c.most_common()]" base.apk
```

**Q1.** Which top-level directories exist, and what does each one hold? If you cannot name what
`META-INF/`, `res/`, `assets/`, `lib/` and `classes*.dex` are for, read
[10-APK-Internals](../../10-APK-Internals/README.md) before continuing — this lab assumes the
container and studies its contents.

### Step 2 — Native libraries (§8, technique: `lib/*/*.so`)

```bash
# host
for a in *.apk; do
  echo "== $a"
  unzip -l "$a" | grep -oE 'lib/[^/]+/[^ ]+\.so' | sort -u
done
```

**Q2.** How many `.so` files, across how many ABIs? Which APK are they in?

Now take each one apart. This is chapter §8.2's hardening and symbol sweep:

```bash
# host
mkdir -p x && cd x && unzip -o ../split_config.arm64_v8a.apk 'lib/*' >/dev/null && cd ..
for so in $(find x -name '*.so'); do
  echo "=== $so"
  readelf -d "$so" | grep NEEDED
  readelf -n "$so" | grep -A1 'Build ID' | tail -1
  readelf -p .comment "$so" 2>/dev/null | sed -n '3p'
  readelf -S "$so" | grep init_array
  readelf --dyn-syms --wide "$so" | awk '{print $8}' | grep -cE '^Java_'
done
```

No `readelf`? The pure-Python route reads the same structures and explains each one:

```bash
# host
python3 ../scripts/lib-fingerprint.py x/lib/arm64-v8a/libfoo.so
```

**Q3.** For each `.so`: what does it depend on (`NEEDED`)? Does it have a build ID? Does it have
`.init_array` entries? Does it export `JNI_OnLoad`, `Java_*` symbols, both, or neither?

**Q4.** One `.so` exports `SSL_CTX_new` and `EVP_DigestInit_ex` but its `NEEDED` list does not
mention `libssl.so` or `libcrypto.so`. What does that combination mean, and why does it matter more
than a version number?

### Step 3 — Version stamps (§3.7 technique 5)

The cheapest exact answer in the whole chapter:

```bash
# host
for f in $(unzip -l base.apk | grep -oE 'META-INF/[^ ]*\.version'); do
  printf "%-64s %s\n" "$f" "$(unzip -p base.apk "$f" | tr -d '\r\n')"
done
```

**Q5.** How many stamps, and which artifacts? If there are none, what are the two possible
explanations, and how would you tell them apart?

### Step 4 — Managed classes (§8.1 Phase 1, the part with the fallbacks)

The authoritative route, if you have it:

```bash
# host
baksmali list classes base.apk | sed 's#^L##; s#;$##' | tr '/' '.' > classes.txt
wc -l classes.txt
```

Every fallback, in the order chapter §8.1 lists them:

```bash
# host — any one of these
dexdump -f classes.dex | grep -oE "Class descriptor +: +'L[^']+'"
apkanalyzer dex packages --defined-only base.apk
jadx --no-src -d out base.apk && find out -name '*.java' | wc -l
python3 ../scripts/lib-fingerprint.py base.apk --list-classes > classes.txt
```

Then collapse to packages, which is what you actually reason about:

```bash
# host
sed 's/\.[^.]*$//' classes.txt | awk -F. 'NF>=3{print $1"."$2"."$3}' \
  | sort | uniq -c | sort -rn | head -40
```

**Q6.** How many classes in total? What fraction of the packages belong to the app itself
(its `applicationId` prefix)? Compute the ratio and write it down — you will use it in the report.

**Q7.** Map each of the top 25 prefixes to a vendor using the table in chapter §8.1 Phase 2. Which
ones are *not* in the table? Those are your ten most interesting minutes; see step 9.

**Q8.** You see a package called `a.a` with 200 classes in it. What is it, and what is the correct
way to identify it? (It is not "read the class names".)

### Step 5 — The manifest surface (§8.1 Phase 3)

```bash
# host
apktool d -f base.apk -o work >/dev/null
echo "== providers"
grep -oE '<provider[^>]*android:name="[^"]*"' work/AndroidManifest.xml | sort -u
echo "== authorities"
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml | sort -u
echo "== permissions"
grep -oE 'android\.permission\.[A-Z_]+' work/AndroidManifest.xml | sort -u
echo "== meta-data"
grep -oE '<meta-data[^>]*/>' work/AndroidManifest.xml | sort -u
echo "== exported"
grep -oE '<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*' \
  work/AndroidManifest.xml
```

No `apktool`? Use `aapt2 dump xmltree --file AndroidManifest.xml base.apk`, or the parser from
chapter 10: `python3 ../../10-APK-Internals/examples/parse_axml.py --extract base.apk`.

**Q9.** Count the initialisation `ContentProvider`s. Each is an SDK that runs code **before**
`Application.onCreate()`. Why can this list not be obfuscated away? (Chapter §3.5 answers it, and
[27-ContentProviders](../../27-ContentProviders/README.md) explains the lifecycle.)

**Q10.** For each permission, decide: did the *app* need this, or did an SDK's manifest fragment
contribute it? How would you prove which, without the source?

**Q11.** What is in the `meta-data` elements? API keys and app IDs live there by convention. Does
any of them tell you whether this build points at production or staging?

### Step 6 — Code that is not in `classes.dex` and not in `lib/`

```bash
# host
unzip -l base.apk | grep -iE 'assets/.*\.(dex|jar|apk|zip|so|bundle|js|lua|wasm)$'
unzip -l base.apk | grep -E 'assets/bin/Data|flutter_assets|index\.android\.bundle'
```

**Q12.** Anything here? If yes, you have a second inventory to do inside the first one. If the app is
React Native, Flutter or Unity, what does that imply about how much of the app your class inventory
in step 4 actually covered?

### Step 7 — Runtime code loading indicators

```bash
# host
grep -rl 'Ldalvik/system/DexClassLoader\|Ldalvik/system/InMemoryDexClassLoader' work/smali* 2>/dev/null
grep -rl 'Ljava/lang/System;->load(' work/smali* 2>/dev/null
```

**Q13.** Hits are common and mean almost nothing on their own. What single question turns a
`DexClassLoader` reference into a finding? (One sentence.)

### Step 8 — Now run the script, and diff it against yourself

```bash
# host
bash ../scripts/lib-inventory.sh -o out base.apk split_config.arm64_v8a.apk split_config.en.apk
ls out/*/*/
cat out/*/*/08-summary.txt
```

**Q14.** What did the script find that you did not? Which of the seven steps above did you rush?

**Q15.** Read the "tooling that was NOT available" section. For each missing tool, what specifically
did this run fail to tell you? (This is not busywork: on an engagement you must be able to say which
parts of your inventory are weaker and why.)

### Step 9 — Identify the unknowns

Take the prefixes from Q7 that no table recognised. For each:

```bash
# host — the strings a library carries about itself
python3 ../../04-Java/scripts/dump-strings.py base.apk --min-len 8 \
  | grep -iE 'https?://|\.com|\.io|sdk|version'
```

Look for: endpoint hostnames, `SharedPreferences` file names, log tags, and `User-Agent` fragments.
Those name the vendor when the package prefix does not.

**Q16.** For each unknown SDK: who publishes it, what category is it (chapter §3.5's table), and what
did it contribute to the manifest?

### Step 10 — What is actually loaded

Everything so far is a claim about a file. Now check the process.

```bash
# adb shell — after launching and using the app
PID=$(pidof -s org.example.target)
grep -E '\.so' /proc/$PID/maps | awk '{print $6}' | sort -u
grep -E '/data/(local/tmp|data)/|/sdcard|/storage|memfd|\(deleted\)' /proc/$PID/maps
```

**Q17.** Which of the `.so` files from step 2 are actually mapped? Is anything mapped that was *not*
in any APK? What would it mean if there were?

---

## The deliverable

One row per library. Chapter §8.1 Phase 5 defines the columns; the **Evidence** column is the one
this lab exists to teach and is not optional.

| Library | Version | Evidence for the version | Ring | Purpose | Permissions added | Endpoints | Loaded at runtime? | Rating |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

Rules for filling it in:

- **Version** may be "unknown". "Unknown" is a legitimate, professional answer.
- **Evidence** must name the technique and the artifact: "`META-INF/androidx.work_work-runtime.version`
  stamp" or "class set fully contained in 4.9.3, not in 4.8.1". "It looked like it" is not evidence.
- **Ring** is platform / bundled / dynamically loaded, from chapter §2.
- **Loaded at runtime?** comes from step 10, and is the column that separates an inventory from a
  finding.
- **Rating** uses the rubric in chapter §8.1 Phase 4. Do not rate anything you have not characterised.

---

## Hints

<details>
<summary>Hint — Q4, exported SSL_* with no NEEDED libssl</summary>

Dynamic linking is a *contract*: `NEEDED` says "the linker must find this library for me at load
time". If a symbol is exported by the file itself and no dependency provides it, the code for it is
**inside this file** — statically linked at build time.

Why it matters more than the version: a statically linked copy is outside every update mechanism.
The platform's TLS stack is a Mainline module and gets fixes through Play; this one gets fixed when
the app developer rebuilds, which may be never. Chapter §3.7 technique 3 calls this the biggest blind
spot in mobile dependency scanning, because no Gradle file mentions it.
</details>

<details>
<summary>Hint — Q8, the obfuscated package</summary>

You identify renamed code by what R8 could not rename:

- **String constants.** Endpoints, `SharedPreferences` keys, log tags, JSON field names.
- **Structure.** The class-and-method shape survives renaming; compare it against a real release with
  `lib-fingerprint.py --prefix ... --refs`.
- **What it references.** Renamed code still calls platform APIs by their real names. A class calling
  `TelephonyManager.getDeviceId` tells you its category immediately.
- **Native symbols.** JNI binds by name, so `Java_*` exports keep the original Java package.

What obfuscation does and does not hide is [40-Obfuscation](../../40-Obfuscation/README.md)'s
subject. Here it is only an obstacle to the inventory.
</details>

<details>
<summary>Hint — Q13, the one question</summary>

**Where do the bytes come from?**

A `DexClassLoader` over a file the app shipped in its own APK is Play Feature Delivery and is
uninteresting. The same class over a file downloaded at runtime, or over a path in shared storage, is
a different severity entirely — and over a path another app can write, it is a critical finding. The
API is identical in all three cases. Only the source of the bytes differs.
</details>

<details>
<summary>Hint — Q15, what a missing tool costs</summary>

Work it out per tool rather than in general:

- No `readelf` **and** no `python3`: you have no ELF analysis, so statically linked OpenSSL, zlib and
  SQLite inside a `.so` are invisible. Your inventory silently omits an entire category.
- No manifest decoder: you can still recover *names* from the binary XML string pool, but not
  structure. You cannot read `android:exported`, and you cannot attribute an attribute to an element.
- No class lister: you lose most of a modern app, since third-party Java and Kotlin code is the bulk
  of it.

Being able to say this to a client — "this section of the inventory is weaker, and here is
specifically why" — is a professional skill in its own right.
</details>

---

## Solution notes

<details>
<summary>Q6 — the ratio, and what to do with it</summary>

In a typical mid-size commercial app you should find somewhere between 20,000 and 60,000 classes, of
which the app's own package holds a few hundred to a few thousand. One to five percent is normal.

Put the number in the report's introduction, not buried in an appendix. "Of the 41,208 classes in
this application, 317 — under one percent — were written by your team. The rest is third-party code
running with your users' data and your app's permissions." That sentence does more to get the
third-party findings taken seriously than the findings do.
</details>

<details>
<summary>Q9 — why the provider list survives obfuscation</summary>

A `ContentProvider`'s **authority** is a string that the system's `PackageManager` resolves at
install time and that other processes use to address it. It cannot be renamed by R8, because R8 does
not know about it and because renaming it would break resolution.

The `android:name` attribute *is* a class name and R8 could in principle rename it — but the manifest
and the code are updated together by the build, so what you read in the merged manifest is the truth
about which class runs. Either way the list is reliable, which is why chapter §3.5 recommends it as
the SDK inventory that works even on a heavily obfuscated app.

Mechanism, one line: `ContentProvider.onCreate()` runs before `Application.onCreate()`, so an SDK
that declares a no-op provider gets to initialise itself without the developer writing any code. See
[27-ContentProviders](../../27-ContentProviders/README.md).
</details>

<details>
<summary>Q17 — the maps sweep, and the two things it can tell you</summary>

Two independent results, and both matter:

1. **`.so` files present in the APK but never mapped.** Dead weight, or a code path you did not
   exercise. Either way, do not rate a library you have not seen load — chapter §11 lists "assuming a
   `.so` in `lib/` is loaded" as a reverse engineer mistake.

2. **Anything mapped from outside `/data/app`.** Executable memory backed by `/data/local/tmp`,
   external storage, a `memfd`, or a deleted file is code the app obtained at runtime. That is ring 3
   and it is usually the most severe row in your table.

An empty result for (2) is also a result. Write it down: "no executable mappings from untrusted
locations were observed across the workflows exercised" is a defensible sentence, and it is
different from silence.
</details>

---

## Success criteria

You have finished when:

- [ ] Every APK the device reports for the package was pulled and analysed, not just `base.apk`.
- [ ] Your table has one row per library and **no row has an empty Evidence cell**.
- [ ] You used all six enumeration angles: native `.so`, `META-INF` stamps, DEX class prefixes,
      manifest components and permissions, assets and resources, and the runtime maps sweep.
- [ ] You identified at least one library that the vendor table did not know, by its strings.
- [ ] You can state, for at least one native library, whether it statically links third-party code,
      and say how you know.
- [ ] You ran `lib-inventory.sh` and can explain every difference between its output and yours.
- [ ] For an F-Droid target: you compared your inventory against the project's real `build.gradle`
      and can list what you missed and why.
- [ ] You can say, out loud, which rows are **findings** and which are merely **inventory**, and why
      the difference is reachability.

---

## Where to go next

| Next | Why |
|---|---|
| [Lab 02 — Version fingerprinting](lab-02-version-fingerprint.md) | Your table has "unknown" in the Version column. That lab fills it in, with evidence |
| [Lab 03 — SDK data-collection audit](lab-03-sdk-audit.md) | Your table has empty Endpoints cells. That lab fills those in |
| [`../examples/inventory-output-annotated.md`](../examples/inventory-output-annotated.md) | A worked inventory with every line annotated: what it proves, what it does not |
| [Chapter 17 §8](../README.md#8-static-analysis) | The five-phase methodology this lab walks. Re-read it now that you have done it once |
