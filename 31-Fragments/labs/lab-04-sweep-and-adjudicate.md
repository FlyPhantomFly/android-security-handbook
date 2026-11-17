# Lab 04 — Sweep and adjudicate

> **Difficulty:** Advanced
> **Time:** 2–3 hours
> **You will need:** a device or emulator you own, `adb`, Python 3, `aapt2` from build-tools, and
> roughly 5 GB of free disk for the corpus.
> **Prerequisite:** [Lab 03](lab-03-beyond-preferenceactivity.md). You must know what the sink looks
> like before a sweep for it means anything.

---

## Why this lab exists

Every previous lab tested an application you wrote, where you already knew the answer. This one turns
the scanner loose on software you did not write and asks the question that separates a tester from a
tool operator:

> **Can you account for every single hit?**

This repository has measured what happens when the answer is no, four times, and the numbers are
worth memorising before you start:

| Chapter | Sweep | Outcome |
|---|---|---|
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | 16,836 raw hits on a 17 MB commercial app | 168 leads; **15 of the top 17 rejected by hand** |
| [64-Xposed](../../64-Xposed/README.md) | 1,141 occurrences of `xposed` across 237 APKs | **all 1,141** explained by the word "exposed"; **0 findings** |
| [33-Storage](../../33-Storage/README.md) | 132 high-confidence secret hits in real browser data | **132 false positives** |
| [38-TamperDetection](../../38-TamperDetection/README.md) | self-signature check in **18 of 18** APKs | tightened to a defensible **13 of 18** |

The rule that came out of them is the one this lab teaches:
**a signature is not evidence until every hit is accounted for**, and *if a detector agrees with you
about a lot of samples, suspect the detector*.

> This lab pulls APKs off a device you own and analyses them **statically**, on the host. Nothing is
> installed, modified, executed or sent anywhere. Do not do this to a device you do not own, and
> delete the corpus afterwards — it is several gigabytes of other people's code and none of it
> belongs in a repository. See [SECURITY.md](../../SECURITY.md) for the handling rules.

---

## Objectives

1. Build a corpus and state its **denominator** honestly, including what you could not pull and why.
2. Run the scanner and separate its three tiers.
3. Adjudicate **every** tier 1 and tier 2 hit by reading bytecode, not by trusting the tier.
4. Resolve each hit to a manifest entry and determine **reachability**, which the DEX cannot tell you.
5. Produce a table where the arithmetic closes: total gates = correct + crash-shaped + injection-shaped.
6. Write a conclusion that says what your corpus supports and, more importantly, what it does not.

---

## Part 1 — Build the corpus, and count honestly

### Step 1.1 — Pull

```bash
# host
cd /path/to/31-Fragments/scripts
mkdir -p /tmp/ch31-corpus
./pull-apk-corpus.sh /tmp/ch31-corpus
```

Reference run on the API 35 AVD:

```
installed packages : 247
pulled             : 241
could not pull     : 6
  the ones that failed, named so the denominator is checkable:
    android.auto_generated_rro_vendor__
    com.google.android.connectivity.resources.goldfish.overlay
    com.google.android.marvin.talkbackoverlay
    com.android.phone.auto_generated_rro_vendor__
    com.android.systemui.auto_generated_rro_vendor__
    com.android.carrierconfig.auto_generated_rro_vendor__

classes*.dex compression split ...
  apks=241  classes*.dex=254  STORED=234  DEFLATED=20

corpus is in /tmp/ch31-corpus -- delete it when you are finished.
```

### Step 1.2 — Write the denominator down before you look at any result

This is the discipline. Fill it in for your device:

```
installed packages          : ____
pulled                      : ____
could not pull              : ____   (names: ____________________)
of the pulled, mine         : ____   (your lab apps, other chapters' apps)
therefore third-party/system: ____
```

On the reference device: 247 installed, 241 pulled, 6 failures — all six runtime resource overlays,
which contain **no DEX at all** and therefore cost a DEX sweep nothing. Of the 241, two were this
chapter's lab apps and two belonged to another chapter's in-flight work, leaving 237.

> **Pentester's Note**
> "We scanned every app on the device" is a claim that is almost never true and is trivially
> checkable. Naming the failures costs one line and is the difference between a measurement and an
> impression. A failure that carries no DEX costs you nothing; a failure that is a real application
> is a hole in your coverage, and only you can tell them apart.

### Step 1.3 — Note the compression split

```
classes*.dex=254  STORED=234  DEFLATED=20
```

A device-side `grep` over `.apk` files can only see the **STORED** entries, because the DEFLATED ones
are compressed. Find out which apps those are:

```bash
# host
python3 -B - /tmp/ch31-corpus <<'PY'
import glob, os, sys, zipfile
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.apk"))):
    with zipfile.ZipFile(p) as z:
        d = [i.filename for i in z.infolist()
             if i.filename.startswith("classes") and i.filename.endswith(".dex")
             and i.compress_type != zipfile.ZIP_STORED]
        if d:
            print("%-52s %d deflated" % (os.path.basename(p), len(d)))
PY
```

Reference run: eight APKs, of which **one browser accounts for ten of the twenty** and the rest are
sideloaded or lab apps. Every preinstalled APK is STORED.

So the on-device shortcut silently skips the largest third-party application present, and nothing in
its output says so. [64-Xposed](../../64-Xposed/README.md) measured the same asymmetry on the same
image; the split moves with what has been sideloaded, the conclusion does not.

---

## Part 2 — Run the sweep

```bash
# host
python3 -B fragment-injection-scan.py /tmp/ch31-corpus --recursive > /tmp/ch31-scan.txt 2>&1
tail -14 /tmp/ch31-scan.txt
```

Reference run:

```
========================================================================
APKs scanned                                    : 241
  tier 1  input reaches a Fragment loader       : 1
  tier 2  PreferenceActivity gate to adjudicate : 6
  tier 3  structural presence only              : 38
  no signal at all                              : 196
classes*.dex entries                            : 254 (234 STORED, 20 DEFLATED)
APKs with a parse error                         : 0
========================================================================
```

**Before you go further, resolve the tier 1 hit.** On the reference run it is this chapter's own
victim app, which you installed. Excluding your own apps is not cheating; failing to notice them is.

```bash
# host
grep -B2 "TIER 1" /tmp/ch31-scan.txt
```

Excluding lab apps: **zero tier 1 findings in 241 APKs.**

### The three tiers, and what each is worth

| Tier | Meaning | Worth |
|---|---|---|
| 1 | one method reads external input **and** calls a Fragment loader | a lead worth reading immediately |
| 2 | a `PreferenceActivity` gate to adjudicate — missing, or present and unread | a lead worth reading |
| 3 | structural presence: subclasses `PreferenceActivity`, or references the extra, or calls a loader | **not a finding** and must never be counted as one |

38 APKs at tier 3 is not "38 vulnerable apps". Most of them reference `:android:show_fragment` because
they **launch somebody else's settings screen**, which is an entirely normal thing to do.

---

## Part 3 — Adjudicate every tier 2 hit

This is the part that takes two hours and is the whole point.

### Step 3.1 — Classify every `isValidFragment` by its bytecode shape

Write the classifier. It reuses the scanner's DEX reader:

```bash
# host
cat > /tmp/adjudicate.py <<'PY'
import collections, glob, importlib.util, os, struct, sys, zipfile

spec = importlib.util.spec_from_file_location(
    "fis", os.path.join(sys.argv[1], "fragment-injection-scan.py"))
fis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fis)

# const/4 vN, #1 followed by return vN -- two instructions, four bytes.
RET_TRUE = {"12110f01", "12100f00", "12120f02", "12130f03", "12140f04"}

shapes = collections.Counter()
rows = []
for apk in sorted(glob.glob(os.path.join(sys.argv[2], "*.apk"))):
    if "ch31" in os.path.basename(apk):
        continue                                   # our own lab apps
    try:
        z = zipfile.ZipFile(apk)
    except Exception:
        continue
    with z:
        for n in z.namelist():
            if not (n.startswith("classes") and n.endswith(".dex")):
                continue
            try:
                d = fis.Dex(z.read(n))
            except Exception:
                continue
            for cd in d.class_defs():
                pref = cd["super"] == fis.PREFERENCE_ACTIVITY
                seen = False
                for midx, acc, code_off in d.methods_of(cd["data_off"]):
                    if d.method(midx)[1] != "isValidFragment":
                        continue
                    seen = True
                    if not code_off:
                        shapes["abstract/native"] += 1
                        continue
                    isz = struct.unpack_from("<HHHHII", d.d, code_off)[5]
                    raw = d.d[code_off + 16: code_off + 16 + isz * 2].hex()
                    kind = ("RETURN TRUE, no check" if raw in RET_TRUE
                            else "3 units or fewer, other" if isz <= 3
                            else "real comparison")
                    shapes[kind] += 1
                    rows.append((os.path.basename(apk), cd["name"], isz, kind, raw))
                if pref and not seen:
                    shapes["NO override"] += 1
                    rows.append((os.path.basename(apk), cd["name"], -1, "NO override", ""))

print("=== isValidFragment shapes (lab apps excluded) ===")
for k, v in shapes.most_common():
    print("%-46s %d" % (k, v))
print()
for a in sorted({r[0] for r in rows}):
    sub = [r for r in rows if r[0] == a]
    print("%-52s %s" % (a[:52], dict(collections.Counter(r[3] for r in sub))))
PY
python3 -B /tmp/adjudicate.py /path/to/31-Fragments/scripts /tmp/ch31-corpus
```

Reference run:

```
=== isValidFragment shapes (lab apps excluded) ===
real comparison                                32
NO override                                    11
RETURN TRUE, no check                           5

<a settings application>                       {'real comparison': 32}
<a preinstalled mail client>                   {'RETURN TRUE, no check': 4, 'NO override': 1}
<a preinstalled search application>            {'NO override': 1, 'RETURN TRUE, no check': 1}
<a preinstalled telephony component>           {'NO override': 7}
<a certificate installer>                      {'NO override': 1}
<a telecom service>                            {'NO override': 1}
```

**48 gates. 32 + 11 + 5 = 48. The arithmetic closes.** If it does not close for you, something is
being double-counted or dropped and you must find out which before going further.

### Step 3.2 — Verify the classifier on a case you can check

Never trust a classifier you have not tested. Your own victim app has one of each:

```bash
# host -- temporarily allow the lab apps through by removing the `continue`,
# or just point it at a directory containing only your victim APK
mkdir -p /tmp/ch31-self && cp /tmp/ch31-corpus/com.pentest.ch31.victim.apk /tmp/ch31-self/
sed 's/if "ch31" in os.path.basename(apk):/if False:/; s/^            continue$//' /tmp/adjudicate.py > /tmp/adj-self.py
python3 -B /tmp/adj-self.py /path/to/31-Fragments/scripts /tmp/ch31-self
```

You should get one `NO override` (`LegacySettingsActivity`), and two `real comparison` entries — your
`SettingsActivity` and `SettingsHardenedActivity` both carry logging, which pushes them over the
size threshold. **That is a false negative in the classifier and you should notice it.** Size alone
does not distinguish a gate from a rubber stamp; the scanner's `calls` list does, because the
vulnerable one calls only `Log` and `StringBuilder` while the hardened one calls `Set.contains`.

Run the scanner on the same APK to see that:

```bash
# host
python3 -B fragment-injection-scan.py /tmp/ch31-self/com.pentest.ch31.victim.apk --verbose | grep -A5 "isValidFragment override"
```

Write down what you learned: **a shape classifier catches the naked case; a call-set classifier
catches the logged case; neither is complete on its own.**

### Step 3.3 — Read the `RETURN TRUE` bodies

```bash
# host
cat > /tmp/dumpgate.py <<'PY'
import importlib.util, os, struct, sys, zipfile
spec = importlib.util.spec_from_file_location(
    "fis", os.path.join(sys.argv[1], "fragment-injection-scan.py"))
fis = importlib.util.module_from_spec(spec); spec.loader.exec_module(fis)
z = zipfile.ZipFile(sys.argv[2])
for n in z.namelist():
    if not (n.startswith("classes") and n.endswith(".dex")):
        continue
    d = fis.Dex(z.read(n))
    for cd in d.class_defs():
        for midx, acc, off in d.methods_of(cd["data_off"]):
            if d.method(midx)[1] == "isValidFragment" and off:
                isz = struct.unpack_from("<HHHHII", d.d, off)[5]
                print("%-64s %2d units  %s" % (
                    cd["name"], isz, d.d[off+16:off+16+isz*2].hex()))
PY
python3 -B /tmp/dumpgate.py /path/to/31-Fragments/scripts /tmp/ch31-corpus/<the mail client>.apk
```

```
Lcom/.../EmailFolderSettingsActivity;     2 units  12110f01
Lkth;                                     2 units  12110f01
Lcom/.../SomePreferenceActivity;          2 units  12110f01
Lcom/.../LabelSettingsActivity;           2 units  12110f01
```

Decode it by hand, because this is the pattern to memorise:

```
12 11   const/4 v1, #int 1
0f 01   return v1
```

**`return true`, unconditionally, in shipping preinstalled software, in 2026.** Anybody who tells you
this bug class was fixed in 2013 is wrong about the code.

Now decode a `real comparison` from the settings application and see the difference:

```
1c00 xxxx   const-class v0, <some Fragment>
6e10 ....   invoke-virtual Class.getName()
6e20 ....   invoke-virtual String.equals(Object)
0a00        move-result v0
0f00        return v0
```

It reads its parameter. That is the question from [README §6.2](../README.md), asked mechanically.

### Step 3.4 — The step everybody skips: is it reachable?

A `return true` gate behind a **non-exported** Activity is not a vulnerability. The DEX cannot tell
you which it is; the manifest can.

```bash
# host
AAPT2=$ANDROID_HOME/build-tools/35.0.1/aapt2
$AAPT2 dump xmltree --file AndroidManifest.xml /tmp/ch31-corpus/<the mail client>.apk > /tmp/mf.txt
grep -n -A6 '<the class you are checking>' /tmp/mf.txt | grep -E 'name|exported|permission'
```

Reference result for the three `return true` classes that appear in a manifest at all:

```
com.../EmailFolderSettingsActivity        exported=false  perm=None
com.../LabelSettingsActivity              exported=false  perm=None
com.../SomePreferenceActivity             exported=false  perm=None
```

And the other two? Check their access flags and superclasses:

```bash
# host
python3 -B - /path/to/31-Fragments/scripts /tmp/ch31-corpus/<the mail client>.apk <<'PY'
import importlib.util, os, sys, zipfile
spec = importlib.util.spec_from_file_location("fis", os.path.join(sys.argv[1], "fragment-injection-scan.py"))
fis = importlib.util.module_from_spec(spec); spec.loader.exec_module(fis)
z = zipfile.ZipFile(sys.argv[2])
for n in z.namelist():
    if n.startswith("classes") and n.endswith(".dex"):
        d = fis.Dex(z.read(n))
        for cd in d.class_defs():
            if cd["name"] in ("Lkth;", "Lktn;"):
                print(cd["name"], "access=0x%x" % cd["access"], "super=", cd["super"])
PY
```

```
Lktn; access=0x1 super= Landroid/preference/PreferenceActivity;
Lkth; access=0x1 super= Lktn;
```

R8-renamed **base classes**, not registered in any manifest. The concrete Activities that inherit
from them are the three above, and all three are `exported="false"`.

**Result: 5 injection-shaped gates, 0 reachable.**

Do the same for the 11 `NO override` classes. Reference result: 7 resolve to manifest entries, of
which **5 are `exported="true"` with no `android:permission`**; the other 4 are base classes. Those
five are the crash primitive of [README §5.4](../README.md).

---

## Part 4 — Make the arithmetic close

Fill in this table for your corpus and make the numbers add up:

| Category | Count | Of which reachable (exported, no permission) | Verdict |
|---|---:|---:|---|
| `isValidFragment` performing a real comparison | | n/a | correct |
| No override at all (`targetSdk >= 19` → throws) | | | crash primitive |
| `return true`, no check | | | injection primitive |
| **Total gates** | | | |

Reference run:

| Category | Count | Reachable | Verdict |
|---|---:|---:|---|
| real comparison | 32 | n/a | 32 of 32 correct, all in one settings application |
| no override | 11 | **5** | crash-on-demand against five exported components |
| `return true` | 5 | **0** | shape present, **not reachable** |
| **Total** | **48** | | |

---

## Part 5 — Write the conclusion, including what it does not support

Three statements your corpus supports, and one it does not.

**Supported:**

1. **The vulnerable shape is alive.** Five `return true` gates on a stock image in 2026.
2. **Not one of them is reachable.** Every host was `exported="false"`. Reporting "found fragment
   injection in a preinstalled app" on the strength of `12 11 0f 01` alone would be publishing a
   finding that does not exist.
3. **The correct shape is also alive and is the majority.** 32 of 48 gates do a real comparison, all
   in one application, which is what a properly hardened fleet looks like.

**Not supported — and this is the sentence that makes the rest credible:**

> This corpus is a stock GMS image. It contains **four** third-party packages and no banking, DRM,
> enterprise or gaming software. These numbers support a statement about *the platform and its
> preinstalled applications*. They support **nothing** about the applications you are paid to test.

[64-Xposed](../../64-Xposed/README.md) recorded exactly this limitation about exactly this device,
and it has not improved. State it in your own write-up rather than letting a reader infer a
generalisation you did not measure.

Also record the scanner's blind spots, because a zero from a blind tool is not a zero:

- **R8 renames `FragmentFactory` and `instantiate`**, so the tier 1 signature cannot fire through the
  AndroidX path in a minified app. Your zero is a zero for the *platform* path.
- **String encryption** defeats the `:android:show_fragment` signature entirely.
- **A source in one method and a sink in another** is invisible to a per-method rule.

---

## Success criteria

- [ ] A denominator with the failures named, and a note on whether they carried DEX.
- [ ] The STORED/DEFLATED split, with the apps that account for the DEFLATED entries.
- [ ] Tier counts, with your own lab apps identified and excluded.
- [ ] A shape classification where **total = correct + no-override + return-true**, exactly.
- [ ] At least one `return true` body decoded by hand from its bytes.
- [ ] At least one `real comparison` body decoded, showing it reads its parameter.
- [ ] Export status resolved from the manifest for every non-correct gate.
- [ ] A written note of the case where your classifier was **wrong** (step 3.2) and why.
- [ ] A conclusion with an explicit statement of what the corpus does not support.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `pull-apk-corpus.sh` refuses to run | You pointed it inside the repository | `.apk` is on the artefact blocklist; pick a directory outside |
| The loop pulls one package and exits | `adb shell` inherited the loop's stdin | Every `adb` call inside a `while read` needs `</dev/null`; the shipped script does this |
| Arithmetic does not close | A class counted twice across multi-DEX APKs, or a `continue` skipping silently | Print the rows, not just the counter |
| Scanner reports a parse error | A DEX version the reader does not know | It names the file; add the magic to `DEX_MAGICS` and re-run |
| `aapt2 dump xmltree` prints nothing | Wrong flag order, or an APK with no manifest | `aapt2 dump xmltree --file AndroidManifest.xml <apk>` |
| Class in the DEX but not in the manifest | It is a base class, or an abstract host | Check its access flags and superclass, as in step 3.4 |

---

## Clean up

```bash
# host
rm -rf /tmp/ch31-corpus /tmp/ch31-self /tmp/adjudicate.py /tmp/adj-self.py /tmp/dumpgate.py /tmp/mf.txt /tmp/ch31-scan.txt
```

The corpus is several gigabytes of other people's code. Delete it.

---

## Where to go next

- [Lab 05 — CTF: The Understudy's Understudy](lab-05-ctf-the-second-cast.md), which chains everything
  you have learned and includes one deliberate dead end.
- [README §8.4](../README.md) for the full adjudication this lab reproduces.
- [52-StaticAnalysis](../../52-StaticAnalysis/README.md) for the funnel discipline applied to a real
  commercial app rather than a stock image.
