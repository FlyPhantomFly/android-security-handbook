# Examples — chapter 41

Four things live here: two rules files that are the point of the chapter, and a
small application that exists so those two rules files can be *measured* rather
than argued about.

| Path | What it is |
|---|---|
| [`01-overbroad-rules.pro`](01-overbroad-rules.pro) | A deliberately over-broad rules file. Every rule in it is a shape that appears in real projects. Annotated line by line with what it costs. |
| [`02-tightened-rules.pro`](02-tightened-rules.pro) | The same application's genuine requirements, expressed as narrowly as the rules language allows. Every rule carries the sentence "delete this and X breaks". |
| [`keeplab/`](keeplab/) | The fixture application: five Java classes, a manifest, two resource files, and [`build.sh`](keeplab/build.sh), which builds it **three times** and prints the diff. |

---

## The three builds

`keeplab/build.sh` produces:

| Build | Engine | Rules | Equivalent Gradle setting |
|---|---|---|---|
| **A** `a-norules` | D8 | none | `isMinifyEnabled = false` |
| **B** `b-tightened` | R8 | `02-tightened-rules.pro` | `isMinifyEnabled = true`, good rules |
| **C** `c-overbroad` | R8 | `01-overbroad-rules.pro` | `isMinifyEnabled = true`, bad rules |

Build C is the one that matters. It has minification **on**, it runs the same
engine as build B, it takes the same time, and its output is — for the
application's own code — indistinguishable from build A. That is the finding
this chapter teaches you to recognise from the outside.

---

## What was measured

Numbers below are from an actual run on the machine this chapter was written on:
Windows 11, Android SDK build-tools 35.0.1, **R8 8.6.2-dev** (extracted from
`build-tools/35.0.1/lib/d8.jar`), JDK 24, `--min-api 21`.

| | A: no rules | B: tightened | C: over-broad |
|---|---|---|---|
| `classes.dex` size | 7,384 B | **2,920 B** | 7,180 B |
| classes in the DEX | 12 | **4** | 12 |
| classes under `com.pentest.ch41` | 12 | 3 | 12 |
| named members visible to `dexdump` | 50 | **10** | 49 |
| `DeadCode` present | yes | **no** | yes |
| `staging-token-do-not-ship` in the DEX | yes | **no** | yes |
| original `.java` filenames in the DEX | **7** | 0 | 0 |
| resource names in `resources.arsc` | 7 | 7 | 7 |

Three of those rows are worth stopping on.

**The APK file sizes were identical — 12,757 bytes for all three.** That is not
a mistake and it is not a coincidence: `apksigner` pads the APK Signing Block so
that the ZIP central directory begins on a 4096-byte boundary, and all three
DEX files fit inside the same padded span. Anyone who compares `ls -l *.apk` on
a small build will conclude that minification achieved nothing. **Compare
`classes.dex`.**

**Build A leaked the original source filenames; builds B and C did not.** The
unminified build carries a `SourceFile` attribute per class holding
`MainActivity.java`, `LicenseValidator.java`, `Transaction.java` and four more.
R8 8.6.2 replaced all of them with the single constant `SourceFile` — *even in
build C*, which sets `-keepattributes *` and `-dontobfuscate` and contains no
`-renamesourcefileattribute` at all. The widely-repeated advice that you must
add `-renamesourcefileattribute` or your filenames ship is describing ProGuard's
behaviour, not R8's default. Verify it on your own build rather than assuming
either way.

**Resource names were untouched in every build.** `id/pin_entry`,
`layout/activity_main`, `string/license_check_failed` are present at every
setting. Nothing in the AGP toolchain renames them.

---

## Running it

```bash
# host — build all three, out of tree
export ANDROID_HOME=~/Android/Sdk
cd examples/keeplab
OUTDIR=/tmp/ch41 ./build.sh
```

Then audit the rules, and report on what actually survived:

```bash
# host — from the chapter root
python3 -B scripts/proguard-rules-audit.py examples/01-overbroad-rules.pro
python3 -B scripts/proguard-rules-audit.py examples/02-tightened-rules.pro

python3 -B scripts/what-survived.py /tmp/ch41/c-overbroad/app.apk \
        --rules examples/01-overbroad-rules.pro
python3 -B scripts/what-survived.py /tmp/ch41/b-tightened/app.apk \
        --rules examples/02-tightened-rules.pro
```

[`labs/lab-02-build-the-diff.md`](../labs/lab-02-build-the-diff.md) walks the
whole sequence with the expected output at each step, including the two places
where the output is *not* what a reader expects.

---

## A note on file layout

The Java sources are stored at `keeplab/java/com/pentest/ch41/*.java` — the real
package directory structure, because `javac` needs it and because the reader
should see a normal source tree. `build.sh` copies nothing; it compiles in
place and writes every `.class`, `.dex` and `.apk` to `$OUTDIR`, outside this
repository. No build artefact is ever created next to these files.

The rules files sit at the `examples/` root rather than inside `keeplab/`
because they are the chapter's primary teaching artefacts and are meant to be
read on their own, without the fixture.
