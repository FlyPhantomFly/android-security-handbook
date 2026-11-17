# Lab 03 — Across the boundary, and back

> **Objective.** Build both halves of an application's managed/native boundary map — the static one
> from the artefact and the runtime one from the process — diff them, and use the three piles that
> fall out. You will measure, on an app you own, what fraction of its native surface is invisible to
> symbol lookup, and you will find at least one thing in the runtime pile that is not in your
> artefact at all.
>
> **Difficulty:** Intermediate–Advanced · **Time:** 3–4 hours
> **Root needed:** Yes, for the runtime half · **Device needed:** Yes
>
> Part 5 is a full no-device fallback that reaches most of the same conclusions.

---

## Why this lab exists

[56-JADX](../../56-JADX/README.md) takes you as far as a `native` declaration and stops, correctly —
there is no Java left. [57-Ghidra](../../57-Ghidra/README.md) starts at the `.so` and assumes you
already know which functions matter. [16-JNI](../../16-JNI/README.md) owns the mangling rules that
connect the two.

Nobody owns the walk. And the walk is where the naive model breaks, because that model — *a `native`
method has a C function named after it, so look up the name* — is correct, documented, and wrong
about real applications most of the time.

Measured across 18 real APKs while writing this chapter: **8,140 distinct methods declared `native`,
1,049 (12.9%) resolvable to an exported symbol.** Eighty-seven percent of the boundary is invisible
to symbol lookup, and it fails *silently*: no match and no indication that a match was ever possible.

This lab makes you produce that number for an app of your own, and then go get the part the static
half cannot see.

> **Warning — scope and ethics.** Use an application **you own**, installed on **your own device**,
> or a well-known deliberately-vulnerable training app. Reverse engineering is contractually and
> statutorily contextual — see README §1.6, which names the three separate axes. A lab suggesting a
> target is not authorisation for it.

---

## Setup

```bash
# host
export S=<your-device-serial>          # from `adb devices -l`
adb devices -l                         # confirm which devices are attached
```

> **Two devices, one silent failure.** If more than one device is attached, `adb` fails loudly —
> which is good behaviour. **Frida does not.** `frida.get_usb_device()` returns the first USB-type
> device it enumerates, and while writing this chapter that was an emulator rather than the phone
> the artefacts came from. Every runtime measurement would have been about a different ABI, API level
> and page size, silently correlated against the wrong static evidence. **Always pass `-D $S`.**
> Verify:
>
> ```bash
> python3 -c "import frida; print(frida.get_usb_device())"
> ```

You need `frida-server` running on the device, `dexdump` from build-tools, and `llvm-nm` from the
NDK. `boundary-map.py` finds the last two itself via `ANDROID_HOME` / `ANDROID_NDK`.

---

## Part 1 — Acquire the program, not a piece of it

**Task 1.1.** Get every APK path. Not the first one:

```bash
# host
adb -s $S shell pm path <your.package>
```

**Task 1.2.** If that returned more than one line, pull all of them. Then record identity:

```bash
# host
mkdir -p target && cd target
adb -s $S pull <each path> .
sha256sum *.apk
aapt2 dump badging base.apk | grep -E 'package: name|versionName'
```

<details>
<summary>Reference: what this looks like on a real app</summary>

`com.android.chrome` on the Redmi returned **seven** APKs:

```
base.apk  split_chrome.apk  split_config.en.apk  split_dev_ui.apk
split_on_demand.apk  split_stack_unwinder.apk  split_test_dummy.apk
```

Pulling only `base.apk` — 12.6 MB of a much larger program — is the single most common acquisition
error, and it makes every later "I searched and found nothing" worthless.

In the same corpus, `com.vendor.professionalnet`'s `base.apk` was **334 KB** and contained no native
methods, no libraries and nothing else of interest. It is a stub. A sweep of it returns nothing, and
nothing is not a result.

</details>

**Task 1.3.** Record how many APKs you pulled, and how many you are about to analyse. If those
numbers differ, that difference is your first residue entry.

---

## Part 2 — The static half

```bash
# host, from the chapter directory
python3 -B scripts/boundary-map.py target/base.apk --report
```

**Task 2.1.** Record five numbers:

| Quantity | Yours |
|---|---|
| `classes*.dex` count | |
| Distinct methods declared `native` | |
| Bundled `arm64-v8a` libraries | |
| `Java_*` symbols exported | |
| Resolvable by symbol lookup (and %) | |

**Task 2.2.** Get the target list — every declared native method with no matching symbol:

```bash
# host
python3 -B scripts/boundary-map.py target/base.apk --unresolved | head -40
python3 -B scripts/boundary-map.py target/base.apk --unresolved | wc -l
```

**Task 2.3 — the discipline task.** Run this and read it properly:

```bash
# host
python3 -B scripts/boundary-map.py --explain
```

Then answer **in writing**: *why is my unresolved count not a count of `RegisterNatives` bindings?*
Name all four causes. If you cannot name four, re-read the output — this is the whole reason the tool
refuses to state a cause.

<details>
<summary>The four, compressed</summary>

1. **Explicit binding.** `RegisterNatives` was called with a function pointer; the function can be
   `static` and stripped, so no symbol exists and none ever did.
2. **The library is somewhere else.** A split, a Play Feature Delivery module, or a download at first
   run. Three APKs in the chapter's corpus declared 480, 618 and 331 native methods and shipped **no
   arm64 library at all** in `base.apk`.
3. **A different ABI.** Re-run with `--abi` or `--all-abis`.
4. **The class is never loaded.** Dead code or a stub.

Only a runtime observation distinguishes them, which is Part 3.

</details>

---

## Part 3 — The runtime half

```bash
# host -- note -D, and note -f: you must spawn, not attach, or you miss startup binding
frida -D $S -f <your.package> -l scripts/boundary-confirm.js -o rn.txt
```

**Task 3.1.** Record the summary line: `calls`, `methods`, `distinct`, and the per-module breakdown.

**Task 3.2 — liveness, before you believe a small number.** If your app reported **zero calls**, that
is not yet a result. A silent run and a broken hook produce identical output.

Run the *same script* against a target you know performs explicit binding:

```bash
# host -- a browser or a large Google app is a safe positive control
frida -D $S -f com.android.chrome -l scripts/boundary-confirm.js -o control.txt
grep SUMMARY control.txt
```

If the control reports non-zero and your target reports zero, the zero is real and is a finding. If
the control also reports zero, your instrument is broken and you have measured nothing.

<details>
<summary>Reference: what the control produced here</summary>

`com.android.chrome` 147.0.7727.111, Redmi, API 30 — **identical across three consecutive spawns**:

```
[*] RegisterNatives @ 0x758af36f40  (libart.so+0x3f3f40)
SUMMARY calls=78 methods=509 distinct=509

bindings by module (this is your target list):
     509  /data/app/~~.../base.apk!/lib/arm64-v8a/libelements.so
```

And in the chapter's own work, a small commercial app reported **`calls=0`** with the same script.
That zero was only trustworthy *because* the Chrome control reported 78. Without it, the honest
statement would have been "I measured nothing".

</details>

> **Pentester's Note — read the module path.** `base.apk!/lib/arm64-v8a/libelements.so` — the `!`
> means the library is mapped **directly out of the APK** (`extractNativeLibs="false"`) and does not
> exist as a file under `/data/app/.../lib/arm64/`. Looking for that file, and not finding it, reads
> as "the library is absent". It is not; it never gets extracted.

---

## Part 4 — Diff the halves, and use the three piles

This is the step that is skipped and the step that pays.

```bash
# host -- static: methods declared but not symbol-resolvable
python3 -B scripts/boundary-map.py target/base.apk --unresolved | cut -f1 | sort -u > static.txt

# host -- runtime: what was actually bound
grep '^RN' rn.txt | awk -F'\t' '{print $2 "." $3}' | sort -u > runtime.txt

# host -- the three piles
comm -12 static.txt runtime.txt | wc -l    # AGREED
comm -23 static.txt runtime.txt | wc -l    # STATIC-ONLY
comm -13 static.txt runtime.txt | wc -l    # RUNTIME-ONLY
```

**Task 4.1.** Record the three counts and interpret each:

| Pile | Count | What it means | What to do |
|---|---|---|---|
| **Agreed** | | Declared in the artefact and observed binding | Your strongest candidates. Start here |
| **Static-only** | | Declared, never bound in your window | Unexercised path, dead code, or a class never loaded |
| **Runtime-only** | | Bound, but not in your artefact | **Fix your acquisition — something ran that you do not have** |

**Task 4.2 — the important one.** Look at your runtime-only pile. For each entry, which of these is
it?

- A class that lives in a split APK you did not pull.
- A class loaded from a downloaded module.
- A class loaded from memory with no file behind it (see §7.4 and
  [40-Obfuscation](../../40-Obfuscation/README.md)'s `frida-classloader-dump.js`).
- A framework class, not the app's at all.

<details>
<summary>Reference: Chrome's diff, and why it is the cleanest example in the chapter</summary>

| | |
|---|---:|
| Declared `native` in `base.apk` | **323** |
| Resolvable by symbol | **6** (1.9%) |
| Bound at runtime | **509** |

**The runtime bound more methods than the entire static artefact declares.** That is impossible if
`base.apk` is the program — and it is not, because there are seven APKs.

The runtime-only pile here is not a curiosity. It is the majority of the evidence, and it exists
entirely because of an acquisition decision made in Part 1.

Note also what the two halves are each blind to. Static saw 323 and could resolve 6. Runtime saw 509
bindings in a 25-second startup window and knows nothing about paths not exercised. **The union is
larger than either and is still not the whole program.**

</details>

---

## Part 5 — No-device fallback: the boundary in one library

If you have no rooted device, this part reaches the structural conclusions without one, using the
fixture.

```bash
# host
cd examples && ./build.sh --both-opt
export OUT="${TMPDIR:-/tmp}/ch68-build"
```

**Task 5.1.** The fixture is pure native, so there is no managed side — which makes it a clean way to
see what a symbol table does and does not tell you:

```bash
# host -- the map a symbol-based tool gets
$NDKBIN/llvm-nm -D --defined-only "$OUT/libinvestigate.so" | grep ' T '
```

Five exported functions. **Now ask which of them are actually reachable from outside**, and which are
merely exported:

```bash
# host -- every call target in the library
$NDKBIN/llvm-objdump -d "$OUT/libinvestigate.so" | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

**Task 5.2.** At `-O2` that list is **empty** — no `bl` instructions at all. At `-O0`:

```
      1 bl	0x1a3c <gate_is_open>
      1 bl	0x1ac0 <iv_derive_seed@plt>
      1 bl	0x1ad0 <strcmp@plt>
```

Note `iv_derive_seed@plt`. **A pattern anchored on `>` immediately after the name misses it**, and
reports zero call sites for a function that is definitely called — measured on this fixture, and
recorded in README §8.3 as a false negative in the chapter's own showcase experiment. Always use
`bl.*<name(@plt)?>`, and always corroborate a zero with the full listing above.

**Task 5.3.** Write the general lesson in your own words: *what is the relationship between "exported"
and "used"?* Then map it onto the managed case — an exported `Java_*` symbol that no `native`
declaration matches is the same phenomenon, and `boundary-map.py` reports those as
`orphan_exports`.

---

## Part 6 — Come back to the managed side

Arriving at a native address is the halfway point of the crossing, not the end. A native function you
fully understand tells you nothing about *when it runs and with what* — and that is usually the half
the question was about.

**Task 6.1.** Pick one method from your **agreed** pile. Find its Java callers:

```bash
# host
jadx -d out target/base.apk 2>&1 | tail -3
grep -rn "<methodName>" out/sources --include='*.java' | head -20
```

**Task 6.2 — the absence check.** If that grep returns nothing, you may **not** conclude the method
is unused. [56-JADX](../../56-JADX/README.md) established five checks that must pass first, and its
`faq.md` question 14 is the canonical statement. Run them:

| # | Check | Command |
|---|---|---|
| 1 | Did decompilation complete? | class count in versus files out |
| 2 | What was refused? | `grep -rc 'Method not decompiled\|JADX ERROR' out/sources \| awk -F: '$2>0' \| wc -l` |
| 3 | Is code loaded dynamically? | `grep -rn 'DexClassLoader\|InMemoryDexClassLoader' out/sources` |
| 4 | Is it native? | you already know — that is why you are here |
| 5 | Do you have every split APK? | Part 1 |

> **Pentester's Note.** Check 1 matters more than it looks. jadx's console reported
> `finished with errors, count: 61` on a real 17.5 MB APK while the output tree contained **2,104
> refused methods across 1,424 files** — a 30× under-report. Count the tree, never the summary.

**Task 6.3.** For the caller you found, answer the three questions that make the crossing a finding
rather than a fact:

1. What arguments does the Java side pass?
2. How much of each is attacker-influenced?
3. What is the shortest path from an exported component to this call?

That third question is what turns "there is a native entry point" into "there is a *reachable* native
entry point", which is the difference between an inventory and an attack surface.

---

## Part 7 — Write it up honestly

**Task 7.1.** Produce the finding in the four-part shape from §3.16 — claim, evidence with tiers,
limits, impact — and **write the limits before the impact.**

<details>
<summary>A worked example, for Chrome, written the way it should be</summary>

> **Claim.** At least 509 native methods are bound by `RegisterNatives` during startup, all into
> `libelements.so`, of which 6 were discoverable by symbol lookup in `base.apk`.
>
> **Evidence.**
> - *Tier 2* — `boundary-map.py` over `base.apk`: 323 methods declared `native`, 11 `Java_*` exports
>   across two arm64 libraries, 6 matches.
> - *Tier 5* — `boundary-confirm.js` hooking `RegisterNatives` via the `JNIEnv` table: `calls=78
>   methods=509 distinct=509`, identical across three consecutive spawns.
>
> **Limits.** Six of seven APKs were not analysed. The runtime observation covers a ~25-second
> startup window only; any binding after that is unobserved. Measured against version 147.0.7727.111
> on Android 11 / API 30, arm64. No attempt was made to determine which of the four causes explains
> any individual unresolved method. No claim is made about reachability from an exported component.
>
> **Impact.** An attack surface of this size that is invisible to symbol-based tooling is absent from
> most threat models, including the vendor's own review if it uses the same tooling. This is an
> attack-surface observation, not a vulnerability — its value is that the next assessment can target
> it.

Notice that the limits paragraph is longer than the claim, and that including it makes the finding
more credible rather than less.

</details>

**Task 7.2 — honest severity.** Rate your finding. Then check it against §5.8:

| Observation | Honest rating |
|---|---|
| "400 unmapped native entry points" | **Informational** as a finding, **High** as a methodology risk |
| "The app can be decompiled" | Not a finding |
| "This specific entry point takes attacker-controlled data and is reachable from an exported Activity" | As high as what it does |

**Task 7.3.** Clean up. Delete the pulled APKs and the jadx tree if your engagement rules require it,
and record what you deleted.

---

## Success criteria

- [ ] You pulled **every** APK `pm path` returned, and recorded the count.
- [ ] A static boundary map with all five numbers recorded.
- [ ] You can name all four causes of an unresolved method without looking.
- [ ] A runtime trace **with a liveness control** run against a known positive.
- [ ] Three pile counts computed, and each interpreted.
- [ ] At least one runtime-only entry investigated and classified — or a written argument for why the
      pile is empty.
- [ ] A finding written in claim / evidence-with-tiers / limits / impact order, limits before impact.
- [ ] Your limits paragraph names the window length, the API level, and the APKs you did not analyse.

---

## Hints

<details>
<summary>Hint 1 — boundary-map.py cannot find dexdump or llvm-nm</summary>

It searches `ANDROID_HOME` / `ANDROID_SDK_ROOT` for build-tools and `ANDROID_NDK` /
`ANDROID_NDK_HOME` (or `$SDK/ndk/<newest>`) for the toolchain. Override directly:

```bash
export DEXDUMP=/path/to/build-tools/35.0.1/dexdump
export LLVM_NM=/path/to/ndk/toolchains/llvm/prebuilt/<host>/bin/llvm-nm
```

On Windows,`dexdump.exe` **cannot read a DEX from inside an APK** — it fails with
`Failed anonymous mmap(...): Invalid argument` and prints `Processing 'base.apk'...` anyway. The
script already extracts every `classes*.dex` to a real file first, which is why it works.

</details>

<details>
<summary>Hint 2 — my runtime trace found nothing and the control also found nothing</summary>

Then your instrument is broken, and that is the correct conclusion to reach. Check, in order:

1. Is `frida-server` actually running, and does its version match your host `frida`?
2. Did you use `-f` (spawn) rather than `-U`/attach? Registration happens at startup; attaching later
   misses all of it.
3. Did the `[*] RegisterNatives @ ...` line print? If not, the hook never installed.
4. Did the script warn that slot 215 points somewhere other than `libart`? If so, the `JNIEnv` layout
   assumption does not hold on your platform and the numbers would be meaningless.

</details>

<details>
<summary>Hint 3 — my static and runtime name formats do not line up for `comm`</summary>

`boundary-map.py --unresolved` prints dotted class names (`com.example.Foo.bar`); the runtime script
prints the class as JNI reports it. Normalise both before comparing — replace `/` with `.`, strip any
leading `L` and trailing `;`, and sort with the same locale:

```bash
sed 's|/|.|g; s|^L||; s|;$||' raw.txt | LC_ALL=C sort -u > normalised.txt
```

A `comm` on unsorted or differently-sorted input silently produces nonsense, which is its own small
lesson about trusting a pipeline you did not check.

</details>

<details>
<summary>Hint 4 — the runtime-only pile is empty and I think I did something wrong</summary>

An empty runtime-only pile is a legitimate result: it means everything that bound was declared in the
artefact you have. That is what a single-APK app with no dynamic loading looks like, and it is good
news for the rest of your analysis.

Before believing it, confirm two things: that `pm path` really returned one line, and that your
liveness control fired. An empty pile because nothing was observed at all is a very different result
from an empty pile because everything matched.

</details>

---

## Debrief

1. What percentage of your target's declared native boundary was symbol-resolvable? **How does it
   compare to 12.9%**, and what would you need to know to say whether your app is unusual?

2. Your runtime trace covered a fixed window. **Name three code paths that certainly did not run in
   it**, and say how you would exercise each.

3. Part 3 asked for a liveness control. **What would you have concluded without it**, and how would
   that have appeared in the report?

4. The `!` in `base.apk!/lib/arm64-v8a/libelements.so` means the library is never extracted. **Name
   one other analysis technique that this breaks**, and how you would work around it.

5. Suppose your static map and your runtime trace had **agreed perfectly** — every declared method
   bound, nothing extra. Would that be evidence that you had the whole program? Justify the answer.

---

## Where this goes next

[Lab 04](lab-04-ctf-the-confident-conclusion.md) is the CTF, and it grades something no other
challenge in this repository grades: not whether you reached the right answer, but whether you know
which of your evidence supports it. Points are deducted for confident claims you cannot back.
