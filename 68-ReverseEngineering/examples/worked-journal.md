# A real journal, dead ends included

This is not a cleaned-up illustration. It is the actual sequence of questions, wrong turns and
corrections from writing chapter 68, reconstructed from the shell history and the commands' own
output, and edited only for length. Nine of the eighteen entries below are **failures**, and they
are the reason the file exists: every published methodology reads as though its author walked
straight to the answer, which teaches the one thing that never happens.

Read it as an example of *shape*, not of content. Your target will be different; the ratio of dead
ends to progress will not be.

**Session facts, recorded first because every claim below is a claim about them:**

| | |
|---|---|
| Devices | `84f7a024` — Redmi `M2101K6P`, Android 11 / API 30, `arm64-v8a`, rooted, frida-server |
| | `emulator-5554` — `sdk_gphone16k_x86_64`, Android 15 / API 35, `x86_64`, 16 KiB pages |
| Toolchain | NDK 25.2.9519653, build-tools 35.0.1, jadx 1.5.3, frida 16.1.6, Python 3.13.3 |
| Host | Windows 11, Git Bash |

---

## Q1 — Which device am I actually talking to?

Not a question about any target. A question about the instrument, asked first because everything
downstream is correlated against the answer.

```
H1  there is one device attached, and my tools will use it
P   `adb devices -l` lists one
R   it lists more than one
E   adb devices -l
O   two: 84f7a024 (M2101K6P) and emulator-5554 (sdk_gphone16k_x86_64)
V   REFUTED
```

**Consequence, immediately.** Every subsequent `adb` command needs `-s`, and — the part that was
nearly missed — so does every Frida command:

```
H2  frida -U will use the phone, since that is the "real" device
P   frida.get_usb_device() returns 84f7a024
R   it returns something else
E   python3 -c "import frida; print(frida.get_usb_device())"
O   Device(id="emulator-5554", name="Android Emulator 5554", type='usb')
V   REFUTED -- and this one would have poisoned the whole chapter
```

Cross-checked: `frida-ps -U` returned five `ranchu` (emulator) processes; `frida-ps -D 84f7a024`
returned zero. **`-U` means "the first USB-type device enumerated", not "the device you meant".**
The static corpus came from the phone. Had the runtime measurements gone to the emulator, they would
have been a different ABI, a different API level and a different page size, silently correlated
against the wrong artefacts.

`Q1 -> answered`. Sources: `frida.enumerate_devices()` output, and the `ranchu` process-count
comparison. Two independent readings of the same fact.

> One further oddity, recorded and **not** explained: the emulator has no running `frida-server`
> process (`ps -A` and `netstat -lntp` under root both show nothing) and Frida enumerated its
> processes anyway. The device-selection finding does not depend on the mechanism, so it stands. The
> mechanism is unknown and is written down as unknown.

---

## Q2 — How much of the managed/native boundary is visible statically?

The chapter's headline question. Corpus: APKs pulled from the phone.

```
H3  most native methods can be resolved to an exported Java_* symbol
P   a high match rate across a corpus
R   a low match rate
E   measure_boundary.py over 19 pulled APKs
O   native=0 for ALL NINETEEN APKs
V   INCONCLUSIVE -- this is not a result, it is a broken tool
```

**Dead end 1, and the most instructive of the session.** A clean, uniform, plausible zero across
every sample. It was not read as a finding for one reason only: §3.10's rule that *if a detector
agrees with you about every sample, suspect the detector.* Nineteen out of nineteen is not data.

```
H4  dexdump is failing rather than reporting a true zero
P   if failing, running it on one APK shows an error
R   it prints a clean parse with no native methods
E   dexdump.exe base.apk
O   E dexdump.exe: mem_map_windows.cc:96 Couldn't get file size.: Bad file descriptor
    E Failed to extract 'classes.dex': Failed anonymous mmap(...): Invalid argument
    Processing 'apks/enterprise-b.apk'...
V   REFUTED H4's negation -- the tool was failing, and printing "Processing" anyway
```

The error had been on screen the whole time, interleaved with output, and was read past. Fix:
extract every `classes*.dex` to a real file first, because **`dexdump.exe` cannot mmap a DEX from
inside an APK on Windows**. Re-run:

```
E   measure_boundary.py, extracting DEX first
O   7,562 distinct native methods, 1,050 symbol-resolvable (13.9%)
V   H3 REFUTED -- the large majority of the boundary is invisible to symbol lookup
```

---

## Q2a — Is that number reproducible with the tool I am shipping?

Asked because the number was produced by an ad-hoc script, and the chapter ships a different one.

```
H5  boundary-map.py reproduces the ad-hoc script's figures
P   same totals on the same corpus
R   different totals
E   boundary-map.py <corpus> --corpus
O   33 APKs, 8,571 declared, 813 resolved (9.5%)
V   REFUTED -- and three numbers moved at once, which is the signature of a
    changed input rather than a changed algorithm
```

**Dead end 2.** The corpus directory had been **deleted and repopulated by something outside this
session** — a shared scratchpad — and the run had swept 33 APKs including apps that were never
pulled. Per-APK spot check showed the two scripts agreeing exactly (`com.vendor.hrapp`: 13 declared, 4
resolved, both tools), so the algorithm was fine and the *input* was contaminated.

The temptation here is real and worth naming: the ad-hoc number was already written into the
chapter, and 9.5% versus 13.9% could have been waved through as "roughly the same". Instead:
re-pulled a corpus enumerated by name, one APK per package, hashes checked for duplicates, and
re-ran the shipped tool.

```
E   re-pulled 18 packages by name; boundary-map.py --corpus
O   18 APKs, 8,140 declared, 1,049 resolved (12.9%), 2,552 Java_* exports
V   ANSWERED -- and this is the number that ships, because it is the one a
    reader can reproduce with the tool in the repository
```

Every figure in the chapter was then updated from 19/7,562/1,050/13.9% to 18/8,140/1,049/12.9%.
Residue recorded: *the corpus is one device, one ABI, one point in time, and `base.apk` only.*

---

## Q3 — Does Chrome's runtime boundary match its static one?

```
H6  a runtime RegisterNatives trace will find roughly as many bindings as the
    static map declares native methods
P   comparable numbers
R   wildly different numbers
E   boundary-confirm.js against com.android.chrome
O   SUMMARY calls=78 methods=509 distinct=509
    static map of the same base.apk: 323 declared, 6 symbol-resolvable
V   REFUTED -- the runtime bound MORE methods than the artefact declares
```

509 > 323 is impossible if `base.apk` is the program. `pm path` returned **seven** APKs; one had been
pulled. The finding is not about Chrome, it is about acquisition.

**Dead end 3, caught by a reproducibility check.** The first write-up said *"490 of 509 bound into
`libelements.so`"*, a 96% figure, derived by counting lines in Frida's `-o` capture file. Running it
twice more to satisfy §3.7's reproducibility question:

```
E   three consecutive spawns, reading the in-process counter
O   run 1: calls=78 methods=509, all 509 -> libelements.so
    run 2: identical
    run 3: identical
V   the "490" was Frida's -o file silently dropping 19 lines to buffering
```

The missing nineteen lines had been read as *a second module*. **The instrument reporting the
measurement was itself the thing that needed a control.** Corrected to 509 of 509.

---

## Q4 — Does the fixture's obfuscation actually hide anything?

Building the lab target, which is the one situation where the answer key is available.

```
H7  XOR-masking the flag keeps the plaintext out of the binary
P   `strings` on the built .so finds only the decoy
R   `strings` finds the real flag
E   build at -O2, then: strings -a libinvestigate.so | grep 'CH68{'
O   CH68{ev1dence_b3ats_a_good_storyPREMIUM-2024-VALID
    CH68{n0t_th3_r3al_0ne_keep_going}
V   REFUTED -- clang constant-folded the decode loop into .rodata
```

**Dead end 4.** Repaired by masking with a value that only exists at runtime, `g_state.seed`:

```
E   rebuild, same check
O   CH68{ev1dence_b3ats_a_good_story...   -- STILL THERE
V   REFUTED AGAIN
```

**Dead end 5, and the better finding.** The decode loop is only reached after
`gate_is_open(g_state.seed)` returns true, and that function is `seed == 0xbd`. On that path the
compiler has *proved* the seed's value and substitutes the constant it proved.

**The check that guards the secret is what told the compiler the secret.**

```
E   volatile uint8_t mask = g_state.seed;  then rebuild
O   only CH68{n0t_th3_r3al_0ne_keep_going}   -- the decoy alone
V   ANSWERED. Two failed repairs, and the second failure is the teaching artefact
```

---

## Q5 — Does the fixture behave as designed on a real device?

```
H8  the traps hold at runtime, not just in the file
P   the licence check and the vault outcome disagree
R   they agree
E   push and run with three keys
O   PREMIUM-2024-VALID -> license: accepted   result: refused
    measure            -> license: rejected   result: CH68{ev1dence_b3ats_a_good_story}
    wrongkey           -> license: rejected   result: refused
V   SUPPORTED, and stronger than predicted -- the control is not merely
    decoupled from the outcome, it is anti-correlated with it
```

**Dead ends 6 and 7, both environment rather than target.** The first push failed with
`remote secure_mkdirs failed: No such file or directory`, which reads as a device permission problem
and is not one: Git Bash had rewritten `/data/local/tmp/ch68` into
`C:/Program Files/Git/data/local/tmp/ch68`. Setting `MSYS_NO_PATHCONV=1` fixed the push and
**broke the build**, because the Windows-hosted clang needs the conversion that adb must not have.
The variable has to be scoped to the push alone.

**Dead end 8.** `frida -f /data/local/tmp/ch68/investigate` returned
`unable to locate Android dynamic linker`. The vendor build blocks `execve` under `/data/local/tmp`,
so the binary runs only via `/system/bin/linker64`, and Frida's spawn cannot do that. Recorded as a
limitation rather than worked around: `dataflow-watch.js` was validated against a live app process
instead, and the fixture-spawn path is stated as untested on this device.

---

## Q6 — Is my own call-site experiment sound?

Asked last, and only because the chapter had just told the reader to rely on it.

```
H9  `grep -c 'bl.*<name>'` reliably counts call sites
P   a function known to be called scores >= 1
R   a function known to be called scores 0
E   build at -O0 (where nothing is inlined) and count calls to iv_derive_seed
O   exact pattern: 0     with (@plt)? : 1
    the disassembly reads: bl 0x1ac0 <iv_derive_seed@plt>
V   REFUTED -- the chapter's own showcase experiment has a false-negative mode
```

**Dead end 9, and the one that mattered most, because it was already published.** A call routed
through the Procedure Linkage Table renders with an `@plt` suffix, so a pattern anchored on `>`
immediately after the name misses it — and it misses in the direction that *feels like a finding*.

The published conclusion survived: `iv_check_license` scores zero under both patterns at both
optimisation levels, so it is genuinely dead. But it survived by luck. Corrected the pattern
everywhere to `bl.*<name(@plt)?>`, and added a cross-check that does not depend on getting a regex
right at all:

```bash
llvm-objdump -d libtarget.so | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

---

## The ledger at the end

| | |
|---|---|
| Questions asked | 6 (plus one sub-question) |
| Hypotheses | 9 |
| **Refuted** | **7** |
| Supported, then corroborated | 2 |
| Dead ends that were environment, not target | 4 of 9 |
| Published numbers corrected after the fact | 3 (`13.9% -> 12.9%`, `490 -> 509`, the grep pattern) |

Seven of nine hypotheses died. That ratio is not a sign the session went badly — it is what §1.5
predicts a healthy investigation looks like, and the two that survived are the two the chapter
actually rests on.

**The residue, written before the chapter was called finished:**

*Chosen.* The 18-APK corpus was not version-pinned per app. No attempt was made to identify which
of the four causes explains any individual unresolved method. The emulator was identified and then
deliberately not used for app measurement.

*Structural.* `base.apk` only, so splits are invisible — three corpus APKs declare native methods and
ship no arm64 library at all. The runtime trace covers a 25-second startup window, so any binding
after that is unobserved. The fixture-spawn path for `dataflow-watch.js` could not be exercised on
this device.

---

## What to copy from this

1. **Ask about your instrument before your target.** Q1 was the highest-value question of the session
   and it was not about any application.
2. **A uniform result across every sample is a tool failure until proven otherwise.** Nineteen zeros
   ended the first measurement; nineteen zeros should have ended it faster.
3. **Write the refutation first.** Every `R` line above is what made the corresponding `O` line
   readable as a verdict rather than as something to explain away.
4. **Re-run for reproducibility even when you believe the number.** It caught `490` and it caught the
   contaminated corpus.
5. **Record observations, not conclusions.** `O  native=0 for ALL NINETEEN APKs` is still true and
   still useful. "There are no native methods" would have been neither.
6. **Turn your own tooling on your own claims last.** Q6 found a defect in advice the chapter had
   already given.

Reproduce this shape with [`scripts/re-journal.py`](../scripts/re-journal.py), which enforces the
parts that are easy to skip — no hypothesis without a refutation test, no verdict without an
observation, no question closed as answered on one source.
