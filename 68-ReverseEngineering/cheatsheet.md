# 68 — Reverse Engineering · Cheat Sheet

> Printable. No prose. See [README.md](README.md) for why each of these works.

---

## The loop

```
Stage 0  QUESTION    one sentence, in a file: answerable / bounded / falsifiable
Stage 1  ACQUIRE     pm path -> EVERY apk. hash it. record the version
Stage 2  TRIAGE      20 min, timed, NO method bodies
Stage 3  FUNNEL      static branch + dynamic branch -> intersect and diff
Stage 4  HYPOTHESIS  H / P / R written BEFORE the experiment -> cheapest decisive
Stage 5  CORRELATE   two independent sources, or it is a lead
Stage 6  STOP        answer + 2 sources + what would have changed your mind + residue
Stage 7  WRITE UP    claim / evidence+tiers / limits / impact -- limits BEFORE impact
```

There is no arrow from Stage 3 to Stage 7.

---

## Evidence tiers

| Tier | What | Establishes | Cost |
|---|---|---|---|
| 1 | Inference | Nothing. A reason to look | free |
| 2 | Artefact shape — name, string, symbol | The file contains X | seconds |
| 3 | Decompiled code — jadx Java, Ghidra C | A tool's reconstruction | minutes |
| 4 | Encoding — Smali, disassembly, bytes | What the file says | minutes–hours |
| 5 | Observed execution | What it did, this session | minutes |
| 6 | Controlled experiment, both directions | Causation | hours |

Tiers 1–3: believe provisionally. Tiers 4–6: write down.

---

## Question states

```
Open -> Investigating -> Supported -> Answered      (2 independent sources)
                      -> Blocked                    (missing capability)  <- a RESULT
                      -> Deferred                   (cost > value)        <- a RESULT
```

`Supported` is not terminal. Blocked and Deferred go in the report with the reason.

---

## The first ten commands

```bash
adb -s $S shell pm path <pkg>                                    # 01 EVERY apk
sha256sum base.apk; aapt2 dump badging base.apk | grep -E 'package: name|versionName'
apksigner verify --print-certs base.apk | head -5                # 03 signer
unzip -l base.apk | grep -cE 'classes[0-9]*\.dex'                # 04 code volume
unzip -v base.apk | grep 'lib/' | head -20                       # 05 libs + compression
aapt2 dump badging base.apk | sed -n 's/^package: name=.\([^.]*\.[^.]*\).*/\1/p'   # 06 prefix
unzip -l base.apk | grep -E 'classes\.dex'                       # 07 packed?
python3 -B scripts/boundary-map.py base.apk --summary            # 08 native surface
jadx -d out base.apk 2>&1 | tail -3                              # 09 did it complete?
grep -rc 'Method not decompiled\|JADX ERROR' out/sources | awk -F: '$2>0' | wc -l  # 10 refusals
```

---

## Triage sheet — 8 questions, 20 minutes, no method bodies

| # | Question | Changes |
|---|---|---|
| 1 | How big is the code really? | Time estimate, by an order of magnitude |
| 2 | Obfuscated, and how? | Whether names are evidence |
| 3 | Packed? | Whether the artefact is the program |
| 4 | How much is native? | Which toolchain you live in |
| 5 | Splits / downloaded modules? | Whether you have the program |
| 6 | App's own package prefix? | Your best noise filter |
| 7 | Resists analysis? | Whether dynamic is available |
| 8 | Which third-party SDKs dominate? | What you stop reading |

---

## Ranking candidates — distance to the question

```
1  on a path from an entry point named in the question
2  reads/writes the state the question is about
3  sits at a trust boundary the question crosses
4  name matches the question's vocabulary     <- weakest; obfuscation destroys it
```

---

## Native call sites — the 40-second experiment

```bash
# MANDATORY (@plt)? -- PLT calls render as <name@plt> and a bare pattern MISSES them
llvm-objdump -d lib.so | grep -cE 'bl.*<fn(@plt)?>'

# corroborate EVERY zero -- does not depend on getting a regex right
llvm-objdump -d lib.so | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

Measured on the fixture at `-O0`: `iv_derive_seed` scores **0** bare, **1** with `(@plt)?`.

---

## Native triage commands

```bash
llvm-nm -D --defined-only lib.so | grep ' T '            # what a symbol tool sees
llvm-nm -S --size-sort -D --defined-only lib.so | tac    # biggest functions first
llvm-nm -D -u lib.so                                     # what it needs from outside
llvm-readelf -d lib.so | grep -E 'NEEDED|SONAME'
llvm-readelf -S lib.so | grep -E 'text|rodata|data|bss|init_array'
strings -a lib.so | grep -E '\{.*\}'                     # flag-shaped -> tier 2 ONLY
llvm-objdump -d lib.so | sed -n '/<fn>:/,/^$/p'          # one body
llvm-objdump -d lib.so | sed -n '/<fn>:/,/^$/p' | grep -E 'cmp|movk|mov.*#'   # inlined checks
```

**When a function you expect does not exist, look for its constant.** Inlining destroys names, not
constants.

---

## The managed/native boundary

| Binding | Mechanism | Visible statically? |
|---|---|---|
| Discovery | ART looks up the mangled symbol on first call | **Yes** |
| Explicit | `RegisterNatives(env, cls, {name,sig,fnPtr}[], n)` | **No** — fnPtr can be static/stripped |

**Measured, 18 real APKs:** 8,140 declared `native`, **1,049 (12.9%)** symbol-resolvable, 2,552
`Java_*` exports. 4 APKs with zero matches; 3 declaring 480/618/331 methods with **no arm64 `.so`** in
`base.apk`.

```bash
python3 -B scripts/boundary-map.py base.apk --summary      # triage line
python3 -B scripts/boundary-map.py base.apk --unresolved   # the RegisterNatives target list
python3 -B scripts/boundary-map.py base.apk --json         # CI baseline
python3 -B scripts/boundary-map.py --explain               # the 4 causes it CANNOT distinguish
frida -D $S -f <pkg> -l scripts/boundary-confirm.js        # runtime truth (slot 215)
```

### Four causes of an unresolved method — never pick one without evidence

```
1  explicit binding (RegisterNatives)
2  library is in a split / downloaded / not pulled
3  different ABI
4  class never loaded
```

### The three piles

| Pile | Meaning | Action |
|---|---|---|
| Agreed | Declared and observed binding | Start here |
| Static-only | Declared, never ran | Why? Unexercised / dead / decoy |
| Runtime-only | Ran, not in your artefact | **Fix your acquisition** |

---

## Crossing routes, cost order

| Route | Cost | Tier | Works when |
|---|---|---|---|
| Mangled symbol lookup | seconds | 2 | Discovery binding, symbol present |
| Hook `RegisterNatives` | minutes | **5** | Process runs under instrumentation |
| Read `ArtMethod` | minutes | 5 | Root + Frida |
| Find `JNI_OnLoad`, type the array | hours | 4 | Static only |

JNI mangling: `/` → `_`, `_` → `_1`, `;` → `_2`, `[` → `_3`, other → `_0` + **four** hex digits
(`$` → `_00024`).

---

## Runtime

```bash
frida -D $S -f <pkg> -l script.js -o out.txt    # -D ALWAYS. -f, not attach
python3 -c "import frida; print(frida.get_usb_device())"   # check what -U would pick
```

| Trap | Reality |
|---|---|
| `-U` with 2 devices | Picks the **first enumerated** — here, an emulator, not the phone |
| `adb` with 2 devices | Fails loudly. Better behaviour than Frida's |
| Frida `-o` capture | **Dropped 19 lines to buffering.** Read the in-process counter |
| Hook did not fire | ART inlining / wrong classloader / class not loaded / did not run / died |
| Zero result | **Liveness-check first**: same script, known-positive target |

---

## Liveness — before any negative result

```
1  Did the instrument install?      print unconditionally at install time
2  Does it fire on a known positive? run it against a target where the signal is certain
3  Was the target alive?             a vanished pid gives identical silence
```

A void run and a clean negative produce identical reports.

---

## Data flow, when control flow will not connect

| Approach | Backtrace? | Cost |
|---|---|---|
| Read-back polling | No | trivial |
| `MemoryAccessMonitor` | Yes | page-granular, noisy, slow |
| Hardware watchpoint | Yes | limited count |
| Java field hooks | Yes | managed side only |

```bash
frida -D $S -f <pkg> -l scripts/dataflow-watch.js    # edit the CONFIG block first
```

Producer writes an address; consumer reads it; no call edge. Branches are what the pattern defeats.

---

## The four ways a tool lies

| Mode | Looks like | Check | Measured |
|---|---|---|---|
| Refusal | It says it failed | Count the tree, not the summary | jadx: 61 reported, **2,104** real |
| Silent wrongness | Clean, wrong | Corroborate one tier lower | Java says 100, bytecode says 105 |
| Scope error | Right answer, wrong question | What did it consume? | pinning "bypassed" on an app with no network code |
| Self-agreement | Matches everything | Test against a known negative | 18/18 → **13/18** after hardening |

**If a detector agrees with you about every sample, suspect the detector.**

---

## Absence — the five checks (56-JADX)

```
1  Did decompilation complete?      class count in vs files out
2  What was refused?                a refused body is not in the Java
3  Code loaded dynamically?         DexClassLoader / InMemoryDexClassLoader / encrypted asset
4  Is it native?                    `native` declarations, System.loadLibrary
5  Every split APK?                 pm path
```

Also: grepping an APK for `FLAG_SECURE` has a **true-positive rate of zero** — `javac` folds `0x2000`,
only `const/16 v0, #int 8192` survives (47-Authentication).

---

## Obfuscation vs the ladder

| Technique | Tier hit | Survives |
|---|---|---|
| Renaming | 2 destroyed | Structure, call graph, 4–6 |
| String encryption | 2 destroyed | Decryptor runs — tier 5 recovers it |
| Control-flow flattening | 3 degraded | 4 unchanged; 5 shows the real path |
| Reflection / API hiding | 3 + static call graph | 5 sees the real call |
| Packing | 2–4 destroyed for the artefact | Real DEX in memory — tier 5 |
| Native migration | Moves the question | The crossing applies |

**Under obfuscation, lead with tier 5.** Kotlin metadata: 19 APKs, 316k classes — 10 carried none,
one carried **1,393 empty shells**, **zero wholesale recovery**. Property names survive structurally.

---

## Note discipline

| Prefix | Means | Evidence |
|---|---|---|
| `X_` | Guess | tier 1–2 |
| (none) | Supported | tier 3–4 |
| `K_` | Known | tier 5–6 |

```
H  hypothesis (could be false)
P  prediction if true
R  refutation if false      <- write BEFORE the experiment
E  experiment
O  observation (what you SAW, not what you concluded)
V  verdict: refuted | supported | inconclusive
```

```bash
python3 -B scripts/re-journal.py init --target <pkg> --sha256 <h> --version <v> --device <serial>
python3 -B scripts/re-journal.py ask "..."
python3 -B scripts/re-journal.py hypothesise Q1 --claim "..." --predict "..." --refute "..."
python3 -B scripts/re-journal.py observe H1 --experiment "..." --observed "..." --tier 4
python3 -B scripts/re-journal.py verdict H1 refuted
python3 -B scripts/re-journal.py residue "..." --kind structural
python3 -B scripts/re-journal.py close Q1 answered --answer "..." --source "..." --source "..."
python3 -B scripts/re-journal.py status
python3 -B scripts/re-journal.py report
python3 -B scripts/re-journal.py selftest
```

Refuses: a hypothesis with no refutation test; a verdict with no observation; `answered` on one
source.

---

## Time boxes

| Unit | Box | At the boundary |
|---|---|---|
| Experiment | 15 min | Is it decisive? |
| Hypothesis | 1 hour | Have I tried to refute it? |
| Question | half a day | Is it bounded? Would a partial answer serve? |
| Target | the engagement | What is the residue? |

**Understand vs predict:** understand only if you must reproduce it off-device, rate the algorithm,
or write a signature. Otherwise predict — borrow the routine on-device.

---

## Stopping rule

```
[ ] state the answer in ONE sentence
[ ] name TWO independent sources
[ ] name what would have changed your mind
[ ] say what you did NOT look at
```

---

## The residue

| Structural blind spot | Measured |
|---|---|
| Runtime-registered receivers | **299/431 actions (69%)** have no manifest receiver |
| `RegisterNatives` bindings | **87.1%** of the boundary |
| Splits / downloaded modules | 7 APKs for Chrome; 334 KB stub for one app |
| Server-side logic | Never in the client |
| Feature-flagged paths | 13-environment enum; 12 never seen in a proxy |
| Methods jadx refused | **2,104** in one APK |
| Properties visible to an app | **~638** to `untrusted_app` vs **~678** to `shell` vs **~1,062** to root |

---

## Honest severity

| Observation | Honest rating |
|---|---|
| "Can be decompiled" | **Not a finding** |
| "Root detection bypassed" | **Not a finding** — report what it reached |
| "Obfuscation is weak" | Informational |
| "Hard-coded key-shaped string" | Depends entirely on the key |
| "400 unmapped native entry points" | Informational + **High methodology risk** |
| "Client-side entitlement, both directions" | As high as the entitlement |

**Rate the consequence, not the technique.**

---

## Environment traps

| Symptom | Cause |
|---|---|
| `remote secure_mkdirs failed` | Git Bash rewrote the device path. `MSYS_NO_PATHCONV=1`, **scoped to adb only** |
| Build breaks after fixing that | Windows clang **needs** the conversion. Do not export globally |
| `su: invalid uid/gid '-c'` | Rooted; its `su` takes `su 0 <cmd>` |
| `dexdump` `Failed anonymous mmap` | Cannot read DEX inside an APK on Windows. Extract `classes*.dex` first |
| `unable to locate Android dynamic linker` | Vendor blocks `execve` in `/data/local/tmp`; run via `/system/bin/linker64` |
| `INSTALL_FAILED_USER_RESTRICTED` | `adb push` then `su -c 'pm install -r ...'` |

---

## Memorable figures

| Figure | What |
|---|---|
| **12.9%** | Native boundary resolvable by symbol, 18 APKs |
| **8,140 / 1,049** | Declared native / symbol-resolvable |
| **323 → 509** | Chrome: declared in `base.apk` → bound at runtime |
| **7** | APKs Chrome ships |
| **78 / 509** | `RegisterNatives` calls / methods bound, 3 identical runs |
| **61 → 2,104** | jadx reported errors → real refusals |
| **15 of 17** | HIGH-band static hits rejected by hand |
| **132 / 132** | High-confidence hits / false positives |
| **18/18 → 13/18** | Detector before and after hardening |
| **0** | True-positive rate of grepping for `FLAG_SECURE` |
| **7 of 9** | Hypotheses refuted while writing this chapter |
