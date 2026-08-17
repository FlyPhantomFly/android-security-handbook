# 73 — Labs · References

Annotated. Every entry says what it is *for*, not merely what it is.

> **Note on the four generated files below.** They carry a `GENERATED FILE` banner and are rebuilt by
> [`../scripts/build-lab-index.py`](../scripts/build-lab-index.py). **Do not edit them by hand** — the
> next run overwrites you. Fix the generator, then regenerate.

---

## 1. Generated in this directory

| File | What it answers | Rebuild |
|---|---|---|
| [`lab-index-by-chapter.md`](lab-index-by-chapter.md) | "What labs does chapter NN have?" | `python3 -B scripts/build-lab-index.py --by chapter` |
| [`lab-index-by-difficulty.md`](lab-index-by-difficulty.md) | "I have ninety minutes and want to be stretched, not stopped" | `--by difficulty` |
| [`lab-index-by-requirement.md`](lab-index-by-requirement.md) | "What do I need to install, and which labs prove it?" — **with the evidence line for every claim** | `--by requirement` |
| [`learning-paths.md`](learning-paths.md) | "I have a goal and a deadline. What order?" | `--by path` |

All four emit chapter links as `../../NN-Chapter/…`, because a file in this directory is **two**
levels below the repository root. Verify by resolving, never by reading:

```bash
# host — from 73-Labs
python3 -B scripts/build-lab-index.py --verify-links
```

```
links=410 broken=0
```

---

## 2. This chapter's own material

| File | Use it for |
|---|---|
| [`../README.md`](../README.md) | The chapter. Environment measurements are §3.6–§3.9 |
| [`../cheatsheet.md`](../cheatsheet.md) | Every command on one page, plus the trap table |
| [`../mindmap.md`](../mindmap.md) | The whole chapter as one map |
| [`../faq.md`](../faq.md) | 23 questions, including the ones people feel stupid asking |
| [`../scripts/build-lab-index.py`](../scripts/build-lab-index.py) | The generator. `--why`, `--stats`, `--verify-links` |
| [`../scripts/lab-env-probe.py`](../scripts/lab-env-probe.py) | Probes host and device; matches against the corpus |
| [`../scripts/lab-doctor.sh`](../scripts/lab-doctor.sh) | Six-step triage when a lab does not reproduce |
| [`../examples/lab-template.md`](../examples/lab-template.md) | The skeleton for a new lab |
| [`../examples/evidence-ledger.md`](../examples/evidence-ledger.md) | Claim tracking with a mandatory vantage column |
| [`../examples/divergence-report.md`](../examples/divergence-report.md) | The short form for "it did not reproduce" |
| [`../examples/build-chain-target.sh`](../examples/build-chain-target.sh) | Out-of-tree APK build, no Gradle, no network |
| [`../examples/chain-target/`](../examples/chain-target/) | Sources for the Lab 02 / Lab 04 target |

---

## 3. Repository documents this chapter depends on

| Document | Why it matters here |
|---|---|
| [STYLE-GUIDE.md](../../STYLE-GUIDE.md) | The binding contract. §4 lists the required files; §4a defines the reference-chapter shape that this chapter is **not** held to |
| [`76-CheatSheets/scripts/lint-commands.py`](../../76-CheatSheets/scripts/lint-commands.py) | The command-shape linter. This chapter is gated on **0 ERROR** from it |
| [`76-CheatSheets/scripts/check-anchors.py`](../../76-CheatSheets/scripts/check-anchors.py) | The link-and-anchor checker. This chapter is gated on **0 broken file paths and 0 broken anchors** from it |

The checker defects and encoding traps worth knowing before you add a lab — a BOM is valid UTF-8 and
survives every decode; `Get-Content -Raw` paired with `Set-Content -Encoding UTF8` corrupted 11 files
in this repository; raw C0 control bytes make a file register as binary and invisible to `grep` — are
written up in [README §8.2](../README.md#82-the-checks-this-repository-runs-on-itself). The measured
claims that contradict the textbook live in the chapters that own them, each with its device and
method; [75-InterviewQuestions/references](../../75-InterviewQuestions/references/README.md) indexes
the strongest of them.

---

## 4. The two aggregator precedents

This chapter is the third attempt in this repository at the same structural problem: what does a
chapter do when its subject is *all the other chapters*?

| Chapter | Aggregates | What it did that this chapter copied |
|---|---|---|
| [75-InterviewQuestions](../../75-InterviewQuestions/README.md) | Every chapter's §10 — over 1,300 questions | Generated its index mechanically and added a meta-layer no single chapter could hold, rather than concatenating. **It also produced the relative-depth defect that this chapter's `--verify-links` exists to prevent** |
| [76-CheatSheets](../../76-CheatSheets/README.md) | Every chapter's condensed material | Held to the STYLE-GUIDE §4a reference-chapter contract, and ships the linter that gates this chapter |
| [78-Diagrams](../../78-Diagrams/README.md) | Every chapter's diagrams | Same contract; the visual counterpart to this chapter's navigational one |

> **The precedent worth stating plainly.** 75's generated index emitted `../NN-Chapter/README.md`
> from a file in `references/`, which resolves inside `75-InterviewQuestions/` and is silently
> wrong. It produced **1,495 broken links**, hidden for months by a checker exemption for "forward
> references to unwritten chapters" that never re-tested whether the chapter was still unwritten.
> Two lessons, and the second is the general one: **resolve links rather than reading them**, and
> **every exemption needs an expiry condition the tool evaluates**, not a comment explaining when it
> applies.

---

## 5. Chapters whose labs this chapter's own labs cross

Lab 02 and Lab 04 are cross-chapter by construction. These are the chapters they draw on, and each
is where you should go for depth on the mechanism the lab only exercises.

| Chapter | What the lab borrows |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | What is inside the file |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | Reading constants out of a DEX |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why a uid is the boundary |
| [23-Permissions](../../23-Permissions/README.md) | `protectionLevel`, and why `signature` decides everything |
| [24-IPC](../../24-IPC/README.md) / [25-Binder](../../25-Binder/README.md) | Why `getCallingUid()` is not always the caller |
| [26-Intent](../../26-Intent/README.md) | Attacker-controlled extras |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Exported providers and ignored selections |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | Broadcast dispatch, and the output that proves nothing |
| [30-Activities](../../30-Activities/README.md) | Task model, and a two-app build worth adapting |
| [32-Manifest](../../32-Manifest/README.md) | The attack-surface declaration, read as integers |
| [33-Storage](../../33-Storage/README.md) | Where the data actually is |
| [34-Cryptography](../../34-Cryptography/README.md) | Why a repeating-key XOR is not encryption |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The stage Lab 02 hands off *into* |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The stage Lab 02 hands off *out of* |
| [56-JADX](../../56-JADX/README.md) | Decompilation, and where it disagrees with `dexdump` |
| [60-ADB](../../60-ADB/README.md) | Every device command runs through it |
| [62-Magisk](../../62-Magisk/README.md) | The root the `su`-form section is about |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The vocabulary the report is written in |
| [72-RealWorldFindings](../../72-RealWorldFindings/README.md) | Severity, defended under pushback |
| [74-CaseStudies](../../74-CaseStudies/README.md) | The reference implementation of a divergence written up properly |

---

## 6. AOSP source

File paths only. Line numbers move and are never quoted here.

| Path | Relevance |
|---|---|
| `frameworks/base/services/core/java/com/android/server/pm/InstallPackageHelper.java` | Install-time checks, including the minimum-`targetSdk` gate |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerShellCommand.java` | `pm install` and `--bypass-low-target-sdk-block` |
| `frameworks/base/core/java/android/content/pm/PackageManager.java` | The `INSTALL_FAILED_*` constants — read it to see the three refusals are genuinely different codes |
| `frameworks/base/core/java/android/os/Binder.java` | `getCallingUid()`, and what "current incoming transaction" means |
| `frameworks/base/services/core/java/com/android/server/am/BroadcastQueue.java` | Broadcast dispatch; holds the sender identity and does not pass it on |
| `frameworks/base/core/java/android/app/ActivityThread.java` | Where a broadcast reaches the app's main thread, outside the transaction |
| `system/extras/su/su.c` | The AOSP `su`. Its first positional argument is a **uid**, which is the whole `su -c` story |

---

## 7. Official documentation

| Source | Use |
|---|---|
| Android Developers — *Command-line tools* (`adb`) | The transport every device command uses |
| Android Developers — *ADB Shell Commands* (`am`, `pm`, `dumpsys`, `content`) | The four commands Lab 02 is built from |
| Android Developers — *Support 16 KB page sizes* | Why native binaries need `-Wl,-z,max-page-size=16384` on this AVD |
| Android Developers — *Permissions on Android* | `protectionLevel` values, including the integers |
| Android Developers — *Run apps on the Android Emulator* | AVD creation and the properties the probe reads |
| Android Developers — *Application Signing* | Why a fresh debug key causes `INSTALL_FAILED_UPDATE_INCOMPATIBLE` |

---

## 8. OWASP

| Identifier | Relevance |
|---|---|
| OWASP MASVS v2 | The control groups mapped in [README §5.5](../README.md#55-owasp-masvsmastg-mapping-for-the-corpus) |
| OWASP MASTG | The testing process Lab 02 follows, and its evidence standards |
| OWASP MASTG — testing-process chapters | The closest external analogue to this chapter's static→dynamic→report chain |

> **⚠️ Warning.** MASVS identifiers changed materially between v1 and v2. Cite the version you used,
> and do not translate an old identifier into a new one from memory.

---

## 9. Tools this chapter names

| Tool | Why it appears |
|---|---|
| `adb` | Everything device-side |
| Android SDK build-tools (`aapt2`, `d8`, `zipalign`, `apksigner`, `dexdump`) | The out-of-tree build, and reading a binary manifest without third-party tools |
| JDK (`javac`, `keytool`) | Compiling the target and generating its key |
| Android NDK | 50 labs in the corpus, and the 16 KiB page-size flag |
| `jadx` | Decompilation. Convenient, not required by this chapter's labs |
| `apktool` | Resource decoding. **Absent on the measured setup**, and the labs route around it |
| Frida | 128 labs in the corpus; **the largest single block on the measured setup** |
| Python 3 | The two generators, and a portable substitute for `zip`/`unzip` |

---

## 10. Related chapters

| Chapter | Relationship |
|---|---|
| [00-Introduction](../../00-Introduction/README.md) | **Installs** the toolchain this chapter measures. Its lab 01 comes first |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | Owns the dynamic stage; this chapter owns the handoff into it |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Owns the static stage; this chapter owns the handoff out of it |
| [53-Frida](../../53-Frida/README.md) | The capability that blocks the most labs here |
| [60-ADB](../../60-ADB/README.md) | The transport under every measurement |
| [62-Magisk](../../62-Magisk/README.md) | Root, and the `su` form question |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Report vocabulary |
| [72-RealWorldFindings](../../72-RealWorldFindings/README.md) | Severity under pushback |
| [74-CaseStudies](../../74-CaseStudies/README.md) | Divergence, done properly, six times |
| [75-InterviewQuestions](../../75-InterviewQuestions/README.md) | The same aggregator problem, solved for §10s |
| [76-CheatSheets](../../76-CheatSheets/README.md) | Condensations, and the linter gating this chapter |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | Commands without the surrounding method |
| [78-Diagrams](../../78-Diagrams/README.md) | Diagrams, aggregated |
| [79-Glossary](../../79-Glossary/README.md) | Terms used without definition here |
| [80-Appendix](../../80-Appendix/README.md) | Points here for the lab index |
