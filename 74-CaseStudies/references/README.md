# 74 — Case Studies · References

Annotated. Every source is grouped by what it is good for, not by type.

---

## 1. The primary sources — chapters that own the facts this chapter retells

This chapter is a synthesis. **Nothing below was measured here first**, except where marked, and when
a chapter disagrees with this one, **the chapter wins.**

| Chapter | Owns | Verified for this chapter |
|---|---|---|
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | §3.10.1 — the `/proc/cmdline` vs `getprop` forgery on the rooted Redmi, and the three-value synthesis at the end of that section | Checked. **Correction to my working notes:** the `orange` reading is on `/proc/cmdline`, **not** bootconfig, and **three** fields were forged, not two |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | §5.1 — `getprop` `green` against a TEE attestation reporting `verifiedBootState=Unverified`, `deviceLocked=false`, all-zero `verifiedBootKey` | Checked; quoted verbatim |
| [61-Fastboot](../../61-Fastboot/README.md) | §5.3 and `examples/measured-avd-boot-state.md` — the empty-string property and the bootconfig key inventory | Checked, **and re-run live**. Reproduced exactly |
| [59-radare2](../../59-radare2/README.md) | §5.4 the short-circuit truth table; §3.8 the `-O2` string leak | Checked. **Note:** measured on the **AVD** with AArch64 translation, not on physical hardware. Its §9.4 carries stale addresses — quote §5.4's `0x481c` / `0x48c0` |
| [18-ARM](../../18-ARM/README.md) | §5.4 — the inlining case, on a **physical** arm64 device (Android 13 / API 33) | Checked; the device contrast with 59 is deliberate and load-bearing |
| [58-IDA](../../58-IDA/README.md) | §11.4 — the `strings` check that "passed for exactly the wrong reason" | Checked. **This chapter refutes the generality of its `noinline` fix**; see §3.3.3 |
| [63-LSPosed](../../63-LSPosed/README.md) | §3.17 and §5.5 — the `/data/adb/lspd` result; `lab-01` holds the full three-vantage table | Checked, **and re-run live**. Reproduced. **One correction:** its "3 lines whose mount source is literally `magisk`" is two by source, three by substring |
| [37-RootDetection](../../37-RootDetection/README.md) | The `/system/xbin/su` vantage result and the wrong-`su` finding (`/debug_ramdisk/su` is Magisk's) | Checked, **and re-run live**. Reproduced |
| [64-Xposed](../../64-Xposed/README.md) | §8.2 the 1,141-hit substring audit; §8.3 the `vxp` signature | Checked; **not** re-run — a 237-APK corpus was out of budget |
| [48-Biometrics](../../48-Biometrics/README.md) | §8.3 — the grader that scored its own reference files backwards, twice | Checked. **Note:** the "43 apps" figure attaches to the *buggy* runs; the working sweep is **38** |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | §9.4 — the 17 MB application sweep | Checked. **Note:** `16,836 -> 168` is the whole-tree run; `15 of 17 HIGH rejected` is the app-scoped run. **Do not chain them** |
| [33-Storage](../../33-Storage/README.md) | §7.4 — 132 high-confidence hits, 132 false positives | Checked |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | §8.1 — twelve of fourteen with a pinning surface, four with a **pin value in the APK** | Checked. **Note:** "had a pin value" is a static claim, **not** "actually pinning" |
| [38-TamperDetection](../../38-TamperDetection/README.md) | The 18-of-18 self-signature claim corrected to 13-of-18 | Checked |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | The shell-versus-app property-visibility claim | **DIVERGED.** Re-running its own documented command gave shell 673 / app 633 / root 1055 against its published 1053 / 634. Raised in §3.5; **chapter 39 not edited** |

---

## 2. The method

| Source | Why |
|---|---|
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | Owns the method this chapter shows instances of: the hypothesis-refutation loop, the evidence ladder, and the H/P/R/E/O/V notation |
| [68's worked journal](../../68-ReverseEngineering/examples/worked-journal.md) | **The reference implementation of the form.** Eighteen entries, nine failures. Read it before writing your own |
| [68's `re-journal.py`](../../68-ReverseEngineering/scripts/re-journal.py) | Enforces the parts that are easy to skip — no hypothesis without a refutation test, no verdict without an observation |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Discovery technique, and a measured lesson this chapter leans on: one defect presenting three ways, two of them invisible to a campaign graded on exit codes |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | Runtime methodology, and the liveness rule — a void run and a clean negative produce identical reports |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Sweep methodology; its `lab-02-false-positive-gauntlet.md` scores you on correct **rejections**, the same way this chapter's CTF does |

---

## 3. The framework and the reporting

| Source | Why |
|---|---|
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS/MASTG identifiers. **This chapter deliberately does not reproduce identifiers it has not verified** — get them from 71 or from OWASP |
| [72-RealWorldFindings](../../72-RealWorldFindings/README.md) | The counterpart: finding classes, base rates, severity distributions. If you are tabulating, you want 72 |
| OWASP MASVS | The control framework. MASVS-RESILIENCE covers cases A, B, D, E, F; MASVS-CRYPTO and MASVS-STORAGE cover case C |
| OWASP MASTG | Test procedures, and worth reading critically — several published root-detection procedures are the exact checks case D shows cannot function |

---

## 4. AOSP source

Given at **file granularity**. This chapter does not cite line numbers: they move between releases,
and a wrong one is worse than none.

| Path | Relevance |
|---|---|
| `system/core/init/init.cpp` | First-stage init; reads `/proc/cmdline` and `/proc/bootconfig` |
| `system/core/init/util.cpp` | Command-line and bootconfig import — where `androidboot.X` becomes `ro.boot.X` |
| `system/core/init/property_service.cpp` | Property area ownership; write permission. Why `ro.` means "read-only after set", not "authentic" |
| `system/sepolicy/private/property_contexts` | Property-name-prefix to SELinux-type mapping — the mechanism behind case E's 37-name gap |
| `frameworks/base/core/java/android/os/SystemProperties.java` | The Java accessor every integrity check calls |
| `bionic/libc/bionic/system_property_*.cpp` | The native read; a domain that cannot read a type does not get the region mapped |
| `libcore/ojluni/src/main/java/java/io/File.java` | `exists()`, returning `boolean` — case D's root cause |
| `libcore/ojluni/src/main/java/java/io/UnixFileSystem.java` | `getBooleanAttributes` |
| `libcore/ojluni/src/main/native/UnixFileSystem_md.c` | The native side, where `errno` exists and is discarded |
| `system/core/fs_mgr/libfs_avb/` | AVB / vbmeta verification |

---

## 5. Official documentation

| Source | Why |
|---|---|
| Android Verified Boot | The four boot states. Note it documents four values; this chapter measured a **fifth** condition — absent |
| Android Keystore key attestation | The `rootOfTrust` structure: `verifiedBootState`, `deviceLocked`, `verifiedBootKey`. The non-forgeable answer in case A |
| `android.system.Os` / `ErrnoException` | The API that preserves what `java.io.File` discards. The fix for case D's detection code |
| Android Security Bulletins | Where to verify any CVE identifier before repeating it — see the warning in README §5.4 |
| LLVM optimisation passes | Interprocedural constant propagation, function specialisation, global dead-code elimination. Case C is about these, not about anything Android does |
| Android NDK — 16 KB page size guidance | Why `-Wl,-z,max-page-size=16384` is required, and why its absence produces a SIGSEGV with no diagnostic naming page size |

---

## 6. CVEs

**See README §5.4 and its warning.** Four widely-documented Android issues are listed there to
illustrate the *shape* of a public advisory. They were **not verified against the NVD or the Android
Security Bulletin in the session that produced this chapter**, and you must verify any identifier
before repeating it.

That is not excessive caution. [STYLE-GUIDE.md](../../STYLE-GUIDE.md) §5 requires that an uncertain
identifier be described as a class rather than invented, and stating the limit explicitly is part of
complying with it. **A fabricated CVE number is the single most damaging error a document like this
can contain**, because it is repeated by everyone downstream and traced by no-one.

**How to read an advisory**, which is the transferable part:

1. **The precondition** — what did the attacker need first? Almost every "critical" is gated on
   something the summary omits.
2. **The primitive** — a read, a write, a controlled free?
3. **The distance to impact** — how many further steps?
4. **The fix** — often the most informative part, because it names the missing invariant.
5. **What is not said** — advisories are negotiated documents; silence about exploitability is not
   evidence of inexploitability.

---

## 7. This chapter's own artefacts

| File | What it is |
|---|---|
| [`examples/replay-journal.md`](../examples/replay-journal.md) | The session log from writing this chapter. Eleven hypotheses, seven refuted, five dead ends, two bugs found in this chapter's own shipped files |
| [`examples/reproduction-log.md`](../examples/reproduction-log.md) | Raw commands and raw output for every measured claim, with an index mapping each claim to its verdict |
| [`examples/fold.c`](../examples/fold.c) | The independent fixture for case C. Compiles clean at `-O0` and `-O2` under `-Wall -Wextra`; reproduces the leak |
| [`scripts/vantage-diff.sh`](../scripts/vantage-diff.sh) | Root / shell / app comparison. The instrument that produced cases D and E. All five modes executed |
| [`scripts/case-replay.sh`](../scripts/case-replay.sh) | Replays the recorded measurements; emits REPRODUCED / DIVERGED / SKIPPED. Executed: 17 reproduced, 0 diverged |
| [`scripts/claim-ledger.py`](../scripts/claim-ledger.py) | Audits a written case study for the four defects. Self-test passes; run against this chapter's examples and 68's journal |

---

## 8. Related chapters

| Chapter | Relationship |
|---|---|
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | Owns the **method**; this chapter supplies worked instances |
| [72-RealWorldFindings](../../72-RealWorldFindings/README.md) | Owns **breadth and taxonomy**; this chapter owns depth and narrative |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Owns **discovery technique** |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Owns the **framework** and the identifiers |
| [73-Labs](../../73-Labs/README.md) | Owns standalone lab targets; this chapter's labs replay recorded investigations instead |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | What to do once case B has told you which decision to move |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | The same narrative form applied to a hostile sample rather than to an assessment |
| [51](../../51-DynamicAnalysis/README.md) / [52](../../52-StaticAnalysis/README.md) | Own the sweep and runtime methodologies these cases are instances of |

The link to `73-Labs` is a **forward reference by directory name**, which is this repository's
standing convention: the directory exists, the link resolves as soon as that chapter lands, and no
claim is made here about its state. Every other chapter linked on this page has a README today.

**Deliberately phrased so it cannot go stale.** A paragraph that enumerates which chapters are
finished is correct when written and decays silently as others ship — this repository accumulated
45 such false statements before the pattern was noticed, and several of them named three or four
chapters at once, so fixing the one you cared about left the neighbouring lies in place. If you
extend this file, **grep the whole sentence, not your own chapter number.**
