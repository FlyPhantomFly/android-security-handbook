# 38 — Tamper Detection · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure. Nothing here is a link dump.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives cross-references and history.
[07-AOSP](../../07-AOSP/README.md) covers navigation technique. **No line numbers appear anywhere in
this chapter** — file paths are stable across releases and line numbers are not.

### The signature APIs — the core of the chapter

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/content/pm/Signature.java` | You want to see that a `Signature` is a **certificate**, not a signature: DER bytes, `toByteArray()` returning a *copy*, and a 32-bit `hashCode()`. Also has a `Signature(String)` hex constructor, which explains a pattern you will meet in decompiled apps |
| `frameworks/base/core/java/android/content/pm/SigningInfo.java` | You are reading `hasMultipleSigners()` versus `hasPastSigningCertificates()` and want to see that the two branches read **different fields** — which is why calling the wrong accessor returns an empty array instead of an error |
| `frameworks/base/core/java/android/content/pm/SigningDetails.java` | The real structure: current signers, the rotation lineage, the signature scheme version, and `CertCapabilities` (the `flags: 17` in §3.2.3). **Was `PackageParser.SigningDetails` before Android 13** — look there in older trees |
| `frameworks/base/core/java/android/content/pm/PackageManager.java` | The flag constants. `GET_SIGNATURES = 0x40`, `GET_SIGNING_CERTIFICATES = 0x08000000`, and the `CERT_INPUT_*` values for `hasSigningCertificate` |
| `frameworks/base/core/java/android/content/pm/ApplicationInfo.java` | `FLAG_DEBUGGABLE = 1<<1`, and the rest of the flag word you will be printing in hex |
| `frameworks/base/core/java/android/content/pm/InstallSourceInfo.java` | The API 30+ replacement for `getInstallerPackageName`, with its three distinct names — initiating, originating, installing |

### The call path — app to `system_server` and back

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/app/ApplicationPackageManager.java` | **The concrete class an app actually holds.** `PackageManager` is abstract; hooking it silently does nothing. This is the single most useful practical fact in the whole reference list |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` | The `system_server` side of the Binder call |
| `frameworks/base/services/core/java/com/android/server/pm/ComputerEngine.java` | On modern trees, the read path that resolves the package and applies visibility filtering |
| `frameworks/base/services/core/java/com/android/server/pm/parsing/PackageInfoUtils.java` | **Where `GET_SIGNING_CERTIFICATES` is honoured.** Read the `signingInfo` branch and the legacy `signatures` branch side by side and the deprecation of `GET_SIGNATURES` explains itself: they are different code paths reading different fields |
| `frameworks/base/services/core/java/com/android/server/pm/Settings.java` | Reads and writes `/data/system/packages.xml` — the file that holds the certificate your app sees at runtime |
| `frameworks/base/services/core/java/com/android/server/pm/AppsFilter.java` | Package visibility filtering. Why a **peer** signature check silently stops working at `targetSdk` 30+ without a `<queries>` declaration |

### Install-time verification — what happened before your code ran

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/util/apk/ApkSignatureVerifier.java` | The descending scheme ladder (v4 → v3 → v2 → v1) and the "not found" versus "found but invalid" distinction that decides which error you see |
| `frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java` | Rotation and the proof-of-rotation lineage, verified at install |
| `frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV2Verifier.java` | The chunked digest that covers the whole file — the mechanism that **forces** a repackager to re-sign |
| `frameworks/base/core/java/android/util/apk/ApkSigningBlockUtils.java` | Finding an ID-value pair in the signing block. Useful when you meet an unknown block ID |
| `tools/apksig/` | The same logic in the form `apksigner` uses. When a device and `apksigner` disagree, read both |

### The native tiers

| Path | Open it when |
|---|---|
| `bionic/linker/linker_soinfo.cpp` | `soinfo::call_constructors()` — the walk over `.preinit_array` and `.init_array`. This is the T3 tier's mechanism |
| `bionic/linker/linker.cpp` | The `dlopen` path that invokes the constructors **before returning**. Confirms the T3-before-T2 ordering is structural, not conventional |
| `art/runtime/java_vm_ext.cc` | `JavaVMExt::LoadNativeLibrary()` — calls `android_dlopen_ext`, then `dlsym`s `JNI_OnLoad` and checks its returned JNI version. The T2 tier |
| `bionic/libc/bionic/` | The `ptrace`, `open`, `openat` wrappers. Confirms which syscall your architecture actually issues, which decides where a hook has to go |

### Kernel — Linux, not Android-specific

| Path | Open it when |
|---|---|
| `fs/proc/array.c` | Formats `/proc/<pid>/status`. `TracerPid` is resolved into the **reader's** PID namespace, which is why the number can differ between readers |
| `kernel/ptrace.c` | `ptrace_attach` / `ptrace_traceme`, and the one-tracer-per-task invariant that `PTRACE_TRACEME` self-attach depends on |
| `fs/proc/task_mmu.c` | Formats `/proc/<pid>/maps`. Generated on read — there is no cached copy to poison, which is why attackers intercept the read instead |

---

## Official Android documentation

| Link | Why |
|---|---|
| [Application signing](https://source.android.com/docs/security/features/apksigning) | The platform's own overview. Start here if the scheme versions are new to you |
| [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2) | The chunked whole-file digest. **The mechanism that makes runtime self-signature verification possible** |
| [APK Signature Scheme v3](https://source.android.com/docs/security/features/apksigning/v3) | Key rotation and the proof-of-rotation lineage. Read this before you hardcode one certificate hash |
| [`PackageManager`](https://developer.android.com/reference/android/content/pm/PackageManager) | Flag reference, and the deprecation notes on `GET_SIGNATURES` |
| [`SigningInfo`](https://developer.android.com/reference/android/content/pm/SigningInfo) | The four methods, and which is valid when |
| [`Signature`](https://developer.android.com/reference/android/content/pm/Signature) | Short page. Confirms it wraps a certificate |
| [`InstallSourceInfo`](https://developer.android.com/reference/android/content/pm/InstallSourceInfo) | The three install-source names, API 30+ |
| [`Debug`](https://developer.android.com/reference/android/os/Debug) | `isDebuggerConnected()` — the check that catches JDWP, which `TracerPid` provably does not |
| [Play Integrity API](https://developer.android.com/google/play/integrity) | The T4 tier. Read the *server* half, not the client half |
| [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts) | What `MEETS_DEVICE_INTEGRITY` and `PLAY_RECOGNIZED` actually assert. Essential before you write a server-side check |
| [Key and ID Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) | The hardware alternative to Play Integrity. [49-KeyStore](../../49-KeyStore/README.md) §3.7 covers the certificate extension field by field |
| [`apksigner`](https://developer.android.com/tools/apksigner) | `verify -v --print-certs` is the first command of every triage |
| [Debug your app](https://developer.android.com/studio/debug) | Background on JDWP, which is what question 5 of the FAQ is about |
| [Package visibility](https://developer.android.com/training/package-visibility) | Why peer checks need `<queries>` at `targetSdk` 30+ |

---

## OWASP

| Link | Why |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | The standard itself |
| [MASVS-RESILIENCE](https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/) | **RESILIENCE-2** (anti-tampering) and **RESILIENCE-4** (anti-dynamic-analysis) are this chapter. Note the category is explicitly *conditional* on a threat model that includes a compromised device — applying it to every app is a misreading, not a strict reading |
| [MASTG](https://mas.owasp.org/MASTG/) | The testing guide |
| [MASTG Android tests](https://mas.owasp.org/MASTG/tests/android/) | The anti-tampering and anti-dynamic-analysis tests. **A MASTG test tells you how to determine whether a control is present. "Absent" is a test result, not a severity** — see README §5.3 |

[71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) carries the full mapping across all categories.

---

## Tooling

| Tool | Why you would reach for it here |
|---|---|
| [Frida](https://frida.re/docs/android/) | The tracer in [`../scripts/which-check-fired.js`](../scripts/which-check-fired.js). **Always spawn (`-f`), never attach** — T2 and T3 have already run by the time you attach |
| [Objection](https://github.com/sensepost/objection) | Fast reconnaissance. `android hooking watch class_method … --dump-args` on `ApplicationPackageManager.getPackageInfo` |
| [jadx](https://github.com/skylot/jadx) | Reading the check. Search for **`134217728`** — jadx prints the flag in decimal. [56-JADX](../../56-JADX/README.md) also documents why the decompiled Java can disagree with the bytecode |
| [apktool](https://apktool.org/) | Smali, and the manifest. The only route to a static patch |
| [Ghidra](https://ghidra-sre.org/) | The native tiers. Start from `.init_array`, then `JNI_OnLoad`. [57-Ghidra](../../57-Ghidra/README.md) |
| [Android NDK](https://developer.android.com/ndk) | Building [`../examples/tamper_check.c`](../examples/tamper_check.c). The chapter's copy compiled clean with `aarch64-linux-android21-clang -O2 -Wall -Wextra` |
| `llvm-readelf` (ships with the NDK) | `--dyn-syms` to separate imports from exports; `-S` to find `.init_array`. **Parse, do not `strings`** — "imports `ptrace`" and "the word ptrace appears" are different claims |
| `apksigner`, `aapt2`, `d8`, `zipalign` | The whole no-Gradle build in [`../examples/build.sh`](../examples/build.sh) |
| `keytool` (JDK) | `-list -v | grep SHA256` gives the same value as `apksigner`'s certificate digest and as `sha256(Signature.toByteArray())`. Verify that equivalence once yourself |

---

## This chapter's own artefacts

| File | What it is for |
|---|---|
| [`../scripts/tamper-surface-map.py`](../scripts/tamper-surface-map.py) | **Run this first.** Maps the tamper surface by tier from a static APK. Parses DEX `string_ids` and the ELF dynamic symbol table properly. Grades every row STRONG or WEAK, because the first version matched 18 of 18 apps and was therefore useless |
| [`../scripts/which-check-fired.js`](../scripts/which-check-fired.js) | **Run this second.** Reports which check fired, what it saw, and where it lives. Deliberately does not bypass, except for one opt-in `BLOCK_EXIT` |
| [`../examples/build.sh`](../examples/build.sh) | No-Gradle, no-network build of the detector app, plus `--repack` which strips the signature and re-signs with a second key. Builds out of tree; **never writes an APK or a keystore into the repository** |
| [`../examples/repack-detector/IntegrityGate.java`](../examples/repack-detector/IntegrityGate.java) | Seven checks that return a **report**, not a boolean, with `UNKNOWN` as a first-class verdict |
| [`../examples/LayeredTamperDetector.java`](../examples/LayeredTamperDetector.java) | The same catalogue written the way a competent defender would: no boolean, several call sites, consequence separated from detection |
| [`../examples/ServerVerifiedIntegrity.java`](../examples/ServerVerifiedIntegrity.java) | The correct design, plus all three anti-patterns as compilable methods with the test that proves each |
| [`../examples/tamper_check.c`](../examples/tamper_check.c) | The native tier: six checks in `JNI_OnLoad`, one in an `.init_array` constructor |

---

## Related chapters

| Chapter | Why |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | **Read §6.5 before this chapter's §3.2.** The signing schemes, the APK Signing Block, `parse_signing_block.py` |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The DEX layout the mapper parses. Also ships `dex-diff.py`, an index-table diff for detecting repackaging |
| [13-ART](../../13-ART/README.md) | The execution model these checks live in; `dump-loaded-dex.js` for a packed app |
| [16-JNI](../../16-JNI/README.md) | The `JNI_OnLoad` boundary and why JNI names survive R8 |
| [17-Libraries](../../17-Libraries/README.md) | `.init_array`, the linker, and the tier below `JNI_OnLoad` |
| [18-ARM](../../18-ARM/README.md) | Patching native checks — and the measured case where a patch provably works against a function the compiler inlined and nothing calls |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Verified Boot and the platform side of device integrity |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why re-signing breaks signature-level permissions and sibling-app trust |
| [23-Permissions](../../23-Permissions/README.md) | `signature` protection level — the other thing your certificate controls |
| [25-Binder](../../25-Binder/README.md) | Why the caller identity on `getPackageInfo` is unforgeable while the returned data is not |
| [32-Manifest](../../32-Manifest/README.md) | `android:debuggable`, and `<queries>` for peer checks |
| [34-Cryptography](../../34-Cryptography/README.md) | DER, SHA-256, and JWS — the format Play Integrity verdicts arrive in |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | The sibling control, and what bites you after you repackage to defeat it |
| [37-RootDetection](../../37-RootDetection/README.md) | The environment half. **"Patch both or neither."** Its native checks are its own; this chapter does not duplicate them |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What survives R8, and what obfuscation does and does not add to these checks |
| [49-KeyStore](../../49-KeyStore/README.md) | Hardware key attestation, §3.7 — the alternative to Play Integrity |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Sweep discipline. Leads versus findings, measured three separate ways |
| [53-Frida](../../53-Frida/README.md) | How the hooks work, and why gadget mode costs you a signature |
| [56-JADX](../../56-JADX/README.md) | Reading the decompiled check, and why the decompiler can silently disagree with the bytecode |
| [57-Ghidra](../../57-Ghidra/README.md) | Recognising these shapes in a native library |
| [60-ADB](../../60-ADB/README.md) | The device-side commands used throughout §7 |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The full MASVS mapping |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The triage one-liners |
| [79-Glossary](../../79-Glossary/README.md) | `TracerPid`, `/proc/<pid>/status`, and the rest |

Referenced in the text as plain names when this chapter was completed, and **all now written**:
[39-EmulatorDetection](../../39-EmulatorDetection/README.md),
[50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md),
[51-DynamicAnalysis](../../51-DynamicAnalysis/README.md),
[65-Hooking](../../65-Hooking/README.md),
**[67-BypassingProtections](../../67-BypassingProtections/README.md)**,
[68-ReverseEngineering](../../68-ReverseEngineering/README.md),
[69-MalwareAnalysis](../../69-MalwareAnalysis/README.md),
[70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md).

> **67 owns the bypass methodology and the adversarial back-and-forth. This chapter owns the
> controls.** Where §6.6 and §7.3 show a neutralisation, it is there so you can *confirm a mechanism*,
> not as a playbook.

---

## Papers, talks and further reading

Deliberately short. Most published material on this topic is either vendor marketing or a blog post
that reprints the same twelve checks without pricing any of them. Prefer primary sources.

- **The MASTG resilience tests** are the best-maintained public catalogue, and unusually for this
  field they are honest about what each test does and does not establish.
- **Frida's own documentation** on the gadget is the clearest statement of the repackaging trade-off:
  gadget mode requires re-signing, and re-signing is exactly what this chapter's core control
  detects. There is no third option that avoids both.
- **The AOSP commit history on `SigningDetails`** is worth skimming if you want to understand why
  rotation is shaped the way it is. The capability flags exist because rotation had to preserve
  behaviour that was already depending on certificate identity — shared user IDs, signature
  permissions, installed-data access.

If you find yourself reading a source that lists checks without stating what each proves and what it
costs to defeat, close it. That pairing is the only thing that makes this material useful, and its
absence is a reliable signal that the author has not done the work.
