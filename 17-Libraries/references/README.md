# 17 — Libraries · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure instead of reading a list of links.

The chapter's own [§14](../README.md#14-references) lists the canonical sources. This file is the
working set: the things you actually open during an assessment, grouped by the question that sends
you there.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives you cross-references, blame and
history. [07-AOSP](../../07-AOSP/README.md) covers the navigation technique.

### How a native library gets loaded — the path to trace at least once

| Path | Open it when |
|---|---|
| `libcore/ojluni/src/main/java/java/lang/Runtime.java` | You want the top of the chain: what `System.loadLibrary` actually does before it becomes native |
| `art/runtime/native/java_lang_Runtime.cc` | The JNI implementation behind that — where the ClassLoader is consulted to decide *which namespace* the library may load from |
| `art/runtime/java_vm_ext.cc` | `LoadNativeLibrary`: the function that calls `dlopen` and then looks up and calls `JNI_OnLoad`. **The single most useful file for understanding load ordering** |
| `libnativeloader/` — historically `system/core/libnativeloader/`, moved under `art/` in later releases | The ClassLoader-to-linker-namespace mapping. Open it when an app can load one library and not another and you need to know why |
| `bionic/linker/linker.cpp` | `dlopen` itself: mapping, relocation, RELRO, dependency resolution |
| `bionic/linker/linker_soinfo.cpp` | `call_constructors` — the function that runs `.init_array`. This is the code that makes lab 04 true |
| `bionic/linker/linker_namespaces.cpp` | Namespace isolation, enforced from Android 7.0. Why an app cannot `dlopen` an arbitrary platform `.so` |
| `bionic/linker/linker_main.cpp` | Process startup before `main`, and what is already mapped when your instrumentation gets control |
| `bionic/libdl/libdl.cpp` | The thin `dlopen`/`dlsym`/`dlerror` shims apps actually call |
| `frameworks/base/core/jni/` | `libandroid_runtime` — the framework's own JNI layer, and a reference for what well-formed JNI looks like |

**On device**, two files answer questions the tree cannot:

```bash
# adb shell — exactly which platform libraries an ordinary app may dlopen
cat /system/etc/public.libraries.txt
ls /system/etc/public.libraries*.txt

# adb shell — which Mainline modules are installed, and at what version
cmd package list packages --apex-only
ls /apex/
```

### Where the interesting platform libraries live

| Path | Open it when |
|---|---|
| `external/boringssl/` | You need to know what a BoringSSL symbol means, or whether a function exists in the platform's copy |
| `external/conscrypt/` | TLS behaviour, provider registration, the CA store |
| `external/sqlite/` | The version Android ships, and the build flags it ships with |
| `external/skia/` | Image decoders — the parsers that take adversary-chosen bytes on the platform side |
| `frameworks/av/media/` | The media framework and extractors; the architecture the Stagefright response produced |
| `system/apex/` | APEX packaging and mounting, for the Mainline story |

---

## Official documentation

| Resource | Why you would open it |
|---|---|
| [NDK guides](https://developer.android.com/ndk/guides) | Building the native code in this chapter's labs, and understanding what a normal NDK build produces so that an abnormal one stands out |
| [`extractNativeLibs` and APK size](https://developer.android.com/topic/performance/reduce-apk-size) | Why some apps map `.so` files straight out of the APK and others extract them at install — it changes what `/proc/<pid>/maps` shows you |
| [Linker namespaces / private API restrictions](https://source.android.com/docs/core/architecture/vndk) | An app fails to load a library on Android 7+ and you need the reason |
| [Modular System Components (Mainline)](https://source.android.com/docs/core/ota/modular-system) | Deciding whether a platform library is the OEM's problem or Google's |
| [APEX file format](https://source.android.com/docs/core/ota/apex) | Reading `/apex` on a device and reporting module versions |
| [Bionic documentation](https://android.googlesource.com/platform/bionic/+/master/docs/) | The status pages on what Bionic does and does not implement — the basis for "desktop exploitation technique X does not transfer" |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Establishing what a device's security patch level actually covers |
| [Play SDK Index](https://play.google.com/sdks) | Google's own view of SDK versions and policy status. **Ask the client to open their Play Console SDK page** — many teams never have, and it sometimes hands you a corroborated inventory for free |
| [App Bundles and splits](https://developer.android.com/guide/app-bundle) | Understanding why `base.apk` alone is not the app |
| [Play Feature Delivery](https://developer.android.com/guide/playcore/feature-delivery) | Distinguishing legitimate dynamic module loading from a finding |

---

## Maven and Gradle — resolving a coordinate to an artifact

You will spend real time downloading reference releases to compare against. Knowing the URL layout
saves you from a browser.

| Resource | Why |
|---|---|
| [Maven Central](https://central.sonatype.com/) | Searching by class name, not just by artifact — the fastest way to answer "which library defines this class?" |
| Maven Central raw layout: `https://repo1.maven.org/maven2/<group-with-slashes>/<artifact>/<version>/<artifact>-<version>.jar` | Scripting a download of ten candidate versions for a class-set comparison. `com.squareup.okhttp3` becomes `com/squareup/okhttp3` |
| [Google's Maven repository](https://maven.google.com/web/index.html) | AndroidX and Play services artifacts, which are not on Maven Central. Same layout under `https://dl.google.com/dl/android/maven2/` |
| [Gradle: declaring repositories and content filtering](https://docs.gradle.org/current/userguide/declaring_repositories.html) | Reading a `repositories` block for the dependency-confusion fix — `exclusiveContent` and `content { includeGroup }` are the concrete control |
| [Gradle: dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html) | `gradle/verification-metadata.xml`. Its presence is a strong maturity signal; its absence is a process observation |
| [Gradle: dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html) | Lockfiles pin transitive versions. Ask for them |
| [Gradle: viewing and debugging dependencies](https://docs.gradle.org/current/userguide/viewing_debugging_dependencies.html) | `dependencies` and `dependencyInsight` — the two commands that settle "who pulled this in?" |
| [POM reference](https://maven.apache.org/pom.html) | A dependency's own POM lists *its* dependencies. When you cannot run Gradle, the POM chain is how you walk the tree by hand |
| [Gradle Module Metadata](https://docs.gradle.org/current/userguide/publishing_gradle_module_metadata.html) | Why the `.module` file sometimes disagrees with the POM, and which one Gradle used |

> **Pentester's Note**
> The class-name search on Maven Central is underused. Paste an unusual class name from an obfuscated
> APK and you often get the artifact back immediately — no fingerprinting required. It fails on
> renamed and shaded code, which is precisely when you fall back to the class-set comparison in
> [`../scripts/lib-fingerprint.py`](../scripts/lib-fingerprint.py).

---

## SBOM and dependency tooling

| Tool | What it does | When it helps, and where it stops |
|---|---|---|
| [CycloneDX](https://cyclonedx.org/) | SBOM standard, OWASP project; has a Gradle plugin | Build-time SBOM. Excellent for "what did we intend to ship". **Blind to native static linking, shading, and post-R8 reality** |
| [SPDX](https://spdx.dev/) | The ISO/IEC 5962 SBOM standard | Same scope. Choose whichever the client's supply-chain tooling already speaks |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | Matches components to the NVD | Needs the build files. Noisy on shaded and Android-specific artifacts. Treat output as leads |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | Queries OSV from lockfiles or an SBOM | Good data source, same dependency on build metadata |
| [Syft](https://github.com/anchore/syft) / [Grype](https://github.com/anchore/grype) | Generate an SBOM from an artifact, then scan it | Better than build-file-only tools because they read the file, but Android-specific formats and native static linking remain gaps |
| [apkid](https://github.com/rednaga/APKiD) | Identifies packers, obfuscators and compilers from DEX/ELF signatures | Excellent at its niche. Not a dependency scanner, and does not claim to be |
| [androguard](https://github.com/androguard/androguard) | Python APK/DEX analysis library | When you want to script something this chapter's tools do not do |
| [apktool](https://apktool.org/) | Decode resources and manifest, rebuild | The manifest side of the inventory |
| [smali/baksmali](https://github.com/google/smali) | DEX assembler/disassembler; `baksmali list classes` | The fastest authoritative class inventory |
| [jadx](https://github.com/skylot/jadx) | Decompiler | When you have to read what a library actually does, not just that it is there |
| `apkanalyzer` (Android SDK command-line tools) | `dex packages`, size attribution | Which library is responsible for how much of the app. Good for prioritising |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Broad automated APK analysis | A starting inventory. Library detection is prefix-based and shallow — verify everything |

**The gap none of them fills**, and the reason this chapter has its own scripts: nothing above
enumerates the third-party code *statically linked into a `.so`*. Symbol enumeration finds it;
build-time tooling never will.

---

## Vulnerability databases — and an honest note on using them

| Source | Why you would open it |
|---|---|
| [OSV](https://osv.dev/) | Best structured data for open-source packages, with precise affected-version ranges and links to the fixing commit. **The fixing commit is the important part** — it tells you which function to look for |
| [OSV API](https://google.github.io/osv.dev/api/) | Scripting a lookup for the versions your fingerprinting produced |
| [NVD](https://nvd.nist.gov/) | The canonical CVE record, CVSS vectors, CPE matching. Authoritative but coarse |
| [GitHub Advisory Database](https://github.com/advisories) | Often has ecosystem context and remediation advice the NVD lacks |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | For *platform* libraries. This is the right source for ring 1, and the NVD is not |
| Upstream project security pages and changelogs | The last word. If OpenSSL, SQLite or FFmpeg publish a security page, read theirs before anyone's summary |
| [Project Zero blog](https://googleprojectzero.blogspot.com/) | Depth on how a library bug becomes an exploit, when you need to argue severity |

### The false-positive problem, stated honestly

A CVE match against an Android app is a **lead**, not a finding, and the base rate of unusable leads
is high. The recurring causes:

| Cause | Example shape |
|---|---|
| **Reachability ignored** | The database matches a version. R8 already deleted the vulnerable class because the app never called it |
| **Server-side conditions** | A large share of advisories for widely used Java libraries describe deserialisation gadgets, JNDI lookups, servlet containers or logging configurations that have no analogue in an app process |
| **Platform substitution** | An advisory against a component when Android supplies its own maintained version and the app never touches the bundled one |
| **Feature not compiled in** | The affected demuxer, cipher or codec was not enabled in this build. An FFmpeg configure line in `.rodata` settles it in one grep |
| **Version matching** | Android artifacts have qualifiers and variants (`-android`, AAR versus JAR) that confuse CPE and coordinate matchers in both directions |
| **The silent failure** | Statically linked native dependencies produce **no** matches at all, because nothing in the build metadata mentions them. The absence of findings here is not evidence of absence |

The working method: use the database to find the **fixing commit**, read it to identify the
vulnerable function, look for that function in the shipped artifact, and then determine whether
anything reaches it ([chapter §7.4](../README.md#7-dynamic-analysis)). That converts a database hit
into either a real finding with a demonstrated path, or a defensible dismissal you can explain to the
client.

---

## ELF and native binary references

| Resource | Why |
|---|---|
| System V ABI (gABI) — the ELF specification | The definitive reference for sections, relocations, dynamic tags and notes. Open it when you are parsing something by hand |
| [AArch64 ELF ABI](https://github.com/ARM-software/abi-aa) | Relocation types (`R_AARCH64_RELATIVE` and friends) and the procedure call standard. Needed for lab 04's method 3 |
| `readelf` / `llvm-readelf` / `objdump` manual pages | The flags that matter here: `-d` for `NEEDED`, `-n` for build ID, `-S` for sections, `--dyn-syms --wide` for symbols, `-p .comment` for the toolchain |
| [Ghidra](https://ghidra-sre.org/) | Reading a constructor, or finding a function that has no symbol. See [57-Ghidra](../../57-Ghidra/README.md) |
| [`../scripts/lib-fingerprint.py`](../scripts/lib-fingerprint.py) | The same structures in ~200 lines of readable Python, when you would rather understand them than invoke them |

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | The standard your client's requirements are probably derived from |
| [MASVS-CODE](https://mas.owasp.org/MASVS/10-MASVS-CODE/) | Third-party components and code quality. **The primary mapping for this chapter** |
| [MASVS-PRIVACY](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/) | Where the SDK data-collection table from lab 03 belongs |
| [MASTG](https://mas.owasp.org/MASTG/) | Test procedures, including dependency and native-library checks |
| [MASTG Android techniques](https://mas.owasp.org/MASTG/0x05b-Android-Security-Testing/) | Concrete procedures mapping onto §7 and §8 |

---

## Research and long-form

Only sources whose details are verifiable, described by what they establish rather than by
paraphrase.

| Source | Why it is worth the time |
|---|---|
| Joshua Drake's Stagefright research (Black Hat USA / DEF CON, 2015) and the surrounding advisories | The canonical case for "a bundled parser is the attack surface". More importantly, the *architectural response* — process splitting, SELinux, seccomp, Mainline updatability — is the template for defending any parser |
| Alex Birsan's 2021 dependency-confusion write-up | Established the class at scale across npm, PyPI and RubyGems. Read it before you write a dependency-confusion finding, so that you describe the mechanism accurately |
| Google Play SDK policy and developer program announcements | Google periodically changes what SDKs may collect. Useful for arguing that a finding has a compliance dimension, not just a security one |
| Academic work on third-party library detection in Android (search for "third-party library detection Android" in any academic index) | The literature has repeatedly measured what package-prefix detection misses. Useful when a client asks why you did the work by hand |
| Vendor transparency and security pages for the SDKs you actually find | Boring and high-yield. Many SDK vendors publish a data-collection page that answers half of lab 03 before you start |

> **Warning**
> When citing research in a report, cite what you can verify. Describe the *class* of issue rather
> than inventing an identifier, and never assert that a named vendor was compromised unless you can
> cite the vendor's own advisory. [Chapter §3.6](../README.md#3-deep-internal-working) makes the same
> point about supply chain language: "outdated dependency" and "supply chain attack" are different
> claims, and only one of them needs evidence you probably do not have.

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | The container these libraries ship in; `examples/parse_axml.py` is `lib-inventory.sh`'s manifest fallback |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | Zygote preloading, and why shared libraries are load-bearing rather than an optimisation |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The `class_defs`, `type_ids` and `string_ids` tables `lib-fingerprint.py` walks to list classes |
| [13-ART](../../13-ART/README.md) | How code enters the runtime, and what "loaded" means for a managed class |
| [04-Java](../../04-Java/README.md) · [05-Kotlin](../../05-Kotlin/README.md) | The languages these libraries are written in; `04-Java/scripts/dump-strings.py` is the string-table tool used throughout the labs |
| [08-Build-System](../../08-Build-System/README.md) | Gradle, the manifest merger, and how an AAR's permissions become the app's |
| [07-AOSP](../../07-AOSP/README.md) | Navigating the source paths at the top of this file |
| [27-ContentProviders](../../27-ContentProviders/README.md) | The lifecycle that makes the initialisation-provider SDK inventory work |
| [32-Manifest](../../32-Manifest/README.md) | Reading the merged manifest, and what each attribute means |
| [34-Cryptography](../../34-Cryptography/README.md) | The crypto libraries this chapter finds, used correctly |
| [37-RootDetection](../../37-RootDetection/README.md) | The same layering argument as lab 04, applied to a whole category of checks |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What obfuscation does to library identification — the obstacle, not the subject |
| [53-Frida](../../53-Frida/README.md) | The instrumentation used throughout §7 and labs 03 to 05 |
| [57-Ghidra](../../57-Ghidra/README.md) | Reading the disassembly of a `.so` you cannot identify any other way |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Where third-party component and privacy findings map in MASVS |
| [79-Glossary](../../79-Glossary/README.md) | ELF, ABI, AAR, SBOM, shading, transitive dependency, and the rest |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The commands in this chapter, in one place |

*Chapters 15 (Native Code) and 16 (JNI) are the natural companions to this one and are referenced in
the chapter text; they have no README in the repository yet, so they are named here as plain text
rather than linked.*
