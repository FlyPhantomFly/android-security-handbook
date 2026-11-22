# 08 — Build System: Annotated References

Every link below has a one-line note saying why you would open it. Grouped by what you are trying to do.

---

## AOSP source (read these in the tree, or on cs.android.com)

- `build/make/envsetup.sh` — the real definitions of `lunch`, `m`, `mm`, `mma`, `croot`, `hmm`; read it once and you never guess at these again.
- `build/make/core/main.mk` — the entry point of the legacy Make world; where the `droid` target is defined.
- `build/make/core/base_rules.mk` — how `LOCAL_*` variables become Make rules, including where `LOCAL_MODULE_TAGS` gates which variants a module appears in.
- `build/make/target/product/` — the product definitions and `PRODUCT_PACKAGES` lists that decide what is actually on an image.
- `build/make/target/product/security/` — the **public** AOSP test keys (`platform`, `shared`, `media`, `testkey`); the reason a test-key-signed device is a total trust compromise.
- `build/make/tools/releasetools/sign_target_files_apks.py` — the script that re-signs a build from test keys to production keys; a device where this was skipped is a finding.
- `build/soong/ui/build/build.go` — the orchestration: product config, Kati, Soong, combine Ninja, run Ninja.
- `build/soong/android/module.go` — the definition of a Soong module, its variants and its properties.
- `build/soong/android/visibility.go` — `visibility:` enforcement, a genuine build-time access-control mechanism.
- `build/soong/android/apex.go` — `apex_available` enforcement: which modules may enter which APEX container.
- `build/soong/cc/builder.go` — where clang command lines are constructed for every native module.
- `build/soong/cc/config/global.go` — the global default compiler and linker flags, including the hardening baseline.
- `build/soong/cc/sanitize.go` — the implementation of `sanitize: { cfi: true, ... }`.
- `build/soong/java/app.go` — how an `android_app` becomes a signed APK, including R8 invocation and `certificate:` resolution.
- `build/soong/java/dexpreopt.go` — whether and how apps are AOT-compiled at build time; pairs with [13-ART](../../13-ART/README.md).
- `build/soong/genrule/genrule.go` — the implementation and sandboxing of the one Blueprint escape hatch.
- `build/soong/androidmk/` — the mechanical `Android.mk` → `Android.bp` converter; it fails on exactly the conditional code you most want to read.
- `build/blueprint/` — the Blueprint parser, module graph and Ninja writer that Soong is built on.
- `build/kati/` — `ckati`, the Make-to-Ninja translator that keeps legacy `Android.mk` alive.
- `build/bazel/` — the Bazel migration, including `bp2build`-generated `BUILD.bazel` files.
- `system/sepolicy/` — SELinux policy source and the build rules that compile it into `plat_sepolicy.cil`; see [22-SELinux](../../22-SELinux/README.md).
- `prebuilts/` — checked-in clang, JDK, build tools and SDKs; the largest trusted-binary surface in the tree.
- **Android Code Search** — https://cs.android.com/ — search any of the above by path or symbol without a local checkout.

---

## Official documentation — platform build

- **Building Android** — https://source.android.com/docs/setup/build/building — prerequisites, `envsetup.sh`, `lunch`, `m`, and the target naming scheme.
- **Soong build system** — https://source.android.com/docs/setup/build — the conceptual overview of Soong, Blueprint, Kati and Ninja.
- **Android.bp file format** — https://source.android.com/docs/setup/reference/androidbp — the reference for every module type and property; keep it open while reading an unfamiliar tree.
- **Build variants (user / userdebug / eng)** — https://source.android.com/docs/setup/build/building#choose-a-target — the table that explains why `ro.build.type` matters so much.
- **Soong config variables** — https://source.android.com/docs/setup/reference/androidbp#conditionals — how conditional behaviour is expressed without a Turing-complete language.
- **APEX file format** — https://source.android.com/docs/core/ota/apex — the containerised modules the build produces and signs separately.
- **Build numbers and fingerprints** — https://source.android.com/docs/setup/about/build-numbers — mapping a device's build fingerprint back to a release.

---

## Official documentation — app build

- **Configure your build** — https://developer.android.com/build — the top-level index for everything AGP.
- **Build variants** — https://developer.android.com/build/build-variants — build types, product flavours, dimensions and the source-set merge ladder.
- **Merge manifest files** — https://developer.android.com/build/manage-manifests — the authoritative description of merger priority and every `tools:` marker; the most under-read page in Android documentation.
- **Add build dependencies** — https://developer.android.com/build/dependencies — the semantics of `implementation`, `api`, `compileOnly`, `runtimeOnly` and the variant-scoped configurations.
- **Version catalogs** — https://developer.android.com/build/migrate-to-catalogs — `libs.versions.toml`, which turns the dependency inventory into one reviewable file.
- **Shrink, obfuscate and optimize** — https://developer.android.com/build/shrink-code — `minifyEnabled`, `shrinkResources`, keep-rule syntax, and where `mapping.txt` lands.
- **Sign your app** — https://developer.android.com/studio/publish/app-signing — keystores, signing configs, upload keys and the scheme toggles.
- **Play App Signing** — https://support.google.com/googleplay/android-developer/answer/9842756 — why the certificate on the device is not the developer's upload key.
- **Android App Bundle** — https://developer.android.com/guide/app-bundle — the AAB format, split generation and dynamic features.
- **bundletool** — https://developer.android.com/tools/bundletool — the local generator; how to produce installable APKs from an AAB for analysis.
- **AGP release notes** — https://developer.android.com/build/releases/gradle-plugin — the behaviour-change log; essential when reasoning about what was a default at the time an APK was built.
- **AGP Variant API** — https://developer.android.com/build/extend-agp — the modern API used by the security-gate plugin in §9.3.
- **NDK build configuration** — https://developer.android.com/ndk/guides/cmake — `externalNativeBuild`, `abiFilters`, and where hardening flags go.
- **Support 16 KB page sizes** — https://developer.android.com/guide/practices/page-sizes — the alignment requirement that breaks old `.so` files on new devices.

---

## Official documentation — APK format and signing

- **APK Signature Scheme v2** — https://source.android.com/docs/security/features/apksigning/v2 — the APK Signing Block and why alignment must precede signing.
- **APK Signature Scheme v3 / v3.1** — https://source.android.com/docs/security/features/apksigning/v3 — signing certificate lineage and key rotation.
- **APK Signature Scheme v4** — https://source.android.com/docs/security/features/apksigning/v4 — the Merkle tree and incremental install.
- **apksigner** — https://developer.android.com/tools/apksigner — `verify --print-certs`, `rotate`, and the `--min-sdk-version` interaction.
- **aapt2** — https://developer.android.com/tools/aapt2 — `compile`, `link`, and the `dump` subcommands you will use constantly.
- **zipalign** — https://developer.android.com/tools/zipalign — the `-p` and `-P` flags and the check mode.

---

## Gradle

- **Gradle user manual** — https://docs.gradle.org/current/userguide/userguide.html — the reference for the build lifecycle and everything below.
- **The build lifecycle** — https://docs.gradle.org/current/userguide/build_lifecycle.html — initialisation, configuration, execution; the page that explains why `--dry-run` is not safe.
- **Declaring repositories** — https://docs.gradle.org/current/userguide/declaring_repositories.html — **repository content filtering**, the exact mechanism that closes dependency confusion.
- **Dependency verification** — https://docs.gradle.org/current/userguide/dependency_verification.html — `verification-metadata.xml`, checksum and PGP pinning; the strongest single supply-chain control available to a Gradle project.
- **Centralizing dependencies** — https://docs.gradle.org/current/userguide/centralizing_repositories.html — `dependencyResolutionManagement` and `FAIL_ON_PROJECT_REPOS`.
- **Build cache** — https://docs.gradle.org/current/userguide/build_cache.html — including the push-access guidance that prevents cache poisoning.
- **Configuration cache** — https://docs.gradle.org/current/userguide/configuration_cache.html — what it restricts build scripts from doing at execution time.
- **The Gradle wrapper** — https://docs.gradle.org/current/userguide/gradle_wrapper.html — `distributionSha256Sum` and regenerating the wrapper from a trusted installation.
- **Gradle release checksums** — https://gradle.org/release-checksums/ — the published SHA-256 values to check `gradle-wrapper.jar` against.
- **Organizing build logic** — https://docs.gradle.org/current/userguide/organizing_gradle_projects.html — `buildSrc` versus `build-logic` and why the former runs first.

---

## OWASP

- **MASVS** — https://mas.owasp.org/MASVS/ — the control framework this chapter maps to.
- **MASVS-CODE** — https://mas.owasp.org/MASVS/10-MASVS-CODE/ — build settings, dependency management, signing and debug configuration.
- **MASVS-RESILIENCE** — https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/ — obfuscation and integrity; where `minifyEnabled` findings belong, and where they do *not*.
- **MASTG** — https://mas.owasp.org/MASTG/ — the test procedures; see the Android platform-overview, code-quality and reverse-engineering sections.
- **OWASP Dependency-Check** — https://owasp.org/www-project-dependency-check/ — the Gradle plugin for known-vulnerable dependency detection; remember it reports the declared graph, not the shipped one.
- **Software Component Verification Standard** — https://owasp.org/www-project-software-component-verification-standard/ — a maturity model for the supply-chain controls in §5.4.

---

## Supply chain

- **Alex Birsan, "Dependency Confusion"** — https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610 — the article that named the class; read it for the resolution-order reasoning, then map it onto Gradle's specifics.
- **SLSA** — https://slsa.dev/ — a framework for describing build-integrity guarantees; useful vocabulary when writing supply-chain recommendations a client can act on.
- **Reproducible Builds** — https://reproducible-builds.org/ — the sources of non-determinism catalogued, with fixes; §3.20 is a summary of this.
- **diffoscope** — https://diffoscope.org/ — the tool for comparing two builds of the same artefact in depth, entry by entry.
- **Sigstore** — https://www.sigstore.dev/ — keyless signing and transparency logs for artefacts.
- **OSV** — https://osv.dev/ — an open vulnerability database with a usable API for Maven coordinates.
- **CycloneDX** — https://cyclonedx.org/ — the SBOM format a client's supply-chain programme will ask for; there is a Gradle plugin.
- **GitHub Advisory Database** — https://github.com/advisories — searchable by Maven coordinate.

---

## Security bulletins and vendor communication

- **Android Security Bulletins** — https://source.android.com/docs/security/bulletin — the authoritative source when you need to cite a specific issue rather than describing a class.
- **Android Developers Blog** — https://android-developers.googleblog.com/ — where signing-policy and Play-requirement changes are announced.
- **Google Play policy: app signing requirements** — https://support.google.com/googleplay/android-developer/answer/9859152 — the AAB requirement and the signing options.

---

## Tools referenced in this chapter

| Tool | Where | Used for |
|---|---|---|
| `apksigner` | Android SDK build-tools | Verifying certificates and signature schemes; key rotation |
| `aapt2` | Android SDK build-tools | Manifest, badging and resource-table dumps |
| `zipalign` | Android SDK build-tools | Alignment and `-c` verification |
| `bundletool` | https://github.com/google/bundletool | AAB → APK set; device-targeted generation |
| `apktool` | https://apktool.org/ | Decoding the binary manifest and resources to readable XML |
| `jadx` | https://github.com/skylot/jadx | Decompiling DEX for `BuildConfig` and library identification |
| `keytool` | JDK | Inspecting keystores and certificates |
| `diffoscope` | https://diffoscope.org/ | Reproducibility comparison |
| `mitmproxy` | https://mitmproxy.org/ | Observing what a build fetches |
| `strace` | Linux | Observing what a build opens and executes |
| `readelf` / `nm` | binutils | Native hardening audit of shipped `.so` files |

---

## Related chapters

- [06-Android-Architecture](../../06-Android-Architecture/README.md) — the system the platform build produces.
- [07-AOSP](../../07-AOSP/README.md) — the source tree, `repo`, and how to read it.
- [10-APK-Internals](../../10-APK-Internals/README.md) — the anatomy of the artefact this chapter builds.
- [12-DEX-Internals](../../12-DEX-Internals/README.md) — the bytecode format D8 and R8 emit.
- [13-ART](../../13-ART/README.md) — dexpreopt, baseline profiles, and what happens after install.
- [15-Native-Code](../../15-Native-Code/README.md) — auditing the `.so` files the native pipeline produces.
- [16-JNI](../../16-JNI/README.md) — why classes with `native` methods keep their original names.
- [22-SELinux](../../22-SELinux/README.md) — the policy compiled by the same build graph.
- [23-Permissions](../../23-Permissions/README.md) — including the ones a library's manifest added.
- [26-Intent](../../26-Intent/README.md) — reaching injected exported components.
- [32-Manifest](../../32-Manifest/README.md) — every attribute in the merged manifest.
- [40-Obfuscation](../../40-Obfuscation/README.md) / [41-ProGuard](../../41-ProGuard/README.md) / [42-R8](../../42-R8/README.md) — the shrink-and-obfuscate stage in full.
- [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) — the config the debug source set overrides.
- [52-StaticAnalysis](../../52-StaticAnalysis/README.md) — the methodology §8 plugs into.
- [55-MobSF](../../55-MobSF/README.md) — automated build-configuration review and its false positives.
- [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) — the MASVS/MASTG mapping methodology.
