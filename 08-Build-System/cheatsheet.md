# 08 — Build System Cheat Sheet

Printable. Tables and commands only. Full explanation in [README.md](README.md).

---

## The two build systems

| | (A) Platform | (B) App |
|---|---|---|
| Build file | `Android.bp`, legacy `Android.mk` | `build.gradle(.kts)` |
| Engine | Soong → Ninja; Kati for Make | Gradle + AGP |
| Language | Blueprint (declarative data) | Groovy / Kotlin (executable) |
| Commands | `source build/envsetup.sh`, `lunch`, `m` | `./gradlew assembleRelease` |
| Output | `system.img`, `vendor.img`, sepolicy, JARs | `.apk` / `.aab` |
| Arbitrary code at parse time | No (except `genrule`) | **Yes** |

---

## Platform build commands

| Command | Effect |
|---|---|
| `source build/envsetup.sh` | Define `lunch`, `m`, `mm`, `mma`, `croot`, `hmm` |
| `lunch <product>-<release>-<variant>` | Set `TARGET_PRODUCT`, `TARGET_RELEASE`, `TARGET_BUILD_VARIANT` |
| `m -j$(nproc)` | Full build of `droid` |
| `m <module>` | Build one module plus dependencies |
| `mm` | Build modules in the current directory, no dependency rebuild |
| `mma` | `mm` plus dependencies |
| `mmm <dir>` / `mmma <dir>` | Same, for a named directory |
| `m snod` | Repack `system.img` from `out/` — fast patch/flash loop |
| `m dist` | Build and copy artefacts to `out/dist/` |
| `m installclean` | Remove installed artefacts, keep objects |
| `m nothing` | Parse only; validate `Android.bp`, measure null build |

## Build variants

| Variant | `ro.debuggable` | `ro.secure` | `adb root` | Ships? |
|---|---|---|---|---|
| `user` | 0 | 1 | No | Yes |
| `userdebug` | 1 | 1 | Yes | QA / research |
| `eng` | 1 | 0 | Yes (adbd may be root) | Never |

```bash
# adb shell — which variant am I holding?
getprop ro.build.type
getprop ro.debuggable
getprop ro.secure
```

## Soong module types

| Type | Produces | Reviewer note |
|---|---|---|
| `cc_library[_shared\|_static\|_headers]` | `.so` / `.a` / headers | Check `vendor_available`, `apex_available`, `sanitize` |
| `cc_binary` | Executable | Pair with its `init_rc` |
| `cc_test` | gtest binary | Often left on userdebug images |
| `java_library` / `java_import` | JAR / prebuilt JAR | `java_import` = no source in tree |
| `android_app` / `android_app_import` | APK / prebuilt APK | `certificate:`, `privileged:` |
| `android_library` | AAR equivalent | Contributes manifest + resources |
| `filegroup` | Named file list | Follow it when tracing inputs |
| `genrule` | Anything, via a shell `cmd:` | **The only shell escape** |
| `prebuilt_etc` | File into `/system/etc` | Config, permission XML, keys |
| `apex` | Signed mountable module | Own key, own manifest |
| `aidl_interface` | Binder bindings | The interface definition |
| `cc_defaults` / `java_defaults` | Reusable property bundle | Follow to see real flags |

## Security-relevant `Android.bp` properties

| Property | Meaning |
|---|---|
| `certificate: "platform"` | Signed with the platform key — inside the platform trust domain |
| `privileged: true` | Installs to `priv-app/`; eligible for `signature\|privileged` permissions |
| `platform_apis: true` | Compiles against internal APIs |
| `vendor: true` / `vendor_available: true` | Vendor partition build |
| `apex_available: [...]` | Which APEX containers may include it |
| `sanitize: { cfi: true, ... }` | CFI, HWASan, integer overflow |
| `visibility: [...]` | Which packages may depend on it |
| `init_rc: [...]` | Installs an init `.rc` — this is how a daemon starts |
| `stem:` / `suffix:` | On-device filename differs from module name |

## Platform output tree

| Path | Contents |
|---|---|
| `out/soong/build.ninja` | The generated graph |
| `out/soong/soong.variables` | **Entire product configuration as JSON** |
| `out/target/product/<d>/system/` | system.img staging |
| `out/target/product/<d>/symbols/` | **Unstripped binaries with symbols** |
| `out/target/product/<d>/installed-files.txt` | Image inventory |
| `out/target/product/<d>/module-info.json` | Module → installed path / source dir |

---

## Gradle phases

| Phase | File | What runs |
|---|---|---|
| Initialisation | `settings.gradle(.kts)` | `pluginManagement`, `dependencyResolutionManagement`, `include` |
| Configuration | every `build.gradle(.kts)` | **Arbitrary code**; plugins applied; tasks registered |
| Execution | — | Out-of-date tasks only |

`--dry-run`, `tasks`, `help` and IDE import all run the **configuration** phase.

## Files a reviewer opens, in order

| File | Look for |
|---|---|
| `settings.gradle(.kts)` | Repository list + order; `content {}` filters; `repositoriesMode` |
| `gradle/wrapper/gradle-wrapper.properties` | `distributionUrl` host; **missing** `distributionSha256Sum` |
| `gradle/wrapper/gradle-wrapper.jar` | SHA-256 vs gradle.org/release-checksums |
| `buildSrc/`, `build-logic/`, `*.init.gradle` | Code that runs before everything |
| `gradle/libs.versions.toml` | Full dependency inventory |
| `gradle.properties`, `local.properties` | `*_PASSWORD`, `*_TOKEN`, `*_KEY` |
| `app/build.gradle(.kts)` | `signingConfig`, `isDebuggable`, `isMinifyEnabled`, `buildConfigField` |
| `proguard-rules.pro` | `-keep class **`, `-dontobfuscate` |
| `gradle/verification-metadata.xml` | Its **absence** is the finding |

## Dependency configurations

| Configuration | Your compile CP | Consumers' compile CP | In the APK |
|---|---|---|---|
| `implementation` | Yes | No | Yes |
| `api` | Yes | Yes | Yes |
| `compileOnly` | Yes | No | **No** |
| `compileOnlyApi` | Yes | Yes | No |
| `runtimeOnly` | No | No | Yes |
| `annotationProcessor` / `kapt` / `ksp` | Processor only | No | No |
| `testImplementation` | Unit tests | No | No |
| `androidTestImplementation` | Instr. tests | No | Test APK |
| `debugImplementation` | Debug only | No | Debug APK only |

## App pipeline, in order

```
manifest merge -> aapt2 compile -> aapt2 link (resources.arsc, R.java)
kotlinc -> javac -> desugar -> D8 (minify off) | R8 (minify on) -> classes.dex
CMake/ndk-build per ABI -> strip -> lib/<abi>/*.so
ZIP -> zipalign -> apksigner -> app-release.apk
                 \-> bundletool -> app-release.aab -> Play splits
```

## Manifest merger priority (highest first)

1. Injected values (`applicationId`, `minSdk`, `targetSdk`, placeholders)
2. Build type manifest — `src/release/AndroidManifest.xml`
3. Product flavour manifest — `src/production/AndroidManifest.xml`
4. Main manifest — `src/main/AndroidManifest.xml`
5. **Library manifests** (lowest — but an element with no counterpart is added verbatim)

## `tools:` merge markers

| Marker | Effect |
|---|---|
| `tools:node="merge"` | Default |
| `tools:node="merge-only-attributes"` | Merge attributes, ignore lower-priority children |
| `tools:node="replace"` | Replace the lower-priority element entirely |
| `tools:node="remove"` | Remove the matching element |
| `tools:node="removeAll"` | Remove all lower-priority elements of that type |
| `tools:node="strict"` | Fail the build on any difference |
| `tools:replace="a,b"` | Replace named attributes |
| `tools:remove="a,b"` | Remove named attributes |
| `tools:selector="pkg"` | Apply only to that library |
| `tools:overrideLibrary="pkg"` | Permit a library with a higher `minSdk` |

## Source set merge order (lowest → highest)

`src/main/` → `src/<flavor>/` → `src/<flavorCombination>/` → `src/<buildType>/` → `src/<fullVariant>/`

| Artefact | Behaviour |
|---|---|
| Java/Kotlin | Concatenated; duplicate FQCN = error |
| `res/` | Overlaid |
| `assets/` | Overlaid by filename |
| Manifests | Merged (build type highest) |
| `jniLibs/` | Overlaid by relative path |
| Dependencies | Additive |

## APK signature schemes

| Scheme | Since | Covers |
|---|---|---|
| v1 (JAR) | 1.0 | Per-file digests in `META-INF/` |
| v2 | 7.0 / 24 | Whole APK bytes |
| v3 | 9 / 28 | v2 + signing certificate lineage (rotation) |
| v3.1 | 13 / 33 | Rotation targeted at newer SDKs |
| v4 | 11 / 30 | Merkle tree in `.apk.idsig` (incremental install) |

---

## Commands — inspecting a build

```bash
# Task graph without running it
./gradlew assembleRelease --dry-run

# True dependency graph for the shipped variant
./gradlew :app:dependencies --configuration releaseRuntimeClasspath

# Why is this artefact present, and who chose the version?
./gradlew :app:dependencyInsight --configuration releaseRuntimeClasspath --dependency okhttp

# Pin every artefact by checksum and signature
./gradlew --write-verification-metadata sha256,pgp help

# Build reports
cat app/build/outputs/logs/manifest-merger-release-report.txt
cat app/build/outputs/mapping/release/configuration.txt   # REAL R8 rules
cat app/build/outputs/mapping/release/seeds.txt           # kept
cat app/build/outputs/mapping/release/usage.txt           # removed
find app/build/intermediates -name AndroidManifest.xml -path "*erged*"
```

## Commands — inspecting an APK

```bash
aapt2 dump badging app.apk                                  # package, sdk, debuggable, native-code
aapt2 dump xmltree app.apk --file AndroidManifest.xml       # merged manifest, binary form
aapt2 dump resources app.apk                                # resources.arsc
apksigner verify --verbose --print-certs app.apk            # schemes + certificates
keytool -printcert -jarfile app.apk                         # full certificate
unzip -p app.apk META-INF/com/android/build/gradle/app-metadata.properties   # AGP version
unzip -p app.apk META-INF/version-control-info.textproto    # git repo + commit
unzip -p app.apk kotlin-tooling-metadata.json               # Kotlin version
unzip -l app.apk | grep -oE "META-INF/[a-zA-Z0-9_.-]+\.version"  # library versions
unzip -v app.apk | grep -E "resources.arsc|\.so"            # Stored vs Deflated
zipalign -c -P 16 -v 4 app.apk                              # 16 KB page alignment check
```

## Commands — hunting secrets

```bash
aapt2 dump resources app.apk | grep -iE "key|token|secret|password|https?://"
unzip -o app.apk 'classes*.dex' -d dex/
strings -n 12 dex/*.dex | grep -inE "sk_live_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_|xox[baprs]-"
strings -n 16 dex/*.dex | grep -E "-----BEGIN"
unzip -o app.apk 'assets/*' -d assets_out/ && grep -rnIE "api[_-]?key|BEGIN .*PRIVATE KEY" assets_out/
grep -rn "buildConfigField\|resValue\|manifestPlaceholders" --include="build.gradle*" .
git log --all --diff-filter=A --name-only --pretty=format: | sort -u | grep -iE "\.jks$|\.keystore$|secret"
```

## Commands — component surface

```bash
apktool d -f app.apk -o out/
grep -nE 'android:exported="true"' out/AndroidManifest.xml
grep -nE '<uses-permission' out/AndroidManifest.xml | sort

# diff: what the developer wrote vs what shipped
grep -oE 'android:name="[^"]+"' app/src/main/AndroidManifest.xml | sort -u > declared.txt
grep -oE 'android:name="[^"]+"' out/AndroidManifest.xml           | sort -u > shipped.txt
comm -13 declared.txt shipped.txt        # <- everything the libraries added
```

```bash
# adb shell — reach them
am start -a android.intent.action.VIEW -d "scheme://host/path"
am start -n com.example.app/com.vendor.sdk.RouterActivity --es url "https://attacker/"
am broadcast -a com.vendor.sdk.EXECUTE -n com.example.app/com.vendor.sdk.CommandReceiver
content query --uri content://com.vendor.sdk.provider/items
dumpsys package com.example.app | sed -n '/Activity Resolver Table/,/Permissions:/p'
```

## Commands — AAB and splits

```bash
bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal
bundletool build-apks --bundle=app.aab --output=d.apks --connected-device
bundletool install-apks --apks=d.apks
adb shell pm path com.example.app            # ALWAYS: enumerate the real split set
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.xxhdpi.apk
```

## Commands — native hardening audit

```bash
unzip -o app.apk 'lib/*' -d nat/
for so in $(find nat -name '*.so'); do
  echo "== $so"
  readelf -h "$so" | grep "Type:"                      # DYN = PIE
  readelf -d "$so" | grep -E "BIND_NOW|RELRO|RUNPATH"
  readelf -sW "$so" | grep -c "__stack_chk_fail"       # canaries
  readelf -sW "$so" | grep -c "_chk@"                  # FORTIFY
  nm -D --defined-only "$so" | grep -c " T Java_"      # JNI exports
done
```

---

## Debug-leak indicators in a shipped APK

| Indicator | Command |
|---|---|
| `debuggable="true"` | `aapt2 dump badging app.apk \| grep application-debuggable` |
| Debug signing key | `apksigner verify --print-certs app.apk \| grep -i "CN=Android Debug"` |
| `testOnly="true"` | `aapt2 dump xmltree app.apk --file AndroidManifest.xml \| grep testOnly` |
| Debug-only libraries | `unzip -l app.apk \| grep -iE "flipper\|chucker\|leakcanary\|stetho"` |
| Coroutines debug | `unzip -l app.apk \| grep DebugProbesKt.bin` |
| Cleartext / user CAs | `grep -n "usesCleartextTraffic\|networkSecurityConfig" out/AndroidManifest.xml` |
| Unguarded logging ratio | `grep -rc "Landroid/util/Log;->" out/smali*/` |

## Supply-chain checks

| Check | Command / file |
|---|---|
| Repository content filtering | `content { includeGroupByRegex(...) }` in `settings.gradle.kts` |
| Per-project repos forbidden | `repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)` |
| Artefact pinning | `gradle/verification-metadata.xml` |
| Wrapper integrity | `sha256sum gradle/wrapper/gradle-wrapper.jar` vs gradle.org/release-checksums |
| Wrapper distribution pinned | `distributionSha256Sum=` present in `gradle-wrapper.properties` |
| Mutable versions | `grep -rnE ":(.*\+\|latest\.[a-z]+\|.*-SNAPSHOT)['\"]" --include="build.gradle*" .` |
| JitPack | `grep -rn "jitpack.io" --include="*.gradle*" .` |
| Pre-execution code | `grep -rnE "exec\(\|ProcessBuilder\|URL\(\|System.getenv" buildSrc/ build-logic/` |
| Build cache push | `isPush = System.getenv("CI") == "true"` |
| What the build touched | `strace -f -e trace=execve,openat ./gradlew --no-daemon assembleRelease` |

## Platform-tree supply-chain checks

```bash
grep -rn --include=Android.bp -A5 "genrule\s*{" . | grep "cmd:"      # shell escapes
grep -rn --include=Android.bp -B5 'certificate: *"platform"' .       # platform-signed apps
grep -rn --include=Android.bp -B10 "privileged: *true" .             # priv-app
grep -rn --include=Android.bp -E "java_import|android_app_import" .  # prebuilts, no source
grep -rn --include=Android.mk '\$(shell\|LOCAL_POST_INSTALL_CMD' .   # legacy escapes
```

---

## Severity quick reference

| Finding | Realistic severity |
|---|---|
| `debuggable="true"` in production | High → Critical |
| Debug signing key on a published app | High |
| Self-managed signing key committed to git | Critical |
| Backend credential (`sk_live_`, AWS secret, DB) in `BuildConfig`/`arsc`/assets | Critical |
| Third-party SaaS write key | Medium |
| Firebase Web API / Maps key | Informational — **verify restrictions first** |
| Injected exported component, no reachable impact | Informational |
| Injected exported component → WebView / intent redirection | High → Critical |
| `mapping.txt` published | Medium (RESILIENCE) |
| `minifyEnabled false` on release | Low (RESILIENCE) |
| Obfuscation disabled by a library consumer rule | Low, but flag the dependency |
| No repository content filtering with internal coordinates | Medium (supply chain) |
| No `distributionSha256Sum` on the wrapper | Low → Medium |
| No `verification-metadata.xml` | Low (programme finding) |
| Mutable dependency version / JitPack branch ref | Medium |
