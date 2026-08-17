# 17 — Libraries: Cheat Sheet

Printable. Tables and commands only. Full explanations in [README.md](README.md).

---

## Ring classification

| Ring | Where it lives | Owner | You report |
|---|---|---|---|
| 1 — Platform | `/system/lib64`, `/apex/*/lib64`, `/vendor/lib64` | Google / OEM | Security patch level + APEX module versions |
| 2 — Bundled | APK `lib/<abi>/*.so`, DEX | App developer | Version, CVEs, SDK behaviour |
| 3 — Dynamic | Downloaded, `assets/`, `/data/local/tmp`, memfd | Nobody | Code-loading finding — usually High/Critical |

---

## Bionic vs glibc — what changes for exploitation

| Feature | glibc | Bionic |
|---|---|---|
| Allocator | ptmalloc2 (tcache, bins) | **Scudo** (dlmalloc → jemalloc → Scudo historically) |
| `__malloc_hook` / `__free_hook` | Existed (removed 2.34) | **Never existed** |
| `printf("%n")` | Supported | **Not supported** |
| FILE vtable (FSOP) | Historically exploitable | Not in the glibc sense |
| `LD_PRELOAD` | Honoured widely | Ignored/blocked for most processes |
| Lazy binding / `ret2dl_resolve` | Available | Full RELRO + BIND_NOW by default |
| Locale / `iconv` / `gconv` | Large loadable surface | Effectively UTF-8 only, no modules |
| NSS DNS plugins | Loadable modules | Fixed resolver (`com.android.resolv` APEX) |
| `FORTIFY_SOURCE` | Optional | On by default, more aggressive |
| Stack canary | TLS via `%fs` | TLS via `TPIDR_EL0`, `__stack_chk_guard` |
| Shell for `system()` | bash / dash | mksh (`/system/bin/sh`) |

---

## Platform library quick reference

| Library | Role | Risk class |
|---|---|---|
| `libc.so` / `libm.so` / `libdl.so` | Bionic | Syscall boundary; hook point |
| `linker64` | ELF loader, namespaces, RELRO | Load policy |
| `libbinder.so` / `libbinder_ndk.so` | Binder IPC (`Parcel`, `IPCThreadState`) | Trust-boundary crosser |
| `libutils.so` | `RefBase`, `sp<>`, `String8/16`, `Looper` | UAF from refcount misuse |
| `libcutils.so` | ashmem, properties, sockets, `native_handle` | FD confusion |
| `liblog.so` | `__android_log_print` | Logging capture |
| `libnativehelper.so` + libnativeloader | JNI helpers; namespace policy for `loadLibrary` | Load policy |
| `libandroid_runtime.so` | **JNI glue for the whole framework** | Java↔native type confusion |
| `libhwui.so` + Skia | Rendering + **image decoders** (PNG/JPEG/WebP/GIF) | Parser |
| `libmedia*`, `libstagefright`, extractors | Container + codec parsing | **Parser — canonical** |
| `libsqlite.so` | SQLite | Injection (app) + file-format parser (native) |
| `libcrypto.so` / `libssl.so` | BoringSSL | TLS state machine, ASN.1 parser |
| Conscrypt (`com.android.conscrypt` APEX) | JCA/JSSE provider, CA store | Policy engine — pinning target |
| `libwebviewchromium.so` | Chromium renderer | Config risk > memory risk |
| `libz.so` | zlib | Decompression = parsing |
| `libicu*.so` | Unicode | Logic bugs (homograph, filter bypass) |

---

## Enumeration commands

```bash
# Native libraries in the APK
unzip -l app.apk | grep -E '\.so$'
unzip -l app.apk | grep -oE 'lib/[^/]+/' | sort -u          # ABIs

# Version stamps (fastest win)
unzip -l app.apk | grep -oE 'META-INF/[^ ]+\.version'
for f in $(unzip -l app.apk | grep -oE 'META-INF/[^ ]*\.version'); do
  printf "%-60s %s\n" "$f" "$(unzip -p app.apk "$f")"; done

# Extra code hidden in assets
unzip -l app.apk | grep -E 'assets/.*\.(dex|jar|apk|zip|so|bundle|js)$'

# Managed class inventory -> package prefixes
baksmali list classes app.apk | sed 's#/[^/]*$##' | sort | uniq -c | sort -rn | head -60

# Manifest surface
apktool d -f app.apk -o work >/dev/null
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml | sort -u   # self-init SDKs
grep -oE '<provider[^>]*android:name="[^"]*"' work/AndroidManifest.xml | sort -u
grep -oE '<meta-data[^>]*/>' work/AndroidManifest.xml | sort -u            # SDK keys/config
grep -oE 'android\.permission\.[A-Z_]+' work/AndroidManifest.xml | sort -u
grep -oE '<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*' work/AndroidManifest.xml
```

---

## ELF inspection

| Need | Command |
|---|---|
| Architecture / type | `readelf -h lib.so` |
| Dependencies | `readelf -d lib.so \| grep NEEDED` |
| Dynamic symbols | `readelf --dyn-syms --wide lib.so` |
| All symbols (unstripped) | `nm -C lib.so` |
| Sections | `readelf -S lib.so` |
| Build ID | `readelf -n lib.so \| grep -A1 'Build ID'` |
| Compiler / NDK | `readelf -p .comment lib.so` |
| Strings | `strings -a -n 8 lib.so` |
| Disassembly | `objdump -d --demangle lib.so` / `llvm-objdump -d` |
| Constructors present | `readelf -S lib.so \| grep init_array` |
| RELRO | `readelf -l lib.so \| grep GNU_RELRO` |
| BIND_NOW | `readelf -d lib.so \| grep -E 'BIND_NOW\|FLAGS.*NOW'` |
| Stack canary | `readelf --dyn-syms lib.so \| grep __stack_chk_fail` |

### ELF sections you care about

| Section | Contents | Why |
|---|---|---|
| `.text` | Code | Disassembly target |
| `.rodata` | Strings, tables, constants | Versions, URLs, crypto S-boxes |
| `.data` / `.bss` | Writable data | Function pointer tables |
| `.init_array` | Constructors | **Runs inside `dlopen`, before `JNI_OnLoad`** |
| `.fini_array` | Destructors | Cleanup / evidence removal |
| `.dynsym` / `.dynstr` | Dynamic symbols | Exports/imports survive stripping |
| `.rela.dyn` / `.rela.plt` | Relocations | Imports always visible here |
| `.got` / `.got.plt` | GOT | Hook/hijack target; RO under full RELRO |
| `.plt` | PLT stubs | Call-through-GOT pattern |
| `.note.gnu.build-id` | Build hash | Identity, correlation, tamper evidence |
| `.comment` | Compiler string | Build-date proxy |

---

## Static-linkage detection by symbol prefix

| Symbols present | Library statically linked |
|---|---|
| `SSL_*`, `EVP_*`, `X509_*` | OpenSSL or BoringSSL |
| `png_*` | libpng |
| `jpeg_*` | libjpeg / libjpeg-turbo |
| `sqlite3_*` | SQLite |
| `curl_*` | libcurl |
| `av_*`, `avcodec_*`, `avformat_*` | FFmpeg |
| `BZ2_*`, `lzma_*`, `ZSTD_*` | compression library |
| `Java_*` | JNI entry points present |
| `JNI_OnLoad` only, no `Java_*` | Dynamic `RegisterNatives` binding |

---

## Version-string greps

| Library | Grep |
|---|---|
| OpenSSL | `strings -a lib.so \| grep -i '^OpenSSL '` |
| BoringSSL | `strings -a lib.so \| grep -i boringssl` |
| zlib | `strings -a lib.so \| grep -E 'inflate [0-9.]+ Copyright'` |
| libpng | `strings -a lib.so \| grep -i 'libpng version'` |
| libcurl | `strings -a lib.so \| grep -oE 'libcurl/[0-9.]+'` |
| FFmpeg | `strings -a lib.so \| grep -E 'FFmpeg version\|--enable-'` |
| SQLite | `strings -a lib.so \| grep -E '^3\.[0-9]+\.[0-9]+$'` |
| OkHttp | `grep -a -oE 'okhttp/[0-9]+\.[0-9]+\.[0-9]+' classes*.dex` |
| Flutter engine | `strings -a libflutter.so \| grep -E '^[0-9a-f]{40}$'` |

---

## Six fingerprinting techniques

| # | Technique | Survives obfuscation? | Survives stripping? |
|---|---|---|---|
| 1 | Embedded version strings | Sometimes | No if `-s` and string encryption |
| 2 | Class-set comparison vs Maven refs | Yes (use structure) | n/a |
| 3 | Native symbol sets | n/a | Yes (`.dynsym` exports, `.rela.plt` imports) |
| 4 | ELF build ID | n/a | Only if not deliberately removed |
| 5 | Resources / `META-INF/*.version` / baseline profile | Yes | n/a |
| 6 | Behaviour: endpoints, UA, thread names, prefs keys | Yes | Yes |

---

## Runtime enumeration

```bash
PID=$(adb shell pidof -s com.example.target)

# Everything mapped
adb shell "awk '{print \$6}' /proc/$PID/maps | grep -E '\.(so|apk|dex|odex|vdex|art|jar)$' | sort -u"

# Suspicious mappings — the highest-value single command
adb shell "grep -E '/data/local/tmp|/sdcard|/storage|memfd|\(deleted\)' /proc/$PID/maps"

# Thread names as a library fingerprint
adb shell "for t in /proc/$PID/task/*; do cat \$t/comm; done | sort -u"

# Platform libraries an app may dlopen
adb shell cat /system/etc/public.libraries.txt
adb shell ls /apex/*/etc/public.libraries.txt

# APEX module versions
adb shell cmd package list packages --apex-only
```

```javascript
// Frida
Process.enumerateModules().forEach(m => console.log(m.base + " " + m.name + " " + m.path));
Module.enumerateExports("libfoo.so").filter(e => /^(Java_|JNI_)/.test(e.name)).forEach(e => console.log(e.name));
Process.enumerateThreads().forEach(t => console.log(t.id));
```

```bash
frida-trace -U -f pkg -i "android_dlopen_ext" -i "dlopen*"    # library loads
frida-trace -U -f pkg -I "libfoo.so"                          # every export of one module
strace -f -e trace=openat,mmap,mprotect -p $PID | grep -E '\.so|\.dex'
```

---

## Smali signatures

| Pattern | Smali |
|---|---|
| Standard load | `invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V` |
| Path load (investigate) | `invoke-static {v3}, Ljava/lang/System;->load(Ljava/lang/String;)V` |
| Dynamic DEX | `Ldalvik/system/DexClassLoader;-><init>(...)` |
| In-memory DEX | `Ldalvik/system/InMemoryDexClassLoader;-><init>(...)` |
| Reflection on decrypted name | `Ljava/lang/Class;->forName(Ljava/lang/String;)` |

```bash
grep -rn "Ljava/lang/System;->loadLibrary" work/smali*/
grep -rn "Ljava/lang/System;->load("       work/smali*/
grep -rn "Ldalvik/system/DexClassLoader"   work/smali*/
grep -rn "Ldalvik/system/InMemoryDexClassLoader" work/smali*/
```

---

## SDK package-prefix map (abridged)

| Prefix | SDK | Category |
|---|---|---|
| `okhttp3.` / `okio.` | OkHttp | HTTP |
| `retrofit2.` | Retrofit | HTTP |
| `com.google.gson.` / `com.squareup.moshi.` | Gson / Moshi | JSON |
| `com.google.android.gms.` | Play services | Platform |
| `com.google.firebase.` | Firebase | Multiple |
| `com.google.firebase.crashlytics.` | Crashlytics | Crash |
| `io.sentry.` / `com.bugsnag.` | Sentry / Bugsnag | Crash |
| `com.amplitude.` / `com.mixpanel.` / `com.segment.analytics.` | Analytics | Analytics |
| `com.appsflyer.` / `com.adjust.sdk.` | AppsFlyer / Adjust | Attribution |
| `com.google.android.gms.ads.` / `com.applovin.` / `com.ironsource.` | Ads | Advertising |
| `com.stripe.android.` / `com.braintreepayments.` / `com.paypal.` | Payments | Payments |
| `com.android.billingclient.` | Play Billing | Payments |
| `com.onesignal.` / `com.urbanairship.` / `com.braze.` | Push / engagement | Push |
| `com.bumptech.glide.` / `coil.` / `com.squareup.picasso.` / `com.facebook.drawee.` | Image loaders | Media |
| `com.google.android.exoplayer2.` / `androidx.media3.` | ExoPlayer / Media3 | Media |
| `org.bouncycastle.` / `com.google.crypto.tink.` | BouncyCastle / Tink | Crypto |
| `net.sqlcipher.` / `io.realm.` / `androidx.room.` | SQLCipher / Realm / Room | Storage |
| `com.facebook.react.` + `libhermes.so` | React Native | Framework |
| `io.flutter.` + `libflutter.so` | Flutter | Framework |
| `com.unity3d.` + `libil2cpp.so` | Unity | Game engine |

---

## Supply chain classes and controls

| Class | Gradle control |
|---|---|
| Dependency confusion | `exclusiveContent { }` / `content { includeGroupByRegex }` on repositories |
| Typosquatting | Approved-dependency list; private mirror allow-list |
| Maintainer compromise | `gradle/verification-metadata.xml` (checksums + PGP) |
| Build compromise | Provenance attestation; reproducible builds |
| Malicious by design | Traffic audit; SDK intake review |
| Abandonment | Dependency freshness monitoring |
| Transitive shadowing | Dependency locking + full tree review |

```bash
./gradlew :app:dependencies --configuration releaseRuntimeClasspath
./gradlew :app:dependencyInsight --configuration releaseRuntimeClasspath --dependency okhttp
ls gradle/dependency-locks/ gradle/verification-metadata.xml
```

```groovy
// The dependency-confusion fix, in full
repositories {
    exclusiveContent {
        forRepository { maven { url = uri("https://artifactory.internal.example/repo") } }
        filter { includeGroupByRegex("com\\.acme\\..*") }
    }
    google()
    mavenCentral()
}
```

---

## Rating rubric

| Factor | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| Known vulnerability | none | low / unused component | medium-high, plausible path | critical, API present |
| Reachability | stripped out | present, no external path | app-internal data only | network or cross-app |
| Data sensitivity | none | device metadata | behavioural | credentials / financial / health / precise location |
| Remote behaviour control | none | inert config | can flip a security control | **can deliver code** |
| Maintenance | current | 1–2 behind | >2 years stale | abandoned |
| Provenance | verified Maven | Maven, unverified | JitPack / third-party repo | unknown prebuilt |

| Total | Rating |
|---|---|
| 0–3 | Informational |
| 4–7 | Low |
| 8–11 | Medium |
| 12–14 | High |
| 15+ | Critical |

Override: **Remote behaviour control = 3 is always at least High.**

---

## Version matrix

| Android | API | Library-layer change |
|---|---|---|
| 5.0 | 21 | ART only; PIE required |
| 7.0 | 24 | **Linker namespaces enforced**; mediaserver split; user CAs untrusted by default |
| 8.0 | 26 | Treble; `/vendor` separation |
| 9 | 28 | Non-SDK interface restrictions; cleartext off by default |
| 10 | 29 | **Mainline / APEX**; Conscrypt, resolver, media modularised |
| 11 | 30 | **Scudo default allocator**; package visibility; GWP-ASan |
| 12 | 31 | ART becomes a Mainline module |
| 14 | 34 | **CA store under APEX**; dynamic code files must be read-only for `targetSdk` 34 |
| 15–16 | 35–36 | Further Mainline expansion; MTE availability grows |

---

## Session checklist

- [ ] Pull every APK path `pm path` returns (base + splits)
- [ ] Native `.so` list per ABI
- [ ] `META-INF/*.version` stamps extracted
- [ ] Manifest: providers, authorities, meta-data, permissions, exported components
- [ ] Managed package prefixes → vendor map
- [ ] Per-`.so`: NEEDED, build ID, `.comment`, hardening, static-linkage symbols, version banners
- [ ] Code-loading indicators: `System.load(`, `DexClassLoader`, `InMemoryDexClassLoader`, assets
- [ ] Runtime: `/proc/<pid>/maps` vs APK contents — anything extra?
- [ ] Runtime: suspicious mappings (`/data/local/tmp`, sdcard, memfd, deleted)
- [ ] Network: every host attributed to an SDK, payloads decoded
- [ ] Rating rubric applied to every row
- [ ] Device API level and security patch recorded
- [ ] APEX module versions recorded
