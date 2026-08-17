# 08 — Build System FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

### 1. There are two build systems and I keep confusing them. How do I tell instantly which one someone means?

Look at the file name. `Android.bp` or `Android.mk` means the **platform** build — someone is building
the operating system. `build.gradle` or `build.gradle.kts` means the **app** build — someone is building
one APK. Look at the command: `m`, `mm`, `lunch` are platform; `./gradlew` is app. They share no code
and no concepts. An application developer will go an entire career without running Soong.

---

### 2. Why does the platform not just use Gradle?

Three reasons. Scale: a full AOSP build is on the order of a hundred thousand compiler invocations
across a few thousand repositories, and Gradle's configuration model does not survive that. Language
diversity: AOSP is C, C++, Java, Kotlin, Rust, Go, assembly, AIDL, SELinux policy and shell, all needing
first-class support. And multi-target: nearly every module is built several times — device and host,
32-bit and 64-bit, system and vendor, in an APEX and out of it, with and without sanitizers — which
Soong expresses through variant mutators and Gradle has no equivalent of.

---

### 3. Is `build.gradle` really a program? It looks like configuration.

It really is a program. `android { ... }` is a method call taking a closure; `implementation("...")` is
a method call. Gradle *executes* the file in a JVM to discover what the build looks like. You can put
`File("/etc/passwd").readText()` in the middle of it and it will run. That is why opening an untrusted
Android project in Android Studio is equivalent to running a shell script as yourself: Studio runs the
configuration phase to populate the IDE.

---

### 4. So is `./gradlew --dry-run` safe on an untrusted project?

No, and this is the single most common misunderstanding in the chapter. `--dry-run` skips the
**execution** phase, which is where compilation happens. The **configuration** phase — where arbitrary
Groovy or Kotlin from `build.gradle`, from `buildSrc`, and from every applied plugin runs — executes in
full. So do `./gradlew tasks`, `./gradlew help`, and IDE project import. There is no read-only mode for
a Gradle build. Read untrusted build files in a text editor, in a container, offline.

---

### 5. What is `namespace` and how is it different from `applicationId`? They are usually the same string.

They are usually the same string and that is why the distinction is invisible until it bites.
`namespace` is the Java/Kotlin package into which `R` and `BuildConfig` are generated; it exists only at
compile time and never varies per variant. `applicationId` is the app's identity on the device: it
determines `/data/data/<applicationId>`, the sandbox UID mapping, what `PackageManager` returns, and
what Play uses as the listing key. `applicationIdSuffix = ".debug"` changes `applicationId` and not
`namespace`, which is exactly why a debug and a release build can coexist on one device while their
`BuildConfig` class lives at the same package name in both.

---

### 6. Why is there an exported `BroadcastReceiver` in the APK that is not in the source code I was given?

Because the manifest merger added it from a library. Every AAR ships its own `AndroidManifest.xml`, and
the merger combines the app's manifest with the manifest of every library in the dependency graph.
Libraries have the *lowest* priority — but lowest priority is not no priority: an element with no
counterpart in the app's manifest is added verbatim. Read
`app/build/outputs/logs/manifest-merger-<variant>-report.txt`; it names the source file *and the Maven
coordinate* of every addition.

---

### 7. How many components do libraries typically add?

In real applications, ten to forty. An analytics SDK adds a `ContentProvider` to self-initialise, a
crash reporter adds a receiver, a payments SDK adds a redirect activity, `androidx.startup` adds
`InitializationProvider`, an ad SDK adds several activities. Diff the merged manifest against
`src/main/AndroidManifest.xml` on any real project and you will see it.

---

### 8. If a library adds a permission, does the user see it?

Yes. `<uses-permission>` entries from libraries are merged into the final manifest exactly like
components, so they appear in the Play listing, in the app's permission list in Settings, and — for
dangerous permissions — in the runtime prompt the user is shown. Developers regularly discover their app
requests `ACCESS_FINE_LOCATION` because an SDK asked for it. `tools:node="remove"` on the
`<uses-permission>` element removes it, at the cost of whatever SDK functionality depended on it.

---

### 9. Does `tools:node="remove"` actually delete the library's code?

No. It removes the *manifest element*, so the component can no longer be started by the system or by
another app. The library's classes are still in `classes.dex` and still run. If the SDK's own
initialisation code expects that component to exist, you will get a runtime crash rather than a security
improvement — so the change must be tested. The durable answer is usually to remove or replace the SDK.

---

### 10. If I obfuscate with R8, is my API key safe?

No. Obfuscation renames *identifiers* — classes, methods, fields. It never touches string *contents*.
Worse, a `buildConfigField` value is a `static final String` initialised with a compile-time constant,
so `javac` inlines it into every call site before R8 ever sees the code. The literal is in the DEX
string pool, `strings classes.dex | grep` finds it in a second, and there is no ProGuard or R8 setting
that changes this. The only way to stop shipping a secret is to stop shipping it.

---

### 11. Then why can I not find the `BuildConfig` class in a decompiled release APK?

Because after `javac` inlined every constant, nothing referenced `BuildConfig` any more, so R8's tree
shaker legitimately deleted the class. The *values* are all still there, scattered through the DEX at
each place they were used. If you cannot find `BuildConfig`, search for the values — URLs, key prefixes,
the strings `"release"` and `"debug"` — not the class name.

---

### 12. Is a Firebase or Google Maps API key a critical finding?

Almost never, and reporting it as one damages your credibility for the rest of the report. Those keys
are *designed* to ship; they are identifiers, not secrets, and their security comes from server-side
restrictions — SHA-1 plus package-name allowlists for Maps, security rules for Firebase, redirect-URI
validation for OAuth public clients. The real finding is when those restrictions are absent: an
unrestricted Maps key is a billing issue, and an open Firebase database is a genuine data-exposure
finding that you demonstrate by reading data, not by quoting the key. A `sk_live_` Stripe key, an AWS
secret access key, or a static server bearer token *is* critical, because it grants authority directly.

---

### 13. What actually happens if a production app ships with `debuggable="true"`?

Any user, on any unrooted device, with a USB cable, can run `adb shell run-as <package>` and read the
entire private data directory: shared preferences, the SQLite databases, cached tokens, everything. They
can also attach a JDWP debugger and execute code inside the app process. It requires no root, no
exploit and no chained precondition. It is one of the few Android findings that is High or Critical on
its own.

---

### 14. `BuildConfig.DEBUG` is false in release, so my logging is stripped. Is that true?

Partly, and the exception matters. `BuildConfig.DEBUG` is a `static final boolean`, so
`if (BuildConfig.DEBUG) { Log.d(TAG, token); }` is eliminated by `javac` at compile time — the guarded
block never reaches the `.class` file. That is genuine. But it only works for *direct* references to the
constant. `if (isDebug())` where `isDebug()` returns `BuildConfig.DEBUG` is a method call, so no constant
folding occurs. And `Log.d(TAG, "token=" + token)` with no guard at all ships unconditionally, because
`Log.d` is a real method that R8 removes only with `-assumenosideeffects` and optimisation enabled. In
real applications, most logging ships.

---

### 15. How do I tell whether an APK is a debug or a release build?

Two reliable signals. `apksigner verify --print-certs app.apk` — a subject containing
`CN=Android Debug, O=Android, C=US` is conclusive. And `aapt2 dump badging app.apk | grep
application-debuggable`. Obfuscated class names are **not** a reliable signal: `minifyEnabled` is an
independent build-type setting and plenty of release builds ship unobfuscated so crash reports stay
readable.

---

### 16. The `proguard-rules.pro` looks fine but nothing is obfuscated. What did I miss?

`app/build/outputs/mapping/release/configuration.txt`. That is the **merged** R8 configuration and it
includes every dependency's `consumer-rules.pro` / `proguard.txt`, which AGP applies silently. One AAR
shipping `-keep class ** { *; }` or `-dontobfuscate` disables obfuscation for the entire application,
and nothing in the app's own repository shows it. Grep `configuration.txt` first; the finding then names
a specific dependency, which is a materially more useful report.

---

### 17. What is `mapping.txt` and why do you keep warning about it?

It is the file R8 writes mapping obfuscated names back to original ones, at
`app/build/outputs/mapping/<variant>/mapping.txt`. Anyone holding it can fully de-obfuscate the shipped
APK, which is the whole point of obfuscation undone in one file. It leaks by being committed to the
repository, attached to a public GitHub release, accidentally packaged inside the APK, or through a
compromised crash-reporting account (Crashlytics, Sentry, Bugsnag all receive it).

---

### 18. `implementation` versus `api` — I have read the docs and still do not get it.

Both put the dependency on *your* compile classpath and both package it into the APK. The difference is
what *consumers of your module* see. With `api`, anyone who depends on your module also gets that
dependency's types on their compile classpath, whether they want them or not. With `implementation`,
they do not. The build-speed argument is real but the useful framing is that `api` is a **transitive
trust declaration**: a graph full of `api` is one where a single compromised leaf artefact is visible
and callable from every module.

---

### 19. Is a dependency listed in `build.gradle` definitely in the APK?

No, in both directions. A `compileOnly` dependency is on the compile classpath and **not packaged** —
touching it at runtime throws `NoClassDefFoundError`. And a transitive dependency that nobody named is
very much in the APK. The authoritative list is
`./gradlew :app:dependencies --configuration releaseRuntimeClasspath`, and the truly authoritative one
is what you find inside the shipped artefact.

---

### 20. What is dependency confusion, in one paragraph, for Gradle specifically?

Gradle asks declared repositories in order and takes the first that has the module; version conflicts
then resolve to the highest version. If a project declares a public repository alongside an internal one
and does not constrain which coordinates each may answer for, an attacker who publishes your internal
coordinate to the public repository — or publishes a higher version of it — may have their artefact
resolved and executed. The fix is repository **content filtering**: `content {
includeGroupByRegex("com\\.acme.*") }` on the internal repository, `excludeGroupByRegex` on the public
ones, `repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)` so no module can quietly add a
repository, and `gradle/verification-metadata.xml` for checksum pinning.

---

### 21. Should I prove dependency confusion by publishing the package?

No. Publishing to a namespace you do not own is at best a terms-of-service violation and at worst an
unauthorised-access offence, it affects every other consumer of that coordinate, and it cannot be
undone. The correct proof is documentary: show the coordinate is unclaimed on the public repository and
show the build's repository declaration order. That is sufficient for any competent reviewer.

---

### 22. What is `buildSrc` and why does everyone say to read it?

If a directory named `buildSrc` exists at the root of a Gradle build, Gradle compiles it as a separate
project **before evaluating anything else** and puts its output on the classpath of every build script.
So its code runs on every invocation, before your build files, with full privileges, and can modify
dependency resolution, add tasks, or rewrite outputs. It also looks like ordinary project code in a
review UI, and is routinely excluded from security review as "just build tooling". `build-logic` with
`includeBuild` is the modern equivalent. Read every line of both.

---

### 23. Why is `gradle-wrapper.jar` a security concern? It is just a downloader.

It is a **binary committed to the repository that executes on the first `./gradlew`**. Nothing about a
code review shows you its contents. Check two things: that `gradle-wrapper.properties` has a
`distributionSha256Sum` (its absence means the wrapper accepts whatever the URL serves) and that the JAR
matches the official checksum for its Gradle version from `https://gradle.org/release-checksums/`. Both
checks take seconds and give binary answers, which is rare in this field.

---

### 24. Why is JitPack singled out?

Because it builds a library **from a Git reference on demand**. `com.github.user:lib:master-SNAPSHOT`
means "build whatever is on that branch right now". The code you compile can change without any change
to your repository, a tag can be deleted and re-pushed to a different commit, and the identity behind it
is a GitHub account rather than a verified Maven namespace. If you must use it, pin to a commit hash
and add verification checksums. Better: fork, review, publish internally, depend on that.

---

### 25. What is the difference between an APK and an AAB, and why does it change how I test?

An APK is installable. An AAB is a *publishing* format that a generator turns into per-device APKs —
Play is that generator, `bundletool` is the local equivalent. Three consequences for testing. The
certificate on the device is Play's signing with the **app signing key**, not the developer's upload
key, so a mismatch against their keystore is expected. The installed application is a **set** of APKs —
base plus ABI, density and language splits — so `adb shell pm path <pkg>` and pull all of them; a
base-only analysis will tell you an app has no native code when it has megabytes of it. And dynamic
feature modules can arrive after install, so exercise the app fully before concluding anything.

---

### 26. Is `bundletool --mode=universal` output good enough for analysis?

For static analysis, yes, and it is convenient. But it is not what any user runs, so any finding that
depends on split content — native libraries, per-density resources, a dynamic feature — must be
reproduced against the actual split set pulled from a device before it goes in a report.

---

### 27. Why must `zipalign` run before `apksigner` and not after?

Because signature schemes v2 and later cover the exact byte layout of the whole file. Re-aligning after
signing moves bytes, so the signature no longer matches. If you rebuild an APK by hand and get
`INSTALL_PARSE_FAILED_NO_CERTIFICATES` or a v2 verification failure, this ordering is the first thing to
check.

---

### 28. What is `m snod` and why do platform researchers love it?

"System, No Dependencies". It repacks `system.img` from whatever is currently in
`out/target/product/<device>/system/`, without re-deriving whether those files are legitimately produced
by the tree. After one full build you can drop in a patched binary or a modified `sepolicy` and have a
flashable image in under a minute. It is the standard patch-flash-test loop for platform vulnerability
research. The corollary is that an `out/` directory produced by someone else is untrusted.

---

### 29. Why does a `userdebug` build matter so much in a report?

`ro.build.type=userdebug` means `ro.debuggable=1`, which means `run-as` works on *every* application on
the device and `adb root` is available. On an `eng` build, `ro.secure=0` as well, and SELinux may be
permissive. Finding a production handset, kiosk, set-top box or in-vehicle unit reporting `userdebug`
is usually worth more than the rest of the engagement, and it is a decision the **platform build system**
made — via the variant, not via any application's code. Check it first: `adb shell getprop
ro.build.type`.

---

### 30. What does `certificate: "platform"` in an `Android.bp` file mean?

The APK is signed with the platform signing key. Combined with `android:sharedUserId="android.uid.system"`
it means the app runs with the system UID, sharing a process identity with core system services.
Compromising such an app compromises the platform. It also means the app can hold `signature`-level
permissions declared by the platform. When reviewing a device image, group every APK by signing
certificate digest — everything sharing the platform digest is one trust domain.

---

### 31. The AOSP test keys are public? Really?

Yes. `platform.pk8`, `platform.x509.pem`, `shared`, `media` and `testkey` are in
`build/make/target/product/security/` in the public AOSP tree, so that a fresh checkout builds and boots.
Every real product is expected to re-sign with private keys via
`build/make/tools/releasetools/sign_target_files_apks.py`. Devices ship that skipped this step — usually
inexpensive set-top boxes, tablets and IoT panels — and on those, anyone can build a platform-signed
app. It is a total compromise of platform trust and it takes one `apksigner verify --print-certs` to
find.

---

### 32. What is `genrule` and why does it come with a warning?

`genrule` is the one Blueprint module type that runs an arbitrary shell command (`cmd:`) to produce its
outputs. Every other part of `Android.bp` is pure data. So in a Soong-based tree, `genrule` is the only
place a build-time backdoor can live, which also makes it easy to audit: `grep -rn "genrule"
--include=Android.bp` and read every `cmd:` string.

---

### 33. What is a "reproducible build" and why does it matter more for some apps than others?

A build is reproducible if the same source and toolchain produce bit-identical output. Signing tells you
*who* built an artefact; reproducibility tells you *what* they built. Without it, "the source is on
GitHub" is an unverifiable claim — the published APK could contain anything. That matters enormously for
a messaging app or a wallet, where users must trust that the binary matches audited source, and much
less for a retail app. It is also the only control that detects a trojanised build *after the fact*,
because every other control is enforced by the system under attack.

---

### 34. My Android builds are not reproducible. What are the usual culprits?

ZIP entry timestamps and file ordering (fixed with `isPreserveFileTimestamps = false` and
`isReproducibleFileOrder = true`), absolute paths embedded in debug info and `.so` files (fixed with
`-ffile-prefix-map`), `buildConfigField` values containing a timestamp, annotation processors that
iterate hash-ordered sets, unpinned AGP/R8/JDK/NDK versions, and dependency version ranges.

---

### 35. Can I just run MobSF and be done?

MobSF is a reasonable first pass and it parses build-relevant configuration well — manifest analysis,
certificate, native hardening flags. But its "hardcoded secrets" section flags anything with high
entropy or a matching keyword, so it reports Firebase keys, Base64 resources and UUIDs as secrets, and
its exported-component list is raw — it never reaches a component or assesses impact. Treat both as
candidate lists and validate each item by hand before it appears in a report.

---

### 36. What is the single highest-value thing to do first on a source-assisted Android review?

Open `settings.gradle(.kts)` and the merged manifest. The first tells you the supply-chain posture —
repositories, ordering, filtering, `repositoriesMode` — in thirty seconds. The second tells you the real
component surface, which is not what the developer's manifest says. Between them they routinely produce
two or three reportable findings before you have opened a single line of application code.

---

### 37. How do I safely get the merged manifest and `configuration.txt` from a client project I do not trust?

Build it in a disposable container with no network, no credentials mounted, and the project mounted
read-only where possible, then copy the reports out. If you need network access for dependency
resolution, put a logging proxy in front of it and review what the build contacted afterwards. And run
`strace -f -e trace=openat` once, grepping for `.ssh`, `.aws`, `.netrc` and `.gnupg` — a legitimate
Android build has no reason to open any of them.

---

### 38. Is `--scan` safe to use on a client's project?

No, not without written permission. A Build Scan uploads a detailed description of the build — module
names, dependency coordinates, plugin versions, environment details — to a Gradle-operated service and
produces a URL that is unauthenticated by default. It is a genuinely useful diagnostic and a genuine
data-disclosure event.

---

### 39. Where do secrets hide that a `strings classes.dex` search misses?

`resources.arsc`. `resValue("string", ...)` in Gradle, the Google Services plugin's processing of
`google-services.json`, and hand-written `res/values/secrets.xml` all land there, and the DEX contains
only the integer resource ID, never the string. Run `aapt2 dump resources app.apk | grep -iE
"key|token|secret|password|url"` on every APK — it takes two seconds. Assets are the other place; unzip
`assets/` and look at anything that is not what its extension claims.

---

### 40. I found a `.jks` in the repository but it is a private repo. Is that still a finding?

Yes. "Private" means readable by every current employee, every former employee whose access was not
revoked, every contractor, every CI integration, and any code-search or backup system with repo access —
and git history preserves it after a `git rm`. For a self-managed app signing key it is Critical:
whoever holds it can produce updates the platform accepts, obtain any `signature`-level permission the
vendor's app family declares, and join any `sharedUserId` those apps use. The remediation is rotation
plus moving to Play App Signing plus a secret store, and rotation does not undo the exposure for
versions already published.
