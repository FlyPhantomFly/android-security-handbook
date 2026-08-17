# 08 — Build System Mind Map

One diagram covering the whole chapter. Read it alongside [README.md](README.md).

```mermaid
mindmap
  root((Android Build System))

    A. PLATFORM BUILD
      Purpose
        Turns ~2000 git repos into partition images
        Scale multi-target partition correctness
      Soong
        Reads Android.bp
        Written in Go on Blueprint
        Declarative data no loops no shell
        Emits out/soong/build.ninja
        Mutators expand variants
          per architecture
          per image core vendor product ramdisk
          per link type shared static
          per sanitizer
      Blueprint
        JSON-like syntax
        No conditionals no env access
        Structured properties arch target
        soong_config_module_type for choices
      Kati
        Reimplementation of GNU Make
        Emits Ninja instead of executing
        Keeps legacy Android.mk alive
        Product and board config still Make
      Ninja
        Dumb and fast executor
        Pre-generated dependency graph
        Runs clang javac r8 aidl aapt2 checkpolicy
      Entry points
        source build/envsetup.sh
        lunch product-release-variant
        m mm mma mmm mmma
        m snod fast image repack
        m dist release artefacts
        m nothing parse only
      Build variants
        user debuggable 0 secure 1
        userdebug debuggable 1 adb root
        eng permissive adbd root
        ro.build.type is the giveaway
      Module types
        cc_library cc_binary cc_test
        java_library java_import
        android_app android_app_import
        android_library filegroup
        prebuilt_etc sh_binary apex
        aidl_interface rust_library
        cc_defaults java_defaults
        genrule THE shell escape
      Security properties
        certificate platform shared media testkey
        privileged true means priv-app
        platform_apis true internal API surface
        vendor_available apex_available
        sanitize cfi integer_overflow hwasan
        visibility build-time access control
        init_rc turns a binary into a daemon
      SELinux policy
        te files plus context files
        m4 macro expansion
        checkpolicy to CIL
        secilc links plat and vendor
        sepolicy_freeze_test treble tests
        precompiled_sepolicy hash mismatch reboots slower
      Bazel migration
        bp2build generates BUILD.bazel
        Starlark deterministic sandboxed
        Between Blueprint data and Gradle code
      Output tree
        out/soong/soong.variables whole product config
        out/target/product/dev/system
        out/target/product/dev/symbols UNSTRIPPED
        installed-files.txt inventory
        module-info.json module to path
      Platform supply chain
        prebuilts checked-in toolchains
        genrule cmd strings
        Android.mk shell escapes
        java_import android_app_import prebuilts
        repo manifest revisions branch vs SHA
        sign_target_files_apks re-signing
        AOSP test keys are PUBLIC

    B. APP BUILD
      Gradle
        General purpose JVM build tool
        Knows nothing about Android alone
        Task DAG with declared inputs outputs
        Daemon caches configuration
      AGP
        com.android.tools.build gradle
        Registers all Android tasks
        The android block is its extension
      Three phases
        Initialisation settings.gradle
          pluginManagement
          dependencyResolutionManagement
          include projects
        Configuration every build.gradle
          ARBITRARY CODE RUNS HERE
          plugins applied
          tasks registered not run
          runs for tasks dry-run and IDE import
        Execution
          only out-of-date tasks
          input hashing
      Key files
        settings.gradle repositories and order
        build.gradle root buildscript classpath
        build.gradle module the android block
        gradle.properties flags and leaked secrets
        local.properties SDK paths and leaked secrets
        libs.versions.toml the inventory
        gradle-wrapper.properties distributionUrl and sha
        gradle-wrapper.jar a committed binary
        buildSrc build-logic runs first
        proguard-rules.pro keep rules
        verification-metadata.xml absence is a finding
      DSL
        namespace vs applicationId
        minSdk targetSdk compileSdk
        buildTypes debug release
        productFlavors and flavorDimensions
        sourceSets merge ladder
        signingConfigs and scheme toggles
        buildFeatures buildConfig viewBinding
        packaging useLegacyPackaging
      Dependency configurations
        implementation default
        api transitive trust declaration
        compileOnly NOT in the APK
        runtimeOnly not on compile CP
        debugImplementation variant scoped
        annotationProcessor kapt ksp
      Variants
        type times flavour per dimension
        source set priority main flavor combo type variant
        Java concatenates resources overlay

    PIPELINE
      Manifest processing first
        Manifest merger
        Placeholder substitution
        merged AndroidManifest plus report
      Resources
        aapt2 compile per file to flat
        resource merge overlay order
        aapt2 link once per variant
        resources.arsc binary manifest R.java
        aapt_rules.txt auto keep rules
        resource shrinker
      Managed code
        kotlinc then javac
        annotation processors kapt KSP
        desugaring lambdas java.time
        D8 translate only
        R8 shrink optimise obfuscate dex
        mapping seeds usage configuration txt
      Native
        externalNativeBuild CMake or ndk-build
        clang per abiFilters
        strip debugSymbolLevel
        lib per abi so files
      Packaging
        merge dex arsc res assets lib
        ZIP with compression policy
        zipalign BEFORE apksigner
        apksigner v1 v2 v3 v3.1 v4
      Bundle path
        bundletool build-bundle
        aab is not installable
        Play generates and signs splits
        dynamic feature modules on demand

    ATTACK SURFACE 1 THE ARTEFACT
      Manifest merger injection
        libraries are lowest priority not no priority
        activity service receiver provider
        uses-permission you never requested
        queries and meta-data
        report names the Maven coordinate
        tools node remove replace removeAll
        removing the component leaves the code
      BuildConfig secrets
        static final inlined by javac
        DEX string pool at every use site
        R8 cannot remove a used constant
        resValue lands in resources.arsc
        manifestPlaceholders land in the manifest
        google-services.json lands in arsc
      Debug leakage
        debuggable true enables run-as and JDWP
        BuildConfig.DEBUG constant folding
        method wrapped DEBUG check survives
        testOnly blocks Play accepts adb install -t
        debug keystore is public
        debug source set trust-all TrustManager
        implementation instead of debugImplementation
      Shrinking and obfuscation
        minifyEnabled runs R8 not D8
        shrinkResources needs minifyEnabled
        keep class ** defeats everything
        mapping.txt undoes obfuscation
        library consumer rules merged silently
        configuration.txt is the truth
      Signing
        identity IS the public key
        no CA no revocation
        v3 lineage rotation breaks pinning
        Play App Signing upload key vs app key
        device certificate is Google's not the developer's

    ATTACK SURFACE 2 THE BUILD
      Eight channels of executable content
        declared dependencies
        transitive dependencies nobody chose
        Gradle plugins at configuration time
        buildSrc build-logic first
        gradle-wrapper.jar
        the Gradle distribution
        remote build cache
        annotation processors
      Dependency confusion
        repositories asked in order
        highest version wins
        public repo answers for internal coordinate
        FIX content filtering include exclude group regex
        FIX FAIL_ON_PROJECT_REPOS
        FIX verification-metadata
        NEVER prove it by publishing
      Malicious Gradle plugin
        apply runs immediately
        reads ssh aws keystore env
        or rewrites classes between compile and dex
        clean repo trojanised APK
      buildSrc and build-logic
        compiled and run before everything
        looks like project code
        resolutionStrategy dependencySubstitution hiding place
      Wrapper
        distributionUrl must be services.gradle.org
        distributionSha256Sum absence is a finding
        jar sha256 vs gradle.org release-checksums
      Maven artefacts
        account takeover
        typosquatting
        abandoned coordinate reuse
        consumer-rules.pro injection
      JitPack
        builds from a branch on demand
        master-SNAPSHOT changes under you
        identity is a GitHub account
        pin a commit hash if you must
      Build cache poisoning
        memoisation table for an assumed-pure function
        write access equals source edit
        push only from CI
        no-build-cache for releases

    DEFENCES
      Repository content filtering
      FAIL_ON_PROJECT_REPOS
      verification-metadata sha256 and pgp
      Exact versions no ranges no SNAPSHOT
      Review buildSrc as production code
      Credential-free ephemeral build container
      Sign in a separate minimal-permission job
      Play App Signing resettable upload key
      Reproducible builds plus independent rebuild
      Build-time security gate task
        fail on unreviewed exported component
        fail on unreviewed permission
        fail on debuggable release
      Lint abortOnError in CI

    ANALYSIS
      Source assisted checklist 33 items
        repository shape
        identity and surface
        release hardening
        secrets and configuration
        dependencies declared and resolved
        native flags
        CI and process
      From the APK alone
        app-metadata.properties AGP version
        version-control-info.textproto git commit
        META-INF version files library versions
        kotlin-tooling-metadata.json
        DebugProbesKt.bin debug dependency shipped
        BNDLTOOL signature came from an AAB
        stamp-cert-sha256 came through Play
      Dynamic
        run untrusted builds in a container
        strace openat for ssh aws netrc
        proxy the build and list contacted hosts
        Frida dump BuildConfig and meta-data
        ApplicationInfo flags and splitSourceDirs
        never --scan without permission
      Evidence artefacts
        manifest-merger report
        configuration seeds usage txt
        apksigner print-certs
        pm path for the full split set
```
