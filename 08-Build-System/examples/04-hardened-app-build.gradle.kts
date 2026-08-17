// examples/04-hardened-app-build.gradle.kts
// ---------------------------------------------------------------------------
// The target-state application build file. Diff a client's app/build.gradle.kts
// against this one; every difference is either a justified product decision or
// a finding.
//
// PURPOSE
//     README section 9.5. This is the "what good looks like" artefact you hand
//     a development team after an engagement, so the remediation section of the
//     report is a diff rather than a paragraph.
//
// USAGE
//     Place at app/build.gradle.kts alongside
//     examples/04-hardened-settings.gradle.kts.
//
// SEE
//     ../README.md sections 3.8-3.20, 5.5, 9.5
// ---------------------------------------------------------------------------

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)

    // The convention plugin from examples/03-SecurityGatePlugin.kt.
    // Release-build security properties become build failures, not report
    // findings. See README 9.3.
    id("com.acme.security-gate")
}

android {
    namespace = "com.acme.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.acme.app"

        // minSdk 26 is a security decision as much as a product one: it lets us
        // disable v1 (JAR) signing, guarantees APK signature scheme v2
        // verification, and gives us the full modern network security config.
        minSdk = 26

        // Always the newest level the app has been tested against. A low
        // targetSdk opts the app OUT of platform hardening — scoped storage,
        // package visibility, mandatory android:exported, PendingIntent
        // mutability rules. Raising it is a security improvement.
        targetSdk = 35

        // Derived from CI, not from the clock, so the build stays reproducible.
        versionCode = providers.environmentVariable("BUILD_NUMBER")
            .orNull?.toIntOrNull() ?: 1
        versionName = "5.1.0"

        // Endpoints only. NO credentials — not plaintext, not Base64, not
        // XORed, not "obfuscated". A static final String is inlined by javac
        // and lands in the DEX string pool at every use site; no R8 setting
        // changes that. See README 3.12 and 5.3.1.
        buildConfigField("String", "API_BASE", "\"https://api.acme.com\"")

        // Only the ABIs we actually test and ship. Every extra ABI is another
        // set of native binaries to keep hardened and patched.
        ndk { abiFilters += listOf("arm64-v8a") }

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Explicit and empty: no placeholder is silently injected into the
        // merged manifest, which is a common place for credentials to appear.
        manifestPlaceholders.clear()
    }

    signingConfigs {
        create("release") {
            // Every value comes from the CI secret store. On a developer
            // machine these are absent, so a developer CANNOT produce a
            // release-signed artefact — which is the point. Signing happens in
            // one place, in a job with minimal permissions, over an artefact
            // that was built somewhere else.
            val ks = providers.environmentVariable("ANDROID_KEYSTORE_PATH").orNull
            if (ks != null) {
                storeFile = file(ks)
                storePassword =
                    providers.environmentVariable("ANDROID_KEYSTORE_PASSWORD").orNull
                keyAlias =
                    providers.environmentVariable("ANDROID_KEY_ALIAS").orNull
                keyPassword =
                    providers.environmentVariable("ANDROID_KEY_PASSWORD").orNull
            }

            // v1 is JAR signing: per-file digests that do not cover the ZIP
            // structure itself. Needed only for minSdk < 24. Ours is 26.
            enableV1Signing = false
            enableV2Signing = true   // whole-file integrity
            enableV3Signing = true   // + signing certificate lineage (rotation)
            enableV4Signing = true   // + Merkle tree for incremental install
        }
    }

    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            isMinifyEnabled = false
            // Debug-only network relaxations live in src/debug/, never here, so
            // the merger keeps them out of release by construction.
            // See app/src/debug/res/xml/network_security_config.xml.
        }

        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            signingConfig = signingConfigs.getByName("release")

            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )

            // SYMBOL_TABLE uploads a symbols file to Play for crash
            // symbolication WITHOUT shipping symbols inside the .so. FULL would
            // hand an analyst a fully symbolised native binary.
            ndk { debugSymbolLevel = "SYMBOL_TABLE" }

            // Modern AGP embeds the git repository URL and commit SHA into the
            // APK as META-INF/version-control-info.textproto. Useful for the
            // developer; also a free disclosure of internal infrastructure to
            // anyone holding the APK. See README 6.1.
            vcsInfo { include = false }
        }
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
        // Explicitly off: each of these generates code and enlarges the DEX.
        aidl = false
        renderScript = false
        shaders = false
    }

    packaging {
        jniLibs {
            // Uncompressed and page-aligned, so the linker mmaps them from
            // inside the APK. Consequence for an analyst: no extracted .so
            // files in the native library directory; look in /proc/<pid>/maps.
            useLegacyPackaging = false
        }
        resources {
            // Do not ship build-time metadata that only helps an analyst
            // inventory the app's dependencies.
            excludes += setOf(
                "META-INF/*.kotlin_module",
                "META-INF/*.version",
                "DebugProbesKt.bin",
                "kotlin-tooling-metadata.json",
                "**/*.proto"
            )
        }
    }

    // Lint finds real security issues: exported components, trust-all
    // TrustManagers, cleartext traffic, insecure PendingIntent flags, weak
    // crypto. Failing the build on them is the cheapest control here.
    lint {
        abortOnError = true
        warningsAsErrors = true
        checkReleaseBuilds = true
        checkDependencies = true
        // Disable only what is genuinely noise. Never disable a security check
        // without a comment saying why and who agreed.
        disable += setOf("GradleDependency", "ObsoleteLintCustomCheck")
        htmlReport = true
        sarifOutput = layout.buildDirectory.file("reports/lint.sarif").get().asFile
    }

    dependenciesInfo {
        // The dependency blob Play uses is also a complete inventory of the
        // app's third-party code for anyone holding the APK. Keep it in the
        // bundle Play receives; leave it out of the artefact users hold.
        includeInApk = false
        includeInBundle = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-Xjvm-default=all")
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    // Every coordinate resolves through gradle/libs.versions.toml, so the whole
    // third-party inventory is one reviewable file with a git history.
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.okhttp)

    coreLibraryDesugaring(libs.desugar.jdk.libs)

    // Debug-only tooling on debugImplementation. Writing `implementation` here
    // is how Flipper, Chucker, Stetho and LeakCanary reach production.
    debugImplementation(libs.leakcanary)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.junit)
}

// ---------------------------------------------------------------------------
// Reproducibility. See README 3.20.
//
// Signing tells you WHO built an artefact. Reproducibility tells you WHAT they
// built, and it is the only control that detects a trojanised build after the
// fact — because every other control is enforced by the system under attack.
// ---------------------------------------------------------------------------
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

// ---------------------------------------------------------------------------
// A release must never be assembled from cached task outputs. A poisoned remote
// cache substitutes compiled classes with no change to source; compiling from
// scratch removes that channel for the artefact users actually receive.
// ---------------------------------------------------------------------------
gradle.taskGraph.whenReady {
    if (allTasks.any { it.name.contains("Release") }) {
        allTasks.forEach { it.outputs.cacheIf { false } }
    }
}
