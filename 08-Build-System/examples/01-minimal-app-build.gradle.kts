// examples/01-minimal-app-build.gradle.kts
// ---------------------------------------------------------------------------
// A minimal Android application build file, annotated line by line.
//
// PURPOSE
//   Read this once and you can read any app/build.gradle.kts. Every line below
//   answers one of the questions in the pentester's checklist in
//   ../README.md section 5.5.
//
// USAGE
//   Place at app/build.gradle.kts in a project whose settings.gradle.kts
//   contains: include(":app")
//
//   ./gradlew :app:assembleRelease
//   aapt2 dump badging app/build/outputs/apk/release/app-release-unsigned.apk
//   cat app/build/outputs/mapping/release/configuration.txt
// ---------------------------------------------------------------------------

plugins {
    // The Android Gradle Plugin. Applying it is what registers the hundreds of
    // tasks (compileReleaseKotlin, mergeReleaseResources, minifyReleaseWithR8,
    // packageRelease, ...) that constitute an Android build. Without this line
    // Gradle knows nothing about Android at all.
    id("com.android.application")

    // Kotlin compilation. Kotlin compiles BEFORE Java, because Java may
    // reference Kotlin output through generated stubs.
    id("org.jetbrains.kotlin.android")
}

android {
    // The Java/Kotlin package into which R and BuildConfig are generated.
    // COMPILE TIME ONLY. It is not the app's identity and it never varies
    // per variant. Confusing this with applicationId is extremely common.
    namespace = "com.example.minimal"

    // The android.jar we compile against. Raising this gives access to newer
    // APIs; it does NOT by itself change runtime behaviour. That is targetSdk.
    compileSdk = 35

    defaultConfig {
        // The application's identity on the device and in Play. It determines
        // /data/data/<applicationId>, the sandbox UID mapping, what
        // PackageManager returns, and what an attacker must impersonate.
        applicationId = "com.example.minimal"

        // Oldest API level the app will install on. Every backwards-compatibility
        // decision in the build — desugaring, v1 signing, multidex — follows
        // from this number.
        minSdk = 24

        // THE security-relevant one. targetSdk is an opt-in declaration: the
        // platform applies behaviour changes (scoped storage, package
        // visibility, exported= being mandatory, pending-intent mutability
        // rules, ...) only up to this level. A low targetSdk means the app is
        // running under older, weaker platform rules.
        targetSdk = 35

        versionCode = 1          // monotonically increasing integer; Play's ordering key
        versionName = "1.0"      // the human-readable string; no semantics

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // NOTE: no buildConfigField with a credential. Ever. See README 5.3.1.
        // Non-secret configuration is fine and is what this mechanism is for:
        buildConfigField("String", "API_BASE", "\"https://api.example.com\"")
    }

    buildTypes {
        getByName("debug") {
            // Lets a debug build sit alongside a release build on one device.
            // Note this changes applicationId, NOT namespace, so BuildConfig
            // still lives at com.example.minimal in both.
            applicationIdSuffix = ".debug"

            // No R8: fast builds, readable stack traces, meaningful names in
            // a decompiler. This is correct for debug and fatal for release.
            isMinifyEnabled = false
        }

        getByName("release") {
            // Runs R8 instead of D8: tree shaking, optimisation, obfuscation
            // and dexing in one pass, plus mapping.txt / seeds.txt / usage.txt
            // / configuration.txt under build/outputs/mapping/release/.
            isMinifyEnabled = true

            // Requires isMinifyEnabled = true. Removes resources not referenced
            // from the shrunk code — which is how leftover debug layouts and
            // test assets get dropped.
            isShrinkResources = true

            // Explicit, even though false is the default, because this is the
            // line a reviewer looks for. See README 5.3.3.
            isDebuggable = false

            // The "-optimize" variant of the default file enables R8's
            // optimisation passes. The plain proguard-android.txt disables them.
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )

            // No signingConfig here on purpose: this example produces
            // app-release-unsigned.apk, so you can see that AGP will NOT
            // silently sign a release build with the debug key.
            // In a real project: signingConfig = signingConfigs.getByName("release")
            // with credentials read from the environment. See 04-hardened-*.
        }
    }

    buildFeatures {
        // From AGP 8.0 this must be requested explicitly. If it is false,
        // there is no BuildConfig class at all — which is a legitimate reason
        // for a decompiler not to show you one.
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            // false (the default for minSdk >= 23 since AGP 4.2) stores .so
            // files uncompressed and page-aligned so the linker can mmap them
            // straight out of the APK. Consequence for an analyst: do NOT
            // expect extracted .so files in the app's native library directory.
            useLegacyPackaging = false
        }
    }

    lint {
        // Lint finds real security issues: exported components, trust-all
        // TrustManagers, cleartext traffic, insecure PendingIntents. Failing
        // the build on them is the cheapest control in this file.
        abortOnError = true
        checkReleaseBuilds = true
    }
}

dependencies {
    // `implementation` is the default and the right answer unless you have a
    // specific reason. It puts the artefact on YOUR compile classpath and in
    // the APK, but not on the compile classpath of anyone who depends on this
    // module. See README 3.11 for the api / compileOnly / runtimeOnly table.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")

    // Debug-only tooling goes on debugImplementation, NEVER implementation.
    // Getting this wrong is how Flipper, Chucker and LeakCanary reach
    // production. See README 5.3.3.
    // debugImplementation("com.squareup.leakcanary:leakcanary-android:2.14")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
