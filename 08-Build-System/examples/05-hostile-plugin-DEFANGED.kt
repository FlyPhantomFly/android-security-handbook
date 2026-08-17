/*
 * examples/05-hostile-plugin-DEFANGED.kt
 * ===========================================================================
 * DEFANGED DEMONSTRATION — reads nothing, sends nothing, changes nothing.
 *
 * PURPOSE
 *     Make the capability of a Gradle plugin concrete during a review
 *     conversation with a development team. Developers reliably underestimate
 *     what `plugins { id("...") version "..." }` grants, because the syntax
 *     looks like configuration. This file shows, in code they can read, that
 *     applying a plugin is arbitrary code execution at the privilege of
 *     whoever ran ./gradlew — which on CI is the holder of the release signing
 *     key and the Play Console credentials.
 *
 * WHAT IT ACTUALLY DOES
 *     It prints the ABSOLUTE PATHS it *could* read and the environment
 *     variable NAMES (never values) it *could* see, and stops. It opens no
 *     file, no socket, and modifies no build output.
 *
 * DO NOT ADD EXFILTRATION TO THIS FILE.
 *     A printout is more persuasive in a client meeting than a working implant,
 *     it is safe to run on their machine, and it does not create an artefact
 *     that could be misused or misattributed. If you need a working payload for
 *     an authorised red-team engagement, build it separately, under that
 *     engagement's rules of engagement, and do not keep it in a training
 *     repository.
 *
 * WHEN THIS CODE RUNS
 *     During Gradle's CONFIGURATION phase, which executes for:
 *         ./gradlew assembleRelease
 *         ./gradlew tasks
 *         ./gradlew help
 *         ./gradlew --dry-run          <-- yes, this one too
 *         opening the project in Android Studio / IntelliJ
 *     There is no read-only mode for a Gradle build.
 *
 * SETUP (to run the demonstration)
 *     build-logic/src/main/kotlin/DemoCapabilityPlugin.kt   <- this file
 *     app/build.gradle.kts:  plugins { id("com.demo.capability") }
 *     ./gradlew :app:tasks
 *
 * SEE
 *     ../README.md sections 3.7, 5.4.2, 5.4.3
 * ===========================================================================
 */

import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.File

class DemoCapabilityPlugin : Plugin<Project> {

    override fun apply(project: Project) {

        val log = project.logger
        val home = System.getProperty("user.home")

        log.lifecycle("")
        log.lifecycle("=".repeat(72))
        log.lifecycle("  GRADLE PLUGIN CAPABILITY DEMONSTRATION (defanged)")
        log.lifecycle("  This code is running RIGHT NOW, during configuration,")
        log.lifecycle("  as user '${System.getProperty("user.name")}'.")
        log.lifecycle("  Nothing below is read, opened, or transmitted.")
        log.lifecycle("=".repeat(72))

        // -------------------------------------------------------------------
        // 1. Files this process could read, if it chose to.
        //    We only test existence — File.exists() opens nothing.
        // -------------------------------------------------------------------
        log.lifecycle("")
        log.lifecycle("  [1] Credential files present and readable by this process:")

        val interesting = listOf(
            "$home/.gradle/gradle.properties"      to "signing passwords, repository credentials",
            "$home/.ssh/id_rsa"                    to "SSH private key",
            "$home/.ssh/id_ed25519"                to "SSH private key",
            "$home/.aws/credentials"               to "AWS access keys",
            "$home/.config/gcloud/credentials.db"  to "Google Cloud credentials",
            "$home/.docker/config.json"            to "registry credentials",
            "$home/.netrc"                         to "arbitrary host credentials",
            "$home/.android/debug.keystore"        to "debug signing key",
            "$home/.gnupg/secring.gpg"             to "PGP private keys",
            "$home/.npmrc"                         to "npm registry token",
            "$home/.git-credentials"               to "git credentials"
        )

        var found = 0
        interesting.forEach { (path, what) ->
            val f = File(path)
            if (f.exists() && f.canRead()) {
                found++
                log.lifecycle("      READABLE  $path")
                log.lifecycle("                -> $what (${f.length()} bytes)")
            }
        }
        if (found == 0) {
            log.lifecycle("      (none of the probed paths exist on this machine)")
        }

        // -------------------------------------------------------------------
        // 2. Environment variables this process can see.
        //    NAMES ONLY. Values are never printed, logged, or stored.
        // -------------------------------------------------------------------
        log.lifecycle("")
        log.lifecycle("  [2] Environment variable NAMES that look credential-bearing:")
        log.lifecycle("      (values deliberately NOT shown)")

        val suspicious = System.getenv().keys.filter { k ->
            listOf("TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL",
                   "AUTH", "API", "PRIVATE").any { k.uppercase().contains(it) }
        }.sorted()

        if (suspicious.isEmpty()) {
            log.lifecycle("      (none — good, or this is not a CI runner)")
        } else {
            suspicious.forEach { log.lifecycle("      $it = <redacted, ${System.getenv(it)?.length ?: 0} chars>") }
        }

        // -------------------------------------------------------------------
        // 3. Network capability. We do NOT connect; we state that we could.
        // -------------------------------------------------------------------
        log.lifecycle("")
        log.lifecycle("  [3] Network:")
        log.lifecycle("      This JVM has unrestricted outbound network access.")
        log.lifecycle("      A hostile plugin would POST the above to a remote host")
        log.lifecycle("      here, in three lines, before a single source file has")
        log.lifecycle("      been compiled. This plugin does not.")

        // -------------------------------------------------------------------
        // 4. The capability that actually matters, and that nobody expects.
        //
        //    Exfiltration is noisy and detectable. The dangerous version is
        //    SILENT MODIFICATION: a task that rewrites a compiled class between
        //    compilation and dexing, or a dependency substitution that swaps a
        //    library for a fork. The repository stays clean, code review finds
        //    nothing, and the shipped APK is trojanised and correctly signed.
        //
        //    Only an independent reproducible rebuild detects this.
        // -------------------------------------------------------------------
        log.lifecycle("")
        log.lifecycle("  [4] The capability that matters more than exfiltration:")
        log.lifecycle("      A plugin can register a task that runs BETWEEN")
        log.lifecycle("      compilation and dexing and rewrite the .class files,")
        log.lifecycle("      or substitute a dependency for a fork at resolution")
        log.lifecycle("      time. Source stays clean; the APK does not. Both are")
        log.lifecycle("      documented, legitimate Gradle features, which is")
        log.lifecycle("      exactly why they are good hiding places.")
        log.lifecycle("")
        log.lifecycle("      Legitimate-looking constructs to question in review:")
        log.lifecycle("        resolutionStrategy.dependencySubstitution { ... }")
        log.lifecycle("        resolutionStrategy.eachDependency { ... }")
        log.lifecycle("        tasks.named(\"...\") { doLast { /* rewrite outputs */ } }")
        log.lifecycle("        project.afterEvaluate { /* late, quiet changes */ }")

        // Example of the substitution construct, commented out so that it is
        // readable without being active. Uncommenting this would silently
        // redirect every okhttp dependency in the build.
        //
        // project.configurations.configureEach {
        //     resolutionStrategy.dependencySubstitution {
        //         substitute(module("com.squareup.okhttp3:okhttp"))
        //             .using(module("com.attacker.mirror:okhttp:4.12.0"))
        //     }
        // }

        // -------------------------------------------------------------------
        // 5. The controls that actually close this.
        // -------------------------------------------------------------------
        log.lifecycle("")
        log.lifecycle("  [5] Controls, strongest first:")
        log.lifecycle("      - Build in an ephemeral container with NO credentials")
        log.lifecycle("        mounted; sign in a separate, minimal-permission job.")
        log.lifecycle("      - gradle/verification-metadata.xml: checksum and PGP")
        log.lifecycle("        pinning for every artefact INCLUDING plugins.")
        log.lifecycle("        ./gradlew --write-verification-metadata sha256,pgp help")
        log.lifecycle("      - Repository content filtering + FAIL_ON_PROJECT_REPOS.")
        log.lifecycle("      - Exact versions everywhere; no +, latest.release, or")
        log.lifecycle("        -SNAPSHOT; no JitPack branch references.")
        log.lifecycle("      - Review buildSrc / build-logic as production code.")
        log.lifecycle("      - Reproducible builds plus an independent rebuild —")
        log.lifecycle("        the ONLY control that detects [4] after the fact.")
        log.lifecycle("")
        log.lifecycle("=".repeat(72))
        log.lifecycle("")
    }
}
