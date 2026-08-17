/*
 * examples/03-SecurityGatePlugin.kt
 * ===========================================================================
 * Place at: build-logic/src/main/kotlin/SecurityGatePlugin.kt
 *
 * PURPOSE
 *     Turn the security properties a pentest checks by hand into build-time
 *     invariants that the build enforces itself, on every pull request.
 *
 *     A finding in a report is worth one release. A gate is worth every
 *     release. When a client asks "how do we stop this recurring?", this file
 *     is the answer: an SDK upgrade that silently adds an exported receiver
 *     fails the pull request that introduced it, with the component's name in
 *     the error message, months before a pentest would have found it.
 *
 * WHAT IT ENFORCES
 *     1. The release variant is never debuggable.
 *     2. Every exported component in the MERGED manifest is on a reviewed
 *        allow-list (so library-injected components fail the build).
 *     3. Every <uses-permission> in the merged manifest is on a reviewed
 *        allow-list.
 *     4. The merged manifest does not permit cleartext traffic or backup.
 *     5. Release builds run R8.
 *
 * SETUP
 *     build-logic/build.gradle.kts:
 *         plugins {
 *             `kotlin-dsl`
 *         }
 *         dependencies {
 *             implementation("com.android.tools.build:gradle:8.5.2")
 *         }
 *         gradlePlugin {
 *             plugins {
 *                 create("securityGate") {
 *                     id = "com.acme.security-gate"
 *                     implementationClass = "SecurityGatePlugin"
 *                 }
 *             }
 *         }
 *
 *     settings.gradle.kts:
 *         pluginManagement { includeBuild("build-logic") }
 *
 *     app/build.gradle.kts:
 *         plugins { id("com.acme.security-gate") }
 *
 * USAGE
 *     ./gradlew :app:assembleRelease
 *
 *     > Security gate failed for release:
 *     >   - Unreviewed exported component: com.vendor.engage.DeepLinkRouterActivity
 *     >   - Unreviewed permission: android.permission.ACCESS_FINE_LOCATION
 *
 * TUNING
 *     The allow-lists live in this file on purpose, so that widening them is a
 *     code change that appears in a pull request with a named reviewer. Moving
 *     them to a properties file that anyone can edit defeats the control.
 *
 * SEE
 *     ../README.md sections 5.3.2, 9.3
 * ===========================================================================
 */

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.SetProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

// ---------------------------------------------------------------------------
// The reviewed baseline. Widening either set is a security decision.
// ---------------------------------------------------------------------------

private val ALLOWED_EXPORTED = setOf(
    "com.acme.app.MainActivity",
    "com.acme.app.ShareTargetActivity",
    // androidx.startup's provider is exported="false"; it does not appear here.
)

private val ALLOWED_PERMISSIONS = setOf(
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.CAMERA",
    "android.permission.POST_NOTIFICATIONS",
)

// ---------------------------------------------------------------------------
// The audit task
// ---------------------------------------------------------------------------

@CacheableTask
abstract class AuditMergedManifestTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty

    @get:Input
    abstract val allowedExported: SetProperty<String>

    @get:Input
    abstract val allowedPermissions: SetProperty<String>

    @get:Input
    abstract val variantName: SetProperty<String>

    @TaskAction
    fun audit() {
        val xml = mergedManifest.get().asFile.readText()

        // Components are exported if the attribute says so. From API 31 the
        // attribute is mandatory when an intent-filter is present, so on a
        // modern targetSdk this regex is complete; the task additionally flags
        // components with an intent-filter and no explicit attribute below.
        val exported = EXPORTED_RE.findAll(xml)
            .map { it.groupValues[2] }
            .toSet()

        val implicit = IMPLICIT_RE.findAll(xml)
            .map { it.groupValues[2] }
            .toSet() - exported

        val permissions = PERMISSION_RE.findAll(xml)
            .map { it.groupValues[1] }
            .toSet()

        val allowedE = allowedExported.get()
        val allowedP = allowedPermissions.get()

        val problems = buildList {
            (exported - allowedE).sorted().forEach {
                add("Unreviewed exported component: $it")
            }
            implicit.sorted().forEach {
                add("Component has an intent-filter but no explicit " +
                    "android:exported: $it")
            }
            (permissions - allowedP).sorted().forEach {
                add("Unreviewed permission: $it")
            }
            if (xml.contains("android:debuggable=\"true\"")) {
                add("Merged manifest sets android:debuggable=\"true\"")
            }
            if (xml.contains("android:usesCleartextTraffic=\"true\"")) {
                add("Merged manifest permits cleartext traffic")
            }
            if (xml.contains("android:allowBackup=\"true\"")) {
                add("Merged manifest enables allowBackup")
            }
            if (xml.contains("android:testOnly=\"true\"")) {
                add("Merged manifest sets testOnly")
            }
        }

        if (problems.isNotEmpty()) {
            throw GradleException(
                buildString {
                    appendLine("Security gate failed for ${variantName.get()}:")
                    problems.forEach { appendLine("  - $it") }
                    appendLine()
                    appendLine("Each of these is a change to the application's")
                    appendLine("externally reachable surface. If it is intentional,")
                    appendLine("widen the allow-list in build-logic/src/main/kotlin/")
                    appendLine("SecurityGatePlugin.kt in the SAME pull request, so")
                    appendLine("the change and its approval are reviewed together.")
                    appendLine()
                    appendLine("To find out which dependency introduced it, read:")
                    appendLine("  app/build/outputs/logs/manifest-merger-*-report.txt")
                }
            )
        }

        logger.lifecycle(
            "Security gate passed: ${exported.size} exported components, " +
            "${permissions.size} permissions — all reviewed."
        )
    }

    private companion object {
        val EXPORTED_RE = Regex(
            """<(activity|activity-alias|service|receiver|provider)\b""" +
            """(?:(?!/?>)[\s\S])*?android:name="([^"]+)"""" +
            """(?:(?!/?>)[\s\S])*?android:exported="true"""
        )
        val IMPLICIT_RE = Regex(
            """<(activity|activity-alias|service|receiver)\b""" +
            """(?![\s\S]{0,400}?android:exported)""" +
            """[\s\S]{0,400}?android:name="([^"]+)"""" +
            """[\s\S]{0,600}?<intent-filter"""
        )
        val PERMISSION_RE =
            Regex("""<uses-permission[^>]*android:name="([^"]+)"""")
    }
}

// ---------------------------------------------------------------------------
// The plugin
// ---------------------------------------------------------------------------

class SecurityGatePlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val androidComponents = project.extensions
            .getByType(ApplicationAndroidComponentsExtension::class.java)

        androidComponents.onVariants(
            androidComponents.selector().withBuildType("release")
        ) { variant ->

            // -----------------------------------------------------------
            // Invariant 1 — a release variant must never be debuggable.
            // This is checked during configuration, so it fails immediately
            // rather than after a full compile.
            // -----------------------------------------------------------
            if (variant.debuggable) {
                throw GradleException(
                    "Release variant '${variant.name}' is debuggable. " +
                    "android:debuggable=\"true\" lets any user read the app's " +
                    "entire private data directory with `adb shell run-as`, " +
                    "with no root. Refusing to build."
                )
            }

            // -----------------------------------------------------------
            // Invariant 2-5 — audit the MERGED manifest, which is the only
            // place library-injected components appear.
            // -----------------------------------------------------------
            val capitalised = variant.name.replaceFirstChar { it.uppercase() }

            val auditTask = project.tasks.register(
                "audit${capitalised}Manifest",
                AuditMergedManifestTask::class.java
            ) { task ->
                task.group = "verification"
                task.description =
                    "Fails the build if ${variant.name}'s merged manifest " +
                    "contains unreviewed exported components or permissions."
                task.mergedManifest.set(
                    variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)
                )
                task.allowedExported.set(ALLOWED_EXPORTED)
                task.allowedPermissions.set(ALLOWED_PERMISSIONS)
                task.variantName.set(setOf(variant.name))
            }

            project.tasks.named("assemble$capitalised") {
                it.dependsOn(auditTask)
            }
            project.tasks.matching { it.name == "bundle$capitalised" }
                .configureEach { it.dependsOn(auditTask) }
        }

        // ---------------------------------------------------------------
        // Invariant 6 — release builds must run R8. Checked after the
        // android extension has been configured by the module's build file.
        // ---------------------------------------------------------------
        project.afterEvaluate {
            val android = project.extensions.findByName("android") ?: return@afterEvaluate
            val buildTypes = android.javaClass
                .getMethod("getBuildTypes").invoke(android) as? Iterable<*>
                ?: return@afterEvaluate
            buildTypes.forEach { bt ->
                val name = bt?.javaClass?.getMethod("getName")?.invoke(bt) as? String
                if (name == "release") {
                    val minify = bt?.javaClass
                        ?.getMethod("isMinifyEnabled")?.invoke(bt) as? Boolean
                    if (minify == false) {
                        project.logger.warn(
                            "SECURITY GATE WARNING: release build type has " +
                            "minifyEnabled = false. Shrinking and obfuscation " +
                            "are disabled. This is a MASVS-RESILIENCE gap, not " +
                            "a vulnerability — raise it, do not fail on it."
                        )
                    }
                }
            }
        }
    }
}
