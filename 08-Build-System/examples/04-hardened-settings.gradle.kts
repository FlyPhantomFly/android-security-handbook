// examples/04-hardened-settings.gradle.kts
// ---------------------------------------------------------------------------
// The single most important file in a Gradle project for supply-chain security,
// and the one reviewers skip.
//
// PURPOSE
//     settings.gradle(.kts) is evaluated during Gradle's INITIALISATION phase,
//     before any build.gradle exists as far as Gradle is concerned. It is the
//     only place where pluginManagement and dependencyResolutionManagement can
//     be declared, which makes it the only place where the set of parties
//     allowed to inject code into this build is defined.
//
//     Three questions answer themselves here in thirty seconds:
//       1. Which repositories are consulted, and in what order?
//       2. Is any of them constrained about WHICH coordinates it may answer for?
//       3. Can an individual module quietly add a repository of its own?
//
//     On a real client project the usual answers are "google, mavenCentral,
//     jitpack", "no", and "yes" — which together are a reportable
//     dependency-confusion exposure with no exploitation required.
//
// USAGE
//     Place at the project root as settings.gradle.kts. Diff a client's file
//     against this one and every difference is a discussion.
//
// SEE
//     ../README.md sections 3.7, 5.4.1, 9.5
// ---------------------------------------------------------------------------

// ===========================================================================
// pluginManagement — where PLUGINS come from.
//
// A plugin is resolved and its apply() method is CALLED during the
// configuration phase, with the full privileges of whoever ran ./gradlew.
// That happens for ./gradlew tasks, ./gradlew --dry-run, and plain IDE import.
// So the repositories below decide who may execute code on your CI runner
// while it is holding the release signing key.
// ===========================================================================
pluginManagement {
    // build-logic is an included build providing our convention plugins,
    // including the security gate. Local source, reviewed like any other code.
    includeBuild("build-logic")

    repositories {
        // Content filters mean each repository is only ASKED about the
        // coordinates it legitimately owns. A repository that is never asked
        // cannot answer with a substituted artefact.
        gradlePluginPortal {
            content {
                includeGroupByRegex("com\\.gradle(\\..*)?")
                includeGroupByRegex("org\\.gradle(\\..*)?")
            }
        }
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        mavenCentral {
            content {
                includeGroupByRegex("org\\.jetbrains(\\..*)?")
                // Everything else must be justified and added explicitly.
            }
        }
    }
}

// ===========================================================================
// dependencyResolutionManagement — where LIBRARIES come from.
// ===========================================================================
dependencyResolutionManagement {

    // THE line that stops a module quietly adding its own repository.
    // Without it, the repository set above is advisory rather than
    // authoritative, and a single `repositories { maven { url = ... } }` block
    // buried in a feature module's build file reopens everything.
    //
    //   FAIL_ON_PROJECT_REPOS  — a project-level repositories {} block is an error
    //   PREFER_SETTINGS        — project repositories are ignored with a warning
    //   PREFER_PROJECT         — the default; project repositories win (avoid)
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)

    repositories {

        // -------------------------------------------------------------------
        // 1. The INTERNAL repository is the ONLY source for internal groups.
        //
        //    This is the exact mechanism that closes dependency confusion.
        //    includeGroupByRegex means Gradle asks this repository about
        //    com.acme.* and nothing else; combined with the exclude on the
        //    public repositories below, com.acme.* can never be answered by
        //    a public repository, whatever version an attacker publishes.
        // -------------------------------------------------------------------
        maven {
            name = "acme-internal"
            url = uri("https://artifactory.acme.internal/artifactory/maven-release/")
            content {
                includeGroupByRegex("com\\.acme(\\..*)?")
            }
            // Credentials come from ~/.gradle/gradle.properties or the CI
            // secret store as acmeInternalUsername / acmeInternalPassword.
            // NEVER from a committed file.
            credentials(PasswordCredentials::class)
            authentication {
                create<BasicAuthentication>("basic")
            }
            // Reject a repository that is somehow reachable over plaintext.
            isAllowInsecureProtocol = false
        }

        // -------------------------------------------------------------------
        // 2. Google's Maven, restricted to the groups Google actually publishes.
        // -------------------------------------------------------------------
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }

        // -------------------------------------------------------------------
        // 3. Maven Central, explicitly forbidden from answering for our groups.
        //
        //    The exclude is belt-and-braces: the include filters above already
        //    mean Central is not consulted for com.acme.*. Declaring both makes
        //    the intent legible to the next reviewer, and survives someone
        //    later loosening the include filters.
        // -------------------------------------------------------------------
        mavenCentral {
            content {
                excludeGroupByRegex("com\\.acme(\\..*)?")
            }
        }

        // -------------------------------------------------------------------
        // 4. NO jitpack.
        //
        //    JitPack builds a library on demand from a git reference, so the
        //    code you compile can change with no change to this project, a tag
        //    can be re-pushed to a different commit, and the identity behind a
        //    coordinate is a GitHub account rather than a verified namespace.
        //    Forks we need are reviewed once and republished to the internal
        //    repository above. See ../README.md section 5.4.6.
        // -------------------------------------------------------------------
    }

    // The single reviewed dependency inventory. Every coordinate in the project
    // resolves through this file, so `git log gradle/libs.versions.toml` is a
    // complete history of what third-party code this application has ever
    // contained.
    versionCatalogs {
        create("libs") {
            from(files("gradle/libs.versions.toml"))
        }
    }
}

// ===========================================================================
// Project structure
// ===========================================================================
rootProject.name = "acme-android"

include(":app")
include(":core")
include(":feature:payments")
include(":feature:profile")

// ===========================================================================
// Build cache.
//
// A remote build cache stores TASK OUTPUTS keyed by a hash of task inputs. A
// cache hit means Gradle skips the work and copies the stored output — so
// anything that can WRITE to the cache can substitute compiled classes without
// touching a line of source. Push access therefore belongs to trusted CI only,
// and a release build should compile rather than fetch.
//
// See ../README.md section 5.4.7.
// ===========================================================================
buildCache {
    local {
        isEnabled = true
    }
    remote<HttpBuildCache> {
        url = uri("https://gradle-cache.acme.internal/cache/")
        isEnabled = true
        // Developers READ from the cache; only CI WRITES to it.
        isPush = System.getenv("CI") == "true"
        isAllowInsecureProtocol = false
        credentials {
            username = System.getenv("GRADLE_CACHE_USER")
            password = System.getenv("GRADLE_CACHE_PASSWORD")
        }
    }
}
