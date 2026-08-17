# Lab 03 — Supply-chain simulation

**Difficulty:** Advanced
**Time:** 3–4 hours
**Chapter:** [08 — The Android Build System](../README.md) §5.4

---

## Objective

Reproduce, entirely on your own machine and against your own artefacts, the three supply-chain
mechanisms that matter for Gradle:

1. **Repository-order resolution** — the mechanism behind dependency confusion.
2. **A plugin executing at configuration time** — arbitrary code before anything compiles.
3. **`buildSrc` rewriting build behaviour** — a clean repository producing a modified artefact.

Then close all three with the exact controls from §5.4 and prove they hold.

---

## Rules of engagement — read before starting

> **⚠️ Everything in this lab runs against a LOCAL Maven repository you create, in a project you own.**
>
> - Do **not** publish anything to Maven Central, the Gradle Plugin Portal, JitPack, or any other public
>   or shared repository. Publishing to a namespace you do not own is at best a terms-of-service
>   violation and at worst an unauthorised-access offence, it affects every other consumer of that
>   coordinate, and it cannot be undone.
> - Do **not** point any part of this lab at an employer's or client's internal repository.
> - The "malicious" plugin in Part B **prints** what it could reach and sends nothing. Keep it that way.
>   A printout is more persuasive in a client conversation than an implant, and it is safe to run.
>
> The correct professional proof of a dependency-confusion exposure is documentary: show the coordinate
> is unclaimed and show the build's repository order. Never by publishing.

---

## Setup

```bash
# host
mkdir -p ~/lab03 && cd ~/lab03
mkdir -p localrepo internalrepo publicrepo
```

You will build three things:

| Component | Role |
|---|---|
| `internalrepo/` | Stands in for the company's Artifactory / Nexus |
| `publicrepo/` | Stands in for Maven Central — the repository an attacker can publish to |
| `consumer/` | The Android application that resolves a dependency |

---

## Part A — Repository-order resolution

### A1. Build the "internal" library

```
lib-internal/
├── build.gradle.kts
└── src/main/java/com/acme/payments/Core.java
```

```java
// lib-internal/src/main/java/com/acme/payments/Core.java
package com.acme.payments;

public final class Core {
    public static String provenance() {
        return "INTERNAL build 1.4.0 — the artefact the developer intended";
    }
}
```

```kotlin
// lib-internal/build.gradle.kts
plugins { `java-library`; `maven-publish` }
group = "com.acme"
version = "1.4.0"
publishing {
    publications { create<MavenPublication>("maven") { from(components["java"]) } }
    repositories { maven { url = uri("${rootDir}/../internalrepo") } }
}
```

```bash
# host
cd lib-internal && gradle publish && cd ..
find internalrepo -name "*.jar"
```

### A2. Build the "attacker's" library with the SAME coordinate

```java
// lib-public/src/main/java/com/acme/payments/Core.java
package com.acme.payments;

public final class Core {
    public static String provenance() {
        // A real substitution payload would do something. This one only
        // announces itself, which is all the lab needs.
        return "SUBSTITUTED build 1.9.9 — this came from the PUBLIC repository";
    }
}
```

Publish it to `publicrepo/` with `group = "com.acme"`, `version = "1.9.9"` — a **higher** version.

### A3. The vulnerable consumer

```kotlin
// consumer/settings.gradle.kts — the DANGEROUS configuration
dependencyResolutionManagement {
    repositories {
        maven { url = uri("${rootDir}/../publicrepo") }     // asked FIRST
        maven { url = uri("${rootDir}/../internalrepo") }
    }
}
rootProject.name = "consumer"
```

```kotlin
// consumer/build.gradle.kts
plugins { application }
dependencies { implementation("com.acme:payments:1.4.0") }
application { mainClass.set("Main") }
```

```java
// consumer/src/main/java/Main.java
public class Main {
    public static void main(String[] args) {
        System.out.println(com.acme.payments.Core.provenance());
    }
}
```

```bash
# host
cd consumer
gradle run
```

**Record:** which build printed. Then run each of these and record the outcome:

```bash
# host — experiment 1: reverse the repository order
# experiment 2: change the requested version to 1.+
# experiment 3: add a second module that requests com.acme:payments:1.9.9,
#               and observe conflict resolution choose the higher version
#               even for the module that asked for 1.4.0
gradle dependencies --configuration runtimeClasspath
gradle dependencyInsight --configuration runtimeClasspath --dependency payments
```

### A4. Close it

```kotlin
// consumer/settings.gradle.kts — the FIX
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // The internal repository is the ONLY source for com.acme.*
        maven {
            url = uri("${rootDir}/../internalrepo")
            content { includeGroupByRegex("com\\.acme(\\..*)?") }
        }
        // The public repository is FORBIDDEN from answering for com.acme.*
        maven {
            url = uri("${rootDir}/../publicrepo")
            content { excludeGroupByRegex("com\\.acme(\\..*)?") }
        }
        mavenCentral { content { excludeGroupByRegex("com\\.acme(\\..*)?") } }
    }
}
```

```bash
# host
gradle run --refresh-dependencies
```

**Success:** the internal build prints, and the public repository is never even queried. Confirm the
second part:

```bash
# host — the public repo should show no access attempt for com.acme
gradle dependencyInsight --configuration runtimeClasspath --dependency payments
```

### A5. Pin it

```bash
# host — from the now-known-good state
gradle --write-verification-metadata sha256 help
cat gradle/verification-metadata.xml | head -30

# now swap the internal JAR for the public one by hand and rebuild
cp ../publicrepo/com/acme/payments/1.9.9/payments-1.9.9.jar \
   ../internalrepo/com/acme/payments/1.4.0/payments-1.4.0.jar
gradle run --refresh-dependencies
```

**Success:** the build **fails** with a checksum mismatch rather than running substituted code.

> **Hint.** `--write-verification-metadata` records whatever you resolve at that moment. Generate it
> from a state you have verified, and review the resulting file in a pull request like any other code.

---

## Part B — A plugin executing at configuration time

### B1. Build the demonstration plugin

Use [`../examples/05-hostile-plugin-DEFANGED.kt`](../examples/05-hostile-plugin-DEFANGED.kt) verbatim.
Publish it to `localrepo/` as a Gradle plugin, and apply it in `consumer`.

### B2. Observe when it runs

```bash
# host — every one of these executes the plugin's apply() method
gradle tasks
gradle help
gradle --dry-run build
gradle build
```

**Record:** the plugin's banner appears for all four, including `--dry-run`. Write down, in your own
words, why `--dry-run` does not prevent it.

### B3. Observe what it can see

Read the plugin's output for sections [1] and [2]. On a machine with an SSH key and a
`~/.gradle/gradle.properties`, it will list them. On a CI runner it would list the signing-key path
and the credential-bearing environment variable names.

### B4. Watch it from outside

```bash
# linux host — what does a build actually touch?
strace -f -e trace=execve,openat -o build.strace gradle --no-daemon build
grep openat build.strace | grep -E "\.ssh|\.aws|\.gnupg|credentials|id_rsa|\.netrc"
grep execve build.strace | grep -vE "gradle|java|javac|kotlinc" | head -20
```

**Record:** the exact lines that reveal the plugin's probing. Then run the same command on a project
*without* the plugin, and compare. That difference is your detection signal.

### B5. Close it

```bash
# host — pin the plugin by checksum
gradle --write-verification-metadata sha256,pgp help
# then modify the plugin JAR and rebuild — the build must fail
```

Also demonstrate the architectural control:

```bash
# host — build with no credentials in scope at all
docker run --rm -v "$PWD":/w -w /w --network none -u "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/w/.gradle-container \
  gradle:8.9-jdk17 gradle --offline build
```

**Record:** the plugin still runs, and finds nothing, because there is nothing in the container to
find. This is the strongest single control and it is an infrastructure decision, not a Gradle setting.

---

## Part C — `buildSrc` changing the artefact

### C1. Add a `buildSrc` that rewrites resolution

```kotlin
// consumer/buildSrc/src/main/kotlin/Substitute.kt
import org.gradle.api.Plugin
import org.gradle.api.Project

class Substitute : Plugin<Project> {
    override fun apply(target: Project) {
        target.configurations.configureEach {
            resolutionStrategy.dependencySubstitution {
                // A documented, legitimate Gradle feature — which is exactly
                // why it is a good hiding place.
                substitute(module("com.acme:payments:1.4.0"))
                    .using(module("com.acme:payments:1.9.9"))
                    .because("internal mirror")     // a plausible-sounding reason
            }
        }
    }
}
```

Apply it and run the consumer.

**Record:** the substituted build runs. Now note the important part: `consumer/build.gradle.kts` still
says `1.4.0`, and a code review of the application module shows nothing wrong. The only visible trace is
in `buildSrc/`, which is frequently excluded from review as "just build tooling".

### C2. Detect it

```bash
# host — the resolved truth, not the declared intent
gradle dependencyInsight --configuration runtimeClasspath --dependency payments
gradle dependencies --configuration runtimeClasspath

# host — the review grep
grep -rnE "resolutionStrategy|dependencySubstitution|eachDependency|force\(" buildSrc/
```

### C3. Close it

Dependency verification (Part A5) catches the substituted artefact by checksum. Add to that the
organisational control: `buildSrc/` and `build-logic/` reviewed as production code, with mandatory
approval.

---

## Part D — Reproducibility as the backstop

Every control above is enforced *by the build*. Part D is the one that is not.

```bash
# host — build the same source twice, in two directories
gradle clean build && cp build/libs/consumer.jar /tmp/a.jar
gradle clean build && cp build/libs/consumer.jar /tmp/b.jar

# entry-by-entry, so timestamps are visible rather than hidden in a whole-file diff
unzip -l /tmp/a.jar | sort > /tmp/a.lst
unzip -l /tmp/b.jar | sort > /tmp/b.lst
diff /tmp/a.lst /tmp/b.lst

diffoscope /tmp/a.jar /tmp/b.jar 2>/dev/null | head -40   # if available
```

Then apply the normalisation:

```kotlin
// consumer/build.gradle.kts
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
```

and repeat until the two artefacts are byte-identical.

**Record:** what differed before normalisation, and why each difference existed.

---

## Success criteria

- [ ] You demonstrated the public repository winning, and can state the two mechanisms that caused it
      (declaration order, and highest-version conflict resolution).
- [ ] Content filtering closed it, and you verified the public repository is no longer consulted.
- [ ] `verification-metadata.xml` failed the build when an artefact was swapped.
- [ ] You showed the plugin executing during `tasks`, `help` and `--dry-run`, and can explain why.
- [ ] You produced a `strace` diff that distinguishes a probing build from a clean one.
- [ ] You showed a `buildSrc` substitution that leaves the application module's build file untouched.
- [ ] You made a build bit-for-bit reproducible and can name every source of variation you removed.
- [ ] **You published nothing to any public or shared repository.**

---

## Discussion questions

1. Rank the controls you applied by effectiveness against a *competent* attacker. Which of them would
   the attacker in Part C have defeated, and which would have stopped them?
2. Dependency verification pins checksums. What does it *not* protect against? (Consider: the state you
   generated it from, and a malicious change present in reviewed source.)
3. Part B's container had no credentials. What did the build lose by running that way, and how would you
   architect a pipeline that keeps the isolation and still ships a signed artefact?
4. You find a client's `settings.gradle` has no content filtering, but no internal coordinates either —
   every dependency is a public artefact. Is it still a finding? Argue both sides, then commit to one.
