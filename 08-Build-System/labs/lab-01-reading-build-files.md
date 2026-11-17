# Lab 01 — Reading a build file cold

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Chapter:** [08 — The Android Build System](../README.md) §3.7–§3.14, §5.5, §8.1

---

## Objective

Given an unfamiliar Android project you have never seen, produce the complete output of the
pentester's build-file checklist ([§5.5](../README.md#55-the-pentesters-build-file-checklist)) in under
an hour, **without running the build**, and without opening a single line of application source.

By the end you will be able to say, from build files alone:

- who is allowed to inject code into this build,
- what the release artefact's hardening posture is,
- what configuration is baked into the shipped APK,
- what third-party code is present and whether any of it is mutable,
- and where the signing key comes from.

---

## Why this lab exists

New testers open JADX first. That is backwards. The build files are the *specification* that produced
the APK, they are far smaller than the app, and on a real repository this hour routinely produces two or
three reportable findings before any application code is read. It also produces a map that makes the
rest of the engagement faster.

---

## Setup

### Target

Any real, moderately complex open-source Android application. Good properties: several Gradle modules,
at least twenty dependencies, a `proguard-rules.pro`, and a CI configuration. Suggestions that satisfy
these without endorsing any specific project: a popular open-source RSS reader, note-taking app, or
podcast client from F-Droid's source list.

```bash
# host — pick one and clone it. Do NOT open it in Android Studio.
git clone --depth 50 <repository-url> target-app
cd target-app
```

> **Do not run `./gradlew` and do not open the project in an IDE for steps 1–8.**
> The configuration phase executes arbitrary code from the project and from every plugin it applies.
> That is the subject of §5.4, and this lab is partly about internalising that constraint. Steps 9–10
> run the build deliberately, in a container.

### Tools

- A text editor and `grep` (or `rg`).
- Python 3.8+ for [`../scripts/gradle-audit.py`](../scripts/gradle-audit.py).
- Docker, for step 9 only.

---

## Steps

### Step 1 — Map the project

```bash
# host
find . -name "settings.gradle*" -o -name "build.gradle*" -o -name "*.versions.toml" \
  | grep -v "/build/" | sort
```

**Record:** how many modules there are, which is the application module (the one applying
`com.android.application`), and which are libraries.

---

### Step 2 — Who can inject code? (`settings.gradle`)

Open `settings.gradle` or `settings.gradle.kts` and answer three questions in writing:

1. Which repositories are declared, **in what order**, in `pluginManagement` and in
   `dependencyResolutionManagement`?
2. Does **any** repository declare a `content { }` filter?
3. Is `repositoriesMode` set, and to what?

**Record:** the ordered repository list, and yes/no for filters and `repositoriesMode`.

> **Hint.** If `dependencyResolutionManagement` is absent entirely, look for
> `allprojects { repositories { ... } }` in the root `build.gradle`. That is the older pattern and it
> means every module shares one unfiltered repository set.

---

### Step 3 — The wrapper

```bash
# host
cat gradle/wrapper/gradle-wrapper.properties
sha256sum gradle/wrapper/gradle-wrapper.jar
```

**Record:** the `distributionUrl` host, whether `distributionSha256Sum` is present, and the JAR's
SHA-256. Compare the JAR's digest against the official value for that Gradle version at
<https://gradle.org/release-checksums/>.

**Success criterion for this step:** you can state, with evidence, whether the committed wrapper JAR is
the official one.

---

### Step 4 — Code that runs before everything

```bash
# host
ls -la buildSrc build-logic 2>/dev/null
find . -name "*.init.gradle*" -not -path "./build/*"
grep -rnE "exec\(|ProcessBuilder|Runtime\.getRuntime|URL\(|System\.getenv|resolutionStrategy|dependencySubstitution" \
     buildSrc/ build-logic/ 2>/dev/null
```

**Record:** whether pre-execution build logic exists, its size in lines, and whether it performs I/O,
spawns processes, or rewrites dependency resolution. Read every match in full.

---

### Step 5 — Release hardening

```bash
# host
grep -rn -A20 "buildTypes" --include="build.gradle*" . | head -80
```

**Record**, for the **release** build type specifically:

| Property | Value | Note |
|---|---|---|
| `isMinifyEnabled` / `minifyEnabled` | | |
| `isShrinkResources` | | |
| `isDebuggable` | | |
| `signingConfig` | | where do the credentials come from? |
| `proguardFiles` | is it the `-optimize` default file? | |
| `enableV1Signing` … `enableV4Signing` | | compare against `minSdk` |
| `ndk { debugSymbolLevel }` | | |

---

### Step 6 — Configuration baked into the artefact

```bash
# host
grep -rn "buildConfigField\|resValue\|manifestPlaceholders" --include="build.gradle*" .
```

For each hit, write down **where the value ends up**: the DEX string pool (`buildConfigField`),
`resources.arsc` (`resValue`), or the merged manifest (`manifestPlaceholders`).

Then classify each value using the severity table in [§5.3.1](../README.md#531-secret-material-embedded-via-buildconfigfield):
genuine credential, third-party SaaS key, or public identifier.

---

### Step 7 — Signing material and credentials

```bash
# host — the working tree
find . \( -name "*.jks" -o -name "*.keystore" -o -name "*.p12" -o -name "*.pk8" \
       -o -name "*.pem" -o -name "google-services.json" \) -not -path "./build/*"

grep -rnIE "(PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIAL)\s*[=:]" \
     --include="*.properties" --include="build.gradle*" --include="*.toml" . | grep -v "/build/"

# host — git history, where they usually still are after a "fix"
git log --all --diff-filter=A --name-only --pretty=format: | sort -u \
  | grep -iE "\.jks$|\.keystore$|\.p12$|\.pk8$|secret|credential"
```

**Record:** every hit, and whether it is in `HEAD`, in history, or both.

---

### Step 8 — Dependencies, from the files

```bash
# host
cat gradle/libs.versions.toml 2>/dev/null

grep -rhoE "['\"][a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+:[^'\"]+['\"]" \
     --include="build.gradle*" --include="*.versions.toml" . \
  | tr -d "'\"" | sort -u | tee declared-coords.txt | wc -l

grep -rnE "['\"][^'\"]+:[^'\"]+:(.*\+|latest\.[a-z]+|.*-SNAPSHOT)['\"]" \
     --include="build.gradle*" --include="*.versions.toml" .

grep -rn "jitpack.io" --include="*.gradle*" --include="*.toml" .
```

**Record:** the declared dependency count, and every mutable version or JitPack coordinate.

---

### Step 9 — The resolved graph (build in a container)

Now, and only now, run the build — with no credentials in scope.

```bash
# host
docker run --rm -v "$PWD":/w -w /w -u "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/w/.gradle-container \
  gradle:8.9-jdk17 \
  gradle :app:dependencies --configuration releaseRuntimeClasspath > resolved-deps.txt

grep -cE "^[+\\\\]" resolved-deps.txt      # how many resolved entries?
wc -l declared-coords.txt                   # how many did the developer declare?
```

**Record:** the ratio. In a real application it is typically between five and twenty transitive
dependencies for every declared one — none of which anyone chose.

---

### Step 10 — Write it up

Produce a one-page summary with exactly these headings and one to three lines under each:

1. **Supply-chain posture** — repositories, filtering, `repositoriesMode`, wrapper, verification metadata.
2. **Release hardening** — R8, debuggable, signing, scheme versions.
3. **Embedded configuration** — what ships inside the artefact, and its classification.
4. **Credentials** — anything in the tree or in history.
5. **Dependencies** — declared count, resolved count, mutable versions.
6. **The three things I would look at first in the application code, and why.**

---

## Check your work

Run the script and compare its output to yours:

```bash
# host
python3 ../scripts/gradle-audit.py . --min-severity LOW
```

You should have found everything it found. If it found something you missed, work out why you missed
it. If **you** found something *it* missed, that is normal and more interesting — the script is
mechanical and you are not.

---

## Success criteria

- [ ] You can state the repository search order and whether content filtering is present.
- [ ] You have verified (or refuted) the wrapper JAR against the official checksum.
- [ ] You can state the release build type's five hardening properties from memory of your notes.
- [ ] You have classified every `buildConfigField` / `resValue` value by severity, and you can defend
      each classification — including any you rated Informational.
- [ ] You have searched git history, not just `HEAD`, for credentials.
- [ ] You can state the declared-to-resolved dependency ratio.
- [ ] You produced the one-page summary in under 90 minutes.
- [ ] **You did not open the project in an IDE, and you can explain why that matters.**

---

## Common mistakes in this lab

| Mistake | Why it is wrong |
|---|---|
| Opening the project in Android Studio "just to look" | Studio runs the configuration phase. This is exactly the thing §5.4 warns about, and the lab is partly a test of whether you internalised it. |
| Reading only `app/build.gradle.kts` | `settings.gradle` decides who may inject code. It is the higher-value file. |
| Rating an `AIza...` key as critical | Verify what it authorises first. See [§5.3.1](../README.md#531-secret-material-embedded-via-buildconfigfield). |
| Reporting the declared dependency list as the inventory | The resolved graph is five to twenty times larger. Step 9 exists for this reason. |
| Stopping at `git status` for secrets | `git log --all` is where removed keystores live. |

---

## Extension

Repeat the whole exercise on a second project from a different ecosystem — a bank, a game, an
enterprise MDM client. Compare the two write-ups. The differences in supply-chain posture between
sectors are large, consistent, and worth being able to describe from experience.
