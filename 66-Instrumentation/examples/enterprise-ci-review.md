# Enterprise example — reviewing a CI pipeline for the instrumentation surface

> Chapter 66's fifth graded example. At one app the question is *"can I instrument this?"*. At
> enterprise scale the question becomes *"who else can, how did the artefact get there, and would
> anybody have noticed?"* — and every one of those is answered in the build system, not in the APK.

**Read [../README.md §5](../README.md) first.** This file is the checklist with the commands
attached; the reasoning behind each item is in §5.1 to §5.4.

**Authorised testing only.** Everything here is read-only reconnaissance against repositories,
pipelines and artefact stores you are contracted to review.

---

## Why this is the highest-value review in the chapter

A test APK is a **signed code-execution primitive against the production package**. Not a
vulnerability, not a misconfiguration — a working, supported, vendor-built capability. §3.9 measured
that the only thing standing between an attacker and code inside the production app's process is the
signing relationship, and a CI pipeline that signs the test APK with the release key has removed
that.

So the review is short and its findings are unusually crisp:

| Question | Where the answer lives | Bad answer |
|---|---|---|
| Is the test APK signed with the release key? | `build.gradle` signing configs, `signingConfig` on `androidTest` | Yes |
| Where does `assembleAndroidTest` output go? | CI YAML | An artefact store readable beyond the pipeline |
| Who can read that store? | IAM / bucket policy / CI permissions | Anyone in the org, or the internet |
| Does the release build carry test residue? | The release APK | Yes |
| Is `testOnly` set on distributed builds? | The distributed APK | Set, on something that reached users |
| Does the production app perform the self-check? | Source | No |

---

## 1. Signing — the single control that matters most

```bash
# host -- how many keys does this project use?
grep -rn -A8 'signingConfigs' --include=build.gradle --include=build.gradle.kts .

# host -- is a signing config applied to the androidTest variant?
grep -rn 'testBuildType\|signingConfig' --include=build.gradle --include=build.gradle.kts .
```

By default, Gradle signs the `androidTest` APK with the **same** config as the variant under test.
For a `release` `testBuildType`, that is the release key.

```groovy
// The recommendation, and it is cheap. A separate key for test artefacts.
android {
    signingConfigs {
        release      { /* the real one, from a secret store */ }
        androidTest  { /* a distinct key, rotated freely, never used for a Play upload */ }
    }
    buildTypes {
        release { signingConfig signingConfigs.release }
    }
    // applied to the instrumentation test APK only
    testBuildType "debug"
}
```

Verify the result on the artefacts rather than trusting the configuration:

```bash
# host -- these two digests must DIFFER
apksigner verify --print-certs app-release.apk           | grep -i 'SHA-256 digest'
apksigner verify --print-certs app-release-androidTest.apk | grep -i 'SHA-256 digest'
```

> A matching digest means anybody holding the test APK can instrument every production install of
> that app on any device where they can also install a package. That is §5.1's first pattern, and it
> is the finding to lead with.

## 2. Artefact flow — where the test APK ends up

```bash
# host -- who builds test APKs?
grep -rn -i 'assembleAndroidTest\|connectedAndroidTest\|packageDebugAndroidTest' \
    .github/ .gitlab-ci.yml Jenkinsfile bitrise.yml fastlane/ 2>/dev/null

# host -- and who publishes them?
grep -rn -i 'upload-artifact\|artifacts:\|aws s3 cp\|gsutil cp\|az storage blob upload\|curl.*-T ' \
    .github/ .gitlab-ci.yml Jenkinsfile 2>/dev/null

# host -- device farm uploads carry the test APK by definition
grep -rn -i 'firebase test\|browserstack\|saucelabs\|device.?farm\|gcloud firebase' \
    .github/ .gitlab-ci.yml Jenkinsfile 2>/dev/null
```

A pattern such as

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: apks
    path: '**/*.apk'
```

publishes the test APK alongside the release APK to whatever retention and access policy that
workflow has. Ask three follow-ups: how long is retention, who can download it, and is the workflow
reachable from a fork or a pull request.

## 3. Residue in the release build

```bash
# host -- the scanner from this chapter
python3 -B ../scripts/instrumentation-surface.py app-release.apk

# host -- and the keep rules that usually cause it
grep -rn -i 'keep.*[Tt]est' --include=*.pro --include=proguard-rules.txt .
```

A `RESIDUE` verdict is a **lead**. Adjudicate it: extract the referencing classes with `baksmali`,
read their string constants, and decide what they give away. `../README.md §6.4` walks through a real
one end to end, including why it was rated Informational.

The generalisation worth writing into the report: **un-minified test classes name minified
production classes.** A `-keep` rule that preserves `**.test.**` does not merely leak test code, it
partially undoes the obfuscation of everything the tests touch.

## 4. `testOnly` and `debuggable` in anything distributed

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml app-release.apk \
    | grep -iE 'testOnly|debuggable'

# host -- across everything on a managed device fleet
adb shell pm list packages | sed 's/^package://' | while IFS= read -r p; do
    adb shell "dumpsys package $p" < /dev/null 2>/dev/null \
        | grep -m1 -E '^[[:space:]]+flags=' | grep -qE 'DEBUGGABLE|TEST_ONLY' \
        && echo "$p"
done
```

`android:testOnly` is an install-time gate defeated by `adb install -t` (§3.14 measured this), so it
is a distribution hygiene signal rather than a control. Its value to a reviewer is what it *implies*:
a `testOnly` APK in an MDM catalogue means the pipeline that filled the catalogue does not
distinguish test builds from release builds, and that is usually true of more than one artefact.

Measured baseline for the fleet sweep, on a stock Android 15 image with 247 packages: **one**
`DEBUGGABLE` package, which was this chapter's own fixture, and **zero** `TEST_ONLY`. The expected
answer on a clean device is zero and zero, which makes any hit worth chasing.

## 5. Test back doors that survive into production

```bash
# host
grep -rn 'Class.forName("androidx.test' --include=*.java --include=*.kt .
grep -rn 'Class.forName("org.junit'     --include=*.java --include=*.kt .
grep -rn -i 'isRunningUnderTest\|isInTest\|TEST_MODE\|instrumentation' \
    --include=*.java --include=*.kt . | head -40
```

The anti-pattern and its fix, side by side:

```java
// WRONG. This check runs inside the process the attacker controls, and it is
// satisfied by ANY class with that name -- which an attacker supplies for free,
// because their DEX is first on the class path (README section 3.7).
private static boolean underTest() {
    try { Class.forName("androidx.test.espresso.Espresso"); return true; }
    catch (ClassNotFoundException e) { return false; }
}
if (underTest()) { skipLicenceCheck(); }
```

```java
// RIGHT. The bypass does not exist in the release artefact at all.
//   src/main/java/...   LicenceGate.java          -- no bypass
//   src/debug/java/...  LicenceGateOverrides.java -- the bypass, debug source set only
// Then assert it in CI:
//   a release-build test that FAILS if the class is present in the release DEX.
```

The property you want is *"the code does not exist"*, never *"the code is not reached"*.

## 6. Does the app notice?

```bash
# host
grep -rn 'queryInstrumentation' --include=*.java --include=*.kt .
```

One line, `PackageManager.queryInstrumentation(getPackageName(), 0)`, and a non-empty list means a
test APK aimed at this package is installed. Recommend it as **telemetry**, not as a gate: a gate runs
inside the process the attacker already owns, and this repository's position on that is set out in
[../../67-BypassingProtections/README.md](../../67-BypassingProtections/README.md).

---

## Report skeleton

Use [../../80-Appendix/README.md](../../80-Appendix/README.md)'s template and severity rubric. The
findings this review produces, with the ratings §5.9 argues for:

| Finding | Severity | Evidence to attach |
|---|---|---|
| Test APK co-signed with the release key and published to a readable store | High | Both signer digests; the artefact URL; the CI YAML lines |
| `testOnly` build present in a distribution channel | Medium to High | `INSTALL_FAILED_TEST_ONLY` transcript; the catalogue entry |
| Co-signed sibling package declaring an instrumentation aimed at production | Medium | `pm list instrumentation -f`; both signer digests |
| `androidTest` residue in the release APK | Low to Informational, stated with what it gives up | Scanner output; the adjudicated class list; the strings |
| Reachable test back door | rate on what it bypasses | The check; the call site; a working demonstration |
| App performs no `queryInstrumentation` self-check | Informational | Absence of the call; recommend as telemetry |

Do **not** file "the app can be instrumented". It is a property of Android and it will cost you the
credibility of the rows above.
