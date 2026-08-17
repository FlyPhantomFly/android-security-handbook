# 66-Instrumentation — examples

Sources only. **This directory ships no binaries**: no `.apk`, no `.dex`, no `.class`, no keystore.
`build-instrumentation-fixtures.sh` builds everything **out of tree**, into `$OUTDIR` (default
`${TMPDIR:-/tmp}/ch66-build`), and generates its two throwaway signing keys there as well.

**Authorised testing only.** `vault-target` holds fixture secrets and `vault-probe` reads another
package's private data by design. Install them on a device you own and run `--uninstall` afterwards.

---

## What is here

| Path | What it is |
|---|---|
| `build-instrumentation-fixtures.sh` | The builder. `aapt2 link` → `javac --release 8` → `d8` → `zipalign` → `apksigner`, no Gradle. Produces five APKs and self-checks the one bit that differs between each pair |
| `vault-target/` | The **target** application: an ordinary app that keeps a secret in three ordinary places |
| `vault-probe/` | The **test** APK: a bare `android.app.Instrumentation`, no androidx, no JUnit |
| `MinimalProbe.java` | The eleven-line version. Chapter §9.1 |
| `HookFromInstrumentation.java` | A `java.lang.reflect.Proxy` hook installed from `onCreate()`. Chapter §9.4 |
| `enterprise-ci-review.md` | The CI-pipeline review checklist. Chapter §9.5 |

### `vault-target/` — the application under test

| File | Role |
|---|---|
| `AndroidManifest.xml` | Deliberately carries **no** `android:debuggable`. The builder injects it for one of the two builds and leaves it out of the other |
| `VaultApp.java` | Logs a timestamp at each of four startup slots, so the ordering in §3.6 is measurable rather than asserted |
| `SeedProvider.java` | A `ContentProvider` that exists only to prove where provider startup sits relative to `Instrumentation.onCreate()` |
| `VaultStore.java` | The secret, in three shapes: a private static field, `SharedPreferences`, and a file under `getFilesDir()`. Also the interface-typed `sSink` that `HookFromInstrumentation` wraps |
| `LicenseGate.java` | One `private static boolean`. The smallest honest model of a licence check |
| `Telemetry.java` | An interface-typed collaborator — the shape `java.lang.reflect.Proxy` can intercept |
| `MainActivity.java` | Prints the current values so a change made from outside is visible on screen |

### `vault-probe/` — the test APK

| File | Role |
|---|---|
| `AndroidManifest.xml` | Three attributes do all the work. Read the comment at the top of the file |
| `VaultProbe.java` | The full probe: identity, ordering, reads, a write, class loaders, denials, hidden-API census, `UiAutomation` |
| `Probes.java` | Reflection and filesystem helpers. Every one reports an **outcome**, never a boolean, because `File.exists()` collapses `ENOENT` and `EACCES` into the same `false` |

---

## The five artefacts, and why there are five

Each differs from another in **exactly one bit**, which is what makes the gate in §3.9 measurable
instead of arguable:

| Artefact | `debuggable` | Signing key | `testOnly` |
|---|---|---|---|
| `vault-release.apk` | absent | A | — |
| `vault-debuggable.apk` | **true** | A | — |
| `probe-sigA.apk` | — | **A** (matches the target) | false |
| `probe-sigB.apk` | — | **B** (differs) | false |
| `probe-testonly.apk` | — | A | **true** |

The builder verifies all three bits after building and prints both signer digests, because a fixture
you have not checked will teach you the wrong thing quietly.

---

## Build and run

```bash
# host -- build only
./build-instrumentation-fixtures.sh

# host -- build, install the debuggable target and the matching probe
./build-instrumentation-fixtures.sh --install

# host -- run it
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe

# host -- readable output
adb shell am instrument -w -r \
    com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe \
  | python3 -B ../scripts/parse-instrumentation-results.py

# host -- remove both packages
./build-instrumentation-fixtures.sh --uninstall
```

To run `MinimalProbe` or `HookFromInstrumentation` instead, copy the file into `vault-probe/`, change
`android:name` in `vault-probe/AndroidManifest.xml` to match, and rebuild. Both file headers spell
this out and both record the output they actually produced.

## Requirements

`ANDROID_HOME` pointing at an SDK with build-tools (`aapt2`, `d8`, `zipalign`, `apksigner`) and one
platform `android.jar`; a JDK with `javac` and `keytool`; `python3` for the zip step; `adb` for the
install targets. Built and run here with **build-tools 35.0.1, platform android-35 and JDK 24.0.2**.

## Three traps this directory has already hit, so you do not have to

1. **An XML comment may not contain a double hyphen.** `aapt2` rejects the file and its error names
   the line, not the reason. `vault-target/AndroidManifest.xml` therefore writes `aapt2` flag names
   without their leading dashes.
2. **`javac`'s `@argfile` and `d8`'s `@argfile` do not share a grammar.** javac honours double quotes;
   d8 hands the quote straight to `java.nio` and fails with `InvalidPathException` naming a path that
   is plainly correct. This repository lives under a directory with a space in its name, so both
   halves fire. The builder passes class files as ordinary argv entries and never uses an argfile.
3. **`adb push` mangles an absolute remote path under MSYS.** `MSYS_NO_PATHCONV=1` is set for every
   `adb` call that carries one.
