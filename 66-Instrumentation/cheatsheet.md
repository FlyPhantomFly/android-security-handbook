# 66 — Instrumentation · cheat sheet

Dense reference. Everything marked **[M]** was measured on `sdk_gphone16k_x86_64`, Android 15 /
API 35, x86_64, `userdebug`, `ro.debuggable=1`. Everything else is documentation-derived.

---

## The gate — measured matrix **[M]**

| Target `debuggable` | Test APK key | Caller | Result |
|---|---|---|---|
| yes | same | shell (2000) | **OK** |
| **no** | same | shell | **OK** |
| no | **differs** | shell | **REFUSED** |
| **yes** | **differs** | shell | **REFUSED** |
| yes | differs | **root (0)** | **OK** |
| no | differs | **root** | **OK** |
| yes | same | app uid (`run-as`) | **OK**, with `--user 0 --no-test-api-access` |

**Rule:** signature match, or root. `android:debuggable` is irrelevant in both directions.

```
Permission Denial: starting instrumentation ComponentInfo{<test>/<runner>}
  from pid=N, uid=2000 not allowed because package <test>
  does not have a signature matching the target <target>
```

## Startup ordering **[M]**

| Order | Event | Offset from ctor | Pre-emptable by you? |
|---|---|---|---|
| 1 | `Application()` ctor | 0.00 ms | no |
| 2 | `Application.attachBaseContext()` | +1.57 ms | no |
| 3 | every `ContentProvider.onCreate()` | +2.75 ms | no |
| 4 | **`Instrumentation.onCreate()`** | **+6.57 ms** | — |
| 5 | `Application.onCreate()` | +9.50 ms | **yes** |
| 6 | `Activity.onCreate()` and later | later | **yes** |

The javadoc claim *"before any application code has been loaded"* is false. **[M]**

## Identity inside the process **[M]**

| Key | Value |
|---|---|
| `Process.myUid()` | the **target's** uid (10210) |
| `getProcessName()` / `/proc/self/cmdline` | the **target's** process name |
| `/proc/self/attr/current` | `u:r:untrusted_app:s0:c210,c256,c512,c768` |
| `getContext().getPackageName()` | the **test** package |
| `getTargetContext().getPackageName()` | the **target** package |
| `getTargetContext().getOpPackageName()` | the **target** package — app-ops are attributed to it |

## Vantage: shell vs instrumented app **[M]**

| Path | `adb shell` (2000) | instrumented app (10210) |
|---|---|---|
| `/data/user/0/<target>/shared_prefs/*` | denied | **read** |
| `/data/data/<other pkg>` | `EACCES` | **`ENOENT`** |
| `/data/adb` | `EACCES` | `EACCES` |
| `/system/xbin/su` | **readable** `-rwsr-x--- root shell` | `EACCES` |
| `/proc/modules` | **readable** | `EACCES` |
| `/proc/1/maps` | exists, `EACCES` | **`ENOENT`** |
| `/data/local/tmp` | **listable** `drwxrwx--x shell shell` | `EACCES` |
| via `UiAutomation.executeShellCommand` | — | **all of the above, as uid 2000** |

## Hidden-API census **[M]**

| Class | default | `--no-hidden-api-checks` |
|---|---|---|
| `android.app.ActivityThread` | 30 methods / 21 fields | **289 / 109** |
| `android.app.ActivityManager` | 89 / 35 | 155 / 170 |
| `dalvik.system.VMRuntime` | 23 / 0 | 72 / 16 |
| `android.os.SystemProperties` | 10 / 2 | 35 / 6 |
| `VMRuntime.setHiddenApiExemptions` visible | **no** | **yes** |
| `SystemProperties.get` reachable | **yes** (greylist) | yes |
| `ServiceManager.getService` reachable | **yes** (greylist) | yes |

Count members; a single lookup proves nothing.

---

## Manifest

```xml
<manifest package="com.example.app.test">
  <instrumentation
      android:name="com.example.probe.Runner"
      android:targetPackage="com.example.app"
      android:targetProcesses="*"
      android:label="probe"
      android:handleProfiling="false"
      android:functionalTest="false" />
  <application />
</manifest>
```

| Attribute | API | Notes |
|---|---|---|
| `android:name` | 1 | Must extend `android.app.Instrumentation`; needs a public no-arg constructor |
| `android:targetPackage` | 1 | **The binding.** Required |
| `android:targetProcesses` | 26 | comma list, or `*` for any process running target code |
| `android:handleProfiling` | 1 | `false` = framework starts/stops profiling for `-p` |
| `android:functionalTest` | 1 | stored, otherwise unused |
| `android:testOnly` (on `<application>`) | 1 | install-time gate; `adb install -t` defeats it **[M]** |

`<instrumentation>` is a **sibling** of `<application>`, not a child.

---

## `am instrument`

```
am instrument [-r] [-e <NAME> <VALUE>] [-p <FILE>] [-w] [-m] [-f [PATH]]
              [--user <USER_ID> | current]
              [--no-hidden-api-checks [--no-test-api-access]]
              [--no-isolated-storage] [--no-window-animation] [--abi <ABI>]
              <TEST_PACKAGE>/<RUNNER_CLASS>
```

| Flag | Use |
|---|---|
| `-w` | wait. Effectively mandatory |
| `-r` | raw protocol. Mandatory for parsing |
| `-e K V` | argument into `onCreate(Bundle)`. Repeatable, strings only |
| `-p FILE` | method-trace profiling output |
| `-m` / `-f [PATH]` | protobuf to stdout / to a file (default `/sdcard/instrument-logs/`) |
| `--user 0` | **needed from a non-shell caller** — `current` is `-2` and needs `INTERACT_ACROSS_USERS_FULL` **[M]** |
| `--no-hidden-api-checks` | lift non-SDK restrictions; needs `DISABLE_HIDDEN_API_CHECKS` |
| `--no-test-api-access` | **needed from a non-shell caller** — the default grants test-API access **[M]** |
| `--no-isolated-storage` | full external storage instead of scoped |
| `--no-window-animation` | fewer flaky UI runs |
| `--abi <ABI>` | force a launch ABI |

## Wire protocol

| Line | Meaning |
|---|---|
| `INSTRUMENTATION_STATUS: k=v` | progress from `sendStatus()` |
| `INSTRUMENTATION_STATUS_CODE: n` | ends a status block |
| `INSTRUMENTATION_RESULT: k=v` | final bundle |
| `INSTRUMENTATION_CODE: n` | overall code. **`-1` = `RESULT_OK` = SUCCESS**, `0` = `RESULT_CANCELED` |
| `INSTRUMENTATION_FAILED: <cmp>` | could not start |

Values may span lines (stack traces). A refused start still exits **0** from `adb shell`.

---

## Commands

```bash
# host -- recon
adb shell pm list instrumentation -f
adb shell pm path <pkg>
adb shell dumpsys package <pkg> | grep -m1 'flags='
aapt2 dump xmltree --file AndroidManifest.xml app.apk | grep -iE 'instrumentation|testOnly|debuggable'
apksigner verify --print-certs app.apk | grep -i 'SHA-256 digest'

# host -- run
adb shell am instrument -w -r <testpkg>/<runner>
adb shell am instrument -w -r --no-hidden-api-checks <testpkg>/<runner>
adb shell "su 0 am instrument -w -r <testpkg>/<runner>"                 # root; NOT su -c
adb shell "run-as <pkg> am instrument -w -r --user 0 --no-test-api-access <testpkg>/<runner>"

# host -- observe
adb logcat -s ActivityManager:I | grep -iE 'instr|Force stopping'
adb shell dumpsys activity | grep -iA6 instrumentation
adb shell pidof <pkg>

# host -- install a testOnly apk
adb install -t app-androidTest.apk

# host -- this chapter's tooling
./scripts/instrumentation-recon.sh [--deep]
OUTDIR=/tmp/ch66 ./scripts/am-instrument-matrix.sh [--row N] [--keep]
python3 -B scripts/instrumentation-surface.py --dir /tmp/corpus
adb shell am instrument -w -r <c> | python3 -B scripts/parse-instrumentation-results.py --strict
```

## Build a test APK without Gradle

```bash
aapt2 link -o base.apk -I android.jar --manifest AndroidManifest.xml \
    --min-sdk-version 24 --target-sdk-version 35
javac --release 8 -classpath android.jar -d classes src/**/*.java
d8 --lib android.jar --min-api 24 --output . classes/**/*.class
python3 -B -c "import zipfile,shutil;shutil.copy('base.apk','u.apk');\
z=zipfile.ZipFile('u.apk','a',zipfile.ZIP_DEFLATED);z.write('classes.dex');z.close()"
zipalign -f -p 4 u.apk a.apk
apksigner sign --ks key.ks --ks-pass pass:x --out out.apk a.apk
# aapt2 link --debug-mode  injects android:debuggable="true"
```

---

## Instrumentation API

| Call | Thread | Notes |
|---|---|---|
| `onCreate(Bundle)` | main | before `Application.onCreate()`; call `start()` or `onStart()` never runs |
| `onStart()` | instrumentation thread | your work; races the app's startup |
| `onException(Object, Throwable)` | thrower's | return `true` to swallow the app's exception |
| `getContext()` | any | **test** package context |
| `getTargetContext()` | any | **target** package context — this is the one you want |
| `getUiAutomation()` | instr | `executeShellCommand` runs as **uid 2000** **[M]** |
| `startActivitySync(Intent)` | instr **only** | returns the real `Activity` |
| `waitForIdleSync()` | instr **only** | blocks on the main looper |
| `runOnMainSync(Runnable)` | instr | the bridge to the main thread |
| `sendStatus(int, Bundle)` | any | progress |
| `addResults(Bundle)` | any | durable results, survives a later crash |
| `finish(int, Bundle)` | any | reports **and kills the process** |
| `callActivityOnCreate` and 12 siblings | framework | override to hook every activity in the process |

## Lifecycle side effects **[M]**

```
I ActivityManager: Force stopping <pkg> appid=<id> user=0: start instr
I ActivityManager: Killing <pid>:<pkg> (adj 0): stop <pkg> due to start instr
I ActivityManager: Force stopping <pkg> appid=<id> user=0: finished inst
I ActivityManager: Killing <pid>:<pkg> (adj 0): stop <pkg> due to finished inst
```

The target is killed at both ends. Sessions do not survive. These lines come from `system_server`
and cannot be suppressed from inside the app — the best forensic artefact this technique has.

## Class loaders **[M]**

```
getContext().getClassLoader()        PathClassLoader[test.apk, target.apk]  ->  parent below
getTargetContext().getClassLoader()  PathClassLoader[test.apk, target.apk]  ->  BootClassLoader
```

**Test APK DEX is first.** Reflection into the target works; a duplicate fully-qualified name
**shadows** the target's class.

---

## Detection and defence

```java
// the whole client-side defence, one line
List<InstrumentationInfo> aimed =
        ctx.getPackageManager().queryInstrumentation(ctx.getPackageName(), 0);
boolean instrumentationInstalled = aimed != null && !aimed.isEmpty();
```

| Control | Value |
|---|---|
| Sign test APKs with a **separate key** | Removes the co-signed path entirely. Highest value |
| `queryInstrumentation` self-check | Telemetry, not a gate |
| No `-keep class **.test.**` | Stops residue and the obfuscation it undoes |
| Server-side entitlements | A flipped static field changes only local UI |
| Hardware-backed attestation | The only class of answer that leaves the process |
| `android:testOnly` | **Not** a control. `adb install -t` **[M]** |
| `android:debuggable="false"` | **Not** a control for this **[M]** |

## Static detection

| Signal | Confidence |
|---|---|
| `<instrumentation targetPackage=...>` in the manifest | certain — it *is* a test APK |
| `.super Landroid/app/Instrumentation;` in Smali | very high |
| `Landroidx/test/runner/AndroidJUnitRunner;` | high |
| `Landroidx/test/platform/app/InstrumentationRegistry;` | high |
| `Landroidx/test/uiautomator/` | high |
| `Lorg/junit/runner/RunWith;` | medium |
| `Landroid/app/Instrumentation;` alone | **low — noise** |

`pm list instrumentation` finds **declarations only**, never residue. Measured: 0 rows on a stock
Android 15 image that nonetheless carried three JUnit test classes in a shipping APK. **[M]**

## Severity

| Finding | Severity |
|---|---|
| Test APK, release-key-signed, publicly downloadable | **High** |
| `testOnly` build in an MDM catalogue | Medium–High |
| Co-signed sibling declaring an instrumentation at production | Medium |
| `androidTest` residue, no secrets | Low / Informational |
| "The app can be instrumented after re-signing" | Informational — the finding is the repackaging |
| "The app can be instrumented on a rooted device" | Informational — root is the finding |

## Traps

| Trap | Fix |
|---|---|
| `getContext()` instead of `getTargetContext()` | reads an empty test-package store, silently |
| Shipping target classes in the test APK | your DEX is first; you read your own defaults |
| Waiting on a flag set on *entry* to the work | reads come back empty and the run passes |
| `UiAutomation.executeShellCommand` in a detection probe | you measured uid 2000, not the app |
| Reading `INSTRUMENTATION_CODE: -1` as failure | it is success |
| A refused start read as a failed test | `adb shell` exits 0 either way — parse the stream |
| `adb shell su -c '…'` | quotes are stripped; use `adb shell "su 0 …"` | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- trap table: the first cell IS the wrong form, the second is the fix -->
| `executeShellCommand` with a pipeline or quotes | not a shell: whitespace split, no quoting, silent empty output |
| Building into a new `OUTDIR` | new signing key, everything stops matching |
| A double hyphen inside an XML comment | `aapt2` rejects the file and blames the line |
