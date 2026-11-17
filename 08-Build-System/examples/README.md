# 08 — Build System: Examples

Runnable material for [README.md §9](../README.md#9-examples). Each file is complete and commented.

| File | Section | What it demonstrates |
|---|---|---|
| [`01-minimal-app-build.gradle.kts`](01-minimal-app-build.gradle.kts) | §9.1 | A minimal, fully annotated app build file — every line explained |
| [`02-injecting-sdk-AndroidManifest.xml`](02-injecting-sdk-AndroidManifest.xml) | §9.2 | A library manifest that injects an exported receiver, a browsable activity and a permission |
| [`02-host-app-AndroidManifest.xml`](02-host-app-AndroidManifest.xml) | §9.2 | The host app's manifest, with the `tools:` markers that neutralise the injection |
| [`02-CommandReceiver.kt`](02-CommandReceiver.kt) | §9.2 | The injected receiver, which proves it runs with the host app's UID |
| [`03-SecurityGatePlugin.kt`](03-SecurityGatePlugin.kt) | §9.3 | A convention plugin that fails the build on unreviewed exported components, permissions or a debuggable release |
| [`04-hardened-settings.gradle.kts`](04-hardened-settings.gradle.kts) | §9.5 | Repository content filtering, `FAIL_ON_PROJECT_REPOS`, and plugin-repository pinning |
| [`04-hardened-app-build.gradle.kts`](04-hardened-app-build.gradle.kts) | §9.5 | The target-state app build file to diff a client's project against |
| [`05-hostile-plugin-DEFANGED.kt`](05-hostile-plugin-DEFANGED.kt) | §5.4.2 | What a malicious Gradle plugin's `apply()` can reach — instrumented, not weaponised |

## Assembling them into a project

Examples 01–03 fit together as one Gradle project:

```
demo/
├── settings.gradle.kts                 <- 04-hardened-settings.gradle.kts (or a plain one)
├── build-logic/
│   └── src/main/kotlin/
│       └── SecurityGatePlugin.kt       <- 03-SecurityGatePlugin.kt
├── app/
│   ├── build.gradle.kts                <- 01-minimal-app-build.gradle.kts
│   └── src/main/AndroidManifest.xml    <- 02-host-app-AndroidManifest.xml
└── evil-sdk/
    ├── build.gradle.kts                <- see the header of 02-CommandReceiver.kt
    └── src/main/
        ├── AndroidManifest.xml         <- 02-injecting-sdk-AndroidManifest.xml
        └── java/com/evil/sdk/CommandReceiver.kt   <- 02-CommandReceiver.kt
```

Then:

```bash
# host
./gradlew :app:assembleDebug
cat app/build/outputs/logs/manifest-merger-debug-report.txt
python3 ../scripts/manifest-merge-diff.py \
  --source app/src/main/AndroidManifest.xml \
  --merged app/build/intermediates/merged_manifests/debug/AndroidManifest.xml \
  --report app/build/outputs/logs/manifest-merger-debug-report.txt \
  --emit-am-commands
```

> **** `05-hostile-plugin-DEFANGED.kt` is deliberately non-functional as an attack: it prints what it
> *would* read and sends nothing anywhere. Do not add exfiltration to it. Its purpose is to make the
> capability concrete during a review conversation with developers, and it is more persuasive as a
> printout than as a working implant.
