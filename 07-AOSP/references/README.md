# 07 — AOSP: Annotated References

Every link has a one-line note saying why you would open it. Grouped by what you are trying to do.

---

## Browsing and searching the source

- **Android Code Search** — https://cs.android.com/ — the primary tool for this whole chapter. Cross-references, blame, history, multiple branches. **Set the branch selector to match the device you are testing before you read anything.**
- **AOSP git** — https://android.googlesource.com/ — the canonical repositories, and where `repo` fetches from.
- **AOSP GitHub mirror** — https://github.com/aosp-mirror — the same code with GitHub's search, blame and PR-style diff UI, which some people find faster for reading history.
- **Android Gerrit** — https://android-review.googlesource.com/ — every proposed and merged change, with review comments. Reading the review discussion on a security fix is often more informative than the diff.
- **Android Common Kernel** — https://android.googlesource.com/kernel/common/ — where `drivers/android/binder.c` lives.
- **Build numbers and tags** — https://source.android.com/docs/setup/reference/build-numbers — maps a device's `ro.build.id` to the AOSP tag you should be reading. Bookmark this; it resolves the most common source of confusion in the chapter.

---

## Getting and managing the source

- **Downloading the Android source** — https://source.android.com/docs/setup/download — prerequisites, `repo` installation, `repo init`, `repo sync`.
- **`repo` command reference** — https://source.android.com/docs/setup/reference/repo — every subcommand, including `manifest -r`, which is how you pin what you tested.
- **Manifest format specification** — https://gerrit.googlesource.com/git-repo/+/HEAD/docs/manifest-format.md — every element and attribute, including `remove-project` and `extend-project`, which are how a vendor replaces an AOSP project with a fork.
- **Using `repo` for local development** — https://source.android.com/docs/setup/create/coding-tasks — branches, patching, uploading.

---

## Building and running

- **Building Android** — https://source.android.com/docs/setup/build/building — `envsetup.sh`, `lunch`, `m`, target naming, and the build-variant table.
- **Establishing a build environment** — https://source.android.com/docs/setup/start/requirements — hardware, OS and package prerequisites. Read before you commit a day to it.
- **Cuttlefish** — https://source.android.com/docs/devices/cuttlefish — the virtual reference device: setup, `launch_cvd` flags, the web UI, and how it differs from the emulator.
- **Cuttlefish advanced options** — https://source.android.com/docs/devices/cuttlefish/get-started — multi-device, GPU modes, snapshotting.
- **Running builds on a device** — https://source.android.com/docs/setup/build/running — flashing, `fastboot`, and the `adb sync`/`adb remount` workflow.
- **Generic System Images** — https://source.android.com/docs/core/tests/vts/gsi — booting an AOSP system image on a Treble-compliant device, which lets you compare AOSP behaviour against an OEM's on the same hardware.

---

## Architecture and the security model

- **Android architecture** — https://source.android.com/docs/core/architecture — the layer diagram AOSP's directory structure implements.
- **Android security overview** — https://source.android.com/docs/security — the model the three traces in §4 demonstrate.
- **Application sandbox** — https://source.android.com/docs/security/app-sandbox — the UID and SELinux layers.
- **Permissions overview** — https://source.android.com/docs/core/permissions — protection levels, privileged permission allow-lists, and the `privapp-permissions` mechanism.
- **Implementing permissions** — https://source.android.com/docs/core/permissions/perms-allowlist — how `/system/etc/permissions/privapp-permissions-*.xml` works, which is what you read when auditing preinstalled apps.
- **SELinux concepts** — https://source.android.com/docs/security/features/selinux — the MAC layer beneath the permission model.
- **Binder IPC** — https://source.android.com/docs/core/architecture/hidl/binder-ipc — the transport every trace in §4 crosses.
- **AIDL for HALs** — https://source.android.com/docs/core/architecture/aidl — stable AIDL, which replaced HIDL for new interfaces.
- **Project Treble** — https://source.android.com/docs/core/architecture/hidl — the platform/vendor separation that produced two security patch levels.
- **Modular system components (Mainline)** — https://source.android.com/docs/core/ota/modular-system — which components update through Play independently of the OS release.
- **Compatibility Definition Document (CDD)** — https://source.android.com/docs/compatibility/cdd — the normative statement of what an Android device **must** do. When you need to argue that a device's behaviour is non-compliant rather than merely undesirable, this is the document to cite.

---

## Hidden APIs and SDK surfaces

- **Restrictions on non-SDK interfaces** — https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces — the official description of the lists, their semantics, and the `targetSdk` interaction.
- **Testing non-SDK interface usage** — https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces#test-for-non-sdk — the `hidden_api_policy` setting and the `am instrument --no-hidden-api-checks` flag.
- **List of non-SDK interfaces** — https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces#list-of-non-sdk-interfaces — the published lists themselves.
- `art/runtime/hidden_api.cc` and `hidden_api.h` — the implementation. Read these rather than the documentation when you need to know exactly which code paths are checked.
- `frameworks/base/core/api/current.txt`, `system-current.txt`, `test-current.txt` — the machine-readable surfaces. `git log -p` on `system-current.txt` is a complete history of every system API ever added or removed.

---

## Testing and compatibility

- **Compatibility Test Suite** — https://source.android.com/docs/compatibility/cts — what CTS is, how to run it, and how to read results.
- **CTS Verifier** — https://source.android.com/docs/compatibility/cts/verifier — the human-in-the-loop tests for camera, sensors, biometrics and NFC.
- **Vendor Test Suite** — https://source.android.com/docs/core/tests/vts — HAL conformance and kernel configuration requirements.
- `cts/tests/tests/security/` in AOSP — security requirements encoded as executable tests. Reading these is a precise statement of what the platform guarantees, and far more exact than the developer documentation.

---

## Security bulletins and patching

- **Android Security Bulletins** — https://source.android.com/docs/security/bulletin — the monthly list, with the AOSP commits that fix each issue. The authority to cite when you need a specific identifier rather than a class of issue.
- **Pixel Update Bulletins** — https://source.android.com/docs/security/bulletin/pixel — device-specific fixes, which frequently reveal vendor-layer issue classes.
- **Android security patch levels explained** — https://source.android.com/docs/security/overview/updates-resources — what `ro.build.version.security_patch` actually asserts, which is less than most people assume.
- **Android Security Rewards programme rules** — https://bughunters.google.com/about/rules — scope, severity criteria and, importantly, the platform-versus-vendor distinction that determines who you report to.

---

## Key source paths (searchable on cs.android.com)

### The files worth bookmarking

- `frameworks/base/core/res/AndroidManifest.xml` — every platform permission with its exact `protectionLevel`. The authority for "can a third-party app hold this?".
- `frameworks/base/core/res/res/values/config.xml` — hundreds of platform behaviour switches an OEM may override without touching code.
- `frameworks/base/services/java/com/android/server/SystemServer.java` — every system service and the order it starts in. Read top to bottom once.
- `frameworks/base/core/java/android/os/Binder.java` — `execTransact`, `getCallingUid`, `clearCallingIdentity`. The universal Java IPC funnel.
- `frameworks/base/core/java/android/app/ContextImpl.java` — the real implementation behind most of `Context`.
- `frameworks/base/core/java/android/app/ActivityThread.java` — the app process lifecycle, `main()`, `bindApplication`.
- `frameworks/base/core/java/android/app/SharedPreferencesImpl.java` — Trace B in §4.2; a small masterclass in concurrent, crash-safe file handling.
- `frameworks/base/core/java/android/app/Instrumentation.java` — `execStartActivity` and `checkStartActivityResult`.

### Enforcement points

- `frameworks/base/services/core/java/com/android/server/wm/ActivityStarter.java` — every activity-launch policy decision. Trace A's destination.
- `frameworks/base/services/core/java/com/android/server/wm/ActivityTaskManagerService.java` — the Binder server for activity operations.
- `frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java` — broadcasts, processes, permission helpers.
- `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` — install, signature verification, component resolution.
- `frameworks/base/services/core/java/com/android/server/pm/permission/` — Trace C's destination. Class names have moved between releases; search rather than assume.
- `frameworks/base/services/core/java/com/android/server/appop/AppOpsService.java` — the second, silent permission gate.
- `frameworks/base/core/java/android/content/PermissionChecker.java` — the helper that combines permission, app-op and attribution, which is what modern framework code should use.

### Native and kernel

- `frameworks/native/libs/binder/IPCThreadState.cpp` — `transact`, `talkWithDriver`; where user space meets the driver.
- `frameworks/native/libs/binder/BpBinder.cpp` — the client-side native proxy.
- `frameworks/base/core/jni/android_util_Binder.cpp` — the JNI bridge between Java and native Binder.
- `frameworks/native/cmds/servicemanager/` — the service directory that `service list` shows you.
- `drivers/android/binder.c` (kernel) — `binder_ioctl`, `binder_transaction`. **Where caller identity is established, and the reason the whole security model works.**
- `bionic/linker/linker.cpp` — `dlopen`, linker namespaces, and why `LD_PRELOAD` sometimes does not work.
- `system/core/init/` — the first user-space process, `.rc` file semantics, and the `ro.*` property machinery.
- `system/core/debuggerd/` — tombstone generation.
- `art/runtime/hidden_api.cc` — hidden-API enforcement.
- `libcore/luni/src/main/java/javax/net/ssl/` — TLS defaults and trust manager dispatch.
- `system/security/keystore2/` — the Keystore implementation.
- `system/sepolicy/` — the policy that constrains everything above.

---

## Research and further reading

- **Google Project Zero blog** — https://googleprojectzero.blogspot.com/ — a large body of Android platform, kernel and vendor research, frequently showing the AOSP source reading in full. The best available worked examples of the methodology in §4.
- **"The Android Platform Security Model"** (Mayrhofer, Stoep, Brubaker, Kralevich) — the academic paper stating the model this chapter traces. Searchable by title; worth reading once end to end.
- **Android Developers Blog** — https://android-developers.googleblog.com/ — where platform behaviour changes and policy shifts are announced.
- **Android Open Source Project release notes** — https://source.android.com/docs/setup/about/build-numbers — release timing and tag mapping.

---

## Tools referenced in this chapter

| Tool | Where | Used for |
|---|---|---|
| `repo` | https://storage.googleapis.com/git-repo-downloads/repo | Managing the ~1000 repositories |
| `ripgrep` (`rg`) | https://github.com/BurntSushi/ripgrep | Tree-wide search; `grep` is impractically slow on AOSP |
| `fd` | https://github.com/sharkdp/fd | Fast file finding across the tree |
| `jadx` | https://github.com/skylot/jadx | Decompiling `services.jar` and preinstalled apps |
| `apktool` | https://apktool.org/ | Decoding binary manifests from preinstalled APKs |
| `apksigner` | Android SDK build-tools | Grouping preinstalled apps by signing certificate |
| `aapt2` | Android SDK build-tools | Reading manifests and permissions from APKs on an image |
| `oatdump` | On-device (AOSP `art/`) | Extracting DEX from `services.vdex` |
| `simg2img` | https://github.com/anestisb/android-simg2img | Converting sparse images for mounting |
| `payload_dumper` | community tooling | Extracting partitions from an A/B `payload.bin` |
| `sesearch` / `setools` | setools-android | Querying a shipped SELinux policy |
| Frida | https://frida.re/ | `Binder.execTransact` tracing; see [53-Frida](../../53-Frida/README.md) |
| Ghidra | https://ghidra-sre.org/ | Native reversing, with `symbols/` applied |

---

## Related chapters

- [06-Android-Architecture](../../06-Android-Architecture/README.md) — the system this source implements.
- [08-Build-System](../../08-Build-System/README.md) — how this source becomes an image; Soong, `lunch`, `m`, `m snod`.
- [12-DEX-Internals](../../12-DEX-Internals/README.md) — the bytecode format the framework ships as.
- [13-ART](../../13-ART/README.md) — the runtime, hidden-API enforcement, and extracting DEX from `services.vdex`.
- [15-Native-Code](../../15-Native-Code/README.md) — reversing the binaries `symbols/` helps you read.
- [16-JNI](../../16-JNI/README.md) — the Java-to-native bridge crossed in Trace A.
- [20-Security-Architecture](../../20-Security-Architecture/README.md) — the model the three traces demonstrate.
- [21-App-Sandbox](../../21-App-Sandbox/README.md) — the UID layer.
- [22-SELinux](../../22-SELinux/README.md) — the policy in `system/sepolicy/`.
- [23-Permissions](../../23-Permissions/README.md) — Trace C in full detail, including app-ops.
- [24-IPC](../../24-IPC/README.md) and [25-Binder](../../25-Binder/README.md) — Trace A's transport.
- [27-ContentProviders](../../27-ContentProviders/README.md) — `packages/providers/` as a model.
- [33-Storage](../../33-Storage/README.md) — Trace B's security consequences.
- [49-KeyStore](../../49-KeyStore/README.md) — `system/security/keystore2/`.
- [53-Frida](../../53-Frida/README.md) — the tooling in §7.
- [57-Ghidra](../../57-Ghidra/README.md) — applying `symbols/` to stripped binaries.
- [60-ADB](../../60-ADB/README.md) — the reconnaissance commands in §7.1.
- [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) — where §5's patterns are applied.
