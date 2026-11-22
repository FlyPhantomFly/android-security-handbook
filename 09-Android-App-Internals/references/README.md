# 09 — Android App Internals — References

Every entry has a one-line annotation saying **why you would open it**. Links to AOSP point at
`refs/heads/main`; if a file has moved in the release you are studying, use the tree search on
`android.googlesource.com` rather than assuming the path is wrong.

> **Warning**
> AOSP file paths in this repository are real, but AOSP *line numbers* are not quoted anywhere,
> because they change with every commit. Where a paper, talk or vulnerability is listed without a
> URL, that is deliberate — the title and venue are given so you can find the authoritative copy
> yourself rather than trust a guessed link.

---

## 1. AOSP source — package management and identity

| Path | Why you would read it |
|---|---|
| [`frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/PackageManagerService.java) | The service that owns every package record, appId allocation and install decision. |
| [`frameworks/base/services/core/java/com/android/server/pm/Settings.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/Settings.java) | Reads and writes `packages.xml` and `packages.list`; the authoritative field order lives here. |
| [`frameworks/base/services/core/java/com/android/server/pm/InstallPackageHelper.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/InstallPackageHelper.java) | The modern home of the install pipeline that was historically inline in PMS. |
| [`frameworks/base/services/core/java/com/android/server/pm/AppDataHelper.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/AppDataHelper.java) | Where CE/DE data directories are requested from `installd` and their SELinux labels are set. |
| [`frameworks/base/services/core/java/com/android/server/pm/DexOptHelper.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/DexOptHelper.java) | Drives `dexopt`/`dex2oat` during and after installation. |
| [`frameworks/base/services/core/java/com/android/server/pm/PackageInstallerService.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/PackageInstallerService.java) | Server side of the session API — where `install-create` lands. |
| [`frameworks/base/services/core/java/com/android/server/pm/PackageInstallerSession.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/PackageInstallerSession.java) | One install session: staging, validation, split handling, commit. |
| [`frameworks/base/services/core/java/com/android/server/pm/UserManagerService.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/UserManagerService.java) | Creation and lifecycle of users and profiles — the source of `userId`. |
| [`frameworks/base/services/core/java/com/android/server/pm/permission/`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/permission/) | Permission grant state, including the permission-to-GID computation. |
| [`frameworks/base/core/java/android/content/pm/PackageInstaller.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/content/pm/PackageInstaller.java) | The public session API: `SessionParams`, `Session`, `openWrite`, `commit`. |
| [`frameworks/base/core/java/android/content/pm/ApplicationInfo.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/content/pm/ApplicationInfo.java) | Canonical list of `FLAG_*` and `PRIVATE_FLAG_*` bits you decode in `dumpsys` output. |
| [`frameworks/base/core/java/android/content/pm/PackageManager.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/content/pm/PackageManager.java) | Client-side API surface: `getPackagesForUid`, `checkSignatures`, `hasSigningCertificate`. |
| [`frameworks/base/core/java/android/util/apk/ApkSignatureVerifier.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/util/apk/ApkSignatureVerifier.java) | Entry point for v1/v2/v3/v4 signature verification during install. |
| [`frameworks/base/data/etc/platform.xml`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/data/etc/platform.xml) | The permission → supplementary GID mapping (`INTERNET` → 3003, and friends). |

---

## 2. AOSP source — UIDs, users and the identity arithmetic

| Path | Why you would read it |
|---|---|
| [`frameworks/base/core/java/android/os/Process.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/Process.java) | `FIRST_APPLICATION_UID`, `LAST_APPLICATION_UID`, isolated and SDK-sandbox ranges, `myUid()`. |
| [`frameworks/base/core/java/android/os/UserHandle.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/UserHandle.java) | `PER_USER_RANGE`, `getUserId(uid)`, `getAppId(uid)`, `getUid(userId, appId)` — the arithmetic itself. |
| [`system/core/libcutils/include/private/android_filesystem_config.h`](https://android.googlesource.com/platform/system/core/+/refs/heads/main/libcutils/include/private/android_filesystem_config.h) | The definitive AID table: every named UID/GID constant and every reserved range. |
| [`bionic/libc/bionic/grp_pwd.cpp`](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/bionic/grp_pwd.cpp) | How `getpwuid()` synthesises `u0_a234` from an integer with no `/etc/passwd`. |
| [`system/core/run-as/run-as.cpp`](https://android.googlesource.com/platform/system/core/+/refs/heads/main/run-as/run-as.cpp) | Why `run-as` refuses non-debuggable apps — it parses `packages.list` field 3. |
| [`frameworks/base/core/java/android/os/UserManager.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/UserManager.java) | Client API for users, profiles and managed-profile queries. |

---

## 3. AOSP source — installd, storage and SELinux labelling

| Path | Why you would read it |
|---|---|
| [`frameworks/native/cmds/installd/`](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/cmds/installd/) | The privileged native daemon that creates, labels, snapshots and destroys app data. |
| [`frameworks/native/cmds/installd/InstalldNativeService.cpp`](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/cmds/installd/InstalldNativeService.cpp) | `createAppData`, `destroyAppData`, `restoreconAppData` — the real directory creation. |
| [`frameworks/native/cmds/installd/dexopt.cpp`](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/cmds/installd/dexopt.cpp) | How `dex2oat` is invoked, with which compiler filter and which sandbox. |
| [`frameworks/native/cmds/installd/binder/android/os/IInstalld.aidl`](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/cmds/installd/binder/android/os/IInstalld.aidl) | The exact Binder interface PMS uses to command `installd`. |
| [`system/sepolicy/private/seapp_contexts`](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/seapp_contexts) | Maps `seinfo` + `targetSdk` + privilege to an SELinux domain and `levelFrom` policy. |
| [`system/sepolicy/private/file_contexts`](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/file_contexts) | Says `/data/data/...` is `app_data_file`; the other half of the labelling story. |
| [`external/selinux/libselinux/src/android/`](https://android.googlesource.com/platform/external/selinux/+/refs/heads/main/libselinux/src/android/) | The `levelFrom=all` category arithmetic that produces `c234,c256,c512,c768`. |
| [`system/vold/`](https://android.googlesource.com/platform/system/vold/+/refs/heads/main/) | Volume daemon: CE/DE key management, per-user storage mounts, FUSE sandbox setup. |

---

## 4. AOSP source — process creation and the app bootstrap

| Path | Why you would read it |
|---|---|
| [`frameworks/base/core/java/android/app/ActivityThread.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/ActivityThread.java) | `main()`, `handleBindApplication()`, `installContentProviders()` — the ordering that makes providers run first. |
| [`frameworks/base/core/java/android/app/Instrumentation.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/Instrumentation.java) | `callApplicationOnCreate()` and `newApplication()` — the hookable seam for startup tracing. |
| [`frameworks/base/core/java/android/app/LoadedApk.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/LoadedApk.java) | Builds the class loader and creates the `Application` instance; where split APKs become code. |
| [`frameworks/base/core/java/com/android/internal/os/ZygoteInit.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/com/android/internal/os/ZygoteInit.java) | Preload, socket loop and the point where a fork becomes an app. |
| [`frameworks/base/core/java/com/android/internal/os/Zygote.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/com/android/internal/os/Zygote.java) | The Java side of `forkAndSpecialize` — UID, GIDs, capabilities, seccomp, SELinux. |
| [`frameworks/base/core/jni/com_android_internal_os_Zygote.cpp`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/jni/com_android_internal_os_Zygote.cpp) | The native specialisation: `setuid`, `setgroups`, `capset`, `selinux_android_setcontext`. |
| [`frameworks/base/core/java/android/os/ZygoteProcess.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/ZygoteProcess.java) | The socket protocol AMS uses to ask Zygote for a new process. |
| [`frameworks/base/core/java/android/os/Looper.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/Looper.java) | The main-thread loop whose starvation produces an ANR. |
| [`frameworks/base/core/java/android/os/MessageQueue.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-13.0.0_r1/core/java/android/os/MessageQueue.java) | `epoll`-backed queue; the native side of "the UI thread is blocked". |
| [`frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/am/ActivityManagerService.java) | Decides when to start a process and when to kill one. |
| [`frameworks/base/services/core/java/com/android/server/am/ProcessList.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/am/ProcessList.java) | The `*_ADJ` constants written to `/proc/<pid>/oom_score_adj`. |
| [`system/memory/lmkd/`](https://android.googlesource.com/platform/system/memory/lmkd/+/refs/heads/main/) | The userspace low-memory killer that turns those adj values into dead processes. |
| [`packages/modules/`](https://android.googlesource.com/platform/packages/modules/) | Mainline modules — several install-flow and permission components now ship here rather than in `frameworks/base`. |

---

## 5. AOSP source — background policy

| Path | Why you would read it |
|---|---|
| [`frameworks/base/apex/jobscheduler/service/java/com/android/server/usage/AppStandbyController.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-13.0.0_r1/apex/jobscheduler/service/java/com/android/server/usage/AppStandbyController.java) | Bucket assignment logic behind `am get-standby-bucket`. |
| [`frameworks/base/apex/jobscheduler/service/java/com/android/server/DeviceIdleController.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-13.0.0_r1/apex/jobscheduler/service/java/com/android/server/DeviceIdleController.java) | The Doze state machine you drive with `dumpsys deviceidle`. |
| [`frameworks/base/core/java/android/app/usage/UsageStatsManager.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/usage/UsageStatsManager.java) | `STANDBY_BUCKET_*` constants (10/20/30/40/45/50). |

---

## 6. Official Android developer documentation

| Link | Why you would read it |
|---|---|
| [Application fundamentals](https://developer.android.com/guide/components/fundamentals) | Google's own statement that each app is a separate Linux user with its own UID. |
| [Processes and threads](https://developer.android.com/guide/components/processes-and-threads) | `android:process`, process importance ranking, main-thread rules. |
| [App startup time](https://developer.android.com/topic/performance/vitals/launch-time) | Cold/warm/hot start definitions and how to measure them. |
| [App Startup library (`androidx.startup`)](https://developer.android.com/topic/libraries/app-startup) | The sanctioned provider-based initialisation mechanism you will find in merged manifests. |
| [Direct Boot](https://developer.android.com/training/articles/direct-boot) | CE vs DE storage, `directBootAware`, `createDeviceProtectedStorageContext()`. |
| [Data and file storage overview](https://developer.android.com/training/data-storage) | Which directory an app is supposed to use for what. |
| [App-specific storage](https://developer.android.com/training/data-storage/app-specific) | `getFilesDir`, `getCacheDir`, `getExternalFilesDir` and their deletion semantics. |
| [`PackageInstaller`](https://developer.android.com/reference/android/content/pm/PackageInstaller) | Session-based install API reference — the thing `adb install` drives. |
| [`PackageInstaller.SessionParams`](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams) | Install reason, package source, staged sessions, multi-package sessions. |
| [`ApplicationInfo`](https://developer.android.com/reference/android/content/pm/ApplicationInfo) | Flag constants you will decode from `dumpsys package`. |
| [`android.os.Process`](https://developer.android.com/reference/android/os/Process) | `myUid()`, `myPid()`, `myUserHandle()`, the UID range constants. |
| [`UserHandle`](https://developer.android.com/reference/android/os/UserHandle) | `getUserHandleForUid()` and the public half of the UID arithmetic. |
| [`<manifest>` element](https://developer.android.com/guide/topics/manifest/manifest-element) | Where `sharedUserId` and `sharedUserMaxSdkVersion` are documented, deprecation included. |
| [`<application>` element](https://developer.android.com/guide/topics/manifest/application-element) | `debuggable`, `allowBackup`, `process`, `directBootAware`. |
| [`<service>` element](https://developer.android.com/guide/topics/manifest/service-element) | `android:isolatedProcess` and `android:process`. |
| [Support multiple users](https://developer.android.com/reference/android/os/UserManager) | Developer-facing view of per-user app instances. |
| [Work profiles / enterprise](https://developer.android.com/work/managed-profiles) | How the profile boundary behaves for an ordinary app. |
| [App standby buckets](https://developer.android.com/topic/performance/appstandby) | Bucket names, numeric values and what each bucket throttles. |
| [Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby) | The idle state machine and the whitelist. |
| [Keep your app responsive (ANRs)](https://developer.android.com/topic/performance/anrs/keep-your-app-responsive) | The timeout values and how traces are produced. |
| [Tasks and the back stack](https://developer.android.com/guide/components/activities/tasks-and-back-stack) | `launchMode`, `taskAffinity`, and the model task-hijacking research attacks. |
| [Android App Bundles](https://developer.android.com/guide/app-bundle) | Why one app arrives as several APKs. |
| [Play Feature Delivery](https://developer.android.com/guide/playcore/feature-delivery) | Dynamic feature modules — code that appears after install. |
| [Instant Apps overview](https://developer.android.com/topic/google-play-instant) | The restricted, unsigned-into-the-launcher install model. |
| [Privacy Sandbox SDK Runtime](https://developer.android.com/design-for-safety/privacy-sandbox/sdk-runtime) | Why some processes run with UIDs outside the usual app range on API 33+. |

---

## 7. Official Android platform (source.android.com) documentation

| Link | Why you would read it |
|---|---|
| [Application sandbox](https://source.android.com/docs/security/app-sandbox) | The platform team's own description of the UID sandbox and its SELinux reinforcement. |
| [SELinux concepts](https://source.android.com/docs/security/features/selinux/concepts) | Domains, types and the MLS categories on app labels. |
| [Implementing SELinux](https://source.android.com/docs/security/features/selinux/implement) | `seapp_contexts`, `file_contexts` and how labels are actually assigned. |
| [File-based encryption](https://source.android.com/docs/security/features/encryption/file-based) | The mechanism behind CE and DE directories. |
| [Multiple users](https://source.android.com/docs/devices/admin/multi-user) | Platform view of `userId`, profiles and per-user storage. |
| [APK signature scheme v2](https://source.android.com/docs/security/features/apksigning/v2) | What install-time verification is checking. |
| [APK signature scheme v3](https://source.android.com/docs/security/features/apksigning/v3) | Key rotation and the proof-of-rotation lineage PMS records. |
| [APK signature scheme v4](https://source.android.com/docs/security/features/apksigning/v4) | Incremental/streamed installs and fs-verity. |
| [Low memory killer daemon](https://source.android.com/docs/core/perf/lmkd) | How memory pressure becomes a process kill. |
| [ART and dexopt / compilation](https://source.android.com/docs/core/runtime) | Where the `.odex`/`.vdex`/`.art` files created at install come from. |
| [Android security bulletins](https://source.android.com/docs/security/bulletin) | The authoritative place to look up real CVEs affecting PMS, installd and the sandbox. |

---

## 8. OWASP MASVS / MASTG

The Mobile Application Security Verification Standard (MASVS) states *what* must be true; the Mobile
Application Security Testing Guide (MASTG) states *how* you test it.

| Identifier | Relevance to this chapter |
|---|---|
| [MASVS-STORAGE-1](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/) | Sensitive data must be stored securely in app-private storage — i.e. inside the UID sandbox, not on shared storage. |
| MASVS-STORAGE-2 | The app must prevent leakage of sensitive data — backups, logs, external storage, DE storage. |
| [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/) | IPC mechanisms must be used securely — exported components, providers, shared UIDs. |
| MASVS-PLATFORM-2 | WebViews configured securely — relevant to isolated renderer processes. |
| MASVS-PLATFORM-3 | Sensitive data must not be exposed through the user interface or notifications. |
| [MASVS-RESILIENCE-1](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/) | The app validates the integrity of the platform (root/emulator/debuggable checks). |
| MASVS-RESILIENCE-2 | The app implements anti-tampering — signature checks, which is the only real package-identity control. |
| MASVS-RESILIENCE-4 | The app impedes dynamic analysis — debuggable flag, JDWP, `ptrace`, Frida detection. |
| [MASVS-CODE-3](https://mas.owasp.org/MASVS/10-MASVS-CODE/) | Third-party components must be current and free of known vulnerabilities — the SDK-provider supply-chain problem. |

MASTG tests worth running against this chapter's material — search
[mas.owasp.org/MASTG](https://mas.owasp.org/MASTG/) by title rather than by a memorised number, since
the numeric test IDs were renumbered in MASTG v2:

| MASTG test title | What it exercises here |
|---|---|
| Testing Local Storage for Sensitive Data | `/data/data/<pkg>` enumeration, `shared_prefs`, SQLite, DE storage |
| Testing Local Storage for Input Validation | provider and file-based inputs into the sandbox |
| Testing Backups for Sensitive Data | `android:allowBackup`, `no_backup/`, `adb backup` |
| Testing Logs for Sensitive Data | logcat output from `Application.onCreate` and provider init |
| Determining Whether Sensitive Data Is Shared with Third Parties | third-party SDK providers running before your code |
| Testing Whether the App Is Debuggable | `FLAG_DEBUGGABLE`, `run-as`, JDWP |
| Testing for Debugging Symbols / Debugging Code | leftover debug scaffolding in release builds |
| Testing Anti-Debugging Detection | `TracerPid`, `ptrace`, JDWP detection |
| Testing Enforced Updating / Integrity | signature verification and install provenance |
| [MASTG demos and Android hacking techniques](https://mas.owasp.org/MASTG/0x05b-Android-Security-Testing/) | Concrete `adb`, `frida` and `objection` recipes matching this chapter's commands |

---

## 9. Books

| Title | Why |
|---|---|
| *Android Security Internals* — Nikolay Elenkov, No Starch Press, 2014 | Still the clearest written explanation of package management, UIDs, signing and permissions; API level is old, the architecture is not. |
| *Android Internals: A Confectioner's Cookbook* (Volumes I and II) — Jonathan Levin | Deep, hands-on treatment of Zygote, `init`, `installd` and the process model with real command output. |
| *The Android Hacker's Handbook* — Drake, Lanier, Mulliner, Fora, Ridley, Wicherski, Wiley, 2014 | The classic offensive treatment; useful for the historic vulnerability classes in package management. |
| *Android Security Cookbook* — Makan and Alexander-Bown, Packt, 2013 | Dated, but the shared-UID and debuggable-app recipes still map cleanly onto modern devices. |

---

## 10. Research papers

Given as title, authors and venue. Look them up through your library, ACM DL, IEEE Xplore or the
authors' own pages rather than trusting a copied URL.

| Paper | Relevance |
|---|---|
| "Upgrading Your Android, Elevating My Malware: Privilege Escalation Through Mobile OS Updating" — Xing, Pan, Wang, Yuan, Wang — IEEE Symposium on Security and Privacy, 2014 | The "Pileup" class: how package/permission records surviving an OS upgrade become privilege escalation. Directly about `packages.xml` semantics. |
| "Towards Discovering and Understanding Task Hijacking in Android" — Ren, Zhang, Wang, Chen, Mao — USENIX Security, 2015 | The systematic study behind task-affinity and `launchMode` abuse. |
| "Android Permissions Demystified" — Felt, Chin, Hanna, Song, Wagner — ACM CCS, 2011 | The original mapping of permissions to what they actually gate, including GID-backed permissions. |
| "Unauthorized Origin Crossing on Mobile Platforms: Threats and Mitigation" — Wang, Unuchek, Wang, Chen — ACM CCS, 2013 | Cross-app identity confusion, of which shared-UID abuse is a special case. |
| "The Impact of Vendor Customizations on Android Security" — Wu, Gao, Rohde, Enck, Jiang — ACM CCS, 2013 | Why OEM builds change the sandbox assumptions you verified on AOSP. |
| "An Empirical Study of Android Application Repackaging" (repackaging/clone detection literature, multiple venues) | Why package name alone is not identity and signature comparison is mandatory. |
| "Analysis of Android SDK supply chain and third-party library behaviour" (multiple works, ACM/IEEE, 2017–present) | Systematic evidence for the "your dependency runs before your code" problem. |

---

## 11. Talks and industry research

| Talk | Venue | Relevance |
|---|---|---|
| "Honey, I Shrunk the Attack Surface — Adventures in Android Security Hardening" — Nick Kralevich | Black Hat USA, 2017 | First-hand account of how the app sandbox, SELinux and seccomp were tightened, and why. |
| "Android: Protecting the Kernel" — Jeff Vander Stoep | Linux Security Summit, 2016 | The kernel-side hardening that backs the UID sandbox. |
| "The Android Platform Security Model" — Mayrhofer, Vander Stoep, Brubaker, Kralevich (paper and conference presentations) | ACM TOPS / various | The single best formal statement of *why* the app is the security principal. Read this if you read only one item on this page. |
| "StrandHogg" task-hijacking disclosure — Promon research, 2019 | vendor research publication | Real-world exploitation of task affinity in the wild; pair with the USENIX 2015 paper above. |
| [Google Online Security Blog](https://security.googleblog.com/) | — | Primary source for platform hardening announcements affecting installs, sandboxing and storage. |
| [Android Developers Blog](https://android-developers.googleblog.com/) | — | Where behaviour changes such as `sharedUserMaxSdkVersion`, scoped storage and package visibility were announced. |
| [Google Project Zero blog](https://googleprojectzero.blogspot.com/) | — | In-depth Android exploitation write-ups; search the archive for `installd`, `PackageManager` and sandbox escapes rather than assuming a specific post URL. |

---

## 12. Tooling documentation

| Link | Why |
|---|---|
| [`adb` documentation](https://developer.android.com/tools/adb) | `install`, `install-multiple`, `install-multi-package`, `shell pm`, `shell cmd package`. |
| [`aapt2` documentation](https://developer.android.com/tools/aapt2) | `dump xmltree` for reading the merged manifest of a built APK. |
| [`apksigner` documentation](https://developer.android.com/tools/apksigner) | `verify --print-certs` — the only trustworthy identity check. |
| [`apkanalyzer` documentation](https://developer.android.com/tools/apkanalyzer) | Scriptable manifest queries such as `manifest debuggable`. |
| [`bundletool`](https://developer.android.com/tools/bundletool) | Build and install split sets from an `.aab` for the split-install lab. |
| [Frida documentation](https://frida.re/docs/android/) | The Android-specific attach models referenced in `scripts/trace-app-startup.js`. |
| [Objection](https://github.com/sensepost/objection) | Wraps many of this chapter's inspection commands in a runtime shell. |
| [Android Studio profiler / Layout Inspector](https://developer.android.com/studio/profile) | Visual confirmation of process count and startup phases. |

---

## 13. Where this chapter connects

| Chapter | Connection |
|---|---|
| [`../06-Android-Architecture/README.md`](../../06-Android-Architecture/README.md) | Where `system_server`, PMS and AMS sit relative to the kernel and the app. |
| [`../07-AOSP/README.md`](../../07-AOSP/README.md) | How to fetch and search the source tree these paths refer to. |
| [`../10-APK-Internals/README.md`](../../10-APK-Internals/README.md) | The container that gets parsed, verified and unpacked by the install flow. |
| [`../11-Android-Runtime/README.md`](../../11-Android-Runtime/README.md) | What `dex2oat` produces and what the forked Zygote child actually runs. |
| [`../20-Security-Architecture/README.md`](../../20-Security-Architecture/README.md) | The platform security model this chapter is one layer of. |
| [`../21-App-Sandbox/README.md`](../../21-App-Sandbox/README.md) | Enforcement of the UID boundary introduced here. |
| [`../22-SELinux/README.md`](../../22-SELinux/README.md) | Domains, `seapp_contexts` and the MLS category encoding. |
| [`../23-Permissions/README.md`](../../23-Permissions/README.md) | Permission-to-GID mapping and runtime grant state. |
| [`../26-Intent/README.md`](../../26-Intent/README.md) | How caller identity is established across component boundaries. |
| [`../27-ContentProviders/README.md`](../../27-ContentProviders/README.md) | Providers as both an IPC surface and a startup hook. |
| [`../32-Manifest/README.md`](../../32-Manifest/README.md) | Every attribute this chapter reads out of the merged manifest. |
| [`../33-Storage/README.md`](../../33-Storage/README.md) | CE/DE, scoped storage, FUSE and shared media. |
| [`../53-Frida/README.md`](../../53-Frida/README.md) | Attaching to the processes and hooking the bootstrap methods traced here. |
| [`../60-ADB/README.md`](../../60-ADB/README.md) | The transport that implements `adb install` on top of the session API. |
| [`../69-MalwareAnalysis/README.md`](../../69-MalwareAnalysis/README.md) | Provider-based persistence, multi-process watchdogs and installer attribution abuse. |
