# 21 — App Sandbox · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives you cross-references and history.
See [07-AOSP](../../07-AOSP/README.md) for the navigation technique. No line numbers are quoted
anywhere in this chapter; they change every release.

### The files that matter most

| Path | Open it when |
|---|---|
| `system/core/libcutils/include/private/android_filesystem_config.h` | You need the authoritative `AID_*` constants — every UID and GID range in §3.1. **The single most useful header for this chapter.** |
| `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp` | You want to read `SpecializeCommon()` — the sandbox, as code, in the order it is applied. If you read one file, read this one. |
| `frameworks/base/core/java/android/os/Process.java` | You need the Java-side range constants: `FIRST_APPLICATION_UID`, `FIRST_ISOLATED_UID`, `FIRST_APP_ZYGOTE_ISOLATED_UID`, `FIRST_SDK_SANDBOX_UID`, `toSdkSandboxUid()` |
| `frameworks/base/core/java/android/os/UserHandle.java` | You are doing UID arithmetic: `getUserId`, `getAppId`, `getUid`, `PER_USER_RANGE` |
| `system/core/run-as/run-as.cpp` | You want the whole of `run-as`, including the `packages.list` lookup and the debuggable check |
| `frameworks/base/data/etc/platform.xml` | You need the permission → GID mapping, including `INTERNET` → `inet` |
| `system/sepolicy/private/seapp_contexts` | You want to know exactly how an app's SELinux domain and file type are chosen |
| `system/sepolicy/public/isolated_app.te`, `system/sepolicy/private/isolated_app.te` | You are characterising what `isolatedProcess` actually removes — including the `neverallow` rules, which are the guarantees |

### Process creation and identity

| Path | Covers |
|---|---|
| `frameworks/base/core/java/com/android/internal/os/ZygoteConnection.java` | Parsing of the fork request: UID, GIDs, seinfo, runtime flags |
| `frameworks/base/core/java/com/android/internal/os/Zygote.java` | The Java side of `forkAndSpecialize` and `forkUsapPool` |
| `frameworks/base/services/core/java/com/android/server/am/ProcessList.java` | How `ActivityManagerService` builds process start arguments and allocates isolated UIDs |
| `frameworks/base/services/core/java/com/android/server/pm/Settings.java` | appId allocation and `packages.list` emission — the field order in §3.1 |
| `system/core/libpackagelistparser/` | The `packages.list` parser; the definitive statement of that file's format |
| `bionic/libc/bionic/grp_pwd.cpp` | Where `10388` becomes `u0_a288` — there is no `/etc/passwd` |

### Filesystem and installation

| Path | Covers |
|---|---|
| `frameworks/native/cmds/installd/InstalldNativeService.cpp` | The privileged operations performed on app data directories |
| `frameworks/native/cmds/installd/utils.cpp` | Every app data path constructor — `create_data_user_ce_package_path` and friends |
| `frameworks/native/cmds/installd/binder/android/os/IInstalld.aidl` | The complete list of privileged filesystem operations the platform will perform for an app. Fast way to see the whole surface. |
| `packages/providers/MediaProvider/` | The FUSE daemon and scoped storage enforcement |
| `system/vold/` | Storage mounting, CE/DE key management, `fscrypt` |

### Isolation features

| Path | Covers |
|---|---|
| `packages/modules/AdServices/sdksandbox/` | The SDK Runtime implementation |
| `system/sepolicy/private/sdk_sandbox*.te` | The `sdk_sandbox` domain |
| `frameworks/base/core/java/android/app/sdksandbox/` | `SdkSandboxManager`, `SandboxedSdkProvider` |
| `frameworks/base/services/core/java/com/android/server/pm/AppsFilter.java` | Package visibility filtering — where `<queries>` is actually evaluated |
| `bionic/libc/seccomp/` | Generated seccomp policies, plus `SECCOMP_ALLOWLIST_APP.TXT` and `SECCOMP_BLOCKLIST_APP.TXT`. Read the branch matching your target, not a blog post. |
| `bionic/libc/SYSCALLS.TXT` | The set of syscalls libc wraps — the input from which the app allowlist is generated |

---

## Official documentation

| Resource | Why |
|---|---|
| [Application Sandbox](https://source.android.com/docs/security/app-sandbox) | AOSP's own canonical statement. Short; read it once properly. |
| [Security-Enhanced Linux in Android](https://source.android.com/docs/security/features/selinux) | The MAC layer, its domains, and how policy is built |
| [Android Security Overview](https://source.android.com/docs/security/overview) | Where the sandbox sits in the whole model |
| [App sandbox (developer docs)](https://developer.android.com/guide/topics/permissions/overview) | The developer-facing framing, which is what your remediation text has to align with |
| [Data and file storage overview](https://developer.android.com/training/data-storage) | CE/DE, app-specific vs shared, and which APIs need which permission |
| [Storage updates in Android 11](https://developer.android.com/about/versions/11/privacy/storage) | Scoped storage as actually shipped |
| [Package visibility filtering](https://developer.android.com/training/package-visibility) | `<queries>`, and the list of always-visible packages |
| [`<service>` manifest reference](https://developer.android.com/guide/topics/manifest/service-element) | The precise semantics of `android:isolatedProcess`, `android:process`, `android:externalService`, `android:useAppZygote` |
| [SDK Runtime](https://developer.android.com/design-for-safety/privacy-sandbox/sdk-runtime) | Privacy Sandbox on Android — the SDK isolation model |
| [Auto Backup for Apps](https://developer.android.com/guide/topics/data/autobackup) | `allowBackup`, `dataExtractionRules`, `fullBackupContent`, `noBackupFilesDir` |
| [`FileProvider`](https://developer.android.com/reference/androidx/core/content/FileProvider) | The remediation you will recommend for every `openFile` traversal |
| [Behaviour changes index](https://developer.android.com/about/versions) | **Check this before asserting any version-dependent behaviour.** The single highest-value habit in this chapter. |

---

## Kernel documentation

| Resource | Why |
|---|---|
| `Documentation/userspace-api/seccomp_filter.rst` | The seccomp-bpf interface, return values, and the `no_new_privs` requirement |
| `Documentation/admin-guide/LSM/Yama.rst` | `ptrace_scope`, one of the three things that stops cross-app `ptrace` |
| `man 7 capabilities` | The capability model and the five sets; read the bounding-set section carefully |
| `man 2 prctl` | `PR_SET_NO_NEW_PRIVS`, `PR_SET_SECCOMP`, `PR_SET_DUMPABLE` |
| `man 7 unix`, `man 3 cmsg` | `SCM_RIGHTS` descriptor passing — the mechanism behind escape class 5 |
| `man 5 proc` | What every field in `/proc/<pid>/status` means; the reference behind lab 1 |
| `Documentation/filesystems/proc.rst` | `hidepid` and the `/proc` hardening of Android 10 |

---

## Tooling

| Tool | Where | Use |
|---|---|---|
| `adb` | host | Everything. See [60-ADB](../../60-ADB/README.md). |
| `dumpsys package` | device | UID, GIDs, data directory, flags, `sharedUser`, declared components |
| `pm list packages -U`, `pm list users` | device | The UID map and the user/work-profile list without root |
| `run-as` | device | Become the app — debuggable builds only |
| `strace` | device (root) | DAC denials, as `EACCES` on `openat` |
| `dmesg` / `logcat` | device (root) | `avc:` lines for SELinux, `type=1326` for seccomp |
| [Frida](https://frida.re/docs/android/) | host + device | In-process probing; see `../scripts/` |
| [Objection](https://github.com/sensepost/objection) | host | Fast sandbox and storage triage on top of Frida |
| [jadx](https://github.com/skylot/jadx) | host | Decompilation; also decodes the binary manifest |
| [apktool](https://apktool.org/) | host | Decode `AndroidManifest.xml` and resources |
| [drozer](https://github.com/WithSecureLabs/drozer) | host + agent | Exported-component sweeps from an actual **app** context |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | host | First-pass manifest and storage triage; verify every finding manually |
| **A purpose-built probe APK** | device | The only experiment that proves app-reachability. See [`../examples/attacker-app/`](../examples/attacker-app/) and [24-IPC's probe](../../24-IPC/examples/attacker-app/README.md). |

---

## Security research

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly, authoritative. Read for the *pattern* of which subsystems recur — drivers, media, `system_server` — rather than for individual identifiers. |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | The highest-quality public work on Android kernel and privileged-service exploitation, which is where genuine sandbox escapes live |
| [Android VRP rules](https://bughunters.google.com/about/rules/android-friends) | Google's own severity model — useful for calibrating how *they* rate an escape versus an app misconfiguration |
| [Android Compatibility Definition Document](https://source.android.com/docs/compatibility/cdd) | What an OEM is *required* to implement. When a device behaves oddly, this tells you whether that is permitted. |

> **Note on CVE citation.** This chapter deliberately describes vulnerability *classes* rather than
> naming identifiers. Kernel and driver bugs are numerous, device-specific and version-specific, and a
> misattributed CVE in a client report is worse than no citation at all. When you need a specific
> reference, pull it from the bulletin for the affected release rather than from memory.

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | **MASVS-STORAGE** (private storage, backups, logs, clipboard), **MASVS-PLATFORM** (IPC, WebView, overlays and capture), **MASVS-CODE** (third-party dependencies, release hygiene), **MASVS-RESILIENCE** (debuggable builds) |
| [MASTG](https://mas.owasp.org/MASTG/) | The data-storage and platform-interaction test chapters map directly onto §5.8 |
| MASTG test apps | Practice targets — see [80-Appendix](../../80-Appendix/README.md) |

See [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) for the current identifier scheme, which has
changed more than once.

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Security Internals* — Nikolay Elenkov | The best structural account of the security model this chapter describes. Dated in specifics; the architecture is still correct. |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest published treatment of Zygote, `init`, and process creation. Occasionally idiosyncratic, unmatched on detail. |
| *The Linux Programming Interface* — Michael Kerrisk | The reference for everything in §3.2 and §3.6 — credentials, capabilities, file permissions, `/proc`. If DAC feels vague, the answer is in here. |
| *SELinux by Example* / the SELinux Notebook | Type enforcement and MLS/MCS, which is what §3.4 compresses into two pages |

---

## Conference talks worth finding

Search for these topics rather than specific URLs, since hosting moves:

- Android sandbox escape chains — Black Hat, OffensiveCon, and the Project Zero blog
- Binder and `system_server` attack surface — Black Hat mobile tracks
- The Privacy Sandbox / SDK Runtime design rationale — Google's own developer events
- Scoped storage migration and its bypasses — mobile security conference tracks
- Isolated processes and site isolation in WebView — Chromium security talks

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | UIDs, GIDs, file modes, `/proc` — the prerequisites, if any of §3.1–3.2 felt fast |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Where the sandbox sits in the whole model — read first |
| [22-SELinux](../../22-SELinux/README.md) | The second enforcement layer, in full: domains, types, MCS, policy debugging |
| [23-Permissions](../../23-Permissions/README.md) | What the sandbox deliberately lets through, and the GID-backed permissions |
| [24-IPC](../../24-IPC/README.md) | The doors in the wall, and the probe-app methodology this chapter borrows |
| [25-Binder](../../25-Binder/README.md) | How identity crosses the boundary: `getCallingUid`, `SCM_RIGHTS`, transaction handling |
| [26-Intent](../../26-Intent/README.md) | Intent redirection, `PendingIntent` mutability, deep links |
| [27-ContentProviders](../../27-ContentProviders/README.md) | `openFile` traversal, `UriMatcher`, URI permission grants |
| [32-Manifest](../../32-Manifest/README.md) | `exported`, `permission`, `debuggable`, `allowBackup`, `sharedUserId` — the highest-yield file in the APK |
| [33-Storage](../../33-Storage/README.md) | Scoped storage, CE/DE, and data-at-rest in detail |
| [37-RootDetection](../../37-RootDetection/README.md) | What the world looks like when the sandbox's assumptions are gone |
| [43-WebView](../../43-WebView/README.md) | The platform's flagship user of `isolatedProcess` |
| [49-KeyStore](../../49-KeyStore/README.md) | The one place a secret can live that survives a compromise of the sandbox's contents |
| [53-Frida](../../53-Frida/README.md) | The in-process instrumentation used by `../scripts/` |
| [62-Magisk](../../62-Magisk/README.md) | How root tooling coexists with SELinux |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | How real malware works *around* the sandbox rather than through it |
