# 06 — Android Architecture · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## AOSP source

Read on [cs.android.com](https://cs.android.com/). See [07-AOSP](../../07-AOSP/README.md) for the
navigation technique. File paths are stable across releases; line numbers are not.

### Boot and init

| Path | Open it when |
|---|---|
| `system/core/init/init.cpp` | Tracing what PID 1 actually does |
| `system/core/init/service.cpp` | Understanding `Service::Start()` — fork, setexeccon, capabilities, setuid, exec |
| `system/core/init/service_parser.cpp` | Working out what an `.rc` option means |
| `system/core/init/property_service.cpp` | **The write path and `CheckPermissions()`** — the SELinux asymmetry |
| `system/core/init/action_manager.cpp` | How triggers fire |
| `system/core/rootdir/init.rc` | The default init script; what starts in what order |
| `system/core/init/ueventd.cpp` | Device node creation |

### Zygote — the most important reading in this chapter

| Path | Open it when |
|---|---|
| `frameworks/base/cmds/app_process/app_main.cpp` | The binary `init` execs to create Zygote |
| `frameworks/base/core/jni/AndroidRuntime.cpp` | `startVm()` — every ART option, many from `dalvik.vm.*` |
| `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java` | Preload and the select loop |
| `frameworks/base/core/java/com/android/internal/os/ZygoteConnection.java` | Argument parsing |
| **`frameworks/base/core/jni/com_android_internal_os_Zygote.cpp`** | **`SpecializeCommon()` — where the app sandbox is actually built.** If you read one function, read this |
| `frameworks/base/core/java/com/android/internal/os/RuntimeInit.java` | How the child becomes an app |

### Framework

| Path | Covers |
|---|---|
| `frameworks/base/services/java/com/android/server/SystemServer.java` | Service startup order — a map of the framework |
| `frameworks/base/services/core/java/com/android/server/` | `am/`, `pm/`, `wm/`, `power/` — the services themselves |
| `frameworks/base/core/java/android/app/ActivityThread.java` | The app process entry point |
| `frameworks/native/cmds/servicemanager/` | Service registration and `Access.cpp`'s SELinux check |
| `frameworks/native/libs/binder/` | `IPCThreadState.cpp`, `Parcel.cpp` — see [25](../../25-Binder/README.md) |

### Platform infrastructure

| Path | Covers |
|---|---|
| `bionic/libc/system_properties/` | The property implementation: `prop_area.cpp`, the trie |
| `bionic/libc/seccomp/` | The syscall allow-lists Zygote installs |
| `system/sepolicy/` | The MAC policy; `property_contexts`, `seapp_contexts`, `file_contexts` |
| `system/apex/` | `apexd` and the APEX container format |
| `external/avb/` | `avbtool` and the vbmeta format |
| `system/core/fs_mgr/` | `liblp` (dynamic partitions) and verity setup |
| `system/vold/` | Volume management and FBE key handling |
| `system/memory/lmkd/` | The userspace low-memory killer |
| `hardware/interfaces/` | Every HAL interface, HIDL `.hal` and AIDL |

---

## Official documentation

### Architecture

| Resource | Why |
|---|---|
| [Platform architecture](https://developer.android.com/guide/platform) | The canonical layer diagram, from the developer side |
| [Android Open Source Project](https://source.android.com/) | The platform-side documentation root |
| [Treble](https://source.android.com/docs/core/architecture/partitions) | The vendor/system split and why it exists |
| [HAL types](https://source.android.com/docs/core/architecture/hal-types) | HIDL vs AIDL vs passthrough |
| [VNDK](https://source.android.com/docs/core/architecture/vndk) | Which native libraries vendor code may use |

### Boot, integrity and partitions

| Resource | Why |
|---|---|
| [Verified Boot](https://source.android.com/docs/security/features/verifiedboot) | AVB, the boot states, rollback protection |
| [dm-verity](https://source.android.com/docs/security/features/verifiedboot/dm-verity) | The Merkle tree and verification-on-read |
| [Boot image header](https://source.android.com/docs/core/architecture/bootloader/boot-image-header) | Format, for when you unpack `boot.img` |
| [Dynamic partitions](https://source.android.com/docs/core/ota/dynamic_partitions) | `super`, `liblp`, why `fastbootd` exists |
| [A/B seamless updates](https://source.android.com/docs/core/ota/ab) | Slots, rollback, the `misc` control block |
| [fs-verity](https://source.android.com/docs/security/features/apksigning/v4) | Per-file integrity for APKs |

### Mainline

| Resource | Why |
|---|---|
| [Modular System Components](https://source.android.com/docs/core/ota/modular-system) | What is modularised and why |
| [APEX file format](https://source.android.com/docs/core/ota/apex) | The container format |
| [ART Mainline module](https://source.android.com/docs/core/ota/modular-system/art) | Why runtime internals differ across devices on one release |

### Properties and services

| Resource | Why |
|---|---|
| [Configuring the system properties](https://source.android.com/docs/core/architecture/configuration) | Property namespaces and contexts |
| [Android init language](https://android.googlesource.com/platform/system/core/+/master/init/README.md) | **The `.rc` language reference.** Essential for the init audit |
| [SELinux concepts](https://source.android.com/docs/security/features/selinux/concepts) | Domains, contexts, `seapp_contexts` |

### Security

| Resource | Why |
|---|---|
| [Android security overview](https://source.android.com/docs/security) | The platform security model |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly. Read for the *pattern* of which layers recur |
| [Android Security Paper](https://source.android.com/docs/security/overview/acknowledgements) | Google's own architecture-level security writing |

---

## Tooling

| Tool | Use |
|---|---|
| `adb` / `fastboot` | See [60](../../60-ADB/README.md) and [61](../../61-Fastboot/README.md) |
| `getprop` / `setprop` / `getprop -Z` | The property service |
| `dumpsys` / `service list` | Binder services |
| `ps -A -Z` | Processes with SELinux domains |
| `lpdump` | Dynamic partition layout |
| `avbtool` (`external/avb/`) | Read and verify vbmeta descriptors |
| [magiskboot](https://github.com/topjohnwu/Magisk) | Unpack and repack `boot.img` |
| [Android_boot_image_editor](https://github.com/cfig/Android_boot_image_editor) | Alternative boot image tooling |
| [lpunpack / lpmake](https://android.googlesource.com/platform/system/extras/+/master/partition_tools/) | Unpack and build `super.img` |
| [payload-dumper-go](https://github.com/ssut/payload-dumper-go) | Extract partitions from an OTA `payload.bin` |
| Perfetto / `atrace` | Boot-time and system tracing |

### Chapter scripts

| Script | Purpose |
|---|---|
| [`scripts/device-posture.sh`](../scripts/device-posture.sh) | Trust posture with per-row verdicts; `--test-device` separates methodology from findings |
| [`scripts/layer-census.sh`](../scripts/layer-census.sh) | Processes by layer, plus anomaly checks (root daemons, app capabilities, world-accessible sockets) |
| [`scripts/firmware-triage.sh`](../scripts/firmware-triage.sh) | Offline image audit: init privilege budgets, privileged apps, APEX, SELinux |

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest published treatment of init, Zygote, the property service and the boot chain |
| *Android Security Internals* — Nikolay Elenkov | The best structural account of the security architecture; dated in specifics, excellent in framing |
| *The Android Hacker's Handbook* — Drake et al. | Older, but the platform-exploitation chapters explain *why* the architecture looks like this |
| *Embedded Android* — Karim Yaghmour | Written from the device-builder's perspective, which is exactly the view you need for OEM assessment |

---

## Research worth following

- **Google Project Zero** — https://googleprojectzero.blogspot.com/ — the highest-quality public
  Android platform research, and a good model for how to write up architectural findings
- **Android Security Bulletins** — read monthly for the *pattern*: which layers and which vendor
  components keep appearing
- **Hardwear.io, OffensiveCon, Recon** — the conferences where bootloader, TEE and firmware research
  is presented

> **Note on CVE citation.** This chapter describes vulnerability *classes* per layer rather than naming
> identifiers, because platform bugs are numerous, version-specific and vendor-specific. A
> misattributed CVE in a client report is worse than no citation. Pull specifics from the bulletin for
> the affected release.

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [07-AOSP](../../07-AOSP/README.md) | Navigating and building the source tree this chapter cites |
| [08-Build-System](../../08-Build-System/README.md) | How the images described here are produced |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | App identity, UID allocation, the install flow |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | The runtime layer in depth |
| [13-ART](../../13-ART/README.md) | The ART implementation and its Mainline module |
| [19-Memory](../../19-Memory/README.md) | The Zygote ASLR consequence, in exploitation terms |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Verified Boot, FBE and Play Integrity in depth |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | What `SpecializeCommon()` actually builds |
| [22-SELinux](../../22-SELinux/README.md) | Domains, `seapp_contexts`, property contexts |
| [24-IPC](../../24-IPC/README.md) | Sockets, including the world-accessible ones this chapter's audit finds |
| [25-Binder](../../25-Binder/README.md) | The transport underneath the framework |
| [60-ADB](../../60-ADB/README.md) | The protocol behind every command here |
| [61-Fastboot](../../61-Fastboot/README.md) | Bootloader, partitions, and flashing without destroying a device |
