# 62 — Magisk · References

Annotated. Every entry says *why* you would open it, so that under time pressure you can pick the
right one instead of the first one.

---

## Read this before you cite anything from here

**Magisk changes fast, and this chapter's version-specific claims decay.** That is not a hedge; it is
the single most important thing on this page.

Between Magisk 20 and Magisk 27 the following all changed in ways that broke published guides: the
module format, the location of Magisk's own tmpfs (`magisk --path` exists precisely because it moved),
whether MagiskHide existed at all, how the DenyList revert is implemented, which partition holds the
ramdisk on new devices, and how the CA trust store is reached on Android 14. A confident sentence
written in 2021 about "how DenyList works" is now, at best, an approximation.

Three habits follow:

1. **Date and version every claim.** "On Magisk 27.0 on a Pixel 6 running Android 14, `X` was
   observed" is a durable statement. "Magisk does `X`" is not.
2. **Prefer the source and the official docs over any blog post, forum thread or video.** The
   ecosystem's secondary literature is enormous, largely undated, heavily copied, and frequently
   describes a version from four years ago.
3. **Measure on your own device.** Every lab in this chapter is built around measuring rather than
   asserting, for exactly this reason. [Lab 03](../labs/lab-03-denylist-investigation.md) is the
   clearest example: it never tells you what DenyList removes, it makes you find out.

---

## Magisk itself — the primary source

There is no substitute for the project's own material. Magisk is not part of AOSP and no third-party
description of it is authoritative.

| Resource | Open it when |
|---|---|
| [Magisk on GitHub](https://github.com/topjohnwu/Magisk) | You need the truth about the current version's behaviour. Releases, changelog, and the source, all in one place |
| [Magisk documentation](https://topjohnwu.github.io/Magisk/) | First stop for anything factual. Short, accurate, and maintained alongside the code |
| [Installation guide](https://topjohnwu.github.io/Magisk/install.html) | Before you touch a device. It is the canonical answer to "boot or init_boot", to the recovery-partition case, and to taking an OTA without losing root |
| [Module developer guide](https://topjohnwu.github.io/Magisk/guides.html) | Writing anything in `labs/lab-02`. Defines `module.prop`, the boot-stage scripts, `system.prop`, `sepolicy.rule`, `skip_mount`, and the installer environment your `customize.sh` runs in |
| [DenyList documentation](https://topjohnwu.github.io/Magisk/deny.html) | Before making any claim about what DenyList does. Notably, it is explicit about what it does *not* do — which is the part everyone skips |
| [Zygisk module sample](https://github.com/topjohnwu/zygisk-module-sample) | Writing native code that runs in every app process. The API surface with a working build |
| [Magisk releases page](https://github.com/topjohnwu/Magisk/releases) | Downloading the APK. **Only** here — not an APK mirror. You are giving this binary permanent boot-time control of a device |

### Reading the source

The project is unusually clean C++/Rust and Kotlin, and reading it removes the mystery from most of
this chapter. Directory map, matching [§4.4](../README.md#44-reading-magisks-own-source):

| Directory in `topjohnwu/Magisk` | Open it when |
|---|---|
| `native/src/init/` | You want to know exactly what runs as PID 1 in a patched boot image, and how it decides which device topology it is on |
| `native/src/core/` | `magiskd`, `su`, module mounting, the DenyList revert. **This is where "what exactly does DenyList unmount" is answered for your version** |
| `native/src/boot/` | `magiskboot` — the image pack/unpack, CPIO handling and compression detection behind "patch a boot image" |
| `native/src/sepolicy/` | `magiskpolicy` — compiled-policy manipulation, and the rule grammar your `sepolicy.rule` is parsed with |
| `native/src/zygisk/` | The zygote loader, JNI hooking, and the module API's implementation |
| `app/` | The Manager app, including the repackaging that "Hide the Magisk app" performs |
| `scripts/` (`util_functions.sh`, `boot_patch.sh`, `flash_script.sh`) | **`boot_patch.sh` is the single most instructive file in the project** — a readable shell script that performs the entire boot image patch. Reading it once removes all the mystery.this is Magisk's own `scripts/` directory in its own repository, not this chapter's |

---

## AOSP — everything Magisk manipulates

Magisk is third-party; the platform it modifies is not. Read these on
[cs.android.com](https://cs.android.com/), which gives cross-references and history. See
[07-AOSP](../../07-AOSP/README.md) for navigation technique.

| Path | Open it when |
|---|---|
| `system/core/init/first_stage_init.cpp` | You want the contract `magiskinit` must satisfy: which filesystems are mounted, which device nodes created, how the command line is parsed, and where the handoff happens |
| `system/core/init/selinux.cpp` | Understanding why loading the policy *first* is the whole game, and what `init` would have done if `magiskinit` had not |
| `system/core/init/property_service.cpp` | The writer side of the property system — which properties `init` refuses to change, and therefore what `resetprop` is bypassing |
| `bionic/libc/bionic/system_property_set.cpp` | The other half of the same story, from the library side |
| `system/tools/mkbootimg/` (`bootimg.h`, `mkbootimg.py`, `unpack_bootimg.py`) | You need the boot image container format, header versions v0–v4, and a second implementation to check `magiskboot` against |
| `external/avb/` | Android Verified Boot. What `vbmeta` contains, how descriptors chain, and where `ro.boot.verifiedbootstate` actually comes from |
| `frameworks/base/core/java/com/android/internal/os/Zygote.java` | The Java side of `nativeForkAndSpecialize` / `nativeSpecializeAppProcess` — the functions Zygisk hooks |
| `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp` | `ForkCommon()` and `SpecializeCommon()`: the exact ordering of the UID drop, the SELinux transition and the seccomp install. **The boundary `preAppSpecialize` and `postAppSpecialize` straddle** |
| `frameworks/base/cmds/app_process/app_main.cpp` | Context for how classic Xposed worked, and why Zygisk's approach differs |
| `system/sepolicy/` | The policy sources whose compiled form `magiskpolicy` edits |
| `system/core/fs_mgr/` | dm-verity setup at mount time — the mechanism Magisk sidesteps rather than fights |

---

## Verified Boot, dm-verity and attestation

This is where chapter 62 stops and
[20-Security-Architecture](../../20-Security-Architecture/README.md) begins. **Chapter 62 owns what
patching a boot image *does*; chapter 20 owns what it *breaks*.** Cite 20 for the model; these for
the primary text.

| Resource | Open it when |
|---|---|
| [Verified Boot](https://source.android.com/docs/security/features/verifiedboot) | You need the definition of the boot states (`green` / `yellow` / `orange`) that you will quote in a report |
| [dm-verity](https://source.android.com/docs/security/features/verifiedboot/dm-verity) | Explaining why persistent `/system` modification stopped being viable, which is the reason systemless root exists at all |
| [AVB 2.0](https://android.googlesource.com/platform/external/avb/) | Working out whether a device needs `--disable-verity --disable-verification` on `vbmeta`, and what that flag actually turns off |
| [Boot image header versions](https://source.android.com/docs/core/architecture/bootloader/boot-image-header) | Reading a `boot.img` by hand, or checking what `magiskboot` reported |
| [Generic Kernel Image (GKI)](https://source.android.com/docs/core/architecture/kernel/generic-kernel-image) | Understanding why `init_boot` exists and which devices have it |
| [Key and ID Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) | The `RootOfTrust` extension, which carries the real verified-boot state signed inside the TEE. **This is the document that ends every "can I hide root" argument** |
| [Play Integrity API](https://developer.android.com/google/play/integrity) | Assessing whether an app's integrity control is client-side or server-side, which decides whether any of your work can help |
| [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts) | Reading a decoded token correctly, field by field, rather than guessing what a verdict name implies |

---

## `fastboot`, `adb` and the bootloader protocol

[60-ADB](../../60-ADB/README.md) and [61-Fastboot](../../61-Fastboot/README.md) own this material in
full; [Lab 01](../labs/lab-01-root-a-device.md) repeats what this chapter needs so it stands alone.
Go to 61 for the protocol itself, the bootloader lock state machine, sparse images, `fastbootd`, A/B
slots, and precisely what `--disable-verity` writes — its
[§3.8](../../61-Fastboot/README.md#38-vbmeta-flags-and-what---disable-verity-actually-disables)
measures that the flag changes **one byte** and thereby invalidates the image's own AVB hash, which
is why it is only usable on an unlocked bootloader. The external references below remain the primary
sources.

| Resource | Open it when |
|---|---|
| [SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools) | Always download `adb` and `fastboot` from here. A distro-packaged `fastboot` that is three years old will not know about partitions your device has |
| [`fastboot` documentation](https://source.android.com/docs/setup/test/running) | Command reference, including `flashing unlock`, `flashing lock`, `getvar`, and slot suffixes on A/B devices |
| [Flashing devices / factory images](https://source.android.com/docs/setup/build/running) | The `flash-all` procedure, and the meaning of the `-w` flag that wipes userdata. **Read this before you need it** |
| [A/B (seamless) system updates](https://source.android.com/docs/core/ota/ab) | Why your device has `boot_a` and `boot_b`, why flashing the wrong slot looks like a failed flash, and what happens to your patched image at the next OTA |
| [`adb` documentation](https://developer.android.com/tools/adb) | The `adb shell` quoting rules, which silently break `su -c "a; b"` — a trap this repository has hit for real |
| Your OEM's factory image page | The only correct source for a stock image matching `ro.build.fingerprint`. There is no generic link, and there should not be |

---

## Alternative root implementations

Worth knowing about for one reason: when Magisk-based hiding fails, moving the privileged logic into
the kernel sometimes moves you back ahead of a userspace scanner. See
[§3.11](../README.md#311-magisk-versus-kernelsu-versus-apatch) for the comparison and its limits.

| Resource | Open it when |
|---|---|
| [KernelSU](https://github.com/tiann/KernelSU) | Magisk is detected and you are considering a kernel-side implementation. Read its device-support requirements *first* — that is usually where the idea dies |
| [APatch](https://github.com/bmax121/APatch) | Same question, different trade-off: kernel patching with Magisk-compatible module support |
| [LSPosed](https://github.com/LSPosed/LSPosed) | You want the flagship Zygisk module, and a large worked example of the Zygisk API. **[63-LSPosed](../../63-LSPosed/README.md)** covers it in full: which of the Zygisk callbacks above LSPosed actually uses and why, the `XposedBridge` API surface, per-application scope (including what `android` scope means), and module development end to end |

---

## OWASP

| Resource | Why |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | The standard your client's requirements are probably derived from |
| [MASVS-RESILIENCE](https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/) | Where root detection sits.MASVS itself frames these as *resilience* controls, assessed by whether they raise attacker effort — not as security controls that must be unbypassable. Quote that framing; it is the honest one |
| [MASTG](https://mas.owasp.org/MASTG/) | Test procedures, including the platform-integrity and anti-reversing tests |
| [MASTG Android tests](https://mas.owasp.org/MASTG/tests/android/) | The specific tests to cite alongside a root-detection finding |

---

## Security research and the forensic view

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | The authoritative record of privilege-escalation fixes. Read for the *pattern* of which subsystems recur, not to memorise identifiers |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | The highest-quality public work on the Android privilege-escalation bugs that made rooting possible before unlockable bootloaders |
| [Android VRP rules](https://bughunters.google.com/about/rules/android-friends) | What Google considers reportable in this area, and the severity model they apply |

> **Note on CVE citation.** This chapter deliberately describes vulnerability *classes* rather than
> naming identifiers. Bootloader, attestation and privilege-escalation bugs are numerous,
> version-specific, and frequently mis-cited in secondary sources. **A misattributed CVE in a client
> report is worse than no citation at all.** When you need a specific reference, pull it from the
> bulletin for the affected release rather than from memory or from a blog.

---

## Books and long-form

Search by topic rather than by URL, since hosting moves.

| Work | Why |
|---|---|
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest published treatment of the low-level boot and `init` path that Magisk modifies. If you want to understand `magiskinit` properly, understand `init` first |
| *Android Security Internals* — Nikolay Elenkov | Best structural account of the security model root breaks. Dated in specifics, still the right mental model |
| Linux `mount_namespaces(7)`, `mount(2)`, `nsenter(1)` man pages | The actual primitives behind everything in [Lab 03](../labs/lab-03-denylist-investigation.md) and [Lab 05](../labs/lab-05-ctf-invisible-mount.md). Mount propagation (`shared`, `slave`, `private`) is explained here and nowhere else as precisely |
| Kernel `Documentation/filesystems/proc.rst` | The field-by-field definition of `/proc/<pid>/mountinfo`, which you will read more of in this chapter than anywhere else |

---

## This chapter's own artefacts

| File | Use it for |
|---|---|
| [`../scripts/root-check-observer.js`](../scripts/root-check-observer.js) | Building an inventory of what an app checks, **before** deciding how to neutralise anything |
| [`../scripts/ns-diff.sh`](../scripts/ns-diff.sh) | On-device: what does this process see, and what did DenyList remove |
| [`../scripts/mountinfo-diff.py`](../scripts/mountinfo-diff.py) | On the host: a structured, diffable comparison of two mount tables |
| [`../scripts/audit-magisk-module.sh`](../scripts/audit-magisk-module.sh) | Before installing any module, ever |
| [`../examples/`](../examples/README.md) | Two working modules and one deliberately hostile, defanged one |
| [`../cheatsheet.md`](../cheatsheet.md) | The command you half-remember |
| [`../faq.md`](../faq.md) | The question you are embarrassed to ask |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | Mount namespaces, bind mounts, UID 0, UNIX sockets — the substrate for everything here |
| [06-Android-Architecture](../../06-Android-Architecture/README.md) | Where Magisk sits in the stack; also `scripts/device-posture.sh`, whose `--test-device` flag encodes the "your rooted device is not a finding" discipline |
| [07-AOSP](../../07-AOSP/README.md) | How to navigate the source tree the tables above point into |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | Application startup ordering — what runs before an app's first line of code, which lab 03 measures |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | Zygote and process creation; the fork Zygisk intercepts |
| [13-ART](../../13-ART/README.md) | The runtime that Zygisk-based hooking frameworks target |
| [15-Native-Code](../../15-Native-Code/README.md) | Reading a Zygisk module's `.so`, and the native layer root checks live in |
| [16-JNI](../../16-JNI/README.md) | JNI method tables — the object Zygisk's `hookJniNativeMethods` modifies |
| [17-Libraries](../../17-Libraries/README.md) | Library load ordering and `.init_array`, which decides how early an app can observe anything |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | **Verified Boot, vbmeta, dm-verity and attestation.** Chapter 62 owns what patching does; 20 owns what it breaks |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The boundary root crosses, and the reason an app cannot read `/sys/fs/selinux/policy` in the first place |
| [34-Cryptography](../../34-Cryptography/README.md) | The AES and PBKDF2 used in lab 05's challenge |
| [37-RootDetection](../../37-RootDetection/README.md) | **The catalogue of detection techniques and their bypass.** 62 owns Magisk; 37 owns the checks. Its lab 04 is a CTF about hidden checks; this chapter's lab 05 is deliberately about mount mechanics instead |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What survives R8, and recovering obfuscated path strings from a native check |
| [49-KeyStore](../../49-KeyStore/README.md) | Hardware-backed keys and the attestation certificate chain root cannot forge |
| [53-Frida](../../53-Frida/README.md) | The tool root exists to enable, and how the hooks in §7 work internally |
| [57-Ghidra](../../57-Ghidra/README.md) | Static analysis of a native root check or a Zygisk module |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The `adb` and `fastboot` invocations you will retype most often |
| [79-Glossary](../../79-Glossary/README.md) | Every term in this chapter, defined in one place |

Chapters this one defers to, in the order you would read them after finishing here. Every link below
resolves:

[22-SELinux](../../22-SELinux/README.md) (policy and domains, and why `magiskpolicy` exists) ·
[35-SSL](../../35-SSL/README.md) and [36-CertificatePinning](../../36-CertificatePinning/README.md)
(the trust store a CA module modifies, and the layer above it) ·
[38-TamperDetection](../../38-TamperDetection/README.md) ·
[39-EmulatorDetection](../../39-EmulatorDetection/README.md) ·
[50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) (the TEE — where root stops) ·
[60-ADB](../../60-ADB/README.md) ·
[63-LSPosed](../../63-LSPosed/README.md) (the flagship Zygisk module, and what it does with the API
described in §3.8) · [65-Hooking](../../65-Hooking/README.md) ·
[67-BypassingProtections](../../67-BypassingProtections/README.md) (the methodology this chapter
serves) · [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md).

The two that were previously outstanding have both landed and are now linked:
[61-Fastboot](../../61-Fastboot/README.md) (unlocking, flashing and the `vbmeta` step §9.1 depends
on — it measured that `--disable-verity` corrupts the image's own AVB signature rather than being an
option AVB honours) and [64-Xposed](../../64-Xposed/README.md) (the historical framework whose
`app_process` replacement §4.1 contrasts against — it owns why replacing a file on `/system` was
fatal, which is the problem this chapter's systemless design exists to solve).

**Every chapter this file defers to now exists.**
