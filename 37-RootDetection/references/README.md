# 37 — Root Detection · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives cross-references and history. See
[07-AOSP](../../07-AOSP/README.md) for navigation technique.

### The filesystem path — where `File.exists()` really goes

| Path | Open it when |
|---|---|
| `libcore/ojluni/src/main/java/java/io/File.java` | You need to see that `exists()` delegates to `UnixFileSystem`, not to a syscall directly |
| `libcore/ojluni/src/main/java/java/io/UnixFileSystem.java` | You are tracing `getBooleanAttributes` down to `Libcore.os` |
| `libcore/luni/src/main/java/libcore/io/Posix.java` | The bottom of the Java filesystem stack; every Java FS API funnels here |
| `libcore/luni/src/main/java/libcore/io/BlockGuardOs.java` | The wrapper an app actually holds. **Hook this class, not `Posix`, when you want to catch every Java filesystem API at once** |
| `libcore/luni/src/main/native/libcore_io_Posix.cpp` | The exact point where Java filesystem calls become native calls — the boundary a Java hook cannot see past |
| `bionic/libc/bionic/` | `access`, `stat`, `openat` wrappers; confirms which syscall your architecture actually issues |

### The property system

| Path | Open it when |
|---|---|
| `bionic/libc/bionic/system_property_get.cpp` | You are hooking `__system_property_get` and your spoof does nothing — check whether the caller uses `__system_property_find` + `read_callback` instead |
| `bionic/libc/include/sys/system_properties.h` | You need `PROP_VALUE_MAX` and the exact reader API surface |
| `system/core/init/property_service.cpp` | You want the writer side, and which properties `init` refuses to change |
| `system/core/init/` | How `ro.boot.*` properties arrive from the kernel command line — the provenance argument for `verifiedbootstate` |
| `frameworks/base/core/jni/android_os_SystemProperties.cpp` | The bridge between `android.os.SystemProperties` and bionic |

### Packages and process execution

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/app/ApplicationPackageManager.java` | The **concrete** `PackageManager` an app receives. The class to hook |
| `frameworks/base/services/core/java/com/android/server/pm/AppsFilter.java` | Package visibility filtering — why an API 30+ check silently returns "not installed" |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` | The `system_server` side of the Binder call |
| `libcore/ojluni/src/main/java/java/lang/ProcessBuilder.java`, `ProcessImpl.java` | The `Runtime.exec` → `fork`/`execve` path |

### Security state

| Path | Open it when |
|---|---|
| `external/selinux/libselinux/src/getenforce.c` | You are reading a native SELinux state check and want the exact sysfs node |
| `system/security/keystore2/` | Key attestation implementation, for the hardware-backed half of §3.15 |
| `external/avb/` | Android Verified Boot — where `verifiedbootstate` actually comes from |

---

## Official documentation

| Resource | Why |
|---|---|
| [Play Integrity API](https://developer.android.com/google/play/integrity) | The only control in this chapter worth real budget. Start here |
| [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts) | What each verdict field means, so you can read a decoded token correctly |
| [Play Integrity — classic requests](https://developer.android.com/google/play/integrity/classic) | Nonce handling; read when assessing whether an integration binds its tokens |
| [Key and ID Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) | The attestation extension structure, including `verifiedBootState` and `deviceLocked` |
| [Verified Boot](https://source.android.com/docs/security/features/verifiedboot) | Why `ro.boot.verifiedbootstate` has provenance outside Android |
| [AVB (Android Verified Boot 2.0)](https://android.googlesource.com/platform/external/avb/) | The implementation behind the above |
| [Package visibility filtering](https://developer.android.com/training/package-visibility) | The `<queries>` mechanism that silently killed a generation of package checks |
| [SELinux on Android](https://source.android.com/docs/security/features/selinux) | Why root is not omnipotence, and why the SELinux check is now worthless |
| [Android behaviour changes](https://developer.android.com/about/versions) | Check before asserting any version-dependent behaviour in a report |

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | The standard your client's requirements are probably derived from |
| [MASVS-RESILIENCE](https://mas.owasp.org/MASVS/09-MASVS-RESILIENCE/) | The category root detection sits in. Note that MASVS itself frames these as *resilience*, not *security* controls — that framing is the whole argument of this chapter |
| [MASTG](https://mas.owasp.org/MASTG/) | Test procedures |
| [MASTG Android tests](https://mas.owasp.org/MASTG/tests/android/) | The platform-integrity and anti-reversing tests map onto §3 |
| MASTG UnCrackable series | Canonical practice targets — see [80-Appendix](../../80-Appendix/README.md) |

---

## Tooling and projects

| Tool | Where | Use |
|---|---|---|
| [Magisk](https://topjohnwu.github.io/Magisk/) | device | The root implementation you will actually meet |
| [Magisk DenyList](https://topjohnwu.github.io/Magisk/deny.html) | device | Step 1 of the bypass ladder — read this before writing any hook |
| [Zygisk](https://topjohnwu.github.io/Magisk/guides.html) | device | Zygote injection; also the module API, if you want to understand hiding modules |
| [RootBeer](https://github.com/scottyab/rootbeer) | source | Read the source. It is the library you will meet most often and it documents its own limitations honestly |
| [Frida](https://frida.re/docs/android/) | host + device | Everything in §7 |
| [Frida JavaScript API](https://frida.re/docs/javascript-api/) | docs | `Interceptor`, `Module`, `Memory.patchCode`, `Java.perform` |
| [Objection](https://github.com/sensepost/objection) | host | `android root disable` as a thirty-second probe |
| [jadx](https://github.com/skylot/jadx) | host | Decompilation; string search is the highest-yield triage step |
| [apktool](https://apktool.org/) | host | Smali-level patching and manifest inspection |
| [Ghidra](https://ghidra-sre.org/) | host | Native checks. Start with Imports and `Java_*` Exports |
| [radare2](https://rada.re/) | host | Faster than Ghidra for "which function references this string" |
| `strace` (toybox / NDK build) | device root | Ground truth. The only tool a hook cannot lie to |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | host | Lead generation, not findings. Verify every hit dynamically |

---

## Standards and regulatory context

Useful when a client asks "why do we have to do this at all", which is a question about compliance
rather than security.

| Reference | Relevance |
|---|---|
| [PCI Mobile Payments on COTS (MPoC)](https://www.pcisecuritystandards.org/) | Requires device-integrity monitoring for software-based PIN entry; a common reason a bank *must* ship a check it knows is weak |
| [PSD2 / EBA RTS on Strong Customer Authentication](https://www.eba.europa.eu/) | Drives the "must detect a compromised device" requirement in EU banking |
| [NIST SP 800-163](https://csrc.nist.gov/publications) | Vetting the security of mobile applications; useful framing for a report's recommendations section |
| [NIST SP 800-124](https://csrc.nist.gov/publications) | Managing enterprise mobile devices — the MDM context of §9.5 |

---

## Security research

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | The authoritative record. Read for the *pattern* of which subsystems recur, not to memorise identifiers |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | The highest-quality public work on Android privilege escalation — the mechanisms that make rooting possible in the first place |
| [Android VRP rules](https://bughunters.google.com/about/rules/android-friends) | What Google considers reportable, and the severity model |
| [OWASP MAS research](https://mas.owasp.org/) | The community's accumulated position on resilience controls |

> **Note on CVE citation.** This chapter deliberately describes vulnerability *classes* rather than
> naming identifiers. Privilege-escalation and attestation-bypass bugs are numerous, version-specific,
> and frequently mis-cited in blog posts; a misattributed CVE in a client report is worse than no
> citation at all. When you need a specific reference, pull it from the bulletin for the affected
> release rather than from memory.

---

## Conference talks and long-form

Search for the topic rather than a URL, since hosting moves.

- Mobile banking app security assessments — OWASP AppSec and local OWASP chapter tracks
- Magisk internals and the hiding arms race — talks by the Magisk maintainer and the module community
- Attestation and hardware roots of trust — USENIX Security, Black Hat mobile tracks
- Frida internals and the Java bridge — the maintainers' own talks are the best source
- Anti-fraud on mobile at scale — fintech engineering blogs, which are more honest about the economics
  than security vendors are

| Work | Why |
|---|---|
| *Android Security Internals* — Nikolay Elenkov | Best structural account of the security model root breaks; dated in specifics, still the right mental model |
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | Deepest published treatment of the low-level boot and init path that root modifies |
| *The Mobile Application Hacker's Handbook* | Dated, but the assessment methodology chapters hold up |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | UID 0, setuid, permissions — the substrate |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | `Application.attachBaseContext`/`onCreate`, where checks run |
| [15-Native-Code](../../15-Native-Code/README.md) | The `.so` layer where the checks that matter live |
| [16-JNI](../../16-JNI/README.md) | Why `Java_*` symbols survive obfuscation and make good anchors |
| [18-ARM](../../18-ARM/README.md) | Reading and patching the arm64 that implements a native check |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | The model this chapter's threat model departs from |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | What root breaks |
| [22-SELinux](../../22-SELinux/README.md) | Why root is not omnipotence |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Signature checks, anti-debug, anti-Frida — patch both or neither |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | The sibling control, same trust boundary |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What survives R8; recovering encrypted path strings |
| [41-ProGuard](../../41-ProGuard/README.md), [42-R8](../../42-R8/README.md) | Why the class names vanished but the strings did not |
| [49-KeyStore](../../49-KeyStore/README.md) | Hardware-backed keys and the attestation certificate chain |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | The TEE — the only component Magisk cannot reach |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The general runtime methodology §7 specialises |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The general static methodology §8 specialises |
| [53-Frida](../../53-Frida/README.md) | How the hooks in this chapter work internally |
| [54-Objection](../../54-Objection/README.md) | `android root disable` and what it actually does |
| [56-JADX](../../56-JADX/README.md) | Decompilation workflow for §6.2 |
| [57-Ghidra](../../57-Ghidra/README.md) | Native analysis workflow for §6.4 |
| [62-Magisk](../../62-Magisk/README.md) | Magisk internals in depth |
| [65-Hooking](../../65-Hooking/README.md) | Hooking from first principles, managed and native |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | The general bypass methodology |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Full MASVS mapping |
