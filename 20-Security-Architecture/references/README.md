# 20 — Security Architecture · References

Every link is annotated with what it is good for. Paths without URLs are AOSP tree locations —
browse them at <https://cs.android.com/> (Android Code Search) or in a local `repo sync`.

---

## AOSP source — Verified Boot and AVB

| Path | Why read it |
|---|---|
| `external/avb/README.md` | The authoritative AVB 2.0 design document. Read this before any blog post. |
| `external/avb/libavb/avb_slot_verify.c` | The entry point a bootloader calls; the whole verification flow in one file. |
| `external/avb/libavb/avb_vbmeta_image.c` | vbmeta parsing and signature validation. |
| `external/avb/libavb/avb_hashtree_descriptor.c` | How a hashtree descriptor becomes a dm-verity table. |
| `external/avb/libavb/avb_ops.h` | The `AvbOps` callback table — the bootloader's side of the contract. |
| `external/avb/avbtool.py` | The host tool. Reading it is the fastest route to genuinely understanding the format. |

## AOSP source — dm-verity, fs-verity, early mount

| Path | Why read it |
|---|---|
| `system/core/fs_mgr/` | Android's mount management, including verity setup. |
| `system/core/fs_mgr/libfs_avb/` | The AVB-driven dm-verity configuration used by modern first-stage init. |
| `system/core/init/first_stage_mount.cpp` | Where `/system` and `/vendor` get mounted before anything else exists. |
| `drivers/md/dm-verity-target.c` *(Linux kernel)* | The verity device-mapper target: hash tree walk and corruption handling. |
| `fs/verity/` *(Linux kernel)* | fs-verity: per-file Merkle trees and the built-in signature keyring. |

## AOSP source — encryption and credentials

| Path | Why read it |
|---|---|
| `system/vold/` | The volume daemon. `FsCrypt.cpp`, `KeyStorage.cpp`, `MetadataCrypt.cpp`. |
| `fs/crypto/` *(Linux kernel)* | fscrypt: per-file keys, filename encryption, the key-management ioctls. |
| `frameworks/base/services/core/java/com/android/server/locksettings/LockSettingsService.java` | Credential verification from the framework's side. |
| `frameworks/base/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java` | The synthetic-password indirection that lets a PIN change without re-encrypting data. |
| `system/gatekeeper/` | The Gatekeeper reference implementation including throttling. |
| `hardware/interfaces/gatekeeper/` | The Gatekeeper HAL interface. |
| `hardware/interfaces/weaver/` | The Weaver HAL — secure-element-backed credential storage. |
| `system/security/keystore2/` | The modern (Rust) Keystore daemon; every hardware-backed key operation passes through here. |
| `hardware/interfaces/security/keymint/` | The KeyMint HAL, including the attestation record definition. |

## AOSP source — updateability and identity

| Path | Why read it |
|---|---|
| `system/apex/apexd/` | APEX verification and mounting — how Mainline modules actually land. |
| `system/core/init/property_service.cpp` | Where `ro.boot.*` properties are imported from the kernel command line. |
| `bionic/libc/bionic/system_properties.cpp` | The read side of the property area; useful when you want to know what `resetprop` manipulates. |
| `frameworks/base/core/java/android/os/Build.java` | The Java-visible build identity. |
| `frameworks/base/services/core/java/com/android/server/pm/` | PackageManagerService and the install/verification pipeline. |

---

## Official documentation

| Resource | Use |
|---|---|
| Android Open Source Project — Security section (`source.android.com/docs/security/`) | Verified Boot, dm-verity, FBE, metadata encryption, Trusty, SELinux, and the security bulletin index. The single most authoritative source. |
| Android Verified Boot documentation (`source.android.com/docs/security/features/verifiedboot/`) | Boot states, AVB, rollback protection, and the exact user-facing warning behaviour. |
| File-Based Encryption (`source.android.com/docs/security/features/encryption/file-based`) | DE/CE, Direct Boot requirements, key hierarchy. |
| Android Security Bulletins (`source.android.com/docs/security/bulletin`) | Monthly CVE lists, severity ratings, and the definition of the two patch level strings. **Verify every CVE you cite here.** |
| Android Compatibility Definition Document (CDD) | What a device *must* implement to ship with Google services — an excellent checklist for assessing an OEM device. |
| Android Developers — Play Integrity API | Verdict semantics, the nonce contract, and the server-side decode API. |
| Android Developers — Android Keystore and Key Attestation | The attestation certificate extension, its ASN.1 schema, and the authorisation tags. |
| Android Developers — Direct Boot | How `directBootAware` and `createDeviceProtectedStorageContext()` work. |
| Android Developers — Project Mainline / APEX | Which modules are updatable and how the format works. |

---

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-STORAGE** | Sensitive data must not be recoverable from device storage. Ties to FBE and Keystore. |
| **MASVS-CRYPTO** | Key management and hardware-backed key requirements. |
| **MASVS-AUTH** | Integrity tokens and attestation used as authentication inputs. |
| **MASVS-NETWORK** | TLS and certificate validation — the network adversary. |
| **MASVS-PLATFORM** | Platform interaction, target SDK level, and IPC. |
| **MASVS-RESILIENCE** | Anti-tampering, device binding, and integrity checks — explicitly framed by OWASP as defence in depth, not a primary control. |
| **MASTG** | The test procedures for device binding, root detection, anti-tampering, and key material protection. Cross-reference [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) for the current numbering. |

---

## Tools

| Tool | What it does here |
|---|---|
| `avbtool` (`external/avb/avbtool.py`) | Inspect, verify, and construct vbmeta and hash footers. |
| `magiskboot` | Unpack/repack boot images; detect whether a boot image has been patched. |
| `payload_dumper` | Extract individual partition images from an OTA `payload.bin`. |
| `simg2img` / `img2simg` | Convert between sparse and raw Android images. |
| `fastboot` | Query lock state, flash, and unlock. See [61 — Fastboot](../../61-Fastboot/README.md). |
| Frida | Observe what integrity signals an app actually reads. See [53 — Frida](../../53-Frida/README.md). |
| `apktool`, `jadx`, `aapt2` | Static inspection of the APK and manifest. |

---

## Research and talks worth your time

These are topic areas rather than specific citations, so that nothing here is fabricated. Search the
proceedings of the following venues for the named topics; all have published substantial Android
platform security work.

| Venue | Topics to search |
|---|---|
| USENIX Security, NDSS, IEEE S&P, ACM CCS | Android permission re-delegation, TEE trusted-application vulnerabilities, verified boot analysis, mobile attestation |
| Black Hat / DEF CON | TrustZone exploitation, bootloader unlock bypasses, secure element attacks, Android privilege escalation chains |
| OffensiveCon, REcon | Baseband and TEE reverse engineering, boot ROM exploitation |
| Google Project Zero blog | Android kernel and driver exploitation write-ups, with full technical detail and real CVE identifiers you can cite safely |
| Android Security Bulletins | The only place to source CVE identifiers for Android platform issues |

> When citing a CVE in a client report, open the Android Security Bulletin entry or the NVD record
> and confirm the identifier, the affected component, and the severity. Never cite from memory.

---

## Related chapters

[06 — Android Architecture](../../06-Android-Architecture/README.md) ·
[09 — App Internals](../../09-Android-App-Internals/README.md) ·
[10 — APK Internals](../../10-APK-Internals/README.md) ·
[21 — App Sandbox](../../21-App-Sandbox/README.md) ·
[22 — SELinux](../../22-SELinux/README.md) ·
[23 — Permissions](../../23-Permissions/README.md) ·
[33 — Storage](../../33-Storage/README.md) ·
[37 — Root Detection](../../37-RootDetection/README.md) ·
[38 — Tamper Detection](../../38-TamperDetection/README.md) ·
[49 — KeyStore](../../49-KeyStore/README.md) ·
[50 — Hardware-Backed Security](../../50-HardwareBackedSecurity/README.md) ·
[61 — Fastboot](../../61-Fastboot/README.md) ·
[62 — Magisk](../../62-Magisk/README.md) ·
[67 — Bypassing Protections](../../67-BypassingProtections/README.md) ·
[70 — Vulnerability Research](../../70-VulnerabilityResearch/README.md)
