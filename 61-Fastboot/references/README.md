# 61 — Fastboot: references

Annotated. Where a source is the primary one for a claim in the chapter, it says so.

---

## Start here

| Source | Why |
|---|---|
| `system/core/fastboot/README.md` (AOSP) | **The protocol specification, and the primary source for chapter §3.2.** It is short enough to read in twenty minutes and doing so removes most of the confusion in this topic. Everything else on this page is commentary on it |
| `system/core/fastboot/device/` (AOSP) | **`fastbootd`** — the half of the protocol whose source you can actually read. `commands.cpp` is one handler per verb; `variables.cpp` is the authoritative `getvar` table |
| `system/core/fastboot/fuzzy_fastboot/` (AOSP) | Google's conformance and **malformed-input** suite for OEM bootloaders. Effectively a published list of the things implementations get wrong. Needs a device to run; reads fine without one. The highest-yield hour available on this subject |

## AOSP source, by subject

### The protocol and the host tool

| Path | Contents |
|---|---|
| `system/core/fastboot/fastboot.cpp` | Argument parsing, the flashing plan, and the `--disable-verity` vbmeta rewrite |
| `system/core/fastboot/engine.cpp` | The action queue, retry and skip logic |
| `system/core/fastboot/fastboot_driver.cpp` | The wire protocol — `RawCommand`, `Download`, `HandleResponse` |
| `system/core/fastboot/usb_linux.cpp`, `usb_windows.cpp`, `usb_osx.cpp` | Finding the interface by class `0xFF` / subclass `0x42` / protocol `0x03` |
| `system/core/fastboot/tcp.cpp`, `udp.cpp`, `socket.cpp` | The non-USB transports |
| `system/core/fastboot/fs.cpp` | `format`, and the shell-out to `mke2fs` / `make_f2fs` — **the source for the "format runs on the host" claim in §3.4** |
| `system/core/fastboot/device/usb_client.cpp` | `fastbootd`'s FunctionFS USB gadget |
| `system/core/fastboot/device/flashing.cpp` | Writing partitions, including logical ones |

### Image formats

| Path | Contents |
|---|---|
| `system/core/libsparse/include/sparse/sparse_format.h` | **The sparse structures — primary source for §3.5.** 28-byte file header, 12-byte chunk header, four chunk types, little-endian |
| `system/core/libsparse/sparse_read.c` | The parser. Compare its validation against `scripts/sparse-tool.py`; lab 02 §6 makes that an exercise |
| `system/core/libsparse/output_file.c` | The writer |
| `system/tools/mkbootimg/include/bootimg/bootimg.h` | Android boot image header, versions 0–4. Version 4 is where the ramdisk moved to `init_boot` |
| `system/core/fs_mgr/liblp/include/liblp/metadata_format.h` | `super` partition metadata — geometry, header, partitions, extents, groups. **Primary source for §3.7** |
| `system/core/fs_mgr/liblp/builder.cpp`, `reader.cpp`, `writer.cpp` | The LP implementation, including the alignment logic that produces the 1 MiB boundaries measured in §3.7 |
| `system/core/fs_mgr/libsnapshot/` | Virtual A/B snapshots and `snapuserd` |

### AVB

| Path | Contents |
|---|---|
| `external/avb/libavb/avb_vbmeta_image.h` | **`AvbVBMetaImageHeader` and the two flag constants — primary source for §3.8 and §4.3.** All fields big-endian; `flags` is a `uint32` at offset 120 |
| `external/avb/libavb/avb_vbmeta_image.c` | `avb_vbmeta_image_verify()` — the hash the chapter recomputed against a real image and got a match for |
| `external/avb/libavb/avb_slot_verify.c` | The slot verification entry point a bootloader calls |
| `external/avb/avbtool.py` | The host-side AVB tool. **Readable Python, and the fastest route to genuinely understanding AVB** — the format and the verification logic in one file. `avbtool info_image --image vbmeta.img` |
| `external/avb/README.md` | AVB's own overview, including the rollback-index design |

> **Boundary note.** AVB, dm-verity, fs-verity and the four boot states are owned by
> [20-Security-Architecture §3.1–§3.3](../../20-Security-Architecture/README.md#31-verified-boot-and-android-verified-boot-20-avb).
> This chapter cites them and owns only what *fastboot does to* that chain. For full vbmeta parsing
> use [`../../20-Security-Architecture/scripts/parse-vbmeta.py`](../../20-Security-Architecture/scripts/parse-vbmeta.py)
> rather than re-implementing it; this chapter's [`../scripts/vbmeta-flags.py`](../scripts/vbmeta-flags.py)
> is deliberately narrower.

### Boot, recovery and updates

| Path | Contents |
|---|---|
| `bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message.h` | **The BCB struct in `misc` — primary source for §3.1.** `command[32]` carries `bootonce-bootloader` or `boot-recovery` |
| `bootable/recovery/` | Recovery, which hosts `fastbootd` |
| `hardware/interfaces/boot/` | `IBootControl` — the A/B slot HAL. `priority`, `tries_remaining`, `successful_boot` |
| `system/update_engine/` | A/B update application |
| `system/update_engine/update_verifier/` | What marks a slot `successful_boot` **after** Android comes up healthily |
| `system/core/init/` | Where `androidboot.*` from the cmdline and bootconfig become `ro.boot.*` properties — the mechanism §5.3 and lab 01 Part 2 trace |

## Official documentation

Cited by title rather than URL, because Android documentation URLs move; search `source.android.com`
for the title.

| Document | Relevance |
|---|---|
| *Fastboot* (AOSP, Bootloader section) | The command reference, from the vendor |
| *Implementing fastbootd* (AOSP) | Why userspace fastboot exists and what an OEM must do |
| *Verified Boot* (AOSP, Security features) | AVB, the four boot states, rollback indexes |
| *Implementing dm-verity* (AOSP) | The hashtree and FEC machinery `--disable-verity` disables |
| *Boot flow* (AOSP, Architecture) | Boot ROM to bootloader to kernel |
| *Dynamic partitions* (AOSP, Bootloader/Partitions) | `super`, `liblp`, retrofit devices |
| *A/B (seamless) system updates* (AOSP, OTA) | Slots, priority, tries, `update_verifier` |
| *Virtual A/B* and *Virtual A/B Compression* (AOSP, OTA) | Snapshots, merge states, `snapshot-update-status` |
| *Bootloader control block* / *Recovery images* (AOSP) | The `misc` mailbox |
| *Generic Kernel Image (GKI)* (AOSP) | Why `init_boot` exists on Android 13+ launch devices |
| *Key and ID attestation* (developer.android.com) | The only non-forgeable statement of lock state |
| Google factory images and OTA images for Pixel devices | The reference artefacts for any Pixel lab device, and the recovery path you must download *before* flashing anything |

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-RESILIENCE-1** | Platform integrity validation — the category the app-side findings in §5.3 belong to |
| **MASVS-RESILIENCE-2** | Anti-tampering. An unlocked bootloader is the substrate every tampering technique in this repository is built on |
| **MASVS-STORAGE-1**, **MASVS-STORAGE-2** | Data at rest, protected by the factory-reset guarantee in §3.9 |
| **MASVS-CRYPTO-1** | Key management and attestation |
| MASTG device-integrity and root-detection tests | The practical tests |

> **⚠️ MASVS v2 *categories* are stable; MASTG *test* identifiers have been renumbered between
> editions.** Cite the category confidently and **look the test number up at the time of writing**
> rather than repeating one from memory — a stale ID reads as carelessness in a report.
> [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) carries the current mapping.

## CVEs and vulnerability research

**This chapter names no CVE identifiers, deliberately.** Bootloader vulnerabilities are real,
published, and per-vendor per-generation; an identifier quoted from memory is worse than an accurate
description of the class. [§5.4](../README.md#54-vulnerability-classes-in-bootloaders-themselves)
describes five classes; look the identifiers up when you write the report.

Where to look, in order of usefulness:

| Source | What it carries |
|---|---|
| **Qualcomm Product Security bulletins** | Bootloader, XBL and TrustZone issues, with Qualcomm's own identifiers alongside CVEs |
| **Samsung Mobile Security bulletins** | SVE identifiers, including bootloader and Knox items |
| **Android Security Bulletin**, *Bootloader* and *Kernel components* sections | Monthly, with severity and affected versions |
| **MediaTek product security advisories** | BROM and preloader issues |
| `system/core/fastboot/fuzzy_fastboot/` | Not a CVE list, but a published list of the *failure modes* that motivated a test suite. Read the test names |

Conference tracks worth searching rather than any single talk: Black Hat and DEF CON have carried
bootloader and secure-boot research for years, as have OffensiveCon, Recon and Ekoparty. Search by
chipset generation rather than by talk title — this material ages by silicon revision, and a talk
about a 2018 SoC tells you little about a 2025 one.

## This chapter's own artefacts

| File | What it is |
|---|---|
| [`../examples/measured-avd-boot-state.md`](../examples/measured-avd-boot-state.md) | **Every raw measurement the chapter is built on**, verbatim, plus an explicit list of what was deliberately not run and why. Read this before trusting any number in the README |
| [`../examples/fastboot-wire-transcript.md`](../examples/fastboot-wire-transcript.md) | Seven annotated protocol sessions. **Labelled at the top as reconstructed rather than captured** |
| [`../examples/BootStateChecker.java`](../examples/BootStateChecker.java) | The vulnerable check, an honest read-only version, and the attestation replacement with eleven server-side checks enumerated |
| [`../scripts/bootstate-audit.sh`](../scripts/bootstate-audit.sh) | Read-only device posture with the evidence beside every verdict. Probes both `su` forms |
| [`../scripts/fastboot-recon.sh`](../scripts/fastboot-recon.sh) | Read-only fastboot recon behind a hard allow-list, plus a `--host-audit` mode needing no device |
| [`../scripts/vbmeta-flags.py`](../scripts/vbmeta-flags.py) | The AVB flags and the hash invariant. 19 self-tests |
| [`../scripts/sparse-tool.py`](../scripts/sparse-tool.py) | Sparse images: info, verify, expand, create. 15 self-tests including seven malformed-input rejections |
| [`../scripts/bootprop-observer.js`](../scripts/bootprop-observer.js) | Frida: every boot-property read by all four routes. **Reviewed and unrun — see the note in §7.2** |
| [`../scripts/make-ctf-images.py`](../scripts/make-ctf-images.py) | Lab 04's artefact generator, with a self-test that solves the challenge programmatically |

## Related chapters

| Chapter | Relationship |
|---|---|
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | **Owns AVB, dm-verity, fs-verity and the four boot states.** Cited here, never restated. §3.1–§3.3 and §4.5 |
| [62-Magisk](../../62-Magisk/README.md) | Owns rooting, boot-image patching and `magiskboot`. This chapter owns the transport and the state machine that make patching possible. **[Its lab 01](../../62-Magisk/labs/lab-01-root-a-device.md) is where the destructive procedure lives** |
| [60-ADB](../../60-ADB/README.md) | The other protocol that talks to a device — with Android behind it, inside the security model |
| [07-AOSP](../../07-AOSP/README.md) | Builds the images this chapter flashes. `fastboot flashall` consumes `$ANDROID_PRODUCT_OUT` |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | Key attestation and the TEE's non-forgeable view of device state. **The source for the measured `green` versus `Unverified` contradiction** |
| [49-KeyStore](../../49-KeyStore/README.md) | Key binding to boot state |
| [06-Android-Architecture](../../06-Android-Architecture/README.md) | Where the boot sequence is introduced, and where `fastboot boot` is first recommended as a habit |
| [37-RootDetection](../../37-RootDetection/README.md) | The check family an unlocked bootloader makes defeatable |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Integrity checks running on a platform that can lie to them |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | The same property-forgery failure mode applied to a different question, and the source of the `ro.bootloader == unknown` measurement |
| [57-Ghidra](../../57-Ghidra/README.md) | Tooling for reversing a bootloader image |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Building the C harness that can exhibit the sparse integer overflow lab 02's Python tool structurally cannot |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Current MASVS and MASTG mapping |
| [79-Glossary](../../79-Glossary/README.md) | Defines *Bootloader* and *Fastboot*, pointing here |
