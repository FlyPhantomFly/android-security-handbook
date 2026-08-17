# 60 — ADB: References

Annotated. Every entry says what you get from it and when to reach for it. Nothing here is cited to
pad a list; if a source is not worth your time, it is not in the table.

---

## 1. The primary sources — AOSP `packages/modules/adb/`

This one directory contains the entire protocol, its two prose specifications, and both ends of the
implementation. It is about 30,000 lines of readable C++ and is genuinely approachable.

| Path | What you get |
|---|---|
| `packages/modules/adb/protocol.txt` | **The specification.** The 24-byte header, every message type, the connect and authentication sequences. Read this before anything else — it is short, it is prose, and it is authoritative. It is also where the `data_check` field is described as a CRC32, which the code does not implement; see §2.3 of the chapter |
| `packages/modules/adb/SYNC.TXT` | **The `sync:` sub-protocol** used by `adb push` and `adb pull` — `STAT`, `LIST`, `SEND`, `RECV`, `DATA`, `DONE`, `OKAY`, `FAIL`, `QUIT`, and the 64 KiB chunk rule |
| `packages/modules/adb/SERVICES.TXT` | **The host smart-socket protocol** on port 5037 *and* the complete list of device service strings. This is the enumeration surface of chapter §3.4 |
| `packages/modules/adb/OVERVIEW.TXT` | The client / server / daemon architecture, in the authors' own words |
| `packages/modules/adb/adb.h` | The `A_*` constants and `struct amessage`. Four minutes of reading that makes §2.3 concrete |
| `packages/modules/adb/types.h` | `apacket`, and the payload checksum helper that is a byte sum rather than a CRC |
| `packages/modules/adb/transport.cpp` | Packet read/write, the transport registry, and how a connection becomes a "device" in `adb devices` |
| `packages/modules/adb/transport_usb.cpp` | The USB framing — why headers and payloads are separate writes |
| `packages/modules/adb/daemon/main.cpp` | `adbd` startup and **the privilege drop**: where `ro.secure` and `ro.debuggable` are consulted |
| `packages/modules/adb/daemon/usb.cpp` | The FunctionFS endpoints `ep0`/`ep1`/`ep2` and the USB descriptors (class `0xFF`, subclass `0x42`, protocol `0x01`) |
| `packages/modules/adb/adb_auth.h` | `ADB_AUTH_TOKEN`, `ADB_AUTH_SIGNATURE`, `ADB_AUTH_RSAPUBLICKEY` |
| `packages/modules/adb/client/auth.cpp` | Host side of `A_AUTH`: key loading, `$ADB_VENDOR_KEYS`, and the `RSA_sign(NID_sha1, token, 20, …)` call that makes the token-is-not-hashed behaviour true |
| `packages/modules/adb/daemon/auth.cpp` | Device side: verifying against `adb_keys`, and handing an unknown key to the framework |
| `packages/modules/adb/crypto/rsa_2048_key.cpp` | Key generation and the `RSAPublicKey` struct encoding — the 524-byte layout of chapter §3.9.2 |
| `packages/modules/adb/services.cpp` | Service-string dispatch. Reading this is how you build the table in §3.4 for a version you do not have a device for |
| `packages/modules/adb/shell_service.cpp` | `shell:` and `shell,v2:`, including the packet ids `0`–`5` |
| `packages/modules/adb/file_sync_service.cpp` | The device half of `push`/`pull` |
| `packages/modules/adb/client/adb_install.cpp` | **The three-stream install** — the strategy choice between `abb_exec`, `exec:cmd package`, and the legacy push-and-`pm` path |
| `packages/modules/adb/pairing_connection/` | The SPAKE2 wireless-debugging pairing |
| `packages/modules/adb/tls/` | The `A_STLS` upgrade and certificate handling |

### Framework and platform, outside that directory

| Path | What you get |
|---|---|
| `frameworks/base/services/core/java/com/android/server/adb/AdbDebuggingManager.java` | The other end of `adbd`'s seqpacket socket: raising the dialog, writing `adb_keys` and `adb_temp_keys.xml`, and the automatic-expiry timer behind `ADB_ALLOWED_CONNECTION_TIME` |
| `frameworks/base/packages/SystemUI/src/com/android/systemui/usb/UsbDebuggingActivity.java` | The "Allow USB debugging?" dialog itself, including the "Always allow from this computer" checkbox |
| `system/core/rootdir/init.usb.rc` | The `service adbd` definition — `class core`, `updatable`, `seclabel u:r:adbd:s0`, the `socket adbd seqpacket 660 system system` line, and `mkdir /data/misc/adb 02750 system shell`. Vendors ship their own copy; read the one on your device, not this one |
| `system/core/rootdir/init.usb.configfs.rc` | The property triggers that start and stop `adbd` |
| `system/sepolicy/private/adbd.te` | The `adbd` SELinux domain |
| `system/sepolicy/private/shell.te` | The `shell` domain — the policy behind the `adb_keys_file` denial measured in §3.9.4 |
| `frameworks/native/cmds/cmd/cmd.cpp` | Where `exec:cmd package …` actually goes: a `servicemanager` lookup and an `IBinder::shellCommand()` transaction carrying the argv and the three stdio file descriptors |

**Android Code Search** — <https://cs.android.com/> — the fastest way to read any of the above
without a checkout. Search for a symbol, not a filename.

---

## 2. Official documentation

| Link | Why |
|---|---|
| <https://developer.android.com/tools/adb> | The user-facing reference. Complete on commands, silent on the protocol |
| <https://developer.android.com/tools/adb#wireless-android11-command-line> | The `adb pair` flow, and the only official description of the Android 11 wireless model |
| <https://source.android.com/docs/core/architecture/kernel/adb> | The platform view: authentication, `ro.adb.secure`, and what an OEM is expected to configure |
| <https://source.android.com/docs/core/ota/modular-system> | APEX and Mainline — why `adbd` moved out of `/system/bin` |
| <https://source.android.com/docs/security/features/selinux> | Needed to read `adbd.te` and `shell.te` |
| <https://developer.android.com/reference/android/provider/Settings.Global#ADB_ENABLED> | The setting the Developer Options toggle writes |
| <https://developer.android.com/reference/android/Manifest.permission> | For working out what each of `com.android.shell`'s 183 permissions actually unlocks |

---

## 3. Standards the protocol depends on

| Standard | Where it appears in ADB |
|---|---|
| **RFC 8017** — PKCS #1 v2.2 | The v1.5 signature padding used by `A_AUTH`, and the DigestInfo prefix `30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14` |
| **RFC 8446** — TLS 1.3 | What `A_STLS` upgrades the connection to |
| **RFC 6762** — Multicast DNS | Wireless-debugging discovery |
| **RFC 6763** — DNS-Based Service Discovery | The `_adb._tcp`, `_adb-tls-pairing._tcp` and `_adb-tls-connect._tcp` service types |
| **RFC 5280** — X.509 | The certificates exchanged during pairing |
| **SPAKE2** (a password-authenticated key exchange; see the CFRG drafts and the original Abdalla–Pointcheval paper) | Turns the six-digit pairing code into a shared key without exposing it |
| **USB 2.0 specification**, chapter 9 | The interface descriptors `adbd` writes to `ep0`; ADB's signature is class `0xFF`, subclass `0x42`, protocol `0x01` |

---

## 4. OWASP

| Reference | Relevance |
|---|---|
| <https://mas.owasp.org/MASVS/> | MASVS-RESILIENCE (anti-tampering and debuggability), MASVS-CODE-2 (debug artefacts), MASVS-STORAGE-2 (logs, reachable because `shell` holds `READ_LOGS`) |
| <https://mas.owasp.org/MASTG/> | The testing guide |
| MASTG "Android Basic Security Testing" | Every setup step in MASTG assumes the transport this chapter documents. Read it *after* this chapter and the instructions stop being magic |

---

## 5. Vulnerability classes

This chapter does not cite identifiers it has not verified. These are the **classes** to search for
by name, each of which has substantial public write-up material:

| Class | What to search |
|---|---|
| Self-propagating malware over exposed ADB port 5555 | "ADB.Miner", "ADB worm 5555", "Android debug bridge cryptominer 2018". Targets were TV boxes, tablets and development boards shipping `ro.adb.secure=0` |
| Pre-authorised vendor keys in shipping firmware | Recurring finding in embedded Android teardowns; search for `/adb_keys` in ramdisk analyses |
| `android:debuggable="true"` in production releases | A standing category in app-store scanning and in MASTG; the impact is entirely via `run-as` over ADB |
| Unauthenticated localhost debug ports | The port-5037 problem generalises: any developer daemon on loopback with no authentication |
| Malicious USB hosts ("juice jacking") | The threat model that the USB transport's lack of channel binding does not address |

> Do not copy a CVE identifier from a blog into a report without checking it against the NVD entry
> and confirming the affected versions. This repository's rule is to describe the class rather than
> invent an identifier, and that rule exists because invented identifiers survive longer than the
> reports that contain them.

---

## 6. Tools that speak this protocol

| Tool | Note |
|---|---|
| `adb` itself (Android SDK platform-tools) | The reference implementation. `adb --version` tells you the client build |
| **`libusb`-based ADB clients** (several exist in Python, Go and Rust) | The way to reach a device over USB without the SDK. Read one after Lab 02 — you will recognise every function |
| `scrcpy` | Speaks the protocol directly to push and run its own server; a good example of a non-SDK client |
| Wireshark | ADB over TCP is cleartext. Filter: `tcp contains "host::features="` |
| `frida-server` | Reached over `adb forward`; see [53-Frida](../../53-Frida/README.md) |

---

## 7. This chapter's own artefacts

| File | What it is |
|---|---|
| [`../scripts/adb-mini-client.py`](../scripts/adb-mini-client.py) | Dependency-free client: `A_CNXN`, `A_AUTH` with the real host key, one stream. The measured transcripts in §7 came from it |
| [`../scripts/adb-install-transport.py`](../scripts/adb-install-transport.py) | The three-stream session install over raw ADB, verified end to end |
| [`../scripts/adb-posture.sh`](../scripts/adb-posture.sh) | Read-only posture report with a reasoned severity call |
| [`../scripts/adbd-trace.js`](../scripts/adbd-trace.js) | Frida agent that decodes headers from inside `adbd` |
| [`../examples/handshake-transcript.txt`](../examples/handshake-transcript.txt) | A complete annotated wire transcript, byte by byte |
| [`../examples/decode_header.py`](../examples/decode_header.py) | Paste hex, get a decoded header. The smallest useful thing in the chapter |
| [`../examples/posture-measured.txt`](../examples/posture-measured.txt) | Real posture output from two devices with opposite configurations |
| [`../labs/lab-01-read-the-wire.md`](../labs/lab-01-read-the-wire.md) | Decode headers by hand |
| [`../labs/lab-02-speak-the-protocol.md`](../labs/lab-02-speak-the-protocol.md) | Write the client yourself |
| [`../labs/lab-03-posture-and-exposure.md`](../labs/lab-03-posture-and-exposure.md) | Measure, sweep, and rate honestly |
| [`../labs/lab-04-ctf-unattended-terminal.md`](../labs/lab-04-ctf-unattended-terminal.md) | Five flags on a simulated exposed device |

---

## 8. Related chapters

| Chapter | Relationship |
|---|---|
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | Owns the command set. This chapter owns the transport beneath every one of them |
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | Owns the package-manager half of `adb install`; §3.14 here owns the transport half |
| [10-APK-Internals](../../10-APK-Internals/README.md) | What `install-commit` verifies once the bytes have arrived |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The app sandbox that `shell` is deliberately outside of |
| [22-SELinux](../../22-SELinux/README.md) | The `adbd` and `shell` domains, and the `adb_keys_file` AVC in §3.9.4 |
| [23-Permissions](../../23-Permissions/README.md) | `platform.xml`, `privapp-permissions`, and where `shell`'s 183 grants come from |
| [24-IPC](../../24-IPC/README.md) | Where `exec:` and `abb_exec:` hand off |
| [25-Binder](../../25-Binder/README.md) | `cmd`, `shellCommand()`, and file-descriptor passing over Binder |
| [06-Android-Architecture](../../06-Android-Architecture/README.md) | `init`, system properties, and the service startup chain |
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | UIDs, supplementary groups, capabilities, `/proc` |
| [34-Cryptography](../../34-Cryptography/README.md) | RSA and PKCS#1 v1.5 — why signing an unhashed token is still sound |
| [35-SSL](../../35-SSL/README.md) | The TLS that `A_STLS` upgrades to |
| [37-RootDetection](../../37-RootDetection/README.md) | Apps that check `adb_enabled` and `ro.debuggable`, and how to defeat them |
| [53-Frida](../../53-Frida/README.md) | Reaches `frida-server` through `adb forward` |
| [62-Magisk](../../62-Magisk/README.md) | Where `su` comes from when `adb root` is refused |
| `61-Fastboot` | The other "only way to talk to a device" — a separate protocol with no Android userspace behind it |
