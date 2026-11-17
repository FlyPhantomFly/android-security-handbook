# Fastboot — Cheat Sheet

> **Commands marked D are DESTRUCTIVE. Two marked B can BRICK a device.**
> Nothing on this page should be typed against a device that is not yours.

---

## Risk key

| Mark | Meaning |
|---|---|
| **R** | Read. Safe on any device already in fastboot mode |
| **S** | Changes what runs; writes nothing to flash. Reversible by power-cycling |
| **D** | Destructive. Overwrites or erases. Irreversible without a backup |
| **B** | Can leave a device that will not boot and cannot be recovered by software you own |

---

## Getting in and out

| Command | Where | Risk | Effect |
|---|---|---|---|
| `adb reboot bootloader` | Android | S | Writes BCB to `misc`, reboots to bootloader fastboot |
| `adb reboot fastboot` | Android, API 29+ | S | Reboots to `fastbootd` in the recovery ramdisk |
| `adb reboot recovery` | Android | S | Writes BCB, reboots to recovery |
| Volume Down + Power (varies) | Powered off | S | **Write yours down.** The only route that works on a bricked device |
| `fastboot reboot` | fastboot | S | Boot Android |
| `fastboot reboot bootloader` | fastbootd | S | Switch to bootloader fastboot |
| `fastboot reboot fastboot` | bootloader | S | Switch to `fastbootd` |
| `fastboot continue` | fastboot | S | Resume the interrupted boot |
| Hold power 10–20 s | any | S | Force power off |

## Reads — the whole safe surface

| Command | Risk | Returns |
|---|---|---|
| `fastboot devices [-l]` | R | Devices in fastboot mode. **No output + exit 0 = none attached** |
| `fastboot --version` | R | Host tool version |
| `fastboot getvar all` | R | Stream of `INFO` lines, then `OKAY`. Not guaranteed complete |
| `fastboot getvar NAME` | R | One variable |
| `fastboot flashing get_unlock_ability` | R | `1` = unlock permitted, `0` = refused |
| `fastboot --verbose <cmd>` | R | Prints raw commands and responses — a protocol tracer |

## `getvar` variables

| Variable | Meaning |
|---|---|
| `product` | Device codename. Factory images are keyed on this |
| `serialno` | Serial |
| `version` | Protocol version. Near-universally `0.4` |
| `secure` | `yes` = the bootloader requires signed images |
| `unlocked` | `yes` / `no`. **Self-reported — a claim, not evidence** |
| `max-download-size` | Download buffer size, hex. Decides whether images need sparsing |
| `partition-type:NAME` | Filesystem type. Used by `format` |
| `partition-size:NAME` | Size in hex bytes |
| `is-logical:NAME` | `yes` = inside `super`, **needs `fastbootd`** |
| `has-slot:NAME` | `yes` = has `_a` / `_b` variants |
| `slot-count` | `2` on A/B |
| `current-slot` | `a` or `b` |
| `is-userspace` | `yes` on `fastbootd`, `no` in the bootloader |
| `super-partition-name` | Usually `super` |
| `snapshot-update-status` | `none` / `snapshotted` / `merging`. **Must be `none` before flashing** |
| `version-bootloader`, `version-baseband` | Firmware versions |
| `logical-block-size`, `erase-block-size` | Storage geometry |
| `off-mode-charge`, `battery-voltage` | Some devices refuse to flash under a voltage threshold |

## Writes

| Command | Risk | Notes |
|---|---|---|
| `fastboot boot IMG` | **S** | RAM only, nothing written. **The habit that saves devices.** Not on every device |
| `fastboot set_active a\|b` | S | Reversible |
| `fastboot flash PART IMG` | **D** | Overwrites a partition |
| `fastboot flash:raw PART KERNEL [RD]` | **D** | Builds a boot image host-side |
| `fastboot erase PART` | **D** | Erases |
| `fastboot format[:TYPE[:SIZE]] PART` | **D** | Builds the filesystem **on the host** with `mke2fs`/`make_f2fs` |
| `fastboot flashall` / `fastboot update ZIP` | **D** | Whole factory image |
| `fastboot wipe-super [SUPER_EMPTY]` | **D** | Resets `super` to an empty default layout |
| `fastboot create/delete/resize-logical-partition` | **D** | `fastbootd` only |
| `fastboot snapshot-update cancel` | **D** | "May make the device unbootable until it is reflashed" — the tool's own words |
| `fastboot flash bootloader\|xbl\|aboot\|sbl1` | **B** | The soft-brick / hard-brick boundary |

## Lock state

| Command | Risk | Notes |
|---|---|---|
| `fastboot flashing unlock` | **D** | **WIPES ALL USER DATA.** Needs `get_unlock_ability = 1` and physical confirmation |
| `fastboot flashing lock` | **B** | **WIPES ALL USER DATA.** Bricks if modified images are present |
| `fastboot flashing unlock_critical` | **D** | Additionally permits bootloader/modem writes |
| `fastboot flashing lock_critical` | D | Reverse |
| `fastboot oem unlock` | **D** | Pre-Android-6 spelling. Vendor-defined |
| `fastboot oem <anything>` | **?** | No specification, no test suite, most privileged context |

### The only safe relock order

```
1. fastboot flashall            # or flash every partition from the STOCK factory image
2. fastboot reboot
3. verify it boots and is stock
4. adb reboot bootloader
5. fastboot flashing lock
```

**Flash stock, boot it, verify it, then lock.** Skipping 1–3 is how devices are lost.

## Useful flags

| Flag | Effect |
|---|---|
| `-s SERIAL` | Target one device |
| `-s tcp\|udp:HOST[:PORT]` | Non-USB transport |
| `--slot a\|b\|all\|other` | Which slot. Default: current active |
| `--set-active[=SLOT]` | Set active slot before rebooting |
| `-S SIZE[K\|M\|G]` | Force a smaller sparse split |
| `-w` | **Wipe userdata** |
| `--disable-verity` | Set vbmeta flags bit 0 — see below |
| `--disable-verification` | Set vbmeta flags bit 1 — strictly larger |
| `--skip-reboot`, `--skip-secondary` | Flashall behaviour |
| `--force` | Force a flash that may be unsafe |
| `--disable-fastboot-info` | Ignore `$OUT/fastboot-info.txt` |
| `--verbose`, `-v` | Print the wire traffic |

---

## The wire protocol

| Prefix | Meaning | Ends the transaction? |
|---|---|---|
| `OKAY` | Success | Yes |
| `FAIL` | Failure | Yes |
| `DATA<8 hex>` | "Send exactly this many bytes now" | No — bulk follows |
| `INFO` | Progress; printed with `(bootloader)` | **No** |
| `TEXT` | Free text; printed verbatim | **No** |

| Property | Value |
|---|---|
| Command max length | **64 bytes** ASCII, no terminator |
| Response max length | **256 bytes** ASCII |
| Download size format | `download:%08x` — eight lowercase hex digits |
| USB interface | class `0xFF`, subclass `0x42`, protocol **`0x03`** |
| adb's interface | class `0xFF`, subclass `0x42`, protocol **`0x01`** |
| Framing on bulk data | **None.** The device counts bytes |
| Authentication | **None** |
| Integrity check | **None** |

**Three legs of every operation:** `getvar` (ask) → `download:` (fill the shared buffer) → `flash:` /
`boot` (act on the buffer). **`flash:` does not carry the image.**

---

## Lock states

| State | Bootloader | Signed by | `ro.boot.verifiedbootstate` | flash/erase/boot |
|---|---|---|---|---|
| GREEN | Locked | OEM key in fuses | `green` | Refused |
| YELLOW | Locked | Owner-supplied key | `yellow` | Refused |
| ORANGE | Unlocked | Nothing enforced | `orange` | **Permitted** |
| RED | Locked | Verification failed | `red` | Refused; will not boot |
| *(none)* | No bootloader | — | *(empty)* | N/A — measured on an emulator |

**Unlocking wipes. Relocking wipes.** Both, by design.
**You cannot unlock from fastboot alone** — `get_unlock_ability` is set only by a booted,
screen-unlocked Android.

---

## Device-side reads (no reboot, non-destructive)

```bash
# adb shell
getprop ro.boot.verifiedbootstate     # green|yellow|orange|red|(empty)
getprop ro.boot.flash.locked          # 1 locked, 0 unlocked
getprop ro.boot.vbmeta.device_state   # locked|unlocked
getprop ro.boot.veritymode            # enforcing|logging|disabled
getprop ro.boot.vbmeta.digest
getprop ro.boot.vbmeta.size
getprop ro.oem_unlock_supported
getprop sys.oem_unlock_allowed
getprop ro.boot.slot_suffix           # _a|_b|(empty)
getprop ro.build.ab_update
getprop ro.boot.dynamic_partitions
getprop ro.virtual_ab.enabled

cat /proc/cmdline    | tr ' ' '\n' | grep androidboot   # often EACCES; root needed
cat /proc/bootconfig | grep androidboot                 # where ro.boot.* come from

ls -l /dev/block/by-name/
```

```bash
# adb shell, root
dmctl list devices                    # GROUND TRUTH for what is mapped
dmctl table system                    # linear: 0-LENGTH: linear, MAJ:MIN START (512B sectors)
dmctl table system-verity             # verity target, root hash, salt, FEC
lpdump                                # super metadata -- believe dmctl if they disagree
bootctl get-number-slots
bootctl get-current-slot
grep -E ' (/|/vendor|/product) ' /proc/mounts
```

> **`su` is not portable.** Magisk: `su -c '<cmd>'`. **Android emulator: `su 0 <cmd>`** — the `-c`
> form fails in a way that reads as "not rooted".

---

## vbmeta flags

| | |
|---|---|
| Field | `flags`, `uint32`, **BIG-ENDIAN**, header offset **120** |
| Byte that changes | **123** (low byte of a big-endian word) |
| Bit 0 | `AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED` — dm-verity never set up |
| Bit 1 | `AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED` — whole chain skipped |
| Header size | 256 bytes |
| Layout | `header (256) \|\| authentication block \|\| auxiliary block` |
| Integrity hash | `sha256(header[0:256] \|\| aux_block)`, stored at `hash_offset` in the auth block |

**Setting either flag invalidates the image's own hash**, because the flags field is inside the hashed
region. `--disable-verity` only works on an unlocked bootloader; on a locked one it produces RED.

```bash
python3 -B scripts/vbmeta-flags.py show vbmeta.img
python3 -B scripts/vbmeta-flags.py set  vbmeta.img out.img --disable-verity
python3 -B scripts/vbmeta-flags.py diff vbmeta.img out.img
```

---

## Sparse images

| Field | Value |
|---|---|
| Magic | `0xED26FF3A`, **little-endian** (opposite of vbmeta) |
| File header | 28 bytes |
| Chunk header | 12 bytes |
| `chunk_sz` | size in **blocks** of the expanded output |
| `total_sz` | size in **bytes** of this chunk including its header |

| Chunk | Value | On disk | Expands to |
|---|---|---|---|
| `RAW` | `0xCAC1` | `chunk_sz × blk_sz` | those bytes |
| `FILL` | `0xCAC2` | **4** | that 4-byte pattern × `chunk_sz` blocks |
| `DONT_CARE` | `0xCAC3` | **0** | skipped — **old flash contents survive** |
| `CRC32` | `0xCAC4` | 4 | nothing; contributes no blocks |

**Not compression.** Random data sparses *larger*.

```bash
python3 -B scripts/sparse-tool.py info   img.simg
python3 -B scripts/sparse-tool.py verify img.simg
python3 -B scripts/sparse-tool.py expand img.simg out.img
python3 -B scripts/sparse-tool.py create raw.img out.simg
```

---

## `super` and dynamic partitions

| | |
|---|---|
| Container | `super`, one physical partition |
| Metadata | `liblp`, at the start of `super` |
| Alignment | **1 MiB = 2048 sectors.** Every logical partition start is a multiple |
| dm table units | **512-byte sectors**, `0-LENGTH: linear, MAJ:MIN START` |
| Flashing them | Requires **`fastbootd`** — the bootloader has no `liblp` |
| Stack | `super` → linear dm → verity dm → mount |

---

## A/B slots

| Field | Meaning |
|---|---|
| `priority` | 0–15; highest bootable slot wins |
| `tries_remaining` | Decremented per attempt; 0 = unbootable |
| `successful_boot` | Set by Android **after** a healthy boot (`update_verifier`) |

```bash
fastboot getvar current-slot
fastboot --slot other flash boot boot.img
fastboot --slot all   flash boot boot.img     # survives a slot switch
fastboot set_active b
```

**Virtual A/B:** `getvar snapshot-update-status` must be `none` before flashing.

---

## AOSP paths

| Path | Contents |
|---|---|
| `system/core/fastboot/README.md` | **The protocol specification** |
| `system/core/fastboot/fastboot.cpp` | Host tool, vbmeta flag rewriting |
| `system/core/fastboot/fastboot_driver.cpp` | The wire protocol |
| `system/core/fastboot/fs.cpp` | `format` and the `mke2fs` shell-out |
| `system/core/fastboot/device/` | **`fastbootd`** |
| `system/core/fastboot/device/commands.cpp` | One handler per verb |
| `system/core/fastboot/device/variables.cpp` | The `getvar` table |
| `system/core/fastboot/fuzzy_fastboot/` | OEM conformance and malformed-input suite |
| `system/core/libsparse/include/sparse/sparse_format.h` | Sparse structures |
| `system/core/fs_mgr/liblp/include/liblp/metadata_format.h` | `super` metadata |
| `system/core/fs_mgr/libsnapshot/` | Virtual A/B |
| `external/avb/libavb/avb_vbmeta_image.h` | `AvbVBMetaImageHeader`, flag constants |
| `external/avb/avbtool.py` | Host AVB tool |
| `bootable/recovery/bootloader_message/…/bootloader_message.h` | The BCB in `misc` |
| `hardware/interfaces/boot/` | `IBootControl` |
| `system/update_engine/` | A/B updates, `update_verifier` |
| `system/tools/mkbootimg/include/bootimg/bootimg.h` | Boot image header v0–v4 |

---

## Boot image versions

| Version | Era | Ramdisk lives in |
|---|---|---|
| 0–2 | Android 9 and earlier | `boot` |
| 3 | Android 11 | `boot` + `vendor_boot` |
| 4 | Android 13 GKI | **`init_boot`** — `boot` holds only the kernel |

```bash
# adb shell -- do not guess, look
ls -l /dev/block/by-name/ | grep -E 'init_boot|boot_[ab]?$|vendor_boot'
```

---

## Failure diagnosis

| Symptom | Cause |
|---|---|
| `fastboot devices` silent, exit 0 | No device in fastboot mode. Also: charge-only cable; Linux udev; device is in Android |
| `< waiting for any device >` forever | Same |
| `FAILED (remote: 'Device is locked...')` | Locked. Working correctly |
| `FAILED (remote: 'oem unlock is not allowed')` | `get_unlock_ability = 0`. Needs a booted Android |
| `FAILED (remote: 'unknown command')` on `boot` | OEM disabled RAM booting |
| Device reboots mid-flash | Automatic reroute to `fastbootd` for a logical partition. Normal |
| Flashed, no root, A/B device | Wrong slot. Check `current-slot`; use `--slot all` |
| Flashed `boot`, no root, Android 13+ | Ramdisk is in `init_boot` on GKI devices |
| `format` fails oddly | Host `mke2fs`/`make_f2fs` missing or wrong version |
| Flash corrupts a virtual-A/B device | `snapshot-update-status` was not `none` |
| Rebuilt `super` flashes, will not boot | 1 MiB alignment not reproduced |
| "Your device is corrupt" after relock | Relocked with modified images. See lab 04 |

---

## Claims versus evidence

| Source | Forgeable by root? | Weight |
|---|---|---|
| `ro.boot.flash.locked`, `ro.boot.verifiedbootstate` | **Yes**, one `resetprop` | Claim |
| `fastboot getvar unlocked` | Yes, if the bootloader is replaced | Claim |
| The boot warning screen | Hard, but cosmetic | Weak |
| `dmctl list devices` | Needs kernel-level control | Strong |
| Hashing `boot` against the OEM factory image | No, if you have the reference | Strong |
| **Key attestation `deviceLocked`** | **No — computed in the TEE** | **Evidence** |

Measured: a device reported `ro.boot.verifiedbootstate = green` from `getprop` while its own
TEE-signed attestation, seconds later, said `verifiedBootState = Unverified, deviceLocked = false`.

---

## Measured facts worth not re-deriving

| Fact | Where |
|---|---|
| `--disable-verity` changes **one byte, offset 123**, and breaks the image's own hash | §3.8 |
| Every logical partition in `super` starts on a **1 MiB** boundary | §3.7 |
| `ro.boot.verifiedbootstate` is **empty**, not `orange`, on an API 35 emulator | §5.3 |
| `!"orange".equals(state)` therefore returns **true** on an emulator | §5.3 |
| An emulator has **no bootloader, no `misc`, no `boot`, no boot control HAL** | §7.6 |
| `adb reboot bootloader` on an AVD returns to Android in ~40 s; `fastboot` never sees it | §7.6 |
| `fastboot devices` with nothing attached: **no output, exit 0** | §3.4 |
| `lpdump` failed where `dmctl table` succeeded — believe the kernel | §3.7 |
| Dynamic partitions and A/B are orthogonal; measured `true` / `false` together | §3.7 |
| `format` runs `mke2fs` **on the host** | §3.4 |
| Hashtree **descriptors** present ≠ verity **running** | §3.7 |
| `ro.bootloader` is `unknown` on both an emulator and a retail phone | Lab 01 |

---

## Chapter files

| | |
|---|---|
| `scripts/bootstate-audit.sh` | Read-only device posture, evidence beside every verdict |
| `scripts/fastboot-recon.sh` | Read-only recon; refuses destructive verbs by construction |
| `scripts/vbmeta-flags.py` | AVB flags, and the hash invariant |
| `scripts/sparse-tool.py` | Sparse images: info / verify / expand / create |
| `scripts/bootprop-observer.js` | Frida: every boot-property read, all four routes |
| `scripts/make-ctf-images.py` | Lab 04 artefact generator |
| `examples/measured-avd-boot-state.md` | Every raw measurement |
| `examples/fastboot-wire-transcript.md` | Seven annotated sessions |
| `examples/BootStateChecker.java` | Vulnerable check and its replacement |
| `labs/lab-01` … `lab-04` | Posture, sparse, vbmeta, CTF |
