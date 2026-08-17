# An annotated fastboot session, on the wire

> **⚠️ THIS TRANSCRIPT IS RECONSTRUCTED, NOT CAPTURED.**
>
> No device was put into fastboot mode while writing chapter 61, and no destructive fastboot command
> was executed against anything. Every byte below is derived from three sources that *were* examined
> directly:
>
> 1. **The protocol specification** in AOSP at `system/core/fastboot/README.md`.
> 2. **Strings extracted from the shipped host binary**, `fastboot 35.0.2-12147458` — the five
>    response prefixes, the `getvar` names, the `download:` format string, and the
>    `Rewriting vbmeta struct at offset: %lld` log line are all confirmed present in that binary.
> 3. **`fastboot --help` output** from the same binary.
>
> **Device responses are illustrative.** Real values differ per device and per bootloader version.
> The *shape* of every exchange — which side speaks, in what order, with what prefix — is specified
> and is accurate. The *content* of the device's replies is representative, not observed.
>
> This distinction is why the file says so at the top rather than in a footnote. A fabricated
> transcript in a chapter about commands that destroy devices would be worse than no transcript.

---

## How to read this

```
H>  bytes the HOST writes to the USB bulk OUT endpoint
D>  bytes the DEVICE writes to the USB bulk IN endpoint
##  annotation
```

Commands are ASCII, at most **64 bytes**, no terminator, no length prefix — the USB transfer length
*is* the length. Responses are ASCII, at most **256 bytes**, and always begin with exactly one of
five four-character prefixes:

| Prefix | Meaning | Ends the transaction? |
|---|---|---|
| `OKAY` | success | yes |
| `FAIL` | failure | yes |
| `DATA` | "send exactly this many bytes now" | no — bulk transfer follows |
| `INFO` | progress; host prints with a `(bootloader)` prefix | **no** |
| `TEXT` | free text; host prints verbatim | **no** |

To see the real thing on a device you own, `fastboot --verbose` prints commands and responses; for
the raw USB, use `usbmon` + Wireshark on Linux or USBPcap on Windows.

---

## Session 1 — reconnaissance, and nothing else

This is the only session in this file that is safe on a device you do not own — and even then,
*getting* the device into fastboot mode is itself a state change.

```
## The host has just enumerated a USB interface with
##   bInterfaceClass    = 0xFF
##   bInterfaceSubClass = 0x42
##   bInterfaceProtocol = 0x03
## Those three constants are how `fastboot devices` finds a device. adb uses
## the same class and subclass but protocol 0x01, which is exactly why a device
## is visible to one tool or the other and never both.

H>  getvar:version
D>  OKAY0.4
##  Near-universally 0.4. It has not moved and tells you nothing.

H>  getvar:product
D>  OKAYexampledevice
##  The single most important identifier: factory images are keyed on it.

H>  getvar:serialno
D>  OKAY1A2B3C4D5E6F

H>  getvar:unlocked
D>  OKAYno
##  LOCKED. flash, erase, format, boot and set_active will all be refused.
##  This is the bootloader answering a question about itself, so treat it as a
##  claim. The evidence version is deviceLocked inside a TEE-signed key
##  attestation -- see 50-HardwareBackedSecurity.

H>  getvar:secure
D>  OKAYyes
##  The bootloader requires signed images.

H>  flashing get_unlock_ability
D>  INFOget_unlock_ability: 0
D>  OKAY
##  0 means the OEM-unlocking toggle in Developer Options is OFF.
##  `fastboot flashing unlock` WILL FAIL, and there is no fastboot-side way to
##  change that. Someone must boot Android, unlock the screen with the owner's
##  credential, and turn the toggle on. THAT DEPENDENCY IS THE ENTIRE
##  THEFT-PROTECTION STORY: a thief with a locked, powered-off phone is stuck
##  here. Note the two-response shape -- INFO does not end the transaction.

H>  getvar:max-download-size
D>  OKAY0x10000000
##  268,435,456 bytes = 256 MiB. Any image larger than this must be split into
##  several sparse images. See session 3.

H>  getvar:is-userspace
D>  OKAYno
##  This is the BOOTLOADER, not fastbootd. It owns the lock state; it cannot
##  flash logical partitions inside super.

H>  getvar:slot-count
D>  OKAY2
H>  getvar:current-slot
D>  OKAYa
##  An A/B device, running slot A. Any `flash` without --slot targets _a.

H>  getvar:snapshot-update-status
D>  OKAYnone
##  Virtual A/B is idle. If this said `snapshotted` or `merging`, flashing now
##  is one of the reliable ways to need a full factory image.

H>  getvar:has-slot:boot
D>  OKAYyes
H>  getvar:is-logical:boot
D>  OKAYno
H>  getvar:partition-size:boot
D>  OKAY0x4000000
H>  getvar:partition-type:boot
D>  OKAYraw
##  boot: has slots, is physical, 64 MiB, raw. Flashable from the bootloader.

H>  getvar:is-logical:system
D>  OKAYyes
##  system is LOGICAL -- it lives inside `super` and the bootloader cannot
##  write it. See session 4.

H>  getvar:all
D>  INFOversion: 0.4
D>  INFOproduct: exampledevice
D>  INFOsecure: yes
D>  INFOunlocked: no
D>  INFOmax-download-size: 0x10000000
D>  INFOpartition-type:boot: raw
D>  INFOpartition-size:boot: 0x4000000
D>  INFOhas-slot:boot: yes
D>  INFOslot-count: 2
D>  INFOcurrent-slot: a
D>  INFOoem-custom-thing: 1
D>  OKAY
##  getvar:all streams INFO lines then a final OKAY. It is NOT guaranteed
##  complete -- a bootloader may implement variables it does not enumerate.
##  The vendor-specific names are the interesting part: `oem-custom-thing` has
##  no specification and no shared test suite, which is where bugs live.
```

## Session 2 — what a locked bootloader does when you try to write

The important session, because it is what "locked" *means* concretely.

```
H>  download:00400000
D>  DATA00400000
##  Note: the DOWNLOAD is allowed. A locked bootloader will happily accept
##  bytes into its RAM buffer -- accepting data is not the privileged act.

H>  <4,194,304 raw bytes -- no framing, no checksum, no escaping>
D>  OKAY
##  The device counted 4,194,304 bytes and stopped. That is the entire framing
##  mechanism: a count, agreed in advance by the DATA response.

H>  flash:boot_a
D>  FAILDevice is locked. Cannot flash images
##  THERE is the lock. The refusal is on the ACT, not on the data transfer.
##  This is why `flash:` carries only a partition name: the image is already
##  in the buffer, and the buffer is not the protected thing.

H>  erase:userdata
D>  FAILDevice is locked. Cannot erase

H>  boot
D>  FAILDevice is locked. Cannot boot images
##  `fastboot boot` is refused too. Running an unverified image from RAM is
##  exactly as much of a Verified Boot bypass as writing one to flash.

H>  flashing unlock
D>  FAILoem unlock is not allowed
##  Because get_unlock_ability was 0 in session 1. Not a bug -- the design.
```

## Session 3 — a large image and the download buffer

The device said 256 MiB in session 1. Here is a 3 GiB `super`.

```
##  Host side, before any bytes move:
##    - super.img is 3,221,225,472 bytes raw
##    - libsparse describes it as chunks; most of it is DONT_CARE and FILL
##    - the sparse form is still larger than 256 MiB, so it is RE-SPARSED into
##      N pieces, each below max-download-size, each carrying a leading
##      DONT_CARE chunk that positions its data at the correct offset

H>  download:0ffff000
D>  DATA0ffff000
H>  <268,431,360 bytes: sparse header + chunks, piece 1 of 7>
D>  OKAY
H>  flash:super
D>  INFOSending sparse 'super' 1/7 (262140 KB)
D>  INFOWriting 'super'
D>  OKAY

H>  download:0ffff000
D>  DATA0ffff000
H>  <piece 2 of 7 -- begins with a DONT_CARE chunk covering piece 1's range>
D>  OKAY
H>  flash:super
D>  INFOSending sparse 'super' 2/7 (262140 KB)
D>  OKAY

##  ... pieces 3 through 7 ...

##  THE THING TO NOTICE: `flash:super` is issued SEVEN TIMES, each time acting
##  on whatever is currently in the download buffer. Reassembly is the DEVICE's
##  job, and it is possible only because each piece says where its data belongs.
##  The `Sending sparse '%s' %zu/%zu (%u KB)` format string is present verbatim
##  in the host binary.
```

> **⚠️ `DONT_CARE` does not mean zeros**
> A `DONT_CARE` chunk says "I decline to describe this range", and the device may legitimately skip
> it — leaving whatever was on flash before. Flashing a sparse image therefore does **not** guarantee
> the undescribed ranges are erased. For a factory image that is fine, because the filesystem
> metadata says those blocks are free. For anyone reasoning about data remanence it is a real and
> frequently-missed fact. If you need the old bytes gone, `erase` first.

## Session 4 — the automatic reroute to `fastbootd`

You type one command; the tool does five things. This is the sequence people find alarming the first
time, because the device reboots in the middle of a flash and nothing is wrong.

```
##  You typed:  fastboot flash system system.img

H>  getvar:is-userspace
D>  OKAYno
##  Talking to the bootloader.

H>  getvar:is-logical:system
D>  OKAYyes
##  But the target lives inside `super`, which needs an liblp parser the
##  bootloader does not have. Wrong endpoint.

H>  reboot-fastboot
D>  OKAY
##  Host prints something like "Rebooting into fastboot" and waits for the
##  device to re-enumerate. The device boots the RECOVERY RAMDISK, which is
##  where fastbootd lives.

##  ... device disappears from USB, reappears ...

H>  getvar:is-userspace
D>  OKAYyes
##  Now talking to fastbootd. Source: system/core/fastboot/device/.

H>  download:20000000
D>  DATA20000000
H>  <536,870,912 bytes>
D>  OKAY

H>  flash:system
D>  INFOResizing 'system'
D>  INFOFlashing sparse image at offset 0
D>  OKAY
##  fastbootd resolved `system` through liblp to a set of extents inside super,
##  created or resized the device-mapper device, and wrote through the kernel
##  block layer.

H>  reboot
D>  OKAY

##  WHAT DID NOT HAPPEN: nothing verified the image. fastbootd does not check
##  that system.img is signed, or that it matches the vbmeta on the device, or
##  that it is even an ext4 filesystem. Verification happens at BOOT, by AVB,
##  and only if the bootloader is locked. The flash path is deliberately dumb;
##  the intelligence is in the verifier.
```

## Session 5 — `--disable-verity`, and the host-side edit

The command that generates the most confident misinformation on the internet.

```
##  You typed:  fastboot --disable-verity flash vbmeta vbmeta.img

##  BEFORE ANY BYTES GO ANYWHERE, the host edits the file in memory. Its own
##  log line for this is present verbatim in the binary:
##      Rewriting vbmeta struct at offset: %lld
##
##  The edit is: set bit 0 of the `flags` field, a big-endian uint32 at offset
##  120 of the 256-byte AvbVBMetaImageHeader. The low-order byte is therefore
##  at offset 123.
##
##  MEASURED on a real vbmeta pulled from an Android 15 device:
##      flags 0x00000000 -> 0x00000001
##      bytes changed: [123]                    <- exactly one byte
##      stored hash  93dfae21...
##      recomputed   3695fea8...                <- NO LONGER MATCHES
##
##  The flags field is INSIDE the region AVB hashes. Setting it invalidates the
##  image's own integrity hash and therefore the signature over that hash.
##  Reproduce with: python3 -B scripts/vbmeta-flags.py

H>  download:00001a80
D>  DATA00001a80
H>  <6,784 bytes -- the MODIFIED vbmeta>
D>  OKAY

H>  flash:vbmeta_a
D>  OKAY
##  Accepted -- BECAUSE THIS DEVICE IS UNLOCKED. On a locked device the same
##  bytes produce boot state RED at the next boot and a device that will not
##  start, because an image whose hash does not match its signature is exactly
##  what Verified Boot exists to refuse.

##  On the next boot:
##    - AVB parses vbmeta, sees HASHTREE_DISABLED
##    - every AvbHashtreeDescriptor is IGNORED
##    - dm-verity is never set up for those partitions
##    - /system can now be modified without a per-block hash to violate
##
##  What it does NOT disable: the hash check on `boot`, and any chained vbmeta.
##  --disable-verification (bit 1) is the bigger hammer that disables those too.
##  "--disable-verity turns off Verified Boot" is a sentence to avoid.
```

## Session 6 — `fastboot boot`, the habit worth building

```
##  You typed:  fastboot boot patched-boot.img

H>  download:02000000
D>  DATA02000000
H>  <33,554,432 bytes -- the patched boot image>
D>  OKAY

H>  boot
D>  INFOBooting from RAM
D>  OKAY
##  The device boots from the download buffer. NOTHING IS WRITTEN TO FLASH.
##  Power-cycle and it comes back exactly as it was.
##
##  Compare the two failure modes:
##    `fastboot boot` on a wrong image  -> hold power for 10-20 s. Done.
##    `fastboot flash boot` on a wrong image -> a device that does not boot,
##       recoverable only via fastboot mode + the correct factory image + the
##       hardware key combination you hopefully wrote down.
##  Same information gained. Enormously different downside.

##  When your OEM has disabled it, which several have:
H>  boot
D>  FAILunknown command
##  On those devices there is no free test. Download the full stock factory
##  image FIRST, confirm the hardware key combination FIRST, then accept the
##  risk deliberately.
```

## Session 7 — the unlock, described and not performed

**This session was not executed.** It is here because the shape of the exchange is specified and
worth knowing, and because the interesting part is what the protocol *cannot* do on its own.

```
##  Precondition, established in Android and NOT in fastboot:
##    Settings -> About phone -> tap Build number x7
##    Settings -> System -> Developer options -> OEM unlocking -> ON
##    (requires unlocking the screen with the owner's credential)

H>  flashing get_unlock_ability
D>  INFOget_unlock_ability: 1
D>  OKAY
##  NOW it is 1. Nothing sent over fastboot could have changed this.

H>  flashing unlock
D>  INFOUnlocking bootloader...
##  The device now shows a CONFIRMATION SCREEN. Volume keys to select, power to
##  confirm. This is a HARDWARE-CONFIRMED action on purpose: it means a
##  malicious USB host cannot unlock a device silently, even one whose owner
##  enabled the toggle.
D>  INFOErasing userdata...
##  THE WIPE. Performed by the BOOTLOADER, not by Android, precisely so it
##  cannot be skipped by controlling Android. On a device with file-based
##  encryption the keys are destroyed too, making the erase cryptographic
##  rather than merely physical.
##
##  WHY: without the wipe, "unlock, flash a permissive boot image, read
##  everything" would be a one-command bypass of Android's entire data-at-rest
##  model for anyone holding the phone.
D>  OKAY

##  The device reboots and shows the setup wizard. Afterwards:
##    ro.boot.verifiedbootstate  -> orange
##    ro.boot.flash.locked       -> 0
##    key attestation deviceLocked -> false          <- the part that cannot be faked
##  and a warning screen appears for a few seconds at every boot.
```

> **⚠️ The relock trap**
> Going back is symmetric and also wipes — but the order matters and getting it wrong is how devices
> are lost. **Flash the full stock factory image, boot it, confirm it works, and only then
> `flashing lock`.** Relocking while a patched boot image is present gives a locked bootloader that
> refuses its own boot image, and it cannot be unlocked again because unlocking requires Android to
> set a flag and Android will not start.

---

## Summary — the whole protocol in one table

| Exchange | Host sends | Device replies | Notes |
|---|---|---|---|
| Query | `getvar:NAME` | `OKAY<value>` or `FAIL<reason>` | The only safe operation |
| Query all | `getvar:all` | `INFO<line>` × N, then `OKAY` | Not guaranteed complete |
| Download | `download:%08x` | `DATA%08x`, then host sends raw bytes, then `OKAY` | Only place bulk data moves |
| Act | `flash:PART` / `boot` / `erase:PART` | `INFO` × N, then `OKAY` or `FAIL` | Acts on the download buffer |
| Slots | `set_active:a` | `OKAY` | Reversible |
| Lock | `flashing unlock` / `lock` | `INFO`, hardware confirm, wipe, `OKAY` | Bootloader only, never `fastbootd` |
| Move | `reboot`, `reboot-bootloader`, `reboot-fastboot`, `continue` | `OKAY` | |

Five prefixes. Three legs. One shared buffer. That is the whole thing.

---

*Referenced by chapter 61 §7.4. See also [`measured-avd-boot-state.md`](measured-avd-boot-state.md)
for the measurements that are not reconstructed.*
