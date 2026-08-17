# Measured boot state — `sdk_gphone16k_x86_64`, Android 15 / API 35

Every raw measurement chapter 61 is built on, recorded verbatim with the command that produced it.
Nothing here is reconstructed, inferred or tidied. Where a command failed, the failure is recorded,
because a failure is a measurement.

**Device:** `emulator-5554`, AVD `Pixel_6_Pro_API_35`
`ro.product.model = sdk_gphone16k_x86_64`, `ro.product.device = emu64xa16k`
`ro.build.fingerprint = google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys`
x86_64, 16 KiB pages, rooted (`su 0 <cmd>` form — **not** `su -c`)

**Host:** Windows 11, `fastboot version 35.0.2-12147458`, `platform-tools` at
`C:\Program Files (x86)\platform-tools\`

> **The emulator has no bootloader.** Everything below is downstream of a boot that a virtual machine
> performed, not a bootloader. It is genuine data about Android's *view* of boot state, partitions
> and AVB, and it is not data about fastboot. See §6 of this file for the proof.

---

## 1. Boot / lock-state properties

```
$ adb shell getprop <name>

ro.product.model                           = sdk_gphone16k_x86_64
ro.build.version.sdk                       = 35
ro.build.version.release                   = 15
ro.product.cpu.abi                         = x86_64
ro.boot.verifiedbootstate                  =
ro.boot.flash.locked                       =
ro.boot.veritymode                         = enforcing
ro.boot.vbmeta.device_state                =
ro.boot.vbmeta.digest                      = 2c9cddc5782070a7bad50e8178173f45bc36ec4603add76004d09e3bfce71eea
ro.boot.vbmeta.avb_version                 =
ro.boot.vbmeta.size                        = 6784
ro.boot.vbmeta.hash_alg                    = sha256
ro.boot.vbmeta.invalidate_on_error         =
ro.oem_unlock_supported                    =
sys.oem_unlock_allowed                     =
ro.boot.slot_suffix                        =
ro.build.ab_update                         = false
ro.boot.dynamic_partitions                 = true
ro.boot.dynamic_partitions_retrofit        =
ro.boot.bootloader                         =
ro.bootloader                              = unknown
ro.boot.hardware                           = ranchu
ro.virtual_ab.enabled                      =
ro.virtual_ab.compression.enabled          =
ro.debuggable                              = 1
ro.secure                                  = 1
ro.build.type                              = userdebug
ro.boot.avb_version                        = 1.3
ro.boot.hardware.platform                  =
```

**What this shows.**

1. **`ro.boot.verifiedbootstate` is the empty string.** Not `orange`, not `green` — absent. An app
   written as `!"orange".equals(state)` returns `true` here, passing on the least trustworthy
   platform it could meet. See §2 for the cause.
2. **AVB metadata is partially present.** `vbmeta.digest`, `vbmeta.size`, `vbmeta.hash_alg` and
   `veritymode` are all set, while every *lock-state* property is empty. The emulator's virtual boot
   path reports what it verified and says nothing about a lock it does not have.
3. **Dynamic partitions without A/B.** `ro.boot.dynamic_partitions = true` and
   `ro.build.ab_update = false`, with `ro.boot.slot_suffix` empty. The two features are orthogonal;
   this is one of the four combinations you can meet.
4. **`ro.bootloader = unknown`.** Chapter 39 measured `Build.BOOTLOADER == "unknown"` on **both** the
   emulator and a retail Redmi, which is why it is useless as an emulator signal. Confirmed here.

## 2. Where those properties come from — `/proc/bootconfig`

```
$ adb shell 'cat /proc/cmdline'
cat: /proc/cmdline: Permission denied

$ adb shell 'cat /proc/bootconfig'
cat: /proc/bootconfig: Permission denied
```

Both are denied to the **shell** user on API 35 — which corroborates chapter 39's measurement that
`/proc/cmdline` is `EACCES` to an app as well. As root:

```
$ adb shell 'su 0 cat /proc/cmdline'
console=ttynull stack_depot_disable=on cgroup_disable=pressure bootconfig
8250.nr_uarts=1 clocksource=pit page_shift=14 no_timer_check console=0 ndns=2
loop.max_part=7 ramoops.mem_address=0xff018000 ramoops.mem_size=0x10000
memmap=0x10000$0xff018000 printk.devkmsg=on bootconfig ndns=2
mac80211_hwsim.radios=0
```

**No `androidboot.*` parameters at all on the cmdline.** The token `bootconfig` tells the kernel to
look elsewhere:

```
$ adb shell 'su 0 cat /proc/bootconfig'          # androidboot.* keys only, adb.pubkey elided
androidboot.qemu = "1"
androidboot.qemu.avd_name = "Pixel_6_Pro_API_35"
androidboot.hardware = "ranchu"
androidboot.hardware.vulkan = "ranchu"
androidboot.hardware.gltransport = "pipe"
androidboot.serialno = "EMULATOR35X3X11X0"
androidboot.veritymode = "enforcing"
androidboot.opengles.version = "196609"
androidboot.debug.hwui.renderer = "skiagl"
androidboot.logcat = "*:V"
androidboot.dalvik.vm.heapsize = "576m"
androidboot.vbmeta.size = "6784"
androidboot.vbmeta.hash_alg = "sha256"
androidboot.vbmeta.digest = "2c9cddc5782070a7bad50e8178173f45bc36ec4603add76004d09e3bfce71eea"
androidboot.boot_devices = "pci0000:00/0000:00:03.0 pci0000:00/0000:00:06.0"
```

**This is the causal explanation for §1, and it is exact.** `init` derives `ro.boot.X` from
`androidboot.X`. Every property that is set above appears here; every property that is empty is
**absent** here. There is no `androidboot.verifiedbootstate`, no `androidboot.flash.locked`, no
`androidboot.slot_suffix`, no `androidboot.vbmeta.device_state`.

A property is empty because nothing told `init` what to put in it. That is a different condition from
"the bootloader reported a bad state", and code that conflates the two gets the wrong answer.

## 3. Partition layout

```
$ adb shell 'su 0 ls -l /dev/block/by-name/'
total 0
lrwxrwxrwx 1 root root 15 metadata -> /dev/block/vdd1
lrwxrwxrwx 1 root root 15 super    -> /dev/block/vda2
lrwxrwxrwx 1 root root 15 vbmeta   -> /dev/block/vda1
lrwxrwxrwx 1 root root 14 vda      -> /dev/block/vda
lrwxrwxrwx 1 root root 14 vdd      -> /dev/block/vdd
```

**Five entries. No `boot`, no `init_boot`, no `recovery`, no `misc`, no `dtbo`, no `userdata`
by-name link.**

- No `misc` means no Bootloader Control Block — the mailbox `adb reboot bootloader` writes into.
- No `boot` means the kernel is not loaded from flash at all; QEMU supplies it.

These two absences are the mechanical reason for §6.

## 4. Device-mapper — the real stack

```
$ adb shell 'su 0 dmctl list devices'          # APEX entries removed for clarity
product              : 254:3
system               : 254:0
system-verity        : 254:5
system_dlkm          : 254:1
system_ext           : 254:2
userdata             : 254:45
vendor               : 254:4
```

```
$ adb shell 'su 0 dmctl table <name>'
system        0-1829440: linear, 253:2 2048
system_dlkm   0-  14088: linear, 253:2 1832960
system_ext    0- 425232: linear, 253:2 1847296
product       0-4189224: linear, 253:2 2273280
vendor        0- 217800: linear, 253:2 6463488

system-verity 0-1800416: verity, 1 254:0 254:0 4096 4096 225052 225052 sha256 \
              d7b94a2a42e4648f6f87c80f2e4ab7b8f7b41a50612b7320504363134315363f \
              34f93a31db2a530c5ec009dee328bcad680cfda410ff4799f39ab2b6d4b7bc09 \
              10 restart_on_corruption ignore_zero_blocks use_fec_from_device 254:0 \
              fec_blocks 226826 fec_start 226826 fec_roots 2
```

```
$ adb shell 'su 0 grep -E " (/|/vendor|/product|/system_ext|/metadata) " /proc/mounts'
/dev/block/dm-5 /            ext4 ro,seclabel,relatime 0 0
/dev/block/vdd1 /metadata    ext4 rw,seclabel,nosuid,nodev,noatime 0 0
/dev/block/dm-4 /vendor      ext4 ro,seclabel,relatime 0 0
/dev/block/dm-3 /product     ext4 ro,seclabel,relatime 0 0
/dev/block/dm-2 /system_ext  ext4 ro,seclabel,relatime 0 0
```

### The `super` extent map, and the 1 MiB alignment

`253:2` is `vda2`, which is `super`. Both numbers in a linear target are 512-byte sectors — length
first, then offset.

| Logical partition | Start sector | Length | Start ÷ 2048 | Ends at |
|---|---:|---:|---:|---:|
| `system` | 2,048 | 1,829,440 | **1** | 1,831,488 |
| `system_dlkm` | 1,832,960 | 14,088 | **895** | 1,847,048 |
| `system_ext` | 1,847,296 | 425,232 | **902** | 2,272,528 |
| `product` | 2,273,280 | 4,189,224 | **1,110** | 6,462,504 |
| `vendor` | 6,463,488 | 217,800 | **3,156** | 6,681,288 |

**Every start offset is an exact multiple of 2,048 sectors = 1 MiB.** That is `liblp`'s default
partition alignment, observed in real data rather than quoted from a header. It also explains the
gaps — `system` ends at 1,831,488 and `system_dlkm` starts at 1,832,960, wasting 1,472 sectors purely
to reach the boundary.

**Consequence:** a `super` image rebuilt by concatenating partition images without reproducing this
alignment will flash and will not boot.

### The four-layer stack for `/`

```
vda2 (physical "super")
  -> dm-0 "system"        linear, offset 2048, length 1829440
     -> dm-5 "system-verity"  verity, sha256, FEC roots 2, restart_on_corruption
        -> mounted at "/" as read-only ext4
```

`system-verity` is 1,800,416 sectors = 225,052 × 8, matching the `num_data_blocks` field in its own
table. Data device and hash device are both `254:0`: the hash tree lives inside `system` itself,
after the data.

**`/vendor`, `/product` and `/system_ext` have no verity layer** — they mount `dm-4`, `dm-3` and
`dm-2`, which are the plain linear targets. See §5 for why that is notable.

### `lpdump` disagrees with the kernel

```
$ adb shell 'su 0 lpdump'
Failed to read metadata.

$ adb shell 'su 0 lpdump /dev/block/by-name/super'
Failed to read metadata.
```

Root, both invocations, both fail — while `dmctl table` produces a complete and internally consistent
extent map. **When they disagree, believe the kernel.** `dmctl` reports what is actually serving
reads; `lpdump` reports a description of it. Cause of the `lpdump` failure was not determined and is
not guessed at here.

## 5. The real `vbmeta`, parsed

Pulled with:

```
$ adb shell 'su 0 dd if=/dev/block/by-name/vbmeta bs=1 count=6784 2>/dev/null | base64' \
    | base64 -d > vbmeta.img          # 6784 bytes, matching ro.boot.vbmeta.size
```

### Header

```
magic                     AVB0
required libavb version   1.0
authentication block      576 bytes
auxiliary block           4224 bytes
algorithm_type            2  (SHA256_RSA4096)
hash_offset / size        0 / 32
signature_offset / size   32 / 512
public_key_offset / size  3176 / 1032
descriptors_offset / size 0 / 3176
rollback_index            0
flags                     0x00000000
rollback_index_location   0
release_string            'avbtool 1.3.0'
```

### The integrity invariant, recomputed

```
stored hash (bytes 256..288)                 93dfae214512fd0b4109c245337a01e885809c29b6c6388d117d16a5cabe3b7b
sha256(header[0:256] || aux_block[832:5056]) 93dfae214512fd0b4109c245337a01e885809c29b6c6388d117d16a5cabe3b7b
                                             MATCH
```

Recomputing AVB's own hash and getting the stored value back is the proof that the parse is correct.
Now flip the `--disable-verity` bit:

```
flags field at offset 120..124 = 00000000

--disable-verity         -> flags=0x00000001   bytes changed: [123]
--disable-verification   -> flags=0x00000002   bytes changed: [123]
both                     -> flags=0x00000003   bytes changed: [123]

after --disable-verity, recomputed hash:
  3695fea807c912e3c0c7c265282055ae5d14c3f1b8594bbcd6f40e83b3e68371
  NO MATCH
```

**One byte, at offset 123, and it breaks the image's own integrity check.** The flags field sits
inside the region AVB hashes, so setting it invalidates the hash and therefore the signature over it.
`fastboot --disable-verity` is not a supported option AVB honours; it is a deliberate corruption that
only an unlocked bootloader will accept. Reproduce with:

```
$ python3 -B ../scripts/vbmeta-flags.py show vbmeta.img
$ python3 -B ../scripts/vbmeta-flags.py set vbmeta.img out.img --disable-verity
```

### Descriptors

```
CHAIN     system       rollback_index_location=1, public key 520 bytes
HASH      vendor_boot  image_size=98304        sha256   digest 56bc7759...
HASHTREE  product      image_size=2110955520   4 KiB blocks, FEC roots 2, root 631fe73e...
HASHTREE  system_dlkm  image_size=6995968      root 63435809...
HASHTREE  system_ext   image_size=214192128    root 12621635...
HASHTREE  vendor       image_size=109670400    root 9ff33e47...
```

Two things worth noting.

**`system` is not verified by this vbmeta at all** — it is delegated by an `AvbChainPartitionDescriptor`
to a separate 520-byte public key with rollback index location 1. Its hashtree descriptor lives in a
chained vbmeta. That matches §4: `system` is the one partition with a live verity device.

**Four hashtree descriptors exist for partitions that have no verity mapping.** `product`,
`system_dlkm`, `system_ext` and `vendor` are all described here and all mount their plain linear
targets. **Descriptors present is not the same as verity enforced.** The cause was not determined —
it may be an emulator-specific first-stage-init path — and is recorded as an observation, not a
conclusion. It is a useful caution for anyone inferring runtime protection from an image.

## 6. The emulator has no bootloader — the proof

```
$ adb reboot bootloader
rc=0

$ fastboot devices        # t = +6 s
                          # no output, exit 0
$ adb devices             # t = +6 s
emulator-5554   offline

# polled every 10 seconds:
t=10s   fastboot: (nothing)   adb: emulator-5554 offline
t=20s   fastboot: (nothing)   adb: emulator-5554 offline
t=30s   fastboot: (nothing)   adb: emulator-5554 offline
t=40s   fastboot: (nothing)   adb: emulator-5554 device      <- back in Android
t=50s   fastboot: (nothing)   adb: emulator-5554 device
t=60s   fastboot: (nothing)   adb: emulator-5554 device
```

`adb reboot fastboot` behaved identically. **`fastboot devices` never saw the device at any point.**

Three independent structural confirmations from the same session:

```
$ adb shell 'su 0 ls /dev/block/by-name/misc'
ls: /dev/block/by-name/misc: No such file or directory      <- no BCB mailbox

$ adb shell 'su 0 bootctl get-number-slots'
Failed to get bootctl module.                               <- no boot control HAL

$ adb shell 'su 0 lshal | grep -i boot'
                                                            <- nothing
```

**Conclusion: nothing about fastboot can be learned on an emulator.** Everything else in this file is
still valid data about Android's view of boot state, partitions and AVB — which is why the file
exists.

## 7. Host-side measurements

```
$ fastboot --version
fastboot version 35.0.2-12147458
Installed as C:\Program Files (x86)\platform-tools\fastboot.exe

$ fastboot devices        # with no fastboot-mode device attached
                          # no output
$ echo $?
0                         # SILENT SUCCESS -- not an error. Easy to misread.

$ fastboot getvar product # with no device attached
< waiting for any device >
                          # blocks indefinitely; killed at 10 s
```

`getvar` names extracted from `fastboot.exe` (14 unique):

```
current-slot            max-download-size       slot-count
erase-block-size        partition-size:         snapshot-update-status
has-slot:               partition-type:         super-partition-name
is-logical:             product                 version
is-userspace            logical-block-size      version-baseband
                                                version-bootloader
```

All five protocol response prefixes present as standalone strings:

```
OKAY   FAIL   DATA   INFO   TEXT
```

The vbmeta rewriting log line, which confirms the mechanism in §5 from the vendor's own binary:

```
Rewriting vbmeta struct at offset: %lld
```

And the filesystem builders `fastboot format` shells out to — confirming that `format` runs on the
host, not the device:

```
/mke2fs
/make_f2fs
/mke2fs.conf
MKE2FS_CONFIG=

present in platform-tools:  mke2fs.exe  mke2fs.conf  make_f2fs.exe  make_f2fs_casefold.exe
```

---

## 8. What was deliberately NOT run

No destructive fastboot command was executed against any device while producing this file, and no
physical device was rebooted into a bootloader. The only physical arm64 devices available are a
daily-driver phone and a borrowed handset; `fastboot flashing unlock` would factory-reset the first
one.

| Not run | Reason |
|---|---|
| `fastboot flashing unlock` / `lock` | Factory-resets the device |
| `fastboot flash` / `erase` / `format` | Destroys a partition |
| `fastboot boot` | Requires a bootloader-mode device |
| `adb reboot bootloader` on a phone | Entering fastboot mode is a state change on someone's daily driver |
| `fuzzy_fastboot` | Requires a device in fastboot mode |
| `scripts/bootprop-observer.js` against a live process | The `frida-server` on the AVD fails to load on API 35: `CANNOT LINK EXECUTABLE ... empty/missing DT_HASH/DT_GNU_HASH ... (new hash type from the future?)`. Script parses clean under `node --check`; it is reviewed and unrun |

Every behaviour those commands would produce is described in the chapter from the protocol
specification, AOSP source, and the host tool's own strings and help output — and labelled as such
where it appears.

## 9. Device hygiene

`/data/local/tmp` on this AVD was found to contain `frida-server` plus a set of `ch59_*` and
`ch59v_*` binaries left by another chapter's work. **Nothing was deleted** — they are not this
chapter's residue and are plausibly another session's live workspace.

**This chapter wrote nothing to the device.** Every measurement above is a read. The only state
change made anywhere was `chmod 755` on the existing `/data/local/tmp/frida-server`, in an attempt to
start it that failed at link time.

---

*Referenced by chapter 61 §1.5, §3.7, §3.8, §5.3, §7.1 and §7.6.*
