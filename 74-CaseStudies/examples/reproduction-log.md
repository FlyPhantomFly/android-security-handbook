# Reproduction log — raw commands and raw output

Every measured claim in [chapter 74](../README.md) is traceable to a block in this file. Nothing here
is edited except to strip carriage returns and to elide one long base64 blob, both of which are
marked where they occur.

This is the artefact that makes the chapter checkable. A case study that quotes numbers without one
of these is asking to be believed rather than verified.

---

## 0. Session facts, recorded before anything else

Recorded first because every claim below is a claim about them. This is 68's Q1 — *ask about your
instrument before your target* — and it is not optional.

```bash
# host -- Windows 11, Git Bash, 2026-08-16
$ adb devices -l
List of devices attached
emulator-5554  device product:sdk_gphone16k_x86_64 model:sdk_gphone16k_x86_64 \
               device:emu64xa16k transport_id:2

$ adb -s emulator-5554 shell getprop ro.product.model
sdk_gphone16k_x86_64

$ adb -s emulator-5554 shell getprop ro.build.version.sdk
35

$ adb -s emulator-5554 shell getprop ro.build.version.release
15

$ adb -s emulator-5554 shell getprop ro.build.fingerprint
google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys
```

| | |
|---|---|
| Devices attached | **One.** `emulator-5554` only |
| Device | AVD `sdk_gphone16k_x86_64` (`emu64xa16k`), AVD name `Pixel_6_Pro_API_35` |
| OS | Android 15 / API 35, `x86_64`, 16 KiB pages, `userdebug` / `dev-keys` |
| Root | Magisk **30.7** (`30700`), binary at `/debug_ramdisk/magisk`, **Zygisk OFF** |
| Host toolchain | NDK 25.2.9519653, Python 3, Git Bash |
| Date | 2026-08-16 |

> **The physical phones referenced in the chapter — the Redmi `M2101K6P` (API 30) and the `i9000S`
> (API 33) — were NOT attached during this session.** Every claim in chapter 74 attributed to those
> devices is transcribed from the chapter that measured it and is labelled as such. Nothing about
> them was re-run here. Recording a device you did *not* use is as important as recording one you
> did.

### 0.1 The root convention

```bash
$ adb -s emulator-5554 shell "su -c id"
su: invalid uid/gid '-c'

$ adb -s emulator-5554 shell "su 0 id"
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),
1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),3003(inet),
3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs) context=u:r:su:s0
```

**This AVD takes `su 0 <cmd>`, not `su -c <cmd>`.** The `-c` form fails in a way that reads exactly
like an unrooted device. This is the fourth chapter in this repository to hit it; treat it as a
standing fact about the emulator.

### 0.2 The app vantage

```bash
$ adb -s emulator-5554 shell "pm list packages -3"
package:org.android.cmpen
package:com.topjohnwu.magisk
package:com.vendor.learning
package:com.devuser.helloworld

$ adb -s emulator-5554 shell "run-as com.devuser.helloworld id"
uid=10207(u0_a207) gid=10207(u0_a207) groups=10207(u0_a207),1004(input),1007(log),1011(adb),
1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),
3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid),3012(readtracefs),50207(all_a207)
context=u:r:runas_app:s0:c207,c256,c512,c768

$ adb -s emulator-5554 shell "run-as org.android.cmpen id"
run-as: package not debuggable: org.android.cmpen
```

One of the four third-party packages is debuggable. **The domain is `runas_app`, not
`untrusted_app`** — carried as a caveat on every "app" row below. See chapter 74 §7.5 for which
conclusions survive that and which do not.

> **Incidental corroboration, free.** The MCS label is `c207,c256,c512,c768`. Chapter 21/22's formula
> says an app's first pair is `c[appId & 0xff]` and `c[256 + (appId >> 8)]`; appId 207 gives `c207`
> and `c256`, which is exactly what is printed. The second pair `c512,c768` is the user-id encoding
> chapter 54 identified. Two chapters' arithmetic confirmed by a command run for another reason.

---

## 1. Case A — the boot-state property

Chapter 74 §3.1.5. Original measurement: [61-Fastboot §5.3](../../61-Fastboot/README.md).

### 1.1 The properties

```bash
$ adb -s emulator-5554 shell "getprop ro.boot.verifiedbootstate" | cat -A
^M$

$ adb -s emulator-5554 shell "getprop ro.boot.flash.locked" | cat -A
^M$

$ adb -s emulator-5554 shell "getprop ro.boot.vbmeta.device_state" | cat -A
^M$

$ adb -s emulator-5554 shell "getprop ro.boot.veritymode"
enforcing

$ adb -s emulator-5554 shell "getprop ro.boot.vbmeta.digest"
2c9cddc5782070a7bad50e8178173f45bc36ec4603add76004d09e3bfce71eea
```

`cat -A` is used deliberately on the three empty ones. Without it, "the property is empty" and "the
command printed nothing because it failed" look identical on a terminal. The output shown is a
carriage return and a line terminator and nothing else — the property is genuinely the empty string,
and the command genuinely ran.

**Verdict: REPRODUCED.** Matches 61's recorded values exactly.

**Consequence:** `!"orange".equals("")` evaluates to `true`. The most-copied verified-boot check in
existence passes on this device.

### 1.2 The cause — `/proc/bootconfig`

```bash
# as shell (uid 2000)
$ adb -s emulator-5554 shell "cat /proc/bootconfig"
cat: /proc/bootconfig: Permission denied

$ adb -s emulator-5554 shell "cat /proc/cmdline"
cat: /proc/cmdline: Permission denied

# as root
$ adb -s emulator-5554 shell "su 0 cat /proc/bootconfig"
androidboot.qemu = "1"
androidboot.qemu.cpuvulkan.version = "4202496"
androidboot.qemu.settings.system.screen_off_timeout = "2147483647"
androidboot.qemu.vsync = "60"
androidboot.qemu.gltransport.name = "pipe"
androidboot.qemu.gltransport.drawFlushInterval = "800"
androidboot.qemu.adb.pubkey = "QAAAAEtv9yCd3Wdygok...[ELIDED -- 700+ base64 chars]... @unknown"
androidboot.qemu.camera_protocol_ver = "1"
androidboot.qemu.camera_hq_edge_processing = "0"
androidboot.qemu.virtiowifi = "1"
androidboot.qemu.hwcodec.avcdec = "2"
androidboot.qemu.hwcodec.hevcdec = "2"
androidboot.qemu.hwcodec.vpxdec = "2"
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

Only the `adb.pubkey` value is elided, and only for length.

**Explicit absence check**, so that "I did not see it" and "it is not there" are different statements:

```bash
$ for k in androidboot.verifiedbootstate androidboot.flash.locked \
           androidboot.vbmeta.device_state androidboot.slot_suffix \
           androidboot.veritymode androidboot.vbmeta.digest; do
    n=$(adb -s emulator-5554 shell "su 0 cat /proc/bootconfig" | grep -c "^$k")
    echo "$k -> $n"
  done
androidboot.verifiedbootstate -> 0
androidboot.flash.locked -> 0
androidboot.vbmeta.device_state -> 0
androidboot.slot_suffix -> 0
androidboot.veritymode -> 1
androidboot.vbmeta.digest -> 1
```

### 1.3 The two findings the original write-up does not have

**(a) The derivation is proven positively, not only negatively.**

| | Value |
|---|---|
| `androidboot.vbmeta.digest` (bootconfig) | `2c9cddc5782070a7bad50e8178173f45bc36ec4603add76004d09e3bfce71eea` |
| `ro.boot.vbmeta.digest` (property) | `2c9cddc5782070a7bad50e8178173f45bc36ec4603add76004d09e3bfce71eea` |

Byte-identical. Combined with the four absent keys producing four empty properties, the rule
*`ro.boot.X` is empty exactly when `androidboot.X` is absent* is demonstrated in both directions on
one device in one session. 61 had the negative half.

**(b) The cross-check is root-only.** `/proc/bootconfig` and `/proc/cmdline` both return
`Permission denied` to uid 2000, and therefore to any application. **The comparison that catches a
forged property cannot be performed by the process doing the checking.** That is the structural
argument, and it needed a measurement.

### 1.4 The kernel command line, for completeness

```bash
$ adb -s emulator-5554 shell "su 0 cat /proc/cmdline"
console=ttynull stack_depot_disable=on cgroup_disable=pressure bootconfig 8250.nr_uarts=1
clocksource=pit page_shift=14 no_timer_check console=0 ndns=2 loop.max_part=7
ramoops.mem_address=0xff018000 ramoops.mem_size=0x10000 memmap=0x10000$0xff018000
printk.devkmsg=on bootconfig ndns=2 mac80211_hwsim.radios=0
```

**No `androidboot.*` parameters at all** on this device's command line. The bare token `bootconfig`
tells the kernel to look elsewhere, which is where the previous section read them from. Note
`page_shift=14`, which is the 16 KiB page size this repository has tripped over twice.

---

## 2. Case D — the three-vantage file probe

Chapter 74 §3.4.2. Original: [63-LSPosed](../../63-LSPosed/README.md) lab-01,
[37-RootDetection](../../37-RootDetection/README.md), [64-Xposed](../../64-Xposed/README.md).

```bash
$ PKG=com.devuser.helloworld
$ for path in /data/adb /data/adb/lspd /data/adb/modules /system/xbin/su \
              /debug_ramdisk /debug_ramdisk/magisk; do
    echo "$path"
    echo "  root : $(adb -s emulator-5554 shell "su 0 ls -ld $path" 2>&1)"
    echo "  shell: $(adb -s emulator-5554 shell "ls -ld $path" 2>&1)"
    echo "  app  : $(adb -s emulator-5554 shell "run-as $PKG ls -ld $path" 2>&1)"
  done
```

```
/data/adb
  root : drwx------ 6 root root 4096 2026-08-16 00:27 /data/adb
  shell: ls: /data/adb: Permission denied
  app  : ls: /data/adb: Permission denied
/data/adb/lspd
  root : ls: /data/adb/lspd: No such file or directory
  shell: ls: /data/adb/lspd: Permission denied
  app  : ls: /data/adb/lspd: Permission denied
/data/adb/modules
  root : drwxr-xr-x 2 root root 4096 2026-07-23 13:18 /data/adb/modules
  shell: ls: /data/adb/modules: Permission denied
  app  : ls: /data/adb/modules: Permission denied
/system/xbin/su
  root : -rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su
  shell: -rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su
  app  : ls: /system/xbin/su: Permission denied
/debug_ramdisk
  root : drwx--x--x 3 root root 160 2026-08-16 00:25 /debug_ramdisk
  shell: drwx--x--x 3 root root 160 2026-08-16 00:25 /debug_ramdisk
  app  : drwx--x--x 3 root root 160 2026-08-16 00:25 /debug_ramdisk
/debug_ramdisk/magisk
  root : -rwxr-xr-x 1 root root 428416 2026-08-16 00:25 /debug_ramdisk/magisk
  shell: -rwxr-xr-x 1 root root 428416 2026-08-16 00:25 /debug_ramdisk/magisk
  app  : -rwxr-xr-x 1 root root 428416 2026-08-16 00:25 /debug_ramdisk/magisk
```

**Verdict: REPRODUCED**, row for row, against 63's lab-01 table.

`/data/adb` is `drwx------` — mode 0700, `root:root`. The refusal happens there, above every leaf
beneath it. `File.exists()` returns `false` for `/data/adb/lspd` (genuinely absent),
`/data/adb/modules` (present and forbidden) and `/system/xbin/su` from the app (present, setuid root,
and forbidden) — three different realities, one return value.

### 2.1 Which `su` actually grants root

```bash
$ for p in /system/xbin/su /system/bin/su /sbin/su /debug_ramdisk/su /data/adb/magisk/magisk; do
    echo -n "$p -> "
    adb -s emulator-5554 shell "su 0 sh -c 'if [ -e $p ]; then echo PRESENT; else echo ENOENT; fi'"
  done
/system/xbin/su -> PRESENT
/system/bin/su -> ENOENT
/sbin/su -> ENOENT
/debug_ramdisk/su -> PRESENT
/data/adb/magisk/magisk -> ENOENT
```

```bash
$ adb -s emulator-5554 shell "su 0 /debug_ramdisk/magisk -v"
30.7:MAGISK:R
$ adb -s emulator-5554 shell "su 0 /debug_ramdisk/magisk -V"
30700
$ adb -s emulator-5554 shell "su 0 sh -c 'grep -c zygisk /proc/\$(pidof zygote64)/maps'"
0
```

The file the classic probe finds (`/system/xbin/su`, AOSP's, shipped by every `userdebug` build) and
the mechanism actually granting root (`/debug_ramdisk/su`, Magisk 30.7) are **two different binaries
in two different places**. The probe finds only the harmless one, and only from the shell.

Zygisk is confirmed off by the second of the two independent checks 63 insists on: no `zygisk`
mapping in `zygote64`. An absent settings row would mean "default", not "off"; the maps are the
evidence.

### 2.2 Stat versus list — the 0711 case

```bash
$ adb -s emulator-5554 shell "run-as $PKG head -c 4 /debug_ramdisk/magisk" | od -c | head -1
0000000 177   E   L   F

$ adb -s emulator-5554 shell "run-as $PKG ls /debug_ramdisk"
ls: /debug_ramdisk: Permission denied
$ adb -s emulator-5554 shell "ls /debug_ramdisk"
ls: /debug_ramdisk: Permission denied
$ adb -s emulator-5554 shell "su 0 ls /debug_ramdisk"
magisk
magiskinit
resetprop
su
supolicy
```

Mode 0711 means traverse, do not list. **An application read the ELF header of `/debug_ramdisk/magisk`
while being refused a listing of the directory containing it.** Path-guessing beats directory
listing. **REPRODUCED** against 63.

### 2.3 The `mountinfo` signal — and a correction

```bash
$ adb -s emulator-5554 shell "run-as $PKG grep -c magisk /proc/self/mountinfo"
3
$ adb -s emulator-5554 shell "run-as $PKG grep -c ' magisk ' /proc/self/mountinfo"
2

$ adb -s emulator-5554 shell "su 0 grep magisk /proc/self/mountinfo"
56 42 0:20 / /debug_ramdisk rw,relatime shared:13 - tmpfs magisk rw,seclabel,mode=755
57 56 0:26 / /debug_ramdisk/.magisk/worker rw,relatime shared:14 - tmpfs magisk rw,seclabel,mode=755
58 56 0:27 / /debug_ramdisk/.magisk/pts rw,nosuid,noexec,relatime shared:15 - devpts devpts \
   rw,seclabel,mode=600,ptmxmode=000
```

Identical counts from root, `shell` and the app uid — the signal needs no privilege, which is 63's
point and it stands.

**But: only TWO of the three lines have `magisk` as the mount source.** Line 58's source is
`devpts`; the token appears there as part of the mount *point path* `/debug_ramdisk/.magisk/pts`.

> **Verdict: DIVERGED on the count, REPRODUCED on the conclusion.**
> 63 records "3 lines whose mount source is literally `magisk`". By source it is two; by substring it
> is three. The signal is real and the conclusion is unaffected — but the discrepancy has exactly the
> shape of case F, where a substring matched something other than what the sentence claimed. Quote it
> as *"two `magisk`-sourced mounts, three lines mentioning `magisk`"* and the ambiguity disappears.

---

## 3. Case E — property visibility by vantage

Chapter 74 §3.5. This is the section that produced a new finding.

### 3.1 The documented command, run verbatim

Chapter 39's `references/README.md` records the method as
`adb shell "getprop | wc -l"` versus the same under `run-as`.

```bash
$ adb -s emulator-5554 shell "getprop | wc -l"
673
$ adb -s emulator-5554 shell "run-as $PKG sh -c 'getprop | wc -l'"
633
$ adb -s emulator-5554 shell "su 0 sh -c 'getprop | wc -l'"
1055
```

Three consecutive repetitions, to rule out sampling noise:

```
run 1: shell=673 app=633 root=1055
run 2: shell=673 app=633 root=1055
run 3: shell=673 app=633 root=1055
```

Counting unique property *names* rather than output lines, which is immune to multi-line values:

```
unique names: shell=670  app=633  root=1052
```

| Vantage | Measured here | Chapter 39 records | Gap |
|---|---|---|---|
| root | **1055** / 1052 names | — | — |
| `shell` | **673** / 670 names | **1053** (labelled *shell*) | **−380** |
| app | **633** / 633 names | **634** (labelled *app*) | −1 |

> **Verdict: DIVERGED — cause not established.**
> The published shell figure reproduces as the **root** figure to within two lines; the published app
> figure reproduces to within one. The most economical explanation is that the shell leg was taken
> through `su`. **That is not proven.** One device, one session, one arithmetic coincidence. The
> alternative — that this AVD's shell-visible set shrank by 380 while its app-visible set moved by
> one — is unlikely, not impossible. Chapter 39 has not been edited on the strength of this.

### 3.1a What drift actually looks like — measured by accident, hours later

The `--props` mode of [`vantage-diff.sh`](../scripts/vantage-diff.sh) was exercised a few hours after
the numbers above were taken, on the same device in the same session. Other work on this machine had
installed several packages in the interval:

| Vantage | Earlier | Later | Change |
|---|---|---|---|
| root | 1052 | **1059** | +7 |
| `shell` | 670 | **675** | +5 |
| app | 633 | **638** | +5 |

**All three columns moved together, by a similar small amount, in the same direction.** That is what
drift on a live device looks like, and it is a genuinely useful control that arrived for free.

It is also the strongest available argument against the "close enough, the device changed" escape
hatch in §3.1. Drift is *proportional and correlated*. A shift of 380 in one column while its partner
moves by 1 is not a bigger version of the table above — it is a different phenomenon, and it points
at the method rather than at the device.

**Note the consequence for this file's own numbers:** every count here is timestamped, not stable.
Quote them with the date attached, exactly as chapter 29 does for its broadcast-registration
snapshots, which varied 1,151 / 1,281 / 1,290 across three readings of one idle device. The *gaps*
between vantages are the durable result; the absolute counts are not.

### 3.2 The better measurement — names, not counts

```bash
$ adb -s emulator-5554 shell "getprop"             | sed -n 's/^\[\([^]]*\)\].*/\1/p' | sort -u > shell.txt
$ adb -s emulator-5554 shell "run-as $PKG getprop" | sed -n 's/^\[\([^]]*\)\].*/\1/p' | sort -u > app.txt
$ comm -23 shell.txt app.txt | wc -l     # shell-only
37
$ comm -13 shell.txt app.txt | wc -l     # app-only
0
```

Zero app-only names confirms the app's view is a strict subset of the shell's — a free correctness
control on the whole measurement. The 37:

```
logd.logpersistd.enable          ro.bootimage.build.id
odsign.key.done                  ro.bootimage.build.tags
odsign.verification.done         ro.bootimage.build.type
odsign.verification.success      ro.bootimage.build.version.incremental
partition.system.verified        ro.bootimage.build.version.release
partition.system.verified.hash_alg     ro.bootimage.build.version.release_or_codename
partition.system.verified.root_digest  ro.bootimage.build.version.sdk
persist.sys.boot.reason          ro.debuggable
persist.sys.boot.reason.history  ro.product.bootimage.brand
persist.traced.enable            ro.product.bootimage.device
qemu.sf.lcd_density              ro.product.bootimage.manufacturer
remote_provisioning.hostname     ro.product.bootimage.model
ro.boot.bootreason               ro.product.bootimage.name
ro.boot.serialno                 ro.secure
ro.bootimage.build.date          ro.serialno
ro.bootimage.build.date.utc      ro.vendor.build.security_patch
ro.bootimage.build.fingerprint   sys.boot.reason
                                 sys.boot.reason.last
                                 sys.init.perf_lsm_hooks
                                 sys.lpdumpd
```

### 3.3 The ones that matter, per vantage

```bash
$ for p in ro.debuggable ro.secure partition.system.verified ro.serialno \
           qemu.sf.lcd_density ro.build.tags ro.build.type \
           ro.boottime.qemu-props ro.boottime.ranchu-net ro.boottime.goldfish-logcat; do
    r=$(adb -s emulator-5554 shell "su 0 getprop $p")
    s=$(adb -s emulator-5554 shell "getprop $p")
    a=$(adb -s emulator-5554 shell "run-as $PKG getprop $p")
    printf '%-32s | %-18s | %-18s | %s\n' "$p" "${r:-(empty)}" "${s:-(empty)}" "${a:-(empty)}"
  done
```

```
prop                             | root               | shell              | app
ro.debuggable                    | 1                  | 1                  | (empty)
ro.secure                        | 1                  | 1                  | (empty)
partition.system.verified        | 2                  | 2                  | (empty)
ro.serialno                      | EMULATOR35X3X11X0  | EMULATOR35X3X11X0  | (empty)
qemu.sf.lcd_density              | 560                | 560                | (empty)
ro.build.tags                    | dev-keys           | dev-keys           | dev-keys
ro.build.type                    | userdebug          | userdebug          | userdebug
ro.boottime.qemu-props           | 11456737100        | (empty)            | (empty)
ro.boottime.ranchu-net           | 26535918900        | (empty)            | (empty)
ro.boottime.goldfish-logcat      | 31008210300        | (empty)            | (empty)
```

```bash
$ for p in ro.debuggable ro.secure partition.system.verified ro.serialno qemu.sf.lcd_density; do
    echo -n "$p  "; adb -s emulator-5554 shell "getprop -Z $p"
  done
ro.debuggable              u:object_r:userdebug_or_eng_prop:s0
ro.secure                  u:object_r:userdebug_or_eng_prop:s0
partition.system.verified  u:object_r:verity_status_prop:s0
ro.serialno                u:object_r:serialno_prop:s0
qemu.sf.lcd_density        u:object_r:qemu_sf_lcd_density_prop:s0
```

Two findings, and the second is a second divergence from chapter 39:

**(a) Three standard integrity properties are invisible to an application.** `ro.debuggable`,
`ro.secure` and `partition.system.verified` all read as the empty string from the app uid, while
`ro.debuggable` is genuinely `1` on this `userdebug` build. A check written the usual way —
`"1".equals(SystemProperties.get("ro.debuggable"))` — concludes the device is fine, on a device where
it is not. **The check fails open, silently, on the only vantage that counts.**

Note the contrast in the same table: `ro.build.tags` reads `dev-keys` from all three vantages. So
*some* integrity signals are readable by the app and some are not, and which is which is not
guessable — it has to be measured.

**(b) The `ro.boottime.*` family is invisible to `shell` as well as to the app.** Chapter 39 describes
it as "a goldmine from `adb shell`, unreachable from the app being assessed". Measured here, all
three are empty to `shell` and populated only under root. **It is a goldmine from root**, and root is
not a vantage any assessment target occupies. The direction of 39's conclusion is right; the vantage
attached to it is one rung off.

> **Verdict: DIVERGED on both.** Same caveat as §3.1 — one device, one session. Recorded here, raised
> in chapter 74 §3.5, and chapter 39 left unedited.

---

## 4. Case C — the compiler, rebuilt from scratch

Chapter 74 §3.3.3. Fixture: [`fold.c`](fold.c), written for this chapter. Original measurement:
[59-radare2 §3.8](../../59-radare2/README.md).

```bash
# host -- NDK 25.2.9519653, building OUTSIDE the repository
$ CC="$NDK/aarch64-linux-android21-clang"
$ "$CC" -Wall -Wextra -O0 -fPIC -shared -o "$OUT/fold-O0.so" examples/fold.c
$ "$CC" -Wall -Wextra -O2 -fPIC -shared -o "$OUT/fold-O2.so" examples/fold.c
# both compile clean; no warnings under -Wall -Wextra
```

```bash
$ llvm-strings -n 4 "$OUT/fold-O0.so" | grep xbin
(nothing)

$ llvm-strings -n 4 "$OUT/fold-O2.so" | grep xbin
/system/xbin/su
```

**Identical source. The `-O2` build ships the plaintext the `-O0` build hid. REPRODUCED** against
59's result, on an independently written fixture.

### 4.1 The mechanism — going one rung down

`strings` is a summary of `.rodata`. When the summary surprised us, we read the thing it summarises.

```bash
$ llvm-objdump -s -j .rodata "$OUT/fold-O0.so"
 0498 88d4ded4 d3c2ca88 dfc5cec9 88d4d225  ...............%
 04a8 730a00                               s..

$ llvm-objdump -s -j .rodata "$OUT/fold-O2.so"
 04a0 2f737973 74656d2f 7862696e 2f737500  /system/xbin/su.
```

At `-O0` the ciphertext is present, exactly as written in the source. At `-O2` **the ciphertext is
gone and the plaintext is there.** The array was not merely decoded — it was deleted, as dead, once
nothing referenced it.

### 4.2 The refutation — `noinline` was honoured and bought nothing

```bash
$ llvm-objdump -d --disassemble-symbols=decode "$OUT/fold-O0.so" | grep -cE '^\s+[0-9a-f]+:'
31
$ llvm-objdump -d --disassemble-symbols=decode "$OUT/fold-O2.so" | grep -cE '^\s+[0-9a-f]+:'
4

$ llvm-objdump -d --disassemble-symbols=decode "$OUT/fold-O2.so"
0000000000001640 <decode>:
    1640: e8 ff ff f0   adrp  x8, 0x0
    1644: 00 29 c1 3d   ldr   q0, [x8, #1184]
    1648: 00 00 80 3d   str   q0, [x0]
    164c: c0 03 5f d6   ret

$ llvm-objdump -d --disassemble-symbols=main "$OUT/fold-O2.so"
0000000000001614 <main>:
    1614: ff c3 00 d1   sub   sp, sp, #48
    1618: fd 7b 02 a9   stp   x29, x30, [sp, #32]
    161c: fd 83 00 91   add   x29, sp, #32
    1620: e0 03 00 91   mov   x0, sp
    1624: 07 00 00 94   bl    0x1640 <decode>
    1628: e0 03 00 91   mov   x0, sp
    162c: 19 00 00 94   bl    0x1690 <puts@plt>
    ...
```

Read `main` carefully. It sets **one** argument register, `x0`, and calls `decode`. The source passes
four arguments. Three of them were compile-time constants, so clang specialised `decode` against them
and dropped the parameters.

`decode` was declared `__attribute__((noinline))`. The attribute was obeyed: the function still
exists as a distinct symbol and `main` still calls it. **What `noinline` does not constrain is
interprocedural constant propagation and function specialisation**, and those are what turned
thirty-one instructions into four.

> **Verdict: the original result REPRODUCED, and a fix recorded in
> [58-IDA §11.4](../../58-IDA/README.md) is REFUTED as a general remedy.**
> `noinline` fixed 58's fixture. It does not fix this one. The remedy that does work is 59's — make a
> value the optimiser cannot prove, e.g. `static volatile unsigned char key`.

### 4.3 A defect found by verification, worth recording

The first version of `fold.c` did not compile. Its header comment contained the path
`prebuilt/*/bin`, and the two characters closing a glob also close a C block comment:

```
fold.c:23:72: error: unknown type name 'bin'
 *   NDK=$HOME/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/*/bin
```

The comment terminated mid-path and the remainder of the header was parsed as code.
[37-RootDetection](../../37-RootDetection/README.md) shipped the identical bug once, with
`/proc/<star>/mounts` inside a block comment.

**This is why an example that has never been through a compiler is not a verified example.** The file
now spells the host tag out and says why.

---

## 5. Index — which claim came from where

| Chapter 74 claim | Section here | Verdict |
|---|---|---|
| `ro.boot.verifiedbootstate` is the empty string on the AVD | §1.1 | REPRODUCED |
| `!"orange".equals(state)` is `true` there | §1.1 | REPRODUCED |
| The four `androidboot.*` keys are absent from bootconfig | §1.2 | REPRODUCED |
| `androidboot.vbmeta.digest` equals `ro.boot.vbmeta.digest` | §1.3 | **New** |
| `/proc/bootconfig` and `/proc/cmdline` are root-only | §1.2 | **New** |
| `/data/adb/lspd`: root `ENOENT`, shell and app `EACCES` | §2 | REPRODUCED |
| `/system/xbin/su` visible to shell, `EACCES` to the app | §2 | REPRODUCED |
| `/debug_ramdisk/magisk` readable from an app; listing refused | §2.2 | REPRODUCED |
| Magisk 30.7, Zygisk off | §2.1 | REPRODUCED |
| `mountinfo` `magisk`-sourced mount count | §2.3 | **DIVERGED** (2 by source, 3 by substring) |
| Property counts: shell 673 / app 633 / root 1055 | §3.1 | **DIVERGED** from 39's 1053 / 634 |
| 37 property names visible to shell and not to the app | §3.2 | **New** |
| `ro.debuggable`, `ro.secure`, `partition.system.verified` invisible to the app | §3.3 | **New** |
| `ro.boottime.*` invisible to shell as well as to the app | §3.3 | **DIVERGED** from 39 |
| `-O2` leaks the plaintext, `-O0` does not | §4 | REPRODUCED |
| `noinline` does not prevent it | §4.2 | **New — refutes 58's fix as general** |

**Not re-run in this session, and transcribed from their owning chapters:** the Redmi's
`green`-versus-attestation contradiction (chapter 50), the `/proc/cmdline` `orange` forgery
(chapter 20), the `r2gate` truth table (chapter 59), the `lc_verify_signature` inlining result
(chapter 18), the 237-APK substring audit (chapter 64), the biometric grader failures (chapter 48),
and the 17 MB application sweep (chapter 52). No physical device was attached during this session.
