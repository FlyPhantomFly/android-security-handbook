# Lab 03 — Posture and exposure

> **Objective:** measure a device's real ADB posture rather than asserting it; prove for yourself
> what identity `adb shell` actually gives you and how it differs from an app; and write three
> different, defensible severities for the *same* technical facts on three different kinds of
> device.

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-read-the-wire.md), [Lab 02](lab-02-speak-the-protocol.md),
[60-ADB §3.9–§3.13](../README.md#3-deep-internal-working)
**You will need:** at least one physical device you own, and ideally an emulator as a contrast.
Root is optional but unlocks §4.

---

## 0. Why this lab exists

There are two failure modes in reporting ADB, and they are mirror images.

**The inflated finding.** "USB debugging is enabled — CRITICAL." A reviewer who has ever developed
an Android app will discount your entire report on the spot, because that sentence describes several
hundred million perfectly ordinary devices.

**The dismissed finding.** "That needs shell access, so it is out of scope." Said about a payment
terminal on a flat retail network with `adb tcpip` baked into the image, where `shell` **is** the
attacker's identity.

The difference between them is not technical skill. It is having measured the right five fields and
having stated the device's role. This lab is about those five fields and that sentence.

---

## 1. Setup

```bash
# host
adb devices -l
```

You want at least one target. Two with opposite configurations is much better — a retail phone and
an emulator will do, and their differences are the whole point of §6.

> **⚠️ Nothing in this lab changes a device.** Every check is read-only. In particular you will
> **not** run `adb tcpip`, and you will **not** modify `/data/misc/adb`. If an instruction ever
> seems to require it, you have misread it.

---

## 2. The five fields that decide everything

Before running any script, collect these by hand so you know what the script is doing.

```bash
# adb shell — no root required
getprop ro.secure
getprop ro.debuggable
getprop ro.adb.secure
getprop service.adb.tcp.port
getprop persist.adb.tcp.port
settings get global adb_enabled
settings get global adb_wifi_enabled
```

Record them in a table:

| Field | Your device | What it means if… |
|---|---|---|
| `ro.secure` | | `0` → `adbd` starts as **root** |
| `ro.debuggable` | | `1` → `adb root` is honoured |
| `ro.adb.secure` | | `0` → **no authentication at all** |
| `service.adb.tcp.port` | | set → TCP listener, dies at reboot |
| `persist.adb.tcp.port` | | set → TCP listener, **survives reboot** |
| `adb_wifi_enabled` | | `1` → wireless debugging (TLS) is on |

### 2.1 The trap: a property is not a socket

```bash
# adb shell — listening sockets. State 0A is LISTEN.
cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4=="0A" {print $2}'
```

The second column is `<hex address>:<hex port>`. Convert the port:

```bash
# adb shell — the same thing, with ports in decimal
cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \
  | awk '$4=="0A" {print $2}' | awk -F: '{printf "%d\n", strtonum("0x" $2)}' | sort -un
```

> **🔬 Measured, and the reason this lab insists on it.** An Android emulator listens on 5555 with
> `service.adb.tcp.port` **unset** — its `adbd` is put into TCP mode by the emulator itself, not by
> the property trigger. An earlier version of this chapter's posture script read only the properties
> and reported "not exposed" for a device with an open, unauthenticated debug port.
>
> **A listening socket beats a property.** Always check both.

### ✅ Checkpoint 2

Your table is complete, and you have a list of listening ports. If 5555 is in it, note that now.

---

## 3. What `adbd` actually is on this device

```bash
# adb shell
ps -A -o PID,USER,LABEL,NAME | grep adbd
getprop init.svc.adbd
```

Then the single most informative command in this lab:

```bash
# adb shell — what is the PARENT of your shell?
cat /proc/$(cut -d" " -f4 /proc/$$/stat)/cmdline | tr '\0' ' '; echo
```

You should get something like:

```
/apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0
```

Three things are visible in that one line:

1. **The parent of your shell is `adbd`.** Not `zygote`. Your shell is not an app. Hold that
   thought for §5.
2. **The path is under `/apex/`.** Since Android 11 `adbd` ships in the `com.android.adbd` APEX and
   `/system/bin/adbd` does not exist. Confirm:
   ```bash
   # adb shell
   ls -l /system/bin/adbd            # No such file or directory, on API 30+
   ```
3. **`--root_seclabel=u:r:su:s0`** is the SELinux domain `adbd` would transition to if it were
   allowed to run as root. It comes from the `init` service definition.

### 3.1 Read the init definition

```bash
# adb shell as root, if you have it
grep -A8 'service adbd' /system/etc/init/hw/init.usb.rc
```

Expect something close to:

```
mkdir /data/misc/adb 02750 system shell

service adbd /system/bin/adbd --root_seclabel=u:r:su:s0
    class core
    socket adbd seqpacket 660 system system
    disabled
    updatable
    seclabel u:r:adbd:s0
```

| Line | Why it matters |
|---|---|
| `mkdir /data/misc/adb 02750 system shell` | Explains the DAC permissions on the key store you will meet in §4 |
| `socket adbd seqpacket 660 system system` | The channel `adbd` uses to ask `system_server` to raise the "Allow USB debugging?" dialog — `adbd` cannot draw one itself |
| `updatable` | `init` resolves the binary through the APEX, so `adbd` can be patched by a Mainline update without an OS release |
| `seclabel u:r:adbd:s0` | The domain the daemon runs in |
| `disabled` | It is not started at boot; a property trigger starts it |

### 3.2 Find the trigger

```bash
# adb shell as root
grep -n -B1 -A2 'start adbd' /system/etc/init/hw/init.usb.configfs.rc | head -20
```

You are looking for `on property:sys.usb.config=adb && property:sys.usb.configfs=1`. That is the
end of the chain that begins with the Developer Options toggle writing
`Settings.Global.ADB_ENABLED`.

### 3.3 Capabilities

```bash
# adb shell as root
grep -E '^Cap(Eff|Bnd)' /proc/$(pidof adbd)/status
```

Expect `CapEff: 0000000000000000` and `CapBnd: 00000000000000c0`. Bits 6 and 7 are `CAP_SETGID` and
`CAP_SETUID` — retained in the *bounding* set so `adbd` can change identity for the processes it
spawns (this is what makes `run-as` possible), but not effective.

### 3.4 The USB endpoints

```bash
# adb shell as root
ls -l /proc/$(pidof adbd)/fd | grep usb-ffs
```

```
13 -> /dev/usb-ffs/adb/ep0     control  — where the USB descriptors are written
14 -> /dev/usb-ffs/adb/ep1     bulk OUT — host to device, hence read-only here
15 -> /dev/usb-ffs/adb/ep2     bulk IN  — device to host, hence write-only here
```

**Those two file descriptors are the entire USB transport.** Every 24-byte header you decoded in
Lab 01 was written into `ep2` with an ordinary `write()`.

### ✅ Checkpoint 3

You can state where `adbd`'s binary lives, which domain it runs in, which two capabilities it keeps
in its bounding set and why, and which two file descriptors carry the USB transport.

---

## 4. The authorised-key store — and a lesson about DAC versus MAC

### 4.1 Try to read it as `shell`

```bash
# adb shell — no root
ls -ld /data/misc/adb
cat /data/misc/adb/adb_keys
```

Both should fail with `Permission denied`.

**Now work out why.** From §3.1 you know the directory is created `02750 system shell`. Decode that:
`0750` is `rwxr-x---` for owner/group/other, and the leading `2` is setgid. The **group is `shell`**
and the group has read and execute. **DAC says you may read it.**

So what refused?

```bash
# adb shell as root
dmesg | grep -i adb_keys | tail -3
```

```
avc: denied { search } for comm="cat" name="adb" ino=240
     scontext=u:r:shell:s0 tcontext=u:object_r:adb_keys_file:s0 tclass=dir permissive=0
```

**SELinux.** The `shell` domain is not permitted even a directory *search* on the `adb_keys_file`
type. This is one of the cleanest demonstrations of Mandatory Access Control overriding Discretionary
Access Control that you will find on a phone, and it has a direct practical consequence:

> **You cannot enumerate a device's authorised host keys from `adb shell`.** Any checklist,
> blog post or tool that tells you to `cat /data/misc/adb/adb_keys` without root has never been run
> on a real device. And an empty result from such a tool is not evidence that no keys exist.

### 4.2 With root — metadata only

> **⚠️ Never copy key material anywhere.** Not into a report, not into a ticket, not into a
> screenshot, not into a repository. A public key plus its comment identifies an authorised host and
> the comment is attacker-controllable text. Record **counts and timestamps**.

```bash
# adb shell as root — counts, sizes and modes only
ls -laZ /data/misc/adb/
wc -l /data/misc/adb/adb_keys
wc -c /data/misc/adb/adb_keys
```

And the structural check, which reveals nothing about the key itself:

```bash
# adb shell as root — field widths, not contents
cut -d' ' -f1 /data/misc/adb/adb_keys | awk '{print length($0)}'
cut -d' ' -f1 /data/misc/adb/adb_keys | base64 -d | wc -c
cut -d' ' -f1 /data/misc/adb/adb_keys | base64 -d | od -An -tu4 -N4
```

Expected, for each 2048-bit key: base64 field **700** characters, decoded blob **524** bytes, first
word **64**. The arithmetic:

```
uint32 len       4
uint32 n0inv     4
uint32 n[64]   256
uint32 rr[64]  256
int32  exponent  4
               ---
               524   -> base64 -> 700 characters, always beginning "QAAA"
```

Anything that does not fit that shape is worth a second look.

### 4.3 The expiry record

```bash
# adb shell as root
cat /data/misc/adb/adb_temp_keys.xml
```

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<keyStore version="1">
<adbKey key="…" lastConnection="1786359848299" />
</keyStore>
```

`lastConnection` is epoch **milliseconds**. Convert it:

```bash
# host
date -d @$((1786359848299/1000))
```

This file exists because Android 11 added automatic revocation:

```bash
# adb shell
settings get global adb_allowed_connection_time
```

Default is 604800000 ms — seven days. A key not used within that window is dropped.

### ✅ Checkpoint 4

- You attempted the read as `shell`, it failed, and you found the AVC that explains it.
- You recorded a **count** of authorised keys and a `lastConnection` timestamp.
- **No key material appears in your notes.** Check.

---

## 5. Prove that `shell` is not an app

This is the part of the lab that will change how you write findings.

### 5.1 The process

```bash
# adb shell
echo "pid=$$"
ls -l /proc/$$/exe
cat /proc/$$/status | grep -E '^Name|^Uid|^Gid|^Groups'
id
id -Z
```

`exe` points at `/system/bin/sh`, a native toybox binary. There is no ART runtime in this process,
no `Application` object, no `Context`, and — crucially — **no package record and therefore no
`targetSdkVersion`**. Every behaviour change Android gates on `targetSdk` (scoped storage,
background service limits, non-SDK interface restrictions) does not apply.

### 5.2 The package that shares its UID

```bash
# adb shell
dumpsys package com.android.shell | grep -E 'userId=|codePath=|flags=|privateFlags=' | head -5
```

```
userId=2000
codePath=/system/priv-app/Shell
flags=[ SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
privateFlags=[ … PRIVILEGED … ]
```

`com.android.shell` declares `android:sharedUserId="android.uid.shell"`, so UID 2000 is shared
between your `sh` process and a privileged system app. **Framework permission checks are made
against the UID**, so your shell inherits everything that package holds.

### 5.3 Count the permissions

```bash
# host
adb shell dumpsys package com.android.shell > /tmp/shellpkg.txt

# requested
awk '/^ *requested permissions:/{f=1;next} /^ *install permissions:/{f=0} f' /tmp/shellpkg.txt \
  | grep -c '[a-z]'

# install permissions granted (take the FIRST block; the second is the
# shared-user record and duplicates it)
awk '/^ *install permissions:/{n++} n==1' /tmp/shellpkg.txt | grep -c 'granted=true'

# runtime permissions granted, user 0
awk '/runtime permissions:/{f=1;next} /^ *User [0-9]+:/{f=0} f' /tmp/shellpkg.txt \
  | grep 'granted=true'
```

On a stock Android 11 device this chapter measured **200 requested, 183 install permissions granted,
16 runtime permissions granted**. Note the flags on the runtime ones:

```
android.permission.CAMERA: granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT ]
android.permission.RECORD_AUDIO: granted=true, flags=[ SYSTEM_FIXED|GRANTED_BY_DEFAULT ]
android.permission.ACCESS_BACKGROUND_LOCATION: granted=true, flags=[ SYSTEM_FIXED|… ]
```

`SYSTEM_FIXED` means **the user cannot revoke them**.

### 5.4 Where the power does *not* come from

A persistent myth says `shell`'s privileges come from `platform.xml`. Check:

```bash
# adb shell
grep -B1 -A1 'uid="shell"' /system/etc/permissions/platform.xml
```

On the device this chapter measured, the entire grant is:

```xml
<assign-permission name="android.permission.INTERNET" uid="shell" />
```

**One permission.** `assign-permission` exists to grant a permission to a bare UID with no package.
Everything else comes from `com.android.shell`'s own manifest, because it is `PRIVILEGED` and lives
in `/system/priv-app`.

### 5.5 The supplementary groups

```bash
# adb shell
id
```

```
groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),
1078(ext_data_rw),1079(ext_obb_rw),3001(net_bt_admin),3002(net_bt),3003(inet),
3006(net_bw_stats),3009(readproc),3011(uhid)
```

| Group | What it grants |
|---|---|
| `3003(inet)` | permission to create network sockets at all |
| `1007(log)` | filesystem-level access to the log devices |
| `3009(readproc)` | visibility of other processes in `/proc` — without it, `hidepid` would hide them |
| `1011(adb)` | exists specifically for this daemon |
| `1015/1028` | shared storage |

### 5.6 The comparison, written out

Fill this in from your own measurements:

| | `adb shell` | An ordinary app |
|---|---|---|
| Parent process | | |
| SELinux context | | |
| MCS categories | | |
| `targetSdkVersion` | | |
| Install permissions | | |
| Runtime permissions pre-granted | | |
| Can be revoked by the user | | |

### ✅ Checkpoint 5

Write the sentence you would put in a report to explain why an `am start` result from `adb shell`
does not prove an app can do the same. Then write the sentence you would use to explain why, on a
kiosk with ADB over TCP, it *does*.

---

## 6. Run the posture script and compare

Only now, run the tool:

```bash
# host
../scripts/adb-posture.sh -s <serial> --root
```

Compare its output with your own measurements. Anything it reports that you did not measure, go and
measure by hand. Anything you measured that it does not report is a candidate improvement — the
script is 200 lines of `bash` and you should feel free to extend it.

Then run it against a second, differently configured target:

```bash
# host
../scripts/adb-posture.sh -s emulator-5554 --kv
```

and diff the two:

```bash
# host
../scripts/adb-posture.sh -s <phone>          --kv > /tmp/a.kv
../scripts/adb-posture.sh -s emulator-5554    --kv > /tmp/b.kv
diff -u /tmp/a.kv /tmp/b.kv | grep -E '^[+-](build|tcp|adb)'
```

Reference output from two such targets is in
[`../examples/posture-measured.txt`](../examples/posture-measured.txt). Only **three** fields move
the severity, and `adb_enabled` — the one everybody quotes — is not among them.

### ✅ Checkpoint 6

Name the three fields.

---

## 7. Sweep the service surface — safely

An unfamiliar ADB endpoint is enumerated by asking for services and recording which are refused.

```bash
# host — SAFE services only
for s in "shell:" "shell,v2,raw:id" "exec:id" "sync:" "jdwp" "track-jdwp" \
         "framebuffer:" "reverse:list-forward" "sink:" "notaservice:"; do
  printf '%-24s ' "$s"
  python3 -B ../scripts/adb-mini-client.py --port 5555 --service "$s" --timeout 2 2>&1 \
    | grep -q 'A_OKAY' && echo AVAILABLE || echo refused
done
```

> **⚠️ Do not add `root:`, `unroot:`, `tcpip:`, `usb:`, `remount:` or `reboot:`.** They are not
> queries. They execute. `tcpip:` in particular would create exactly the exposure you are supposed
> to be measuring.

Record the results. On a device where `exec:` is available but `shell:` is not, or where
`framebuffer:` answers, you have learned something about how that endpoint is configured.

### ✅ Checkpoint 7

A service table, produced with no side effects, and a written justification for each service you
chose to exclude.

---

## 8. The exercise: three severities, same facts

Here are the measured facts. They are identical in all three scenarios.

```
ro.secure          = 1
ro.debuggable      = 0
ro.adb.secure      = 1
adb_enabled        = 1
persist.adb.tcp.port = 5555
5555 listening     = yes
authorised keys    = 3
screen lock        = set
```

Now write a finding — title, description, severity, and remediation — for each of:

**Scenario A.** A developer's own phone, on their home network, which they use for testing the app
you are assessing.

**Scenario B.** A tablet used as a shared demo unit in a company's sales office, on the corporate
wifi, wiped and reconfigured monthly.

**Scenario C.** An Android-based self-service kiosk in a shopping centre, on the mall's flat guest
network, never rebooted, physically bolted down, running the client's payment application.

<details>
<summary>Model answers — after you have written yours</summary>

**Scenario A — Informational.** The device is the tester's own and the exposure is on a network they
control. Report it as a *methodology note*: "the assessment device had ADB over TCP enabled; this
was the tester's configuration and is not a property of the application under test." Failing to
record it is worse than recording it, because a later reader may otherwise attribute your
observations to a stock device.

**Scenario B — Medium.** Three authorised keys on a shared unit means three hosts, at least one of
which probably belongs to somebody who has left. TCP is reachable by anyone on corporate wifi.
Authentication is required, so an attacker needs one of those three private keys — which are
unencrypted files on three laptops. Remediation: revoke authorisations, disable TCP debugging,
disable developer options on demo units, and add ADB posture to the monthly rebuild checklist.

**Scenario C — Critical.** `persist.adb.tcp.port` means the exposure survives every reboot and was
almost certainly baked into the provisioning image, so it is probably on **every** kiosk, not this
one. The device is unattended, on a network any member of the public can join, and runs a payment
application. Authentication is required, but the three authorised keys were installed by whoever
provisioned the fleet and the same key is likely on all units — one leak compromises everything.
`shell` on that device holds `INSTALL_PACKAGES`, `WRITE_SECURE_SETTINGS`, `READ_LOGS` and a
non-revocable `CAMERA` grant. Remediation: remove the TCP debug port from the image, revoke all
authorisations, and treat the provisioning key as compromised.

**The lesson:** every technical fact was identical. The severity moved by three levels on **role,
network reachability, persistence, and who holds the keys** — none of which is visible in a
`getprop`.

</details>

### ✅ Checkpoint 8

Your three findings differ in severity, and each one states the device role explicitly in its first
sentence.

---

## 9. Hints

<details>
<summary>`dmesg` returns nothing on my device</summary>

Kernel log access is restricted on many builds. Try `su -c dmesg`. If that also fails, the SELinux
denial is still real — you can infer it from the fact that DAC permits the read and the read failed.
On some devices `logcat -b events | grep avc` or `/proc/kmsg` will show it instead.

</details>

<details>
<summary>`wc -l /data/misc/adb/adb_keys` says 0 but the device is authorised</summary>

Either the file has no trailing newline (so `wc -l` undercounts by one — use
`grep -c ''` instead), or the key is only in `adb_temp_keys.xml` because the user tapped Allow
without ticking "Always allow from this computer".

</details>

<details>
<summary>My device has no `/system/etc/init/hw/init.usb.rc`</summary>

Vendors move it. Try:
```bash
adb shell "su -c 'grep -rl \"service adbd\" /system/etc/init /vendor/etc/init 2>/dev/null'"
```

</details>

<details>
<summary>The permission counts do not match the chapter's</summary>

They should not, exactly — they vary by Android version and by OEM. What should hold is the shape:
close to 200 requested, most of them granted, and a double-digit number of `SYSTEM_FIXED` runtime
grants. If you get single digits, check you are not counting only one of the two blocks that
`dumpsys` prints.

</details>

---

## 10. Success criteria

1. A completed five-field posture table, produced by hand before running any script.
2. A listening-port list, and an explanation of why a property alone is not enough.
3. You located `adbd`'s binary, domain, capabilities and USB endpoints.
4. You attempted the key-store read as `shell`, it was denied, and you can name **which** access
   control refused and prove it.
5. Key **counts and timestamps** recorded; **no key material** anywhere in your notes.
6. A completed `shell`-versus-app comparison table from your own measurements.
7. A service-availability table produced with no side effects.
8. Three findings, three severities, same facts, each stating the device role.

---

## 11. Going further

- Extend `adb-posture.sh` to detect a `/adb_keys` on the ramdisk (a pre-authorised vendor key) and
  rate it. You will need a firmware image, not a running device.
- Write a fleet script that runs the `--kv` mode against every attached device, stores the output by
  date, and alerts on any change to the three fields that matter.
- Measure the wireless-debugging path on a spare device: enable it, run `adb mdns services`, capture
  the mDNS advertisement, and observe `A_STLS` with this chapter's client. Then turn it off.
- Compare `shell`'s permission set across two Android versions and write up what was taken away.

---

## Next

**[Lab 04 — CTF: The unattended terminal](lab-04-ctf-unattended-terminal.md)** — five flags, one
badly configured device, and a report to write at the end.
