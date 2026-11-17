# 60 — ADB Cheat Sheet

Protocol and transport only. For the command set, see
[77-UsefulCommands/cheatsheet.md](../77-UsefulCommands/cheatsheet.md).

---

## The 24-byte message header

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `command` | four ASCII chars, little-endian uint32 |
| 4 | 4 | `arg0` | per-command; for streams, **the sender's own id** |
| 8 | 4 | `arg1` | per-command; for streams, **the peer's id** |
| 12 | 4 | `data_length` | payload bytes following the header |
| 16 | 4 | `data_check` | documented CRC32, implemented byte-sum, **verified by nobody**, arrives as 0 |
| 20 | 4 | `magic` | `command ^ 0xffffffff`, always |

```
struct amessage { uint32 command, arg0, arg1, data_length, data_check, magic; };
```

---

## Message types

| Constant | ASCII | uint32 LE | arg0 | arg1 | Payload |
|---|---|---|---|---|---|
| `A_SYNC` | `SYNC` | `0x434e5953` | online | sequence | — |
| `A_CNXN` | `CNXN` | `0x4e584e43` | version | maxdata | `<type>:<serial>:<banner>` + NUL |
| `A_AUTH` | `AUTH` | `0x48545541` | 1/2/3 | 0 | token / signature / public key |
| `A_STLS` | `STLS` | `0x534c5453` | version | 0 | — |
| `A_OPEN` | `OPEN` | `0x4e45504f` | local-id | 0 | service string + NUL |
| `A_OKAY` | `OKAY` | `0x59414b4f` | local-id | remote-id | — |
| `A_WRTE` | `WRTE` | `0x45545257` | local-id | remote-id | up to `maxdata` bytes |
| `A_CLSE` | `CLSE` | `0x45534c43` | local-id | remote-id | — |

**`A_AUTH` arg0:** `1` = `ADB_AUTH_TOKEN` (device→host, 20 bytes) · `2` = `ADB_AUTH_SIGNATURE`
(host→device, 256 bytes) · `3` = `ADB_AUTH_RSAPUBLICKEY` (host→device, 709 bytes + NUL).

**Protocol versions:** `0x01000000` maxdata 4096 · `0x01000001` maxdata 262144, checksum abandoned.

---

## Stream rules

| Rule | |
|---|---|
| Opener picks a non-zero local id | `A_OPEN(local, 0, "service\x00")` |
| Peer answers | `A_OKAY(its id, your id)` |
| Demultiplex on | **`arg1`** — your own id echoed back |
| Flow control window | **exactly one** unacknowledged `A_WRTE` per stream |
| Every `A_WRTE` | must be answered with `A_OKAY` |
| Either side closes | `A_CLSE`; peer replies `A_CLSE`; ids reusable |
| Service refused | `A_CLSE` with **`arg0 = 0`**, no message, no code |
| Framing lost | `magic != command ^ 0xffffffff` — drop the connection |

---

## Service strings (the `A_OPEN` payload)

| Service | Effect |
|---|---|
| `shell:` | interactive PTY, v1 framing |
| `shell:<cmd>` | one command, no PTY, v1 |
| `shell,v2,raw:<cmd>` | v2 packet framing, separate stdout/stderr, exit code |
| `shell,v2,TERM=xterm,pty:` | interactive, v2 |
| `exec:<cmd>` | via `sh`, binary-safe stdio — `adb exec-out`, `adb install` |
| `abb:<args>` | `cmd` sub-command, NUL-delimited args, v2 framing, **no shell** |
| `abb_exec:<args>` | same, raw stdio |
| `sync:` | switch to the sync sub-protocol |
| `root:` / `unroot:` | restart adbd as uid 0 / uid 2000 — needs `ro.debuggable=1` |
| `tcpip:<port>` / `usb:` | restart adbd on TCP / on USB |
| `reboot:<target>` | `""`, `bootloader`, `recovery`, `fastboot`, `sideload` |
| `remount:` | remount system partitions rw |
| `jdwp` / `track-jdwp` | debuggable process ids |
| `framebuffer:` | raw screen capture |
| `reverse:forward:<l>;<r>` | device→host port forward |
| `reverse:list-forward` / `killforward:` | manage them |
| `dev:<path>` | open a device node |
| `sink:` / `source:` | bandwidth test |

`root:`, `unroot:`, `tcpip:`, `usb:`, `remount:`, `reboot:` **take effect immediately.**

---

## shell v2 packet framing (inside `A_WRTE` payloads)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | packet id |
| 1 | 4 | length, little-endian |
| 5 | *length* | payload |

| id | Meaning |
|---|---|
| 0 | stdin |
| 1 | stdout |
| 2 | stderr |
| 3 | exit code (1 byte) |
| 4 | close stdin |
| 5 | window size change |

Measured, `shell,v2,raw:echo hi`: `01 03 00 00 00 68 69 0a` = stdout, 3 bytes, `hi\n`.
Same command as `shell:echo hi`: `68 69 0a` — no framing, and **no exit code at all**.

---

## sync sub-protocol (`SYNC.TXT`)

All messages: four ASCII id bytes, then a little-endian uint32 length.

| Verb | Direction | Meaning |
|---|---|---|
| `STAT` / `STA2` | host→device | file metadata (v1 / `stat_v2`) |
| `LIST` / `LST2` | host→device | list a directory |
| `DENT` | device→host | one directory entry |
| `SEND` | host→device | begin upload; payload `<path>,<mode>` |
| `DATA` | host→device | up to 64 KiB of file content |
| `DONE` | host→device | end of file; the length field is the mtime |
| `RECV` | host→device | begin download |
| `OKAY` | either | success |
| `FAIL` | either | failure; payload is the message |
| `QUIT` | host→device | end the sync session |

`STAT` v1 returns mode 0 for both "missing" and "denied". `stat_v2` returns a real errno.

---

## Authentication

| | |
|---|---|
| Gate | `ro.adb.secure=1` |
| Algorithm | RSA-2048, PKCS#1 v1.5 |
| Signed value | `SHA1-DigestInfo \|\| token` — **the 20-byte token is not hashed** |
| DigestInfo prefix | `30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14` |
| Signature size | 256 bytes |
| Host private key | `~/.android/adbkey` — **unencrypted PKCS#8 PEM**, ~1732 bytes |
| Host public key | `~/.android/adbkey.pub` — 709 bytes |
| Extra host keys | `$ADB_VENDOR_KEYS` (path list) |
| Device key store | `/data/misc/adb/adb_keys` — `0640 system:shell`, `u:object_r:adb_keys_file:s0` |
| Device temp store | `/data/misc/adb/adb_temp_keys.xml` — `<adbKey key="…" lastConnection="epoch-ms"/>` |
| Ramdisk store | `/adb_keys` — a **pre-authorised vendor key** if present |
| Readable by `shell`? | **No.** DAC allows it; SELinux denies the directory search |
| Expiry | `settings get global adb_allowed_connection_time` — default 7 days (Android 11+) |
| Revoke | Developer options → Revoke USB debugging authorizations |

### Public key blob (`RSAPublicKey`, mincrypt) — 524 bytes for RSA-2048

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `len` — modulus words; **64** for 2048-bit |
| 4 | 4 | `n0inv` |
| 8 | 256 | `n[64]` — modulus, little-endian words |
| 264 | 256 | `rr[64]` — R² mod n |
| 520 | 4 | `exponent` — 3 or 65537 |

`4 + 4 + 256 + 256 + 4 = 524` → base64 = **700 characters, always starting `QAAA`**.
Line format: `<700 base64 chars> <free-text comment>` — the comment is **not authenticated**.

---

## Privilege model

| Property | `0` | `1` |
|---|---|---|
| `ro.secure` | adbd starts as root | adbd drops to uid 2000 |
| `ro.debuggable` | `adb root` refused | `adb root` honoured |
| `ro.adb.secure` | **no authentication at all** | `A_AUTH` required |

| | Measured value (test device, API 30 `user`) |
|---|---|
| adbd binary | `/apex/com.android.adbd/bin/adbd` (Android 11+; **no `/system/bin/adbd`**) |
| adbd argv | `adbd --root_seclabel=u:r:su:s0` |
| adbd uid / domain | `shell` (2000) / `u:r:adbd:s0` |
| adbd rooted domain | `u:r:su:s0` |
| adbd `CapEff` | `0000000000000000` |
| adbd `CapBnd` | `00000000000000c0` = `CAP_SETGID` + `CAP_SETUID` |
| init service | `class core`, `updatable`, `seclabel u:r:adbd:s0`, `socket adbd seqpacket 660 system system` |
| key dir created as | `mkdir /data/misc/adb 02750 system shell` |
| start trigger | `on property:sys.usb.config=adb && property:sys.usb.configfs=1` |

---

## `shell` (uid 2000) versus an app — measured on API 30

| | `adb shell` process | `com.android.shell` app | Ordinary third-party app |
|---|---|---|---|
| Parent process | **`adbd`** | `zygote` | `zygote` |
| Binary | `/system/bin/sh` (toybox) | ART / `ActivityThread` | ART / `ActivityThread` |
| UID | 2000 `shell` | 2000 `shell` (sharedUserId `android.uid.shell`) | 10000+ `u0_aNNN` |
| SELinux | `u:r:shell:s0` | `u:r:shell:s0` | `u:r:untrusted_app:s0:c…,c…` |
| MCS categories | **none** | none | unique per app |
| `targetSdkVersion` | **none — no package record** | 30 | app's own |
| Scoped storage / background limits | **do not apply** | apply partially | apply |
| `Context` / `Application` | none | yes | yes |
| Home directory | none | `/data/user/0/com.android.shell` | `/data/user/0/<pkg>` |
| Requested permissions | — | **200** | app's own |
| Install permissions granted | **inherits all 183** | **183** | typically 0–5 |
| Runtime permissions pre-granted | **inherits all 16** | **16**, `SYSTEM_FIXED` | 0 |
| `platform.xml` `assign-permission` | `INTERNET` only | — | — |
| Supplementary groups | `input log adb sdcard_rw sdcard_r ext_data_rw ext_obb_rw net_bt_admin net_bt inet net_bw_stats readproc uhid` | same | `inet` and app-specific |

**The 16 pre-granted, non-revocable runtime permissions include** `CAMERA`, `RECORD_AUDIO`,
`READ_SMS`, `SEND_SMS`, `READ_CONTACTS`, `WRITE_CONTACTS`, `READ_CALENDAR`, `WRITE_CALENDAR`,
`ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, `READ_PHONE_STATE`,
`CALL_PHONE`, `GET_ACCOUNTS`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`.

**Install permissions that shape testing:** `WRITE_SECURE_SETTINGS`, `INSTALL_PACKAGES`, `DUMP`,
`READ_LOGS`, `REAL_GET_TASKS`, `GRANT_RUNTIME_PERMISSIONS`, `REVOKE_RUNTIME_PERMISSIONS`,
`FORCE_STOP_PACKAGES`, `SET_DEBUG_APP`, `INTERACT_ACROSS_USERS_FULL`,
`CHANGE_COMPONENT_ENABLED_STATE`, `SET_ACTIVITY_WATCHER`, `GET_APP_OPS_STATS`.

> **A result obtained from `adb shell` is evidence about `shell`, not about an app.**

---

## Transports

| | USB | `adb tcpip` | Wireless debugging |
|---|---|---|---|
| From | Android 1.0 | Android 1.x | Android 11 / API 30 |
| Device side | FunctionFS: `ep0` control, `ep1` bulk OUT, `ep2` bulk IN | TCP listener | TCP listener |
| Port | — | fixed **5555** | random, mDNS-advertised |
| Discovery | USB enumeration (class `0xFF`, subclass `0x42`, protocol `0x01`) | you must know the IP | mDNS `_adb-tls-connect._tcp` |
| Transport security | none | **none — cleartext** | TLS 1.3, mutual certs |
| Enrolment | the Allow dialog | none beyond `A_AUTH` | SPAKE2, 6-digit code |
| Survives reboot | n/a | only with `persist.adb.tcp.port` | yes, per network |
| Turn off | — | `adb usb` | Developer options |

---

## `adb install` = three streams

```
exec:cmd package install-create -r -S <size>     -> "Success: created install session [<id>]"
exec:cmd package install-write -S <size> <id> base -   <- APK as A_WRTE payloads
                                                  -> "Success: streamed <size> bytes"
exec:cmd package install-commit <id>             -> "Success"  |  "Failure [INSTALL_FAILED_…]"
```

With `abb_exec` (Android 11+, no device-side shell):

```
abb_exec:package \x00 install-create \x00 -r \x00 -S \x00 <size>
```

Staging directory between write and commit: **`/data/app/vmdl<session>.tmp/base`**, owned
`system:system`. Invisible to `pm list packages`. An orphaned one is IR evidence.

---

## Host smart-socket protocol (port 5037) — a different protocol

Request: four hex digits of length, then the request string. Reply: `OKAY` or `FAIL`, then four hex
digits of length, then the payload.

```bash
printf '000chost:version'    | nc 127.0.0.1 5037
printf '000ehost:devices-l'  | nc 127.0.0.1 5037
printf '000dhost:features'   | nc 127.0.0.1 5037
printf '0009host:kill'       | nc 127.0.0.1 5037
```

| Request | Meaning |
|---|---|
| `host:version` | server protocol version |
| `host:devices` / `host:devices-l` | attached devices |
| `host:track-devices` | live feed (how the IDE dropdown updates) |
| `host:features` / `host:host-features` | device / client feature sets |
| `host:kill` | stop the server |
| `host:transport-any` / `host:transport:<serial>` | bind this socket to a device |

Port 5037 is bound to loopback and has **no authentication**. Any local process can drive every
attached device.

---

## Feature flags in the banner

| Feature | Effect |
|---|---|
| `shell_v2` | the `shell,v2:` service becomes available |
| `cmd` | `cmd <service>` exists — session installs possible |
| `abb`, `abb_exec` | NUL-delimited args, no shell |
| `stat_v2`, `ls_v2` | 64-bit sizes and real errnos in sync |
| `fixed_push_mkdir` | `push` creates parents correctly |
| `apex` | `adb install --apex` |
| `remount_shell` | `adb remount` without a root adbd |
| `sendrecv_v2`, `…_brotli`, `…_lz4`, `…_zstd` | compressed transfer |
| `openscreen_mdns` | wireless-debugging discovery |
| `track_app` | live app process feed |
| `delayed_ack` | a real send window instead of one message |

Effective set = **intersection** of both banners. `adb features` (device) vs `adb host-features`
(client).

---

## Posture: what to read, and what it means

```bash
# adb shell — no root needed
getprop ro.secure ; getprop ro.debuggable ; getprop ro.adb.secure
getprop ro.build.type ; getprop ro.build.tags
getprop service.adb.tcp.port ; getprop persist.adb.tcp.port
settings get global adb_enabled
settings get global adb_wifi_enabled
settings get global adb_allowed_connection_time
ps -A -o PID,USER,LABEL,NAME | grep adbd
cat /proc/net/tcp /proc/net/tcp6 | awk '$4=="0A"'    # LISTEN
```

```bash
# adb shell as root — the key store
ls -laZ /data/misc/adb/
wc -l /data/misc/adb/adb_keys
cat /data/misc/adb/adb_temp_keys.xml     # lastConnection is epoch ms
```

**A listening socket beats a property.** The emulator listens on 5555 with
`service.adb.tcp.port` unset.

---

## Severity

| Situation | Rating |
|---|---|
| USB debugging on your own test device | not a finding — methodology note |
| USB debugging on a user phone, screen locked, `ro.adb.secure=1` | informational |
| USB debugging, no screen lock, unattended | medium |
| `adb tcpip` on a trusted lab network | low/medium |
| `adb tcpip` on a corporate/public network, auth on | medium/high |
| ADB over TCP with `ro.adb.secure=0` | **critical** |
| ADB over TCP on a kiosk / signage / TV / head unit | **critical** |
| `ro.debuggable=1` shipped | high |
| Vendor key in `/adb_keys` in a public image | high |

Always state the **device role**. A severity without a role is a guess.

---

## Scripts in this chapter

| Script | What it does |
|---|---|
| [`scripts/adb-mini-client.py`](scripts/adb-mini-client.py) | Full handshake and one stream, no `adb`, no dependencies |
| [`scripts/adb-install-transport.py`](scripts/adb-install-transport.py) | The three-stream session install over raw ADB |
| [`scripts/adb-posture.sh`](scripts/adb-posture.sh) | Read-only posture report with a reasoned severity |
| [`scripts/adbd-trace.js`](scripts/adbd-trace.js) | Frida: decode headers from inside `adbd` (device must be rooted) |

---

## Gotchas

| Symptom | Cause |
|---|---|
| `unauthorized` | signature not in `adb_keys`; tap Allow, or the 7-day expiry fired |
| `offline` | `A_CNXN` never completed |
| `device not found` after a working session | adbd restarted (`root:`, `tcpip:`, USB re-enumeration) |
| Binary file corrupted by `adb shell cat` | PTY translates `\n` to `\r\n`; use `adb exec-out` |
| `adb shell false; echo $?` prints 0 | v1 shell carries no exit code |
| `adb root` fails | `ro.debuggable=0`; use `su` |
| Can't `cat /data/misc/adb/adb_keys` | SELinux denies the `shell` domain; needs root |
| `/system/bin/adbd` missing | it is in the `com.android.adbd` APEX |
| Two `adb` versions fighting | one server per machine; `adb kill-server` |
| Push to `/data/local/tmp` works but the binary won't run | some vendor builds block `execve` there; try `/system/bin/linker64 <exe>` |
