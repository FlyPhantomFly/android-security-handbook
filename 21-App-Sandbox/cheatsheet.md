# 21 — App Sandbox · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these is true.

---

## The one paragraph

Each app is a separate **Linux user**. `uid = userId * 100000 + appId`. The sandbox is installed by
Zygote **before any app code runs**, and it is at least seven mechanisms: UID/DAC, SELinux MAC with
per-app MCS categories, seccomp-bpf, an empty capability set, `isolatedProcess`/SDK sandbox, network
GIDs, and package visibility filtering. The boundary is enforced by the **kernel**, not the runtime.

---

## UID arithmetic

```
uid    = userId * 100000 + appId
userId = uid / 100000
appId  = uid % 100000
```

| Range | Symbolic | Meaning |
|---|---|---|
| `0` | `AID_ROOT` | `init`, `vold`, `ueventd` |
| `1000` | `AID_SYSTEM` | `system_server` |
| `1001` / `1002` / `1013` / `1019` | `AID_RADIO` / `AID_BLUETOOTH` / `AID_MEDIA` / `AID_DRM` | Core daemons |
| `2000` | `AID_SHELL` | **What you are in `adb shell`** |
| `3001`–`3011` | `AID_NET_*`, `AID_READPROC`, `AID_WAKELOCK` | Capability-like supplementary GIDs |
| `9997` / `9998` / `9999` | `AID_EVERYBODY` / `AID_MISC` / `AID_NOBODY` | — |
| `10000`–`19999` | `FIRST_APPLICATION_UID`–`LAST_APPLICATION_UID` | **Ordinary apps** |
| `20000`–`29999` | `FIRST_SDK_SANDBOX_UID` | SDK Runtime; `appUid + 10000` |
| `90000`–`98999` | `FIRST_APP_ZYGOTE_ISOLATED_UID` | Isolated, forked from an App Zygote |
| `99000`–`99999` | `FIRST_ISOLATED_UID` | Ordinary `isolatedProcess` |
| `+100000` | `AID_USER_OFFSET` | Per Android user / work profile |

Name form: `u<userId>_a<appId - 10000>`. `u0_a288` = 10288. `u10_a288` = 1010288. `u0_i9` = 99009.

---

## Network GIDs (`platform.xml` → supplementary groups)

| GID | Name | Confers |
|---|---|---|
| 3001 | `AID_NET_BT_ADMIN` | Bluetooth admin |
| 3002 | `AID_NET_BT` | Bluetooth sockets |
| **3003** | **`AID_INET`** | **`AF_INET`/`AF_INET6` sockets — the whole `INTERNET` permission** |
| 3004 | `AID_NET_RAW` | `SOCK_RAW` |
| 3005 | `AID_NET_ADMIN` | Network configuration |
| 3006 / 3007 | `AID_NET_BW_STATS` / `AID_NET_BW_ACCT` | Bandwidth stats / accounting |
| 3009 | `AID_READPROC` | Read other processes' `/proc` |
| 3010 | `AID_WAKELOCK` | Kernel wakelocks |

`INTERNET` is **kernel-enforced**. Not hookable from inside the app's own process.

---

## Reading a process's sandbox

```bash
# adb shell
PID=$(pidof com.example.torch)
cat /proc/$PID/status
cat /proc/$PID/attr/current
ps -A -Z | grep com.example.torch
```

| `/proc/<pid>/status` field | Expect on an app | Means |
|---|---|---|
| `Uid:` | `10388 10388 10388 10388` | real / effective / saved / fs |
| `Gid:` | same four numbers | primary group == UID |
| `Groups:` | `3003 9997 …` | supplementary GIDs; **3003 = INTERNET** |
| `CapInh/Prm/Eff/Bnd/Amb:` | **all `0000000000000000`** | no capabilities, and `CapBnd` = can never acquire any |
| `Seccomp:` | **`2`** | `SECCOMP_MODE_FILTER` active |
| `Seccomp_filters:` | `1` | one filter installed (Zygote's) |
| `NoNewPrivs:` | **`1`** | `execve` can never raise privilege |
| `attr/current` | `u:r:untrusted_app_34:s0:c288,c256,c512,c768` | domain + MCS categories |

Shell for comparison: `Seccomp: 0`, `NoNewPrivs: 0`, non-empty `CapBnd`, context `u:r:shell:s0`.

---

## SELinux contexts you will see

| Context | Who |
|---|---|
| `u:r:untrusted_app:s0:c…` / `untrusted_app_29/_30/_32/_34` | Ordinary third-party app |
| `u:r:platform_app:s0:c…` | Signed with the platform key |
| `u:r:priv_app:s0:c…` | `/system/priv-app` |
| `u:r:system_app:s0:c…` | Shares `AID_SYSTEM` |
| `u:r:isolated_app:s0:c…` | `android:isolatedProcess="true"` |
| `u:r:sdk_sandbox[_34]:s0:c…` | SDK Runtime |
| `u:r:shell:s0` | `adb shell` |
| `u:r:runas_app:s0:c…` | Inside `run-as` |

MCS categories are per app+user. Two `untrusted_app` processes are the **same domain** — the
categories are what separates them.

---

## Filesystem layout

```
/data/user/<userId>/<pkg>          CE  0700 app:app        (alias /data/data/<pkg> for user 0)
  ├── cache/  code_cache/  databases/  files/  no_backup/  shared_prefs/
/data/user_de/<userId>/<pkg>       DE  0700 app:app        Direct Boot state only
/data/app/~~<rand>/<pkg>-<rand>/base.apk   0644 system:system   WORLD-READABLE
/data/misc_ce|_de/<userId>/sdksandbox/<pkg>/<sdk>@<rand>   SDK Runtime storage
/storage/emulated/<userId>/Android/data/<pkg>              FUSE, MediaProvider-mediated
/data/local/tmp                    shell-owned; NOT reachable by an app
/data/system/packages.list         0640 system:package_info — the UID map
```

`packages.list` field order:

```
pkgName  uid  debugFlag  dataDir  seinfo  gids  profileableFromShell  versionCode
```

Field 3 (`debugFlag`) is what `run-as` reads.

---

## The three storage trees

| Path | Encryption | Backed up |
|---|---|---|
| `/data/user/<u>/<pkg>` | CE (credential encrypted) | Yes, except `no_backup/` and `cache/` |
| `/data/user_de/<u>/<pkg>` | DE (device encrypted) | No |
| `/storage/emulated/<u>/Android/data/<pkg>` | CE via `/data` | Configurable |

---

## Version matrix

| Android | Change |
|---|---|
| ≤ 8.1 (27) | Data dir `0751` for `targetSdk < 24` — traversal possible; origin of legacy world-readable prefs findings |
| 9 (28) | Data dir `0700` unconditionally |
| 10 (29) | `/proc` hardened — an app sees only its own processes; scoped storage introduced |
| 10 (29) | `sharedUserId` deprecated; App Zygote added |
| 11 (30) | Package visibility filtering (`<queries>`); `/data/app` randomised path segments; FUSE blocks direct access to others' `Android/data` |
| 12 (31) | `PendingIntent` mutability must be explicit |
| 12L (32) | `android:sharedUserMaxSdkVersion` |
| 13 (33) | Clipboard auto-clear; notification permission |
| 14 (34) | SDK Runtime (Privacy Sandbox) generally available |

---

## `android:process` vs `android:isolatedProcess`

| | `android:process=":x"` | `android:isolatedProcess="true"` |
|---|---|---|
| Separate process | Yes | Yes |
| Separate **UID** | **No** — same app UID | **Yes** — 99000–99999 (or 90000–98999) |
| Permissions | All the app's | **None** |
| Data directory | The app's | **None created** |
| Network | Yes (`AID_INET`) | **No** |
| SELinux domain | `untrusted_app` | `isolated_app` |
| Binder services | All | A tiny allowlist |
| Is it a security boundary? | **No** | **Yes** |

Companion attributes: `android:useAppZygote="true"` (share preloaded pages; UID range 90000–98999),
`android:externalService="true"` (charge lifetime to the binding client — how WebView renderers work).

---

## What the sandbox does NOT stop

| Not protected against | Because |
|---|---|
| **The user** | They own the device; a backup, a rooted device, or an emulator image reads everything |
| **Root** | Outside the threat model; defeats DAC entirely (SELinux still applies until policy is patched) |
| **IPC you exported** | You opened the door yourself |
| **Shared storage** | Data written there has left the sandbox permanently |
| **The clipboard** | A system-wide shared buffer by design |
| **Screen capture / overlays / `MediaProjection`** | Pixels are outside the filesystem model — use `FLAG_SECURE` |
| **Accessibility services** | A sanctioned, user-granted read of every window |
| **Side channels** | Timing, memory pressure, power, sensors — no UID check applies |
| **Backup** | `allowBackup` moves data off-device by design |
| **Your own SDKs** | They are your UID, your process, your memory, your permissions |

---

## Six classes of sandbox escape

1. Kernel vulnerability (the only *true* escape)
2. Privileged service vulnerability (`system_server`, `installd`, vendor HALs)
3. SELinux policy misconfiguration (usually vendor-added rules)
4. Confused deputy via a system app
5. File-descriptor leak across the boundary (`SCM_RIGHTS`, `ContentProvider.openFile`)
6. Binder transaction handling bug

---

## Commands

### Identity and inventory

```bash
# adb shell
id                                            # who am I? (2000 shell — NOT an app)
pm list packages -U                           # package:… uid:10388
pm list users                                 # every Android user / work profile
dumpsys package com.example.torch | grep -E 'userId|gids|dataDir|flags|sharedUser'
ps -A -Z | grep u0_a                          # every app process with SELinux context
ps -A -o USER,PID,NAME | grep _i              # isolated processes (u0_i9 …)
pm path com.example.torch                     # resolve the randomised APK path
```

```bash
# adb shell as root
cat /data/system/packages.list | grep com.example.torch
ls -ldZ /data/data/com.example.torch
ls -lZ  /data/data/com.example.torch/shared_prefs/
```

### Constraint checks

```bash
# adb shell
PID=$(pidof com.example.torch)
grep -E '^(Uid|Gid|Groups|Cap|Seccomp|NoNewPrivs)' /proc/$PID/status
cat /proc/$PID/attr/current
mount | grep -E ' /data | /storage '          # expect nosuid,nodev
```

### Becoming the app

```bash
# adb shell — debuggable builds ONLY
run-as com.example.torch id
run-as com.example.torch ls -la /data/data/com.example.torch
run-as com.example.torch cat shared_prefs/prefs.xml
run-as com.example.torch sh -c 'cd /data/data/com.example.torch && tar cf - .' > /sdcard/d.tar
```

`run-as: package not debuggable` means field 3 of `packages.list` is `0`. On a `userdebug` build
`ro.debuggable=1` makes `run-as` work on **everything** — never generalise from such a device.

### Denials

```bash
# adb shell as root
dmesg | grep -i avc                           # SELinux denials
dmesg -w | grep -i seccomp                    # seccomp kills/traps
strace -f -p $PID -e trace=file 2>&1 | grep EACCES     # DAC denials
```

| Evidence | Layer |
|---|---|
| `EACCES` at `openat`, no `avc:` line | DAC |
| `avc: denied { read } for … scontext=u:r:untrusted_app…` | SELinux |
| `audit: type=1326 … syscall=NNN` | seccomp |

### Backup surface

```bash
# host
adb shell dumpsys package com.example.torch | grep -i 'allowBackup\|fullBackup'
adb shell bmgr list transports
adb shell bmgr backupnow com.example.torch
```

---

## Static analysis one-liners

```bash
# host — after apktool d -f target.apk -o work/
grep -oE 'android:(debuggable|allowBackup|sharedUserId|sharedUserMaxSdkVersion|usesCleartextTraffic)="[^"]*"' work/AndroidManifest.xml
grep -E '<(activity|service|receiver|provider)' work/AndroidManifest.xml | grep 'exported="true"'
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml
grep -c 'isolatedProcess="true"' work/AndroidManifest.xml
```

```bash
# host — after jadx -d out target.apk
grep -rnE 'getExternalStorage|/sdcard|Environment\.getExternal' out/sources/
grep -rnE 'openFileOutput\([^,]+, *[12]\)|MODE_WORLD_(READ|WRITE)' out/sources/
grep -rnE 'ClipboardManager|setPrimaryClip' out/sources/
grep -rnE 'PendingIntent\.(getActivity|getBroadcast|getService)' out/sources/
grep -rnE 'FLAG_SECURE' out/sources/
grep -rnE 'openFile\(|ParcelFileDescriptor\.open' out/sources/
grep -rnE 'Binder\.getCallingUid|getCallingPid|checkCallingPermission' out/sources/
```

---

## Verdict vocabulary for a probe app

| Verdict | Meaning |
|---|---|
| `REACHABLE` | Succeeded **from an ordinary app UID** — the strongest claim available without root |
| `DENIED` | Platform refused (`SecurityException`, `EACCES`, `bindService` → `false`) |
| `ABSENT` | Does not exist **or** package visibility filtering is hiding it — check `<queries>` first |
| `ERROR` | Target accepted the request then threw — **still reachable** |
| `INCONCLUSIVE` | The API cannot tell us; go get the evidence elsewhere |

---

## Reachability discipline

| Experiment | Proves |
|---|---|
| `adb shell` / `am start` / `content query` | Reachable **by UID 2000 in the `shell` domain**. Nothing about apps. |
| `run-as <pkg>` | Reachable by that app's own UID — only on debuggable builds |
| Frida inside the target | Reachable by code **already executing** in the target |
| **A separate installed probe APK** | Reachable by **any app the user installs** — this is the finding |

Run both experiments. Record both results. The difference is the finding.

---

## Rules

1. `uid % 100000` is the appId. Do the arithmetic before saying anything about identity.
2. `adb shell` is not an app. Never conclude "an app can do X" from a shell.
3. `android:process` is not isolation. `android:isolatedProcess` is.
4. `INTERNET` is GID 3003 and cannot be hooked away in-process.
5. The APK is world-readable — nothing shipped in it is secret.
6. Check `sharedUserId` on every engagement; analyse at the granularity of the shared UID group.
7. `CapBnd` all zeros means the process can never acquire a capability, ever.
8. `Seccomp: 2` and `NoNewPrivs: 1` on an app; `0` and `0` in your shell.
9. `dmesg | grep avc` distinguishes SELinux from DAC in one command. Get it right.
10. Most findings are not sandbox failures — they are developers trusting the sandbox against an
    adversary it was never built to stop.
