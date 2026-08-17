# 09 — Android App Internals — Cheat Sheet

> Printable. Tables and commands only. Full explanations live in [`README.md`](README.md).
> Baseline: Android 13–16 (API 33–36). Historical behaviour marked in the *Since / Until* columns.

Legend for code fences: `# host` = your workstation, `# adb shell` = unprivileged device shell
(`shell` user, uid 2000), `# adb shell (root)` = `adb root` or `su`, `# Frida REPL` = inside Frida.

---

## 1. Identity — package, UID, appId, userId

| Term | Meaning | Where it lives |
|---|---|---|
| Package name | Reverse-DNS string, e.g. `com.example.app`. The primary security principal. | `AndroidManifest.xml` → `package` attribute |
| appId | Per-package integer, `10000`–`19999` for normal apps. | Allocated by `PackageManagerService`, stored in `packages.xml` `userId=` |
| userId | Android multi-user / profile id: `0` owner, `10`+ work profiles & secondary users. | `pm list users` |
| UID | Linux uid the process actually runs as. | `/proc/<pid>/status` `Uid:` |
| sharedUserId | Legacy manifest attribute making several packages share one appId. | `AndroidManifest.xml`, `packages.xml` `<shared-user>` |
| seinfo | SELinux "app category" string used by `seapp_contexts`. | `/data/system/packages.list` field 5 |

### 1.1 The arithmetic

```text
UID    = userId * 100000 + appId
userId = UID / 100000        (integer division)
appId  = UID % 100000
```

| Constant | Value | AOSP symbol |
|---|---|---|
| `PER_USER_RANGE` / `AID_USER_OFFSET` | 100000 | `android.os.UserHandle.PER_USER_RANGE` |
| First app appId | 10000 | `Process.FIRST_APPLICATION_UID` / `AID_APP_START` |
| Last app appId | 19999 | `Process.LAST_APPLICATION_UID` / `AID_APP_END` |
| First isolated uid | 90000 | `Process.FIRST_ISOLATED_UID` / `AID_ISOLATED_START` |
| Last isolated uid | 99999 | `Process.LAST_ISOLATED_UID` / `AID_ISOLATED_END` |
| First SDK-sandbox uid (API 33+) | 20000 | `Process.FIRST_SDK_SANDBOX_UID` (verify per release) |
| Shared app GID range | 50000–59999 | `AID_SHARED_GID_START` .. `AID_SHARED_GID_END` |
| Cache GID range | 20000–29999 | `AID_CACHE_GID_START` .. `AID_CACHE_GID_END` |
| Ext storage GID range | 30000–39999 | `AID_EXT_GID_START` .. `AID_EXT_GID_END` |
| Ext cache GID range | 40000–49999 | `AID_EXT_CACHE_GID_START` .. `AID_EXT_CACHE_GID_END` |

### 1.2 Worked UID table

| UID | userId | appId | Meaning |
|---|---|---|---|
| `0` | 0 | 0 | `root` |
| `1000` | 0 | 1000 | `system` (system_server) |
| `2000` | 0 | 2000 | `shell` (adb) |
| `10000` | 0 | 10000 | first app installed on owner user |
| `10234` | 0 | 10234 | ordinary app, owner user |
| `1010234` | 10 | 10234 | **same package**, work-profile / second user instance |
| `1110234` | 11 | 10234 | same package, user 11 |
| `99001` | 0 | 99001 | isolated process (e.g. WebView renderer) |
| `1099001` | 10 | 99001 | isolated process inside user 10 |

### 1.3 Quick conversion one-liners

```bash
# host  — UID -> userId/appId
u=1010234; echo "userId=$((u/100000)) appId=$((u%100000))"

# host  — userId/appId -> UID
uid=10234; user=10; echo $((user*100000 + uid%100000))
```

```bash
# adb shell — every UID currently backing a package, sorted
pm list packages -U | sed 's/package://;s/ uid:/ /' | awk '{printf "%s %s %s\n",$2,$2%100000,$1}' | sort -n
```

---

## 2. Package / UID inspection commands

| Goal | Command | Notes |
|---|---|---|
| List all packages | `pm list packages` | prefix `package:` on each line |
| …with UID | `pm list packages -U` | `package:com.x uid:10234` |
| …with APK path | `pm list packages -f` | shows `/data/app/...` |
| …third-party only | `pm list packages -3` | excludes system |
| …system only | `pm list packages -s` | |
| …disabled / enabled | `pm list packages -d` / `-e` | |
| …uninstalled-but-retained | `pm list packages -u` | includes `DELETE_KEEP_DATA` |
| …with installer | `pm list packages -i` | `installer=com.android.vending` |
| …for another user | `pm list packages --user 10` | |
| …matching filter | `pm list packages com.exam` | substring match |
| APK path(s) | `pm path <pkg>` | one line per split |
| Everything PMS knows | `dumpsys package <pkg>` | the workhorse |
| Only the record block | `dumpsys package <pkg> \| sed -n '/^Packages:/,/^$/p'` | |
| Users on device | `pm list users` | `UserInfo{10:Work profile:1030}` |
| User detail | `dumpsys user` | flags, profile parent, quiet mode |
| Which UID owns a pid | `cat /proc/<pid>/status \| grep -E '^(Uid|Gid|Groups)'` | |
| Resolve appId to package | `cmd package list packages -U \| grep ':10234$'` | |
| Package for a UID (API 26+) | `dumpsys package --uid 10234` | not on all builds |

```bash
# adb shell — the five facts you always want first
p=com.example.app
pm path $p
pm list packages -U | grep -w "package:$p"
dumpsys package $p | grep -E 'userId=|dataDir=|primaryCpuAbi=|versionCode=|targetSdk=|flags=|installerPackageName=|firstInstallTime=|lastUpdateTime='
```

---

## 3. `/data/system/packages.list`

Readable only by root (mode `0640`, owner `system:package_info`).

```bash
# adb shell (root)
cat /data/system/packages.list | grep -w com.example.app
```

Example line:

```text
com.example.app 10234 0 /data/user/0/com.example.app default:targetSdkVersion=34 3003,1015,1028 0 42 null null
```

| # | Field | Example | Meaning |
|---|---|---|---|
| 1 | package name | `com.example.app` | security principal |
| 2 | uid | `10234` | appId for user 0 |
| 3 | debug flag | `0` | `1` if `FLAG_DEBUGGABLE` — this is what `run-as` checks |
| 4 | data dir | `/data/user/0/com.example.app` | CE data path |
| 5 | seinfo | `default:targetSdkVersion=34` | feeds `seapp_contexts` |
| 6 | supplementary GIDs | `3003,1015,1028` | comma list, `none` if empty |
| 7 | profileable-from-shell | `0` | `android:profileableByShell` / `<profileable shell="true">` |
| 8 | longVersionCode | `42` | `versionCodeMajor<<32 \| versionCode` |
| 9+ | trailing columns | `null null` | `usesSdkLibraries` etc.; **added over time — parse tolerantly** |

| seinfo value | Typical owner |
|---|---|
| `default` | ordinary third-party app (`untrusted_app`) |
| `platform` | signed with the platform key |
| `system_app` | `/system/app` non-privileged |
| `platform:privapp` | privileged app in `priv-app` |
| `ephemeral` | Instant App |
| `media`, `network_stack`, `bluetooth` | mainline / special-domain components |
| `…:targetSdkVersion=NN` | suffix appended on modern releases; selects the `untrusted_app_NN` domain |

---

## 4. `/data/system/packages.xml`

```bash
# adb shell (root)
grep -A 30 'package name="com.example.app"' /data/system/packages.xml
```

| Element / attribute | Meaning |
|---|---|
| `<package name=… >` | one record per installed package |
| `codePath=` | `/data/app/~~xxx~~/com.example.app-yyy` |
| `nativeLibraryPath=` | extracted `.so` directory |
| `primaryCpuAbi=` / `secondaryCpuAbi=` | selected ABI(s) |
| `publicFlags=` / `privateFlags=` | decimal `ApplicationInfo` flag bitmaps |
| `ft=` | APK file timestamp (hex ms since epoch) |
| `it=` | first install time (hex ms) |
| `ut=` | last update time (hex ms) |
| `version=` | `versionCode` |
| `userId=` | **the appId** (name is historic and misleading) |
| `sharedUserId=` | appId of the shared user, when the package joins one |
| `installer=` / `installerPackageName=` | attributing installer |
| `installInitiator=` / `installOriginator=` | provenance (API 30+) |
| `packageSource=` | `PackageInstaller.SessionParams` source enum |
| `isOrphaned=` | installer uninstalled |
| `<sigs count=…><cert index= key=…/></sigs>` | signing certs; `key=` present only the first time a cert appears |
| `<perms><item name= granted= flags=/></perms>` | install-time / runtime permission state |
| `<proper-signing-keyset identifier=/>` | keyset id into `<keyset-settings>` |
| `<user id="0" ce-data-inode= installed= hidden= suspended= stopped= not-launched= enabled= instant= …/>` | per-user state |
| `<shared-user name="android.uid.system" userId="1000">` | shared UID definitions with their own `<sigs>` and `<perms>` |
| `<updated-package>` | system app that has been updated by an APK in `/data/app` |

```bash
# adb shell (root) — every shared-user group and its members
grep -o 'sharedUserId="[0-9]*"' /data/system/packages.xml | sort | uniq -c | sort -rn
grep -E '<shared-user name=' /data/system/packages.xml
```

---

## 5. Well-known AIDs (from `system/core/libcutils/include/private/android_filesystem_config.h`)

### 5.1 Core identities

| AID | Value | Role |
|---|---|---|
| `AID_ROOT` | 0 | root |
| `AID_SYSTEM` | 1000 | `system_server`, most framework services |
| `AID_RADIO` | 1001 | telephony stack |
| `AID_BLUETOOTH` | 1002 | Bluetooth stack |
| `AID_GRAPHICS` | 1003 | SurfaceFlinger buffers |
| `AID_INPUT` | 1004 | input devices |
| `AID_AUDIO` | 1005 | audio devices |
| `AID_CAMERA` | 1006 | camera devices |
| `AID_LOG` | 1007 | historic log access |
| `AID_MOUNT` | 1009 | `vold` clients |
| `AID_WIFI` | 1010 | Wi-Fi stack |
| `AID_ADB` | 1011 | `adbd` after dropping root |
| `AID_INSTALL` | 1012 | package installer helper |
| `AID_MEDIA` | 1013 | mediaserver |
| `AID_SDCARD_RW` | 1015 | **write to shared external storage** |
| `AID_KEYSTORE` | 1017 | keystore daemon |
| `AID_DRM` | 1019 | DRM server |
| `AID_MEDIA_RW` | 1023 | direct read/write on media dirs |
| `AID_SDCARD_R` | 1028 | **read shared external storage** |
| `AID_PACKAGE_INFO` | 1032 | group that may read `packages.list` |
| `AID_LOGD` | 1036 | `logd` |
| `AID_STATSD` | 1066 | statsd |
| `AID_LMKD` | 1069 | low-memory killer daemon |
| `AID_EXTERNAL_STORAGE` | 1077 | MediaProvider / storage stack |
| `AID_EXT_DATA_RW` | 1078 | `Android/data` on shared storage |
| `AID_EXT_OBB_RW` | 1079 | `Android/obb` on shared storage |
| `AID_SHELL` | 2000 | `adb shell` |
| `AID_CACHE` | 2001 | cache partition |
| `AID_DIAG` | 2002 | diagnostics |
| `AID_NOBODY` | 9999 | unprivileged sentinel |

### 5.2 Networking / capability GIDs — the ones granted by permissions

| GID | Value | Granted because the app holds |
|---|---|---|
| `AID_NET_BT_ADMIN` | 3001 | `BLUETOOTH_ADMIN` (legacy) |
| `AID_NET_BT` | 3002 | `BLUETOOTH` (legacy) |
| `AID_INET` | **3003** | `android.permission.INTERNET` |
| `AID_NET_RAW` | 3004 | raw sockets (system only) |
| `AID_NET_ADMIN` | 3005 | network admin (system only) |
| `AID_NET_BW_STATS` | 3006 | read bandwidth stats |
| `AID_NET_BW_ACCT` | 3007 | change bandwidth accounting |
| `AID_READPROC` | 3009 | read other processes' `/proc` entries |
| `AID_WAKELOCK` | 3010 | kernel wakelock control |
| `AID_UHID` | 3011 | create virtual HID devices |

> The permission → GID mapping itself lives in
> `frameworks/base/data/etc/platform.xml` (`<permission name=…><group gid=…/></permission>`).

```bash
# adb shell — see the mapping the device actually uses
cat /system/etc/permissions/platform.xml | grep -B1 -A3 'permission name="android.permission.INTERNET"'
```

### 5.3 Reserved ranges

| Range | Purpose |
|---|---|
| 0–999 | core system AIDs |
| 1000–1999 | system service AIDs |
| 2000–2999 | shell / debug AIDs (2900–2999 OEM reserved) |
| 3000–3999 | supplementary capability GIDs |
| 5000–5999 | OEM reserved |
| 6000–6499 | OEM reserved (block 2) |
| 9997 / 9998 / 9999 | `everybody` / `misc` / `nobody` |
| 10000–19999 | **application appIds** |
| 20000–29999 | per-app cache GIDs (also SDK-sandbox UIDs on API 33+) |
| 30000–39999 | per-app external-storage data GIDs |
| 40000–49999 | per-app external-storage cache GIDs |
| 50000–59999 | shared-app GIDs |
| 90000–99999 | isolated process UIDs |
| ≥100000 | secondary users (`userId * 100000 + appId`) |

---

## 6. Directory layout

| Path | Owner:group | Contents | Since |
|---|---|---|---|
| `/data/app/~~<rand>~~/<pkg>-<rand>/base.apk` | `system:system` | installed APK, randomised path | API 30 |
| `/data/app/<pkg>-<rand>/base.apk` | `system:system` | same, older randomisation | API 26–29 |
| `/data/app/<pkg>-1/base.apk` | `system:system` | legacy sequential naming | ≤ API 25 |
| `…/split_<name>.apk` | `system:system` | split APKs | API 21+ |
| `…/lib/<abi>/*.so` | `system:system` | extracted native libs | |
| `…/oat/<isa>/base.{odex,vdex,art}` | `system:system` | AOT artefacts (older layout) | |
| `/data/misc/apexdata`, `/data/misc/profiles/{cur,ref}` | mixed | profiles used by `dex2oat` | |
| `/data/data/<pkg>` | `u<userId>_a<appId>` | CE data, user 0 | all |
| `/data/user/0` → `/data/data` | symlink | canonical CE path | API 17+ |
| `/data/user/<N>/<pkg>` | `u<N>_a<appId>` | CE data, user N | API 17+ |
| `/data/user_de/<N>/<pkg>` | `u<N>_a<appId>` | DE data (available before unlock) | API 24 |
| `/data/media/<N>/Android/data/<pkg>` | `media_rw` | app-specific external files (backing store) | |
| `/storage/emulated/<N>/Android/data/<pkg>` | FUSE view | same, as the app sees it | |
| `/storage/emulated/<N>/Android/obb/<pkg>` | FUSE view | expansion files | |
| `/storage/emulated/<N>/Android/media/<pkg>` | FUSE view | media-scannable app files | |

### 6.1 Inside `/data/data/<pkg>`

| Subdir | Java accessor | Backed up by default | Notes |
|---|---|---|---|
| `files/` | `getFilesDir()` | yes | general private storage |
| `databases/` | `getDatabasePath()` | yes | SQLite `.db`, `-wal`, `-shm` |
| `shared_prefs/` | `getSharedPreferences()` | yes | world-readable XML **inside** the sandbox |
| `cache/` | `getCacheDir()` | no | evictable |
| `code_cache/` | `getCodeCacheDir()` | no | cleared on app upgrade |
| `no_backup/` | `getNoBackupFilesDir()` | **no** | correct home for tokens/keys material |
| `lib` | `applicationInfo.nativeLibraryDir` | n/a | symlink into `/data/app/.../lib/<abi>` |
| `app_<name>/` | `getDir("<name>", mode)` | yes | e.g. `app_webview`, `app_textures` |

```bash
# adb shell — the layout, without root, using run-as (debuggable apps only)
run-as com.example.app ls -la /data/data/com.example.app
# adb shell (root)
ls -laZ /data/data/com.example.app /data/user_de/0/com.example.app
```

### 6.2 CE vs DE storage

| | CE (credential encrypted) | DE (device encrypted) |
|---|---|---|
| Path | `/data/user/<N>/<pkg>` | `/data/user_de/<N>/<pkg>` |
| Readable before first unlock | no | yes |
| Context accessor | default `Context` | `createDeviceProtectedStorageContext()` |
| Manifest opt-in for components | n/a | `android:directBootAware="true"` |
| Key material | tied to user credential | tied to device |
| Since | API 24 | API 24 |

---

## 7. Install command reference

### 7.1 Single-APK

```bash
# host
adb install app.apk
adb install -r app.apk                 # reinstall, keep data
adb install -t app.apk                 # allow test-only APK
adb install -d app.apk                 # allow version downgrade
adb install -g app.apk                 # grant all runtime permissions
adb install --user 10 app.apk          # install into user 10
adb install --instant app.apk          # install as Instant App
adb install -i com.android.vending app.apk   # fake the attributing installer
adb install --bypass-low-target-sdk-block app.apk   # API 34+ blocks very old targetSdk
```

| Flag | `pm` equivalent | Effect |
|---|---|---|
| `-r` | `pm install -r` | replace existing |
| `-t` | `pm install -t` | allow `android:testOnly` |
| `-d` | `pm install -d` | allow downgrade (debuggable/eng) |
| `-g` | `pm install -g` | grant all runtime permissions |
| `-i <pkg>` | `pm install -i <pkg>` | set installer package |
| `--user N` | `pm install --user N` | target user |
| `--full` | `pm install --full` | force full (non-instant) install |
| `--pkg <pkg>` | `pm install --pkg` | assert expected package name |
| `--abi <abi>` | `pm install --abi` | force ABI selection |
| `--install-reason N` | | 0 unknown, 1 policy, 2 device restore, 3 device setup, 4 user |

### 7.2 Session-based install (what `adb install` actually does)

```bash
# adb shell — do it by hand
SZ=$(stat -c %s /data/local/tmp/app.apk)
SID=$(pm install-create -r -S $SZ | grep -o '[0-9]\+')
pm install-write -S $SZ $SID base /data/local/tmp/app.apk
pm install-commit $SID
# or throw the session away:
pm install-abandon $SID
```

```bash
# host — stream the APK over the session without staging it on the device
SZ=$(stat -c %s app.apk)
SID=$(adb shell pm install-create -r -S $SZ | tr -dc '0-9')
adb shell pm install-write -S $SZ $SID base - < app.apk
adb shell pm install-commit $SID
```

| Command | Purpose |
|---|---|
| `pm install-create [opts]` | opens a session, prints `Success: created install session [1234567]` |
| `pm install-write -S <size> <sid> <splitName> <path or ->` | writes one APK into the session |
| `pm install-commit <sid>` | verify + commit atomically |
| `pm install-abandon <sid>` | destroy the session |
| `pm install-existing --user N <pkg>` | make an already-installed package visible to user N |
| `pm list sessions` (or `pm install-list`) | not on all builds; use `dumpsys package installs` |
| `dumpsys package installs` | inspect staged/active sessions |

### 7.3 Splits and multi-package

```bash
# host
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.xxhdpi.apk
adb install-multi-package app1.apk app2.apks           # atomic multi-package
```

```bash
# adb shell — split install by hand
SID=$(pm install-create -r | grep -o '[0-9]\+')
pm install-write -S $(stat -c %s base.apk)     $SID base            /data/local/tmp/base.apk
pm install-write -S $(stat -c %s split_a.apk)  $SID config.arm64_v8a /data/local/tmp/split_a.apk
pm install-commit $SID
```

| Split kind | Typical name | `splitName` used in `install-write` |
|---|---|---|
| Base | `base.apk` | `base` |
| ABI config | `split_config.arm64_v8a.apk` | `config.arm64_v8a` |
| Density config | `split_config.xxhdpi.apk` | `config.xxhdpi` |
| Language config | `split_config.en.apk` | `config.en` |
| Dynamic feature | `split_featurex.apk` | `featurex` |

### 7.4 Uninstall / data lifecycle

| Command | Effect on `/data/data/<pkg>` | Effect on `/sdcard/Android/data/<pkg>` |
|---|---|---|
| `pm uninstall <pkg>` | deleted | deleted |
| `pm uninstall -k <pkg>` | **kept** (`DELETE_KEEP_DATA`) | kept |
| `pm uninstall --user 10 <pkg>` | only user 10's dirs deleted | only user 10's |
| `pm clear <pkg>` | contents wiped, dirs recreated, app stopped | contents wiped |
| `pm clear --cache-only <pkg>` | only `cache/` and `code_cache/` | only cache |
| `pm disable-user <pkg>` | untouched | untouched |

---

## 8. Reading `dumpsys package <pkg>`

| Line you will see | What it tells you |
|---|---|
| `userId=10234` | the appId |
| `sharedUser=SharedUserSetting{… name/uid}` | package is in a shared-UID group |
| `pkg=Package{…}` | in-memory object id |
| `codePath=/data/app/~~a~~/com.x-b==` | install directory |
| `resourcePath=` | same as codePath on modern releases |
| `legacyNativeLibraryDir=` | `lib/` location |
| `primaryCpuAbi=arm64-v8a` | selected ABI — tells you which `.so` set loads |
| `versionCode=42 minSdk=24 targetSdk=34` | **targetSdk drives sandbox strictness** |
| `versionName=1.2.3` | |
| `splits=[base, config.arm64_v8a]` | split set |
| `apkSigningVersion=3` | v1/v2/v3/v3.1/v4 |
| `flags=[ DEBUGGABLE HAS_CODE ALLOW_BACKUP … ]` | decoded `ApplicationInfo.flags` |
| `privateFlags=[ PRIVATE_FLAG_… ]` | decoded private flags |
| `dataDir=/data/user/0/com.x` | CE dir |
| `timeStamp=` / `firstInstallTime=` / `lastUpdateTime=` | forensic timeline |
| `installerPackageName=com.android.vending` | attributed installer |
| `installInitiatorPackageName=` / `originatingPackageName=` | provenance chain (API 30+) |
| `packageSource=` | `SessionParams` source hint |
| `signatures=PackageSignatures{…}` | cert identifiers (not full digests) |
| `installPermissions:` | granted install-time permissions |
| `requested permissions:` | everything in the manifest |
| `User 0: … installed=true hidden=false suspended=false stopped=false enabled=0 instant=false` | per-user state |
| `gids=[3003, 1015, 1028]` | supplementary GIDs actually granted |
| `queriesPackages=` / `queriesIntents=` | package-visibility declarations (API 30+) |

```bash
# adb shell — the greps worth memorising
dumpsys package com.example.app | grep -E 'userId=|sharedUser|dataDir=|flags=|targetSdk|installerPackageName|firstInstallTime|lastUpdateTime|apkSigningVersion|gids='
dumpsys package com.example.app | sed -n '/requested permissions:/,/install permissions:/p'
dumpsys package com.example.app | sed -n '/User 0:/,+3p'
dumpsys package | grep -E '^\s+userId=10234' -B 5      # reverse lookup by appId
dumpsys package installs                               # active install sessions
dumpsys package l                                      # brief listing
```

### 8.1 Signature digest (the reliable way)

```bash
# host
adb shell pm path com.example.app
adb pull /data/app/~~xxx~~/com.example.app-yyy/base.apk .
apksigner verify --print-certs --verbose base.apk
keytool -printcert -jarfile base.apk
```

---

## 9. Process inspection

```bash
# adb shell — processes with SELinux label
ps -A -Z | grep com.example.app
ps -A -o PID,PPID,USER,RSS,NAME | grep com.example
ps -A -Z -o LABEL,USER,PID,PPID,NAME | grep untrusted_app
```

| Column | Read it as |
|---|---|
| `u:r:untrusted_app:s0:c234,c256,c512,c768` | ordinary app, user 0 |
| `u:r:untrusted_app_27:s0:…` | app with an older `targetSdk` (looser policy) |
| `u:r:platform_app:s0:c512,c768` | platform-signed app |
| `u:r:priv_app:s0:c512,c768` | privileged app |
| `u:r:system_app:s0:c512,c768` | `system` UID app |
| `u:r:isolated_app:s0:…` | `android:isolatedProcess="true"` |
| `u:r:ephemeral_app:s0:…` | Instant App |
| `u:r:sdk_sandbox…` | SDK Runtime process (API 33+) |
| `u<N>_a<appId>` in the USER column | e.g. `u0_a234` = userId 0, appId 10234 |

### 9.1 The MLS category encoding

```text
appId'  = appId - 10000
context = …:s0:c<appId' & 0xff>,c<256 + (appId' >> 8)>,c<512 + (userId & 0xff)>,c<768 + (userId >> 8)>
```

| UID | userId | appId | Expected categories |
|---|---|---|---|
| 10234 | 0 | 10234 | `c234,c256,c512,c768` |
| 10500 | 0 | 10500 | `c244,c257,c512,c768` |
| 1010234 | 10 | 10234 | `c234,c256,c522,c768` |

```bash
# host — compute the expected categories for a UID
u=1010234; a=$((u%100000-10000)); n=$((u/100000))
echo "c$((a&255)),c$((256+(a>>8))),c$((512+(n&255))),c$((768+(n>>8)))"
```

### 9.2 `/proc/<pid>/`

```bash
# adb shell (root)
PID=$(pidof com.example.app)
cat /proc/$PID/status | grep -E '^(Name|State|Tgid|Pid|PPid|TracerPid|Uid|Gid|Groups|Threads|VmRSS)'
cat /proc/$PID/cmdline | tr '\0' '\n'
cat /proc/$PID/attr/current
cat /proc/$PID/oom_score_adj
cat /proc/$PID/oom_score
ls -l /proc/$PID/fd | head
cat /proc/$PID/maps | grep -E '\.(so|apk|oat|vdex|art)$' | head
cat /proc/$PID/mountinfo | grep -E 'storage|data'
```

| File | Tells you |
|---|---|
| `status` → `Uid:` | real/effective/saved/fs UID |
| `status` → `Groups:` | supplementary GIDs (3003 = INTERNET) |
| `status` → `TracerPid:` | non-zero when a debugger/Frida is attached |
| `cmdline` | process name, i.e. `com.x` or `com.x:worker` |
| `attr/current` | SELinux domain + MLS categories |
| `oom_score_adj` | LMK priority set by `system_server` |
| `maps` | which APK/split/`.so`/`.oat` is mapped |
| `mountinfo` | storage sandbox mounts, per-app FUSE views |

### 9.3 `oom_score_adj` reference (`ProcessList.java`)

| Constant | Value | Meaning |
|---|---|---|
| `NATIVE_ADJ` | -1000 | native daemons, never killed by lmkd |
| `SYSTEM_ADJ` | -900 | `system_server` |
| `PERSISTENT_PROC_ADJ` | -800 | persistent apps (telephony) |
| `PERSISTENT_SERVICE_ADJ` | -700 | bound to persistent process |
| `FOREGROUND_APP_ADJ` | 0 | app the user is looking at |
| `PERCEPTIBLE_RECENT_FOREGROUND_APP_ADJ` | 50 | just left foreground |
| `VISIBLE_APP_ADJ` | 100 | visible but not focused |
| `PERCEPTIBLE_APP_ADJ` | 200 | foreground service, audio |
| `PERCEPTIBLE_MEDIUM_APP_ADJ` | 225 | lower-value perceptible |
| `PERCEPTIBLE_LOW_APP_ADJ` | 250 | lowest perceptible tier |
| `BACKUP_APP_ADJ` | 300 | running a backup |
| `HEAVY_WEIGHT_APP_ADJ` | 400 | `android:cantSaveState` |
| `SERVICE_ADJ` | 500 | started service |
| `HOME_APP_ADJ` | 600 | launcher |
| `PREVIOUS_APP_ADJ` | 700 | last app the user used |
| `SERVICE_B_ADJ` | 800 | old / less used service |
| `CACHED_APP_MIN_ADJ` | 900 | cached, first to die |
| `CACHED_APP_MAX_ADJ` | 999 | cached, absolutely first to die |

```bash
# adb shell — who is closest to being killed
for p in $(pidof -s zygote64 >/dev/null; ls /proc | grep -E '^[0-9]+$'); do
  n=$(tr -d '\0' < /proc/$p/cmdline 2>/dev/null); a=$(cat /proc/$p/oom_score_adj 2>/dev/null)
  [ -n "$n" ] && echo "$a $p $n"
done | sort -rn | head -20
```

```bash
# adb shell — process importance from the framework's own view
dumpsys activity processes | grep -E 'Proc #|adj=|oom:'
dumpsys activity oom
dumpsys meminfo com.example.app
logcat -b all -s lowmemorykiller lmkd ActivityManager | grep -i kill
```

---

## 10. Process model quick facts

| Item | Value |
|---|---|
| Parent of every app process | `zygote64` (and `zygote` for 32-bit), pid usually low |
| App entrypoint | `android.app.ActivityThread.main()` |
| Bootstrap message | `H.BIND_APPLICATION` → `handleBindApplication()` |
| Order inside `handleBindApplication` | `attachBaseContext()` → **ContentProvider `onCreate()`** → `Application.onCreate()` |
| Main-thread loop | `Looper.prepareMainLooper()` + `Looper.loop()` over a `MessageQueue` |
| Default process name | package name |
| Extra process | `android:process=":name"` (private) or `android:process="a.b.c"` (global, needs same UID+cert) |
| Isolated process | `android:isolatedProcess="true"` → UID 90000–99999, no permissions |

### 10.1 ANR timeouts

| Trigger | Default timeout |
|---|---|
| Input dispatch (key/touch) | 5 s |
| Foreground broadcast | 10 s |
| Background broadcast | 60 s |
| Foreground service start (`Service.onCreate`/`onStartCommand`) | 20 s |
| Background service start | 200 s |
| `ContentProvider` publish at process start | 10 s |
| `JobService.onStartJob` returning | 10 s |

```bash
# adb shell
ls -l /data/anr/
cat /data/anr/anr_*                 # requires root
logcat -b crash,main | grep -E 'ANR in|Reason:'
dumpsys activity anrs
```

### 10.2 Start types

| Start type | What already exists | Typical cost |
|---|---|---|
| Cold | nothing — Zygote fork, class load, `Application.onCreate`, first Activity | highest |
| Warm | process alive, Activity destroyed | medium |
| Hot | process and Activity alive, just brought forward | lowest |

```bash
# adb shell — measure a cold start
am force-stop com.example.app
am start-activity -W -n com.example.app/.MainActivity   # look at TotalTime / WaitTime
logcat -s ActivityTaskManager | grep 'Displayed'
```

### 10.3 Task / back stack

```bash
# adb shell
dumpsys activity activities | grep -E 'Task\{|Hist |mResumedActivity'
dumpsys activity recents | head -40
am stack list            # older releases
```

| Manifest attribute | Effect |
|---|---|
| `android:taskAffinity` | which task the Activity prefers; empty string isolates it |
| `android:launchMode` | `standard`, `singleTop`, `singleTask`, `singleInstance` |
| `android:excludeFromRecents` | hide task from Recents |
| `android:allowTaskReparenting` | Activity can move task — historic StrandHogg-class abuse |
| `android:documentLaunchMode` | multiple document tasks |

---

## 11. `android:debuggable` — what it actually unlocks

| Capability | Needs `FLAG_DEBUGGABLE` | Needs root | Notes |
|---|---|---|---|
| `adb shell run-as <pkg>` | **yes** | no | `run-as` reads field 3 of `packages.list` |
| JDWP debugger attach (`adb jdwp`, Android Studio) | yes | no | Zygote enables the JDWP thread |
| `am set-debug-app -w <pkg>` | yes | no | wait-for-debugger |
| `setprop wrap.<pkg> …` (LD_PRELOAD injection) | yes | no on user builds for debuggable apps | classic gadget-injection path |
| Frida via `frida-server` (root) | no | **yes** | root + `ptrace`, debuggable irrelevant |
| Frida Gadget embedded in APK | no | no | requires repackaging + re-signing |
| Frida via `run-as` + gadget (`frida -U -f`) | yes | no | non-root workflow |
| `ptrace` another process | n/a | yes (or same-uid + yama) | governed by SELinux + `kernel.yama.ptrace_scope` |
| Backup via `adb backup` | no | no | governed by `android:allowBackup` (deprecated API 31+) |

```bash
# adb shell — is it debuggable?
dumpsys package com.example.app | grep -o 'DEBUGGABLE'
run-as com.example.app id                        # succeeds only if debuggable
# adb shell (root)
awk '$1=="com.example.app"{print "debugFlag="$3}' /data/system/packages.list
```

```bash
# host — from the APK, before installing
aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -i debuggable
apkanalyzer manifest debuggable app.apk
```

```bash
# host — is the whole build debuggable?
adb shell getprop ro.debuggable
adb shell getprop ro.build.type          # user / userdebug / eng
adb shell getprop ro.secure
```

---

## 12. Multi-user and work profiles

```bash
# adb shell
pm list users
dumpsys user
am get-current-user
am switch-user 10
pm list packages --user 10
pm install-existing --user 10 com.example.app
pm uninstall --user 10 com.example.app
pm create-user --profileOf 0 --managed "Work"     # needs privileges
pm remove-user 10
```

| Path template | Example (user 10) |
|---|---|
| CE data | `/data/user/10/com.example.app` |
| DE data | `/data/user_de/10/com.example.app` |
| Shared storage | `/storage/emulated/10/` |
| Media backing | `/data/media/10/` |

| Cross-user concern | Check |
|---|---|
| Same package, two UIDs | `pm list packages -U --user 0` vs `--user 10` |
| Exported component reachable across users | `INTERACT_ACROSS_USERS[_FULL]` holders only |
| `Intent` sent with `sendBroadcastAsUser` | system/privileged callers |
| Work-profile data crossing to personal | `dumpsys device_policy` |
| Badged / cross-profile intent filters | `dumpsys package \| grep -i crossProfile` |

---

## 13. App standby buckets, Doze, background restrictions

```bash
# adb shell
am get-standby-bucket com.example.app
am set-standby-bucket com.example.app rare
am set-standby-bucket com.example.app 40
dumpsys usagestats | grep -A 3 'App Standby States'
dumpsys usagestats appstandby
```

| Bucket | Numeric | Meaning |
|---|---|---|
| `active` | 10 | in use right now |
| `working_set` | 20 | used regularly |
| `frequent` | 30 | used often but not daily |
| `rare` | 40 | rarely used — heavy job/alarm throttling |
| `restricted` | 45 | user- or system-restricted (API 30+) |
| `never` | 50 | installed but never launched |

```bash
# adb shell — Doze
dumpsys deviceidle
dumpsys deviceidle enable
dumpsys deviceidle force-idle          # jump straight to deep idle
dumpsys deviceidle step                # advance one state
dumpsys deviceidle unforce
dumpsys deviceidle whitelist +com.example.app
dumpsys deviceidle whitelist -com.example.app
dumpsys battery unplug                 # required for Doze to engage
dumpsys battery reset
```

```bash
# adb shell — background restrictions & app ops
cmd appops get com.example.app
cmd appops set com.example.app RUN_ANY_IN_BACKGROUND ignore
dumpsys jobscheduler | grep -A 20 com.example.app
dumpsys alarm | grep -A 10 com.example.app
```

---

## 14. Install-flow observation

```bash
# adb shell — watch an install happen live
logcat -c
logcat -v time PackageManager:V PackageInstaller:V installd:V dex2oat:V ActivityManager:I '*:S'
```

| Tag | Emitted by | What to look for |
|---|---|---|
| `PackageInstaller` | `PackageInstallerSession` | session create / write / commit |
| `PackageManager` | PMS | parse, verify, `New package installed` |
| `installd` | `frameworks/native/cmds/installd` | `createAppData`, `restorecon`, `dexopt` |
| `dex2oat` / `dexopt` | ART compiler | compiler filter, time taken |
| `ActivityManager` | AMS | `Start proc`, broadcast delivery |
| `PackageParser` / `ParsingPackageUtils` | manifest parsing | malformed-manifest errors |
| `ApkSignatureVerifier` | signature check | v2/v3 verification failures |

```bash
# adb shell — see PACKAGE_ADDED land
logcat -v time | grep -E 'ACTION_PACKAGE_ADDED|android.intent.action.PACKAGE_'
dumpsys package r | head -40                      # resolvers
cmd package compile -m speed -f com.example.app   # force AOT recompile
```

---

## 15. ADB one-liners worth keeping

```bash
# host — pull every APK of a package (base + splits)
for p in $(adb shell pm path com.example.app | tr -d '\r' | sed 's/package://'); do adb pull "$p"; done

# host — package name of the app currently on screen
adb shell dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'
adb shell dumpsys activity activities | grep mResumedActivity

# host — launcher activity of a package
adb shell cmd package resolve-activity --brief com.example.app | tail -1

# host — start / stop / clear
adb shell am start -n com.example.app/.MainActivity
adb shell am force-stop com.example.app
adb shell pm clear com.example.app

# host — every UID that shares an appId with another package
adb shell pm list packages -U | tr -d '\r' | sed 's/package://;s/uid://' \
  | awk '{print $2, $1}' | sort -n | awk '{c[$1]=c[$1]" "$2} END{for(u in c){n=split(c[u],a," "); if(n>1) print u, c[u]}}'

# host — size of a package's data (root)
adb shell "su -c 'du -sh /data/data/com.example.app /data/user_de/0/com.example.app'"

# host — file contexts of app data
adb shell "su -c 'ls -laZ /data/data/com.example.app'"

# host — which processes belong to one app
adb shell ps -A -o USER,PID,PPID,NAME | grep com.example.app

# host — kill just one of a multi-process app's processes
PID=$(adb shell pidof com.example.app:worker | tr -d '\r')
adb shell "su -c 'kill $PID'"

# host — dump the merged manifest of an installed app
adb shell pm path com.example.app | sed 's/package://' | head -1 | xargs -I{} adb pull {} base.apk
aapt2 dump xmltree base.apk --file AndroidManifest.xml | less

# host — list every provider a package declares (persistence hunting)
adb shell dumpsys package com.example.app | sed -n '/Provider Resolver Table/,/Service Resolver Table/p'
adb shell dumpsys package providers | grep -A 5 com.example.app
```

---

## 16. Fast triage checklist

| # | Question | Command |
|---|---|---|
| 1 | What is the appId / UID? | `pm list packages -U \| grep -w package:<pkg>` |
| 2 | Does it share a UID? | `dumpsys package <pkg> \| grep sharedUser` |
| 3 | Is it debuggable? | `dumpsys package <pkg> \| grep DEBUGGABLE` |
| 4 | What is `targetSdk`? | `dumpsys package <pkg> \| grep targetSdk` |
| 5 | Where is the APK, and are there splits? | `pm path <pkg>` |
| 6 | Who installed it, and when? | `dumpsys package <pkg> \| grep -E 'installer\|InstallTime\|lastUpdate'` |
| 7 | Which GIDs does it hold? | `dumpsys package <pkg> \| grep gids=` |
| 8 | How many processes? | `ps -A \| grep <pkg>` |
| 9 | What SELinux domain? | `ps -A -Z \| grep <pkg>` |
| 10 | Which providers run at startup? | `dumpsys package <pkg> \| grep -i provider` |
| 11 | Is it in another user? | `pm list packages --user 10 \| grep <pkg>` |
| 12 | What is on external storage? | `ls -la /sdcard/Android/data/<pkg>` |

---

## See also

- [`../06-Android-Architecture/README.md`](../06-Android-Architecture/README.md) — where PMS and AMS sit in the stack
- [`../10-APK-Internals/README.md`](../10-APK-Internals/README.md) — what is actually inside the APK being installed
- [`../21-App-Sandbox/README.md`](../21-App-Sandbox/README.md) — the UID sandbox in depth
- [`../22-SELinux/README.md`](../22-SELinux/README.md) — domains, contexts, MLS categories
- [`../23-Permissions/README.md`](../23-Permissions/README.md) — permission-to-GID mapping
- [`../27-ContentProviders/README.md`](../27-ContentProviders/README.md) — provider internals
- [`../33-Storage/README.md`](../33-Storage/README.md) — CE/DE, scoped storage, FUSE
- [`../53-Frida/README.md`](../53-Frida/README.md) — attaching to the processes described here
- [`../60-ADB/README.md`](../60-ADB/README.md) — how `adb install` is implemented
