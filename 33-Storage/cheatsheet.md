# 33 — Storage · Cheat Sheet

Dense reference. Prose is in [README.md](README.md).

---

## Storage roots for one package

| Root | Path (user `n`, package `p`) | Accessor | uid-protected | In backup | Removed on uninstall |
|---|---|---|---|---|---|
| CE internal | `/data/user/n/p` | `getDataDir()` | Yes | Yes | Yes |
| CE, second name | `/data/data/p` (user 0 only) | — | Yes | Yes | Yes |
| DE internal | `/data/user_de/n/p` | `createDeviceProtectedStorageContext()` | Yes | **No** | Yes |
| External app-specific | `/storage/emulated/n/Android/data/p` | `getExternalFilesDir()` | **No** | Configurable | Yes |
| External media | `/storage/emulated/n/Android/media/p` | `getExternalMediaDirs()` | **No** | No | Yes |
| OBB | `/storage/emulated/n/Android/obb/p` | `getObbDir()` | **No** | No | Yes |
| ART profile | `/data/misc/profiles/cur/n/p` | — | Yes | No | Yes |
| Shared collections | `/storage/emulated/n/{DCIM,Download,Documents,Pictures,Music,Movies}` | MediaStore / SAF | **No** | No | **NO — survives** |

## Subdirectories of the CE/DE tree

| Dir | Accessor | Mode | Group | In backup |
|---|---|---|---|---|
| `files/` | `getFilesDir()` | 0771 | app | Yes |
| `cache/` | `getCacheDir()` | 0771 **setgid** | `<uid>_cache` = `20000 + (appId - 10000)` | No |
| `code_cache/` | `getCodeCacheDir()` | 0771 setgid | `<uid>_cache` | No |
| `databases/` | `getDatabasePath()` | 0771 | app | Yes |
| `shared_prefs/` | `getSharedPreferences()` | 0771 | app | Yes |
| `no_backup/` | `getNoBackupFilesDir()` | 0771 | app | **No** |
| `app_<name>/` | `getDir(name, MODE_PRIVATE)` | 0771 | app | Yes |
| `lib` | — | symlink | — | No |

## Availability by device state

| State | CE | DE | Shared |
|---|---|---|---|
| Powered off | Encrypted | Encrypted | Encrypted |
| Booted, **never unlocked** | **Unavailable** | **Available** | Volume mounted |
| Unlocked once, now locked | Available | Available | Available |
| Unlocked | Available | Available | Available |

---

## Reachability: three gates, all must agree

| Gate | Question | Check |
|---|---|---|
| DAC | Does every ancestor grant `o+x`, and the file `o+r`? | `ls -ld` each component up the path |
| MAC | Do the SELinux type and MCS categories permit the reader? | `ls -Zd`; compare category pairs |
| Policy | Does MediaProvider allow it? (shared storage only) | Test from an app; there is no file to read |

MCS formula: `c[appId & 0xff]` , `c[256 + (appId >> 8)]` , then the user pair.
A first category above `c255` is arithmetically impossible — the context was fabricated.

| Label | Meaning |
|---|---|
| `app_data_file:s0:c<a>,c<b>,c512,c768` | Ordinary app; per-app categories isolate it from every other app |
| `privapp_data_file:s0:c512,c768` | Privileged/system app; **no per-app categories** |
| `fuse:s0` | Anything under `/storage/emulated` |
| `user_profile_data_file` | `/data/misc/profiles/...` |

---

## Commands

### Recon

```bash
# host
./scripts/storage-map.sh <pkg> --media                # every root, modes, labels, reachability
./scripts/storage-map.sh <pkg> --no-root              # what an unprivileged principal sees
adb shell "su -c 'ls -laZR /data/user/0/<pkg>'"
adb shell "su -c 'ls -laZR /data/user_de/0/<pkg>'"    # DE is a SIBLING tree, not a subdir
adb shell "ls -la /sdcard/Android/data/<pkg>"
adb shell "dumpsys package <pkg> | grep -iE 'userId|backup|flags'"
```

### The method — filesystem diff plus log capture

```bash
# host
adb shell "am force-stop <pkg>; pm clear <pkg>"
python3 -B scripts/storage-diff.py snapshot --package <pkg> --out before.json
adb logcat -c
#   ... scripted exercise ...
python3 -B scripts/storage-diff.py snapshot --package <pkg> --out after.json
adb logcat -d > session.log
python3 -B scripts/storage-diff.py diff before.json after.json --only-findings
grep -inE "token|password|secret|bearer|authorization|eyJ" session.log
```

### Transient writes (what the diff cannot see)

```bash
# host
frida -U -f <pkg> -l scripts/storage-trace.js
frida -U -f <pkg> -l scripts/storage-trace.js -- --outside-only
```

### Value hunting

```bash
# host
python3 -B scripts/leak-hunter.py --package <pkg> --keep ./pulled
python3 -B scripts/leak-hunter.py --dir ./pulled/<pkg> --min-confidence high
python3 -B scripts/leak-hunter.py --dir ./pulled/<pkg> --pattern "internal=ACME-[0-9A-F]{32}"
python3 -B scripts/leak-hunter.py --dir ./pulled/<pkg> --exclude-value "MyTestPassw0rd"
```

### Pulling private data (a plain `adb pull` of `/data/data` fails — adb is shell, not root)

```bash
# host
adb shell "su -c 'tar cf /data/local/tmp/x.tar /data/user/0/<pkg> /data/user_de/0/<pkg>; chmod 644 /data/local/tmp/x.tar'"
MSYS_NO_PATHCONV=1 adb pull /data/local/tmp/x.tar .
adb shell "su -c 'rm -f /data/local/tmp/x.tar'"
```

### MediaStore

```bash
# adb shell
content query --uri content://media/external/file --projection _id:_data:owner_package_name:is_pending
content query --uri content://media/external/images/media --projection _id:_data:owner_package_name
content query --uri content://media/external/file --where "owner_package_name='<pkg>'"
content delete --uri content://media/external/downloads --where "_display_name='x.txt'"
```

### Backup

```bash
# host
adb shell bmgr enabled
adb shell bmgr list transports
adb shell bmgr backupnow <pkg>
adb backup -f out.ab -noapk <pkg>          # restricted or absent on many modern/OEM builds
dd if=out.ab bs=1 skip=24 | zlib-flate -uncompress | tar tvf -
```

### SQLite (there is **no** `sqlite3` on a stock device — pull and analyse on the host)

```bash
# host
adb shell "su -c 'cp /data/user/0/<pkg>/databases/x.db-wal /data/local/tmp/w; chmod 644 /data/local/tmp/w'"
MSYS_NO_PATHCONV=1 adb pull /data/local/tmp/w ./x.db-wal
python3 -B -c "import re;d=open('x.db-wal','rb').read();print(set(re.findall(rb'[ -~]{8,}',d)))" | head
```

### Device facts

```bash
# adb shell
getprop ro.crypto.type                     # 'file' = FBE, 'block' = legacy FDE
getprop ro.crypto.state
getprop ro.crypto.volume.filenames_mode
grep -E "fuse|sdcardfs|/data " /proc/mounts
sm list-volumes all
dumpsys diskstats | head -12
id                                          # shell holds 1078 ext_data_rw on API 30+
```

---

## Version matrix

| API | Release | Change |
|---|---|---|
| 17 | 4.2 | `MODE_WORLD_*` deprecated |
| 19 | 4.4 | `getExternalFilesDir()` needs **no permission** |
| 21 | 5.0 | SELinux fully enforcing for apps |
| 23 | 6.0 | Runtime permissions; `fullBackupContent` |
| 24 | 7.0 | `MODE_WORLD_*` **throws**; Direct Boot + DE storage; `FileProvider` required for file sharing |
| 26 | 8.0 | `getNoBackupFilesDir()` widely used |
| 29 | 10 | **Scoped storage**, opt-out via `requestLegacyExternalStorage` |
| 30 | 11 | **Enforced**; opt-out ignored for targetSdk 30+; `MANAGE_EXTERNAL_STORAGE`; FUSE replaces sdcardfs; `Android/data` closed to other apps |
| 31 | 12 | `dataExtractionRules` replaces `fullBackupContent` — **ship both** |
| 33 | 13 | `READ_EXTERNAL_STORAGE` splits into `READ_MEDIA_{IMAGES,VIDEO,AUDIO}`; clipboard sensitivity flag |
| 34 | 14 | `READ_MEDIA_VISUAL_USER_SELECTED` — partial media access |

---

## Measured on the test device (Redmi M2101K6P, Android 11 / API 30, rooted, Enforcing)

| Claim | Measurement |
|---|---|
| `/data/user/0` is a symlink to `/data/data` | **False.** `readlink` exits 1; both are inode **118**; `/proc/mounts` shows a bind mount |
| Apps cannot read another app's `/data/data` file | **Not unconditionally.** An ordinary app with no permissions read `com.google.android.gms/shared_prefs/google_sdk_flags.xml` — `privapp_data_file` has no per-app MCS categories, dir is `0711`, file is `0664`. Contents are SDK flags → **Informational** |
| An app can enumerate `/sdcard/Android/data` on API 30 | **No** — `list()` returns `null`. But `exists()` on another package's dir returns **true**, so existence still leaks |
| `adb shell` can enumerate it | **Yes** — 111 entries; shell holds `1078 (ext_data_rw)` |
| Writing to `/sdcard` root without permission | `FileNotFoundException … EPERM`, **not** `SecurityException` |
| Scoped storage forces shared-collection writes through MediaStore | **False on API 30.** A raw `File` write to `Download/` from an app with no storage permission **succeeded**. The root is closed; the collections are not |
| Files an app wrote to `Download/` are removed on uninstall | **No.** After `adb uninstall`, the MediaStore rows were gone and the **files remained on disk** |
| MediaStore rows visible with no permission | **0** |
| `DELETE` removes the data | **No.** SQL showed 1 row remaining; the 61,832-byte `-wal` still held all four deleted secrets. Main `.db` was clean |
| Fixed app after `VACUUM` then `wal_checkpoint(TRUNCATE)` | `-wal` = **0 bytes** |
| A filesystem diff finds every leak | **No.** 4 of 5 leaks appeared; the `cache/` staging file was created and deleted between snapshots |
| `leak-hunter.py` high-confidence hits are real | **132 of 132 were false positives** on Chrome (component-updater signature manifests) |

---

## Static-analysis greps

```bash
# host
grep -nE "allowBackup|dataExtractionRules|fullBackupContent|debuggable|directBootAware|requestLegacyExternalStorage|MANAGE_EXTERNAL_STORAGE" out/AndroidManifest.xml
grep -rnE "getExternalFilesDir|getExternalCacheDir|getExternalMediaDirs|getExternalStorageDirectory|/sdcard/|/storage/emulated" --include=*.java --include=*.kt src/
grep -rn "createDeviceProtectedStorageContext\|moveSharedPreferencesFrom\|moveDatabaseFrom" --include=*.java --include=*.kt src/
grep -rnE "Log\.[vdiwe]\(.*(token|password|secret|key|auth|session|jwt)" --include=*.java --include=*.kt src/
grep -rnE "enableWriteAheadLogging|secure_delete|wal_checkpoint|VACUUM" --include=*.java --include=*.kt src/
grep -rnE "MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getSharedPreferences\([^,]+,\s*[123]\s*\)" --include=*.java --include=*.kt src/
grep -rn "FLAG_SECURE" --include=*.java --include=*.kt src/
strings -a lib/arm64-v8a/*.so | grep -E "^/(data|storage|sdcard)|Android/data"
```

---

## SQLite companion files

| File | Contains | Present when |
|---|---|---|
| `<db>` | The database; free pages keep deleted content unless `secure_delete=ON` | Always |
| `<db>-wal` | Pre-delete pages — **where deleted rows live** | WAL mode, between checkpoints. **Deleted on clean close** |
| `<db>-shm` | Shared-memory index into the WAL | Alongside the WAL |
| `<db>-journal` | Rollback journal | Non-WAL mode, or left behind after a crash |
| `<prefs>.xml.bak` | The **previous** preferences | After a crash mid-write |

Remediation order: `secure_delete=ON` (from the start — it is not retroactive) → `VACUUM` →
`PRAGMA wal_checkpoint(TRUNCATE)`. Swapping the last two silently refills the WAL.
Use `rawQuery` for pragmas that return a value; `execSQL` throws.

---

## Backup rules domains

| Domain | Maps to |
|---|---|
| `root` | `/data/user/0/<pkg>/` |
| `file` | `files/` |
| `database` | `databases/` |
| `sharedpref` | `shared_prefs/` |
| `external` | `Android/data/<pkg>/` |
| `device_root` / `device_file` / `device_database` / `device_sharedpref` | The same under DE storage (API 31+ format only) |

Always excluded, no rule needed: `cache/`, `code_cache/`, `no_backup/`.
Paths are **relative** — a leading `/` silently matches nothing.
Excluding `x.db` does **not** exclude `x.db-wal`.

---

## Severity rubric

| Observation | Severity on its own | What raises it |
|---|---|---|
| Token in `shared_prefs`, mode 0600, in the app's own dir | **Informational** | A second copy somewhere weaker; a long-lived token; a debuggable build |
| `allowBackup="true"` | **Informational** | Extracting the backup and showing a credential in it → High |
| World-readable file in an app dir | **Informational** | DAC path walkable **and** MCS permits **and** contents matter |
| File on external app-specific storage | **Low** | Contents are sensitive → Medium/High |
| Secret in logcat | **Medium** | Long-lived bearer credential, or a crash SDK uploading the buffer → High |
| Credential in DE storage | **Medium** | Confirmed readable before first unlock → High |
| Deleted rows recoverable from `-wal` | **Medium** | The product promised deletion → High |
| Secret in a shared collection | **High** | Survives uninstall; readable by any app with a media permission |

Always: **name the adversary**. A finding without one cannot be triaged.

---

## Traps

| Trap | Fix |
|---|---|
| Git Bash rewrites `/data/...` in argv | `MSYS_NO_PATHCONV=1` |
| `adb shell su -c "a b c"` runs only `a` | Pass as one argument, or base64-encode | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- trap table: this cell IS the wrong form -->
| `adb pull` onto NTFS drops modes | Read modes on the device |
| No `sqlite3` on device | Pull and use Python `sqlite3` |
| Keyguard blocks app-originated activity starts (MIUI) | `adb shell "dumpsys trust" \| grep -o "deviceLocked=[01]"` |
| `am start` does not redeliver to a `standard` activity | `android:launchMode="singleTop"` |
| `-wal` absent after app stops | Snapshot while the app is running |
| `File.exists()` false on an unreadable path | `EACCES` is reported as `false`; check as root |
| `INSTALL_FAILED_USER_RESTRICTED` on MIUI | `adb push` then `su -c 'pm install -r ...'` |
