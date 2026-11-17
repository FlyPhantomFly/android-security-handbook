# 33 — Storage · References

Two rules govern this list.

**AOSP file paths are given without line numbers.** Paths are stable across releases; line numbers
are not, and a wrong line number is worse than no line number because it looks authoritative. Open
the file and search for the named symbol.

**No CVE identifier is invented.** Where a vulnerability class matters but the specific identifier is
not something this chapter verified, the class is described by its shape — which is what you match
against in the field anyway.

---

## 1. AOSP source

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/os/Environment.java` | You need to know where an external path comes from. `UserEnvironment` builds every one of them from environment variables set at fork time, which is why they differ per user and why hardcoding `/storage/emulated/0` breaks on a work profile |
| `frameworks/base/core/java/android/app/ContextImpl.java` | Tracing `getFilesDir()`, `getCacheDir()`, `getNoBackupFilesDir()`. `ensurePrivateDirExists` is why those directories do not exist until first use; `getDataDir()` is the fork between credential- and device-encrypted storage |
| `frameworks/base/core/java/android/app/SharedPreferencesImpl.java` | Understanding `apply()` versus `commit()`, the `.bak` file left behind by a crash mid-write, and the `FileUtils.setPermissions` call that produces `-rw-rw----` on every preference file |
| `frameworks/base/core/java/android/app/backup/FullBackup.java` | Working out which `domain` names a backup rules file may use, and what each maps to on disk |
| `frameworks/base/core/java/android/app/backup/BackupAgent.java` | The contract an app's own backup agent implements, and what the default full-backup path includes |
| `packages/providers/MediaProvider/src/com/android/providers/media/MediaProvider.java` | **The scoped-storage policy itself.** Who may see whose files, the owner checks, and the bypass conditions. This is application logic, not kernel policy, which is why shared-storage behaviour varies by release |
| `packages/providers/MediaProvider/jni/FuseDaemon.cpp` | The FUSE upcall handler that sits in the path of every shared-storage syscall. Read it when you need to know why an `open` on `/sdcard` behaved differently from one on `/data` |
| `system/vold/FsCrypt.cpp` | How credential- and device-encrypted keys are installed into the kernel keyring and bound to directories |
| `system/vold/KeyStorage.cpp` | How those keys are wrapped with the user's credential and a Keymaster/KeyMint-held secret. This is what makes offline brute-forcing of the lock screen infeasible |
| `frameworks/base/services/core/java/com/android/server/pm/Installer.java` | How app data directories are created, cleared and destroyed. The other end of `pm clear` |
| `frameworks/native/cmds/installd/InstalldNativeService.cpp` | The privileged service that actually performs those operations, including the Android 11 data-mirror bind mounts |
| `libcore/luni/src/main/native/libcore_io_Linux.cpp` | The JNI layer between Java file I/O and the `open` syscall. The last stop before bionic |
| `system/core/logd/` | The logcat ring buffers. Read it when arguing about who can read a log and for how long it persists |
| `frameworks/base/core/java/android/content/ClipboardManager.java` | Clipboard semantics, and the Android 13 `EXTRA_IS_SENSITIVE` flag |

---

## 2. Official Android documentation

| Document | Why it is worth reading, and what it will not tell you |
|---|---|
| **Data and file storage overview** | The canonical map of every storage option. The one page to hand a developer who asks where something should go. It does not discuss reachability by other principals |
| **Storage updates in Android 11** | The definitive statement of what scoped storage enforced and of the `requestLegacyExternalStorage` behaviour change. Read it alongside a measurement — it describes intent, and OEM builds vary |
| **Direct Boot** | Credential- versus device-encrypted storage, `directBootAware`, `LOCKED_BOOT_COMPLETED`, and `createDeviceProtectedStorageContext()`. It is clear on the mechanism and silent on the security trade-off, which is section 3.3 of this chapter |
| **File-Based Encryption** (AOSP, Security) | The CE/DE key hierarchy, what each key is bound to, and metadata encryption. The place to check before claiming anything about what encryption at rest does or does not buy |
| **Access documents and other files using SAF** | `ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`, `ACTION_OPEN_DOCUMENT_TREE`, and `takePersistableUriPermission`. The persistence semantics are the part that matters for an audit |
| **MediaStore reference** | The collections, `IS_PENDING`, `OWNER_PACKAGE_NAME`, `RELATIVE_PATH` and `createWriteRequest`. `OWNER_PACKAGE_NAME` is documented as an attribution feature and is equally a privacy surface |
| **Back up user data with Auto Backup** | `dataExtractionRules`, `fullBackupContent`, the domain names, and the 25 MB cap. It does **not** emphasise that shipping only the newer attribute leaves an app unprotected below API 31 |
| **Save data in a local database using Room** | Relevant because Room changes nothing on disk: same SQLite file, same WAL, same defaults |
| **Android Keystore system** | Where the key that makes crypto-shredding possible lives. Depth is in [49-KeyStore](../../49-KeyStore/README.md) |

---

## 3. SQLite documentation

| Document | Why |
|---|---|
| **Write-Ahead Logging** (sqlite.org) | The authoritative description of why `<db>-wal` exists, when a checkpoint occurs, and why the file is deleted on a clean close — which is why the WAL's *absence* proves nothing |
| **PRAGMA secure_delete** | What it costs and what it does not cover. Note explicitly that it is not retroactive |
| **PRAGMA wal_checkpoint** | The difference between `PASSIVE`, `FULL`, `RESTART` and `TRUNCATE`. Only `TRUNCATE` resets the file to zero length |
| **VACUUM** | Why it is the only way to reclaim residue from deletions made before `secure_delete` was enabled, and why it needs temporary space roughly equal to the database |
| **The SQLite file format** | Page structure and the freelist — the basis of every carving tool that recovers deleted rows from the main database file |

---

## 4. OWASP MASVS and MASTG

| Identifier | What it asks | Where this chapter answers it |
|---|---|---|
| **MASVS-STORAGE-1** | The app stores sensitive data securely | [README §3.5](../README.md#35-inside-the-app-directory), [§3.10](../README.md#310-sqlite-on-disk), [§3.11](../README.md#311-sharedpreferences-on-disk), [§5.4](../README.md#54-vulnerability-class--the-plaintext-copy-beside-the-ciphertext) |
| **MASVS-STORAGE-2** | The app prevents leakage of sensitive data through backups, logs, external storage and device-encrypted storage | [§3.6](../README.md#36-external-app-specific-storage), [§3.9](../README.md#39-the-stores-that-are-not-files), [§3.12](../README.md#312-the-backup-channels), [§5.5](../README.md#55-vulnerability-class--residual-data-after-deletion), [§5.6](../README.md#56-allowbackup-a-candidate-not-a-finding) |
| **MASVS-PRIVACY-1 / -2** | Data minimisation and non-identification | [§3.7](../README.md#37-shared-collections-and-mediastore) — MediaStore's `owner_package_name` yields an installed-app fingerprint and a behaviour profile with no package-visibility permission |
| **MASVS-PLATFORM-3** | The app does not expose sensitive data through the user interface | [§3.9](../README.md#39-the-stores-that-are-not-files) — recents thumbnails, `FLAG_SECURE`, clipboard |
| **MASTG** — testing local storage for sensitive data | The core storage test | [§7](../README.md#7-dynamic-analysis), [lab-02](../labs/lab-02-filesystem-diff-across-a-session.md) |
| **MASTG** — testing logs for sensitive data | Log capture | [§3.9](../README.md#39-the-stores-that-are-not-files), [§7.1](../README.md#71-the-method-filesystem-diff-plus-log-capture) |
| **MASTG** — testing backups for sensitive data | Backup extraction | [§5.6](../README.md#56-allowbackup-a-candidate-not-a-finding), and the chain in [21-App-Sandbox §5.5](../../21-App-Sandbox/README.md) |
| **MASTG** — finding sensitive data in the recents screen | `FLAG_SECURE` | [§3.9](../README.md#39-the-stores-that-are-not-files) |

[71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) names the method for MASVS-STORAGE as
**"filesystem diff + log capture"**. That is exactly [§7.1](../README.md#71-the-method-filesystem-diff-plus-log-capture).

---

## 5. Vulnerability classes

Described by shape rather than by identifier, for the reason given at the top of this file.

| Class | Shape | Where it is covered |
|---|---|---|
| World-readable or world-writable app files | `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`, or a native component calling `chmod` directly and bypassing the framework entirely. The framework modes throw from API 24; the native path does not | [§5.3](../README.md#53-honest-severity-a-worked-example) |
| Path traversal through a misconfigured `FileProvider` | A `<root-path>` or over-broad `<files-path>` in the provider's paths XML, reaching `shared_prefs/` or `databases/` and their WAL companions | [27-ContentProviders](../../27-ContentProviders/README.md) owns the exploitation; this chapter owns what the traversal reaches |
| Sensitive data in device-encrypted storage | A credential moved to DE storage so a boot-time component could use it, recoverable from a locked but powered-on device | [§3.3](../README.md#33-direct-boot); the vulnerability class itself is [09 §5.7](../../09-Android-App-Internals/README.md) |
| Residual data after deletion | A `DELETE` the app reports as successful, with the rows intact in `<db>-wal` or in the main file's free pages | [§3.10](../README.md#310-sqlite-on-disk), [§5.5](../README.md#55-vulnerability-class--residual-data-after-deletion) |
| Backup extraction of credentials | `allowBackup` enabled with no exclusion rules, or rules that exclude `x.db` and miss `x.db-wal`, or that set only `dataExtractionRules` and are therefore inert below API 31 | [§3.12](../README.md#312-the-backup-channels), [§5.6](../README.md#56-allowbackup-a-candidate-not-a-finding) |
| Cross-app exposure through shared storage | Pre-scoped-storage devices where one broad permission reached every app's `Android/data`, plus the enumerable list of installed packages that came with it | [§3.13](../README.md#313-version-matrix) |
| The plaintext copy beside the ciphertext | Correct encryption, with the cleartext also present in a cache file, an export, a preference, a log or a WAL | [§5.4](../README.md#54-vulnerability-class--the-plaintext-copy-beside-the-ciphertext) |

---

## 6. Research, talks and background

- **Google I/O and Android Dev Summit sessions on scoped storage** — the clearest statements of the
  intent behind the FUSE migration and the API 29/30 split. Useful for understanding *why* the
  behaviour is inconsistent across releases rather than merely cataloguing that it is.
- **The Android Security Paper** (Google) — the platform's own account of the application sandbox and
  file-based encryption. Read it for the threat model the platform designers held, which is the
  yardstick your findings are implicitly measured against.
- **Mobile forensics literature on SQLite recovery** — the WAL and free-page carving techniques used
  in [§5.5](../README.md#55-vulnerability-class--residual-data-after-deletion) were developed in the
  forensics community and predate Android. They apply unchanged, which is worth knowing because the
  best material on residual data is not in the mobile-security literature at all.
- **f2fs design documentation** (kernel.org) — why a log-structured filesystem allocates new blocks
  for an overwrite, and therefore why "overwrite the file before deleting it" is a gesture rather
  than an erase.
- **FUSE documentation** (kernel.org) — the protocol between the kernel and the userspace daemon.
  Read it if you need to reason about what a hook inside the app process can and cannot observe.

---

## 7. Tooling used in this chapter

| Tool | What it is used for here |
|---|---|
| `adb` | Everything.`adb shell` is a *more privileged principal than any app* — section 3.13 |
| `frida` / `frida-server` | [`../scripts/storage-trace.js`](../scripts/storage-trace.js), for the writes a filesystem diff structurally cannot see. Depth in [53-Frida](../../53-Frida/README.md) |
| `objection` | `env` prints every storage root in one command — the fastest possible orientation |
| `apktool`, `jadx` | Manifest and DEX inspection, section 8 |
| `aapt2`, `d8`, `zipalign`, `apksigner` | [`../examples/build.sh`](../examples/build.sh) builds both example apps with no Gradle |
| Python `sqlite3` (read-only URI mode) | There is **no `sqlite3` binary on a stock device**. Pull the database and analyse it on the host |
| `toybox find -printf` | The snapshot engine behind [`../scripts/storage-diff.py`](../scripts/storage-diff.py).`%y` is not supported — the type comes from `%M`'s first character |

---

## 8. This chapter's own artefacts

| File | What it does |
|---|---|
| [`../scripts/storage-diff.py`](../scripts/storage-diff.py) | Snapshot and diff an app's whole on-disk footprint across six roots; classifies every change and computes DAC reachability, while stating explicitly that it does not compute the SELinux gate |
| [`../scripts/leak-hunter.py`](../scripts/leak-hunter.py) | Type-aware credential hunting across preferences, SQLite (including `-wal`), JSON, text and binaries — with a numbered false-positive list that is not optional reading |
| [`../scripts/storage-map.sh`](../scripts/storage-map.sh) | Enumerate every root for one package with modes, SELinux labels and per-file reachability |
| [`../scripts/storage-trace.js`](../scripts/storage-trace.js) | Frida tracer for file writes, preferences, SQLite, logs, the clipboard and native `open`/`openat` |
| [`../examples/leaky-vault/`](../examples/leaky-vault/) | Correct AES-256/GCM surrounded by five leaks, plus `StorageProbe.java`, the measurement instrument behind every API 30 claim in this chapter |
| [`../examples/fixed-vault/`](../examples/fixed-vault/) | The same app with each decision reversed and the cryptography unchanged |
| [`../labs/`](../labs/) | Four labs, ending in a CTF |

---

## 9. Related chapters

| Chapter | Relationship |
|---|---|
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | Chapter 09 owns the data directory's *identity* — uid assignment, `packages.list`, the supplementary-GID table, the CE/DE API surface and `pm clear` semantics; this chapter owns *what is inside those directories and who can reach it* |
| [**21-App-Sandbox**](../../21-App-Sandbox/README.md) | **Owns sandbox enforcement and what scoped storage *is*, including the `allowBackup` extraction chain; this chapter owns the storage *mechanisms* and the testing method. Read 21 §3.11 first** |
| [23-Permissions](../../23-Permissions/README.md) | Owns the permission string and its *grant state*, including the measured retirement of the legacy storage GIDs on modern releases; this chapter owns *what the filesystem does once a grant exists, and what it does when there is none* |
| [22-SELinux](../../22-SELinux/README.md) | The second reachability gate. Its MCS arithmetic decides whether a world-readable file is readable in practice, and this chapter's §5.3 is a worked instance of that |
| [34-Cryptography](../../34-Cryptography/README.md) | Owns whether the ciphertext is *sound*, and `EncryptedSharedPreferences` / `EncryptedFile` / Tink; this chapter owns *where that output landed and what landed beside it*. 34 lists 33 as a prerequisite |
| [49-KeyStore](../../49-KeyStore/README.md) | Where the non-exportable key lives — and therefore the only mechanism that makes deletion on flash storage meaningful |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Owns `FileProvider` exploitation and path traversal; this chapter owns what such a traversal *reaches* |
| [10-APK-Internals](../../10-APK-Internals/README.md) | The APK container, and the data an app ships inside it in `assets/` and `res/raw/` |
| [19-Memory](../../19-Memory/README.md) | The copy that never reaches disk, and the measured reason a `byte[]` beats a `String` for a secret |
| [32-Manifest](../../32-Manifest/README.md) | The declaration audit for `allowBackup`, `directBootAware`, `debuggable` and the storage permissions |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Why storage calls survive R8, and what `-assumenosideeffects` on `android.util.Log` does and does not strip |
| [53-Frida](../../53-Frida/README.md) | The instrumentation behind `storage-trace.js` |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Maps every finding here to MASVS-STORAGE and MASVS-PRIVACY, and names this chapter's method as the standard one |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | Its `lab-04-storage-diff` is the short-form version of this chapter's §7 method |
