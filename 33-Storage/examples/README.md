# 33 — Storage · Examples

Two apps, deliberately built as a pair. `leaky-vault/` encrypts a secret **correctly** and then
leaves the plaintext in four other places. `fixed-vault/` is the same app with every one of those
decisions reversed and the cryptography **byte-for-byte unchanged**.

Diff the two directories. Every difference is about *where bytes go*, not about how they are
protected. That is the entire argument of this chapter, expressed as a diff you can run.

---

## What is here

| Path | What it is |
|---|---|
| `build.sh` | No-Gradle build: `aapt2 link` → `javac` → `d8` → `zipalign` → `apksigner`. Builds **out of tree**; no `.apk`, `.dex` or `.class` ever reaches the repository |
| `leaky-vault/AndroidManifest.xml` | `allowBackup="true"`, `debuggable="true"`, no rules file, no `FLAG_SECURE` — and **no storage permissions at all**, which is the point |
| `leaky-vault/Vault.java` | Correct AES-256/GCM with an AndroidKeyStore key, surrounded by five leaks marked `LEAK-1` … `LEAK-5` |
| `leaky-vault/NoteStore.java` | SQLite in WAL mode with `secure_delete=OFF`. Its `clearSecretsOnLogout()` really does delete the rows and really does leave them on disk |
| `leaky-vault/StorageProbe.java` | A **measurement instrument**, not a vulnerability. Enumerates every root and tests the scoped-storage restrictions from inside an ordinary app |
| `leaky-vault/VaultActivity.java` | Headless-drivable entry point (`am start --es action …`) so a session is exactly reproducible |
| `leaky-vault/ExportActivity.java` | Writes to a **shared collection** (Downloads) via MediaStore, and via the legacy `File` API so you can watch the legacy path fail |
| `fixed-vault/AndroidManifest.xml` | `allowBackup="false"`, no `debuggable` |
| `fixed-vault/Vault.java` | `FIX-1` … `FIX-7`. Encrypt-then-write-once, atomic rename, `fsync`, key destruction as the only real deletion guarantee |
| `fixed-vault/NoteStore.java` | `secure_delete=ON`, `VACUUM`, then `wal_checkpoint(TRUNCATE)` — **in that order**, and the comment explains why the other order silently fails |
| `fixed-vault/VaultActivity.java` | `FLAG_SECURE`, and a `wipe` action |
| `fixed-vault/backup_rules.xml` | A **reference file**, not wired into this build. Shows the API 23–30 and API 31+ rules formats side by side and why you must ship both |

---

## Build and install

```bash
# host
export ANDROID_HOME=/path/to/Android/Sdk        # or ANDROID_SDK_ROOT
cd 33-Storage/examples
./build.sh                                       # build only
./build.sh --install                             # build, then install both
```

On the MIUI device this chapter was measured against, `adb install` may return
`INSTALL_FAILED_USER_RESTRICTED` — an OEM "Install via USB" policy, not a fault in the APK, and
nobody cancelled anything despite what the message says. `build.sh` detects that exact failure and
retries through `su -c 'pm install'`, which is not subject to the gate.

Then drive a session. Every step is an `am start`, so the sequence is identical on every run — a lab
whose "exercise the app" step is *tap around for a bit* cannot produce a diff anyone can reproduce.

```bash
# host
./build.sh --exercise                            # store, notes, logout, probe, export
```

```bash
# host — the individual actions
adb shell am start -n com.pentest.ch33.vault/.VaultActivity --es action store \
    --es secret "hunter2-REPLACE-ME"
adb shell am start -n com.pentest.ch33.vault/.VaultActivity --es action notes
adb shell am start -n com.pentest.ch33.vault/.VaultActivity --es action logout
adb shell am start -n com.pentest.ch33.vault/.VaultActivity --es action probe
adb shell am start -n com.pentest.ch33.vault/.ExportActivity
```

Clean up when you are finished. `--uninstall` also removes the file the leaky app wrote into the
shared **Downloads** collection, which uninstalling the app does *not* do:

```bash
# host
./build.sh --uninstall
```

---

## The five leaks, and where each one shows up

The apps exist so that each detection method can be seen succeeding *and* failing. This table is the
map; [`../labs/lab-02-filesystem-diff-across-a-session.md`](../labs/lab-02-filesystem-diff-across-a-session.md)
walks it.

| | Leak | Lands at | Found by a filesystem diff? | Found by a manifest audit? |
|---|---|---|---|---|
| `LEAK-1` | Plaintext staging file written before encryption | `cache/vault-staging.tmp` | **No** — it is deleted on the happy path, so it never exists at snapshot time | No |
| `LEAK-2` | "Debug export" outside the sandbox | `Android/data/<pkg>/files/debug/export.json` | Yes | No — the app declares no storage permission and needs none |
| `LEAK-3` | Duplicate token in preferences | `shared_prefs/session.xml` | Yes | No |
| `LEAK-4` | Secret in `Log.d` | logcat ring buffer | **No** — logcat is not a file in the app's tree | No |
| `LEAK-5` | Secret in device-encrypted storage | `/data/user_de/0/<pkg>/files/boot-token.txt` | Yes, **if** you snapshot the DE root — a scan of `/data/data` alone misses it entirely | No |
| — | Deleted rows surviving in the write-ahead log | `databases/notes.db-wal` | Only if you look at the companion files, and only before a checkpoint | No |
| — | Recents thumbnail (no `FLAG_SECURE`) | A system-owned directory, not the app's | **No** — written by `system_server`, outside this app's tree and outside every hook you can install in it | No — `FLAG_SECURE` is a window flag, not a manifest attribute |

Three of the seven are invisible to a filesystem diff and **all seven are invisible to a manifest
audit**. Any assessment built on one method reports a clean app.

---

## Deliberate limitations, so you do not mistake them for bugs

- **No `res/` directory.** Both apps build their UI in code so that `aapt2` only ever has a manifest
  to link and the build stays a dozen lines. The consequence is that `fixed-vault/backup_rules.xml`
  is **not wired in** — read its header, which explains how to wire it in a real project and why it
  ships as reference rather than as a live file.
- **No androidx.** `EncryptedSharedPreferences` and `EncryptedFile` would need Gradle, and they
  belong to [34-Cryptography](../../34-Cryptography/README.md) in any case. These apps use the
  framework's own `AndroidKeyStore` and JCA, which is enough to make the point that correct
  encryption does not prevent a plaintext copy.
- **The secrets are fake and named so no one can mistake them for real.** `sk_live_EXAMPLE_NOT_A_REAL…`, `ch33-recovery-code-889912`.
  They are shaped like real credentials so the detectors in
  [`../scripts/leak-hunter.py`](../scripts/leak-hunter.py) have something honest to match, and they
  are unmistakably synthetic so nobody reports them.
- **`launchMode="singleTop"` is a testing accommodation, not a design choice.** Without it a second
  `am start` for an already-top activity never reaches `onNewIntent`, and a scripted four-step
  exercise silently runs only its first step. The manifest comment records the failure in full.

---

## Two bugs this example had, found by running it

Both are recorded rather than quietly fixed, because the *symptom* is what makes them worth knowing:
in each case the app produced a `notes.db` that exists, is a valid SQLite file, and contains **no
tables**, with no error visible anywhere in the UI.

1. **`db.enableWriteAheadLogging()` inside `onConfigure()` throws.** `onConfigure` runs inside a
   transaction and WAL cannot be enabled from within one. The fix is
   `setWriteAheadLoggingEnabled(true)` on the helper, in the constructor.
2. **`execSQL("PRAGMA secure_delete = OFF")` throws.** That pragma returns a value, and `execSQL`
   refuses any statement that produces rows:
   `Queries can be performed using SQLiteDatabase query or rawQuery methods only`. Thrown from
   `onConfigure`, it propagates out of `getWritableDatabase()` so *every* database call fails, and
   the message mentions neither pragmas nor `onConfigure`. Use `rawQuery`.

Both were caught by running the app and looking at the disk — which is the method this whole chapter
teaches, applied to the chapter's own example.

---

## Cleanup and handling

`leaky-vault` is deliberately vulnerable. Install it on a device you own, and run
`./build.sh --uninstall` when you are finished. See [SECURITY.md](../../SECURITY.md) for the
handling rules.
