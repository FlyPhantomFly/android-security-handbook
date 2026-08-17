# 33 — Storage · FAQ

Real questions, including the ones people are embarrassed to ask. Those are usually the good ones.

---

### 1. Where does my app's data actually live?

In a directory named after your package, owned by your app's own Linux user account, at
`/data/user/<userId>/<yourPackage>`. For the primary user that is user 0, and the same directory is
also reachable as `/data/data/<yourPackage>`.

Inside it: `files/` for whatever you write, `cache/` for things you can afford to lose,
`databases/` for SQLite, `shared_prefs/` for the XML behind `SharedPreferences`, `code_cache/` for
compiled or extracted code, and `no_backup/` for things you do not want in a backup.

Do not hardcode `/data/data/<pkg>`. On a device with a work profile your app may be user 10 and the
path is `/data/user/10/<pkg>`. Call `getDataDir()` and let the framework tell you.

### 2. Why can't I see another app's files?

Because each app is a different *user* as far as Linux is concerned. Your app runs as uid 10314;
another runs as 10196. The directory's mode denies every uid but its owner, and the kernel enforces
that on every single `open()`.

There is a second, completely independent gate. SELinux gives each app's files a label carrying
unique category numbers, and refuses a read when the reader's categories do not match — *even if the
mode bits would have allowed it*. Two locks, different keys, both must open.

### 3. But I found a world-readable file in another app's directory. Can I read it?

Maybe. Check three things, in this order, and be prepared for the answer to be no twice.

**Is the path walkable?** `open()` resolves one directory at a time, and each one needs execute
permission for you to pass through. A mode-`0644` file inside a mode-`0700` directory is unreachable,
full stop. On the device this chapter was measured against, a scan turned up three world-readable
files in third-party app directories and **two of the three were blocked by a `0700` ancestor**.

**Do the SELinux categories permit it?** An ordinary app's files are labelled `app_data_file` with a
per-app category pair. Another ordinary app cannot read them regardless of mode.

**Is there anything in it?** The one file that passed both gates on the test device — and an
ordinary app with no permissions really did read it — contained SDK feature flags and crash-buffer
sizes. Informational. The mechanism is worth understanding; the file is not worth reporting.

### 4. What is the difference between internal and external storage when they are both on the same chip?

Nothing physical. This is the right question and almost nobody asks it.

The words date from when "external" meant a microSD card you could physically remove. On a phone
with no card slot, "external storage" is a directory on the same partition as everything else,
encrypted by the same subsystem.

What survives is administrative:

| | Internal | External app-specific |
|---|---|---|
| Owned by | Your app's uid | The media stack |
| Enforced by | The kernel, on every `open` | MediaProvider, a userspace app, per call |
| Readable by another app | No | No on API 30+; **yes** before that with one permission; yes to anything with all-files access |
| Permission to write | None needed | None needed |
| Removed on uninstall | Yes | Yes |

So: same chip, same encryption, wildly different guarantees. Put nothing sensitive on external
storage.

### 5. Is `/sdcard` a real SD card?

Almost certainly not. It is a symlink:

```bash
# adb shell
$ ls -l /sdcard
lrw-r--r-- 1 root root 21 /sdcard -> /storage/self/primary
```

`/storage/self/primary` is a FUSE mount that presents `/data/media/<userId>` — a directory on the
same internal partition. If the device genuinely has a card, it appears as a *second* volume with a
UUID-shaped name, and `getExternalFilesDirs()` returns more than one entry.

### 6. Why did my file survive uninstall?

Because it was never your file.

Anything you write into a **shared collection** — `Download/`, `DCIM/`, `Pictures/`, `Documents/` —
belongs to the *user*, not to your app. The system removes what belonged to your app when it
uninstalls: your `/data/user/0/<pkg>` tree, your `/data/user_de/0/<pkg>` tree, and your
`Android/data/<pkg>` directory. A photo in `DCIM/` is not in any of those. Deleting it because an
app was removed would mean uninstalling a camera app deletes your holiday photos.

If you want a file gone on uninstall, write it under `getExternalFilesDir()` or inside the app's own
directory — not into a shared collection.

### 7. What is the difference between CE and DE storage, in plain terms?

CE — credential-encrypted — is locked with a key derived from the user's PIN or password. Until
somebody unlocks the phone at least once after it boots, that key does not exist and the data cannot
be read *by anyone, including the system*.

DE — device-encrypted — is locked with a key tied to the device itself, available from the moment
the phone boots.

DE exists so your alarm still rings after a 3 a.m. reboot, and so a user who depends on a screen
reader can actually reach the unlock screen. That is a real safety requirement, not a convenience.

The security consequence: anything you put in DE storage is readable before the user has proved who
they are. If your boot-time code needs to know *whether* a credential exists, store a boolean there.
Do not store the credential.

### 8. My app encrypts everything. Am I done?

No, and this chapter exists mainly to answer that question.

Encryption decides whether the *encrypted file* is safe. It says nothing about the other five places
the same bytes may be sitting:

- a temporary file written before encryption and deleted afterwards — except on the error path;
- a diagnostic export on external storage, because support asked for one;
- a second copy in `SharedPreferences`, because another feature needed it synchronously;
- a `Log.d` from when somebody was debugging that second copy;
- rows in a database that a `DELETE` removed and the write-ahead log still holds.

[`examples/leaky-vault/Vault.java`](examples/leaky-vault/Vault.java) performs textbook-correct
AES-256/GCM with a non-exportable hardware key *in the same method* that creates all five.

### 9. I deleted the row. Why is the data still there?

Because `DELETE` is a statement about the table, not about the disk.

SQLite defaults to write-ahead logging: instead of editing the database file, it appends the changed
page to a companion file, `<db>-wal`. A `DELETE` rewrites a whole page, so the *previous* copy of
that page — containing your row — stays in the WAL until a checkpoint folds it away.

Measured on the example app: the logout code deleted two rows, SQL reported one row remaining, and
the 61 KB `notes.db-wal` still contained every deleted secret. The main database file was clean.

To actually remove it: `PRAGMA secure_delete=ON` from the start (it is not retroactive), then
`VACUUM`, then `PRAGMA wal_checkpoint(TRUNCATE)` — in that order. Doing the checkpoint first
truncates the WAL and then `VACUUM` immediately refills it, which is a mistake with no visible
symptom.

Better still: do not store the plaintext. Store a reference and keep the secret sealed under a key
you can destroy.

### 10. Is `allowBackup="true"` a vulnerability?

It is a **candidate**. On its own it is worth an informational note and nothing more.

It is also the *default*, so "the manifest does not set `allowBackup`" is not a defence — the
behaviour is identical.

To turn it into a finding: confirm no `fullBackupContent` or `dataExtractionRules` already excludes
what matters; confirm the backup channel actually works on this platform, because `adb backup` is
restricted or gone on many modern and OEM builds; extract; and show something sensitive in the
extract. That last step is the only one that sets the severity. An empty 1 KB `.ab` file is not proof
of protection — it is usually proof the transport refused for an unrelated reason.

### 11. Why does `adb shell` see files my test app cannot?

Because `adb shell` is a **more privileged principal than any app**. On the API 30 test device:

```bash
# adb shell
$ id
uid=2000(shell) ... groups=...,1015(sdcard_rw),1028(sdcard_r),1078(ext_data_rw),1079(ext_obb_rw),...
```

`ext_data_rw` (1078) is exactly what lets shell list `/sdcard/Android/data` — 111 entries, no
complaint. An ordinary app on the same device at the same moment gets `null` from `list()` on that
path.

This is the single most important practical fact in the chapter. **Every conclusion you draw about
app-to-app reachability using only `adb` is wrong by default.** If you want to know what an app can
see, ask an app. That is what
[`examples/leaky-vault/StorageProbe.java`](examples/leaky-vault/StorageProbe.java) is for.

### 12. What does `MANAGE_EXTERNAL_STORAGE` actually give an app?

Read and write across the **shared volume** — including every other app's `Android/data` and
`Android/obb` directories, which are otherwise closed on API 30+.

What it does **not** give: any access to another app's internal `/data/user/0/<pkg>` directory. That
is a different tree with a different enforcement mechanism, and no shared-storage permission touches
it. Conflating the two is a common over-claim in reports.

It is also not a normal permission. The device's own dump shows
`prot=signature|appop|preinstalled`, meaning it cannot be granted by a runtime dialog: the user is
walked out to a full-screen Settings page, and Play policy requires a written justification.

### 13. Is `cache/` safe because the system might delete it?

No. `cache/` is on the same disk, in the same directory tree, with the same permissions and the same
reachability as `files/`. The only differences are that the system *may* reclaim it under storage
pressure — *may*, not will, and possibly never — and that it is excluded from backups.

Treating "temporary" as "does not count" is precisely how the plaintext staging file in the example
app comes to exist. If it is sensitive, it does not go in `cache/` any more than it goes anywhere
else.

### 14. Does file-based encryption protect my app's data from other apps?

No. That is the sandbox's job, not encryption's.

Every process on a booted phone sees plaintext, because the kernel decrypts transparently for anyone
the keys are installed for. A root shell reads your `shared_prefs` in cleartext. Another app is
blocked by uid permissions and SELinux — not by encryption.

FBE protects against someone holding the *hardware*: a stolen, powered-off phone. That is an
enormously valuable guarantee and it is a completely different one. "The data is encrypted at rest"
is never a valid answer to a finding about a running device, and always a valid answer to a finding
about a stolen one. Work out which conversation you are in before it goes anywhere else.

### 15. Is a secret in `Log.d` really a problem? Nobody can read logcat.

On a modern device an ordinary app cannot, that is true — `READ_LOGS` is signature-level and a normal
app cannot obtain it.

Four other principals can, and all four matter: `adb shell` on any host the user has authorised;
root; **every SDK running inside your own process**, including crash reporters that upload the buffer
wholesale; and anyone who obtains those uploaded crash reports.

So the honest framing is not "any app can steal this". It is "this secret leaves the device inside
crash reports and is visible to anyone with a USB cable and developer mode". Usually Medium, and High
when the value is a long-lived bearer credential — because that credential then works from anywhere.

### 16. What is FUSE and why should I care?

FUSE lets an ordinary userspace program implement a filesystem: the kernel forwards each `open`,
`read` and `readdir` to that program and waits for its answer.

On Android 11 and later, `/sdcard` is a FUSE mount served by **MediaProvider**, which is a normal
Android app. So the rules governing shared storage are *application logic*, not kernel policy — which
is why they can differ by calling package, by path, by file type and by API level, and why they have
changed materially in three consecutive releases.

Two practical consequences. First, `/sdcard` file ownership is synthesised: everything shows as
`root:everybody` regardless of who wrote it, so you can never attribute a file there by its uid.
Second, a Frida hook on `open()` inside your app sees the call and never sees what MediaProvider
decided — the decision happens in another process.

### 17. Should I use `EncryptedSharedPreferences`?

Generally yes, and it belongs to [34-Cryptography](../34-Cryptography/README.md) rather than here.

Two things worth knowing from the storage side. It changes the file *contents*, not the file
*location* or the write path — the file is still `shared_prefs/x.xml` at mode `0600`, still in the
backup set unless excluded, and still readable in cleartext by an in-process hook on a rooted device.
And its value collapses entirely if the same data is *also* stored unencrypted somewhere else, which
34 notes is "a surprisingly common finding". That second copy is this chapter's subject.

### 18. Can I stop screenshots of my app appearing in the recents switcher?

Yes — `FLAG_SECURE`, and only `FLAG_SECURE`:

```java
// Android app code
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                     WindowManager.LayoutParams.FLAG_SECURE);
```

Set it before `setContentView`, and on **every** window that can show the secret. It is per-window,
not per-application, and the classic mistake is setting it on the login screen and forgetting the
account screen that displays the same data afterwards.

`android:excludeFromRecents` and `android:noHistory` do **not** prevent the snapshot. And because
`FLAG_SECURE` is a window flag rather than a manifest attribute, no manifest audit can ever detect
its absence — you have to open the screen, press recents, and look.

### 19. My filesystem diff shows nothing. Does that mean the app is clean?

No. It means the app wrote nothing *persistent* to the roots you snapshotted between the two
snapshots. There are at least five ways to get an empty diff from a leaky app:

- the file was created and deleted between the snapshots — measured, this is exactly what happens to
  the example app's plaintext staging file, so a diff finds 4 of its 5 leaks;
- you snapshotted `/data/data` and the write went to `/data/user_de`;
- the leak was to logcat or the clipboard, which are not files;
- the leak was the recents thumbnail, which `system_server` writes outside your app's tree;
- the app never ran the code path, because your exercise did not reach it.

Run a write tracer alongside the diff, capture logcat, and script the exercise so you know exactly
what you did and did not touch.

### 20. Why is my Windows tool reporting that `/data/local/tmp` does not exist on the device?

Because Git Bash rewrote the path before your program ever saw it. MSYS converts anything that looks
like a Unix absolute path in `argv`, so `--root /data/local/tmp/x` arrives as
`C:/Program Files/Git/data/local/tmp/x`. The tool then faithfully reports that the directory does not
exist, and the error points at the device instead of at your shell.

```bash
# host
MSYS_NO_PATHCONV=1 python3 -B scripts/storage-diff.py snapshot --root /data/local/tmp/x --out a.json
```

[`scripts/storage-diff.py`](scripts/storage-diff.py) detects this specific mangling and prints the
fix rather than blaming the device.

### 21. How do I copy an app's private data off the device?

`adb pull /data/data/<pkg>` fails, because `adb` runs as the shell user and the shell user cannot
read it. Tar it as root into a location shell *can* read, pull that, and clean up:

```bash
# host
adb shell "su -c 'tar cf /data/local/tmp/x.tar /data/user/0/<pkg> /data/user_de/0/<pkg>; chmod 644 /data/local/tmp/x.tar'"
MSYS_NO_PATHCONV=1 adb pull /data/local/tmp/x.tar .
adb shell "su -c 'rm -f /data/local/tmp/x.tar'"
```

Two caveats. On a *debuggable* app you need no root at all — `run-as <pkg>` gives you the app's own
identity, which is why `android:debuggable="true"` in a release build is such a serious finding. And
`adb pull` onto NTFS silently discards mode bits, so never answer permission questions from pulled
files: ask the device.

### 22. Where do I even start on an app I have never seen?

In this order, because it finds the most for the least effort:

1. `grep` the manifest for `allowBackup`, `debuggable`, and the storage permissions. One minute, and
   it tells you which later steps will pay.
2. `./scripts/storage-map.sh <pkg> --media` — which roots exist at all, and what is in them.
3. `pm clear`, snapshot, scripted exercise, snapshot, diff — with a write tracer attached.
4. `leak-hunter.py` over the pulled data. Treat the output as a queue, not a result.
5. logcat, the clipboard, and the recents thumbnail, which steps 2 to 4 structurally cannot find.

Then, for every candidate, answer three questions before it becomes a finding: **who can reach it,
what is in it, and what does that let them do.** A candidate that fails any of the three is an
observation and belongs in an appendix.
