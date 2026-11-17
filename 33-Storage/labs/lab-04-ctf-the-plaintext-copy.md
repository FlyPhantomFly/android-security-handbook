# Lab 04 — CTF: The Plaintext Copy

**Difficulty:** Expert / CTF
**Time:** 180 minutes
**Prerequisites:** [Lab 01](lab-01-map-the-eight-roots.md),
[Lab 02](lab-02-filesystem-diff-across-a-session.md),
[Lab 03](lab-03-scoped-storage-and-fuse.md),
[Chapter 33 §3.1–3.9, §5](../README.md),
[34-Cryptography](../../34-Cryptography/README.md), a rooted device, Frida, Python 3

---

## Objective

Recover four flags of the form `CH33{...}` from an app that **encrypts its data correctly**.

The target uses AES-256/GCM with a random per-operation IV and a non-exportable key generated inside
the AndroidKeyStore. [34-Cryptography](../../34-Cryptography/README.md) would grade that Tier 1. A
reviewer reading the `seal()` method signs it off. A static scanner hunting for hardcoded keys, ECB
mode or fixed IVs finds nothing. There is no cryptography to break in this challenge and no key to
recover — attacking the cipher is explicitly out of scope and will waste your evening.

Every flag is somewhere the plaintext went **anyway**.

### Scoring

| Stage | What it tests | Points |
|---|---|---|
| 1 | The plaintext copy on external app-specific storage | 10 |
| 2 | Residual data in a SQLite write-ahead log after a real `DELETE` | 25 |
| 3 | A value that never persisted — created and deleted between any two snapshots | 30 |
| 4 | Distinguishing a reachable exposure from an unreachable decoy | 35 |
| — | **Penalty** for submitting the decoy flag from stage 4 | **−15** |

100 points available. A scanner-driven run scores 10 and then loses 15.

### Rules

- **No `su` for the recovery itself.** You may use root to *set up* and to *verify*, but every flag
  must be recoverable by an adversary you can name, and you must name that adversary when you submit
  it. A flag you read as uid 0 and cannot attribute to a realistic attacker scores nothing.
- **No grepping the source you are about to write.** You build the challenge, so you will have seen
  the constants. The flags are not the point; the recovery method is. Submit the *method* alongside
  each flag, and if you find yourself unable to describe how you would have found it without the
  source, you have not finished that stage.
- **No breaking the cryptography.** Not because you could not — because it is a different chapter's
  exercise and it is not how this app fails.
- **Stage 4 must be argued, not scanned.** A world-readable file is a candidate, never a finding.

## Why this matters

This is the signature finding of chapter 33 and one of the most common real findings in mobile
security work: **an application that encrypts correctly and leaves the plaintext somewhere else.**

It matters because it defeats the two cheapest forms of assurance simultaneously. A code review of
the crypto passes, because the crypto is right. An automated scan passes, because the scanner looks
for weak ciphers, hardcoded keys and permissive mode bits, and this app has none of those. The
finding exists only for someone who asks a different question: not *is this encrypted*, but *where
did the plaintext go on the way here, and what else has a copy*. Once you have done that once, "the
data is encrypted at rest" stops functioning as an answer and becomes a claim about one file.

> **Mental Model**
> Encryption is a property of a **byte sequence at a location**, not of a value. A secret that passes
> through five locations is protected at exactly those locations where somebody chose to protect it,
> and the security of the whole is the security of the **weakest copy**, not the strongest. Your job
> is never to evaluate the strongest copy; it is to enumerate all of them.

---

## Setup

You build the challenge yourself. The repository ships no APK and this lab creates no files inside
it: everything below is yours to create, in a scratch directory of your own, outside the repo.

### Step 0 — Make a working copy of the examples

```bash
# host
mkdir -p ~/ch33-ctf
cp -r Android-Pentesting-Notes/33-Storage/examples/* ~/ch33-ctf/
ls ~/ch33-ctf
```

You now have your own `build.sh`, `leaky-vault/` and `fixed-vault/`. Everything you edit from here is
in `~/ch33-ctf`, never in the repository.

### Step 0b — Add the challenge activity

Save this as **`~/ch33-ctf/leaky-vault/ChallengeActivity.java`**. It is yours to create;
[`../examples/build.sh`](../examples/build.sh) compiles every `*.java` in the app directory, so
dropping it in is all that is required.

```java
// ~/ch33-ctf/leaky-vault/ChallengeActivity.java
//
// The CTF driver for 33-Storage lab 04. It seeds four flags into four
// structurally different places, using only mechanisms already present in
// Vault.java and NoteStore.java. Do not ship this.

package com.pentest.ch33.vault;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;

public class ChallengeActivity extends Activity {

    // Change these before running the challenge for somebody else.
    static final String STAGE1 = "CH33{d3bug_3xp0rt_1s_st1ll_st0rag3}";
    static final String STAGE2 = "CH33{d3l3t3d_r0ws_l1v3_1n_th3_w4l}";
    static final String STAGE3 = "CH33{n0_f1l3_n0_pr0bl3m_r1ght}";
    static final String STAGE4 = "CH33{r34ch4b1l1ty_n0t_m0d3_b1ts}";
    static final String DECOY  = "CH33{m0d3_b1ts_w1th0ut_r34ch4b1l1ty}";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setTextSize(12);
        tv.setPadding(32, 48, 32, 32);
        setContentView(tv);

        StringBuilder log = new StringBuilder("CH33 CTF -- challenge seeded\n\n");
        try {
            stage1();  log.append("stage 1 ok\n");
            stage2();  log.append("stage 2 ok\n");
            stage3();  log.append("stage 3 ok\n");
            stage4();  log.append("stage 4 ok\n");
        } catch (Throwable t) {
            Log.e(Vault.TAG, "challenge setup failed", t);
            log.append("FAILED: ").append(t).append('\n');
        }
        log.append("\nFour flags are on this device. None of them is in vault.bin.\n");
        tv.setText(log.toString());
    }

    /** Stage 1. The vault seals it correctly -- and copies it out four times. */
    private void stage1() {
        new Vault(this).store("primary-account", STAGE1);
    }

    /** Stage 2. A real INSERT, a real DELETE, and no erasure. */
    private void stage2() {
        NoteStore ns = new NoteStore(this);
        ns.addNote("Bank", "checking account", STAGE2);
        ns.addNote("Mail", "recovery address", "ch33-recovery-code-889912");
        ns.addNote("Shopping list", "milk, bread", null);
        ns.clearSecretsOnLogout();
    }

    /** Stage 3. Written and unlinked in one method. The Log.v under a
     *  DIFFERENT tag is the second recovery route. */
    private void stage3() throws Exception {
        File tmp = new File(getCacheDir(), "stage3-staging.tmp");
        write(tmp, STAGE3);
        tmp.delete();
        Log.v("CH33Stage3", "staged and removed: " + STAGE3);
    }

    /** Stage 4. One world-readable file that is unreachable, one mode-0600 file
     *  that a whole class of apps can read. Mode bits rank them backwards. */
    private void stage4() throws Exception {
        // The decoy: o+r, inside files/ inside a package directory at 0700.
        File decoy = new File(getFilesDir(), "PUBLIC-READ-ME.txt");
        write(decoy, DECOY + "\n");
        decoy.setReadable(true, false);   // equivalent to chmod o+r

        // The real one: app-specific MEDIA storage, which MediaStore indexes.
        File[] media = getExternalMediaDirs();
        if (media != null && media.length > 0 && media[0] != null) {
            File audit = new File(media[0], "audit");
            audit.mkdirs();
            write(new File(audit, "keys.txt"), STAGE4 + "\n");
        }
    }

    private static void write(File f, String s) throws Exception {
        File parent = f.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        FileOutputStream fos = new FileOutputStream(f);
        try {
            fos.write(s.getBytes("UTF-8"));
        } finally {
            fos.close();
        }
    }
}
```

### Step 0c — Declare it

Add this `<activity>` element inside the `<application>` block of
**`~/ch33-ctf/leaky-vault/AndroidManifest.xml`**, alongside the two that are already there:

```xml
<!-- ~/ch33-ctf/leaky-vault/AndroidManifest.xml -- inside <application> -->
<activity
    android:name=".ChallengeActivity"
    android:exported="true"
    android:launchMode="singleTop"
    android:label="CH33 CTF" />
```

`launchMode="singleTop"` is not decoration. Without it, a second `am start` for an activity already
at the top of its task delivers no new Intent and `adb` prints *Activity not started, intent has been
delivered to currently running top-most instance* — which reads like success.

### Step 0d — Build, install, arm

```bash
# host
cd ~/ch33-ctf
./build.sh --install
adb shell pm clear com.pentest.ch33.vault
adb shell "am start -n com.pentest.ch33.vault/.ChallengeActivity"
```

Now **stop looking at your source**. Close the editor. From here you are a tester who has been handed
a device and a package name.

> **Warning**
> The leaky app writes a file into the shared Downloads collection that survives its own uninstall,
> and this challenge leaves a file in `Android/media/<pkg>/`. Clean up with `./build.sh --uninstall`
> from `~/ch33-ctf` when you are finished, and delete `~/ch33-ctf` itself — it contains your flags in
> plaintext, which is a small irony worth noticing.

### Environment traps you will hit

| Trap | Symptom | Fix |
|---|---|---|
| No `sqlite3` on the device | `/system/bin/sh: sqlite3: inaccessible or not found` | Pull the DB, use Python's `sqlite3`, or `strings` / `grep -a` |
| `adb pull` onto NTFS | Every pulled file has the same meaningless mode | Read modes **on the device** with `ls -l`, never from the copy |
| Git Bash path rewriting | `/data/local/tmp/x` becomes `C:/Program Files/Git/data/local/tmp/x` | `MSYS_NO_PATHCONV=1` |
| `adb shell` quoting | `su -c "ls -l /data/data"` runs only `ls` | Pass the whole command as **one** argument |
| MIUI keyguard | `am start` reports success, nothing happens | `adb shell "dumpsys trust" \| grep -o "deviceLocked=[01]"` |

---

## Steps

### Step 1 — Reconnaissance: map before you hunt

```bash
# host
cd Android-Pentesting-Notes/33-Storage
./scripts/storage-map.sh com.pentest.ch33.vault
./scripts/storage-map.sh com.pentest.ch33.vault --media
```

Every flag is under one of the roots this prints, or in a store that is not a path at all. Before
running a single grep, write down which roots exist and which of them an **unprivileged** adversary
can reach. You are going to be asked to name the adversary for each flag, and doing that at the end
is how people end up submitting root-only reads as findings.

**Q1.** Which of the roots can `adb shell` read without `su` on your device? Which can an ordinary
third-party app with no permissions read?

### Step 2 — Stage 1 (10 points): the easy one

The app has a debug export feature. Support asked for it.

```bash
# adb shell — note: no su
cat /storage/emulated/0/Android/data/com.pentest.ch33.vault/files/debug/export.json
```

That yields stage 1. Confirm what else has a copy of the same value:

```bash
# adb shell as root
cat /data/user/0/com.pentest.ch33.vault/shared_prefs/session.xml
cat /data/user_de/0/com.pentest.ch33.vault/files/boot-token.txt
```

One more copy is in the log buffer — `adb logcat -d -s CH33Vault | grep -i "stored secret"`. One
secret, several copies, one of them outside the uid sandbox and readable without root.

**Q2.** The same value is in `files/vault.bin` too — sealed with AES-256/GCM under an
AndroidKeyStore key. Explain, in one sentence, what that encryption bought the user here.

**Q3.** Name the adversary for stage 1. Be specific: what does that adversary need, and is the answer
different on Android 10 than on Android 11?

### Step 3 — Stage 2 (25 points): the delete that was real

Look at the app's logout path.

```bash
# host
adb logcat -d -s CH33Vault | grep -i logout
```

The reference measurement of the equivalent session reads `logout: deleted 2 rows carrying a secret`,
and the SQL agrees — afterwards `SELECT COUNT(*)` reports `rows visible to SQL: 1`. The developer is
not lying. The rows are gone from the table.

Now look at the disk. There is **no `sqlite3` binary on the device**, so pull:

```bash
# host
adb shell "su -c 'ls -l /data/user/0/com.pentest.ch33.vault/databases/'"
adb shell "su -c 'cp -r /data/user/0/com.pentest.ch33.vault/databases /data/local/tmp/db'"
adb shell "su -c 'chmod -R 755 /data/local/tmp/db'"
adb pull /data/local/tmp/db ./db
```

Measured file sizes after a `store,notes,logout` session on the reference device:

| File | Size |
|---|---|
| `notes.db` | 4096 |
| `notes.db-shm` | 32768 |
| `notes.db-wal` | **61832** |

Then scan all three for residue. Save this as your own `wal-scan.py` and run
`python3 -B wal-scan.py ./db`:

```python
# host -- wal-scan.py: residual-string scan over a SQLite file and its companions
import re, sys, pathlib

# Flag-shaped values, plus the column contents the app claims to have deleted.
PATTERNS = [rb'CH33\{[^}]{1,80}\}', rb'sk_live_[A-Za-z0-9]{8,}',
            rb'ch33-recovery-code-\d+', rb'recovery address', rb'checking account']

for p in sorted(pathlib.Path(sys.argv[1]).glob('notes.db*')):
    raw = p.read_bytes()
    hits = []
    for pat in PATTERNS:
        for m in re.finditer(pat, raw):
            v = m.group().decode('utf-8', 'replace')
            if v not in hits:
                hits.append(v)
    print(f"{p.name:16s} {len(raw):8d} bytes   RESIDUAL: {hits}")
```

The measured output of the plain (non-CTF) session on the reference device was:

```
# host — measured
notes.db          4096 bytes   RESIDUAL: []
notes.db-wal     61832 bytes   RESIDUAL: ['ch33-recovery-code-889912', 'checking account', 'recovery address', 'sk_live_EXAMPLE_NOT_A_REAL_KEY_ch33']
notes.db-shm     32768 bytes   RESIDUAL: []
```

In your CTF run, the stage 2 flag takes the place of one of those values. Note **where** it is: not
in `notes.db`, which is where a tester who pulls "the database" would look, and not in `-shm`. It is
in the write-ahead log.

> **Definition — WAL (write-ahead log)**
> SQLite's default journal mode on Android since API 16. Instead of modifying the main database file
> on every write, SQLite **appends the new version of each changed page** to a companion file
> `<db>-wal`; readers consult the WAL first, and only at a **checkpoint** are those pages folded
> back into the main file. Because a page is copied wholesale rather than edited in place, a `DELETE`
> that removes a row rewrites the entire page — and the previous copy of that page, containing the
> row, remains in the WAL until a checkpoint.

Three separate mechanisms keep deleted rows on disk, and each needs its own fix:

1. **The WAL** holds the pre-delete pages. Fixed by `PRAGMA wal_checkpoint(TRUNCATE)`, which folds
   the WAL into the main file *and* resets the WAL file to zero length. A `PASSIVE` checkpoint folds
   but does not truncate, so the bytes stay.
2. **Free pages in the main file** keep their contents, because SQLite marks space free rather than
   erasing it. Fixed by `PRAGMA secure_delete = ON`, at a write-amplification cost that is real on a
   phone.
3. **Space that was already free** before `secure_delete` was enabled is not retroactively cleaned.
   Fixed only by `VACUUM`, which rebuilds the file and needs temporary space roughly equal to the
   database.

Verify the fix rather than believing it. Run the same session against the fixed app:

```bash
# host
adb shell pm clear com.pentest.ch33.vaultfixed
for a in store notes logout; do
  adb shell "am start -n com.pentest.ch33.vaultfixed/.VaultActivity --es action $a"; sleep 2
done
adb shell "su -c 'ls -l /data/user/0/com.pentest.ch33.vaultfixed/databases/'"
adb logcat -d -s CH33Fixed | grep -i logout
```

Measured on the reference device: `notes.db 20480`, `notes.db-shm 32768`, `notes.db-wal` **0**, and
the log line `logout: deleted 2 rows; wal now 0 bytes`.

> **Under the Hood**
> The fixed implementation does `VACUUM` **first**, then `wal_checkpoint(TRUNCATE)`. The first version
> did it the other way round and measured `wal now 20632 bytes`, because `VACUUM` rewrites the whole
> database and generates a fresh WAL full of pages after the truncate. The log line prints the size
> instead of asserting success, which is the only reason the ordering bug was caught. Assert nothing
> you can measure.

**Q4.** Below all three SQLite mechanisms sits one nobody in user space can fix. Name it, and name
the only technique that genuinely makes data on a flash device unrecoverable.

### Step 4 — Stage 3 (30 points): the value that never persisted

Take a proper baseline and diff the whole session. You will not find stage 3 this way, and finding
out *why* is the stage.

```bash
# host
adb shell pm clear com.pentest.ch33.vault
python3 -B scripts/storage-diff.py snapshot --package com.pentest.ch33.vault --out ctf-before.json
adb shell "am start -n com.pentest.ch33.vault/.ChallengeActivity"
python3 -B scripts/storage-diff.py snapshot --package com.pentest.ch33.vault --out ctf-after.json
python3 -B scripts/storage-diff.py diff ctf-before.json ctf-after.json
```

Then run the content scanner over everything that persisted, with
`python3 -B scripts/leak-hunter.py --package com.pentest.ch33.vault --min-confidence low`.

Stage 3 is in neither. There is no file to find, because the file was created and unlinked inside a
single method — it never existed at the moment either snapshot was taken.

Two recovery routes exist, and you should do both.

**Route A — the continuous camera.** Set `content: true` in the `CONFIG` block at the top of your
copy of [`../scripts/storage-trace.js`](../scripts/storage-trace.js), then spawn the app under it and
drive the activity from a second terminal:

```bash
# host
adb shell pm clear com.pentest.ch33.vault
frida -U -f com.pentest.ch33.vault -l scripts/storage-trace.js
```

```bash
# host — second terminal
adb shell "am start -n com.pentest.ch33.vault/.ChallengeActivity"
```

The tracer hooks `java.io.FileOutputStream.<init>` **and** `java.io.File.delete`, so the create and
the unlink both appear, in order, with the app's own stack frames:

```
# host — tracer output
[FileOut  ] CE-cache    /data/user/0/com.pentest.ch33.vault/cache/stage3-staging.tmp
              bytes: CH33{...
[delete   ] CE-cache    /data/user/0/com.pentest.ch33.vault/cache/stage3-staging.tmp
```

Spawn with `-f`. Attaching with `-n` after the activity has run misses everything, and concluding
"the app does not write it" from a late attach is the most common wrong negative in this technique.

**Route B — logcat is storage.** The challenge logs the value once, under a tag that is **not** the
app's usual one, so the obvious filter misses it:

```bash
# host
adb logcat -d -s CH33Vault | grep -c 'CH33{'      # the obvious filter
adb logcat -d | grep -o 'CH33{[^}]*}' | sort -u   # the whole buffer
```

> **Pentester's Note**
> Logcat is storage. It is a ring buffer, but it is written, it is readable by root, by anything
> holding `READ_LOGS`, by `adb logcat` from any host the user has ever authorised, and by any crash
> reporter that uploads the buffer. On a debuggable build the app's own uid can read it back, which
> means injected code can retrieve a secret that was logged before the injection. Treating a secret
> in `Log.d` as a storage finding is not pedantry; it is the correct classification.

**Q5.** You caught stage 3 with a hook. Name two writes that reach the disk on the app's behalf and
that this hook will **still** never see, and say which process performs them.

**Q6.** Stage 3's staging file was deleted on the happy path. Read the equivalent code in
[`../examples/leaky-vault/Vault.java`](../examples/leaky-vault/Vault.java) and say what happens to
its staging file when `seal()` throws — and why that error path is the one that matters most.

### Step 5 — Stage 4 (35 points): the decoy

Two candidate files. Both contain something that looks like a flag. One of them costs you 15 points.

Find them:

```bash
# adb shell as root
find /data/user/0/com.pentest.ch33.vault -type f -perm -o+r
ls -l /data/user/0/com.pentest.ch33.vault/files/PUBLIC-READ-ME.txt
ls -ld /data/user/0/com.pentest.ch33.vault/files
ls -ld /data/user/0/com.pentest.ch33.vault
```

```bash
# adb shell
ls -lR /storage/emulated/0/Android/media/com.pentest.ch33.vault/
```

Now do the work. For **each** candidate, answer three questions in this order, and do not skip to the
third:

1. **DAC.** Does the mode of the file permit another uid to open it, *and* does every ancestor
   directory on the path grant `o+x`? Path resolution happens one component at a time; a single
   ancestor without `o+x` makes the file unreachable regardless of its own mode.
2. **MAC.** Do the SELinux labels permit the reader you have in mind? Compare with `ls -ldZ`.
3. **Reachability in practice.** Is there an actual adversary — one you can name, with a capability
   you can state — that ends up holding those bytes?

Then prove your answer instead of asserting it, from a vantage point that is **not** root:

```bash
# adb shell — uid 2000, no su
cat /data/user/0/com.pentest.ch33.vault/files/PUBLIC-READ-ME.txt
cat /storage/emulated/0/Android/media/com.pentest.ch33.vault/audit/keys.txt
```

One of those two commands fails. That failure is the stage.

The same pattern exists on a stock device, so you know it is not an artefact of the challenge:
`/data/data/me.bmax.apatch/patch/ramdisk.cpio` is mode `-rw-r--r--` inside a package directory and a
`patch/` subdirectory that are both `drwx------`, and `cat` as uid 2000 answers `Permission denied`.
Mode bits say exposed; reachability says no.

**Q7.** Rank the two candidate files by mode permissiveness, then rank them by actual exposure. The
two rankings disagree. Explain the disagreement in one sentence a developer would accept.

**Q8.** Name the adversary that reaches the real stage 4 file. What permission do they hold, and why
does `Android/media` behave differently from `Android/data` here?

### Step 6 — Submit

For each of the four flags, submit the flag, the **command or hook** that produced it (exactly, so it
can be re-run), and the **adversary**: who reaches it, what they need, and what they get. If the
honest answer is "root only", say so, and then say what the severity is once that is priced in.

Then write the closing paragraph, which is the actual deliverable of this lab:

> *The app encrypts its data with AES-256/GCM under a hardware-backed, non-exportable key. Explain,
> in five sentences a developer will accept, why that is not an answer to "is the data safe".*

---

## Hints

<details>
<summary>Hint — Stage 1: I cannot find any export file</summary>

Two possibilities. Either the activity never ran, or you are looking under the wrong root.

```bash
# host
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
adb shell "am start -n com.pentest.ch33.vault/.ChallengeActivity"
adb shell ls -R /storage/emulated/0/Android/data/com.pentest.ch33.vault/
```

`adb shell` can list `Android/data` on Android 11 because it holds `ext_data_rw` (gid
1078). An ordinary app cannot — which is exactly the asymmetry
[Lab 03](lab-03-scoped-storage-and-fuse.md) measured, and it matters for naming the adversary.
</details>

<details>
<summary>Hint — Stage 2: I pulled the database and found nothing</summary>

You almost certainly pulled only `notes.db`. There are three files, and the one that matters is the
one nobody copies:

```bash
# adb shell as root
ls -l /data/user/0/com.pentest.ch33.vault/databases/
```

`notes.db`, `notes.db-shm`, `notes.db-wal`. Copy the whole directory. The reference measurement found
the residue in `notes.db-wal` (61832 bytes) and in neither of the other two.

There is no `sqlite3` binary on the device — most builds answer
`/system/bin/sh: sqlite3: inaccessible or not found`. Do not install one. Use Python's own `sqlite3`
module on the pulled copy, in read-only URI mode so that examining a database cannot modify it:

```python
# host
import sqlite3
c = sqlite3.connect('file:./db/notes.db?mode=ro', uri=True)
print(c.execute("SELECT name, sql FROM sqlite_master").fetchall())
print(c.execute("SELECT COUNT(*) FROM notes").fetchone())
```

That will show you an empty `notes` table and nothing else, because SQL is exactly the layer at which
the delete really did happen. The schema tells you a column called `secret` exists; only the raw
bytes tell you what is still in it.
</details>

<details>
<summary>Hint — Stage 3: the tracer prints nothing</summary>

In order:

1. Are you spawning with `-f` or attaching with `-n`? The write happens during `onCreate`.
2. Is `frida-server` running, and does its major version match your host `frida`?
3. Did you set `content: true` in `CONFIG`? Without it you get the path and the delete but not the
   bytes — which is enough to *locate* the stage but not to read the flag.
4. Is `quietCache` set? The staging file is under `cache/`, and `--quiet-cache` suppresses exactly
   that.
</details>

<details>
<summary>Hint — Stage 3: I would rather not use Frida</summary>

Then use the other route. The value is logged once, under a tag that is not the app's usual one, so
the filter everybody reaches for first misses it:

```bash
# host
adb logcat -d | grep -o 'CH33{[^}]*}' | sort -u
```

If your buffer has already rotated, clear it with `adb logcat -c`, re-run the activity, and dump
immediately. Racing the filesystem from a root shell in a `while true; do ls .../cache/; done` loop
also works, and is instructive about exactly why you should not have to.
</details>

<details>
<summary>Hint — Stage 4: both files look readable to me</summary>

You are reading modes as root, or from a `adb pull` copy. Neither is valid evidence.

`adb pull` onto NTFS discards mode bits entirely, so the modes you see on your host are invented by
your host filesystem. Read modes **on the device**:

```bash
# adb shell as root
ls -l  /data/user/0/com.pentest.ch33.vault/files/PUBLIC-READ-ME.txt
ls -ld /data/user/0/com.pentest.ch33.vault/files
ls -ld /data/user/0/com.pentest.ch33.vault
```

Then walk the path by hand: the file needs `o+r`, and **every** directory above it needs `o+x`. Then
stop reasoning and test it as uid 2000, without `su`.
</details>

<details>
<summary>Hint — Stage 4: why would a 0600 file be more exposed than a 0644 one?</summary>

Because they are on different volumes with different reachability models. Ask what
`getExternalMediaDirs()` returns, then ask what is special about `Android/media` compared with
`Android/data` on API 30. [`../scripts/storage-map.sh`](../scripts/storage-map.sh) describes it in one
line in its `EXT-MEDIA` block, and calls it "the worst of both worlds and the one people forget".
</details>

---

## Solution

<details>
<summary>Full solution — do not open until you have attempted all four stages</summary>

### Stage 1 — `CH33{d3bug_3xp0rt_1s_st1ll_st0rag3}`

```bash
# adb shell — no su required
cat /storage/emulated/0/Android/data/com.pentest.ch33.vault/files/debug/export.json
```

`Vault.store()` writes the plaintext to five places and seals it into one. LEAK-2 is the debug export
on external app-specific storage, written with `getExternalFilesDir()`, which has needed **no
permission since API 19** — so a permission audit of the manifest reports a clean app while the app
writes outside its uid-protected sandbox.

**Adversary:** on Android 11, `adb shell` (gid `ext_data_rw` 1078), any app holding
`MANAGE_EXTERNAL_STORAGE`, and any OEM file manager built with that reach. On Android 10 and earlier
the answer is worse: any app with `READ_EXTERNAL_STORAGE`, and the user with any file browser.

**A2.** Nothing, for this value. The encryption protected `files/vault.bin`. The plaintext went to
four other locations, and the security of a secret is the security of its **weakest** copy.

### Stage 2 — `CH33{d3l3t3d_r0ws_l1v3_1n_th3_w4l}`

```bash
# host
adb shell "su -c 'cp -r /data/user/0/com.pentest.ch33.vault/databases /data/local/tmp/db'"
adb shell "su -c 'chmod -R 755 /data/local/tmp/db'"
adb pull /data/local/tmp/db ./db
python3 -B wal-scan.py ./db
```

The flag is in `notes.db-wal`, not in `notes.db`. The `DELETE` genuinely executed and `SELECT` returns
nothing; the WAL still holds the pre-delete page because a page is copied wholesale rather than
edited in place, and nothing checkpointed.

**Adversary:** anyone with root, a device-image acquisition, or an `adb backup` on a platform that
still permits it if the file is in the backup set. Not another app — this is inside the sandbox. That
makes it a **forensic-recovery** finding rather than a cross-app one, and the severity should say so.

**A4.** The flash translation layer. An eMMC or UFS controller remaps logical blocks to physical ones
and does not erase the old physical block when you overwrite the logical one; nothing in user space
can reach it. `f2fs` compounds it by being log-structured, so an overwrite allocates new blocks by
design and overwrite-before-unlink is a gesture rather than an erase. The only technique that works
is **crypto-shredding** — encrypt with a key you can destroy, then destroy the key, which is what
`fixed-vault`'s `wipe()` relies on and what an app storing plaintext has no equivalent of.

### Stage 3 — `CH33{n0_f1l3_n0_pr0bl3m_r1ght}`

Either route — Frida with `content: true`, or the whole log buffer:

```bash
# host
frida -U -f com.pentest.ch33.vault -l scripts/storage-trace.js
adb logcat -c && adb shell "am start -n com.pentest.ch33.vault/.ChallengeActivity"
adb logcat -d | grep -o 'CH33{[^}]*}' | sort -u
```

The filesystem diff cannot see it, and no improvement to `storage-diff.py` would change that: the
file was created and unlinked between the two snapshots, so it is absent from both. This is the
structural limit of differencing, stated in the tool's own docstring, and it is the reason the two
tools in [`../scripts/`](../scripts/storage-trace.js) answer different questions rather than
overlapping ones.

**A5.** Anything MediaProvider performs on the app's behalf through FUSE — the app writes to a file
descriptor and MediaProvider performs the real write in **its own process** — and anything another
process does for the app, such as `system_server` writing a recents task snapshot when the activity
backgrounds, or the share sheet copying a URI. Both are invisible to an in-process hook for the same
reason the diff missed the temp file: the instrument is attached to the wrong process.

**A6.** In `Vault.store()` the `staging.delete()` sits at the end of the `try` block, so it does not
run when `seal()` throws — and `seal()` throws on any keystore error. The plaintext staging file then
survives **permanently**, precisely in the situation where the app has malfunctioned and is most
likely to be examined. A diff run on a healthy device never shows this; a diff run on a device where
the keystore was unhappy shows it every time. The error path is the one that matters because the
error path is the one nobody tested.

### Stage 4 — `CH33{r34ch4b1l1ty_n0t_m0d3_b1ts}`

The decoy is `files/PUBLIC-READ-ME.txt` at mode `-rw-r--r--`. It sits inside `files/` inside the
package directory, both of which are `drwx------` (0700). `open(2)` resolves a path one component at
a time and requires `x` on every directory along the way, so no uid other than the app's can resolve
it. Prove it as uid 2000:

The real flag is at mode 0600 — the *more restrictive* of the two — and it is readable:

```bash
# adb shell
cat /data/user/0/com.pentest.ch33.vault/files/PUBLIC-READ-ME.txt   # -> Permission denied
cat /storage/emulated/0/Android/media/com.pentest.ch33.vault/audit/keys.txt
```

**A7.** By mode, the decoy is more permissive (0644 versus 0600). By exposure, the media file is
strictly worse. The one sentence for a developer: *"Permissions on external storage are synthesised
by the mount, not enforced from the file's own bits, and `Android/media` is indexed by MediaStore —
so the mode you set on that file is decoration, while the 0644 file inside your app directory is
unreachable because both of its parent directories are 0700."*

**A8.** Any app holding a media read permission (`READ_EXTERNAL_STORAGE`, or the granular
`READ_MEDIA_*` permissions on newer releases), plus `MANAGE_EXTERNAL_STORAGE` holders, plus `adb
shell`. `Android/media` differs from `Android/data` because MediaStore **indexes** it: the API 30
restriction that makes `Android/data` non-enumerable does not apply, and the contents are surfaced
through the provider to any app the user has granted media access. Developers pick
`getExternalMediaDirs()` believing it is a sibling of `getExternalFilesDir()` with a nicer name.

### The closing paragraph — a model answer

The app encrypts one file. Encryption is a property of a byte sequence at a location, not of a value,
so protecting `vault.bin` says nothing about the four other locations the same plaintext reached on
the way there — a debug export outside the uid sandbox, a shared preference, a device-encrypted file
readable before the user has entered a PIN, and the log buffer. The security of a secret is the
security of its weakest copy, and the app's own logout path proves the same point in the other
direction: the `DELETE` executed correctly and the bytes stayed on disk, because deleting a row and
erasing data are different operations. Asking "is it encrypted" tests one location; asking "where did
the plaintext go, and who can reach each place it went" tests the system. Only the second question
has an answer that is worth anything to the user.

</details>

---

## Success criteria

- [ ] You **built the challenge yourself** from sources you saved outside the repository, and installed it on a device you own
- [ ] You recovered stage 1 **without root**, and named an adversary who reaches it on Android 11
- [ ] You recovered stage 2 from `notes.db-wal` and can explain why the **`DELETE` was real** and the erasure was not
- [ ] You can name the **three SQLite mechanisms** that retain deleted rows, and the fix each one needs
- [ ] You verified the fixed app's `notes.db-wal` is **0 bytes** rather than taking the fix on trust
- [ ] You recovered stage 3 after confirming a full snapshot diff **could not see it**, and can explain the structural reason
- [ ] You ruled out the stage 4 **decoy** by walking the path's ancestors, and proved the refusal as an unprivileged uid rather than asserting it
- [ ] You can explain why a **0600 file was more exposed** than a 0644 one, in terms a developer accepts
- [ ] You submitted, for every flag, the exact command **and the named adversary**, including where the honest answer was "root only"
- [ ] You can state, in one sentence, why **"the app encrypts its data" is not an answer** to "is the data safe"
