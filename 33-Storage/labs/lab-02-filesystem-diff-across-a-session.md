# Lab 02 — Filesystem Diff Across a Session

**Difficulty:** Intermediate
**Time:** 150 minutes
**Prerequisites:** [Lab 01](lab-01-map-the-eight-roots.md),
[Chapter 33 §3.1–3.8](../README.md),
[71-OWASP-Mobile](../../71-OWASP-Mobile/README.md),
an Android SDK with build-tools and a JDK, a rooted device, `frida-server` running on the device

---

## Objective

Learn the method that [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) names as the standard
procedure for the MASVS-STORAGE group: **snapshot, exercise, snapshot, diff**. You will apply it to
a deliberately vulnerable app whose leaks are documented in its own source, so that you can grade
your own results — and then you will discover, by measurement rather than by being told, the class
of leak this method **cannot see at all**.

That discovery is the point of the lab. Anybody can run a diff. The professional skill is knowing
what a diff is structurally blind to, and having a second tool ready for exactly that gap.

## Why this matters

A storage assessment that consists of "I looked in `/data/data` and found a token" is not
reproducible, not complete, and not defensible. It is not reproducible because nobody else knows
what you did to the app in between. It is not complete because you looked in one of the eight roots
from [Lab 01](lab-01-map-the-eight-roots.md). And it is not defensible because you cannot show that
the token appeared *as a result of the feature you exercised* rather than having been there since
install.

The diff method fixes all three. Because you control the baseline, every line of output is causally
attributable to the exercise you ran. Because the snapshot walks all six package-derived roots, the
coverage is stated rather than assumed. And because the exercise is scripted, a developer can run it
themselves and get the same list — which is what makes a finding survive the meeting where it is
disputed.

> **Mental Model**
> A snapshot is a photograph of a hard drive; a diff is what changed between two photographs. That
> analogy also tells you the method's limit, immediately and without any Android knowledge: anything
> that happened *between* the two photographs and was cleaned up before the second one is not in
> either picture. A burglar who tidies up is invisible to before-and-after photos. You need a camera
> that runs continuously, and that camera is [`../scripts/storage-trace.js`](../scripts/storage-trace.js).

---

## Setup

### Build and install the example pair

The repository ships **sources, never APKs**. Build them out of tree:

```bash
# host
cd Android-Security-Handbook/33-Storage
chmod +x examples/build.sh
./examples/build.sh --install
```

That builds both [`leaky-vault`](../examples/leaky-vault/Vault.java) and
[`fixed-vault`](../examples/fixed-vault/Vault.java) with `aapt2`,
`javac`, `d8`, `zipalign` and `apksigner` — no Gradle, no network, no androidx — and installs both.
Read the script's header block before running it; the `WHAT THIS WILL *NOT* DO FOR YOU` section is
the part that saves you time.

Confirm:

```bash
# host
adb shell pm list packages | grep pentest
```

```
# host — measured
package:com.pentest.ch33.vault
package:com.pentest.ch33.vaultfixed
```

> **Warning**
> `examples/leaky-vault` is deliberately vulnerable and writes a plaintext token to several places,
> including one file in the shared Downloads collection that **survives its own uninstall**. Install
> it on a device you own, and finish with `./examples/build.sh --uninstall`, which removes that file
> too.

### Confirm Frida is up

You need it for Step 9. Get it working now rather than discovering it is broken two hours in.

```bash
# host
adb shell "su -c '/data/local/tmp/frida-server &'"
frida-ps -U | head -5
```

If `frida-ps -U` lists processes, you are set. See [53-Frida](../../53-Frida/README.md) if it does
not.

### Environment traps that are real

Three of these cost real time on the reference device, so deal with them before you start.

| Trap | Symptom | Fix |
|---|---|---|
| MSYS path rewriting | `--root /sdcard/Download` becomes `C:/Program Files/Git/sdcard/Download` | `MSYS_NO_PATHCONV=1` before the command |
| `adb shell` quoting | `su -c "ls -l /data/data"` arrives as `su -c ls -l /data/data`; only `ls` runs | Pass the whole thing as **one** argument |
| Keyguard on MIUI | `am start` appears to work, nothing happens | `adb shell "dumpsys trust" \| grep -o "deviceLocked=[01]"` — unlock if `=1` |

[`../scripts/storage-diff.py`](../scripts/storage-diff.py) detects the first one and explains it
rather than failing obscurely. It is worth reading how, because you will meet the same corruption
in every other tool that takes device paths as arguments on Windows.

---

## Steps

### Step 1 — `pm clear`, and why the baseline is the experiment

```bash
# host
adb shell pm clear com.pentest.ch33.vault
```

```
# host — measured
Success
```

`pm clear` deletes the app's CE and DE directories, its external app-specific directories, and its
shared preferences, then recreates the package directory empty. It is equivalent to "clear storage"
in Settings.

You do this **before** the first snapshot, and it is not a tidiness step. It is what converts the
diff from a description into an experiment. Without it, your before-snapshot contains whatever
accumulated during install, during your last test run, and during whatever the app did in the
background — and every one of those files becomes a permanent unexplained resident of your baseline
that you will spend the rest of the session mentally subtracting.

> **Pentester's Note**
> On a real engagement you frequently **cannot** `pm clear`, because the app's state is the
> engagement — a logged-in session you cannot easily recreate, or data belonging to a test account
> the client set up once. In that case take the baseline anyway and accept a noisier diff, and say
> so in the report. The alternative, which is to clear the app and lose the state, is usually worse.
> What you must never do is take a baseline *after* exercising the feature you are investigating.

**Question 1.** `pm clear` does not remove the file the leaky app wrote into `Downloads`. Why not,
and what does that tell you about who owns a file in a shared collection?

### Step 2 — The before-snapshot

```bash
# host
python3 -B scripts/storage-diff.py snapshot \
    --package com.pentest.ch33.vault --out before.json
```

The snapshot walks all six package-derived roots and records, for every file and directory: type,
octal mode, owner uid and gid, size, mtime, inode, SELinux label, and a SHA-256 of the contents for
files under the hash cap. Nothing is interpreted at snapshot time — it is a faithful record, and
that matters because you will want to ask it questions you have not thought of yet.

Look at the top of the output. If it says root was unavailable, stop and fix that; a snapshot that
silently skipped the CE root will produce a diff that looks clean.

```bash
# host
python3 -B -c "import json;d=json.load(open('before.json'));print(len(d['entries']),'entries');print([r['path'] for r in d['roots']])"
```

**Question 2.** The snapshot records an SELinux label for every entry, even though the tool
explicitly says it computes DAC reachability only and cannot answer MAC questions. Why record the
label at all?

### Step 3 — Exercise the app with a script, not with your fingers

```bash
# host
./examples/build.sh --exercise
```

That drives four actions and a second activity, each with `am start`:

```bash
# host — what --exercise actually runs
adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action store"
adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action notes"
adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action logout"
adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action probe"
adb shell "am start -n com.pentest.ch33.vault/.ExportActivity"
```

A lab whose "exercise the app" step reads *tap around for a bit* cannot produce a diff anybody can
reproduce, including you tomorrow. Every step here is one `am start`, so the sequence is identical
on every run, and a developer disputing your finding can run the same five lines.

> **Under the Hood**
> `am start` sets `FLAG_ACTIVITY_NEW_TASK`. With the default `standard` launch mode, a second
> `am start` for an activity that is already top of its task does **not** deliver a new Intent — the
> system brings the existing task forward and `onNewIntent` is never called. `adb` prints
> *Activity not started, intent has been delivered to currently running top-most instance*, which
> reads like success and is not. The leaky app's manifest declares `launchMode="singleTop"`
> specifically so that this lab's four actions all actually run. If you script an `am start`
> sequence against a real app and only the first action seems to happen, this is why.

**Question 3.** Why does the exercise include `probe`, which only writes a report file, and
`ExportActivity`, which writes to a shared collection? What would the diff lose if you dropped
either?

### Step 4 — The after-snapshot and the diff

```bash
# host
python3 -B scripts/storage-diff.py snapshot \
    --package com.pentest.ch33.vault --out after.json
python3 -B scripts/storage-diff.py diff before.json after.json
```

Measured on the reference device (Redmi `M2101K6P`, Android 11 / API 30):

```
# host — abridged; the counts and the paths are verbatim
  APPEARED=21  CONTENT=1  TOUCHED=3

  NEW ROOT      /storage/emulated/0/Android/media/com.pentest.ch33.vault
```

APPEARED (21), including:

```
# host
  -rw-------        76  /data/user/0/com.pentest.ch33.vault/files/vault.bin
  -rw-rw----       260  /data/user/0/com.pentest.ch33.vault/shared_prefs/session.xml
  -rw-------      4402  /data/user/0/com.pentest.ch33.vault/files/probe.txt
  -rw-rw----     12288  /data/user/0/com.pentest.ch33.vault/databases/notes.db
  -rw-------        48  /data/user_de/0/com.pentest.ch33.vault/files/boot-token.txt
  -rw-rw----       107  /storage/emulated/0/Android/data/com.pentest.ch33.vault/files/debug/export.json
  -r--------     19236  /data/user_de/0/com.pentest.ch33.vault/code_cache/com.android.opengl.shaders_cache
  -r--------      5128  /data/user_de/0/com.pentest.ch33.vault/code_cache/com.android.skia.shaders_cache
```

CONTENT (1):

```
# host
  /data/misc/profiles/cur/0/com.pentest.ch33.vault/primary.prof  e3b0c44298fc1c14 -> 7c42d4b4f0940a0a  (0 -> 84 bytes)
```

And the exposure review:

```
# host
EXPOSURE REVIEW  -- mode bits that let another uid at the data
  Nothing world-readable or world-writable changed or appeared.
```

**Read that last line carefully.** It is a true statement and it is not a clean bill of health. Every
file the leaky app wrote is at mode 0600 or 0660 inside a directory the app owns — which is exactly
correct DAC hygiene — and the app is still leaking a token to five places. Mode bits are one gate of
several, and a tool that only checks mode bits will pass this app.

### Step 5 — Interpret each class

The diff classifies every difference. Learn to read each class as a **question**, not an answer.

| Class | What it means | What it usually is |
|---|---|---|
| `APPEARED` | A path that did not exist before | The main event. Every new file is something the exercise caused. |
| `DISAPPEARED` | A path that no longer exists | An app cleaning up — or destroying evidence between your snapshots. |
| `CONTENT` | Same path, different SHA-256 | A real write. The strongest single signal in the report. |
| `MODE` | Permission bits changed | Rare and always worth a look; apps almost never `chmod` deliberately. |
| `OWNER` | uid or gid changed | Rarer still. On `/sdcard` it is usually the FUSE daemon, not the app. |
| `LABEL` | SELinux label changed | Effectively never in normal operation. Investigate. |
| `GREW` / `SHRANK` | Size changed, hashing skipped | A weaker claim than `CONTENT`, and labelled as one. |
| `TOUCHED` | Only mtime moved | Noise. See below. |

`TOUCHED=3` deserves its own paragraph, because it is the class most likely to waste your afternoon.
On this device `/data` is **f2fs mounted with `lazytime`**, which means the kernel is permitted to
update an inode's timestamp in memory and defer writing it to disk. An mtime can therefore move
without any data write reaching storage at all, and can also fail to move when you expected it to.
`storage-diff.py` excludes `TOUCHED` from `--only-findings` for exactly this reason. Treat a
timestamp as a hint and never as evidence.

The `NEW ROOT` event is the opposite — it is a strong signal and easy to miss:

```
# host
  NEW ROOT      /storage/emulated/0/Android/media/com.pentest.ch33.vault
```

`getExternalMediaDirs()` and `getExternalFilesDir()` **create their directory on first call.** So a
root that did not exist before the exercise and does now tells you the app reached for a storage
area it had never used. Here it was `StorageProbe` enumerating roots. In a real app, a media
directory appearing after a "save draft" action is a question worth asking out loud, because
`Android/media` is indexed by MediaStore and its contents are visible to any app holding a media
read permission — unlike `Android/data`.

The `CONTENT` change on `primary.prof` is the ART profile:

> **Definition — ART profile**
> A file the Android Runtime writes under `/data/misc/profiles/cur/<user>/<pkg>/`, recording which
> methods of the app were executed, so that the profile-guided compiler can optimise the hot ones
> later. It is not app data and the app cannot control it. It went from **0 to 84 bytes** across this
> session, which is the runtime recording that code ran.

That is a genuine information leak of a narrow kind — it tells a reader with root which code paths
executed — and it is almost never a finding on its own. It appears in your diff on every app, every
time, and you should recognise it instantly so it stops costing you attention. See
[13-ART](../../13-ART/README.md).

**Question 4.** `shared_prefs/session.xml` is mode `-rw-rw----`, not `-rw-------`. Which gid owns the
group bit, and is the difference a finding? Check with `ls -l` on the device before answering.

### Step 6 — The report modes

```bash
# host
python3 -B scripts/storage-diff.py diff before.json after.json --only-findings
python3 -B scripts/storage-diff.py diff before.json after.json --json --strict > diff.json
echo "exit status: $?"
```

`--only-findings` drops the classes that carry no security weight — `TOUCHED` chief among them — and
leaves the shape you would paste into a report appendix.

`--strict` makes the tool exit non-zero when the exposure review found something, which is what turns
it into a CI gate: a build that newly world-exposes a file fails the pipeline. Note what that means
in practice on this app — the leaky vault **passes** a `--strict` gate, because none of its five
leaks is a mode-bits problem. A gate that only catches mode changes is worth having and is not worth
trusting.

### Step 7 — Account for all five leaks

Open [`../examples/leaky-vault/Vault.java`](../examples/leaky-vault/Vault.java) and read the header
comment. Five leaks are named, each with the reason a developer writes it:

| Leak | What it writes | Where |
|---|---|---|
| LEAK-1 | plaintext staging file, written before encryption, deleted after | `cache/vault-staging.tmp` |
| LEAK-2 | plaintext "debug export" | `Android/data/<pkg>/files/debug/export.json` |
| LEAK-3 | the same secret in SharedPreferences under `auth_token` | `shared_prefs/session.xml` |
| LEAK-4 | the secret in `Log.d` | logcat ring buffer |
| LEAK-5 | the secret in device-encrypted storage | `user_de/0/<pkg>/files/boot-token.txt` |

Now go through your diff and tick each one off. Confirm the contents rather than trusting the
filename:

```bash
# host
adb shell "su -c 'cat /storage/emulated/0/Android/data/com.pentest.ch33.vault/files/debug/export.json'"
adb shell "su -c 'cat /data/user/0/com.pentest.ch33.vault/shared_prefs/session.xml'"
adb shell "su -c 'cat /data/user_de/0/com.pentest.ch33.vault/files/boot-token.txt'"
adb logcat -d -s CH33Vault | grep -i "stored secret"
```

LEAK-2 is `export.json`, 107 bytes, in the diff. LEAK-3 is `session.xml`, 260 bytes, in the diff.
LEAK-5 is `boot-token.txt`, 48 bytes, in the diff. LEAK-4 is in logcat and was never going to be in
a filesystem diff, which the table in [Lab 01](lab-01-map-the-eight-roots.md) already told you —
logcat is root 8, and root 8 is not a path.

**LEAK-1 is not in the diff at all.** There is no `cache/vault-staging.tmp` in `APPEARED`, no
`DISAPPEARED` entry for it, nothing.

Stop here and work out why before reading on. You have everything you need: the source of
`Vault.store()`, and the definition of what a diff is.

### Step 8 — Why the method could not see it

`Vault.store()` writes the plaintext to `cache/vault-staging.tmp`, then encrypts, then calls
`staging.delete()` on the happy path. The file was created *after* your before-snapshot and removed
*before* your after-snapshot. It existed for a few milliseconds, entirely inside the gap between the
two photographs.

This is not a bug in `storage-diff.py`. It is a **structural property of differencing**, and no
amount of improving the tool changes it. The script says so in its own docstring, under
`WHAT THIS SCRIPT WILL *NOT* TELL YOU`:

> *Anything about a file that was created and deleted between the two snapshots. A temp file that
> lives for 40 ms during a login is invisible to this method by construction.*

> **Warning**
> Read the error path in `Vault.store()` before you decide LEAK-1 is minor. The `delete()` sits at
> the end of the `try` block, so it does **not** run when `seal()` throws — and `seal()` throws on
> any keystore error, which is precisely the situation in which a device is most likely to be
> examined. The failure path leaves the plaintext on disk permanently. A diff taken on a healthy
> device will never show you that, and a diff taken on a device where the keystore was
> misbehaving would show it every time.

And even on the happy path, `delete()` unlinks a directory entry. It does not overwrite data blocks,
and on a log-structured filesystem like f2fs it very often does not even make them reusable
immediately. A raw partition carve recovers the contents. **The filesystem does not owe you an
erase.**

**Question 5.** Name two other categories of storage event, besides create-then-delete, that a
before/after diff structurally cannot report.

### Step 9 — Catch it with the tracer

Now use a camera that runs continuously.

```bash
# host
adb shell pm clear com.pentest.ch33.vault
frida -U -f com.pentest.ch33.vault -l scripts/storage-trace.js
```

Spawning with `-f` rather than attaching with `-n` matters: a great deal of an app's storage setup
happens in `onCreate`, and attaching afterwards misses it. Concluding "the app does not write the
token" because you attached late is the single most common way this technique produces a wrong
negative.

With the app up under the tracer, drive the same action from a second terminal:

```bash
# host — second terminal
adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action store"
```

The tracer hooks `java.io.FileOutputStream.<init>`, `RandomAccessFile.<init>`,
`SharedPreferencesImpl$EditorImpl.putString`, the `SQLiteDatabase` write methods, `android.util.Log`,
`ClipboardManager.setPrimaryClip`, and — at the floor — libc `open`/`openat` with write flags. It
also hooks `java.io.File.delete`, which is the hook that matters here:

```
# host — the shape of what you are looking for
[FileOut  ] CE-cache    /data/user/0/com.pentest.ch33.vault/cache/vault-staging.tmp
                at com.pentest.ch33.vault.Vault.store(Vault.java)
[FileOut  ] CE          /data/user/0/com.pentest.ch33.vault/files/vault.bin
[delete   ] CE-cache    /data/user/0/com.pentest.ch33.vault/cache/vault-staging.tmp
[prefs    ] SET         auth_token = ch33-demo-token-...
[log.d    ] LOGCAT      CH33Vault: stored secret for primary-account: ch33-demo-token-...
```

Add `--content` in `CONFIG` at the top of the script if you want the bytes previewed, and note the
`<<< OUTSIDE` marker the tracer appends to any path that has left the app's uid-protected
directories — that marker fires on `export.json` and on anything written to a shared collection.

> **Mental Model**
> The two tools answer different questions and neither replaces the other. `storage-diff.py` tells
> you **what state persists**, which is what a forensic acquisition of the handset would find.
> `storage-trace.js` tells you **what happened**, which is what an attacker with code execution in
> the process would see. An app can look clean to one and terrible to the other, in both directions.
> Run both, and say in the report which one produced each finding.

**Question 6.** The tracer also misses things. Name two writes that reach the disk on the app's
behalf and never appear in its output, and say why.

### Step 10 — Diff the two footprints

Now run the identical cycle against the fixed app and compare the *footprints*, not just the diffs.

```bash
# host
adb shell pm clear com.pentest.ch33.vaultfixed
python3 -B scripts/storage-diff.py snapshot \
    --package com.pentest.ch33.vaultfixed --out fixed-before.json
./examples/build.sh --exercise com.pentest.ch33.vaultfixed
python3 -B scripts/storage-diff.py snapshot \
    --package com.pentest.ch33.vaultfixed --out fixed-after.json
python3 -B scripts/storage-diff.py diff fixed-before.json fixed-after.json
```

Then confirm the contents of what survived:

```bash
# host
adb shell "su -c 'cat /data/user/0/com.pentest.ch33.vaultfixed/shared_prefs/session.xml'"
adb shell "su -c 'ls -l /data/user/0/com.pentest.ch33.vaultfixed/databases/'"
adb logcat -d -s CH33Fixed
```

Read [`../examples/fixed-vault/Vault.java`](../examples/fixed-vault/Vault.java) alongside the
output. The
cryptography in the fixed app is **byte for byte identical** to the leaky one: the same AES-256/GCM,
the same non-exportable AndroidKeyStore key, the same IV handling. Every difference between the two
files is about *where bytes go*, not about how they are protected. That is the chapter's whole thesis
expressed as a diff.

Specifically: FIX-1 encrypts in memory and writes once to a temporary name in the same directory,
then renames — so there is no point in the control flow, including every error path, at which
cleartext exists on the filesystem. FIX-2 removes the external debug export. FIX-3 puts a label and a
timestamp in prefs instead of the token. FIX-4 logs that a store happened rather than what was
stored. FIX-5 puts a boolean `credential_present` in DE storage instead of the credential.

**Question 7.** The fixed app still writes `shared_prefs/session.xml`, still writes to DE storage,
and still writes a file to `files/`. Its diff is not empty. What, precisely, makes it acceptable
where the leaky app's is not? Answer in terms of what an attacker gets, not in terms of file count.

### Step 11 — Write it up

Produce a finding for LEAK-2 (the external debug export) in report shape:

1. **Title** naming the mechanism — where the data went — not the tool that found it.
2. **Reproduction** as the exact five commands, so the developer can run them.
3. **Evidence** — the `APPEARED` line with mode and size, plus the file contents with the token
   partly redacted.
4. **Reachability** — who can read `Android/data/<pkg>/files/` on API 30, and who cannot. This is the
   paragraph that decides the severity, and it is the one most reports omit.
5. **Severity**, argued.
6. **Remediation as code**, taken from the FIX-2 comment in the fixed app.

Then write a second, shorter finding for LEAK-1, and note explicitly in it that the finding was
**not** produced by the diff and could not have been. A report that says how each finding was
obtained is a report whose gaps a client can reason about.

---

## Hints

<details>
<summary>Hint 1 — build.sh fails before it builds anything</summary>

```bash
# host
echo "$ANDROID_HOME"
ls "$ANDROID_HOME/build-tools" | tail -1
ls "$ANDROID_HOME/platforms"
java -version
```

The script needs `ANDROID_HOME` or `ANDROID_SDK_ROOT` pointing at an SDK containing build-tools
(`aapt2`, `d8`, `zipalign`, `apksigner`) and at least one platform `android.jar`, plus a JDK with
`javac` and `keytool`, plus `python3` (used only to add `classes.dex` to the APK zip, because `zip`
is not reliably present on Windows).
</details>

<details>
<summary>Hint 2 — install refused with INSTALL_FAILED_USER_RESTRICTED</summary>

That is an OEM restriction ("Install via USB" disabled at the vendor level), not a fault in the APK,
and nobody cancelled anything despite what the message says. `build.sh` detects this exact failure
and falls back to pushing the APK and running `pm install` through root, which works on a rooted
device. On the device this chapter was measured against, plain `adb install` **did** work — this
failure is device-dependent.
</details>

<details>
<summary>Hint 3 — the diff refuses to run</summary>

```
# host — measured
error: the two snapshots were taken over different root SETS, so
       every entry in the extra root would be reported as APPEARED.
```

That guard exists because a snapshot taken with `--root /sdcard/Download` and one taken with
`--package` are not comparable, and diffing them produces a page of phantom `APPEARED` entries.

The honest case where it fires legitimately: a root that did not exist at baseline and does now. The
tool compares the *requested* root set, not the found set, precisely so that a genuinely new root is
reported as `NEW ROOT` rather than hidden. If you really mean to diff across different sets, pass
`--force`.
</details>

<details>
<summary>Hint 4 — everything is APPEARED, hundreds of entries</summary>

You almost certainly took the before-snapshot after exercising the app, or forgot `pm clear` and
then reinstalled between the two. Check the timestamps:

```bash
# host
python3 -B -c "import json;print(json.load(open('before.json'))['taken_at'], json.load(open('after.json'))['taken_at'])"
```
</details>

<details>
<summary>Hint 5 — the tracer prints nothing at all</summary>

Three things, in order:

1. Are you spawning (`-f`) or attaching (`-n`)? Attaching after `onCreate` misses the interesting
   writes.
2. Did the activity actually start? Check `deviceLocked`:
   `adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"`. On MIUI, while the keyguard is up,
   app-originated activity starts are refused.
3. Is `frida-server` the same major version as your host `frida` package? A mismatch fails at
   attach time with a message about the protocol.
</details>

<details>
<summary>Hint 6 — I want to see the staging file with my own eyes</summary>

Race it. Drive `store` in a loop from one terminal and poll `cache/` from another:

```bash
# host — terminal A
while true; do adb shell "am start -n com.pentest.ch33.vault/.VaultActivity --es action store" >/dev/null; done
```

```bash
# adb shell as root — terminal B
while true; do ls -l /data/user/0/com.pentest.ch33.vault/cache/ 2>/dev/null | grep staging && break; done
```

You will catch it eventually, and catching it by racing is a good demonstration of *why* you should
not have to. The deterministic method is the hook.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** `pm clear` removes the app's own storage — its CE and DE directories, its external
app-specific directories. A file in `Downloads` is in a **shared collection**: it is not the app's
storage, it is the user's, and MediaStore merely records which package created it in
`owner_package_name`. The app does not own it, cannot assume it can delete it, and does not lose it
when the app is cleared or even uninstalled. That is the answer to "why did my file survive
uninstall", and it is also the reason `build.sh --uninstall` explicitly deletes that file through
MediaStore rather than relying on the uninstall.

**2.** Because the SELinux label is the input to the question the tool cannot answer. `storage-diff.py`
computes DAC reachability and says so; deciding whether *another app* can read a world-readable file
requires comparing MCS categories, and the only way to do that later is to have recorded the labels
at snapshot time. A tool that refuses to guess but preserves the evidence for the human is behaving
correctly. The alternative — printing "INSECURE" — is how storage scanners earn their reputation.

**3.** `probe` produces `files/probe.txt` (4402 bytes) and, as a side effect of enumerating roots,
causes `getExternalMediaDirs()` to be called — which is what creates the `Android/media/<pkg>`
directory and generates the `NEW ROOT` event. Drop it and you lose the demonstration that merely
*asking* for a root creates it. `ExportActivity` writes into a shared collection, which is a
different leak class entirely from everything in `Vault.java`: it survives uninstall, it is indexed
by MediaStore, and it is attributed to the package in `owner_package_name`. Drop it and the diff
contains no shared-collection event at all, because the filesystem walk of the six package roots
would never have seen it anyway.

**4.** The group bit belongs to a per-app gid that shares the app's app id, so the file is group
`u0_a<n>` — the same app. It is not a finding: `MODE_PRIVATE` prefs land at 0660 with owner and group
both belonging to the app, and no other uid is in that group. Reporting `-rw-rw----` as
"group-readable, potential exposure" without checking who the group *is* is a routine false positive.
Confirm with `ls -l` on the device, where the gid is resolved to a name.

**5.** Several, and any two will do. (a) A file whose contents changed and changed back — same path,
same hash at both snapshots, real writes in between. (b) A file created and deleted between
snapshots, which is LEAK-1. (c) Anything written to a store that is not a path in the six roots:
logcat, the clipboard, a system task snapshot, a backup transport. (d) A file written by a
*different process* on the app's behalf, such as MediaProvider performing the real write behind a
FUSE fd. (e) Data that never reached disk at all and lived only in memory — visible to
[19-Memory](../../19-Memory/README.md)'s methods and to nothing here.

**6.** Two good answers. First, anything MediaProvider does through FUSE: the app calls `write(2)` on
a FUSE file descriptor, MediaProvider performs the actual write in **its own process**, and only the
app-side call appears in the tracer. Second, anything a different process does on the app's behalf —
the system share sheet copying a URI, `system_server` writing a recents task snapshot, `logd`
persisting the ring buffer. Both are invisible for the same structural reason the diff misses LEAK-1:
the instrument is attached to the wrong process. A third acceptable answer: writes that happened
before you attached.

**7.** The fixed app's diff is not empty and does not need to be. What matters is what an attacker
gets from each artefact. `shared_prefs/session.xml` now holds a label, a timestamp and a boolean —
disclosing all three tells an attacker that a credential exists and when it was issued, which is
metadata, not a credential. DE storage holds `credential_present=true`, so a before-first-unlock
acquisition learns that the user has logged in and nothing more. `files/vault.bin` holds ciphertext
sealed with a key that lives in the AndroidKeyStore and never enters the process's address space, so
possession of the file is not possession of the secret. The leaky app's artefacts, by contrast, each
yield the token itself to anyone who reads them. The test is not "how many files" but "what does the
weakest copy give up" — and in the leaky app the weakest copy is a plaintext token on external
storage.

</details>

---

## Success criteria

- [ ] You built and installed both example apps from source with [`../examples/build.sh`](../examples/build.sh), without Gradle
- [ ] You took a **clean baseline** with `pm clear` and can explain why the baseline is the experiment
- [ ] You exercised the app with a **scripted** sequence and can explain why `am start` beats tapping, including the `singleTop` trap
- [ ] You produced a diff and can read every class in it — `APPEARED`, `CONTENT`, `MODE`, `TOUCHED`, `NEW ROOT` — as a question rather than a verdict
- [ ] You can explain why **`TOUCHED` is noise** on an f2fs volume mounted with `lazytime`
- [ ] You accounted for all five documented leaks and found that **LEAK-1 was absent from the diff**
- [ ] You worked out that the method is **structurally blind** to a file created and deleted between snapshots, and can name two other blind spots
- [ ] You caught LEAK-1's write and its `delete` with [`../scripts/storage-trace.js`](../scripts/storage-trace.js) under Frida, spawning rather than attaching
- [ ] You ran the same cycle against the fixed app and can point at the **identical cryptography** in both
- [ ] You can state, in one sentence, what a filesystem diff proves and what it cannot prove
