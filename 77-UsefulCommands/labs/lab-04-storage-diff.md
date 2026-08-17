# Lab 04 — Storage Diff

**Difficulty:** Intermediate
**Time:** 60–90 minutes
**Prerequisites:** [Lab 01](lab-01-device-recon.md), [33-Storage](../../33-Storage/README.md)

---

## Objective

Capture a complete snapshot of an app's private data directory before and after a login, diff the two,
and locate the credential material — in under ten minutes, repeatably.

## Why this matters

"Sensitive data stored unencrypted" is one of the most consistently present findings in real
applications, and the slow way to find it is to read the decompiled source hoping to spot a
`putString`.

The fast way is to let the app tell you. Snapshot, exercise the feature, snapshot again, diff. Whatever
changed is what that feature wrote. It requires no source, no decompilation, and no guessing — and it
catches data written by third-party SDKs whose source you will never read.

Once you have done this a few times it becomes a ten-minute reflex you run on every engagement.

---

## Setup

```bash
# host
export PKG=com.example.target
adb shell pm path $PKG
adb shell 'command -v su >/dev/null && echo root || echo no-root'
```

You need **one** of:

- **root** — works on any app
- the app being **`debuggable`** — `run-as` works, no root needed

Check:

```bash
# host
adb shell dumpsys package $PKG | grep -i "flags=" | head -2
```

If you see `DEBUGGABLE` in the flags, `run-as` is available. If not, you need root — or you can
repackage the app with `android:debuggable="true"`, which is covered in
[10-APK-Internals](../../10-APK-Internals/README.md).

> **Important.** Uninstall and reinstall the app first so you start from a genuinely clean state. An
> app that has been used before will have data from earlier sessions that muddies the diff.

```bash
# host
adb uninstall $PKG
adb install -r target.apk
```

---

## Steps

### Step 1 — Snapshot BEFORE

Launch the app once and let it reach the login screen, but **do not log in**.

```bash
# host
adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1
sleep 3
```

Now capture. With root:

```bash
# adb shell as root
PKG=com.example.target
su -c "tar czf /sdcard/before.tgz -C /data/data/$PKG . 2>/dev/null"
```

Without root, on a debuggable app:

```bash
# host
adb exec-out run-as $PKG tar czf - . > before.tgz
```

> **⚠️ Warning**
> Use `adb exec-out`, not `adb shell`. `adb shell` performs line-ending translation that will corrupt
> a binary stream, and you will get a tar archive that will not extract. This wastes a surprising
> amount of people's time.

```bash
# host — if you used the root path
adb pull /sdcard/before.tgz
ls -la before.tgz
```

**Q1.** How large is the archive? Roughly how many files does it contain?

```bash
# host
tar tzf before.tgz | wc -l
tar tzf before.tgz | head -30
```

### Step 2 — Exercise the feature

Log in through the UI with credentials you control and can recognise later. Use a **distinctive**
password — something like `ARTLAB_pw_9f3c` — so you can grep for it.

Then let the app settle:

```bash
# host
sleep 5
```

### Step 3 — Snapshot AFTER

```bash
# adb shell as root
su -c "tar czf /sdcard/after.tgz -C /data/data/$PKG . 2>/dev/null"
```

or

```bash
# host
adb exec-out run-as $PKG tar czf - . > after.tgz
```

```bash
# host
adb pull /sdcard/after.tgz   # only if you used the root path
```

### Step 4 — Diff

```bash
# host
rm -rf b a && mkdir -p b a
tar xzf before.tgz -C b
tar xzf after.tgz  -C a
diff -rq b a
```

**Q2.** Which files are new? Which changed? Write the list down — this is the login feature's complete
storage footprint.

```bash
# host — see the actual textual changes
diff -ru b a 2>/dev/null | head -80
```

### Step 5 — Read what changed

For each changed file, look at it with the right tool.

**SharedPreferences (XML):**

```bash
# host
find a -path '*shared_prefs*' -name '*.xml' -newer b -exec sh -c \
  'echo "=== $1"; cat "$1"' _ {} \;
```

**SQLite databases:**

```bash
# host
find a -name '*.db' | while read db; do
  echo "=== $db"
  sqlite3 "$db" ".tables"
  for t in $(sqlite3 "$db" ".tables"); do
    echo "--- $t"
    sqlite3 "$db" "SELECT * FROM $t LIMIT 5;"
  done
done
```

**Everything else:**

```bash
# host
find a -type f -newer b | while read f; do
  echo "=== $f  ($(file -b "$f"))"
  head -c 400 "$f" | strings | head -10
done
```

**Q3.** Did you find your distinctive password? Verbatim, hashed, or not at all?

```bash
# host — the direct search
grep -ri "ARTLAB_pw_9f3c" a/ 2>/dev/null
```

**Q4.** Did you find a session token or JWT?

```bash
# host
grep -rhoE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+' a/ | sort -u
```

If you find a JWT, decode it:

```bash
# host
echo '<payload-part>' | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool
```

**Q5.** What claims does it carry? What is its expiry? Is it device-bound in any way?

### Step 6 — The WAL trap

SQLite in WAL mode keeps recent writes in a side file. Data you "deleted" is frequently still there.

```bash
# host
find a -name '*-wal' -o -name '*-shm' -o -name '*-journal'
```

**Q6.** Do WAL files exist? If so:

```bash
# host — strings often reveal rows that the main .db no longer shows
strings a/databases/app.db-wal | grep -iE 'token|password|user|email' | head -20
```

Now do the deletion test. In the app, log out. Snapshot again and compare:

```bash
# adb shell as root
su -c "tar czf /sdcard/afterlogout.tgz -C /data/data/$PKG . 2>/dev/null"
```

```bash
# host
adb pull /sdcard/afterlogout.tgz
rm -rf c && mkdir c && tar xzf afterlogout.tgz -C c
grep -rhoE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+' c/ | sort -u
```

**Q7.** Is the token still on disk after logout? Is it still valid server-side? (Test by replaying it
with `curl`.) These are two different findings and both matter.

### Step 7 — Check the incidental channels

Storage is not only the data directory.

```bash
# host — logs written during login
adb logcat -d --pid=$(adb shell pidof -s $PKG) | grep -iE "token|password|auth|session" | head
```

```bash
# adb shell as root — external storage
ls -la /sdcard/Android/data/$PKG/ 2>/dev/null
find /sdcard/Android/data/$PKG -type f 2>/dev/null | head
```

```bash
# host — is a backup possible?
adb shell dumpsys package $PKG | grep -i allowBackup
```

**Q8.** Did anything sensitive reach logcat, external storage, or a backup?

### Step 8 — Automate it

Write `storage-diff.sh` that does the whole cycle: snapshot, prompt you to exercise the app, snapshot
again, diff, and run the secret regexes over the delta.

**Q9.** How long does your script take end to end? Target: under three minutes of your attention.

### Step 9 — Report

For each item found, write:

- What it is and where exactly (full path, and the key within the file)
- How you obtained it (root, or `run-as` on a debuggable app)
- What an attacker needs to reach it (device access? root? a backup? another app?)
- Impact
- Severity, with the prerequisite stated
- Fix as code

**Q10.** A plaintext token in `SharedPreferences` — what severity, and what changes it? Be specific
about the prerequisites in each direction.

---

## Hints

<details>
<summary>Hint 1 — the tar archive will not extract</summary>

You almost certainly used `adb shell` instead of `adb exec-out`. `adb shell` translates line endings
and corrupts binary streams.

```bash
adb exec-out run-as $PKG tar czf - . > before.tgz
```

With root, write to `/sdcard` first and `adb pull` the file — pull is binary-safe.
</details>

<details>
<summary>Hint 2 — run-as says "not debuggable"</summary>

`run-as` only works on apps with `android:debuggable="true"`. Options: use root; or repackage the app
with the flag set and re-sign it (see [10-APK-Internals](../../10-APK-Internals/README.md)), noting
that this changes the signature and may trip tamper detection.
</details>

<details>
<summary>Hint 3 — diff shows every file as changed</summary>

Timestamps and cache files create noise. Focus on the directories that matter:

```bash
diff -rq b/shared_prefs a/shared_prefs
diff -rq b/databases a/databases
diff -rq b/files a/files
```

And exclude the churn:

```bash
diff -rq b a | grep -vE 'cache|code_cache|\.jpg|\.png|webview'
```
</details>

<details>
<summary>Hint 4 — sqlite3 is not on the device</summary>

Do it on the host — you have already pulled the files:

```bash
sqlite3 a/databases/app.db ".dump" | head -50
```

Or use DB Browser for SQLite if you prefer a GUI.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q3.** Three outcomes, three very different findings. The password stored **verbatim** is Critical —
there is almost never a legitimate reason for an app to retain the user's password at all. A
**hash** is better but still questionable: what is it for? Client-side hashing is not authentication.
**Absent** is correct — the app should hold a token, not the credential.

**Q4–Q5.** A JWT in plaintext `SharedPreferences` is the single most common storage finding in real
apps. Decode it and check: the expiry (a 30-day token is far worse than a 5-minute one), whether it
carries a device binding, and what claims it asserts. Those three facts drive the severity far more
than the mere fact of plaintext storage.

**Q6.** WAL files routinely contain rows the main database no longer shows. "We delete the token on
logout" is frequently untrue at the storage layer, and `strings` on the `-wal` file is how you prove
it in thirty seconds. See [33-Storage](../../33-Storage/README.md).

**Q7.** Two separate findings, and testers regularly conflate them. **Token still on disk after
logout** is a storage hygiene issue. **Token still valid server-side after logout** is an
authentication issue and usually the more serious of the two — it means logout is cosmetic. Test the
second by replaying the token with `curl` after logging out.

**Q10.** A plaintext session token in `SharedPreferences` is typically **Medium**: exploitation needs
device access or root, so it is not remotely exploitable. It rises to **High** when combined with
`allowBackup="true"` (extractable with no root at all), when the token is long-lived with no device
binding, or when the app is `debuggable`. It falls to **Low** if the token is short-lived, bound to the
device, and revoked server-side on logout. State the prerequisite explicitly — "sensitive data stored
in plaintext" with no threat model is an observation, not a finding.

</details>

---

## Success criteria

- [ ] You started from a genuinely clean install
- [ ] You captured before/after snapshots without corrupting the archives
- [ ] You produced a complete list of files the login feature touched
- [ ] You read every changed SharedPreferences file and database table
- [ ] You determined whether the password is stored, and in what form
- [ ] You extracted and decoded any token, and recorded its expiry and claims
- [ ] You checked WAL/journal files for data the main database no longer shows
- [ ] You tested whether the token survives logout **on disk** and **server-side**
- [ ] You checked logcat, external storage and backup as incidental channels
- [ ] You automated the whole cycle into a script that runs in under three minutes
- [ ] Every finding states its prerequisite and a defensible severity
